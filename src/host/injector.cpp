#include "v8inject/injector.h"
#include "v8inject/procs.h"
#include "v8inject/diag.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <cstring>

namespace v8i {

namespace {

// Writes a buffer into the target and keeps the allocation alive.
void* AllocRemote(HANDLE hProc, const void* data, size_t bytes) {
    void* remote = VirtualAllocEx(hProc, nullptr, bytes,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return nullptr;
    if (!WriteProcessMemory(hProc, remote, data, bytes, nullptr)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return nullptr;
    }
    return remote;
}

// LoadLibraryW is resolved locally and rebased into the target, never used by
// its local address. On one Windows boot the system DLLs sit at the same base
// in every process of a bitness, so the delta is usually zero -- but that is
// an assumption, and checking it turns a silent wrong-address call in the
// target into a clean, explained failure.
bool RemoteLoadLibrary(HANDLE hProc, const std::wstring& dllPath, HMODULE* baseOut) {
    void* remote = AllocRemote(hProc, dllPath.c_str(),
                               (dllPath.size() + 1) * sizeof(wchar_t));
    if (!remote) return false;

    HMODULE localK32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC localLoadLib = localK32 ? GetProcAddress(localK32, "LoadLibraryW") : nullptr;
    HMODULE remoteK32 = localLoadLib ? FindModuleInProcess(hProc, L"kernel32.dll") : nullptr;
    LPTHREAD_START_ROUTINE loadLib = nullptr;
    if (localLoadLib && remoteK32) {
        loadLib = (LPTHREAD_START_ROUTINE)((uintptr_t)localLoadLib
                                           - (uintptr_t)localK32
                                           + (uintptr_t)remoteK32);
    }
    LogLine("RemoteLoadLibrary: kernel32 local=%p remote=%p LoadLibraryW local=%p remote=%p",
            (void*)localK32, (void*)remoteK32, (void*)localLoadLib, (void*)loadLib);
    if (!loadLib) {
        LogLine("RemoteLoadLibrary: cannot resolve LoadLibraryW in the target");
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        return false;
    }

    HANDLE th = CreateRemoteThread(hProc, nullptr, 0, loadLib, remote, 0, nullptr);
    DWORD wait = WAIT_FAILED;
    DWORD code = 0;
    if (th) {
        wait = WaitForSingleObject(th, 15000);
        if (wait == WAIT_OBJECT_0) GetExitCodeThread(th, &code);
    }

    // On anything but a clean finish, find out whether the load completed
    // anyway: a slow target may have loaded the DLL after the timeout fired.
    bool modulePresent = false;
    if (wait != WAIT_OBJECT_0)
        modulePresent = FindModuleInProcess(hProc, dllPath) != nullptr;

    RemoteLoadDecision d = th
        ? EvaluateRemoteLoad(wait, code, modulePresent)
        : RemoteLoadDecision{ false, true, "no remote thread was created" };
    LogLine("RemoteLoadLibrary(%ls) -> %s (wait=%lu code=%lu): %s%s",
            dllPath.c_str(), d.ok ? "ok" : "FAILED", wait, code, d.reason,
            d.freeBuffer ? "" : "; path buffer left allocated");
    if (th) CloseHandle(th);
    if (d.freeBuffer) VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    if (!d.ok) return false;

    // Resolve the real module base inside the target.
    if (baseOut) {
        HMODULE remoteBase = FindModuleInProcess(hProc, dllPath);
        LogLine("FindModuleInProcess -> %p", (void*)remoteBase);
        if (!remoteBase) return false;
        *baseOut = remoteBase;
    }
    return true;
}

}  // namespace

// The decision table for the remote LoadLibrary thread. Kept pure: the unit
// tests pin it down, so a future edit cannot silently reintroduce a free
// under a still-running remote thread.
RemoteLoadDecision EvaluateRemoteLoad(DWORD wait, DWORD exitCode, bool modulePresent) {
    if (wait == WAIT_OBJECT_0) {
        if (exitCode != 0 && exitCode != STILL_ACTIVE)
            return { true, true, "the remote thread finished and returned a module handle" };
        if (exitCode == 0)
            return { false, true, "LoadLibraryW returned NULL" };
        // A finished thread that reports STILL_ACTIVE is indistinguishable
        // from a handle value of 259: neither is a base address we trust.
        return { false, true, "the remote thread exited with code STILL_ACTIVE" };
    }
    // WAIT_TIMEOUT (and, hypothetically, WAIT_FAILED): the thread's fate is
    // unknown, and the path buffer may still be read by it. Never freed.
    if (modulePresent)
        return { true, false, "timed out, but the module is loaded in the target" };
    return { false, false, "injection hung: the remote thread did not finish" };
}

HMODULE FindModuleInProcess(HANDLE hProc, const std::wstring& dllPath) {
    const wchar_t* want = wcsrchr(dllPath.c_str(), L'\\');
    want = want ? want + 1 : dllPath.c_str();

    HMODULE mods[1024] = {};
    DWORD needed = 0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &needed, LIST_MODULES_ALL))
        return nullptr;

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; ++i) {
        wchar_t path[MAX_PATH] = {};
        if (!GetModuleFileNameExW(hProc, mods[i], path, MAX_PATH)) continue;
        const wchar_t* got = wcsrchr(path, L'\\');
        got = got ? got + 1 : path;
        if (_wcsicmp(got, want) == 0) return mods[i];
    }
    return nullptr;
}

DWORD FindProcessByName(const wchar_t* exeName) {
    if (!exeName) return 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

bool InjectLibrary(DWORD pid, const std::wstring& dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) return false;
    bool ok = RemoteLoadLibrary(hProc, dllPath, nullptr);
    CloseHandle(hProc);
    return ok;
}

bool StartPayloadThread(DWORD pid,
                        const std::wstring& payloadDll,
                        const wchar_t* sharedName,
                        HANDLE& hProcessOut,
                        HANDLE& hThreadOut,
                        int& stageOut,
                        DWORD& win32ErrorOut) {
    hProcessOut = nullptr;
    hThreadOut = nullptr;
    stageOut = kStageOpenProcess;
    win32ErrorOut = 0;
    if (!sharedName) { win32ErrorOut = ERROR_INVALID_PARAMETER; return false; }

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) { win32ErrorOut = GetLastError(); return false; }

    // The target base comes back as the thread's exit code (HMODULE value).
    stageOut = kStageLoadLibrary;
    HMODULE targetBase = nullptr;
    if (!RemoteLoadLibrary(hProc, payloadDll, &targetBase)) {
        win32ErrorOut = GetLastError();
        CloseHandle(hProc);
        return false;
    }

    // Load the very same file here so the export RVA is known locally,
    // then map it into the target's address space.
    stageOut = kStageLocalLoad;
    HMODULE localBase = LoadLibraryW(payloadDll.c_str());
    if (!localBase) {
        win32ErrorOut = GetLastError();
        CloseHandle(hProc);
        return false;
    }
    stageOut = kStageGetProcAddress;
    FARPROC localProbe = GetProcAddress(localBase, "v8i_probe");
    if (!localProbe) {
        // x86 builds without the alias export: try the decorated form.
        const char* alias = sizeof(void*) == 4 ? "_v8i_probe@4" : "v8i_probe";
        localProbe = GetProcAddress(localBase, alias);
        LogLine("GetProcAddress(v8i_probe) failed, tried '%s' -> %p",
                alias, (void*)localProbe);
    }
    if (!localProbe) {
        win32ErrorOut = GetLastError();
        FreeLibrary(localBase);
        CloseHandle(hProc);
        return false;
    }

    uintptr_t delta = (uintptr_t)targetBase - (uintptr_t)localBase;
    uintptr_t remoteProbeAddr = (uintptr_t)localProbe + delta;
    LogLine("targetBase=%p localBase=%p delta=%lld localProbe=%p -> remoteProbe=%p",
            (void*)targetBase, (void*)localBase, (long long)(intptr_t)delta,
            (void*)localProbe, (void*)remoteProbeAddr);
    FreeLibrary(localBase);   // target keeps its own reference

    // Nothing is passed to the payload: it derives the block name from its own
    // PID, so there is no cross-process string to marshal.
    stageOut = kStageCreateThread;
    HANDLE th = CreateRemoteThread(hProc, nullptr, 0,
                                   (LPTHREAD_START_ROUTINE)remoteProbeAddr,
                                   nullptr, 0, nullptr);
    LogLine("CreateRemoteThread -> %p err=%lu", (void*)th, GetLastError());
    if (!th) {
        win32ErrorOut = GetLastError();
        CloseHandle(hProc);
        return false;
    }

    stageOut = kStageOk;
    hProcessOut = hProc;
    hThreadOut = th;

    // Ask the thread what happened: exit code 259 means it is still running,
    // anything else is the value v8i_probe returned (or a crash code).
    DWORD wait = WaitForSingleObject(th, 3000);
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    LogLine("thread wait=%lu exitCode=%lu (259=STILL_ACTIVE, 0=returned)",
            wait, code);
    return true;
}

}  // namespace v8i
