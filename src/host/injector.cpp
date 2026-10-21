#include "v8inject/injector.h"
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

// LoadLibraryW lives at the same address in every process of one bitness,
// so its address is valid remotely. The returned HMODULE is fetched separately
// because GetExitCodeThread only carries 32 bits and would truncate it on x64.
bool RemoteLoadLibrary(HANDLE hProc, const std::wstring& dllPath, HMODULE* baseOut) {
    void* remote = AllocRemote(hProc, dllPath.c_str(),
                               (dllPath.size() + 1) * sizeof(wchar_t));
    if (!remote) return false;

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");

    bool ok = false;
    HANDLE th = loadLib ? CreateRemoteThread(hProc, nullptr, 0, loadLib,
                                             remote, 0, nullptr) : nullptr;
    if (th) {
        WaitForSingleObject(th, 15000);
        DWORD code = 0;
        GetExitCodeThread(th, &code);
        ok = (code != 0);
        CloseHandle(th);
    }
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    LogLine("RemoteLoadLibrary(%ls) -> %s", dllPath.c_str(), ok ? "ok" : "FAILED");
    if (!ok) return false;

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

bool IsProcess64(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;

    BOOL wow = FALSE;
    bool ok = IsWow64Process(h, &wow) != FALSE;
    CloseHandle(h);

#if defined(_WIN64)
    return !ok ? true : (wow == FALSE);
#else
    return false;   // a 32-bit host can only reach 32-bit targets
#endif
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
                        void*& remoteNameOut,
                        void*& remoteArgsOut,
                        int& stageOut,
                        DWORD& win32ErrorOut) {
    hProcessOut = nullptr;
    hThreadOut = nullptr;
    remoteNameOut = nullptr;
    remoteArgsOut = nullptr;
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

    stageOut = kStageAllocName;
    const size_t nameBytes = (wcslen(sharedName) + 1) * sizeof(wchar_t);
    void* rn = AllocRemote(hProc, sharedName, nameBytes);
    if (!rn) { win32ErrorOut = GetLastError(); CloseHandle(hProc); return false; }

    stageOut = kStageAllocArgs;
    const uintptr_t nameArg = (uintptr_t)rn;
    void* ra = AllocRemote(hProc, &nameArg, sizeof(nameArg));
    if (!ra) {
        win32ErrorOut = GetLastError();
        VirtualFreeEx(hProc, rn, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    stageOut = kStageCreateThread;
    HANDLE th = CreateRemoteThread(hProc, nullptr, 0,
                                   (LPTHREAD_START_ROUTINE)remoteProbeAddr,
                                   ra, 0, nullptr);
    LogLine("CreateRemoteThread -> %p err=%lu", (void*)th, GetLastError());
    if (!th) {
        win32ErrorOut = GetLastError();
        VirtualFreeEx(hProc, rn, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, ra, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    stageOut = kStageOk;
    hProcessOut = hProc;
    hThreadOut = th;
    remoteNameOut = rn;
    remoteArgsOut = ra;
    return true;
}

}  // namespace v8i
