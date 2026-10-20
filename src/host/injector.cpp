#include "v8inject/injector.h"
#include <tlhelp32.h>
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

// LoadLibraryW has the same address in every process of the same bitness
// because kernel32 maps at a fixed base, so the address is usable remotely.
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
        if (baseOut && ok) *baseOut = (HMODULE)(uintptr_t)code;
        CloseHandle(th);
    }
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    return ok;
}

}  // namespace

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
                        void*& remoteArgsOut) {
    hProcessOut = nullptr;
    hThreadOut = nullptr;
    remoteNameOut = nullptr;
    remoteArgsOut = nullptr;
    if (!sharedName) return false;

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, pid);
    if (!hProc) return false;

    // The target base comes back as the thread's exit code (HMODULE value).
    HMODULE targetBase = nullptr;
    if (!RemoteLoadLibrary(hProc, payloadDll, &targetBase)) {
        CloseHandle(hProc);
        return false;
    }

    // Load the very same file here so the export RVA is known locally,
    // then map it into the target's address space.
    HMODULE localBase = LoadLibraryW(payloadDll.c_str());
    if (!localBase) {
        CloseHandle(hProc);
        return false;
    }
    FARPROC localProbe = GetProcAddress(localBase, "v8i_probe");
    if (!localProbe) {
        FreeLibrary(localBase);
        CloseHandle(hProc);
        return false;
    }

    uintptr_t delta = (uintptr_t)targetBase - (uintptr_t)localBase;
    uintptr_t remoteProbeAddr = (uintptr_t)localProbe + delta;
    FreeLibrary(localBase);   // target keeps its own reference

    const size_t nameBytes = (wcslen(sharedName) + 1) * sizeof(wchar_t);
    void* rn = AllocRemote(hProc, sharedName, nameBytes);
    if (!rn) { CloseHandle(hProc); return false; }

    const uintptr_t nameArg = (uintptr_t)rn;
    void* ra = AllocRemote(hProc, &nameArg, sizeof(nameArg));
    if (!ra) {
        VirtualFreeEx(hProc, rn, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE th = CreateRemoteThread(hProc, nullptr, 0,
                                   (LPTHREAD_START_ROUTINE)remoteProbeAddr,
                                   ra, 0, nullptr);
    if (!th) {
        VirtualFreeEx(hProc, rn, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, ra, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    hProcessOut = hProc;
    hThreadOut = th;
    remoteNameOut = rn;
    remoteArgsOut = ra;
    return true;
}

}  // namespace v8i
