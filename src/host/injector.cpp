#include "v8inject/injector.h"
#include <tlhelp32.h>

namespace v8i {

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

    const size_t bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(hProc, nullptr, bytes,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { CloseHandle(hProc); return false; }

    bool ok = WriteProcessMemory(hProc, remote, dllPath.c_str(), bytes, nullptr) != FALSE;

    if (ok) {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
        HANDLE th = loadLib ? CreateRemoteThread(hProc, nullptr, 0, loadLib,
                                                 remote, 0, nullptr) : nullptr;
        if (th) {
            WaitForSingleObject(th, 15000);
            DWORD code = 0;
            GetExitCodeThread(th, &code);
            ok = (code != 0);
            CloseHandle(th);
        } else {
            ok = false;
        }
    }

    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return ok;
}

}  // namespace v8i
