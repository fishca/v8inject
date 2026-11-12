#include "v8inject/procs.h"

#include <tlhelp32.h>
#include <psapi.h>

namespace v8i {

namespace {

std::wstring QueryImagePath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return std::wstring();
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD size = (DWORD)(sizeof(buf) / sizeof(buf[0]));
    std::wstring out;
    if (QueryFullProcessImageNameW(h, 0, buf, &size)) out.assign(buf, size);
    CloseHandle(h);
    return out;
}

}  // namespace

bool IsPe64(const std::wstring& path) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;

    IMAGE_DOS_HEADER dos{};
    DWORD read = 0;
    bool ok = ReadFile(f, &dos, sizeof(dos), &read, nullptr) && read == sizeof(dos) &&
              dos.e_magic == IMAGE_DOS_SIGNATURE;
    if (ok) {
        if (SetFilePointer(f, dos.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
            IMAGE_NT_HEADERS nt{};
            ok = ReadFile(f, &nt, sizeof(nt), &read, nullptr) && read >= sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) &&
                 nt.Signature == IMAGE_NT_SIGNATURE;
            CloseHandle(f);
            return ok && nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
        }
    }
    CloseHandle(f);
    return false;
}

// Processes in session 0 are services; injecting into them needs SYSTEM rights
// and is never the goal, so the GUI hides them.
bool IsSession0(DWORD pid) {
    DWORD session = 0;
    if (!ProcessIdToSessionId(pid, &session)) return false;
    return session == 0;
}

// The bitness of a running process. IsWow64Process2 (Windows 10 1709+) tells
// the native machine of the image directly; the old IsWow64Process cannot:
// on a 32-bit host it answers FALSE for every process, which would make all
// of them look 64-bit and send the GUI after an x64 payload for an x86 target.
bool IsProcess64(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;

    using FnIsWow64Process2 = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    static FnIsWow64Process2 isWow64Process2 = nullptr;
    static bool isWow64Process2Resolved = false;
    if (!isWow64Process2Resolved) {
        isWow64Process2Resolved = true;
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        if (k32) isWow64Process2 = (FnIsWow64Process2)GetProcAddress(k32, "IsWow64Process2");
    }

    bool is64 = false;
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (isWow64Process2 && isWow64Process2(h, &processMachine, &nativeMachine)) {
        is64 = nativeMachine == IMAGE_FILE_MACHINE_AMD64 ||
               nativeMachine == IMAGE_FILE_MACHINE_ARM64;
    } else {
        BOOL wow64 = FALSE;
        if (IsWow64Process(h, &wow64)) {
#if defined(_M_X64) || defined(_M_ARM64)
            // On a 64-bit host: wow64 == TRUE means a 32-bit process.
            is64 = !wow64;
#else
            // On a 32-bit host nothing 64-bit can run at all.
            is64 = false;
#endif
        }
    }
    CloseHandle(h);
    return is64;
}

std::vector<ProcessEntry> ListProcesses() {
    std::vector<ProcessEntry> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessEntry e;
            e.pid = pe.th32ProcessID;
            e.name.assign(pe.szExeFile);
            e.path = QueryImagePath(e.pid);
            e.is64 = e.path.empty() ? IsProcess64(e.pid) : IsPe64(e.path);
            e.session0 = IsSession0(e.pid);
            out.push_back(std::move(e));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

}  // namespace v8i
