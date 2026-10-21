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

bool IsProcess64(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    BOOL wow64 = FALSE;
    bool is64 = true;
    if (IsWow64Process(h, &wow64)) is64 = !wow64;
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
            out.push_back(std::move(e));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

}  // namespace v8i
