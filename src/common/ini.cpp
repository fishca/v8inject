#include "v8inject/ini.h"

#include <windows.h>

namespace v8i {

namespace {

// Creates the folder of an ini file when it is missing. Without it the write
// fails with ERROR_FILE_NOT_FOUND, and the settings are lost without a word.
void EnsureFolderOf(const wchar_t* path) {
    if (!path) return;
    std::wstring p(path);
    const size_t slash = p.find_last_of(L"\\");
    if (slash == std::wstring::npos) return;
    p.resize(slash);
    if (p.empty()) return;
    CreateDirectoryW(p.c_str(), nullptr);   // ERROR_ALREADY_EXISTS is fine
}

}  // namespace

std::wstring IniGet(const wchar_t* path, const wchar_t* section, const wchar_t* key) {
    return IniGet(path, section, key, L"");
}

std::wstring IniGet(const wchar_t* path, const wchar_t* section, const wchar_t* key,
                    const wchar_t* fallback) {
    if (!path || !key) return fallback ? fallback : L"";
    wchar_t buf[1024] = {};
    GetPrivateProfileStringW(section, key, fallback ? fallback : L"", buf,
                             (DWORD)(sizeof(buf) / sizeof(buf[0])), path);
    return buf;
}

bool IniSet(const wchar_t* path, const wchar_t* section, const wchar_t* key,
            const wchar_t* value) {
    if (!path || !key) return false;
    EnsureFolderOf(path);
    return WritePrivateProfileStringW(section, key, value ? value : L"", path) != FALSE;
}

}  // namespace v8i
