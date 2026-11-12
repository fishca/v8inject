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

// The Win32 ini functions write Unicode only into a file that already has a
// UTF-16 byte order mark. Into a new file they write the system code page,
// and a Russian setting (the commit message, a path with Cyrillic) is then
// stored in cp1251 or cp1252 - and mangled on a machine with a different code
// page. The file is therefore created as Unicode from the start, and an old
// ANSI file is converted once.
void EnsureUnicodeFile(const wchar_t* path) {
    if (!path) return;

    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) {
        // A new file: an empty one with the byte order mark.
        HANDLE n = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (n == INVALID_HANDLE_VALUE) return;
        const unsigned char bom[2] = { 0xFF, 0xFE };
        DWORD written = 0;
        WriteFile(n, bom, sizeof(bom), &written, nullptr);
        CloseHandle(n);
        return;
    }

    // An existing file: UTF-16 with a mark is left alone, an ANSI one is
    // converted (its content is read in the current code page - what was
    // written there before cannot be recovered).
    unsigned char head[2] = {};
    DWORD read = 0;
    const bool haveMark = ReadFile(f, head, sizeof(head), &read, nullptr) && read == 2 &&
                          head[0] == 0xFF && head[1] == 0xFE;
    if (haveMark) { CloseHandle(f); return; }

    SetFilePointer(f, 0, nullptr, FILE_BEGIN);
    std::string ansi;
    char chunk[4096];
    DWORD got = 0;
    while (ReadFile(f, chunk, sizeof(chunk), &got, nullptr) && got) ansi.append(chunk, got);
    CloseHandle(f);

    const int wide = MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), (int)ansi.size(),
                                         nullptr, 0);
    std::wstring text;
    if (wide > 0) {
        text.resize((size_t)wide);
        MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), (int)ansi.size(), &text[0], wide);
    }

    HANDLE n = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (n == INVALID_HANDLE_VALUE) return;
    const unsigned char bom[2] = { 0xFF, 0xFE };
    DWORD written = 0;
    WriteFile(n, bom, sizeof(bom), &written, nullptr);
    if (!text.empty())
        WriteFile(n, text.c_str(), (DWORD)(text.size() * sizeof(wchar_t)), &written, nullptr);
    CloseHandle(n);
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
    EnsureUnicodeFile(path);
    return WritePrivateProfileStringW(section, key, value ? value : L"", path) != FALSE;
}

}  // namespace v8i
