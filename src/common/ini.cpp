#include "v8inject/ini.h"

#include <windows.h>

namespace v8i {

namespace {

// Creates the folder of an ini file when it is missing. Without it the write
// fails with ERROR_FILE_NOT_FOUND, and the settings are lost without a word.
// Every missing component is created: a caller may point the file at a path
// deeper than one folder, and CreateDirectoryW alone would fail there.
void EnsureFolderOf(const wchar_t* path) {
    if (!path) return;
    std::wstring p(path);
    const size_t slash = p.find_last_of(L"\\");
    if (slash == std::wstring::npos) return;
    p.resize(slash);
    if (p.empty()) return;
    const bool rooted = p.size() >= 2 && (p[1] == L':' || (p[0] == L'\\' && p[1] == L'\\'));
    if (!rooted) {
        CreateDirectoryW(p.c_str(), nullptr);
        return;
    }
    for (size_t i = 2; i <= p.size(); ++i) {
        if (i < p.size() && p[i] != L'\\') continue;
        const std::wstring part = p.substr(0, i);
        // A trailing separator would name nothing; "C:" is a volume.
        if (part.empty() || part.back() == L'\\' || part.back() == L':') continue;
        CreateDirectoryW(part.c_str(), nullptr);   // ERROR_ALREADY_EXISTS is fine
    }
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

namespace {

// Whole file into memory. An ini file of the project is a few hundred bytes;
// the cap keeps a wrong path (a directory, a huge log) from being slurped.
bool ReadFileBytes(const wchar_t* path, std::string& out) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(f, &size) || size.QuadPart <= 0 ||
        size.QuadPart > 4 * 1024 * 1024) {
        CloseHandle(f);
        return false;
    }
    out.resize((size_t)size.QuadPart);
    DWORD got = 0;
    const bool ok = ReadFile(f, &out[0], (DWORD)out.size(), &got, nullptr) != FALSE &&
                    got == out.size();
    CloseHandle(f);
    if (!ok) out.clear();
    return ok;
}

// UTF-8 → wide; empty on invalid input, so the caller can fall back.
std::wstring FromUtf8(const char* p, size_t n) {
    const int need = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p, (int)n,
                                         nullptr, 0);
    if (need <= 0) return std::wstring();
    std::wstring w((size_t)need, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p, (int)n, &w[0], need);
    return w;
}

std::wstring FromAnsi(const char* p, size_t n) {
    const int need = MultiByteToWideChar(CP_ACP, 0, p, (int)n, nullptr, 0);
    if (need <= 0) return std::wstring();
    std::wstring w((size_t)need, L'\0');
    MultiByteToWideChar(CP_ACP, 0, p, (int)n, &w[0], need);
    return w;
}

// Decodes the file by its byte order mark. IniSet writes UTF-16LE with 0xFF
// 0xFE; an ANSI file from an older build has no mark at all.
std::wstring DecodeBytes(const std::string& b) {
    const unsigned char* u = (const unsigned char*)b.data();
    if (b.size() >= 2 && u[0] == 0xFF && u[1] == 0xFE) {
        const size_t n = (b.size() - 2) / sizeof(wchar_t);
        std::wstring w((const wchar_t*)(u + 2), n);
        return w;
    }
    if (b.size() >= 2 && u[0] == 0xFE && u[1] == 0xFF) {
        std::wstring w;
        w.reserve((b.size() - 2) / 2);
        for (size_t i = 2; i + 1 < b.size(); i += 2)
            w.push_back((wchar_t)((u[i] << 8) | u[i + 1]));
        return w;
    }
    if (b.size() >= 3 && u[0] == 0xEF && u[1] == 0xBB && u[2] == 0xBF)
        return FromUtf8(b.data() + 3, b.size() - 3);
    // No mark: a UTF-8 file from another tool is still valid UTF-8, and an ANSI
    // file is all that is left.
    std::wstring w = FromUtf8(b.data(), b.size());
    return w.empty() ? FromAnsi(b.data(), b.size()) : w;
}

bool IsSpace(wchar_t c) { return c == L' ' || c == L'\t' || c == L'\r'; }

std::wstring Trim(const std::wstring& s) {
    size_t b = 0, e = s.size();
    while (b < e && IsSpace(s[b])) ++b;
    while (e > b && IsSpace(s[e - 1])) --e;
    return s.substr(b, e - b);
}

}  // namespace

std::wstring IniGetManual(const wchar_t* path, const wchar_t* section,
                          const wchar_t* key, const wchar_t* fallback, bool* found) {
    if (found) *found = false;
    const std::wstring missing = fallback ? fallback : L"";
    if (!path || !key) return missing;
    std::string bytes;
    if (!ReadFileBytes(path, bytes)) return missing;
    const std::wstring text = DecodeBytes(bytes);

    std::wstring current;   // current [section]; empty = before the first one
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t eol = text.find(L'\n', pos);
        if (eol == std::wstring::npos) eol = text.size();
        const std::wstring line = Trim(text.substr(pos, eol - pos));
        pos = eol + 1;
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line[0] == L'[') {
            const size_t close = line.find(L']');
            current = close == std::wstring::npos ? std::wstring()
                                                  : Trim(line.substr(1, close - 1));
            continue;
        }
        const size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;
        // Windows ini semantics: a section name in brackets, keys before any
        // section belong to the empty section.
        if (!current.empty() && (!section || _wcsicmp(current.c_str(), section) != 0))
            continue;
        if (current.empty() && section && *section) continue;
        const std::wstring k = Trim(line.substr(0, eq));
        if (_wcsicmp(k.c_str(), key) != 0) continue;
        if (found) *found = true;
        return Trim(line.substr(eq + 1));
    }
    return missing;
}

}  // namespace v8i
