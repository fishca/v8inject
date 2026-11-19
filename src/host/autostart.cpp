#include "autostart.h"

#include "v8inject/text.h"

#include <vector>

namespace v8i {

namespace {

std::wstring Win32Text(const wchar_t* what, LSTATUS st) {
    wchar_t buf[512];
    _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%ls: код %ld", what, (long)st);
    return buf;
}

}  // namespace

std::wstring AutostartCommandLine(const std::wstring& exePath) {
    if (exePath.empty()) return std::wstring();
    return QuoteArg(exePath);
}

bool AutostartSet(HKEY root, const wchar_t* subKey, const wchar_t* valueName,
                  const std::wstring& exePath, bool on, std::wstring* error) {
    if (error) error->clear();
    if (!root || !subKey || !valueName) {
        if (error) *error = L"пустой корень, ключ или имя значения";
        return false;
    }

    HKEY key = nullptr;
    LSTATUS st = RegCreateKeyExW(root, subKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                                 &key, nullptr);
    if (st != ERROR_SUCCESS) {
        if (error) *error = Win32Text(L"RegCreateKeyExW", st);
        return false;
    }

    bool ok = true;
    if (on) {
        const std::wstring cmd = AutostartCommandLine(exePath);
        if (cmd.empty()) {
            if (error) *error = L"пустой путь к агенту";
            ok = false;
        } else {
            st = RegSetValueExW(key, valueName, 0, REG_SZ, (const BYTE*)cmd.c_str(),
                                (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
            if (st != ERROR_SUCCESS) {
                if (error) *error = Win32Text(L"RegSetValueExW", st);
                ok = false;
            }
        }
    } else {
        // A missing value already means "not autostarting".
        st = RegDeleteValueW(key, valueName);
        if (st != ERROR_SUCCESS && st != ERROR_FILE_NOT_FOUND) {
            if (error) *error = Win32Text(L"RegDeleteValueW", st);
            ok = false;
        }
    }
    RegCloseKey(key);
    return ok;
}

std::wstring AutostartValue(HKEY root, const wchar_t* subKey,
                            const wchar_t* valueName) {
    if (!root || !subKey || !valueName) return std::wstring();

    // Two passes: the value is a path of a few hundred characters, but a stale
    // entry can be longer (or not a string at all), and RegGetValueW then says
    // ERROR_MORE_DATA instead of truncating.
    DWORD size = 1024;
    for (int attempt = 0; attempt < 3; ++attempt) {
        std::vector<wchar_t> buf(size / sizeof(wchar_t) + 1, L'\0');
        DWORD sz = (DWORD)(buf.size() * sizeof(wchar_t));
        const LSTATUS st = RegGetValueW(root, subKey, valueName, RRF_RT_REG_SZ,
                                        nullptr, buf.data(), &sz);
        if (st == ERROR_SUCCESS) return std::wstring(buf.data());
        if (st != ERROR_MORE_DATA) return std::wstring();
        size = sz;
    }
    return std::wstring();
}

bool AutostartActive(HKEY root, const wchar_t* subKey, const wchar_t* valueName) {
    return !AutostartValue(root, subKey, valueName).empty();
}

}  // namespace v8i
