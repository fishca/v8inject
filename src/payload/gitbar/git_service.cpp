#include "git_service.h"

#include "v8inject/diag.h"
#include "v8inject/ini.h"
#include "v8inject/text.h"

#include <windows.h>
#include <string>
#include <vector>

namespace v8i {
namespace gitbar {

const wchar_t* GitIniPath() {
    static wchar_t path[MAX_PATH] = {};
    if (!path[0]) {
        ExpandEnvironmentStringsW(L"%APPDATA%\\v8inject\\gitbar.ini", path, MAX_PATH);
    }
    return path;
}

// The ini helpers live in v8i_common (see v8inject/ini.h): one place, and
// the folder of the file is created before the first write.
std::wstring GitIniGet(const wchar_t* key, const wchar_t* fallback) {
    return v8i::IniGet(GitIniPath(), L"git", key, fallback);
}

// Writes one key of the gitbar ini. Returns false when the file could not be
// written -- on a machine that never ran v8inject the %APPDATA%\v8inject
// folder does not exist, and WritePrivateProfileString then fails silently,
// so the settings look saved and are not.
bool GitIniSet(const wchar_t* key, const wchar_t* value) {
    if (!v8i::IniSet(GitIniPath(), L"git", key, value)) {
        LogLine("gitbar: cannot write ini key %ls (win32 %lu)", key, GetLastError());
        return false;
    }
    return true;
}

// Client width below which the full strip would cover the designer's own
// toolbar buttons; the bar then collapses to a single menu button instead.
// 0 disables the compact mode. Read on every reposition, so a hand-edited
// ini takes effect without restarting 1C.
int CompactThreshold() {
    const std::wstring buf = GitIniGet(L"compactwidth", L"900");
    int v = (int)wcstol(buf.c_str(), nullptr, 10);
    if (v < 0) v = 0;
    return v > 10000 ? 10000 : v;
}

std::wstring GitExe() {
    std::wstring p = GitIniGet(L"gitpath");
    if (p.empty()) p = L"git.exe";  // fall back to PATH
    return p;
}

// Trim + squeeze for tooltips: git output is multi-line and CRLF-terminated.
std::wstring TrimForTip(const std::wstring& s, size_t maxLen) {
    std::wstring out;
    bool space = false;
    for (wchar_t c : s) {
        if (c == L'\r' || c == L'\n' || c == L'\t' || c == L' ') {
            space = !out.empty();
            continue;
        }
        if (space) { out += L' '; space = false; }
        out += c;
        if (out.size() >= maxLen) { out += L"…"; break; }
    }
    return out;
}

std::wstring TrimWs(const std::wstring& s) {
    size_t b = s.find_first_not_of(L" \t\r\n");
    if (b == std::wstring::npos) return L"";
    size_t e = s.find_last_not_of(L" \t\r\n");
    return s.substr(b, e - b + 1);
}

// LogLine takes a narrow printf format and vfprintf converts %ls with the "C"
// locale: any Cyrillic character in the text makes the conversion fail and the
// whole argument prints empty. Convert to UTF-8 and pass it as %s instead.

void LogGit(const wchar_t* what, const std::wstring& text) {
    std::string u = WideToUtf8(text);
    LogLine("gitbar: %s: %s", WideToUtf8(what).c_str(), u.c_str());
}

// Runs "<gitpath> <args>" and returns stdout + stderr. Only ever runs from the
// toolbar's own thread. A git that waits for console input (credential prompt)
// is killed at the deadline instead of hanging the panel forever.
std::wstring RunGit(const std::vector<std::wstring>& args, DWORD timeoutMs) {
    std::wstring cmdline = L"\"" + GitExe() + L"\"";
    for (const std::wstring& a : args) {
        cmdline += L" \"";
        cmdline += a;
        cmdline += L"\"";
    }

    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE outRd = nullptr, outWr = nullptr;
    if (!CreatePipe(&outRd, &outWr, &sa, 0)) return L"<pipe failed>";
    SetHandleInformation(outRd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{ sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = outWr;
    si.hStdError = outWr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::wstring cmd = cmdline;  // CreateProcessW may write into it
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(outRd);
        CloseHandle(outWr);
        wchar_t b[128];
        _snwprintf_s(b, _countof(b), _TRUNCATE, L"<cannot start git (win32 %lu)>", GetLastError());
        return b;
    }
    CloseHandle(outWr);

    std::string out;
    char buf[4096];
    DWORD start = GetTickCount();
    bool exited = false;
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(outRd, nullptr, 0, nullptr, &avail, nullptr)) break;  // closed
        if (avail) {
            DWORD rd = 0;
            // Read exactly what the pipe holds. A byte-mode pipe blocks until
            // the whole requested count arrives, so asking for the full buffer
            // while only a few dozen bytes are buffered would hang here until
            // the writer closes -- and the timeout below would never be
            // reached.
            DWORD want = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
            if (!ReadFile(outRd, buf, want, &rd, nullptr) || rd == 0) break;
            out.append(buf, rd);
            continue;
        }
        if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) { exited = true; break; }
        if (GetTickCount() - start > timeoutMs) {
            TerminateProcess(pi.hProcess, 1);
            out.append("\n<timeout>");
            break;
        }
    }
    if (exited) {  // drain whatever is still buffered in the pipe
        DWORD avail = 0;
        while (PeekNamedPipe(outRd, nullptr, 0, nullptr, &avail, nullptr) && avail) {
            DWORD rd = 0;
            DWORD want = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
            if (!ReadFile(outRd, buf, want, &rd, nullptr) || rd == 0) break;
            out.append(buf, rd);
        }
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(outRd);
    return Utf8ToWide(out);
}

std::wstring NowStamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t b[64];
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"%04d-%02d-%02d %02d:%02d:%02d",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}

// git reads the commit message from a file: argv quoting of a Cyrillic
// multi-line message is a lottery, a UTF-8 file without BOM is not.
std::wstring TempMsgPath() {
    wchar_t dir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, dir);
    return std::wstring(dir) + L"v8i_commitmsg.txt";
}

bool WriteUtf8File(const std::wstring& path, const std::wstring& text) {
    int n = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(),
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0) return false;
    std::string u((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), &u[0], n, nullptr, nullptr);

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    bool ok = WriteFile(h, u.data(), (DWORD)u.size(), &wr, nullptr) && wr == u.size();
    CloseHandle(h);
    return ok;
}

HWND FindFrame() {
    struct Ctx { HWND h; DWORD pid; } ctx = { nullptr, GetCurrentProcessId() };
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        Ctx* c = (Ctx*)lp;
        DWORD pid = 0;
        GetWindowThreadProcessId(h, &pid);
        if (pid != c->pid) return TRUE;
        wchar_t cls[64] = {};
        GetClassNameW(h, cls, 64);
        if (wcscmp(cls, L"V8iGitBar") == 0) return TRUE;
        wchar_t title[64] = {};
        GetWindowTextW(h, title, 64);
        if (title[0] && IsWindowVisible(h)) { c->h = h; return FALSE; }
        return TRUE;
    }, (LPARAM)&ctx);
    return ctx.h;
}

}  // namespace gitbar
}  // namespace v8i
