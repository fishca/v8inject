#include "git_service.h"

#include "v8inject/diag.h"
#include "v8inject/ini.h"
#include "v8inject/text.h"

#include <windows.h>
#include <cstddef>
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

// One argument of a command line, quoted the way CommandLineToArgvW expects.
// Only an empty argument or one containing a space / tab needs the quotes: a
// quoted switch is not a switch for cmd.exe, and a path that ends in a backslash
// loses it to the \" escape when it is quoted unconditionally (A76).
static std::wstring QuoteArg(const std::wstring& arg) {
    if (!arg.empty() && arg.find_first_of(L" \t") == std::wstring::npos) return arg;
    std::wstring out;
    size_t slashes = 0;
    for (const wchar_t c : arg) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        if (c == L'"') {
            out.append(slashes * 2 + 1, L'\\');   // the quote itself, escaped
            out += L'"';
            slashes = 0;
            continue;
        }
        out.append(slashes, L'\\');
        slashes = 0;
        out += c;
    }
    out.append(slashes * 2, L'\\');   // trailing backslashes stay literal
    return L"\"" + out + L"\"";
}

// Runs "<exe> <args>" and collects stdout + stderr.
//
// Three properties the old implementation did not have (docs/AUDIT.md A76):
//  * the deadline is wall clock and is tested on every iteration, before the
//    pipe is looked at. The old loop checked it only when the pipe was empty, so
//    a git that kept printing never timed out at all;
//  * the child is created suspended and put into a job object with
//    kill-on-close, so stopping it kills what it spawned itself (credential
//    helper, ssh, hooks). TerminateProcess on git.exe alone left those running;
//  * the result carries the flags: callers can tell a timeout from an empty
//    answer, and the output is capped so a runaway git cannot grow the 1C
//    process (docs/AUDIT.md A76, A77).
GitResult RunProcess(const std::wstring& exe, const std::vector<std::wstring>& args,
                     DWORD timeoutMs, size_t maxBytes) {
    GitResult res;

    std::wstring cmdline = L"\"" + exe + L"\"";
    for (const std::wstring& a : args) {
        cmdline += L" ";
        cmdline += QuoteArg(a);
    }

    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE outRd = nullptr, outWr = nullptr;
    if (!CreatePipe(&outRd, &outWr, &sa, 0)) {
        res.error = L"<pipe failed>";
        return res;
    }
    SetHandleInformation(outRd, HANDLE_FLAG_INHERIT, 0);

    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION li{};
        li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &li, sizeof(li))) {
            CloseHandle(job);
            job = nullptr;
        }
    }

    STARTUPINFOW si{ sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = outWr;
    si.hStdError = outWr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::wstring cmd = cmdline;  // CreateProcessW may write into it
    // Suspended: the child is inside the job before it can start anything of its
    // own, so whatever it spawns is born into the job too.
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        CloseHandle(outRd);
        CloseHandle(outWr);
        if (job) CloseHandle(job);
        wchar_t b[192];
        _snwprintf_s(b, _countof(b), _TRUNCATE, L"<cannot start %ls (win32 %lu)>",
                     exe.c_str(), (unsigned long)GetLastError());
        res.error = b;
        return res;
    }
    res.started = true;
    CloseHandle(outWr);
    // Without a job (AssignProcessToJobObject refused) a timeout still falls
    // back to TerminateProcess on git itself.
    const bool inJob = job && AssignProcessToJobObject(job, pi.hProcess) != FALSE;
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    std::string out;
    char buf[4096];
    const ULONGLONG start = GetTickCount64();
    bool stopped = false;
    for (;;) {
        if (GetTickCount64() - start > (ULONGLONG)timeoutMs) {
            res.timedOut = true;
            stopped = true;
            break;
        }
        DWORD avail = 0;
        if (!PeekNamedPipe(outRd, nullptr, 0, nullptr, &avail, nullptr)) break;  // closed
        if (avail) {
            // Read exactly what the pipe holds. A byte-mode pipe blocks until
            // the whole requested count arrives, so asking for the full buffer
            // while only a few dozen bytes are buffered would hang here until
            // the writer closes.
            DWORD rd = 0;
            DWORD want = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
            if (!ReadFile(outRd, buf, want, &rd, nullptr) || rd == 0) break;
            out.append(buf, rd);
            if (maxBytes && out.size() >= maxBytes) {
                out.resize(maxBytes);
                res.truncated = true;
                stopped = true;
                break;
            }
            continue;
        }
        if (WaitForSingleObject(pi.hProcess, 25) == WAIT_OBJECT_0) break;  // exited
    }
    if (!stopped) {  // drain whatever is still buffered in the pipe
        DWORD avail = 0;
        while (PeekNamedPipe(outRd, nullptr, 0, nullptr, &avail, nullptr) && avail) {
            DWORD rd = 0;
            DWORD want = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
            if (!ReadFile(outRd, buf, want, &rd, nullptr) || rd == 0) break;
            out.append(buf, rd);
            if (maxBytes && out.size() > maxBytes) {
                out.resize(maxBytes);
                res.truncated = true;
                break;
            }
        }
    }
    if (stopped) {
        if (inJob) TerminateJobObject(job, 1);
        else TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    DWORD code = 0;
    if (GetExitCodeProcess(pi.hProcess, &code)) res.exitCode = code;
    CloseHandle(pi.hProcess);
    CloseHandle(outRd);
    // Kill-on-close: nothing that git started is left behind even when git
    // itself exited normally.
    if (job) CloseHandle(job);
    res.out = Utf8ToWide(out);
    return res;
}

GitResult RunGitEx(const std::vector<std::wstring>& args, DWORD timeoutMs, size_t maxBytes) {
    return RunProcess(GitExe(), args, timeoutMs, maxBytes);
}

// Text-only form for read-only queries: a stopped git leaves a marker so the
// tooltip says what happened instead of looking like an empty answer.
std::wstring RunGit(const std::vector<std::wstring>& args, DWORD timeoutMs) {
    const GitResult r = RunGitEx(args, timeoutMs);
    if (!r.started) return r.error;
    std::wstring out = r.out;
    if (r.timedOut) out += L"\n<timeout>";
    if (r.truncated) out += L"\n<truncated>";
    return out;
}

std::wstring GitFailureText(const GitResult& r, DWORD timeoutMs, size_t byteCap) {
    if (!r.started) return r.error.empty() ? L"git не запущен" : r.error;
    if (r.timedOut) {
        wchar_t b[128];
        _snwprintf_s(b, _countof(b), _TRUNCATE,
                     L"git не ответил за %lu с — процесс остановлен",
                     (unsigned long)(timeoutMs / 1000));
        return b;
    }
    if (r.truncated) {
        wchar_t b[128];
        _snwprintf_s(b, _countof(b), _TRUNCATE,
                     L"git выдал больше %lu МБ — процесс остановлен",
                     (unsigned long)(byteCap >> 20));
        return b;
    }
    std::wstring text = TrimWs(r.out);
    if (text.empty()) {
        wchar_t b[96];
        _snwprintf_s(b, _countof(b), _TRUNCATE, L"git завершился с кодом %lu",
                     (unsigned long)r.exitCode);
        return b;
    }
    return text;
}

// ---------------------------------------------------------------------------
// A58: the dump folder must own its repository.
// ---------------------------------------------------------------------------

std::wstring NormalizeDir(const std::wstring& dir) {
    if (dir.empty()) return std::wstring();
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetFullPathNameW(dir.c_str(), MAX_PATH, buf, nullptr);
    std::wstring out;
    if (n > 0 && n < MAX_PATH) {
        out.assign(buf, n);
    } else if (n >= MAX_PATH) {
        std::wstring big((size_t)n, L'\0');
        DWORD m = GetFullPathNameW(dir.c_str(), n, &big[0], nullptr);
        if (m == 0 || m > n) return dir;
        out.assign(big.c_str(), m);
    } else {
        return dir;   // GetFullPathNameW failed: keep what we were given
    }
    // "E:\dump\" and "E:\dump" are the same folder; a drive root keeps its slash.
    while (out.size() > 1 && (out.back() == L'\\' || out.back() == L'/')) {
        if (out.size() == 3 && out[1] == L':') break;
        out.pop_back();
    }
    return out;
}

bool SamePath(const std::wstring& a, const std::wstring& b) {
    const std::wstring na = NormalizeDir(a);
    const std::wstring nb = NormalizeDir(b);
    if (na.empty() || nb.empty()) return false;
    return _wcsicmp(na.c_str(), nb.c_str()) == 0;
}

bool IsSubPath(const std::wstring& child, const std::wstring& parent) {
    const std::wstring c = NormalizeDir(child);
    const std::wstring p = NormalizeDir(parent);
    if (c.empty() || p.empty() || p.size() > c.size()) return false;
    if (_wcsnicmp(c.c_str(), p.c_str(), p.size()) != 0) return false;
    if (c.size() == p.size()) return true;             // the same folder
    if (p.back() == L'\\') return true;                // "C:\" and anything below
    return c[p.size()] == L'\\';                       // component boundary
}

bool HasDotGit(const std::wstring& dir) {
    const std::wstring d = NormalizeDir(dir);
    if (d.empty()) return false;
    // A linked worktree has a .git *file*, a normal repository a directory; both
    // make "git -C dir" work, so both count.
    return GetFileAttributesW((d + L"\\.git").c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::wstring RepoTopLevel(const std::wstring& dir) {
    const GitResult r = RunGitEx({ L"-C", dir, L"rev-parse", L"--show-toplevel" }, 15000);
    if (!r.started || !r.Finished() || r.exitCode != 0) return std::wstring();
    std::wstring out = TrimWs(r.out);
    const size_t e = out.find_first_of(L"\r\n");
    if (e != std::wstring::npos) out = TrimWs(out.substr(0, e));
    // stdout and stderr share the pipe, so a failure arrives here as git's
    // "fatal: ..." line. Only an absolute path is an answer.
    if (out.size() < 3) return std::wstring();
    const bool unc = out[0] == L'\\' && out[1] == L'\\';
    const bool drive = out[1] == L':';
    if (!unc && !drive) return std::wstring();
    return out;
}

RepoRootCheck ClassifyRepoRoot(const std::wstring& dir, const std::wstring& toplevel) {
    const std::wstring d = NormalizeDir(dir);
    const std::wstring t = NormalizeDir(toplevel);
    if (d.empty() || t.empty()) return RepoRootCheck::NoRepo;
    if (SamePath(d, t)) return RepoRootCheck::IsRoot;
    if (IsSubPath(d, t)) return RepoRootCheck::InsideOther;
    return RepoRootCheck::Elsewhere;
}

bool DumpRepoRootOk(const std::wstring& dir, RepoRootCheck* kind, std::wstring* why) {
    RepoRootCheck k = RepoRootCheck::NoRepo;
    std::wstring reason;
    if (dir.empty()) {
        reason = L"Не указана папка выгрузки — откройте настройки GitBar.";
    } else if (!HasDotGit(dir)) {
        reason = L"В папке выгрузки нет git-репозитория:\n" + dir;
    } else {
        const std::wstring top = RepoTopLevel(dir);
        k = ClassifyRepoRoot(dir, top);
        switch (k) {
        case RepoRootCheck::IsRoot:
            break;
        case RepoRootCheck::InsideOther: {
            const std::wstring shown = top.empty() ? std::wstring() : top;
            reason = L"Папка выгрузки лежит ВНУТРИ другого репозитория:\n" + shown +
                     L"\n\ngit add -A/commit/push отправили бы в удалённый репозиторий "
                     L"файлы чужого проекта, поэтому операция отменена.\n"
                     L"Укажите в настройках корень того репозитория или создайте "
                     L"репозиторий прямо в папке выгрузки.";
            break;
        }
        case RepoRootCheck::Elsewhere:
            reason = L"git считает корнем репозитория другую папку:\n" + top +
                     L"\n\nПапка выгрузки: " + dir +
                     L"\nОперация отменена: коммит и пуш ушли бы не туда.";
            break;
        default:
            k = RepoRootCheck::Unknown;
            reason = L"Не удалось определить корень репозитория в папке выгрузки:\n" + dir +
                     L"\n\ngit вернул пустой ответ — проверьте путь к git.exe в настройках.";
            break;
        }
    }
    if (kind) *kind = k;
    if (why) *why = reason;
    return k == RepoRootCheck::IsRoot;
}

// ---------------------------------------------------------------------------
// A77: bounded cache of one commit's patch.
// ---------------------------------------------------------------------------

PatchCache::PatchCache(size_t maxChars, size_t maxEntries)
    : maxChars_(maxChars), maxEntries_(maxEntries) {}

bool PatchCache::Get(const std::wstring& hash, std::wstring* patch) {
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].hash != hash) continue;
        Entry e = entries_[i];
        entries_.erase(entries_.begin() + (std::ptrdiff_t)i);
        entries_.push_back(e);
        if (patch) *patch = entries_.back().patch;
        return true;
    }
    return false;
}

void PatchCache::Put(const std::wstring& hash, const std::wstring& patch) {
    // A patch bigger than the whole budget would evict everything and be dropped
    // on the next call anyway.
    if (hash.empty() || patch.size() > maxChars_) return;
    for (size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].hash != hash) continue;
        chars_ -= entries_[i].patch.size();
        entries_.erase(entries_.begin() + (std::ptrdiff_t)i);
        break;
    }
    entries_.push_back(Entry{ hash, patch });
    chars_ += patch.size();
    while (entries_.size() > maxEntries_ || (chars_ > maxChars_ && entries_.size() > 1)) {
        chars_ -= entries_.front().patch.size();
        entries_.erase(entries_.begin());
    }
}

void PatchCache::Clear() {
    entries_.clear();
    chars_ = 0;
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
