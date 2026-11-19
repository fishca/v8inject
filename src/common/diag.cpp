#include "v8inject/diag.h"

#include <cstdlib>
#include <cstring>

#ifndef _countof
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#endif

namespace v8i {

namespace {

// A63: the payload is multi-threaded within milliseconds of injection (the
// command loop, the early-subscribe workers, hooks, GitBar), while the log
// path is only known later, when the shared block is mapped. A lazily
// initialised CRITICAL_SECTION plus an unprotected path buffer meant that two
// threads could re-initialise the section under each other's feet, and a third
// could read a half-written path.
//
// INIT_ONCE closes the initialisation window once and for all. The section is
// deliberately a CRITICAL_SECTION and not an SRWLOCK: the payload registers a
// process-wide VEH that logs a fault, so LogLine can be re-entered by the same
// thread (a fault inside the logging path). A CRITICAL_SECTION is recursive for
// its owner, an SRWLOCK is not, and the second acquisition deadlocks the thread
// that was supposed to answer the command loop.
INIT_ONCE g_logOnce = INIT_ONCE_STATIC_INIT;
CRITICAL_SECTION g_logLock;
wchar_t g_logPath[MAX_PATH] = {};

BOOL CALLBACK InitLogLock(PINIT_ONCE, PVOID, PVOID*) {
    InitializeCriticalSection(&g_logLock);
    return TRUE;
}

void EnsureLogLock() {
    InitOnceExecuteOnce(&g_logOnce, InitLogLock, nullptr, nullptr);
}

void CopyLogPath(wchar_t* out, size_t cch) {
    EnsureLogLock();
    EnterCriticalSection(&g_logLock);
    wcsncpy_s(out, cch, g_logPath, _TRUNCATE);
    LeaveCriticalSection(&g_logLock);
}

// One line, one file, one open. Runs under the lock so two threads cannot
// interleave the halves of their lines.
void WriteLineLocked(const wchar_t* path, const char* line, int n) {
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        // Fallback chain: temp dir, then next to the module.
        wchar_t tmp[MAX_PATH] = {};
        DWORD tmpLen = GetTempPathW(MAX_PATH, tmp);
        if (tmpLen > 0 && tmpLen < MAX_PATH) {
            lstrcatW(tmp, L"v8inject_payload.log");
            h = CreateFileW(tmp, FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        }
    }
    if (h != INVALID_HANDLE_VALUE) {
        SetFilePointer(h, 0, nullptr, FILE_END);
        DWORD written = 0;
        WriteFile(h, line, (DWORD)n, &written, nullptr);
        CloseHandle(h);
    }
}

// With no path configured the payload writes next to the module: a payload
// loaded before the shared block existed must still leave a trace.
void WriteToModuleFile(const char* fmt, va_list ap) {
    char tmp[MAX_PATH * 2] = {};
    GetModuleFileNameA(nullptr, tmp, MAX_PATH);
    char* dot = strrchr(tmp, '.');
    if (dot) strcpy_s(dot + 1, 8, "log");
    FILE* f = nullptr;
    if (fopen_s(&f, tmp, "a") != 0 || !f) return;
    vfprintf(f, fmt, ap);
    fputc('\n', f);
    fclose(f);
}

}  // namespace

void SetLogDirectory(const wchar_t* dir) {
    wchar_t next[MAX_PATH] = {};
    if (dir) {
        _snwprintf_s(next, _countof(next), _TRUNCATE,
                     L"%s\\v8inject.log", dir);
    }
    EnsureLogLock();
    // Whole-buffer replacement under the lock: a reader either sees the old
    // path or the new one, never a mixture.
    EnterCriticalSection(&g_logLock);
    memcpy(g_logPath, next, sizeof(g_logPath));
    LeaveCriticalSection(&g_logLock);
}

const wchar_t* GetLogPath() {
    // The pointer stays valid for this thread until the next call: callers
    // print it or hand it straight to the file APIs, while another thread may
    // replace the path at any moment.
    static thread_local wchar_t snapshot[MAX_PATH] = {};
    CopyLogPath(snapshot, _countof(snapshot));
    if (!snapshot[0]) wcscpy_s(snapshot, _countof(snapshot), L"(unset)");
    return snapshot;
}

void LogLine(const char* fmt, ...) {
    wchar_t path[MAX_PATH] = {};
    CopyLogPath(path, _countof(path));

    if (!path[0]) {
        EnsureLogLock();
        EnterCriticalSection(&g_logLock);
        va_list ap;
        va_start(ap, fmt);
        WriteToModuleFile(fmt, ap);
        va_end(ap);
        LeaveCriticalSection(&g_logLock);
        return;
    }

    // Build the whole line first, then append it in one WriteFile call: cheap,
    // crash-safe, and unaffected by CRT buffering.
    char line[2048] = {};
    SYSTEMTIME st{};
    GetLocalTime(&st);
    int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
                        "%02u:%02u:%02u.%03u [pid %5lu tid %5lu] ",
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                        GetCurrentProcessId(), GetCurrentThreadId());
    if (n > 0) {
        va_list ap;
        va_start(ap, fmt);
        int m = _vsnprintf_s(line + n, sizeof(line) - n, _TRUNCATE, fmt, ap);
        va_end(ap);
        if (m > 0) n += m;
        if (n < (int)sizeof(line) - 2) {
            line[n++] = '\r';
            line[n++] = '\n';
            line[n] = 0;
        }
    }

    EnsureLogLock();
    EnterCriticalSection(&g_logLock);
    WriteLineLocked(path, line, n);
    LeaveCriticalSection(&g_logLock);
}

void LogError(const char* what) {
    LogLine("%s failed, win32=%lu", what, GetLastError());
}

}  // namespace v8i
