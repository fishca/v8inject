#include "v8inject/diag.h"

#include <cstdlib>
#include <cstring>

#ifndef _countof
#define _countof(a) (sizeof(a) / sizeof((a)[0]))
#endif

namespace v8i {

namespace {
wchar_t  g_logPath[MAX_PATH] = {};
CRITICAL_SECTION g_cs;
bool     g_csReady = false;
}

void SetLogDirectory(const wchar_t* dir) {
    if (!g_csReady) {
        InitializeCriticalSection(&g_cs);
        g_csReady = true;
    }
    if (!dir) { g_logPath[0] = 0; return; }
    _snwprintf_s(g_logPath, _countof(g_logPath), _TRUNCATE,
                 L"%s\\v8inject.log", dir);
}

const wchar_t* GetLogPath() {
    return g_logPath[0] ? g_logPath : L"(unset)";
}

void LogLine(const char* fmt, ...) {
    if (!g_logPath[0]) {
        // No path configured: still write something so the failure is visible.
        char tmp[MAX_PATH * 2] = {};
        GetModuleFileNameA(nullptr, tmp, MAX_PATH);
        char* dot = strrchr(tmp, '.');
        if (dot) strcpy_s(dot + 1, 8, "log");
        FILE* f = nullptr;
        if (fopen_s(&f, tmp, "a") != 0 || !f) return;
        va_list ap;
        va_start(ap, fmt);
        vfprintf(f, fmt, ap);
        va_end(ap);
        fputc('\n', f);
        fclose(f);
        return;
    }

    EnterCriticalSection(&g_cs);
    FILE* f = nullptr;
    if (_wfopen_s(&f, g_logPath, L"a") == 0 && f) {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        fprintf(f, "%02u:%02u:%02u.%03u [pid %5lu tid %5lu] ",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                GetCurrentProcessId(), GetCurrentThreadId());
        va_list ap;
        va_start(ap, fmt);
        vfprintf(f, fmt, ap);
        va_end(ap);
        fputc('\n', f);
        fclose(f);
    }
    LeaveCriticalSection(&g_cs);
}

void LogError(const char* what) {
    LogLine("%s failed, win32=%lu", what, GetLastError());
}

}  // namespace v8i
