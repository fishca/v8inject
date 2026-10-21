#include "v8inject/v8i_export.h"
#include "v8inject/pe_utils.h"
#include "v8inject/protocol.h"
#include "v8inject/typeinfo_utils.h"
#include "v8inject/report.h"

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

// Uncomment to write a trace to %TEMP%\v8i_payload.log when debugging.
#define V8I_DEBUG_LOG 1

using namespace v8i;

namespace {

SharedIo* g_io = nullptr;

#ifdef V8I_DEBUG_LOG
void DbgLog(const char* fmt, ...) {
    char path[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, path);
    strcat_s(path, "v8i_payload.log");
    FILE* f = nullptr;
    if (fopen_s(&f, path, "a") == 0 && f) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(f, fmt, ap);
        va_end(ap);
        fputc('\n', f);
        fclose(f);
    }
}
#else
inline void DbgLog(const char*, ...) {}
#endif

void PutResponse(const std::string& json) {
    if (!g_io) return;
    size_t n = json.size();
    if (n > kResponseBytes - 1) n = kResponseBytes - 1;
    memcpy(g_io->response, json.data(), n);
    g_io->response[n] = 0;
    InterlockedExchange((volatile LONG*)&g_io->responseLen, (LONG)n);
    InterlockedExchange((volatile LONG*)&g_io->ready, kStateResponse);
}

// SEH helper: __try cannot live in a function that needs C++ unwinding,
// so the guarded call is isolated in a POD-only function.
HRESULT ScanGuarded(ITypeInfo* ti, TypeInfoReport* rep) {
    HRESULT hr = E_UNEXPECTED;
    __try {
        hr = ScanTypeInfo(ti, *rep);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hr = E_UNEXPECTED;
    }
    return hr;
}

// "scan <moduleName> <addrHex>"
bool RunScan(const wchar_t* cmd, TypeInfoReport& rep) {
    wchar_t moduleName[64] = {};
    unsigned long long addr = 0;
    int matched = swscanf_s(cmd, L"scan %63s %llx", moduleName,
                            (unsigned)_countof(moduleName), &addr);
    if (matched != 2) return false;

    ModuleRange mr;
    if (!FindModule(moduleName, mr)) return false;

    rep.moduleName = moduleName;
    rep.moduleBase = mr.base;

    void* p = (void*)(uintptr_t)addr;
    if (!IsReadable(p, sizeof(void*))) return false;

    IUnknown* unk = (IUnknown*)p;
    ITypeInfo* ti = nullptr;
    if (FAILED(GetTypeInfoFromUnknown(unk, &ti)) || !ti) return false;

    HRESULT hr = ScanGuarded(ti, &rep);
    ti->Release();
    return SUCCEEDED(hr);
}

}  // namespace

V8I_API int V8I_CALL v8i_version() {
    return 1;
}

static int RunPayload(const wchar_t* sharedName) {
    DbgLog("RunPayload entered, pid=%lu sharedName=%ls", GetCurrentProcessId(),
           sharedName ? sharedName : L"(null)");
    if (!sharedName) return -1;

    HANDLE hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sharedName);
    DbgLog("OpenFileMapping -> %p err=%lu", (void*)hMap, GetLastError());
    if (!hMap) return -2;

    g_io = (SharedIo*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
    DbgLog("MapViewOfFile -> %p err=%lu", (void*)g_io, GetLastError());
    if (!g_io) { CloseHandle(hMap); return -3; }

    // Report readiness before anything that can fail.
    PutResponse("{\"status\":\"loaded\"}");

    for (;;) {
        LONG state = g_io->ready;
        if (state == kStateExit) break;
        if (state != kStateRequest) {
            Sleep(15);
            continue;
        }
        if (wcscmp(g_io->request, L"exit") == 0) break;

        if (wcscmp(g_io->request, L"version") == 0) {
            char buf[128] = {};
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "{\"status\":\"ok\",\"api\":%d,\"pointerSize\":%d}",
                        v8i_version(), (int)sizeof(void*));
            PutResponse(buf);
            continue;
        }

        TypeInfoReport rep;
        if (!RunScan(g_io->request, rep)) {
            PutResponse("{\"status\":\"error\",\"message\":\"scan failed\"}");
            continue;
        }
        PutResponse(ToJson(rep));
    }

    InterlockedExchange((volatile LONG*)&g_io->ready, kStateExit);
    UnmapViewOfFile(g_io);
    CloseHandle(hMap);
    g_io = nullptr;
    return 0;
}

struct WorkerArgs {
    wchar_t name[64];
};

static DWORD WINAPI WorkerProc(LPVOID param) {
    auto* args = (WorkerArgs*)param;
    RunPayload(args->name);
    return 0;
}

// The host starts this on a remote thread. We immediately hand the work to our
// own thread and keep the caller blocked, so the payload keeps running even
// though the host opened that thread with default settings.
V8I_API int V8I_CALL v8i_probe(const wchar_t* sharedName) {
    DbgLog("v8i_probe entered, pid=%lu", GetCurrentProcessId());

    WorkerArgs args{};
    if (sharedName) {
        wcsncpy_s(args.name, _countof(args.name), sharedName, _TRUNCATE);
    }

    HANDLE hWorker = CreateThread(nullptr, 0, WorkerProc, &args, 0, nullptr);
    if (hWorker) {
        DbgLog("worker thread created %p", (void*)hWorker);
        // Block the remote thread forever; the worker owns the session.
        WaitForSingleObject(hWorker, INFINITE);
        CloseHandle(hWorker);
    } else {
        DbgLog("CreateThread failed err=%lu", GetLastError());
        RunPayload(args.name);   // fall back to running inline
    }
    return 0;
}
