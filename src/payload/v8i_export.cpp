#include "v8inject/v8i_export.h"
#include "v8inject/pe_utils.h"
#include "v8inject/typeinfo_utils.h"
#include "v8inject/report.h"

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>

using namespace v8i;

namespace {

// Shared block layout between host and payload. Must stay plain-old-data.
struct SharedIo {
    volatile LONG ready;        // 0 = idle, 1 = request, 2 = response
    volatile LONG requestLen;
    volatile LONG responseLen;
    wchar_t       request[4096];
    char          response[1024 * 512];
};

SharedIo* g_io = nullptr;

void PutResponse(const std::string& json) {
    if (!g_io) return;
    size_t n = json.size();
    if (n > sizeof(g_io->response) - 1) n = sizeof(g_io->response) - 1;
    memcpy(g_io->response, json.data(), n);
    g_io->response[n] = 0;
    InterlockedExchange(&g_io->responseLen, (LONG)n);
    InterlockedExchange(&g_io->ready, 2);
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

V8I_API int V8I_CALL v8i_probe(const wchar_t* sharedName) {
    if (!sharedName) return -1;

    HANDLE hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sharedName);
    if (!hMap) return -2;

    g_io = (SharedIo*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
    if (!g_io) { CloseHandle(hMap); return -3; }

    PutResponse("{\"status\":\"loaded\"}");

    for (;;) {
        if (InterlockedCompareExchange(&g_io->ready, 1, 1) != 1) {
            Sleep(20);
            continue;
        }
        if (wcscmp(g_io->request, L"exit") == 0) break;

        TypeInfoReport rep;
        if (!RunScan(g_io->request, rep)) {
            PutResponse("{\"status\":\"error\",\"message\":\"scan failed\"}");
            continue;
        }
        PutResponse(ToJson(rep));
    }

    UnmapViewOfFile(g_io);
    CloseHandle(hMap);
    g_io = nullptr;
    return 0;
}
