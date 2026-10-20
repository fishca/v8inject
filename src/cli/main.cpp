#include "v8inject/injector.h"
#include "v8inject/pe_utils.h"

#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>

namespace {

struct SharedIo {
    volatile LONG ready;
    volatile LONG requestLen;
    volatile LONG responseLen;
    wchar_t       request[4096];
    char          response[1024 * 512];
};

void PrintUsage() {
    wprintf(L"v8inject — inject a payload DLL into a running process\n\n");
    wprintf(L"usage:\n");
    wprintf(L"  v8inject --help\n");
    wprintf(L"  v8inject inject <exe> [--dll <path>]\n");
    wprintf(L"  v8inject modules <exe>\n\n");
    wprintf(L"examples:\n");
    wprintf(L"  v8inject modules 1cv8.exe\n");
    wprintf(L"  v8inject inject 1cv8.exe --dll bin\\x64\\v8i_payload.dll\n");
}

std::wstring DefaultPayloadPath() {
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring p(self);
    size_t pos = p.find_last_of(L'\\');
    if (pos != std::wstring::npos) p.resize(pos + 1);
#if defined(_WIN64)
    p += L"v8i_payload.dll";
#else
    p += L"v8i_payload.dll";
#endif
    return p;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { PrintUsage(); return 1; }

    std::wstring cmd = argv[1];
    if (cmd == L"--help" || cmd == L"-h" || cmd == L"/?") { PrintUsage(); return 0; }

    if (cmd == L"modules") {
        if (argc < 3) { PrintUsage(); return 1; }
        DWORD pid = v8i::FindProcessByName(argv[2]);
        if (!pid) { wprintf(L"process not found: %s\n", argv[2]); return 2; }
        wprintf(L"pid          : %lu\n", pid);
        wprintf(L"is64         : %s\n", v8i::IsProcess64(pid) ? L"yes" : L"no");
        wprintf(L"host arch    : %s\n", sizeof(void*) == 8 ? L"x64" : L"x86");
        return 0;
    }

    if (cmd == L"inject") {
        if (argc < 3) { PrintUsage(); return 1; }
        DWORD pid = v8i::FindProcessByName(argv[2]);
        if (!pid) { wprintf(L"process not found: %s\n", argv[2]); return 2; }
        wprintf(L"pid=%lu\n", pid);

        std::wstring dll = DefaultPayloadPath();
        for (int i = 3; i + 1 < argc; ++i)
            if (std::wstring(argv[i]) == L"--dll") dll = argv[i + 1];

        wprintf(L"payload: %s\n", dll.c_str());
        if (!v8i::InjectLibrary(pid, dll)) {
            wprintf(L"inject failed (check arch match and privileges)\n");
            return 3;
        }
        wprintf(L"injected ok\n");
        return 0;
    }

    PrintUsage();
    return 1;
}
