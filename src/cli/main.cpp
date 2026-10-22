#include "v8inject/client.h"
#include "v8inject/diag.h"
#include "v8inject/injector.h"
#include "v8inject/pe_utils.h"
#include "v8inject/protocol.h"

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

void PrintUsage() {
    wprintf(L"v8inject - interact with a running process\n\n");
    wprintf(L"usage:\n");
    wprintf(L"  v8inject --help\n");
    wprintf(L"  v8inject modules <exe>\n");
    wprintf(L"  v8inject inject  <exe> [--dll <path>]\n");
    wprintf(L"  v8inject probe   <exe> [--dll <path>] [--timeout <ms>]\n");
    wprintf(L"  v8inject scan    <exe> <iunknown-addr-hex> [--module <name>] [--dll <path>]\n");
    wprintf(L"  v8inject objects <exe> [--dll <path>] [--timeout <ms>]\n");
    wprintf(L"  v8inject peek    <exe> <hex-addr> [len] [--dll <path>]\n");
    wprintf(L"  v8inject pe      <exe> [module] [--dll <path>]\n");
    wprintf(L"  v8inject find    <exe> <pattern> [--module <dll>] [--wide] [--max N]\n");
    wprintf(L"  v8inject disasm  <exe> [<hex-addr>] [--module <dll>]\n");
    wprintf(L"  v8inject imports <exe> <module> [filter]\n");
    wprintf(L"  v8inject exports <exe> <module> [filter]\n");
    wprintf(L"  v8inject mods    <exe> [filter] [--count N]\n");
    wprintf(L"  v8inject memmap  <exe> [--count N]\n");
    wprintf(L"  v8inject heapobjects <exe> [--module <dll>] [--count N]\n");
    wprintf(L"  v8inject findvalue <exe> <hex> [--count N] [--module <dll>]\n");
    wprintf(L"  v8inject byhwnd  <exe> <hwnd> [--module <dll>] [--offset 0x200]\n");
    wprintf(L"  v8inject around  <exe> <hex-addr> [--count N]\n");
    wprintf(L"  v8inject xref    <exe> <hex-addr|name> [--module <dll>] [--from A --to B] [--count N]\n");
    wprintf(L"  v8inject log     [--clear]\n\n");
    wprintf(L"examples:\n");
    wprintf(L"  v8inject probe 1cv8.exe\n");
    wprintf(L"  v8inject scan  1cv8.exe 0x1A2B3C4D --module 1cv8.exe\n");
    wprintf(L"  v8inject xref  1cv8.exe 0x140001234 --module 1cv8.exe --from 0x140000000 --to 0x140100000\n");
    wprintf(L"  v8inject byhwnd 1cv8.exe 0x1090C --offset 0x34\n");
}

std::wstring ExeDir() {
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring p(self);
    size_t pos = p.find_last_of(L'\\');
    return pos == std::wstring::npos ? std::wstring() : p.substr(0, pos + 1);
}

std::wstring DefaultPayloadPath() {
    return ExeDir() + L"v8i_payload.dll";
}

// Directory of the running executable: logs go next to v8inject.exe.
void InitHostLog() {
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    wchar_t* slash = wcsrchr(self, L'\\');
    if (slash) *slash = 0;
    v8i::SetLogDirectory(self);
    v8i::LogLine("---- v8inject started, pid=%lu arch=%s ----",
                 GetCurrentProcessId(), sizeof(void*) == 8 ? "x64" : "x86");
}

bool ParseHex(const wchar_t* s, uint64_t& out) {
    if (!s) return false;
    wchar_t* end = nullptr;
    unsigned long long v = wcstoull(s, &end, 0);
    if (end == s) return false;
    out = v;
    return true;
}

// Shared option parsing for inject/probe/scan.
struct Options {
    std::wstring dll;
    std::wstring module;
    int timeoutMs = 15000;
};

Options ParseOptions(int argc, wchar_t** argv, int first) {
    Options o;
    o.dll = DefaultPayloadPath();
    for (int i = first; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--dll" && i + 1 < argc)              o.dll = argv[++i];
        else if (a == L"--module" && i + 1 < argc)      o.module = argv[++i];
        else if (a == L"--timeout" && i + 1 < argc)     o.timeoutMs = _wtoi(argv[++i]);
    }
    return o;
}

// Console output must be wide: the payload speaks UTF-8, and %hs would try to
// interpret that as the active ANSI code page (866/1251), producing mojibake.
std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}

void PrintOpenFailure(v8i::Client& client, const Options& o) {
    wprintf(L"handshake failed\n  reason : %s\n  diag   : %ld\n"
            L"  stage  : %d  win32: %lu\n"
            L"  shared : %s\n  payload: %s\n",
            client.LastError(), client.LastDiag(),
            client.LastStage(), client.LastWin32Error(),
            client.SharedName(), o.dll.c_str());
    v8i::LogLine("handshake FAILED stage=%d win32=%lu diag=%ld",
                 client.LastStage(), client.LastWin32Error(), client.LastDiag());
    wprintf(L"log    : %ls\n", v8i::GetLogPath());
}

// A payload command that just forwards its argument string across the shared
// memory. The payload (not the CLI) owns the grammar, so the CLI's job is only
// to build the request line and print whatever JSON comes back.
int RunPayloadCommand(const wchar_t* cmdName, const wchar_t* exe,
                      int argc, wchar_t** argv, int first, int timeoutMs) {
    DWORD pid = v8i::FindProcessByName(exe);
    if (!pid) { wprintf(L"process not found: %s\n", exe); return 2; }

    Options o = ParseOptions(argc, argv, first);
    v8i::LogLine("%ls: target pid=%lu", cmdName, pid);

    // Rebuild the request verbatim from the trailing args, but strip the
    // CLI-level options (--dll / --timeout) the payload doesn't understand.
    // Everything else — positional args plus --module/--count/--offset/--from/
    // --to/--addr/--pattern — is the payload's concern and passes through.
    std::wstring request = cmdName;
    for (int i = first; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--dll" || a == L"--timeout") { ++i; continue; }
        request += L" ";
        request += a;
    }
    v8i::LogLine("%ls: request: %ls", cmdName, request.c_str());

    v8i::Client client;
    if (!client.Open(pid, o.dll, ExeDir(), o.timeoutMs)) {
        PrintOpenFailure(client, o);
        return 4;
    }
    std::string resp;
    bool ok = client.Call(request, resp, timeoutMs);
    wprintf(L"reply : %ls\n", ok ? Utf8ToWide(resp).c_str() : L"<no reply>");
    client.Close();
    return ok ? 0 : 5;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { PrintUsage(); return 1; }

    std::wstring cmd = argv[1];
    if (cmd == L"--help" || cmd == L"-h" || cmd == L"/?") { PrintUsage(); return 0; }

    // Everything below this point is a real session and gets logged.
    InitHostLog();

    // Windows console defaults to the OEM code page; switching to UTF-8 lets
    // Cyrillic window titles survive the trip from the payload.
    SetConsoleOutputCP(CP_UTF8);

    if (cmd == L"objects") {
        if (argc < 3) { PrintUsage(); return 1; }
        DWORD pid = v8i::FindProcessByName(argv[2]);
        if (!pid) { wprintf(L"process not found: %ls\n", argv[2]); return 2; }

        Options o = ParseOptions(argc, argv, 3);
        v8i::LogLine("objects: target pid=%lu", pid);

        v8i::Client client;
        if (!client.Open(pid, o.dll, ExeDir(), o.timeoutMs)) {
            PrintOpenFailure(client, o);
            return 4;
        }

        std::string resp;
        bool ok = client.Call(L"objects", resp, o.timeoutMs);
        wprintf(L"reply : %ls\n", ok ? Utf8ToWide(resp).c_str() : L"<no reply>");
        wprintf(L"log   : %ls\n", v8i::GetLogPath());
        client.Close();
        return ok ? 0 : 5;
    }

    if (cmd == L"find") {
        if (argc < 4) { PrintUsage(); return 1; }
        DWORD pid = v8i::FindProcessByName(argv[2]);
        if (!pid) { wprintf(L"process not found: %ls\n", argv[2]); return 2; }

        Options o = ParseOptions(argc, argv, 4);
        std::wstring request = L"find ";
        for (int i = 3; i < argc; ++i) {
            std::wstring a = argv[i];
            if (a == L"--dll" || a == L"--timeout") { ++i; continue; }
            request += a;
            request += L" ";
        }
        v8i::LogLine("request: %ls", request.c_str());

        v8i::Client client;
        if (!client.Open(pid, o.dll, ExeDir(), o.timeoutMs)) {
            PrintOpenFailure(client, o);
            return 4;
        }
        std::string resp;
        bool ok = client.Call(request, resp, 120000);
        wprintf(L"reply : %ls\n", ok ? Utf8ToWide(resp).c_str() : L"<no reply>");
        client.Close();
        return ok ? 0 : 5;
    }

    // Reverse-engineering commands forwarded verbatim to the payload. Each needs
    // at least the target process; the payload enforces its own argument count.
    if (cmd == L"disasm" || cmd == L"imports" || cmd == L"exports" || cmd == L"mods" ||
        cmd == L"memmap" || cmd == L"heapobjects" || cmd == L"findvalue" || cmd == L"byhwnd" ||
        cmd == L"around" || cmd == L"xref") {
        if (argc < 3) { PrintUsage(); return 1; }
        if (cmd == L"imports" && argc < 4) { PrintUsage(); return 1; }
        int timeout = (cmd == L"xref") ? 120000 : 15000;
        Options o = ParseOptions(argc, argv, 3);
        return RunPayloadCommand(cmd.c_str(), argv[2], argc, argv, 3, timeout);
    }

    if (cmd == L"peek" || cmd == L"pe") {
        if (argc < 3) { PrintUsage(); return 1; }
        DWORD pid = v8i::FindProcessByName(argv[2]);
        if (!pid) { wprintf(L"process not found: %ls\n", argv[2]); return 2; }

        Options o = ParseOptions(argc, argv, 3);
        std::wstring request;
        int next = 3;

        if (cmd == L"peek") {
            if (argc < 4) { PrintUsage(); return 1; }
            uint64_t addr = 0;
            if (!ParseHex(argv[3], addr)) { wprintf(L"bad address: %ls\n", argv[3]); return 1; }
            int len = 64;
            if (argc > 4 && argv[4][0] != L'-') { len = _wtoi(argv[4]); next = 5; }
            wchar_t buf[128] = {};
            _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"peek %llx %d",
                         (unsigned long long)addr, len);
            request = buf;
        } else {
            std::wstring mod;
            if (argc > 3 && argv[3][0] != L'-') { mod = argv[3]; next = 4; }
            request = L"pe";
            if (!mod.empty()) request += L" " + mod;
        }
        (void)next;
        v8i::LogLine("request: %ls", request.c_str());

        v8i::Client client;
        if (!client.Open(pid, o.dll, ExeDir(), o.timeoutMs)) {
            PrintOpenFailure(client, o);
            return 4;
        }
        std::string resp;
        bool ok = client.Call(request, resp, o.timeoutMs);
        wprintf(L"reply : %ls\n", ok ? Utf8ToWide(resp).c_str() : L"<no reply>");
        client.Close();
        return ok ? 0 : 5;
    }

    if (cmd == L"log") {
        bool clear = false;
        for (int i = 2; i < argc; ++i)
            if (std::wstring(argv[i]) == L"--clear") clear = true;

        if (clear) {
            _wremove(v8i::GetLogPath());
            wprintf(L"cleared: %ls\n", v8i::GetLogPath());
            return 0;
        }

        FILE* f = nullptr;
        if (_wfopen_s(&f, v8i::GetLogPath(), L"r") != 0 || !f) {
            wprintf(L"no log at %ls\n", v8i::GetLogPath());
            return 2;
        }
        char buf[4096];
        while (fgets(buf, sizeof(buf), f)) fputs(buf, stdout);
        fclose(f);
        return 0;
    }

    if (cmd == L"modules") {
        if (argc < 3) { PrintUsage(); return 1; }
        DWORD pid = v8i::FindProcessByName(argv[2]);
        if (!pid) { wprintf(L"process not found: %s\n", argv[2]); return 2; }
        wprintf(L"pid        : %lu\n", pid);
        wprintf(L"target x64 : %s\n", v8i::IsProcess64(pid) ? L"yes" : L"no");
        wprintf(L"host arch  : %s\n", sizeof(void*) == 8 ? L"x64" : L"x86");
        return 0;
    }

    if (cmd == L"inject") {
        if (argc < 3) { PrintUsage(); return 1; }
        DWORD pid = v8i::FindProcessByName(argv[2]);
        if (!pid) { wprintf(L"process not found: %s\n", argv[2]); return 2; }

        Options o = ParseOptions(argc, argv, 3);
        wprintf(L"pid=%lu payload=%s\n", pid, o.dll.c_str());
        if (!v8i::InjectLibrary(pid, o.dll)) {
            wprintf(L"inject failed (arch mismatch or insufficient rights)\n");
            return 3;
        }
        wprintf(L"injected ok\n");
        return 0;
    }

    if (cmd == L"probe") {
        if (argc < 3) { PrintUsage(); return 1; }
        DWORD pid = v8i::FindProcessByName(argv[2]);
        if (!pid) { wprintf(L"process not found: %s\n", argv[2]); return 2; }

        Options o = ParseOptions(argc, argv, 3);
        v8i::LogLine("probe: target pid=%lu payload=%ls timeout=%d",
                     pid, o.dll.c_str(), o.timeoutMs);

        v8i::Client client;
        if (!client.Open(pid, o.dll, ExeDir(), o.timeoutMs)) {
            PrintOpenFailure(client, o);
            return 4;
        }
        v8i::LogLine("probe: handshake ok, sending version");
        std::string resp;
        bool ok = client.Call(L"version", resp, o.timeoutMs);
        v8i::LogLine("probe: version reply ok=%d", (int)ok);
        wprintf(L"session    : %s\n", client.SharedName());
        wprintf(L"reply      : %ls\n", ok ? Utf8ToWide(resp).c_str() : L"<no reply>");
        wprintf(L"log        : %ls\n", v8i::GetLogPath());
        client.Close();
        return ok ? 0 : 5;
    }

    if (cmd == L"scan") {
        if (argc < 4) { PrintUsage(); return 1; }
        DWORD pid = v8i::FindProcessByName(argv[2]);
        if (!pid) { wprintf(L"process not found: %s\n", argv[2]); return 2; }

        uint64_t addr = 0;
        if (!ParseHex(argv[3], addr)) {
            wprintf(L"bad address: %s\n", argv[3]);
            return 1;
        }

        Options o = ParseOptions(argc, argv, 4);
        if (o.module.empty()) o.module = argv[2];
        v8i::LogLine("scan: target pid=%lu addr=%llx module=%ls",
                     pid, (unsigned long long)addr, o.module.c_str());

        v8i::Client client;
        if (!client.Open(pid, o.dll, ExeDir(), o.timeoutMs)) {
            wprintf(L"handshake failed\n  reason : %s\n  diag   : %ld\n"
                    L"  stage  : %d  win32: %lu\n"
                    L"  shared : %s\n  payload: %s\n",
                    client.LastError(), client.LastDiag(),
                    client.LastStage(), client.LastWin32Error(),
                    client.SharedName(), o.dll.c_str());
            v8i::LogLine("scan: handshake FAILED stage=%d win32=%lu diag=%ld",
                         client.LastStage(), client.LastWin32Error(), client.LastDiag());
            return 4;
        }

        wchar_t request[256] = {};
        _snwprintf_s(request, _countof(request), _TRUNCATE,
                     L"scan %s %llx", o.module.c_str(), (unsigned long long)addr);

        std::string resp;
        bool ok = client.Call(request, resp, o.timeoutMs);
        client.Close();

        if (!ok) { wprintf(L"no reply from payload\n"); return 5; }
        fwrite(resp.data(), 1, resp.size(), stdout);
        if (resp.empty() || resp.back() != '\n') fputc('\n', stdout);
        return 0;
    }

    PrintUsage();
    return 1;
}
