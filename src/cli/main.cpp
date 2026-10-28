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
    wprintf(L"  [--pid <n>] on any command targets that process exactly; otherwise the\n");
    wprintf(L"  first process with the given image name is used.\n\n");
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
    wprintf(L"  v8inject attach  <exe> [--dll <path>]          # interactive session, one command per line\n");
    wprintf(L"  v8inject hook    <exe> <addr|module!Export|module+0xRVA> [--name <text>]\n");
    wprintf(L"  v8inject hooks   <exe>\n");
    wprintf(L"  v8inject unhook  <exe> <id|all>\n");
    wprintf(L"  v8inject trace   <exe> [--count N] [--since N] [--clear]\n");
    wprintf(L"  v8inject watch   <exe> --dump-dir <path> --run <cmd> [--debounce-sec N]\n");
    wprintf(L"                             [--timeout-sec N] [--once] [--dry-run]\n");
    wprintf(L"                             # fires --run when a burst of CreateFileW on\n");
    wprintf(L"                             # --dump-dir quiets down (1C dump-to-files trigger)\n");
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

// Defined below RunWatch; declared here so the watch block can use them.
DWORD ResolvePid(int argc, wchar_t** argv, const wchar_t* exe);
void PrintOpenFailure(v8i::Client& client, const Options& o);

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

// Unpack the "value" field of a `str` reply: UTF-8 text with \" \\ \n \r \t
// and \uXXXX escapes. Returns the wide string.
std::wstring UnescapeStrValue(const std::string& v) {
    std::string raw;
    raw.reserve(v.size());
    for (size_t i = 0; i < v.size(); ++i) {
        char c = v[i];
        if (c != '\\' || i + 1 >= v.size()) { raw += c; continue; }
        char n = v[i + 1];
        switch (n) {
        case '"': raw += '"'; ++i; break;
        case '\\': raw += '\\'; ++i; break;
        case 'n': raw += '\n'; ++i; break;
        case 'r': raw += '\r'; ++i; break;
        case 't': raw += '\t'; ++i; break;
        case 'u': {
            if (i + 5 < v.size()) {
                unsigned cp = 0;
                for (int k = 1; k <= 4; ++k) {
                    char h = v[i + 1 + k];
                    cp <<= 4;
                    if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                    else { cp = 0; break; }
                }
                if (cp) {
                    char b3[3];
                    b3[0] = (char)(0xE0 | (cp >> 12));
                    b3[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    b3[2] = (char)(0x80 | (cp & 0x3F));
                    raw += b3[0]; raw += b3[1]; raw += b3[2];
                }
                i += 5;
            }
            break;
        }
        default: raw += c; break;
        }
    }
    return Utf8ToWide(raw);
}

// Normalize a path for prefix comparison: absolute, forward slashes, lowercase.
std::wstring NormalizePath(const std::wstring& p) {
    wchar_t full[MAX_PATH] = {};
    GetFullPathNameW(p.c_str(), MAX_PATH, full, nullptr);
    std::wstring out = full;
    for (wchar_t& c : out) {
        if (c == L'\\') c = L'/';
        c = towlower(c);
    }
    while (!out.empty() && out.back() == L'/') out.pop_back();
    return out;
}

// watch <exe> --dump-dir <path> --run <cmd> [--debounce-sec N] [--timeout-sec N]
//       [--once] [--dry-run]
//
// "1C dumped the config to files" trigger for the git pipeline. Attaches to the
// running configurator, hooks CreateFileW, polls the trace, decodes each new
// path argument via `str`, and waits for a burst of writes under --dump-dir to
// go quiet (--debounce-sec, default 8 s). Then it runs --run (any command
// line, e.g. a git commit script). With --once it fires exactly once and
// exits; without it, it rearms and keeps watching until --timeout-sec.
int RunWatch(int argc, wchar_t** argv) {
    if (argc < 3) {
        wprintf(L"usage: v8inject watch <exe> --dump-dir <path> --run <cmd> "
                L"[--debounce-sec N] [--timeout-sec N] [--once] [--dry-run]\n");
        return 1;
    }
    DWORD pid = ResolvePid(argc, argv, argv[2]);
    if (!pid) { wprintf(L"process not found: %ls\n", argv[2]); return 2; }

    std::wstring dumpDir, runCmd;
    int debounceMs = 8000, timeoutMs = 600000;
    bool once = false, dryRun = false;
    for (int i = 3; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--dump-dir" && i + 1 < argc) dumpDir = argv[++i];
        else if (a == L"--run" && i + 1 < argc) runCmd = argv[++i];
        else if (a == L"--debounce-sec" && i + 1 < argc) debounceMs = _wtoi(argv[++i]) * 1000;
        else if (a == L"--timeout-sec" && i + 1 < argc) timeoutMs = _wtoi(argv[++i]) * 1000;
        else if (a == L"--once") once = true;
        else if (a == L"--dry-run") dryRun = true;
    }
    if (dumpDir.empty() || runCmd.empty()) {
        wprintf(L"watch needs --dump-dir and --run\n");
        return 1;
    }
    if (debounceMs <= 0) debounceMs = 8000;
    if (timeoutMs <= 0) timeoutMs = 600000;

    Options o = ParseOptions(argc, argv, 3);
    v8i::Client client;
    if (!client.Open(pid, o.dll, ExeDir(), o.timeoutMs)) {
        PrintOpenFailure(client, o);
        return 4;
    }

    std::string resp;
    // A previous attach session can leave its payload (and hooks) resident:
    // hook ids are then not 1..N. Clear the slate so cfw gets id 1 and the
    // trace filter below stays correct.
    client.Call(L"unhook all", resp, 10000);
    if (!client.Call(L"hook kernel32.dll!CreateFileW --name cfw", resp, 30000) ||
        resp.find("\"status\":\"ok\"") == std::string::npos) {
        wprintf(L"watch: hook failed: %ls\n", Utf8ToWide(resp).c_str());
        client.Close();
        return 5;
    }
    // Parse the allocated hook id: it is 1 after unhook all, but read it
    // instead of assuming.
    size_t idPos = resp.find("\"id\":");
    LONG cfwId = (idPos != std::string::npos)
                     ? _wtol(Utf8ToWide(resp.substr(idPos + 5, 8)).c_str())
                     : 1;
    client.Call(L"trace --clear", resp, 10000);

    std::wstring needle = NormalizePath(dumpDir);
    wprintf(L"{\"status\":\"watching\",\"pid\":%lu,\"dumpDir\":\"%ls\",\"debounceMs\":%d,\"timeoutMs\":%d,%s}\n",
            pid, needle.c_str(), debounceMs, timeoutMs, once ? L"\"once\":true" : L"\"once\":false");
    fflush(stdout);

    struct PathCache { uintptr_t addr; std::wstring path; };
    std::vector<PathCache> cache;
    LONG lastSeq = 0;
    int matchCount = 0, fireCount = 0;
    ULONGLONG startTick = GetTickCount64();
    ULONGLONG lastActive = 0;
    bool fired = false;

    auto findPath = [&](uintptr_t addr) -> const std::wstring* {
        for (auto& c : cache)
            if (c.addr == addr) return &c.path;
        return nullptr;
    };
    auto decodePath = [&](uintptr_t addr) -> const std::wstring* {
        if (const std::wstring* p = findPath(addr)) return p;
        wchar_t req[64];
        _snwprintf_s(req, _countof(req), _TRUNCATE, L"str 0x%llX", (unsigned long long)addr);
        std::string r2;
        std::wstring path;
        if (client.Call(req, r2, 5000)) {
            size_t v = r2.find("\"value\":\"");
            if (v != std::string::npos) {
                std::string val = r2.substr(v + 9);
                // strip the closing "\"}
                size_t e = val.find_last_of('"');
                if (e != std::string::npos) val.erase(e);
                path = UnescapeStrValue(val);
            }
        }
        cache.push_back({addr, path});
        return &cache.back().path;
    };

    while (true) {
        ULONGLONG now = GetTickCount64();
        if (now - startTick > (ULONGLONG)timeoutMs) {
            wprintf(L"{\"status\":\"timeout\",\"matches\":%d,\"fired\":%d}\n", matchCount, fireCount);
            break;
        }

        wchar_t req[96];
        _snwprintf_s(req, _countof(req), _TRUNCATE, L"trace --since %ld", (long)lastSeq);
        if (!client.Call(req, resp, 10000)) {
            Sleep(250);
            continue;
        }

        // Walk the trace records: {"seq":N,"hook":H,...,"args":["0x..",...]}
        LONG maxSeq = lastSeq;
        bool any = false;
        size_t pos = 0;
        while ((pos = resp.find("\"seq\":", pos)) != std::string::npos) {
            pos += 6;
            LONG seq = _wtol(Utf8ToWide(resp.substr(pos, 16)).c_str());
            size_t h = resp.find("\"hook\":", pos);
            if (h == std::string::npos || h > pos + 40) break;
            LONG hook = _wtol(Utf8ToWide(resp.substr(h + 7, 8)).c_str());
            size_t a = resp.find("\"args\":[", h);
            if (a == std::string::npos || a > h + 60) break;
            size_t q1 = resp.find('"', a + 7);   // opening quote of args[0]
            if (q1 == std::string::npos) break;
            size_t q2 = resp.find('"', q1 + 1);  // closing quote of args[0]
            if (q2 == std::string::npos) break;
            std::string arg0 = resp.substr(q1 + 1, q2 - q1 - 1);
            if (seq > maxSeq) maxSeq = seq;
            any = true;

            if (hook == cfwId) {  // cfw: args[0] = path pointer
                uintptr_t addr = (uintptr_t)_wcstoui64(Utf8ToWide(arg0).c_str(), nullptr, 16);
                const std::wstring* p = decodePath(addr);
                if (p && !p->empty()) {
                    std::wstring np = NormalizePath(*p);
                    if (np.compare(0, needle.size(), needle) == 0 &&
                        np.size() > needle.size() && np[needle.size()] == L'/') {
                        ++matchCount;
                        lastActive = now;
                    }
                }
            }
            pos = q2;
        }
        if (any) lastSeq = maxSeq;

        ULONGLONG quiet = (lastActive == 0) ? 0 : now - lastActive;
        if (matchCount > 0 && !fired && quiet > (ULONGLONG)debounceMs) {
            fired = true;
            ++fireCount;
            wprintf(L"{\"status\":\"%s\",\"matches\":%d,\"command\":\"%ls\"}\n",
                    dryRun ? L"would-fire" : L"firing", matchCount, runCmd.c_str());
            fflush(stdout);
            if (!dryRun) {
                std::wstring cmdline = L"cmd.exe /S /C \"" + runCmd + L"\"";
                STARTUPINFOW si{ sizeof(si) };
                PROCESS_INFORMATION pi{};
                if (CreateProcessW(nullptr, &cmdline[0], nullptr, nullptr, FALSE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                    CloseHandle(pi.hThread);
                    // Let the command finish before we exit so the commit is
                    // complete; the dump is done, nothing depends on us.
                    WaitForSingleObject(pi.hProcess, 180000);
                    DWORD ec = 0;
                    GetExitCodeProcess(pi.hProcess, &ec);
                    CloseHandle(pi.hProcess);
                    wprintf(L"{\"status\":\"done\",\"exit\":%lu}\n", ec);
                    fflush(stdout);
                } else {
                    wprintf(L"{\"status\":\"error\",\"message\":\"cannot start command (win32 %lu)\"}\n",
                            GetLastError());
                    fflush(stdout);
                }
            }
            if (once) break;
            lastActive = 0;  // rearm for the next dump
        }
        Sleep(250);
    }

    client.Close();
    return 0;
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

// Target selection. A name picks the first process with that image; --pid picks
// one exactly, which matters when several instances of the same binary run (two
// 1cv8.exe windows, for instance).
DWORD ResolvePid(int argc, wchar_t** argv, const wchar_t* exe) {
    for (int i = 2; i + 1 < argc; ++i) {
        if (std::wstring(argv[i]) == L"--pid") {
            DWORD pid = (DWORD)_wtoi(argv[i + 1]);
            if (!pid) continue;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) {
                wprintf(L"cannot open pid %lu (win32 %lu)\n", pid, GetLastError());
                return 0;
            }
            CloseHandle(h);
            return pid;
        }
    }
    return v8i::FindProcessByName(exe);
}

// A payload command that just forwards its argument string across the shared
// memory. The payload (not the CLI) owns the grammar, so the CLI's job is only
// to build the request line and print whatever JSON comes back.
int RunPayloadCommand(const wchar_t* cmdName, const wchar_t* exe,
                      int argc, wchar_t** argv, int first, int timeoutMs) {
    DWORD pid = ResolvePid(argc, argv, exe);
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
        if (a == L"--dll" || a == L"--timeout" || a == L"--pid") { ++i; continue; }
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
        DWORD pid = ResolvePid(argc, argv, argv[2]);
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
        DWORD pid = ResolvePid(argc, argv, argv[2]);
        if (!pid) { wprintf(L"process not found: %ls\n", argv[2]); return 2; }

        Options o = ParseOptions(argc, argv, 4);
        std::wstring request = L"find ";
        for (int i = 3; i < argc; ++i) {
            std::wstring a = argv[i];
            if (a == L"--dll" || a == L"--timeout" || a == L"--pid") { ++i; continue; }
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
        cmd == L"around" || cmd == L"xref" ||
        cmd == L"gitbar" || cmd == L"cmdinfo" || cmd == L"exports85" || cmd == L"frames" ||
        cmd == L"hook" || cmd == L"hooks" || cmd == L"unhook" || cmd == L"trace") {
        if (argc < 3) { PrintUsage(); return 1; }
        if (cmd == L"imports" && argc < 4) { PrintUsage(); return 1; }
        int timeout = (cmd == L"xref") ? 120000 : 15000;
        Options o = ParseOptions(argc, argv, 3);
        return RunPayloadCommand(cmd.c_str(), argv[2], argc, argv, 3, timeout);
    }

    if (cmd == L"peek" || cmd == L"pe") {
        if (argc < 3) { PrintUsage(); return 1; }
        DWORD pid = ResolvePid(argc, argv, argv[2]);
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

    if (cmd == L"watch") {
        return RunWatch(argc, argv);
    }

    if (cmd == L"attach") {
        if (argc < 3) { PrintUsage(); return 1; }
        DWORD pid = ResolvePid(argc, argv, argv[2]);
        if (!pid) { wprintf(L"process not found: %ls\n", argv[2]); return 2; }

        Options o = ParseOptions(argc, argv, 3);
        v8i::Client client;
        if (!client.Open(pid, o.dll, ExeDir(), o.timeoutMs)) {
            PrintOpenFailure(client, o);
            return 4;
        }

        // One session, many commands: hooks stay installed for as long as this
        // loop runs, which is the whole point of the mode. `sleep <ms>` is
        // handled here, not in the payload, so a script can wait for the target
        // to call into a hook.
        wprintf(L"attached: %ls pid=%lu\n", client.SharedName(), pid);
        fflush(stdout);

        char line[4096];
        while (fgets(line, sizeof(line), stdin)) {
            std::wstring req = Utf8ToWide(line);
            // A piped stream may start with a UTF-8 BOM. Left in place it turns
            // the first command into "\uFEFFhook ...", which matches no command
            // prefix -- the payload answers "scan failed" and the command is
            // silently lost. This bit us in CI, where the runner's pipe
            // encoding differs from a local console's.
            if (!req.empty() && req[0] == 0xFEFF) req.erase(0, 1);
            while (!req.empty() && (req.back() == L'\n' || req.back() == L'\r' ||
                                    req.back() == L' ' || req.back() == L'\t')) {
                req.pop_back();
            }
            if (req.empty()) continue;
            if (req == L"exit" || req == L"quit") break;

            if (req.compare(0, 6, L"sleep ") == 0) {
                Sleep((DWORD)_wtoi(req.c_str() + 6));
                wprintf(L"{\"status\":\"ok\",\"slept\":true}\n");
                fflush(stdout);
                continue;
            }

            std::string resp;
            bool ok = client.Call(req, resp, 120000);
            wprintf(L"%ls\n", ok ? Utf8ToWide(resp).c_str() : L"<no reply>");
            fflush(stdout);
        }

        client.Close();
        return 0;
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
        DWORD pid = ResolvePid(argc, argv, argv[2]);
        if (!pid) { wprintf(L"process not found: %s\n", argv[2]); return 2; }
        wprintf(L"pid        : %lu\n", pid);
        wprintf(L"target x64 : %s\n", v8i::IsProcess64(pid) ? L"yes" : L"no");
        wprintf(L"host arch  : %s\n", sizeof(void*) == 8 ? L"x64" : L"x86");
        return 0;
    }

    if (cmd == L"launch") {
        // v8inject launch <exe> [args...] [--dll <path>]
        // Starts the target and injects the payload immediately, before 1C
        // creates its main window — the payload arms a WH_CBT hook in
        // v8i_probe, so the splash screen is still ahead.
        if (argc < 3) { PrintUsage(); return 1; }
        Options o = ParseOptions(argc, argv, 3);
        std::wstring exe = argv[2];
        std::wstring cmdline = L"\"" + exe + L"\"";
        for (int i = 3; i < argc; ++i) {
            std::wstring a = argv[i];
            if (a == L"--dll") { ++i; continue; }
            cmdline += L" ";
            cmdline += a;
        }
        wprintf(L"cmdline=[%s]\n", cmdline.c_str());
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessW(nullptr, &cmdline[0], nullptr, nullptr, FALSE,
                            0, nullptr, nullptr, &si, &pi)) {
            wprintf(L"launch failed: %lu\n", GetLastError());
            return 3;
        }
        // Injection goes through the Client (shared block + v8i_probe), the
        // only path that works on 8.5. Open() blocks until the payload answers,
        // which may not happen while 1C is still starting — the CBT hook is
        // armed before that, so the wait is harmless for the frame capture.
        v8i::Client client;
        bool ok = client.Open(pi.dwProcessId, o.dll, ExeDir(), o.timeoutMs);
        wprintf(L"launched pid=%lu inject=%s\n", pi.dwProcessId, ok ? L"ok" : L"FAILED");
        if (ok) client.Close();
        DWORD wait = WaitForSingleObject(pi.hProcess, 8000);
        if (wait == WAIT_OBJECT_0) {
            DWORD ec = 0;
            GetExitCodeProcess(pi.hProcess, &ec);
            wprintf(L"1C exited code=0x%08X\n", ec);
        } else {
            wprintf(L"1C alive after 8s\n");
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return ok ? 0 : 4;
    }

    if (cmd == L"inject") {
        if (argc < 3) { PrintUsage(); return 1; }
        DWORD pid = ResolvePid(argc, argv, argv[2]);
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
        DWORD pid = ResolvePid(argc, argv, argv[2]);
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
        DWORD pid = ResolvePid(argc, argv, argv[2]);
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
