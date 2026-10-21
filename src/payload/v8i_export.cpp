#include "v8inject/diag.h"
#include "v8inject/v8i_export.h"
#include "v8inject/objects.h"
#include "v8inject/memscan.h"
#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"
#include "v8inject/protocol.h"
#include "v8inject/typeinfo_utils.h"
#include "v8inject/report.h"

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

using namespace v8i;

namespace {

SharedIo* g_io = nullptr;

// Log folder comes from the shared block, so host and payload always agree.
void InitPayloadLog(const wchar_t* dirFromBlock) {
    if (dirFromBlock && dirFromBlock[0]) {
        SetLogDirectory(dirFromBlock);
        return;
    }
    // Fallback: next to the payload DLL itself.
    HMODULE me = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)&InitPayloadLog, &me) && me) {
        wchar_t self[MAX_PATH] = {};
        GetModuleFileNameW(me, self, MAX_PATH);
        wchar_t* slash = wcsrchr(self, L'\\');
        if (slash) *slash = 0;
        SetLogDirectory(self);
    }
}

// JSON-escape into UTF-8; window titles are often Cyrillic.
std::string EscapeW(const std::wstring& w) {
    std::string out;
    out.reserve(w.size());
    for (wchar_t ch : w) {
        unsigned c = (unsigned)ch;
        switch (ch) {
        case L'"':  out += "\\\""; break;
        case L'\\': out += "\\\\"; break;
        case L'\n': out += "\\n"; break;
        case L'\r': out += "\\r"; break;
        case L'\t': out += "\\t"; break;
        default:
            if (c < 0x20) { char b[8]; _snprintf_s(b, sizeof(b), _TRUNCATE, "\\u%04x", c); out += b; }
            else if (c < 0x80) out += (char)c;
            else if (c < 0x800) { out += (char)(0xC0 | (c >> 6)); out += (char)(0x80 | (c & 0x3F)); }
            else { out += (char)(0xE0 | (c >> 12)); out += (char)(0x80 | ((c >> 6) & 0x3F)); out += (char)(0x80 | (c & 0x3F)); }
        }
    }
    return out;
}

// Reads raw bytes at an address inside this process. Read-only: nothing is
// executed and no pointers are followed beyond classifying the first qword.
std::string PeekToJson(const std::wstring& args) {
    uintptr_t addr = 0;
    int count = 64;
    const wchar_t* p = args.c_str();
    if (swscanf_s(p, L"%llx %d", (unsigned long long*)&addr, &count) < 1) {
        return "{\"status\":\"error\",\"message\":\"usage: peek <hex-addr> [len]\"}";
    }
    if (count <= 0) count = 64;
    if (count > 4096) count = 4096;

    char head[128];
    _snprintf_s(head, sizeof(head), _TRUNCATE,
                "{\"status\":\"ok\",\"address\":\"0x%llX\",\"bytes\":%d,\"data\":\"",
                (unsigned long long)addr, count);
    std::string j = head;

    unsigned char buf[64] = {};
    bool anyRead = false;
    for (int off = 0; off < count; off += (int)sizeof(buf)) {
        int chunk = count - off;
        if (chunk > (int)sizeof(buf)) chunk = (int)sizeof(buf);
        if (!IsReadable((const void*)(addr + off), (size_t)chunk)) break;
        memcpy(buf, (const void*)(addr + off), (size_t)chunk);
        anyRead = true;
        for (int i = 0; i < chunk; ++i) {
            char h[4];
            _snprintf_s(h, sizeof(h), _TRUNCATE, "%02X", buf[i]);
            j += h;
        }
    }
    if (!anyRead) return "{\"status\":\"error\",\"message\":\"unreadable address\"}";
    j += "\"";

    // If the first qword looks like a vtable pointer, say which module owns it.
    if (IsReadable((const void*)addr, sizeof(uintptr_t))) {
        uintptr_t first = *(const uintptr_t*)addr;
        char vb[96];
        _snprintf_s(vb, sizeof(vb), _TRUNCATE, ",\"firstQword\":\"0x%llX\"",
                    (unsigned long long)first);
        j += vb;
        for (const ModuleRange& m : EnumModules()) {
            if (first >= m.base && first < m.base + m.size) {
                const wchar_t* f = wcsrchr(m.path.c_str(), L'\\\\');
                j += ",\"inModule\":\"" + EscapeW(f ? f + 1 : m.path) + "\"";
                _snprintf_s(vb, sizeof(vb), _TRUNCATE, ",\"moduleRva\":\"0x%llX\"",
                            (unsigned long long)(first - m.base));
                j += vb;
                break;
            }
        }
        // A vtable pointer inside an image base is a strong hint that the value
        // is a C++ object; PE headers at that address confirm it.
        PeImage probe = ParsePe(first);
        if (probe.valid) j += ",\"firstQwordIsPeImage\":true";
    }
    j += "}";
    return j;
}

std::string PeToJson(const std::wstring& args) {
    std::wstring name = args;
    while (!name.empty() && (name.back() == L' ' || name.back() == L'\t')) name.pop_back();
    size_t start = 0;
    while (start < name.size() && (name[start] == L' ' || name[start] == L'\t')) ++start;
    name = name.substr(start);

    ModuleRange m;
    if (name.empty()) {
        // Default to the executable itself; in 1C that is 1cv8.exe regardless of
        // how the file was renamed on disk.
        HMODULE mainBase = GetModuleHandleW(nullptr);
        m.base = (uintptr_t)mainBase;
        for (const ModuleRange& cand : EnumModules()) {
            if (cand.base == m.base) { m = cand; break; }
        }
    } else {
        FindModule(name.c_str(), m);
    }
    if (!m.base) return "{\"status\":\"error\",\"message\":\"module not found\"}";

    PeImage img = ParsePe(m.base);
    if (!img.valid) return "{\"status\":\"error\",\"message\":\"" + img.error + "\"}";

    const wchar_t* fname = wcsrchr(m.path.c_str(), L'\\\\');
    char buf[256];

    std::string j = "{\"status\":\"ok\",\"module\":\"" + EscapeW(fname ? fname + 1 : m.path) + "\"";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                ",\"base\":\"0x%llX\",\"sizeOfImage\":%u,\"machine\":\"%s\",\"entryPoint\":\"0x%llX\"",
                (unsigned long long)img.base, img.sizeOfImage, img.MachineName().c_str(),
                (unsigned long long)(img.base + img.entryPointRva));
    j += buf;

    j += ",\"sections\":[";
    for (size_t i = 0; i < img.sections.size(); ++i) {
        const PeSection& s = img.sections[i];
        if (i) j += ",";
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"name\":\"%s\",\"rva\":\"0x%X\",\"va\":\"0x%llX\",\"vsize\":%u,\"raw\":%u,"
                    "\"flags\":\"%s%s%s\"}",
                    s.name.c_str(), s.va, (unsigned long long)(img.base + s.va),
                    s.virtualSize, s.rawSize,
                    s.Readable() ? "R" : "-", s.Writable() ? "W" : "-",
                    s.Executable() ? "X" : "-");
        j += buf;
    }
    j += "]";

    j += ",\"exportCount\":" + std::to_string(img.exports.size());
    j += ",\"exports\":[";
    size_t shown = 0;
    for (const PeExport& e : img.exports) {
        if (shown++) j += ",";
        if (shown > 200) break;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"name\":\"%s\",\"rva\":\"0x%X\",\"va\":\"0x%llX\",\"ordinal\":%u%s%s%s}",
                    e.name.c_str(), e.rva, (unsigned long long)(img.base + e.rva), e.ordinal,
                    e.forwarded ? ",\"forwarded\":true,\"to\":\"" : "",
                    e.forwarded ? e.forwarder.c_str() : "",
                    e.forwarded ? "\"" : "");
        j += buf;
    }
    j += "]";

    // Only the module names: a full list with bases overflows the response
    // buffer and hides the interesting fields.
    j += ",\"moduleCount\":" + std::to_string(EnumModules().size());
    j += "]}";
    return j;
}

// find <pattern> [--module <dll>] [--wide] [--max N]
std::string FindToJson(const std::wstring& args) {
    v8i::FindOptions opt;
    std::wstring rest = args;

    auto takeToken = [](std::wstring& in) -> std::wstring {
        while (!in.empty() && in.front() == L' ') in.erase(in.begin());
        if (in.empty()) return std::wstring();
        if (in.front() == L'"') {
            size_t end = in.find(L'"', 1);
            if (end == std::wstring::npos) { std::wstring all = in.substr(1); in.clear(); return all; }
            std::wstring tok = in.substr(1, end - 1);
            in.erase(0, end + 1);
            return tok;
        }
        size_t sp = in.find(L' ');
        std::wstring tok = sp == std::wstring::npos ? in : in.substr(0, sp);
        in = sp == std::wstring::npos ? std::wstring() : in.substr(sp);
        return tok;
    };

    std::wstring first = takeToken(rest);
    if (first.empty()) {
        return "{\"status\":\"error\",\"message\":\"usage: find <pattern> [--module <dll>] [--wide] [--max N]\"}";
    }
    opt.pattern = first;

    for (;;) {
        std::wstring tok = takeToken(rest);
        if (tok.empty()) break;
        if (tok == L"--module")      opt.module = takeToken(rest);
        else if (tok == L"--wide")   opt.wide = true;
        else if (tok == L"--max")    opt.maxHits = (size_t)_wtoi(takeToken(rest).c_str());
        else if (tok == L"--first")  opt.stopAtFirst = true;
    }
    if (opt.maxHits == 0) opt.maxHits = 64;

    size_t scanned = 0;
    std::vector<MemoryHit> hits = FindInMemory(opt, &scanned);

    char buf[256];
    std::string j = "{\"status\":\"ok\",\"pattern\":\"" + EscapeW(opt.pattern) + "\"";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                ",\"wide\":%s,\"scannedBytes\":%llu,\"hitCount\":%zu,\"hits\":[",
                opt.wide ? "true" : "false", (unsigned long long)scanned, hits.size());
    j += buf;

    size_t shown = 0;
    for (const MemoryHit& h : hits) {
        if (shown++) j += ",";
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "{\"address\":\"0x%llX\"",
                    (unsigned long long)h.address);
        j += buf;
        if (h.inModule) j += ",\"module\":\"" + EscapeW(h.module) + "\"";
        if (!h.bytesBefore.empty()) j += ",\"before\":\"" + h.bytesBefore + "\"";
        if (!h.bytesAfter.empty())  j += ",\"after\":\"" + h.bytesAfter + "\"";
        j += "}";
    }
    j += "]}";
    return j;
}

std::string ObjectsToJson() {
    std::vector<WindowEntry> wins = EnumProcessWindows();
    std::string j = "{\"status\":\"ok\",\"windows\":[";
    bool first = true;
    for (const WindowEntry& w : wins) {
        if (!first) j += ",";
        first = false;
        char num[32];
        _snprintf_s(num, sizeof(num), _TRUNCATE, "%llX", (unsigned long long)(uintptr_t)w.hwnd);
        j += "{\"hwnd\":\"0x"; j += num; j += "\"";
        j += ",\"class\":\"" + EscapeW(w.cls) + "\"";
        j += ",\"title\":\"" + EscapeW(w.title) + "\"";
        _snprintf_s(num, sizeof(num), _TRUNCATE, "%llX", (unsigned long long)w.userData);
        j += ",\"userdata\":\"0x"; j += num; j += "\"";
        j += std::string(",\"readable\":") + (w.readable ? "true" : "false");
        j += "}";
    }
    j += "]}";
    return j;
}

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
    if (!sharedName) return -1;

    HANDLE hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sharedName);
    if (!hMap) {
        InitPayloadLog(nullptr);
        LogLine("OpenFileMapping(%ls) failed, win32=%lu", sharedName, GetLastError());
        return -2;
    }

    g_io = (SharedIo*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
    if (!g_io) { CloseHandle(hMap); return -3; }

    InitPayloadLog(g_io->logDir);
    LogLine("RunPayload started, pid=%lu arch=%s", GetCurrentProcessId(),
            sizeof(void*) == 8 ? "x64" : "x86");
    LogLine("MapViewOfFile -> %p", (void*)g_io);

    // Report readiness before anything that can fail.
    PutResponse("{\"status\":\"loaded\"}");

    LogLine("waiting for commands, ready=%ld", (long)g_io->ready);
    for (;;) {
        LONG state = g_io->ready;
        if (state == kStateExit) break;
        if (state != kStateRequest) {
            Sleep(15);
            continue;
        }
        LogLine("command received: %ls (ready=%ld)", g_io->request, (long)state);
        if (wcscmp(g_io->request, L"exit") == 0) break;

        if (wcscmp(g_io->request, L"version") == 0) {
            char buf[128] = {};
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "{\"status\":\"ok\",\"api\":%d,\"pointerSize\":%d}",
                        v8i_version(), (int)sizeof(void*));
            PutResponse(buf);
            continue;
        }

        if (wcsncmp(g_io->request, L"find ", 5) == 0) {
            LogLine("find: starting scan");
            PutResponse(FindToJson(std::wstring(g_io->request + 5)));
            LogLine("find: done");
            continue;
        }

        if (wcsncmp(g_io->request, L"peek ", 5) == 0) {
            PutResponse(PeekToJson(std::wstring(g_io->request + 5)));
            continue;
        }

        if (wcsncmp(g_io->request, L"pe", 2) == 0) {
            const wchar_t* arg = g_io->request + 2;
            while (*arg == L' ') ++arg;
            PutResponse(PeToJson(std::wstring(arg)));
            continue;
        }

        if (wcscmp(g_io->request, L"objects") == 0) {
            LogLine("objects: enumerating windows");
            PutResponse(ObjectsToJson());
            continue;
        }

        TypeInfoReport rep;
        if (!RunScan(g_io->request, rep)) {
            PutResponse("{\"status\":\"error\",\"message\":\"scan failed\"}");
            continue;
        }
        PutResponse(ToJson(rep));
        LogLine("response sent, %zu bytes", rep.funcs.size());
    }

    InterlockedExchange((volatile LONG*)&g_io->ready, kStateExit);
    UnmapViewOfFile(g_io);
    CloseHandle(hMap);
    g_io = nullptr;
    return 0;
}

// The host starts this on a remote thread. The shared-memory name is derived
// from our own PID, so nothing has to be marshalled across the process
// boundary: a bad pointer in a remote thread is the classic way to lose the
// argument, and we do not need one at all.
V8I_API int V8I_CALL v8i_probe(const wchar_t* /*ignored*/) {
    InitPayloadLog(nullptr);          // provisional, refined after mapping

    wchar_t name[64] = {};
    _snwprintf_s(name, _countof(name), _TRUNCATE, L"Local\\v8inject.%lu",
                 GetCurrentProcessId());
    LogLine("v8i_probe entered, pid=%lu block=%ls",
            GetCurrentProcessId(), name);

    // Run the session inline on this thread. The host owns and closes the
    // remote thread, and keeping the work here means no second thread has to
    // be created inside a process we do not control.
    int rc = RunPayload(name);
    LogLine("v8i_probe leaving, rc=%d", rc);
    return rc;
}

