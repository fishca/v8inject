#include "v8inject/diag.h"
#include "v8inject/v8i_export.h"
#include "v8inject/objects.h"
#include "v8inject/disasm.h"
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
    {
        // Base-0 parse: addresses pasted from the UI are plain hex without 0x.
        wchar_t token[64] = {};
        int want = 64;
        if (swscanf_s(args.c_str(), L"%63ls %d", token, (unsigned)_countof(token), &want) < 1) {
            return "{\"status\":\"error\",\"message\":\"usage: peek <hex-addr> [len]\"}";
        }
        addr = (uintptr_t)_wcstoui64(token, nullptr, 16);
        count = want;
    }
    if (count <= 0) count = 64;
    if (count > 4096) count = 4096;

    char head[160];
    _snprintf_s(head, sizeof(head), _TRUNCATE,
                "{\"status\":\"ok\",\"address\":\"0x%llX\",\"bytes\":%d,\"data\":\"",
                (unsigned long long)addr, count);
    std::string j = head;

    // One byte at a time: a partially readable block is more informative than a
    // flat "unreadable", and a failed chunk must not hide the rest.
    unsigned char buf[64] = {};
    int got = 0;
    for (int off = 0; off < count; off += (int)sizeof(buf)) {
        int chunk = count - off;
        if (chunk > (int)sizeof(buf)) chunk = (int)sizeof(buf);
        if (!IsReadable((const void*)(addr + off), (size_t)chunk)) break;
        memcpy(buf, (const void*)(addr + off), (size_t)chunk);
        got += chunk;
        for (int i = 0; i < chunk; ++i) {
            char h[4];
            _snprintf_s(h, sizeof(h), _TRUNCATE, "%02X", buf[i]);
            j += h;
        }
    }
    if (got == 0) {
        char why[256];
        _snprintf_s(why, sizeof(why), _TRUNCATE,
                    "{\"status\":\"error\",\"message\":\"unreadable address\","
                    "\"address\":\"0x%llX\",\"hint\":%s}",
                    (unsigned long long)addr,
                    IsReadable((const void*)addr, 1)
                        ? "\"region readable but shorter than requested\""
                        : "\"region not committed or not readable\"");
        return why;
    }
    {
        char tail[64];
        _snprintf_s(tail, sizeof(tail), _TRUNCATE, "\",\"readableBytes\":%d", got);
        j += tail;
    }

    if (IsReadable((const void*)addr, sizeof(uintptr_t))) {
        uintptr_t first = *(const uintptr_t*)addr;
        char vb[128];
        _snprintf_s(vb, sizeof(vb), _TRUNCATE, ",\"firstQword\":\"0x%llX\"",
                    (unsigned long long)first);
        j += vb;
        for (const ModuleRange& m : EnumModules()) {
            if (first >= m.base && first < m.base + m.size) {
                const wchar_t* f = wcsrchr(m.path.c_str(), L'\\');
                j += ",\"inModule\":\"" + EscapeW(f ? f + 1 : m.path) + "\"";
                _snprintf_s(vb, sizeof(vb), _TRUNCATE, ",\"moduleRva\":\"0x%llX\"",
                            (unsigned long long)(first - m.base));
                j += vb;
                break;
            }
        }
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

// ---------------------------------------------------------------------------
// Reverse-engineering commands: disasm / xref / imports / iat
// ---------------------------------------------------------------------------

namespace {

struct ReArgs {
    std::wstring module;
    uintptr_t    addr = 0;
    uintptr_t    from = 0;
    uintptr_t    to = 0;
    size_t       count = 64;
    bool         haveAddr = false;
    bool         haveFrom = false;
    bool         haveTo = false;
    std::wstring pattern;
};

std::wstring NextToken(std::wstring& in) {
    while (!in.empty() && in.front() == L' ') in.erase(in.begin());
    if (in.empty()) return std::wstring();
    size_t sp = in.find(L' ');
    std::wstring tok = sp == std::wstring::npos ? in : in.substr(0, sp);
    in = sp == std::wstring::npos ? std::wstring() : in.substr(sp);
    return tok;
}

uintptr_t ParseHexToken(const std::wstring& t) {
    if (t.empty()) return 0;
    std::wstring s = t;
    if (s.size() > 2 && s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s = s.substr(2);
    return (uintptr_t)_wcstoui64(s.c_str(), nullptr, 16);
}

ReArgs ParseReArgs(const std::wstring& args) {
    ReArgs a;
    std::wstring rest = args;
    for (;;) {
        std::wstring tok = NextToken(rest);
        if (tok.empty()) break;
        if (tok == L"--module")      a.module = NextToken(rest);
        else if (tok == L"--addr")   { a.addr = ParseHexToken(NextToken(rest)); a.haveAddr = true; }
        else if (tok == L"--from")   { a.from = ParseHexToken(NextToken(rest)); a.haveFrom = true; }
        else if (tok == L"--to")     { a.to = ParseHexToken(NextToken(rest)); a.haveTo = true; }
        else if (tok == L"--count")  a.count = (size_t)_wtoi(NextToken(rest).c_str());
        else if (tok == L"--pattern") a.pattern = NextToken(rest);
        else if (a.pattern.empty() && tok[0] != L'-') a.pattern = tok;
    }
    if (a.count == 0) a.count = 64;
    return a;
}

// Resolves the module to work on, defaulting to the process executable.
bool ResolveModule(const std::wstring& name, ModuleRange& m, PeImage& img) {
    if (name.empty()) {
        HMODULE mainBase = GetModuleHandleW(nullptr);
        m.base = (uintptr_t)mainBase;
        for (const ModuleRange& cand : EnumModules()) {
            if (cand.base == m.base) { m = cand; break; }
        }
    } else if (!FindModule(name.c_str(), m)) {
        return false;
    }
    if (!m.base) return false;
    img = ParsePe(m.base);
    return img.valid;
}

const PeSection* CodeSection(const PeImage& img) {
    for (const PeSection& s : img.sections)
        if (s.name == ".text") return &s;
    for (const PeSection& s : img.sections)
        if (s.Executable()) return &s;
    return nullptr;
}

}  // namespace

std::string DisasmToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);
    ModuleRange m;
    PeImage img;
    if (!ResolveModule(a.module, m, img)) {
        return "{\"status\":\"error\",\"message\":\"module not found or not a PE\"}";
    }

    uintptr_t start = a.haveAddr ? a.addr : 0;
    if (!a.haveAddr) {
        const PeSection* c = CodeSection(img);
        if (!c) return "{\"status\":\"error\",\"message\":\"no executable section\"}";
        start = img.base + c->va;
    }
    if (start < img.base || start > img.base + img.sizeOfImage) {
        char b[160];
        _snprintf_s(b, sizeof(b), _TRUNCATE,
                    "{\"status\":\"error\",\"message\":\"address outside module\","
                    "\"base\":\"0x%llX\",\"size\":%u}",
                    (unsigned long long)img.base, img.sizeOfImage);
        return b;
    }

    uintptr_t stopped = start;
    std::vector<Insn> insns = Disassemble(start, a.count * 8, a.count, &stopped, sizeof(void*) == 8);

    char buf[256];
    std::string j = "{\"status\":\"ok\",\"arch\":\"" + img.MachineName() + "\"";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                ",\"start\":\"0x%llX\",\"count\":%zu,\"stoppedAt\":\"0x%llX\",\"insns\":[",
                (unsigned long long)start, insns.size(), (unsigned long long)stopped);
    j += buf;

    bool first = true;
    for (const Insn& i : insns) {
        if (!first) j += ",";
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"addr\":\"0x%llX\",\"bytes\":\"%s\",\"text\":\"%s %s\"}",
                    (unsigned long long)i.address, i.bytes.c_str(),
                    i.mnemonic.c_str(), i.opStr.c_str());
        j += buf;
    }
    j += "]}";
    return j;
}

std::string ImportsToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);
    ModuleRange m;
    PeImage img;
    if (!ResolveModule(a.module, m, img)) {
        return "{\"status\":\"error\",\"message\":\"module not found or not a PE\"}";
    }

    std::wstring want = a.pattern;
    for (auto& c : want) c = (wchar_t)towlower(c);

    size_t matched = 0;
    for (const PeImport& im : img.imports) {
        if (want.empty()) { ++matched; continue; }
        std::string hayA = im.name;
        for (auto& c : hayA) c = (char)tolower((unsigned char)c);
        std::string dllA = im.dll;
        for (auto& c : dllA) c = (char)tolower((unsigned char)c);
        std::string wantA(want.begin(), want.end());
        if (dllA.find(wantA) != std::string::npos || hayA.find(wantA) != std::string::npos)
            ++matched;
    }

    std::string j = "{\"status\":\"ok\",\"total\":" ;
    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%zu,\"matched\":%zu,\"imports\":[",
                img.imports.size(), matched);
    j += buf;

    bool first = true;
    size_t shown = 0;
    for (const PeImport& im : img.imports) {
        if (!want.empty()) {
            std::string hayA = im.name;
            for (auto& c : hayA) c = (char)tolower((unsigned char)c);
            std::string dllA = im.dll;
            for (auto& c : dllA) c = (char)tolower((unsigned char)c);
            std::wstring wantA(want.begin(), want.end());   // already lowercased
            bool byDll = dllA.find(std::string(wantA.begin(), wantA.end())) != std::string::npos;
            if (!byDll && hayA.find(std::string(wantA.begin(), wantA.end())) == std::string::npos)
                continue;
        }
        if (shown >= a.count) break;
        if (!first) j += ",";
        ++shown;
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"dll\":\"%s\",\"name\":\"%s\",\"ordinal\":%u,\"iat\":\"0x%llX\"}",
                    im.dll.c_str(), im.name.c_str(), im.ordinal,
                    (unsigned long long)(img.base + im.iatRva));
        j += buf;
    }
    j += "]}";
    return j;
}

// xref --addr <target> [--module m] [--from a --to b] [--count N]
// Resolves the target through the IAT when it looks like an import slot.
std::string XrefToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);
    ModuleRange m;
    PeImage img;
    if (!ResolveModule(a.module, m, img)) {
        return "{\"status\":\"error\",\"message\":\"module not found or not a PE\"}";
    }

    uintptr_t target = a.addr;
    std::string targetKind = "absolute";
    if (!a.haveAddr && !a.pattern.empty()) {
        // Allow "xref CreateWindowExW" — look the name up in the IAT.
        std::string want(a.pattern.begin(), a.pattern.end());
        for (const PeImport& im : img.imports) {
            if (_stricmp(im.name.c_str(), want.c_str()) == 0) {
                target = img.base + im.iatRva;
                targetKind = "iat:" + im.dll + "!" + im.name;
                break;
            }
        }
        if (!a.haveAddr && targetKind == "absolute") {
            return "{\"status\":\"error\",\"message\":\"import not found in module\"}";
        }
    }
    if (!target) return "{\"status\":\"error\",\"message\":\"--addr required\"}";

    uintptr_t from = a.haveFrom ? a.from : 0;
    uintptr_t to = a.haveTo ? a.to : 0;
    if (!from) {
        const PeSection* c = CodeSection(img);
        if (!c) return "{\"status\":\"error\",\"message\":\"no executable section\"}";
        from = img.base + c->va;
    }
    if (!to) to = from + (CodeSection(img) ? CodeSection(img)->virtualSize : 0x100000);

    std::vector<Xref> hits = FindXrefs(from, to, target, sizeof(void*) == 8, a.count);

    char buf[320];
    std::string j = "{\"status\":\"ok\",\"target\":\"" + targetKind + "\"";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                ",\"targetAddr\":\"0x%llX\",\"scanned\":\"0x%llX-0x%llX\",\"hitCount\":%zu,\"xrefs\":[",
                (unsigned long long)target, (unsigned long long)from,
                (unsigned long long)to, hits.size());
    j += buf;

    bool first = true;
    for (const Xref& x : hits) {
        if (!first) j += ",";
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"from\":\"0x%llX\",\"how\":\"%s\"}",
                    (unsigned long long)x.from, x.how.c_str());
        j += buf;
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

// MSVC C2712: __try cannot live in a function that needs C++ unwinding, so the
// guarded body takes only POD pointers. The command text is copied into a
// stack buffer before the call; the result is written into an out-parameter.
typedef std::string (*CommandFn)(const std::wstring&);

static int GuardCall(CommandFn fn, wchar_t* text, std::string* out, unsigned* code) {
    int ok = 0;
    __try {
        std::wstring args(text);       // constructed inside the guarded frame
        *out = fn(args);
        ok = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        ok = 0;
    }
    return ok;
}

// Runs one command under SEH. A crash becomes a JSON error reply instead of
// taking the host process down with it.
static std::string Guarded(const wchar_t* what, CommandFn fn, const std::wstring& args) {
    // Cap the length so the copy into the guarded frame cannot overflow.
    wchar_t safe[1024] = {};
    wcsncpy_s(safe, _countof(safe), args.c_str(), _TRUNCATE);

    std::string out;
    unsigned code = 0;
    if (GuardCall(fn, safe, &out, &code)) return out;

    char buf[320];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "{\"status\":\"error\",\"message\":\"command crashed\","
                "\"command\":\"%ls\",\"exception\":\"0x%08X\"}",
                what ? what : L"?", code);
    LogLine("command raised 0x%08X", code);
    return buf;
}

}  // namespace

V8I_API int V8I_CALL v8i_version() {
    return 1;
}

// Every command runs behind a guard: a bad pointer in a foreign image must
// produce an error reply, never take the host process down.
static std::string Guarded(const wchar_t* what, std::string (*fn)(const std::wstring&),
                           const std::wstring& args);

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

        if (wcsncmp(g_io->request, L"disasm", 6) == 0) {
            LogLine("disasm: decoding");
            PutResponse(Guarded(L"disasm", DisasmToJson, std::wstring(g_io->request).size() > 7
                                   ? std::wstring(g_io->request).substr(7)
                                   : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"imports", 7) == 0) {
            PutResponse(Guarded(L"imports", ImportsToJson, std::wstring(g_io->request).size() > 8
                                    ? std::wstring(g_io->request).substr(8)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"xref", 4) == 0) {
            LogLine("xref: scanning code");
            PutResponse(Guarded(L"xref", XrefToJson, std::wstring(g_io->request).size() > 5
                                 ? std::wstring(g_io->request).substr(5)
                                 : std::wstring()));
            LogLine("xref: done");
            continue;
        }

        if (wcsncmp(g_io->request, L"find ", 5) == 0) {
            LogLine("find: starting scan");
            PutResponse(Guarded(L"find", FindToJson, std::wstring(g_io->request + 5)));
            LogLine("find: done");
            continue;
        }

        if (wcsncmp(g_io->request, L"peek ", 5) == 0) {
            PutResponse(Guarded(L"peek", PeekToJson, std::wstring(g_io->request + 5)));
            continue;
        }

        if (wcsncmp(g_io->request, L"pe", 2) == 0) {
            const wchar_t* arg = g_io->request + 2;
            while (*arg == L' ') ++arg;
            PutResponse(Guarded(L"pe", PeToJson, std::wstring(arg)));
            continue;
        }

        if (wcscmp(g_io->request, L"objects") == 0) {
            LogLine("objects: enumerating windows");
            PutResponse(Guarded(L"objects", ObjectsToJson, std::wstring()));
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

