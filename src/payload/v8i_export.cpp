#include "v8inject/diag.h"
#include "v8inject/v8i_export.h"
#include "v8inject/hook.h"
#include "v8inject/menu.h"
#include "v8inject/gitbar.h"
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

// Reads a NUL-terminated UTF-16 string at an address inside this process,
// bounded. Used to decode paths/names captured in trace args.
std::string StrToJson(const std::wstring& args) {
    uintptr_t addr = 0;
    int max = 256;
    {
        wchar_t token[64] = {};
        int want = 256;
        if (swscanf_s(args.c_str(), L"%63ls %d", token, (unsigned)_countof(token), &want) < 1) {
            return "{\"status\":\"error\",\"message\":\"usage: str <hex-addr> [max-chars]\"}";
        }
        addr = (uintptr_t)_wcstoui64(token, nullptr, 16);
        max = want;
    }
    if (max <= 0) max = 256;
    if (max > 8192) max = 8192;

    if (!IsReadable((const void*)addr, 2)) {
        return "{\"status\":\"error\",\"message\":\"unreadable address\"}";
    }
    std::wstring w;
    w.reserve(max);
    for (int i = 0; i < max; ++i) {
        if (!IsReadable((const void*)(addr + (size_t)i * 2), 2)) break;
        wchar_t ch = *(const wchar_t*)(addr + (size_t)i * 2);
        if (ch == 0) break;
        if (ch == 0xFFFE || ch == 0xFFFF) break;  // not really a string
        w.push_back(ch);
    }
    char head[160];
    _snprintf_s(head, sizeof(head), _TRUNCATE,
                "{\"status\":\"ok\",\"address\":\"0x%llX\",\"chars\":%d,\"value\":\"",
                (unsigned long long)addr, (int)w.size());
    return head + EscapeW(w) + "\"}";
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
    std::vector<std::wstring> positional;   // module name, then a filter
    bool         haveAddr = false;
    size_t       offset = 0;                 // --offset, for byhwnd
    bool         haveOffset = false;
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

// Numbers on the command line may be written in hex (0x38) or decimal (56).
size_t ParseNum(const std::wstring& t) {
    if (t.empty()) return 0;
    if (t.size() > 2 && t[0] == L'0' && (t[1] == L'x' || t[1] == L'X'))
        return (size_t)ParseHexToken(t);
    return (size_t)_wtoi(t.c_str());
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
        else if (tok == L"--count")  a.count = ParseNum(NextToken(rest));
        else if (tok == L"--offset") { a.offset = ParseNum(NextToken(rest)); a.haveOffset = true; }
        else if (tok == L"--pattern") a.pattern = NextToken(rest);
        else if (tok[0] != L'-')     a.positional.push_back(tok);
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

// End of the region to scan: the section may claim a virtual size that runs past
// the image, which silently moves the scan into unrelated memory.
uintptr_t SectionEnd(const PeImage& img, const PeSection* sec) {
    if (!sec) return img.base;
    uintptr_t begin = img.base + sec->va;
    uintptr_t bySize = img.base + img.sizeOfImage;
    uintptr_t bySec = begin + (sec->virtualSize ? sec->virtualSize : sec->rawSize);
    return bySec < bySize ? bySec : bySize;
}

}  // namespace

std::string DisasmToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);
    // disasm [<hex-addr>] [--module m] — a positional hex number is the address.
    for (const std::wstring& p : a.positional) {
        if (p.find(L'.') != std::wstring::npos) { if (a.module.empty()) a.module = p; }
        else if (!a.haveAddr) { a.addr = ParseHexToken(p); a.haveAddr = true; }
    }
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
    // imports <module> [filter] — the module is positional, not a filter.
    if (a.module.empty() && !a.positional.empty()) {
        a.module = a.positional[0];
        if (a.positional.size() > 1 && a.pattern.empty()) a.pattern = a.positional[1];
    }
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

    const wchar_t* modLeaf = wcsrchr(m.path.c_str(), L'\\');
    std::string j = "{\"status\":\"ok\",\"module\":\"" +
                    EscapeW(modLeaf ? modLeaf + 1 : m.path) + "\",\"total\":" ;
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

// exports <module> [filter] — the module's export table, matched by name.
// Used to locate engine entry points (autocomplete, editor, ...) by name.
std::string ExportsToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);
    if (a.module.empty() && !a.positional.empty()) {
        a.module = a.positional[0];
        if (a.positional.size() > 1 && a.pattern.empty()) a.pattern = a.positional[1];
    }
    ModuleRange m;
    PeImage img;
    if (!ResolveModule(a.module, m, img)) {
        return "{\"status\":\"error\",\"message\":\"module not found or not a PE\"}";
    }

    std::wstring want = a.pattern;
    for (auto& c : want) c = (wchar_t)towlower(c);

    size_t matched = 0;
    if (!want.empty()) {
        for (const PeExport& ex : img.exports) {
            std::string hay = ex.name;
            for (auto& c : hay) c = (char)tolower((unsigned char)c);
            if (hay.find(std::string(want.begin(), want.end())) == std::string::npos) continue;
            ++matched;
        }
    } else {
        matched = img.exports.size();
    }

    const wchar_t* modLeaf = wcsrchr(m.path.c_str(), L'\\');
    std::string j = "{\"status\":\"ok\",\"module\":\"" +
                    EscapeW(modLeaf ? modLeaf + 1 : m.path) + "\",\"total\":" ;
    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%zu,\"matched\":%zu,\"exports\":[",
                img.exports.size(), matched);
    j += buf;

    bool first = true;
    size_t shown = 0;
    for (const PeExport& ex : img.exports) {
        if (!want.empty()) {
            std::string hay = ex.name;
            for (auto& c : hay) c = (char)tolower((unsigned char)c);
            if (hay.find(std::string(want.begin(), want.end())) == std::string::npos) continue;
        }
        if (shown >= a.count) break;
        if (!first) j += ",";
        ++shown;
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"name\":\"%s\",\"rva\":\"0x%X\",\"addr\":\"0x%llX\",\"ordinal\":%u",
                    ex.name.c_str(), ex.rva, (unsigned long long)(img.base + ex.rva),
                    ex.ordinal);
        j += buf;
        if (ex.forwarded) {
            j += ",\"forwarded\":true,\"forwarder\":\"";
            j += ex.forwarder;
            j += "\"";
        }
        j += "}";
    }
    j += "]}";
    return j;
}

// mods [filter] — loaded modules, with base/size and the bitness-appropriate
// PE machine. This is the first thing to ask when mapping the engine: it shows
// every DLL 1C pulled in, so exports/imports/xref can be pointed at the right
// one (1cv8core, frame, v8baseeditor, ...).
std::string ModsToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);
    // Positional filter: `mods edit`, `mods 1cv8`. --pattern also accepted.
    if (a.pattern.empty() && !a.positional.empty()) a.pattern = a.positional[0];

    std::wstring want = a.pattern;
    for (auto& c : want) c = (wchar_t)towlower(c);

    std::vector<ModuleRange> all = EnumModules();

    size_t matched = 0;
    for (const ModuleRange& m : all) {
        if (want.empty()) { ++matched; continue; }
        const wchar_t* leaf = wcsrchr(m.path.c_str(), L'\\');
        std::wstring leafW = leaf ? leaf + 1 : m.path;
        std::wstring hay = leafW;
        for (auto& c : hay) c = (wchar_t)towlower(c);
        if (hay.find(want) != std::wstring::npos) ++matched;
    }

    char buf[512];
    std::string j = "{\"status\":\"ok\",\"total\":";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%zu,\"matched\":%zu,\"modules\":[",
                all.size(), matched);
    j += buf;

    bool first = true;
    size_t shown = 0;
    for (const ModuleRange& m : all) {
        if (!want.empty()) {
            const wchar_t* leaf = wcsrchr(m.path.c_str(), L'\\');
            std::wstring leafW = leaf ? leaf + 1 : m.path;
            std::wstring hay = leafW;
            for (auto& c : hay) c = (wchar_t)towlower(c);
            if (hay.find(want) == std::wstring::npos) continue;
        }
        if (shown >= a.count) break;
        if (!first) j += ",";
        ++shown;
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"base\":\"0x%X\",\"size\":\"0x%X\",\"name\":\"",
                    (unsigned)(m.base & 0xFFFFFFFFul), (unsigned)m.size);
        j += buf;
        const wchar_t* leaf = wcsrchr(m.path.c_str(), L'\\');
        j += EscapeW(leaf ? leaf + 1 : m.path);
        j += "\"}";
    }
    j += "]}";
    return j;
}

// Resolves the target through the IAT when it looks like an import slot.
std::string XrefToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);
    // A positional token is an address when it starts with 0x or looks hex,
    // otherwise it is an import name to resolve through the IAT.
    if (!a.haveAddr) {
        for (const std::wstring& p : a.positional) {
            bool hexLike = (p.size() > 2 && p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) ||
                           (p.find(L'.') == std::wstring::npos && p.size() >= 5);
            if (hexLike) {
                uintptr_t v = ParseHexToken(p);
                if (v) { a.addr = v; a.haveAddr = true; }
            } else if (a.pattern.empty()) {
                a.pattern = p;
            }
        }
    }
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
    if (!to) to = SectionEnd(img, CodeSection(img));

    XrefResult xr = FindXrefsVerbose(from, to, target, sizeof(void*) == 8, a.count);
    const std::vector<Xref>& hits = xr.hits;

    // Report what was actually scanned: a wrong module here silently produces
    // an empty result that looks like "no references".
    const wchar_t* leaf = wcsrchr(m.path.c_str(), L'\\');
    char buf[320];
    std::string j = "{\"status\":\"ok\",\"target\":\"" + targetKind + "\"";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                ",\"module\":\"%ls\",\"moduleBase\":\"0x%llX\",\"moduleSize\":%zu"
                ",\"scannedTo\":\"0x%llX\",\"bytesSeen\":%zu,\"badBytes\":%zu%s"
                ",\"from\":\"0x%llX\",\"to\":\"0x%llX\",\"stop\":\"%s\",\"csError\":%d",
                leaf ? leaf + 1 : m.path.c_str(),
                (unsigned long long)img.base, (size_t)m.size,
                (unsigned long long)xr.scannedTo, xr.bytesSeen, xr.badBytes,
                xr.hitLimit ? ",\"hitLimit\":true" : "",
                (unsigned long long)from, (unsigned long long)to,
                xr.stopReason ? xr.stopReason : "", xr.csError);
    j += buf;
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
    (void)first;
    return j;
}

// Shows the instructions around an address, with a marker on the exact one.

// byhwnd <hwnd> [--module m] [--offset 0x34] — find the object that owns a window.

// heapobjects [--module m] [--count n] — list heap objects whose vtable belongs
// to a module, grouped by vtable RVA. Shows which classes are alive and how many.

// memmap [--count n] — committed regions by protection, with sizes. Used to find
// where 1C keeps its heap; the object scanner only walks writable regions.
std::string MemMapToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);
    size_t cap = a.count ? a.count : 60;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    struct Reg { uintptr_t base; size_t size; uint32_t protect; uint32_t state; uint32_t type; };
    std::vector<Reg> big;

    size_t committedRw = 0, committedAll = 0, regTotal = 0;
    size_t rwRegions = 0;
    uintptr_t highestCommit = 0;

    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;
        const uintptr_t rb = (uintptr_t)mbi.BaseAddress;
        const uintptr_t re = rb + mbi.RegionSize;
        ++regTotal;
        if (mbi.State == MEM_COMMIT) {
            committedAll += mbi.RegionSize;
            const DWORD pr = mbi.Protect & ~(PAGE_NOCACHE | PAGE_WRITECOMBINE);
            if (!(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                (pr == PAGE_READONLY || pr == PAGE_READWRITE || pr == PAGE_WRITECOPY ||
                 pr == PAGE_EXECUTE_READ || pr == PAGE_EXECUTE_READWRITE ||
                 pr == PAGE_EXECUTE_WRITECOPY)) {
                committedRw += mbi.RegionSize;
                ++rwRegions;
            }
            if (re > highestCommit) highestCommit = re;
        }
        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= 0x10000) {
            big.push_back({rb, (size_t)mbi.RegionSize, (uint32_t)mbi.Protect,
                           (uint32_t)mbi.State, (uint32_t)mbi.Type});
        }
        if (re <= rb) break;
        addr = re;
    }

    // Largest first.
    for (size_t i = 0; i + 1 < big.size(); ++i)
        for (size_t k = 0; k + 1 < big.size() - i; ++k)
            if (big[k].size < big[k + 1].size) std::swap(big[k], big[k + 1]);

    char buf[512];
    std::string j = "{\"status\":\"ok\",\"regions\":";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "%zu,\"regionsTotal\":%zu,\"committedBytes\":%zu,\"readableBytes\":%zu,"
                "\"readableRegions\":%zu,\"highestCommit\":\"0x%llX\",\"regions\":[",
                big.size(), regTotal, committedAll, committedRw, rwRegions,
                (unsigned long long)highestCommit);
    j += buf;

    size_t shown = 0;
    bool first = true;
    for (const Reg& r : big) {
        if (shown++ >= cap) break;
        if (!first) j += ",";
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"base\":\"0x%llX\",\"size\":%zu,\"protect\":\"0x%X\","
                    "\"type\":\"0x%X\"}",
                    (unsigned long long)r.base, r.size, r.protect, r.type);
        j += buf;
    }
    j += "]}";
    return j;
}

std::string HeapObjectsToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);
    for (const std::wstring& p : a.positional)
        if (p.find(L'.') != std::wstring::npos && a.module.empty()) a.module = p;

    ModuleRange m;
    PeImage img;
    if (!ResolveModule(a.module, m, img))
        return "{\"status\":\"error\",\"message\":\"module not found\"}";

    size_t scanned = 0, regions = 0, committed = 0;
    size_t cap = a.count ? a.count : 20000;
    std::vector<HeapObject> objs = FindHeapObjects(m.base, m.size, cap, &scanned, &regions,
                                                   &committed);

    // Group by vtable RVA.
    std::vector<std::pair<uint32_t, size_t>> groups;
    for (const HeapObject& o : objs) {
        bool seen = false;
        for (auto& g : groups) {
            if (g.first == o.vtableRva) { g.second++; seen = true; break; }
        }
        if (!seen) groups.push_back({o.vtableRva, 1});
    }
    // Most frequent first.
    for (size_t i = 0; i + 1 < groups.size(); ++i)
        for (size_t k = 0; k + 1 < groups.size() - i; ++k)
            if (groups[k].second < groups[k + 1].second)
                std::swap(groups[k], groups[k + 1]);

    char buf[512];
    std::string j = "{\"status\":\"ok\",\"module\":\"";
    j += img.MachineName();
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "\",\"moduleBase\":\"0x%llX\",\"objects\":%zu,\"classes\":%zu,"
                "\"scannedBytes\":%zu,\"committedBytes\":%zu,\"regions\":%zu,\"vtables\":[",
                (unsigned long long)m.base, objs.size(), groups.size(), scanned, committed,
                regions);
    j += buf;

    size_t shown = 0;
    bool first = true;
    for (const auto& g : groups) {
        if (shown++ >= 40) break;
        if (!first) j += ",";
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"rva\":\"0x%X\",\"addr\":\"0x%llX\",\"count\":%zu}",
                    g.first, (unsigned long long)(m.base + g.first), g.second);
        j += buf;
    }
    j += "]}";
    return j;
}


// findvalue <hex> [--count n] [--module m] — every 4-byte occurrence of the value
// in memory, annotated with the module/offset when it lands inside a module and
// with the distance to the nearest object header candidate.
std::string FindValueToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);

    uint32_t value = 0;
    bool have = false;
    for (const std::wstring& p : a.positional) {
        if (p.find(L'.') != std::wstring::npos) { if (a.module.empty()) a.module = p; }
        else if (!have) { value = (uint32_t)ParseHexToken(p); have = true; }
    }
    if (!have) return "{\"status\":\"error\",\"message\":\"value required\"}";

    size_t scanned = 0;
    std::vector<DwordHit> hits = FindDword(value, a.count ? a.count : 32, &scanned);

    char buf[512];
    std::string j = "{\"status\":\"ok\",\"value\":\"0x";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "%X\",\"scannedBytes\":%zu,\"hitCount\":%zu,\"hits\":[",
                value, scanned, hits.size());
    j += buf;

    bool first = true;
    for (const DwordHit& hh : hits) {
        if (!first) j += ",";
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"addr\":\"0x%llX\",\"pageOff\":\"0x%llX\"}",
                    (unsigned long long)hh.address, (unsigned long long)(hh.address & 0xFFF));
        j += buf;
    }
    j += "]}";
    return j;
}

std::string ByHwndToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);

    uintptr_t hwndVal = 0;
    for (const std::wstring& p : a.positional) {
        if (p.find(L'.') != std::wstring::npos) { if (a.module.empty()) a.module = p; }
        else if (!hwndVal) hwndVal = ParseHexToken(p);
    }
    if (!hwndVal) return "{\"status\":\"error\",\"message\":\"hwnd required\"}";

    // The window object from `findvalue` showed the vtable up to ~0x40 bytes
    // above the handle. Search a generous window so the exact layout of the
    // current 1C build doesn't matter; the scanner reports the real offset.
    size_t off = a.haveOffset ? a.offset : 0x200;

    // moduleBase=0 tells the scanner the vtable may live in any loaded module:
    // window objects in 1C frequently inherit system vtables. If the caller
    // narrowed the module, the scan stays inside it.
    uintptr_t base = 0, size = 0;
    ModuleRange m;
    PeImage img;
    if (!ResolveModule(a.module, m, img))
        return "{\"status\":\"error\",\"message\":\"module not found\"}";
    if (!a.module.empty()) { base = m.base; size = m.size; }

    size_t scanned = 0, regions = 0;
    std::vector<HwndOwner> found =
        FindObjectsByHwnd((HWND)hwndVal, base, size, off, a.count ? a.count : 16,
                          &scanned, &regions);

    char buf[512];
    std::string j = "{\"status\":\"ok\",\"hwnd\":\"0x";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "%llX\",\"offset\":%zu,\"count\":%zu,\"scannedBytes\":%zu,"
                "\"regions\":%zu,\"moduleBase\":\"0x%llX\",\"moduleSize\":%zu,\"objects\":[",
                (unsigned long long)hwndVal, off, found.size(), scanned, regions,
                (unsigned long long)m.base, m.size);
    j += buf;

    bool first = true;
    for (const HwndOwner& o : found) {
        if (!first) j += ",";
        first = false;
        // vtableModule comes from EnumModules as UTF-16; JSON is UTF-8.
        std::string modUtf8;
        if (!o.vtableModule.empty()) {
            int n = WideCharToMultiByte(CP_UTF8, 0, o.vtableModule.c_str(),
                                        (int)o.vtableModule.size(), nullptr, 0, nullptr, nullptr);
            if (n > 0) {
                modUtf8.resize((size_t)n);
                WideCharToMultiByte(CP_UTF8, 0, o.vtableModule.c_str(),
                                    (int)o.vtableModule.size(), &modUtf8[0], n, nullptr, nullptr);
            }
        }
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"addr\":\"0x%llX\",\"vtable\":\"0x%llX\",\"vtableInModule\":%s,\"moduleRva\":\"0x%X\",\"offset\":%u",
                    (unsigned long long)o.address, (unsigned long long)o.vtable,
                    o.vtableInModule ? "true" : "false", o.moduleRva, o.offset);
        j += buf;
        if (!o.vtableModule.empty()) {
            j += ",\"vtableModule\":\"";
            j += modUtf8;
            j += "\"";
        }
        j += "}";
    }
    j += "]}";
    return j;
}

std::string AroundToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args);
    // around <hex-addr> [--count n] — the address is positional, as in xref.
    for (const std::wstring& p : a.positional) {
        if (p.find(L'.') != std::wstring::npos) continue;   // a module name
        uintptr_t v = ParseHexToken(p);
        if (v) { a.addr = v; a.haveAddr = true; break; }
    }
    if (!a.haveAddr) return "{\"status\":\"error\",\"message\":\"address required\"}";

    // Walk back a little so the caller sees the setup before the call.
    uintptr_t start = a.addr >= 48 ? a.addr - 48 : a.addr;
    uintptr_t stopped = start;
    std::vector<Insn> insns = Disassemble(start, 256, a.count ? a.count : 16, &stopped,
                                          sizeof(void*) == 8);

    char buf[320];
    std::string j = "{\"status\":\"ok\",\"around\":\"0x";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%llX\",\"insns\":[",
                (unsigned long long)a.addr);
    j += buf;

    bool first = true;
    for (const Insn& i : insns) {
        if (!first) j += ",";
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"addr\":\"0x%llX\",\"text\":\"%s %s\"%s}",
                    (unsigned long long)i.address, i.mnemonic.c_str(), i.opStr.c_str(),
                    i.address == a.addr ? ",\"here\":true" : "");
        j += buf;
    }
    j += "]}";
    return j;
}

std::string ObjectsToJson(const std::wstring& /*unused*/) {
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

// "cmd <num> [sub]" — invoke a designer command of the Config group
// {F10CBB81-F679-11D4-9DD3-0050BAE2BC79} on the main frame, exactly like
// Snegopat's sendCommand. Calibrated chain on 8.3.27.1989 (x64):
//   frame object (heap) -> [0] = ITopLevelFrame vtable (config.dll+0x2EFB50)
//   frame+8             -> coreMainFrame; ICommandReceiver = core - 0x20
//   recv->vtbl[3]       -> transmitCommand(Command*, bool)
// The transmit runs on the 1C UI thread via a frame-window subclass +
// PostMessage (see EnsureCmdUi); 1C UI code must not be called cross-thread.
// The frame is located by scanning committed writable memory for the vtable
// pointer; the result is cached and re-validated for subsequent calls.
namespace {
uintptr_t g_cmdFrameCache = 0;
#if !defined(_WIN64)
uintptr_t g_x86FrameObj = 0;   // discovered frame object (x86 runtime calibration)
#endif
}

// SEH cannot live in a function that needs C++ unwinding (MSVC C2712); the
// transmit call is isolated in a POD-only helper.
#if defined(_WIN64)
typedef int(__fastcall* V8iTransmitFn)(void*, const void*, uint8_t);
#else
// x86 vtable methods are __thiscall: this in ECX, remaining args on the stack.
typedef int(__thiscall* V8iTransmitFn)(void*, const void*, uint8_t);
#endif
#if defined(_WIN64)
typedef int(__fastcall* V8iHasFn)(void*, const void*);
#else
typedef int(__thiscall* V8iHasFn)(void*, const void*);
#endif
typedef void(__fastcall* V8iRecvFn)(void*, void**);

namespace {
LONG g_cmdLastExc = 0;
int TransmitGuarded(void* trFn, void* recv, const void* cmd) {
    int rc = 0;
    __try {
        // deactivate=true mirrors Snegopat's sendCommand default; commands that
        // open modal dialogs expect the current UI to be deactivated first.
        rc = ((V8iTransmitFn)trFn)(recv, cmd, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_cmdLastExc = GetExceptionCode();
        return -1;
    }
    return rc;
}
int HasGuarded(void* fn, void* recv, const void* id) {
    int rc = 0;
    __try {
        rc = ((V8iHasFn)fn)(recv, id);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_cmdLastExc = GetExceptionCode();
        return -1;
    }
    return rc;
}
}  // namespace

// Command { CommandID id; int param; void* object; }, CommandID { Guid; uint }
// (x64 layout: 16 + 4 + 4 + 8 = 32 bytes)
struct __declspec(align(8)) V8Cmd {
    unsigned char group[16];
    unsigned int cmdNum;
    int param;
    void* object;
};
static const unsigned char kConfigGroup[16] = {
    0x81, 0xBB, 0x0C, 0xF1, 0x79, 0xF6, 0xD4, 0x11,
    0x9D, 0xD3, 0x00, 0x50, 0xBA, 0xE2, 0xBC, 0x79};

// Designer commands must run on the 1C UI thread. The payload subclasses the
// frame window once; a posting thread fills the pending slot and posts a
// custom message, the UI thread's WndProc executes transmitCommand and flips
// the done flag. Pod-only state; no calls from the io thread into 1C UI.
namespace {
const UINT kV8iCmdMsg = WM_APP + 0x2F11;
struct V8iPending {
    void* recv;
    void* trFn;
    V8Cmd cmd;
    volatile LONG done;
    int rc;
    LONG exc;
    int mode;   // 0 = transmitCommand(recv, &cmd, 0), 1 = hasHandler(recv, &cmd)
};
V8iPending g_pending = {};
HWND g_cmdHwnd = NULL;
bool g_cmdSubclassed = false;
bool g_cmdViaSubclass = false;
LONG_PTR g_cmdOldWndProc = 0;

typedef LRESULT(CALLBACK* V8iSubclassProc)(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);
LRESULT CALLBACK V8iCmdSubclass(HWND h, UINT m, WPARAM w, LPARAM l,
                                UINT_PTR id, DWORD_PTR data) {
    if (m == kV8iCmdMsg) {
        V8iPending* p = (V8iPending*)data;
        p->rc = p->mode == 1 ? HasGuarded(p->trFn, p->recv, &p->cmd)
                             : TransmitGuarded(p->trFn, p->recv, &p->cmd);
        if (p->rc < 0) p->exc = g_cmdLastExc;
        InterlockedExchange(&p->done, 1);
        return 0;
    }
    typedef LRESULT(WINAPI* V8iDefSubclassProcFn)(HWND, UINT, WPARAM, LPARAM);
    static V8iDefSubclassProcFn defFn = []() -> V8iDefSubclassProcFn {
        HMODULE ctl = GetModuleHandleW(L"comctl32.dll");
        return ctl ? (V8iDefSubclassProcFn)GetProcAddress(ctl, "DefSubclassProc") : nullptr;
    }();
    return defFn ? defFn(h, m, w, l) : DefWindowProcW(h, m, w, l);
}

LRESULT CALLBACK V8iCmdWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == kV8iCmdMsg) {
        g_pending.rc = g_pending.mode == 1
                           ? HasGuarded(g_pending.trFn, g_pending.recv, &g_pending.cmd)
                           : TransmitGuarded(g_pending.trFn, g_pending.recv, &g_pending.cmd);
        if (g_pending.rc < 0) g_pending.exc = g_cmdLastExc;
        InterlockedExchange(&g_pending.done, 1);
        return 0;
    }
    return CallWindowProcW((WNDPROC)g_cmdOldWndProc, h, m, w, l);
}

bool EnsureCmdUi(HWND* outHwnd, DWORD* outErr, const char** outPath) {
    // 1C recreates its top-level windows (toolbar/title changes) and can drop a
    // replaced WndProc; re-verify and re-install on every call unless the
    // comctl32 subclass chain is our installation.
    if (g_cmdSubclassed && g_cmdHwnd && IsWindow(g_cmdHwnd)) {
        if (!g_cmdViaSubclass) {
            // Re-assert our WndProc right before every send: 1C re-creates its
            // toolbar/UI and re-sets the frame WndProc while a config opens.
            LONG_PTR old = SetWindowLongPtrW(g_cmdHwnd, GWLP_WNDPROC, (LONG_PTR)V8iCmdWndProc);
            if (!old) return false;
            if (old != (LONG_PTR)V8iCmdWndProc) g_cmdOldWndProc = old;
            *outPath = "wndproc";
        } else {
            *outPath = "subclass";
        }
        *outHwnd = g_cmdHwnd;
        return true;
    }
    std::vector<WindowEntry> wins = EnumProcessWindows();
    HWND frame = nullptr;
    for (const WindowEntry& w : wins)
        if (w.cls == L"V8TopLevelFrame") { frame = w.hwnd; break; }
    if (!frame) { *outErr = 0xFFFFFF01; return false; }

    // Preferred: comctl32 SetWindowSubclass (chains cleanly with 1C's own).
    HMODULE ctl = GetModuleHandleW(L"comctl32.dll");
    if (ctl) {
        typedef BOOL(WINAPI* V8iSetWindowSubclassFn)(HWND, V8iSubclassProc, UINT_PTR, DWORD_PTR);
        V8iSetWindowSubclassFn setFn =
            (V8iSetWindowSubclassFn)GetProcAddress(ctl, "SetWindowSubclass");
        if (setFn && setFn(frame, V8iCmdSubclass, 1, (DWORD_PTR)&g_pending)) {
            g_cmdHwnd = frame;
            g_cmdSubclassed = true;
            g_cmdViaSubclass = true;
            *outHwnd = frame;
            *outPath = "subclass";
            return true;
        }
    }

    // Fallback: classic WndProc replacement, chaining via CallWindowProcW.
    LONG_PTR old = SetWindowLongPtrW(frame, GWLP_WNDPROC, (LONG_PTR)V8iCmdWndProc);
    if (!old || old == (LONG_PTR)V8iCmdWndProc) {
        *outErr = GetLastError();
        return false;
    }
    g_cmdOldWndProc = old;
    g_cmdHwnd = frame;
    g_cmdSubclassed = true;
    g_cmdViaSubclass = false;
    *outHwnd = frame;
    *outPath = "wndproc";
    return true;
}
}  // namespace

#if !defined(_WIN64)
// x86 runtime calibration: find the ITopLevelFrame vtable without hardcoded
// constants. Returns 0 when not found. POD-only reads; no calls into 1C.
static uintptr_t g_x86RecvOffset = 0x20;

static uintptr_t DiscoverFrameVtblX86(const ModuleRange& cfg) {
    PeImage cfgImg = ParsePe(cfg.base);
    if (!cfgImg.valid) return 0;
    const PeSection* textSec = nullptr;
    const PeSection* rdataSec = nullptr;
    for (const PeSection& s : cfgImg.sections) {
        if (s.Executable() && s.name == ".text") textSec = &s;
        if (s.Readable() && !s.Executable() && s.name == ".rdata") rdataSec = &s;
    }
    if (!textSec || !rdataSec) return 0;
    const uintptr_t textLo = cfg.base + textSec->va;
    const uintptr_t textHi = textLo + textSec->virtualSize;
    const uintptr_t rdataLo = cfg.base + rdataSec->va;
    const uintptr_t rdataHi = rdataLo + rdataSec->virtualSize;

    ModuleRange frame;
    bool haveFrame = FindModule(L"frame.dll", frame);
    uintptr_t frameRdataLo = 0, frameRdataHi = 0, frameTextLo = 0, frameTextHi = 0;
    if (haveFrame) {
        PeImage fImg = ParsePe(frame.base);
        for (const PeSection& s : fImg.sections) {
            if (s.Executable() && s.name == ".text") {
                frameTextLo = frame.base + s.va;
                frameTextHi = frameTextLo + s.virtualSize;
            }
            if (s.Readable() && !s.Executable() && s.name == ".rdata") {
                frameRdataLo = frame.base + s.va;
                frameRdataHi = frameRdataLo + s.virtualSize;
            }
        }
    }

    // walk heap once, remember (object -> vtable) where vtable is in config .rdata
    std::vector<uintptr_t> objs;
    std::vector<uintptr_t> vts;  // parallel; dedupe vts
    uintptr_t addr = 0x10000;
    while (addr < 0x7FFFFFFF) {
        MEMORY_BASIC_INFORMATION mi = {};
        if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
        uintptr_t end = addr + mi.RegionSize;
        bool usable = mi.State == MEM_COMMIT &&
                      (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                      !(mi.Protect & PAGE_GUARD);
        if (usable) {
            const uintptr_t cap = mi.RegionSize > 64 * 1024 * 1024 ? 64 * 1024 * 1024 : (uintptr_t)mi.RegionSize;
            for (uintptr_t p = (uintptr_t)mi.BaseAddress; p < (uintptr_t)mi.BaseAddress + cap; p += 4) {
                uint32_t v = *(uint32_t*)p;
                if (v < (uint32_t)rdataLo || v >= (uint32_t)rdataHi) continue;
                // vtable start must satisfy: no header dwords (IUnknown trio) — slots 3..40 in .text
                bool ok = true;
                for (int s = 3; s <= 40; ++s) {
                    uint32_t fn = *(uint32_t*)((uintptr_t)v + s * 4);
                    if (fn < (uint32_t)textLo || fn >= (uint32_t)textHi) { ok = false; break; }
                }
                if (!ok) continue;
                objs.push_back(p);
                vts.push_back((uintptr_t)v);
            }
        }
        addr = end == addr ? addr + 4 : end;
    }

    // try each (object, vtable) — receiver chain must land in frame.dll
    static const uintptr_t kRecvOffs[] = {0x20, 0x1C, 0x18, 0x14, 0x10, 0x24, 0x28,
                                          0x0C, 0x08, 0x04, 0x30, 0x34, 0x38, 0x3C, 0x40};
    for (size_t i = 0; i < objs.size(); ++i) {
        uintptr_t v = vts[i];
        uintptr_t core = *(uint32_t*)(objs[i] + 4);
        if (!IsReadable((void*)core, 4)) continue;
        for (size_t off = 0; off < sizeof(kRecvOffs) / sizeof(kRecvOffs[0]); ++off) {
            uintptr_t recv = core - kRecvOffs[off];
            if (!IsReadable((void*)recv, 4)) continue;
            uint32_t recvVt = *(uint32_t*)recv;
            if (!haveFrame) continue;
            if (recvVt < (uint32_t)frameRdataLo || recvVt >= (uint32_t)frameRdataHi) continue;
            uint32_t tr = *(uint32_t*)((uintptr_t)recvVt + 3 * 4);
            if (tr < (uint32_t)frameTextLo || tr >= (uint32_t)frameTextHi) continue;
            // transmitCommand is a real method (thiscall, 2 stack args -> ret 8),
            // NOT a 6-byte property getter `mov eax,[ebp+8]; mov eax,[eax+off]; pop ebp; ret 4`
            // (several interface wrapper vtables near the frame use those).
            const unsigned char* code = (const unsigned char*)tr;
            if (!IsReadable((void*)code, 0x60)) continue;
            static const unsigned char kGetter[] = {0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x40};
            if (memcmp(code, kGetter, sizeof(kGetter)) == 0) continue;
            bool sawRet8 = false;
            for (int b = 0; b < 0x60; ++b) {
                if (code[b] == 0xC2 && b + 2 < 0x60 && code[b + 1] == 0x08 && code[b + 2] == 0x00) {
                    sawRet8 = true;
                    break;
                }
            }
            if (!sawRet8) continue;
            g_x86RecvOffset = kRecvOffs[off];
            return objs[i];  // the frame object itself (vtable validated above)
        }
    }
    return 0;
}
#endif

static std::string CmdCommandToJson(const std::wstring& args0) {
    std::wstring args = args0;
    bool wantHas = false;
    if (args.rfind(L"has ", 0) == 0) {
        wantHas = true;
        args = args.substr(4);
    }
    unsigned int num = 0;
    int sub = 0;
    if (swscanf_s(args.c_str(), L"%u %d", &num, &sub) < 1)
        return "{\"status\":\"error\",\"message\":\"usage: cmd <num> [sub]\"}";

    ModuleRange cfg;
    if (!FindModule(L"config.dll", cfg))
        return "{\"status\":\"error\",\"message\":\"config.dll not loaded\"}";

#if defined(_WIN64)
    const uintptr_t kFrameVtblRva = 0x2EFB50;   // ITopLevelFrame vtable, 8.3.27.1989 x64
    const uintptr_t kCoreOffset = sizeof(void*);
    const int kTransmitSlot = 3;
    const uintptr_t kRecvBackOffset = 0x20;   // ICommandReceiver sits 0x20 before coreMainFrame
    uintptr_t vtblPtr = cfg.base + kFrameVtblRva;
    if (kFrameVtblRva == 0)
        return "{\"status\":\"error\",\"message\":\"frame vtable not calibrated for this build\"}";
#else
    // x86: calibrate at runtime — no hardcoded RVA. A heap object whose first
    // dword points into config.dll .rdata, whose vtable slots 3..40 all point
    // into config.dll .text, and whose receiver chain (core = obj+4,
    // recv = core - off, recv vtable in frame.dll .rdata) is consistent is the
    // main frame. See CmdDiscoverFrameVtblX86 below.
    static const uintptr_t kCoreOffset = sizeof(void*);
    static const int kTransmitSlot = 3;
    g_x86FrameObj = DiscoverFrameVtblX86(cfg);
    if (!g_x86FrameObj)
        return "{\"status\":\"error\",\"message\":\"no frame vtable found on x86\"}";
    const uintptr_t kRecvBackOffset = g_x86RecvOffset;
    const uintptr_t vtblPtr = *(uint32_t*)g_x86FrameObj;   // vtable of the discovered frame
#endif

    char numBuf[256];
    std::string j = "{\"status\":\"ok\"";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"num\":%u,\"sub\":%d,\"vtbl\":\"0x%llX\"",
                num, sub, (unsigned long long)vtblPtr);
    j += numBuf;

    uintptr_t frame = g_cmdFrameCache;
    bool cached = false;
    std::vector<uintptr_t> candidates;
#if !defined(_WIN64)
    if (g_x86FrameObj) {
        // x86: the discovery pass already validated the object and the exact
        // receiver offset; use it directly instead of re-scanning by vtable
        // (several sibling classes share the vtable, so a vtable-only scan
        // would pick objects with a different receiver layout).
        frame = g_x86FrameObj;
        cached = true;
        candidates.push_back(frame);
    }
#endif
    if (frame && IsReadable((void*)frame, sizeof(void*)) &&
        *(uintptr_t*)frame == vtblPtr) {
        cached = true;
        candidates.push_back(frame);
    } else {
        frame = 0;
        // Walk the address space, skip module images, and look for heap objects
        // whose first word is the ITopLevelFrame vtable. Both the shell frame and
        // the core frame share this vtable; any of them routes to the receiver.
        std::vector<ModuleRange> mods;
        for (const ModuleRange& m : EnumModules()) mods.push_back(m);
        auto insideModule = [&mods](uintptr_t a) {
            for (const ModuleRange& m : mods)
                if (a >= m.base && a < m.base + m.size) return true;
            return false;
        };
        uintptr_t addr = 0x10000;
        uint64_t scanned = 0;
        while (addr < 0x00007FFFFFFFFFFFULL) {
            MEMORY_BASIC_INFORMATION mi = {};
            if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
            uintptr_t end = addr + mi.RegionSize;
            bool usable = mi.State == MEM_COMMIT &&
                          (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                          !(mi.Protect & PAGE_GUARD) && !insideModule((uintptr_t)mi.BaseAddress);
            if (usable) {
                const uintptr_t cap = mi.RegionSize > 64 * 1024 * 1024
                                          ? 64 * 1024 * 1024 : (uintptr_t)mi.RegionSize;
                for (uintptr_t p = (uintptr_t)mi.BaseAddress; p < (uintptr_t)mi.BaseAddress + cap;
                     p += sizeof(void*)) {
                    ++scanned;
                    if (*(uintptr_t*)p == vtblPtr) {
                        uintptr_t core = *(uintptr_t*)(p + kCoreOffset);
                        if (IsReadable((void*)core, sizeof(void*)) &&
                            IsReadable((void*)*(uintptr_t*)core, 32 * sizeof(void*))) {
                            candidates.push_back(p);
                            if (candidates.size() >= 16) break;
                        }
                    }
                }
            }
            if (candidates.size() >= 16) break;
            addr = end == addr ? addr + sizeof(void*) : end;
        }
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"scan\":{\"cached\":%s,\"scanned\":%llu,\"candidates\":%zu}",
                    cached ? "true" : "false", (unsigned long long)scanned, candidates.size());
        j += numBuf;
    }

    void* recv = nullptr;
    void* trFn = nullptr;
    uintptr_t usedFrame = 0;
    // For each candidate the receiver is a fixed distance before coreMainFrame
    // (frame+ptrSize), so no vtable calls are needed to obtain it.
    for (uintptr_t cand : candidates) {
        uintptr_t core = *(uintptr_t*)(cand + kCoreOffset);
        if (!IsReadable((void*)core, sizeof(void*))) continue;
        uintptr_t candRecv = core - kRecvBackOffset;
        if (!IsReadable((void*)candRecv, sizeof(void*))) continue;
        uintptr_t recvVt = *(uintptr_t*)candRecv;
        if (!IsReadable((void*)(recvVt + 4 * sizeof(void*)), sizeof(void*))) continue;
        void* candTr = ((void**)recvVt)[kTransmitSlot];
        if (!IsReadable(candTr, 1)) continue;
        if (wantHas) {
            // ICommandReceiver::hasHandler is the 5th slot (after queryIface).
            candTr = ((void**)recvVt)[5];
            if (!IsReadable(candTr, 1)) continue;
        }
        usedFrame = cand;
        recv = (void*)candRecv;
        trFn = candTr;
        frame = cand;
        break;
    }

    if (!trFn)
        return j + ",\"error\":\"no working receiver chain\"}";

    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"frame\":\"0x%llX\",\"recv\":\"0x%llX\"",
                (unsigned long long)usedFrame, (unsigned long long)(uintptr_t)recv);
    j += numBuf;

    // Marshal onto the 1C UI thread: fill the pending slot, post a message to
    // the frame window; its WndProc (our subclass) runs on the UI thread and
    // executes transmitCommand there.
    HWND cmdHwnd = nullptr;
    DWORD ensureErr = 0;
    const char* marshalPath = "";
    if (!EnsureCmdUi(&cmdHwnd, &ensureErr, &marshalPath)) {
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE,
                    ",\"error\":\"marshaling setup failed\",\"code\":\"0x%X\"", (unsigned)ensureErr);
        return j + numBuf + "}";
    }
    j += std::string(",\"marshal\":\"") + marshalPath + "\"";

    g_pending.recv = recv;
    g_pending.trFn = trFn;
    g_pending.mode = wantHas ? 1 : 0;
    memcpy(g_pending.cmd.group, kConfigGroup, 16);
    g_pending.cmd.cmdNum = num;
    g_pending.cmd.param = sub;
    g_pending.cmd.object = nullptr;
    g_pending.rc = -2;
    g_pending.exc = 0;
    InterlockedExchange(&g_pending.done, 0);

    // Synchronous cross-thread dispatch: blocks until the UI thread's WndProc
    // runs (SMTO_BLOCK) or the target is hung (capped by the timeout).
    DWORD_PTR smRes = 0;
    if (!SendMessageTimeoutW(cmdHwnd, kV8iCmdMsg, 0, 0,
                             SMTO_ABORTIFHUNG | SMTO_BLOCK, 30000, &smRes)) {
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE,
                    ",\"error\":\"UI thread did not answer (0x%X)\"", (unsigned)GetLastError());
        return j + numBuf + "}";
    }
    if (!g_pending.done)
        return j + ",\"error\":\"timeout waiting for UI thread\"}";

    int rc = g_pending.rc;
    if (rc < 0) {
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"error\":\"transmit exception 0x%X\"",
                    (unsigned)g_pending.exc);
        return j + numBuf + "}";
    }
    if (wantHas) {
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"has\":%s",
                    rc == 0 ? "false" : "true");
        return j + numBuf + "}";
    }
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"sent\":true,\"rc\":%d", rc);
    j += numBuf;
    return j + "}";
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

// SEH cannot protect a frame that needs C++ unwinding (MSVC C2712), so the
// guarded function receives no C++ objects at all: it calls a POD-shaped
// thunk that writes into a raw buffer and reports a status code.
typedef int (*PackedFn)(const wchar_t* text, char* out, size_t outCap, size_t* outLen);

static int GuardCall(PackedFn fn, const wchar_t* text, char* out, size_t outCap,
                     size_t* outLen, unsigned* code) {
    int ok = 0;
    __try {
        ok = fn(text, out, outCap, outLen);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *code = GetExceptionCode();
        ok = 0;
    }
    return ok;
}

// Runs one command under SEH. A crash becomes a JSON error reply instead of
// taking the host process down with it.
namespace {

// Carries the real command function through a POD-only interface.
struct ThunkCtx {
    CommandFn fn;
};
ThunkCtx g_thunk{};

int PackedThunk(const wchar_t* text, char* out, size_t outCap, size_t* outLen) {
    if (!g_thunk.fn) return 0;
    std::string tmp = g_thunk.fn(std::wstring(text ? text : L""));
    size_t n = tmp.size();
    if (n > outCap - 1) n = outCap - 1;
    memcpy(out, tmp.data(), n);
    out[n] = 0;
    *outLen = n;
    return 1;
}

}  // namespace

static std::string Guarded(const wchar_t* what, CommandFn fn, const std::wstring& args) {
    wchar_t safe[1024] = {};
    wcsncpy_s(safe, _countof(safe), args.c_str(), _TRUNCATE);

    static std::vector<char> buffer(512 * 1024);
    buffer.resize(512 * 1024);

    g_thunk.fn = fn;
    size_t len = 0;
    unsigned code = 0;
    if (GuardCall(PackedThunk, safe, buffer.data(), buffer.size(), &len, &code))
        return std::string(buffer.data(), len);

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
    HookInstallFaultLogger();
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

        if (wcsncmp(g_io->request, L"exports", 7) == 0) {
            PutResponse(Guarded(L"exports", ExportsToJson,
                                std::wstring(g_io->request).size() > 8
                                    ? std::wstring(g_io->request).substr(8)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"mods", 4) == 0) {
            PutResponse(Guarded(L"mods", ModsToJson,
                                std::wstring(g_io->request).size() > 5
                                    ? std::wstring(g_io->request).substr(5)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"memmap", 6) == 0) {
            PutResponse(Guarded(L"memmap", MemMapToJson, std::wstring(g_io->request).size() > 7
                                                            ? std::wstring(g_io->request).substr(7)
                                                            : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"heapobjects", 10) == 0) {
            PutResponse(Guarded(L"heapobjects", HeapObjectsToJson,
                                std::wstring(g_io->request).size() > 11
                                    ? std::wstring(g_io->request).substr(11)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"findvalue", 9) == 0) {
            PutResponse(Guarded(L"findvalue", FindValueToJson,
                                std::wstring(g_io->request).size() > 10
                                    ? std::wstring(g_io->request).substr(10)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"byhwnd", 6) == 0) {
            PutResponse(Guarded(L"byhwnd", ByHwndToJson, std::wstring(g_io->request).size() > 7
                                                             ? std::wstring(g_io->request).substr(7)
                                                             : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"around", 6) == 0) {
            PutResponse(Guarded(L"around", AroundToJson, std::wstring(g_io->request).size() > 7
                                                              ? std::wstring(g_io->request).substr(7)
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

        if (wcsncmp(g_io->request, L"cmd ", 4) == 0) {
            LogLine("cmd: invoking designer command");
            PutResponse(Guarded(L"cmd", CmdCommandToJson, std::wstring(g_io->request).substr(4)));
            LogLine("cmd: done");
            continue;
        }

        // ---- extension layer: hooks and call tracing ----
        if (wcscmp(g_io->request, L"hooks") == 0) {
            PutResponse(Guarded(L"hooks", HooksCommandToJson, std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"hook ", 5) == 0) {
            LogLine("hook: installing");
            PutResponse(Guarded(L"hook", HookCommandToJson, std::wstring(g_io->request + 5)));
            continue;
        }

        if (wcsncmp(g_io->request, L"unhook", 6) == 0) {
            LogLine("unhook: restoring");
            PutResponse(Guarded(L"unhook", UnhookCommandToJson,
                                std::wstring(g_io->request).size() > 7
                                    ? std::wstring(g_io->request).substr(7)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"trace", 5) == 0) {
            PutResponse(Guarded(L"trace", TraceCommandToJson,
                                std::wstring(g_io->request).size() > 6
                                    ? std::wstring(g_io->request).substr(6)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"gitbar", 6) == 0) {
            PutResponse(Guarded(L"gitbar", GitBarCommandToJson,
                                std::wstring(g_io->request).size() > 7
                                    ? std::wstring(g_io->request).substr(7)
                                    : std::wstring()));
            continue;
        }

        if (wcscmp(g_io->request, L"menu") == 0 ||
            wcsncmp(g_io->request, L"menu ", 5) == 0) {
            PutResponse(Guarded(L"menu", MenuCommandToJson,
                                std::wstring(g_io->request).size() > 5
                                    ? std::wstring(g_io->request).substr(5)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"str ", 4) == 0) {
            PutResponse(Guarded(L"str", StrToJson,
                                std::wstring(g_io->request).substr(4)));
            continue;
        }

        if (wcsncmp(g_io->request, L"menucmd", 7) == 0) {
            PutResponse(Guarded(L"menucmd", MenuCmdToJson,
                                std::wstring(g_io->request).size() > 8
                                    ? std::wstring(g_io->request).substr(8)
                                    : std::wstring()));
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

    // Hooks must be gone before the DLL that owns their thunks is unloaded.
    {
        size_t removed = HookRemoveAll();
        if (removed) LogLine("payload exit: %zu hook(s) restored", removed);
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

