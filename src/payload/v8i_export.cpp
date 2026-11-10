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
#else
uintptr_t g_x64FrameObj = 0;   // discovered frame object (x64 runtime calibration)
uintptr_t g_x64RecvOffset = 0x20;
bool g_x64DiscoveryDone = false;       // discovery attempted this session
ULONGLONG g_x64DiscoveryTick = 0;      // cooldown gate for re-discovery
#endif
}

// SEH cannot live in a function that needs C++ unwinding (MSVC C2712); the
// transmit call is isolated in a POD-only helper.
#if defined(_WIN64)
typedef int(__fastcall* V8iTransmitFn)(void*, const void*, uint8_t);
#else
// 1C x86 interface methods are C-style: self is the FIRST STACK argument and
// the callee pops it (ret 0xC for transmitCommand) — verified against
// frame.dll+0x8980A0 (`ret 0xc`, reads [ebp+8]=self, [ebp+0xC]=cmd,
// [ebp+0x10]=deactivate).
typedef int(__stdcall* V8iTransmitFn)(void*, const void*, int);
#endif
#if defined(_WIN64)
typedef int(__fastcall* V8iHasFn)(void*, const void*);
#else
typedef int(__stdcall* V8iHasFn)(void*, const void*);
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
// 8.5 command receiver, captured from the slot-31 forwarder of a live
// ITopLevelFrame (declared here: the marshal bridges below read them).
static uintptr_t g85_recv = 0;
static uintptr_t g85_recvVt = 0;
static void V8iCaptureCmdRecv(void* obj);   // 8.5 slot-31 walk, defined below
namespace {
const UINT kV8iCmdMsg = WM_APP + 0x2F11;
struct V8iPending {
    void* recv;
    void* trFn;
    // Command buffer, shared by both platform layouts at the same address.
    // 8.3 transmits V8Cmd (32 bytes); 8.5 expects the RECON-85 layout
    // (CommandID padded to 24, param at 24, object at 32 — 40 bytes). The
    // sender zeroes raw first, so either interpretation of the padding reads
    // param=0 / object=nullptr. hasHandler (CommandID, 20 bytes) is identical
    // in both layouts.
    union {
        V8Cmd cmd;
        unsigned char raw[48];
    } u;
    volatile LONG done;
    int rc;
    LONG exc;
    int mode;   // 0 = transmitCommand(recv, &cmd, 0), 1 = hasHandler(recv, &cmd),
                // 2 = capture the 8.5 receiver from the frame object in recv
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
        if (p->mode == 2) {
            // The slot-31 walk calls into core85, which on 8.5 only answers on
            // the UI thread — so the capture rides the same marshal bridge.
            V8iCaptureCmdRecv(p->recv);
            p->rc = g85_recv ? 0 : -1;
        } else {
            p->rc = p->mode == 1 ? HasGuarded(p->trFn, p->recv, &p->u.cmd)
                                 : TransmitGuarded(p->trFn, p->recv, &p->u.cmd);
            if (p->rc < 0) p->exc = g_cmdLastExc;
        }
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
        if (g_pending.mode == 2) {
            V8iCaptureCmdRecv(g_pending.recv);
            g_pending.rc = g85_recv ? 0 : -1;
        } else {
            g_pending.rc = g_pending.mode == 1
                               ? HasGuarded(g_pending.trFn, g_pending.recv, &g_pending.u.cmd)
                               : TransmitGuarded(g_pending.trFn, g_pending.recv, &g_pending.u.cmd);
            if (g_pending.rc < 0) g_pending.exc = g_cmdLastExc;
        }
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
        if (w.cls == L"V8TopLevelFrame" ||
            w.cls.rfind(L"V8Window0", 0) == 0) { frame = w.hwnd; break; }
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

#if defined(_WIN64)
// True when `vt` is a config.dll .rdata table whose slots 3..40 point into
// config.dll .text — the shape shared by the ITopLevelFrame vtable family.
// Used both by the discovery and to re-validate the cached frame object:
// 1C destroys transient frames, and freed memory reads as garbage (live:
// a stale object's "vtable" was a module base).
static bool X64FrameVtValid(const ModuleRange& cfg, uintptr_t vt) {
    if (!vt) return false;
    PeImage cfgImg = ParsePe(cfg.base);
    if (!cfgImg.valid) return false;
    const PeSection* textSec = nullptr;
    const PeSection* rdataSec = nullptr;
    for (const PeSection& s : cfgImg.sections) {
        if (s.Executable() && s.name == ".text") textSec = &s;
        if (s.Readable() && !s.Executable() && s.name == ".rdata") rdataSec = &s;
    }
    if (!textSec || !rdataSec) return false;
    const uintptr_t textLo = cfg.base + textSec->va;
    const uintptr_t textHi = textLo + textSec->virtualSize;
    const uintptr_t rdataLo = cfg.base + rdataSec->va;
    const uintptr_t rdataHi = rdataLo + rdataSec->virtualSize;
    if (vt < rdataLo || vt >= rdataHi) return false;
    if (!IsReadable((void*)vt, 41 * sizeof(void*))) return false;
    for (int s = 3; s <= 40; ++s) {
        uintptr_t fn = ((uintptr_t*)vt)[s];
        if (fn < textLo || fn >= textHi) return false;
    }
    return true;
}

// x64 runtime calibration: the hardcoded ITopLevelFrame vtable RVA below is
// valid for 8.3.27.1989 only — on other 8.3 patches (8.3.27.2342, live) an
// unrelated vtable sits at the same RVA, the scan finds a wrong object and
// the receiver chain fails ("no working receiver chain"). Same heuristics as
// the x86 discovery: a heap object whose vtable lives in config.dll .rdata
// with slots 3..40 pointing into config.dll .text, and whose receiver chain
// (core = obj+8, recv = core - off, recvVt readable, transmit slot readable
// inside a loaded module) validates. POD-only reads; no calls into 1C.
static uintptr_t DiscoverFrameVtblX64(const ModuleRange& cfg) {
    PeImage cfgImg = ParsePe(cfg.base);
    if (!cfgImg.valid) return 0;
    const PeSection* rdataSec = nullptr;
    for (const PeSection& s : cfgImg.sections) {
        if (s.Readable() && !s.Executable() && s.name == ".rdata") rdataSec = &s;
    }
    if (!rdataSec) return 0;
    const uintptr_t rdataLo = cfg.base + rdataSec->va;
    const uintptr_t rdataHi = rdataLo + rdataSec->virtualSize;

    std::vector<ModuleRange> mods;
    for (const ModuleRange& m : EnumModules()) mods.push_back(m);
    auto insideModule = [&mods](uintptr_t a) {
        for (const ModuleRange& m : mods)
            if (a >= m.base && a < m.base + m.size) return true;
        return false;
    };

    // one heap walk: objects whose first qword is a config.dll .rdata vtable
    std::vector<uintptr_t> objs;
    uintptr_t addr = 0x10000;
    while (addr < 0x00007FFFFFFFFFFFULL) {
        MEMORY_BASIC_INFORMATION mi = {};
        if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
        uintptr_t end = addr + mi.RegionSize;
        bool usable = mi.State == MEM_COMMIT &&
                      (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                      !(mi.Protect & PAGE_GUARD);
        if (usable) {
            const uintptr_t cap = mi.RegionSize > 64 * 1024 * 1024
                                      ? 64 * 1024 * 1024 : (uintptr_t)mi.RegionSize;
            for (uintptr_t p = (uintptr_t)mi.BaseAddress;
                 p < (uintptr_t)mi.BaseAddress + cap; p += sizeof(void*)) {
                uintptr_t v = *(uintptr_t*)p;
                if (v < rdataLo || v >= rdataHi) continue;
                if (!X64FrameVtValid(cfg, v)) continue;
                objs.push_back(p);
                if (objs.size() >= 64) break;
            }
        }
        if (objs.size() >= 64) break;
        addr = end == addr ? addr + sizeof(void*) : end;
    }

    // receiver chain must validate; try the documented offset first. The
    // structural checks alone are NOT enough (8.3.27.2342 live: nine heap
    // slots pass them, the first pick was garbage that died within 21 ms) —
    // every candidate is probed live: hasHandler(45) on the UI thread through
    // the marshal bridge. Only a receiver that answers without an exception
    // is trusted; the first alive-but-silent one is the fallback.
    static const uintptr_t kRecvOffs[] = {0x20, 0x10, 0x18, 0x28, 0x30, 0x38, 0x40, 0x08};
    uintptr_t fallbackObj = 0, fallbackOff = 0;
    for (uintptr_t obj : objs) {
        uintptr_t core = *(uintptr_t*)(obj + sizeof(void*));
        if (!IsReadable((void*)core, sizeof(void*))) continue;
        for (uintptr_t off : kRecvOffs) {
            uintptr_t recv = core - off;
            if (!IsReadable((void*)recv, sizeof(void*))) continue;
            uintptr_t recvVt = *(uintptr_t*)recv;
            if (!IsReadable((void*)recvVt, 6 * sizeof(void*))) continue;
            if (!insideModule(recvVt)) continue;
            uintptr_t tr = ((uintptr_t*)recvVt)[3];
            if (!insideModule(tr)) continue;
            if (!IsReadable((void*)tr, 32)) continue;
            if (*(const unsigned char*)tr == 0xCC) continue;   // int3 padding, not code

            // live probe: hasHandler(45), mode 1, SEH on the UI thread
            HWND probeHwnd = nullptr;
            DWORD probeErr = 0;
            const char* probePath = "";
            if (!EnsureCmdUi(&probeHwnd, &probeErr, &probePath))
                break;   // no frame window yet — fall back to structural pick
            void* hasTr = (void*)((uintptr_t*)recvVt)[5];
            if (!IsReadable(hasTr, 1)) continue;
            g_pending.recv = (void*)recv;
            g_pending.trFn = hasTr;
            g_pending.mode = 1;
            memcpy(g_pending.u.cmd.group, kConfigGroup, 16);
            g_pending.u.cmd.cmdNum = 45;
            g_pending.u.cmd.param = 0;
            g_pending.u.cmd.object = nullptr;
            g_pending.rc = -2;
            g_pending.exc = 0;
            InterlockedExchange(&g_pending.done, 0);
            DWORD_PTR probeRes = 0;
            if (!SendMessageTimeoutW(probeHwnd, kV8iCmdMsg, 0, 0,
                                     SMTO_ABORTIFHUNG | SMTO_BLOCK, 10000, &probeRes))
                continue;
            if (g_pending.exc != 0 || g_pending.rc < 0) continue;   // wrong chain
            if (g_pending.rc == 0 && fallbackObj == 0) {
                fallbackObj = obj; fallbackOff = off;   // alive, no handler yet
                continue;
            }
            g_x64RecvOffset = off;
            LogLine("cmd x64 discovery: frame=0x%llX recvOff=0x%llX recv=0x%llX probed=1",
                    (unsigned long long)obj, (unsigned long long)off,
                    (unsigned long long)recv);
            return obj;
        }
    }
    if (fallbackObj) {
        g_x64RecvOffset = fallbackOff;
        LogLine("cmd x64 discovery: frame=0x%llX recvOff=0x%llX (fallback, alive)",
                (unsigned long long)fallbackObj, (unsigned long long)fallbackOff);
        return fallbackObj;
    }
    return 0;
}
#endif

// A heap page can be freed between VirtualQuery and the read (1C allocates
// constantly), and a vtable near the end of .rdata can overrun into a page the
// loader did not commit. Both faults used to take down the payload io thread.
static bool ReadU32Safe(uintptr_t addr, uint32_t* out) {
    __try {
        *out = *(uint32_t*)addr;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool ReadPtrSafe(uintptr_t addr, uintptr_t* out) {
    __try {
        *out = *(uintptr_t*)addr;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

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
                uint32_t v = 0;
                if (!ReadU32Safe(p, &v)) continue;
                if (v < (uint32_t)rdataLo || v >= (uint32_t)rdataHi) continue;
                // vtable start must satisfy: no header dwords (IUnknown trio) — slots 3..40 in .text
                bool ok = true;
                for (int s = 3; s <= 40; ++s) {
                    uint32_t fn = 0;
                    if (!ReadU32Safe((uintptr_t)v + s * 4, &fn) ||
                        fn < (uint32_t)textLo || fn >= (uint32_t)textHi) { ok = false; break; }
                }
                if (!ok) continue;
                objs.push_back(p);
            }
        }
        addr = end == addr ? addr + 4 : end;
    }

    // try each (object, vtable) — receiver chain must land in frame.dll
    static const uintptr_t kRecvOffs[] = {0x10, 0x20, 0x1C, 0x18, 0x14, 0x24, 0x28,
                                          0x0C, 0x08, 0x04, 0x30, 0x34, 0x38, 0x3C, 0x40};
    for (size_t i = 0; i < objs.size(); ++i) {
        uint32_t core32 = 0;
        if (!ReadU32Safe(objs[i] + 4, &core32) || !core32) continue;
        uintptr_t core = core32;
        if (!IsReadable((void*)core, 4)) continue;
        for (size_t off = 0; off < sizeof(kRecvOffs) / sizeof(kRecvOffs[0]); ++off) {
            uintptr_t recv = core - kRecvOffs[off];
            uint32_t recvVt = 0;
            if (!ReadU32Safe(recv, &recvVt)) continue;
            if (!haveFrame) continue;
            if (recvVt < (uint32_t)frameRdataLo || recvVt >= (uint32_t)frameRdataHi) continue;
            uint32_t tr = 0;
            if (!ReadU32Safe((uintptr_t)recvVt + 3 * 4, &tr)) continue;
            if (tr < (uint32_t)frameTextLo || tr >= (uint32_t)frameTextHi) continue;
            // transmitCommand is a real method (thiscall, 2 stack args -> ret 8),
            // NOT a 6-byte property getter `mov eax,[ebp+8]; mov eax,[eax+off]; pop ebp; ret 4`
            // (several interface wrapper vtables near the frame use those).
            const unsigned char* code = (const unsigned char*)tr;
            if (!IsReadable((void*)code, 0x60)) continue;
            static const unsigned char kGetter[] = {0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x40};
            if (memcmp(code, kGetter, sizeof(kGetter)) == 0) continue;
            bool sawRet = false;
            for (int b = 0; b < 0x100; ++b) {
                if (code[b] == 0xC2 && b + 2 < 0x100 &&
                    ((code[b + 1] == 0x08 && code[b + 2] == 0x00) ||   // 2 stack args
                     (code[b + 1] == 0x0C && code[b + 2] == 0x00))) {  // 3 stack args (self, cmd, deact)
                    sawRet = true;
                    break;
                }
            }
            if (!sawRet) continue;
            g_x86RecvOffset = kRecvOffs[off];
            return objs[i];  // the frame object itself (vtable validated above)
        }
    }
    return 0;
}
#endif

typedef HRESULT(__stdcall* V8iQIFn)(void*, const GUID*, void**);
static int V8iQIProbe(void* obj, const GUID* iid, void** out) {
    int rc = -1;
    __try {
        rc = ((V8iQIFn)(*(void**)obj))(obj, iid, out);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        rc = -2;
    }
    return rc;
}

static void* V8iCallNoArg(uintptr_t fn) {
    void* r = nullptr;
    __try {
        r = ((void*(__cdecl*)())fn)();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        r = nullptr;
    }
    return r;
}

// --- 8.5 UI-thread bridge ---
// 1C 8.5 crashes (0xC0000005) when core85 functions are called from a foreign
// thread. To run them on the UI thread we subclass the main window for a
// moment and post WM_APP+0x602; the subclass proc executes
// current_process() -> getService(IID_IEventService) and caches the results.
// (g85_recv / g85_recvVt live near the top of the file, next to the marshal
// bridge that reads them.)
static uintptr_t g85_fn = 0;
static uintptr_t g85_proc = 0;
static uintptr_t g85_procVt = 0;
static uintptr_t g85_svc = 0;
static uintptr_t g85_svcVt = 0;
static uintptr_t g85_svc2 = 0;
static uintptr_t g85_svc2Vt = 0;
static uintptr_t g85_svc3 = 0;
static uintptr_t g85_svc3Vt = 0;
static uintptr_t g85_svc4 = 0;
static uintptr_t g85_svc4Vt = 0;
static int g85_svcSlot = -1;
static int g85_svc2Slot = -1;
static uintptr_t g85_frame = 0;
static uintptr_t g85_frameVt = 0;
static uintptr_t g85_frames[4] = {};
static int g85_nFrames = 0;
static uintptr_t g85_qProcFrame = 0, g85_qProcRecv = 0;
static uintptr_t g85_qCmdFrame = 0, g85_qCmdRecv = 0;
static uintptr_t g85_qEvFrame = 0, g85_qEvRecv = 0;
static int g85_sawMsg = 0;
static volatile int g85_subscribed = 0;
static uintptr_t g85_slots[24] = {};
static uintptr_t g85_uiWin = 0;
static uintptr_t g85_evFrame = 0;
static volatile long g85_evCount = 0;
static const GUID g85_kExitEv = {0x18B3F170, 0x4979, 0x11D6,
                                 {0xB2, 0x2B, 0x00, 0x50, 0xBA, 0xE2, 0xBC, 0x79}};
// eventCreateFrame: fired when the platform creates a frame; the event object
// IS the ITopLevelFrame (verified live on 8.5.1.1529 — object vtable
// config.dll+0x2ED3B0, and its vtbl[30] gives the command receiver).
static const GUID g85_kCreateFrameEv = {0x3573FFE0, 0x2FFF, 0x11D5,
                                        {0xBF, 0x5E, 0x00, 0x50, 0xBA, 0xE2, 0xBC, 0x79}};
static volatile long g85_exitEvCount = 0;
static volatile unsigned long g85_attachTick = 0;
// Diagnostic split of the two candidate receiver chains — one live run settles
// which is real on 8.5 (the code comment below claimed A; the skill's later
// live finding is B):
//   A) obj IS ITopLevelFrame         -> obj->vtbl[30] = commandReceiver
//   B) obj is an IUnknown wrapper   -> QI(obj, IID_ITopLevelFrame) = frame
//                                        -> frame->vtbl[30] = commandReceiver
// Both results are kept so cmdinfo/frames can report them without guessing.
static const GUID g85_kIID_TopFrame = {0xDE300901, 0xA120, 0x11d4,
                                       {0x94, 0x29, 0x00, 0x80, 0x48, 0xDA, 0x11, 0xF9}};
static uintptr_t g85_dirRecv = 0, g85_dirRecvVt = 0;       // path A: obj->vtbl[30]
static uintptr_t g85_qiFrame = 0, g85_qiFrameVt = 0;       // path B: QI(obj) result
static uintptr_t g85_qiRecv = 0, g85_qiRecvVt = 0;         // path B: frame->vtbl[30]
static long g85_dirExc = 0;    // exception from calling vtbl[30] on obj (A)
static long g85_qiExc = 0;     // error code from QI(obj) (B)
static long g85_qiCallExc = 0; // exception from vtbl[30] on the QI'd frame (B)
static uintptr_t g85_dump[4] = {};                       // obj qwords (layout)

typedef void* (__cdecl* V8iCurProcFn)();
typedef void* (__cdecl* V8iGetSvcFn)(void*, const GUID*);
static WNDPROC g85_origWndProc = nullptr;

static void V8iScanFrame85();

static LRESULT CALLBACK V8iSubclass85(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_APP + 0x602) {
        g85_sawMsg = 1;
        void* proc = nullptr;
        __try {
            proc = ((V8iCurProcFn)g85_fn)();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            proc = nullptr;
        }
        g85_proc = (uintptr_t)proc;
        g85_procVt = proc ? *(uintptr_t*)proc : 0;
        for (int i = 0; i < 24; ++i) {
            g85_slots[i] = 0;
            __try { g85_slots[i] = ((uintptr_t*)g85_procVt)[i]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { g85_slots[i] = 0; }
        }
        if (proc && g85_procVt) {
            static const GUID kIID_EventService = {0xEBF766AA, 0xF32C, 0x11D3,
                                                   {0x98, 0x51, 0x00, 0x80, 0x48, 0xDA, 0x12, 0x52}};
            static const GUID kIID_CmdService = {0x8F885821, 0xD353, 0x11D3,
                                                 {0x8A, 0x57, 0x00, 0x80, 0x48, 0xDA, 0x06, 0xDF}};
            void* svc = nullptr;
            void* svc2 = nullptr;
            void* svc3 = nullptr;
            void* svc4 = nullptr;
            int svcSlot = -1, svc2Slot = -1;
            __try {
                for (int slot : {14, 15}) {
                    uintptr_t f = 0;
                    __try { f = ((uintptr_t*)g85_procVt)[slot]; }
                    __except (EXCEPTION_EXECUTE_HANDLER) { f = 0; }
                    if (!f) continue;
                    void* r1 = nullptr, * r2 = nullptr;
                    __try { r1 = ((V8iGetSvcFn)f)(proc, &kIID_EventService); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { r1 = (void*)-1; }
                    __try { r2 = ((V8iGetSvcFn)f)(proc, &kIID_CmdService); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { r2 = (void*)-1; }
                    if (slot == 14) { svc = r1; svc2 = r2; svcSlot = (r1 && r1 != (void*)-1) ? 14 : -1; svc2Slot = (r2 && r2 != (void*)-1) ? 14 : -1; }
                    else { svc3 = r1; svc4 = r2; }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                svc = nullptr;
            }
            g85_svc = (uintptr_t)svc;
            g85_svcVt = svc && svc != (void*)-1 ? *(uintptr_t*)svc : 0;
            g85_svc2 = (uintptr_t)svc2;
            g85_svc2Vt = svc2 && svc2 != (void*)-1 ? *(uintptr_t*)svc2 : 0;
            g85_svc3 = (uintptr_t)svc3;
            g85_svc3Vt = svc3 && svc3 != (void*)-1 ? *(uintptr_t*)svc3 : 0;
            g85_svc4 = (uintptr_t)svc4;
            g85_svc4Vt = svc4 && svc4 != (void*)-1 ? *(uintptr_t*)svc4 : 0;
            g85_svcSlot = svcSlot;
            g85_svc2Slot = svc2Slot;

            // QI the objects we already hold for ITopLevelFrame/ICommandReceiver
            {
                static const GUID kIID_TopFrame = {0xDE300901, 0xA120, 0x11d4,
                                                   {0x94, 0x29, 0x00, 0x80, 0x48, 0xDA, 0x11, 0xF9}};
                static const GUID kIID_CmdRecv = {0x377A2018, 0xC51B, 0x4cf5,
                                                  {0xAC, 0x03, 0xA1, 0x50, 0x92, 0x66, 0xDF, 0x2D}};
                struct { uintptr_t obj; uintptr_t* out; } probes[] = {
                    {g85_proc, &g85_qProcFrame}, {g85_proc, &g85_qProcRecv},
                    {g85_svc2, &g85_qCmdFrame}, {g85_svc2, &g85_qCmdRecv},
                    {g85_svc, &g85_qEvFrame}, {g85_svc, &g85_qEvRecv},
                };
                const GUID* iids[] = {&kIID_TopFrame, &kIID_CmdRecv, &kIID_TopFrame,
                                      &kIID_CmdRecv, &kIID_TopFrame, &kIID_CmdRecv};
                for (int i = 0; i < 6; ++i) {
                    *probes[i].out = 0;
                    if (!probes[i].obj || !IsReadable((void*)probes[i].obj, 16)) continue;
                    void* out = nullptr;
                    if (V8iQIProbe((void*)probes[i].obj, iids[i], &out) == 0 && out)
                        *probes[i].out = (uintptr_t)out;
                }
            }

            // QI the window's OLE drop target — it is a real 1C object
            if (g85_uiWin) {
                static const GUID kIID_TopFrame = {0xDE300901, 0xA120, 0x11d4,
                                                   {0x94, 0x29, 0x00, 0x80, 0x48, 0xDA, 0x11, 0xF9}};
                static const GUID kIID_CmdRecv = {0x377A2018, 0xC51B, 0x4cf5,
                                                  {0xAC, 0x03, 0xA1, 0x50, 0x92, 0x66, 0xDF, 0x2D}};
                uintptr_t dt = (uintptr_t)GetPropW((HWND)g85_uiWin, L"OleDropTargetInterface");
                if (dt && IsReadable((void*)dt, 16)) {
                    void* o1 = nullptr;
                    void* o2 = nullptr;
                    if (V8iQIProbe((void*)dt, &kIID_TopFrame, &o1) == 0 && o1)
                        g85_qProcFrame = (uintptr_t)o1;
                    if (V8iQIProbe((void*)dt, &kIID_CmdRecv, &o2) == 0 && o2)
                        g85_qProcRecv = (uintptr_t)o2;
                }
            }

            // Slot 27 copies {ptr, refcount} from [rcx+0x148] — looks like a
            // getTopLevelFrame-style getter. Try it, then QI the result for
            // ICommandReceiver.
            if (proc) {
                struct { void* p; void* rc; } fr{};
                __try {
                    uintptr_t f27 = ((uintptr_t*)g85_procVt)[27];
                    if (f27)
                        ((void(__cdecl*)(void*, void*))f27)(proc, &fr);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    fr.p = nullptr;
                }
                g85_frame = (uintptr_t)fr.p;
                g85_frameVt = fr.p ? *(uintptr_t*)fr.p : 0;
                if (fr.p) {
                    static const GUID kIID_CmdRecv = {0x377A2018, 0xC51B, 0x4cf5,
                                                      {0xAC, 0x03, 0xA1, 0x50, 0x92, 0x66, 0xDF, 0x2D}};
                    void* recv = nullptr;
                    __try {
                        uintptr_t qi = 0;
                        __try { qi = ((uintptr_t*)*(uintptr_t*)fr.p)[0]; }
                        __except (EXCEPTION_EXECUTE_HANDLER) { qi = 0; }
                        if (qi)
                            ((HRESULT(__stdcall*)(void*, const GUID*, void**))qi)(
                                fr.p, &kIID_CmdRecv, &recv);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        recv = nullptr;
                    }
                    g85_recv = (uintptr_t)recv;
                    g85_recvVt = recv ? *(uintptr_t*)recv : 0;
                }
            }

            // Heap QI scan for IID_ITopLevelFrame — done in a helper that avoids
            // __try/C++ object conflicts; QI goes through the SEH probe.
            V8iScanFrame85();
            // Trace which stage the subscribe chain reached, for the early-path
            // diagnosis (hookcbt loads the payload without a cmdinfo run).
            {
                FILE* tf = nullptr;
                if (_wfopen_s(&tf, L"C:\\Users\\fishca\\AppData\\Local\\Temp\\v8i_subscribe.txt", L"a") == 0 && tf) {
                    fprintf(tf, "dt=%lu fn=%llx proc=%llx procVt=%llx svc=%llx svcVt=%llx "
                                "subscribed=%d evCount=%ld exitEv=%ld evFrame=%llx\n",
                            GetTickCount() - g85_attachTick, (unsigned long long)g85_fn,
                            (unsigned long long)g85_proc, (unsigned long long)g85_procVt,
                            (unsigned long long)g85_svc, (unsigned long long)g85_svcVt,
                            g85_subscribed, g85_evCount, g85_exitEvCount,
                            (unsigned long long)g85_evFrame);
                    fclose(tf);
                }
            }
        }
        return 0;
    }
    return g85_origWndProc ? CallWindowProcW(g85_origWndProc, h, m, w, l) : 0;
}

// Startup watch: the payload may be injected before 1C creates its main
// window. A worker polls for the window and, the moment it exists, runs the
// subscribe chain on the UI thread (through the subclass bridge) — early
// enough for the platform to deliver eventCreateFrame to us.
static BOOL CALLBACK V8iFindMainWindow(HWND w, LPARAM lp) {
    wchar_t cls[64] = {};
    GetClassNameW(w, cls, 64);
    if (wcsncmp(cls, L"V8Window0", 9) == 0 || wcsncmp(cls, L"V8TopLevelFrame", 15) == 0) {
        *(HWND*)lp = w;
        return FALSE;
    }
    return TRUE;
}

static LRESULT CALLBACK V8iCbtProc(int nCode, WPARAM wParam, LPARAM lParam);
static HHOOK g_cbtThreadHook;
static volatile long g_cbtThreadTid;
static void V8iResolveCore85Proc(uintptr_t* outBase, uint32_t* outRva);

static DWORD WINAPI V8iStartupWatchThread(LPVOID) {
    for (int i = 0; i < 4000 && !g85_subscribed; ++i) {
        HWND h = nullptr;
        EnumWindows(V8iFindMainWindow, (LPARAM)&h);
        if (h) {
            g85_uiWin = (uintptr_t)h;
            g85_origWndProc = (WNDPROC)SetWindowLongPtrW(h, GWLP_WNDPROC,
                                                         (LONG_PTR)V8iSubclass85);
            if (g85_origWndProc) {
                SendMessageW(h, WM_APP + 0x602, 0, 0);
                SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)g85_origWndProc);
            }
            // The global CBT hook never fires in 8.5 (cbtCalls stays 0 even for
            // newly opened windows), so try a thread-scoped one on the UI thread.
            if (!g_cbtThreadHook) {
                DWORD tid = GetWindowThreadProcessId(h, nullptr);
                HINSTANCE self = nullptr;
                GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCWSTR)&V8iCbtProc, &self);
                HHOOK th = SetWindowsHookExW(WH_CBT, (HOOKPROC)&V8iCbtProc, self, tid);
                if (th) {
                    g_cbtThreadHook = th;
                    g_cbtThreadTid = (long)tid;
                }
            }
            // The core is not ready the instant the window appears, so keep
            // retrying until the subscribe chain actually succeeds.
            if (g85_subscribed) return 0;
            Sleep(50);
            continue;
        }
        Sleep(5);
    }
    return 0;
}

// --- early subscribe (plan_inj_ext P0-2) -----------------------------------
// Snegopat catches window creation with a WH_CBT hook and subscribes while the
// platform DLLs are loaded but the main window does not exist yet. Subscribing
// inside the hook itself crashes 1C (the core is not ready at that point), so
// the hook only remembers the window and starts a worker that retries the
// subscribe chain on that window's UI thread until the core answers.
static HHOOK g_cbtHook = nullptr;
static volatile long g_cbtFault = 0;
static volatile long g_cbtCalls = 0;
static volatile long g_cbtLastCode = -1;
static volatile long g_cbtCreateCount = 0;
static volatile long g_cbtStrCreates = 0;
static char g_cbtFirstClass[96] = {};
static char g_cbtLastClass[96] = {};
static DWORD g_ownerPid = 0;
static volatile int g_cbtFired = 0;

static DWORD WINAPI V8iEarlySubscribeThread(LPVOID);

// True when the current process is a 1C:Enterprise Configurator. The hook is
// loaded into every GUI process by the global WH_CBT, but only 1C is worth
// arming. Works even before the session sets g_ownerPid (the hook fires while
// the payload is still being loaded by Windows itself).
static bool V8iIsTargetProcess() {
    wchar_t path[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    const wchar_t* leaf = wcsrchr(path, L'\\');
    leaf = leaf ? leaf + 1 : path;
    return _wcsicmp(leaf, L"1cv8.exe") == 0 ||
           _wcsicmp(leaf, L"1cv8c.exe") == 0;
}

static LRESULT CALLBACK V8iCbtProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // A fault inside a hook callback terminates the whole process
    // (0xC000041D), and during 1C start-up almost nothing is safe to call, so
    // the whole body sits under SEH: a failure must not kill the Configurator.
    __try {
        InterlockedIncrement(&g_cbtCalls);
        // Ignore non-1C processes the global hook is also delivered to
        // (Explorer etc). The pid filter alone is wrong: when the payload is
        // pulled in by the hook itself g_ownerPid is still 0.
        if (!V8iIsTargetProcess())
            return CallNextHookEx(g_cbtHook, nCode, wParam, lParam);
        if (nCode == HCBT_CREATEWND) {
            InterlockedIncrement(&g_cbtCreateCount);
            HWND hwnd = (HWND)wParam;
            CBT_CREATEWNDW* cw = (CBT_CREATEWNDW*)lParam;
            const wchar_t* cls = (cw && cw->lpcs) ? cw->lpcs->lpszClass : nullptr;
            // Remember what actually arrives, so the filter can be fixed from
            // real data instead of guesses.
            g_cbtLastCode = nCode;
            if (cls && cls > (const wchar_t*)0x10000 && IsReadable(cls, 96)) {
                size_t k = 0;
                for (; k < sizeof(g_cbtLastClass) - 1 && cls[k]; ++k)
                    g_cbtLastClass[k] = (char)((cls[k] < 128) ? cls[k] : '?');
                g_cbtLastClass[k] = 0;
                if (InterlockedIncrement(&g_cbtStrCreates) == 1 && k)
                    memcpy(g_cbtFirstClass, g_cbtLastClass, sizeof(g_cbtFirstClass));
                // Dump every string class that reaches the hook, so we can see
                // whether the main window "V8Window0.xxx" passes through here
                // at all.
                FILE* cf = nullptr;
                if (_wfopen_s(&cf, L"C:\\Users\\fishca\\AppData\\Local\\Temp\\v8i_cbt_classes.txt", L"a") == 0 && cf) {
                    fprintf(cf, "%s\n", g_cbtLastClass);
                    fclose(cf);
                }
            } else {
                g_cbtLastClass[0] = 0;
            }
            // On 8.5 the main window is created with a numeric class in
            // CREATESTRUCT.lpszClass, so "V8Window0.xxx" never shows up here
            // (it is only visible via GetClassName on the finished window).
            // Exactly why Snegopat is force-patched on 8.5 to take the first
            // window. Only the first window of the Configurator is needed to
            // arm the subscribe chain — take it and unhook so nothing can
            // re-enter.
            if (!g_cbtFired) {
                g_cbtFired = 1;
                g85_uiWin = (uintptr_t)hwnd;
                HHOOK h = g_cbtHook;
                g_cbtHook = nullptr;
                if (h) UnhookWindowsHookEx(h);
                CreateThread(nullptr, 0, V8iEarlySubscribeThread, (LPVOID)hwnd, 0, nullptr);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_cbtFault = GetExceptionCode();
    }
    return CallNextHookEx(g_cbtHook, nCode, wParam, lParam);
}

// Installs the hook; called from v8i_probe before the session starts, so the
// splash screen is still ahead.
static bool V8iArmEarlySubscribe() {
    if (g_cbtHook) return true;
    g_ownerPid = GetCurrentProcessId();
    HMODULE self = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)&V8iCbtProc, &self)) return false;
    g_cbtHook = SetWindowsHookExW(WH_CBT, (HOOKPROC)&V8iCbtProc, self, 0);
    return g_cbtHook != nullptr;
}

// C linkage: the host installs this as a *global* WH_CBT hook (hMod = payload),
// so Windows loads the payload into the target before 1C creates its main
// window, and DllMain then arms the in-process hook as well.
static volatile long g_cbtExportCalls = 0;
extern "C" __declspec(dllexport) LRESULT CALLBACK V8iCbtProcExport(
    int nCode, WPARAM wParam, LPARAM lParam) {
    // Marker: does the global hook actually reach a 1C process?
    if (InterlockedIncrement(&g_cbtExportCalls) == 1) {
        wchar_t p[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, p, MAX_PATH);
        const wchar_t* leaf = wcsrchr(p, L'\\');
        leaf = leaf ? leaf + 1 : p;
        FILE* f = nullptr;
        if (_wfopen_s(&f, L"C:\\Users\\fishca\\AppData\\Local\\Temp\\v8i_cbt_hit.txt", L"a") == 0 && f) {
            fprintf(f, "%lu %ls nCode=%d cbtCalls=%ld fired=%d\n",
                    GetCurrentProcessId(), p, nCode, g_cbtCalls, g_cbtFired);
            fclose(f);
        }
    }
    return V8iCbtProc(nCode, wParam, lParam);
}

static DWORD WINAPI V8iEarlySubscribeThread(LPVOID param) {
    HWND h = (HWND)param;
    // The hook fires on the very first 1C window, but the core (and its
    // services) are not initialized that early — subscribing immediately
    // crashes 1C. Wait for the platform to settle before the first attempt.
    // The cmdinfo command fills in g85_fn; with the hook path it must be
    // resolved here (static file resolution, safe at any time).
    if (!g85_fn) {
        uintptr_t base = 0;
        uint32_t rva = 0;
        V8iResolveCore85Proc(&base, &rva);
        if (base && rva) g85_fn = base + rva;
    }
    // eventCreateFrame fires when the MAIN window is created (~0.81s after
// launch; verified: with a 31ms subscribe it arrives, with a 3s subscribe it
// is long gone). So subscribe FAST. The early subscribe does not crash 1C —
// the "crash at start" seen earlier was a busy infobase (leftover process).
Sleep(0);
    for (int i = 0; i < 600 && !g85_subscribed; ++i) {
        Sleep(10);
        if (!IsWindow(h)) break;
        DWORD tid = GetWindowThreadProcessId(h, nullptr);
        if (tid && tid != GetCurrentThreadId()) {
            WNDPROC old = (WNDPROC)SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)V8iSubclass85);
            if (old) {
                g85_origWndProc = old;
                SendMessageW(h, WM_APP + 0x602, 0, 0);
                SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)old);
            }
        }
        if (g85_subscribed) break;
    }
    LogLine("early subscribe: done, subscribed=%d", g85_subscribed);
    return 0;
}

// C linkage so DllMain can arm the hook the moment the payload is loaded —
// before 1C reaches its main window (the session in v8i_probe starts later).
extern "C" __declspec(dllexport) void V8iArmEarly() {
    g85_attachTick = GetTickCount();
    V8iArmEarlySubscribe();
}

static bool V8iInstallCreateWindowHook();

void V8iStartStartupWatch() {
    // NOTE: the inline hook on CreateWindowExW is disabled — the current
    // trampoline crashes 1C when the window is created. Re-enable after the
    // trampoline is fixed (see V8iInstallCreateWindowHook).
    // V8iInstallCreateWindowHook();
    CreateThread(nullptr, 0, V8iStartupWatchThread, nullptr, 0, nullptr);
}

// Runs on the 1C UI thread (called from the subclass proc).
// Subscribes to eventCreateFrame so the next frame creation hands us an
// ITopLevelFrame; a recipient object with a 4-slot vtable lives here.
static unsigned char g85_frameDump[64] = {};
static char g85_frameMod[40] = {};
static uint32_t g85_frameRva = 0;
static HRESULT __stdcall V8iRecipQI(void* self, const GUID*, void** out) {
    if (out) *out = self;
    return 0;
}
static ULONG __stdcall V8iRecipAddRef(void*) { return 1; }
static ULONG __stdcall V8iRecipRelease(void*) { return 1; }
// ---------------------------------------------------------------------------
// 8.5: ITopLevelFrame -> ICommandReceiver.  Runs INSIDE the event callback, i.e.
// on the 1C UI thread: on 8.5 every core85 call from a foreign thread returns
// 0 (or crashes the process), so the receiver is captured exactly when the
// platform hands us the frame — the same moment Snegopat's
// `mainFrame.getCoreTopLevelFrame(coreMainFrame)` runs.
//   obj            = ITopLevelFrame (vtable config.dll+0x2ED3B0 on 8.5.1.1529)
//   obj->vtbl[30]  = commandReceiver(out ICommandReceiver*)   (v8api/window.v)
//   recv->vtbl[0]  = transmitCommand(const Command&, bool), [1] updateState,
//                   [2] hasHandler(const CommandID&)          (v8api/command.v)
// POD + SEH only: no std containers in this frame (MSVC C2712).
// ---------------------------------------------------------------------------
// --- 8.5 command send via the early-captured receiver ---------------------
// V8iCmd85Send sends a designer command through g85_recv on the 1C UI thread
// (kV8iCmdMsg marshal). rc: >=0 transmit result, -99 no receiver/unreadable,
// -98 no marshal window, -97 UI thread did not answer, -96 timeout.
// `has` queries ICommandReceiver::hasHandler instead of transmitting.
// The v8api slot numbering EXCLUDES IUnknown: the live vtable is
// [0]=QI, [1]=AddRef, [2]=Release (verified by disasm on 8.5.1.1529 —
// slot 0 compares its arg against IID_IUnknown and writes *out; "has" via
// slot 2 was a false positive: AddRef just returns 1). Real slots are +3,
// same as the 8.3 chain (kTransmitSlot=3): transmit=[3], hasHandler=[5].
static int V8iCmd85Send(unsigned int num, int sub, bool has = false) {
    if (!g85_recv || !g85_recvVt) return -99;
    if (!IsReadable((void*)g85_recvVt, 6 * sizeof(void*))) return -99;
    uintptr_t tr = ((uintptr_t*)g85_recvVt)[has ? 5 : 3];
    if (!tr || !IsReadable((void*)tr, 1)) return -99;
    HWND cmdHwnd = nullptr;
    DWORD ensureErr = 0;
    const char* marshalPath = "";
    if (!EnsureCmdUi(&cmdHwnd, &ensureErr, &marshalPath)) return -98;
    g_pending.recv = (void*)g85_recv;
    g_pending.trFn = (void*)tr;
    g_pending.mode = has ? 1 : 0;
    // 8.5 Command layout (RECON-85 §3.3): CommandID { GUID, num } padded to
    // 24, param at 24, object at 32 — 40 bytes total. Zeroed tail = nullptr
    // object; the 8.3 32-byte interpretation of the same buffer would read
    // param from the pad (0) and object from the first zeroed qword.
    memset(g_pending.u.raw, 0, sizeof(g_pending.u.raw));
    memcpy(g_pending.u.raw, kConfigGroup, 16);
    *(unsigned int*)(g_pending.u.raw + 16) = num;
    *(int*)(g_pending.u.raw + 24) = sub;
    g_pending.rc = -2;
    g_pending.exc = 0;
    InterlockedExchange(&g_pending.done, 0);
    DWORD_PTR smRes = 0;
    if (!SendMessageTimeoutW(cmdHwnd, kV8iCmdMsg, 0, 0,
                             SMTO_ABORTIFHUNG | SMTO_BLOCK, 30000, &smRes))
        return -97;
    if (!g_pending.done) return -96;
    return g_pending.rc;
}

// Post-start receiver capture for 8.5: the eventCreateFrame path only runs
// when the payload subscribed before the frames existed (hookcbt/launch).
// For a plain post-start inject (`v8inject gitbar ...`) nothing hands us the
// frame, so: scan the heap for the live-calibrated ITopLevelFrame vtable and
// marshal the slot-31 walk onto the UI thread (mode 2) — the only context
// where 8.5 answers. The static check (slot 31 is readable code inside
// config.dll) keeps bogus candidates from executing random bytes; SEH covers
// the rest.
static bool V8iCaptureRecv85Late() {
    if (g85_recv && g85_recvVt) return true;
    ModuleRange cfg;
    if (!FindModule(L"config.dll", cfg)) return false;
    const uintptr_t kFrameVtbl = cfg.base + 0x2ED3B0;  // ITopLevelFrame, live-calibrated on 8.5.1.1529

    std::vector<ModuleRange> mods;
    for (const ModuleRange& m : EnumModules()) mods.push_back(m);
    auto insideCfg = [&](uintptr_t a) {
        return a >= cfg.base && a < cfg.base + cfg.size;
    };

    uintptr_t addr = 0x10000;
    while (addr < 0x00007FFFFFFFFFFFULL) {
        MEMORY_BASIC_INFORMATION mi = {};
        if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
        uintptr_t end = addr + mi.RegionSize;
        bool usable = mi.State == MEM_COMMIT &&
                      (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                      !(mi.Protect & PAGE_GUARD) &&
                      !insideCfg((uintptr_t)mi.BaseAddress);
        if (usable) {
            const uintptr_t cap = mi.RegionSize > 64 * 1024 * 1024
                                      ? 64 * 1024 * 1024 : (uintptr_t)mi.RegionSize;
            for (uintptr_t p = (uintptr_t)mi.BaseAddress;
                 p < (uintptr_t)mi.BaseAddress + cap; p += sizeof(void*)) {
                if (*(uintptr_t*)p != kFrameVtbl) continue;
                uintptr_t fvt = *(uintptr_t*)p;
                uintptr_t fn31 = ((uintptr_t*)fvt)[31];
                if (!fn31 || !IsReadable((void*)fn31, 1) || !insideCfg(fn31)) continue;

                HWND cmdHwnd = nullptr;
                DWORD ensureErr = 0;
                const char* marshalPath = "";
                if (!EnsureCmdUi(&cmdHwnd, &ensureErr, &marshalPath)) return false;
                g_pending.recv = (void*)p;
                g_pending.trFn = nullptr;
                g_pending.mode = 2;
                g_pending.rc = -2;
                g_pending.exc = 0;
                InterlockedExchange(&g_pending.done, 0);
                DWORD_PTR smRes = 0;
                SendMessageTimeoutW(cmdHwnd, kV8iCmdMsg, 0, 0,
                                    SMTO_ABORTIFHUNG | SMTO_BLOCK, 10000, &smRes);
                if (g85_recv && g85_recvVt) {
                    LogLine("cmd85 late capture: frame=0x%llX recv=0x%llX rvt=0x%llX",
                            (unsigned long long)p, (unsigned long long)g85_recv,
                            (unsigned long long)g85_recvVt);
                    return true;
                }
            }
        }
        addr = end == addr ? addr + sizeof(void*) : end;
    }
    LogLine("cmd85 late capture: no frame with vtable config.dll+0x2ED3B0 found");
    return false;
}

// Shared JSON front for the 8.5 send path: `cmd85 ...` and `cmd ...` on 8.5
// both land here. Captures the receiver post-start when it is missing, so a
// plain post-start GitBar dump button works without hookcbt/launch.
static std::string Cmd85SendJson(unsigned int num, int sub, bool has) {
    if (!g85_recv && !V8iCaptureRecv85Late())
        return "{\"status\":\"error\",\"message\":\"no 8.5 receiver captured — "
               "needs early subscribe (hookcbt/launch) or a live frame\"}";
    int rc = V8iCmd85Send(num, sub, has);
    char nb[256];
    if (rc == -99)
        return "{\"status\":\"error\",\"message\":\"receiver vtbl[0] unreadable\"}";
    if (rc == -98)
        return "{\"status\":\"error\",\"message\":\"marshaling setup failed\"}";
    if (rc == -97)
        return "{\"status\":\"error\",\"message\":\"UI thread did not answer\"}";
    if (rc == -96)
        return "{\"status\":\"error\",\"message\":\"timeout waiting for UI thread\"}";
    if (rc < 0) {
        _snprintf_s(nb, sizeof(nb), _TRUNCATE,
                    "{\"status\":\"error\",\"message\":\"transmit exception\",\"exc\":\"0x%X\"}",
                    (unsigned)g_pending.exc);
        return nb;
    }
    if (has)
        _snprintf_s(nb, sizeof(nb), _TRUNCATE,
                    "{\"status\":\"ok\",\"num\":%u,\"sub\":%d,\"recv\":\"0x%llX\",\"has\":%s}",
                    num, sub, (unsigned long long)g85_recv, rc == 0 ? "false" : "true");
    else
        _snprintf_s(nb, sizeof(nb), _TRUNCATE,
                    "{\"status\":\"ok\",\"num\":%u,\"sub\":%d,\"recv\":\"0x%llX\",\"rvt\":\"0x%llX\",\"rc\":%d}",
                    num, sub, (unsigned long long)g85_recv, (unsigned long long)g85_recvVt, rc);
    return nb;
}

// File-driven command sender: lets a host drive 8.5 designer commands without a
// Client session (the hookcbt-loaded payload is sessionless). Watches
// %TEMP%\v8i_cmd85_req.txt ("<num> [sub]"), sends each request once (file is
// consumed), appends the result to %TEMP%\v8i_cmd85_res.txt.
static DWORD WINAPI V8iCmd85PollThread(LPVOID) {
    const wchar_t* reqPath = L"C:\\Users\\fishca\\AppData\\Local\\Temp\\v8i_cmd85_req.txt";
    const wchar_t* resPath = L"C:\\Users\\fishca\\AppData\\Local\\Temp\\v8i_cmd85_res.txt";
    for (int i = 0; i < 900; ++i) {          // 900 * 200 ms = 3 min
        Sleep(200);
        FILE* f = nullptr;
        if (_wfopen_s(&f, reqPath, L"r") == 0 && f) {
            unsigned num = 0;
            int sub = 0;
            int matched = fscanf_s(f, "%u %d", &num, &sub);
            fclose(f);
            if (matched >= 1) {
                _wremove(reqPath);
                int rc = V8iCmd85Send(num, sub);
                FILE* rf = nullptr;
                if (_wfopen_s(&rf, resPath, L"a") == 0 && rf) {
                    fprintf(rf, "num=%u sub=%d rc=%d\n", num, sub, rc);
                    fclose(rf);
                }
            }
        }
    }
    return 0;
}

static void V8iCaptureCmdRecv(void* obj) {
    if (!obj) return;
    uintptr_t fvt = 0;
    __try { fvt = *(uintptr_t*)obj; } __except (EXCEPTION_EXECUTE_HANDLER) { fvt = 0; }
    if (!fvt) {
        LogLine("cmdrecv: frame has no vtable");
        return;
    }
    // Live-calibrated on 8.5.1.1529: the event's obj IS the ITopLevelFrame
    // (vtable config.dll+0x2ED3B0, a forwarder table; slot 0 = init, NOT QI —
    // no IUnknown cast is needed). commandReceiver = slot 31, NOT 30 (slot 30
    // is a different method and raises 0xC0000005). The slot-31 forwarder
    // reads inner = [obj+8] and dispatches [inner->vt + 0xF8]; the receiver
    // returned sits 0x20 before that inner object (the same geometry as the
    // 8.3 "recv = core - 0x20"). recv->vtbl[0] = transmitCommand.
    uintptr_t fn31 = 0;
    __try { fn31 = ((uintptr_t*)fvt)[31]; } __except (EXCEPTION_EXECUTE_HANDLER) { fn31 = 0; }
    g85_recv = 0;
    g85_recvVt = 0;
    long exc = 0;
    if (fn31 && IsReadable((void*)fn31, 1)) {
        void* recv = nullptr;
        __try {
            ((void(__cdecl*)(void*, void**))fn31)(obj, &recv);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            exc = GetExceptionCode();
            recv = nullptr;
        }
        if (recv && IsReadable(recv, 4 * sizeof(void*))) {
            g85_recv = (uintptr_t)recv;
            __try { g85_recvVt = *(uintptr_t*)recv; }
            __except (EXCEPTION_EXECUTE_HANDLER) { g85_recvVt = 0; }
            LogLine("cmdrecv85: OK recv=0x%llX rvt=0x%llX",
                    (unsigned long long)(uintptr_t)recv, (unsigned long long)g85_recvVt);
        } else {
            LogLine("cmdrecv85: slot31 no receiver (exc=0x%X)", (unsigned)exc);
        }
    }
    // Marker file: the only channel when the payload was loaded by the global
    // CBT hook (sessionless, no command readback).
    {
        FILE* cf = nullptr;
        if (_wfopen_s(&cf, L"C:\\Users\\fishca\\AppData\\Local\\Temp\\v8i_cmdrecv.txt", L"a") == 0 && cf) {
            fprintf(cf, "obj=%llx vt=%llx recv31=%llx recvVt31=%llx exc=%x\n",
                    (unsigned long long)(uintptr_t)obj, (unsigned long long)fvt,
                    (unsigned long long)g85_recv, (unsigned long long)g85_recvVt, (unsigned)exc);
            fclose(cf);
        }
    }
    // One-shot: spawn the file-driven command sender (host drives 8.5 command
    // sends without a Client session; end-to-end proof of the receiver chain).
    {
        static bool s_cmd85PollSpawned = false;
        if (!s_cmd85PollSpawned && g85_recv) {
            s_cmd85PollSpawned = true;
            CreateThread(nullptr, 0, V8iCmd85PollThread, nullptr, 0, nullptr);
        }
    }
}

// The frame is handed to us on the 1C UI thread and the receiver chain must be
// walked right there (8.5 refuses cross-thread calls into core85, so deferring
// to a worker thread silently yields 0). No std containers in this frame —
// EnumModules() (std::vector) is called from the caller, not from here.
static void V8iTakeFrame85(void* obj) {
    g85_evFrame = (uintptr_t)obj;
    for (int i = 0; i < 4; ++i) g85_dump[i] = 0;
    if (IsReadable(obj, 16)) {
        g85_frameVt = *(uintptr_t*)obj;
        for (int i = 0; i < 4; ++i) {
            __try { g85_dump[i] = ((uintptr_t*)obj)[i]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { g85_dump[i] = 0; }
        }
        if (IsReadable(obj, 64)) memcpy(g85_frameDump, obj, 64);
    }
    if (!g85_subscribed) return;   // only the eventCreateFrame path owns a frame
    V8iCaptureCmdRecv(obj);        // always: diagnose both chains in one shot
}

static HRESULT __stdcall V8iRecipOnEvent(void*, const GUID* ev, long, void* obj) {
    ++g85_evCount;
    if (ev && memcmp(ev, &g85_kExitEv, 16) == 0)
        ++g85_exitEvCount;
    bool isCreateFrame = ev && memcmp(ev, &g85_kCreateFrameEv, 16) == 0;
    // Diagnostic trail (append-only; a marker file is the only channel that
    // also works when the payload was loaded by the global CBT hook, i.e.
    // without any Client session to answer commands).
    {
        FILE* rf = nullptr;
        if (_wfopen_s(&rf, L"C:\\Users\\fishca\\AppData\\Local\\Temp\\v8i_recip.txt", L"a") == 0 && rf) {
            fprintf(rf, "ev=%d create=%d exit=%d obj=%llx evid=%02x%02x%02x%02x-%02x%02x-%02x%02x"
                        "-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                    g85_evCount, isCreateFrame ? 1 : 0, g85_exitEvCount,
                    (unsigned long long)(uintptr_t)obj,
                    ev ? ev->Data1 & 0xFF : 0, ev ? (ev->Data1 >> 8) & 0xFF : 0,
                    ev ? (ev->Data1 >> 16) & 0xFF : 0, ev ? (ev->Data1 >> 24) & 0xFF : 0,
                    ev ? ev->Data2 & 0xFF : 0, ev ? (ev->Data2 >> 8) & 0xFF : 0,
                    ev ? ev->Data3 & 0xFF : 0, ev ? (ev->Data3 >> 8) & 0xFF : 0,
                    ev ? ev->Data4[0] : 0, ev ? ev->Data4[1] : 0,
                    ev ? ev->Data4[2] : 0, ev ? ev->Data4[3] : 0,
                    ev ? ev->Data4[4] : 0, ev ? ev->Data4[5] : 0,
                    ev ? ev->Data4[6] : 0, ev ? ev->Data4[7] : 0);
            fclose(rf);
        }
    }
    if (isCreateFrame && obj) V8iTakeFrame85(obj);
    return 0;
}
// The exact IEventRecipient slot layout is not documented for 8.5: the 1C
// event interface appears to be IUnknown-derived (QI/AddRef/Release first),
// but ICommandReceiver-like pure interfaces put their single method at slot 0.
// To not guess, every slot dispatches onEvent — whichever one the platform
// calls (0, 3, …), we see the event.
static void* g85_recipVt[8] = {
    (void*)V8iRecipOnEvent,  // slot 0: pure-interface layout (onEvent)
    (void*)V8iRecipAddRef,   // slot 1
    (void*)V8iRecipRelease,  // slot 2
    (void*)V8iRecipOnEvent,  // slot 3: IUnknown-derived layout (onEvent)
    (void*)V8iRecipOnEvent,
    (void*)V8iRecipOnEvent,
    (void*)V8iRecipOnEvent,
    (void*)V8iRecipOnEvent,
};
static struct V8iRecip { void** vt; } g85_recip = {g85_recipVt};

static void V8iScanFrame85() {
    static const GUID kEvCreateFrame = {0x3573FFE0, 0x2FFF, 0x11D5,
                                        {0xBF, 0x5E, 0x00, 0x50, 0xBA, 0xE2, 0xBC, 0x79}};
    if (!g85_svc || !g85_svcVt) return;
    uintptr_t f1 = 0;
    __try { f1 = ((uintptr_t*)g85_svcVt)[1]; }
    __except (EXCEPTION_EXECUTE_HANDLER) { f1 = 0; }
    if (!f1) return;
    typedef void(__cdecl* SubFn)(void*, const GUID*, void*, const char*, int);
    // 8.5: slot 4 = _subscribe, slot 3 = notify, slot 5 = unsubscribe
    // (all three do a GUID lookup; 0..2 are interface thunks).
    {
        uintptr_t f = 0;
        __try { f = ((uintptr_t*)g85_svcVt)[4]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { f = 0; }
        if (f) {
            __try {
                ((SubFn)f)((void*)g85_svc, &kEvCreateFrame, (void*)&g85_recip, "v8inject", 0);
                // Also subscribe to an event that always fires at close, to
                // prove the platform delivers to *our* recipient at all.
                ((SubFn)f)((void*)g85_svc, &g85_kExitEv, (void*)&g85_recip, "v8inject", 0);
                g85_subscribed = 1;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
    {
        uintptr_t f = 0;
        __try { f = ((uintptr_t*)g85_svcVt)[3]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { f = 0; }
        if (f) {
            __try {
                ((void(__cdecl*)(void*, const GUID*, long, void*))f)(
                    (void*)g85_svc, &kEvCreateFrame, 0, nullptr);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
}

// --- inline hook on user32!CreateWindowExW -------------------------------
// The only moment where eventCreateFrame can still be caught: the UI thread
// calls CreateWindowExW for the main window, the core is already loaded and
// the window does not exist yet. Runs current_process -> getService ->
// subscribe right there, then lets the original call proceed.
static uintptr_t V8iResolveExportFromFile(const std::wstring& modulePath,
                                          const char* namePrefix, size_t prefixLen) {
    HANDLE fh = CreateFileW(modulePath.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER sz{};
    GetFileSizeEx(fh, &sz);
    uintptr_t result = 0;
    if (sz.QuadPart > 0 && sz.QuadPart < 64 * 1024 * 1024LL) {
        std::vector<unsigned char> fbuf((size_t)sz.QuadPart);
        DWORD got = 0;
        if (ReadFile(fh, fbuf.data(), (DWORD)fbuf.size(), &got, nullptr) && got == fbuf.size()) {
            const unsigned char* fd = fbuf.data();
            auto r32 = [fd](uintptr_t o) -> uint32_t { return *(const uint32_t*)(fd + o); };
            uintptr_t dos = fd[0x3C] | (fd[0x3D] << 8) | (fd[0x3E] << 16) | ((uintptr_t)fd[0x3F] << 24);
            if (dos + 0x100 < fbuf.size()) {
                uintptr_t nt = dos + 4;
                uint16_t nsec = *(const uint16_t*)(fd + nt + 2);
                uint16_t optSize = *(const uint16_t*)(fd + nt + 16);
                uintptr_t opt = nt + 20;
                uintptr_t secTab = opt + optSize;
                auto toRaw = [&](uint32_t rva) -> uint32_t {
                    for (uint16_t i = 0; i < nsec; ++i) {
                        uintptr_t sh = secTab + (uintptr_t)i * 40;
                        if (sh + 40 > fbuf.size()) break;
                        uint32_t va = r32(sh + 12);
                        uint32_t vs = r32(sh + 8);
                        uint32_t raw = r32(sh + 20);
                        if (rva >= va && rva < va + vs) return rva - va + raw;
                    }
                    return rva;
                };
                uintptr_t dd = opt + (optSize != 224 ? 112 : 96);
                uint32_t expRva = (dd + 8 <= fbuf.size()) ? r32(dd) : 0;
                if (expRva && expRva + 40 <= fbuf.size()) {
                    uint32_t eo = toRaw(expRva);
                    if (eo + 40 <= fbuf.size()) {
                        uint32_t names = r32(eo + 32);
                        uint32_t funcs = r32(eo + 28);
                        uint32_t ords = r32(eo + 36);
                        uint32_t nNames = r32(eo + 24);
                        for (uint32_t i = 0; i < nNames && i < 16384; ++i) {
                            uint32_t np = toRaw(r32(toRaw(names + i * 4)));
                            if (!np || np + prefixLen + 1 > (uint32_t)fbuf.size()) continue;
                            if (memcmp(fd + np, namePrefix, prefixLen) != 0) continue;
                            uint16_t idx = *(const uint16_t*)(fd + toRaw(ords + i * 2));
                            result = r32(toRaw(funcs + (uint32_t)idx * 4));
                            break;
                        }
                    }
                }
            }
        }
    }
    CloseHandle(fh);
    return result;  // RVA
}

// ---------------------------------------------------------------------------
// exports85: dump every export of a module straight from the file on disk.
// 8.5 zeroes the export directory in memory, so this is the only reliable
// source of names and RVAs.
// ---------------------------------------------------------------------------

struct V8iExportEntry {
    char name[256];
    uint32_t ordinal;
    uint32_t rva;
};

static int V8iDumpExportsFromFile(const std::wstring& modulePath,
                                  V8iExportEntry* out, int maxEntries) {
    if (!out || maxEntries <= 0) return 0;
    HANDLE fh = CreateFileW(modulePath.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER sz{};
    GetFileSizeEx(fh, &sz);
    int count = 0;
    if (sz.QuadPart > 0 && sz.QuadPart < 128 * 1024 * 1024LL) {
        std::vector<unsigned char> fbuf((size_t)sz.QuadPart);
        DWORD got = 0;
        if (ReadFile(fh, fbuf.data(), (DWORD)fbuf.size(), &got, nullptr) && got == fbuf.size()) {
            const unsigned char* fd = fbuf.data();
            auto r32 = [fd](uintptr_t o) -> uint32_t { return *(const uint32_t*)(fd + o); };
            uintptr_t dos = fd[0x3C] | (fd[0x3D] << 8) | (fd[0x3E] << 16) | ((uintptr_t)fd[0x3F] << 24);
            if (dos + 0x100 < fbuf.size()) {
                uintptr_t nt = dos + 4;
                uint16_t nsec = *(const uint16_t*)(fd + nt + 2);
                uint16_t optSize = *(const uint16_t*)(fd + nt + 16);
                uintptr_t opt = nt + 20;
                uintptr_t secTab = opt + optSize;
                auto toRaw = [&](uint32_t rva) -> uint32_t {
                    for (uint16_t i = 0; i < nsec; ++i) {
                        uintptr_t sh = secTab + (uintptr_t)i * 40;
                        if (sh + 40 > fbuf.size()) break;
                        uint32_t va = r32(sh + 12);
                        uint32_t vs = r32(sh + 8);
                        uint32_t raw = r32(sh + 20);
                        if (rva >= va && rva < va + vs) return rva - va + raw;
                    }
                    return rva;
                };
                uintptr_t dd = opt + (optSize != 224 ? 112 : 96);
                uint32_t expRva = (dd + 8 <= fbuf.size()) ? r32(dd) : 0;
                if (expRva && expRva + 40 <= fbuf.size()) {
                    uint32_t eo = toRaw(expRva);
                    if (eo + 40 <= fbuf.size()) {
                        uint32_t names = r32(eo + 32);
                        uint32_t funcs = r32(eo + 28);
                        uint32_t ords = r32(eo + 36);
                        uint32_t nNames = r32(eo + 24);
                        for (uint32_t i = 0; i < nNames && count < maxEntries; ++i) {
                            uint32_t nameRva = r32(toRaw(names + i * 4));
                            if (!nameRva) continue;
                            uint32_t np = toRaw(nameRva);
                            if (np + 2 >= (uint32_t)fbuf.size()) continue;
                            const char* nm = (const char*)(fd + np);
                            size_t len = strnlen_s(nm, 255);
                            if (len == 0) continue;
                            uint16_t idx = *(const uint16_t*)(fd + toRaw(ords + i * 2));
                            V8iExportEntry& e = out[count++];
                            memcpy(e.name, nm, len);
                            e.name[len] = 0;
                            e.ordinal = idx;
                            e.rva = r32(toRaw(funcs + (uint32_t)idx * 4));
                        }
                    }
                }
            }
        }
    }
    CloseHandle(fh);
    return count;
}

static ModuleRange V8iFindModuleByName(const wchar_t* leaf) {
    for (const ModuleRange& m : EnumModules()) {
        size_t s = m.path.find_last_of(L"\\/");
        std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
        if (_wcsicmp(n.c_str(), leaf) == 0) return m;
    }
    return ModuleRange{};
}

// current_process -> getService(IEventService) -> subscribe(eventCreateFrame)
static void V8iResolveCore85Proc(uintptr_t* outBase, uint32_t* outRva) {
    *outBase = 0;
    *outRva = 0;
    for (const ModuleRange& m : EnumModules()) {
        size_t s = m.path.find_last_of(L"\\/");
        std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
        if (_wcsicmp(n.c_str(), L"core85.dll") != 0) continue;
        *outBase = m.base;
        *outRva = (uint32_t)V8iResolveExportFromFile(m.path, "?current_process@core@@", 23);
        return;
    }
}

static void V8iSubscribeNow() {
    if (g85_subscribed) return;
    uintptr_t base = 0;
    uint32_t rva = 0;
    V8iResolveCore85Proc(&base, &rva);
    if (!base || !rva) return;
    uintptr_t fn = base + rva;
    void* proc = nullptr;
    __try {
        proc = ((V8iCurProcFn)fn)();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        proc = nullptr;
    }
    if (!proc) return;
    uintptr_t vt = 0;
    __try { vt = *(uintptr_t*)proc; }
    __except (EXCEPTION_EXECUTE_HANDLER) { vt = 0; }
    if (!vt) return;
    static const GUID kIID_EventService = {0xEBF766AA, 0xF32C, 0x11D3,
                                           {0x98, 0x51, 0x00, 0x80, 0x48, 0xDA, 0x12, 0x52}};
    static const GUID kEvCreateFrame = {0x3573FFE0, 0x2FFF, 0x11D5,
                                        {0xBF, 0x5E, 0x00, 0x50, 0xBA, 0xE2, 0xBC, 0x79}};
    void* svc = nullptr;
    __try {
        svc = ((V8iGetSvcFn)((uintptr_t*)vt)[14])(proc, &kIID_EventService);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        svc = nullptr;
    }
    if (!svc) return;
    uintptr_t svt = 0;
    __try { svt = *(uintptr_t*)svc; }
    __except (EXCEPTION_EXECUTE_HANDLER) { svt = 0; }
    if (!svt) return;
    typedef void(__cdecl* SubFn)(void*, const GUID*, void*, const char*, int);
    __try {
        ((SubFn)((uintptr_t*)svt)[4])(svc, &kEvCreateFrame, (void*)&g85_recip, "v8inject", 0);
        g85_subscribed = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static void* g_cwTrampoline = nullptr;
static BYTE g_cwOrig[24] = {};
static volatile int g_cwHookOk = 0;
static volatile long g_cwHits = 0;

static HWND WINAPI V8iDetourCreateWindowExW(DWORD exStyle, LPCWSTR cls, LPCWSTR name,
                                            DWORD style, int x, int y, int w, int h,
                                            HWND parent, HMENU menu, HINSTANCE inst,
                                            LPVOID param) {
    ++g_cwHits;
    if (cls && !g85_subscribed &&
        (wcsncmp(cls, L"V8Window0", 9) == 0 || wcsncmp(cls, L"V8TopLevelFrame", 15) == 0)) {
        V8iSubscribeNow();
    }
    typedef HWND(WINAPI* Fn)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int,
                             HWND, HMENU, HINSTANCE, LPVOID);
    return ((Fn)g_cwTrampoline)(exStyle, cls, name, style, x, y, w, h, parent, menu, inst, param);
}

// Installs the inline hook (mov rax, detour; jmp rax = 12 bytes + NOPs).
static bool V8iInstallCreateWindowHook() {
    if (g_cwTrampoline) return true;
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    if (!u32) u32 = LoadLibraryW(L"user32.dll");
    if (!u32) return false;
    void* target = (void*)GetProcAddress(u32, "CreateWindowExW");
    if (!target) return false;
    // Prologue of user32!CreateWindowExW on this build:
    //   4C 8B DC              mov  r11, rsp
    //   48 81 EC 88 00 00 00  sub  rsp, 0x88
    //   33 C0                 xor  eax, eax
    //   66 89 44 24 78        mov  [rsp+78h], ax
    const BYTE expect[8] = {0x4C, 0x8B, 0xDC, 0x48, 0x81, 0xEC, 0x88, 0x00};
    if (memcmp(target, expect, sizeof(expect)) != 0) return false;
    const int len = 17;  // whole instructions: 3 + 7 + 2 + 5
    memcpy(g_cwOrig, target, len);
    BYTE* tr = (BYTE*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tr) return false;
    memcpy(tr, target, len);
    tr[len] = 0x48; tr[len + 1] = 0xB8;
    *(uintptr_t*)(tr + len + 2) = (uintptr_t)target + len;
    tr[len + 10] = 0xFF; tr[len + 11] = 0xE0;
    g_cwTrampoline = tr;
    DWORD oldProt = 0;
    if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &oldProt)) return false;
    BYTE patch[20];
    memset(patch, 0x90, sizeof(patch));
    patch[0] = 0x48; patch[1] = 0xB8;
    *(uintptr_t*)(patch + 2) = (uintptr_t)&V8iDetourCreateWindowExW;
    patch[10] = 0xFF; patch[11] = 0xE0;
    memcpy(target, patch, len);
    VirtualProtect(target, len, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), target, len);
    g_cwHookOk = 1;
    return true;
}

// "cmdinfo" — read-only diagnostics: how the command receiver can be located
// on THIS platform. 8.3 carries config.dll with the calibrated ITopLevelFrame
// vtable; 8.5 has core85/frame/mngcore instead, so the chain must be
// discovered: window -> GWLP_USERDATA object -> core (obj+8) ->
// ICommandReceiver (core - offset). No 1C code is called here.
static std::string CmdInfoToJsonA() {
    // Arm the startup watcher on every call: if the main window does not exist
    // yet, the worker subscribes the moment it appears (before the platform
    // dispatches eventCreateFrame).
    {
        static bool armed = false;
        if (!armed) { armed = true; V8iStartStartupWatch(); }
    }
    struct WinRec { HWND h; std::wstring cls; std::wstring title; };
    std::vector<WinRec> wins;
    struct Ctx { std::vector<WinRec>* v; DWORD pid; };
    Ctx ctx{ &wins, GetCurrentProcessId() };
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        Ctx* c = (Ctx*)lp;
        DWORD pid = 0;
        GetWindowThreadProcessId(h, &pid);
        if (pid != c->pid) return TRUE;
        wchar_t cls[128] = {}, ttl[128] = {};
        GetClassNameW(h, cls, 128);
        GetWindowTextW(h, ttl, 128);
        if (!ttl[0]) return TRUE;
        WinRec r;
        r.h = h;
        r.cls = cls;
        r.title = ttl;
        c->v->push_back(r);
        return TRUE;
    }, (LPARAM)&ctx);

    std::vector<ModuleRange> mods;
    for (const ModuleRange& m : EnumModules()) mods.push_back(m);
    auto modAt = [&mods](uintptr_t a) -> const ModuleRange* {
        for (const ModuleRange& m : mods)
            if (a >= m.base && a < m.base + m.size) return &m;
        return nullptr;
    };
    auto modRva = [&mods](uintptr_t a, std::string& mod) -> unsigned long long {
        for (const ModuleRange& m : mods) {
            if (a >= m.base && a < m.base + m.size) {
                size_t s = m.path.find_last_of(L"\\/");
                std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
                mod.assign(n.begin(), n.end());
                return (unsigned long long)(a - m.base);
            }
        }
        mod = "?";
        return 0;
    };
    auto isFrameMod = [](const std::string& m) {
        return m == "frame.dll" || m == "mngcore.dll" || m == "mngui.dll" ||
               m == "config.dll" || m == "frmcore.dll";
    };

    std::string j = "{\"status\":\"ok\",\"windows\":[";
    bool first = true;
    char b[768];
    int frameCount = 0;
    for (const WinRec& w : wins) {
        uintptr_t obj = (uintptr_t)GetWindowLongPtrW(w.h, GWLP_USERDATA);
        if (!obj || !IsReadable((void*)obj, 16)) continue;
        uintptr_t vt = *(uintptr_t*)obj;
        std::string mod;
        unsigned long long rva = modRva(vt, mod);
        if (!first) j += ",";
        first = false;
        _snprintf_s(b, sizeof(b), _TRUNCATE,
                    "{\"hwnd\":\"0x%llX\",\"cls\":\"%s\",\"obj\":\"0x%llX\",\"vt\":\"%s+0x%llX\"",
                    (unsigned long long)(uintptr_t)w.h,
                    std::string(w.cls.begin(), w.cls.end()).c_str(),
                    (unsigned long long)obj, mod.c_str(), rva);
        j += b;
        if (!isFrameMod(mod)) {
            j += ",\"frame\":false}";
            continue;
        }
        uintptr_t core = *(uintptr_t*)(obj + 8);
        std::string cmod;
        unsigned long long crva = modRva(core, cmod);
        _snprintf_s(b, sizeof(b), _TRUNCATE,
                    ",\"frame\":true,\"core\":\"0x%llX %s+0x%llX\",\"recv\":[",
                    (unsigned long long)core, cmod.c_str(), crva);
        j += b;
        bool firstR = true;
        for (int off = 0x08; off <= 0x60; off += 4) {
            uintptr_t recv = core - off;
            if (!IsReadable((void*)recv, 16)) continue;
            uintptr_t vtr = *(uintptr_t*)recv;
            std::string rmod;
            unsigned long long rrva = modRva(vtr, rmod);
            if (!isFrameMod(rmod)) continue;
            uintptr_t slot3 = ((uintptr_t*)vtr)[3];
            std::string smod;
            unsigned long long srva = modRva(slot3, smod);
            if (!firstR) j += ",";
            firstR = false;
            _snprintf_s(b, sizeof(b), _TRUNCATE,
                        "{\"off\":\"0x%X\",\"vt\":\"%s+0x%llX\",\"slot3\":\"%s+0x%llX\"}",
                        off, rmod.c_str(), rrva, smod.c_str(), srva);
            j += b;
        }
        j += "]}";
        if (isFrameMod(mod)) ++frameCount;
    }
    j += "]";

    // 8.5 does not keep the frame object in GWLP_USERDATA: fall back to a heap
    // scan. Look for objects whose vtable lies in a frame-related module and
    // whose second word points at a core object (core85/config/mngcore).
    if (frameCount == 0) {
        struct MR { uintptr_t base = 0, size = 0; std::string leaf; };
        std::vector<MR> fam, cores;
        for (const ModuleRange& m : mods) {
            size_t s = m.path.find_last_of(L"\\/");
            std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
            std::string leaf(n.begin(), n.end());
            if (leaf == "frame.dll" || leaf == "mngcore.dll" || leaf == "mngui.dll" ||
                leaf == "frmcore.dll" || leaf == "config.dll")
                fam.push_back({ m.base, m.size, leaf });
            if (leaf == "core85.dll" || leaf == "core83.dll" || leaf == "config.dll" ||
                leaf == "mngcore.dll")
                cores.push_back({ m.base, m.size, leaf });
        }
        auto inSpan = [](const std::vector<MR>& v, uintptr_t a) -> const MR* {
            for (const MR& r : v)
                if (a >= r.base && a < r.base + r.size) return &r;
            return nullptr;
        };
        j += ",\"scan\":[";
        bool firstS = true;
        int found = 0;
        uintptr_t addr = 0x10000;
        while (addr < 0x00007FFFFFFFFFFFULL && found < 40) {
            MEMORY_BASIC_INFORMATION mi{};
            if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
            uintptr_t end = addr + mi.RegionSize;
            bool usable = mi.State == MEM_COMMIT &&
                          (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                          !(mi.Protect & PAGE_GUARD) &&
                          !inSpan(fam, (uintptr_t)mi.BaseAddress) &&
                          !inSpan(cores, (uintptr_t)mi.BaseAddress);
            if (usable) {
                uintptr_t cap = mi.RegionSize > 32 * 1024 * 1024 ? 32 * 1024 * 1024
                                                                 : (uintptr_t)mi.RegionSize;
                for (uintptr_t p = (uintptr_t)mi.BaseAddress;
                     p + 16 < (uintptr_t)mi.BaseAddress + cap; p += 8) {
                    uintptr_t vt = *(uintptr_t*)p;
                    const MR* mf = inSpan(fam, vt);
                    if (!mf) continue;
                    uintptr_t core = *(uintptr_t*)(p + 8);
                    const MR* mc = inSpan(cores, core);
                    if (!mc) continue;
                    if (!firstS) j += ",";
                    firstS = false;
                    _snprintf_s(b, sizeof(b), _TRUNCATE,
                                "{\"obj\":\"0x%llX\",\"vt\":\"%s+0x%llX\",\"core\":\"%s+0x%llX\"",
                                (unsigned long long)p, mf->leaf.c_str(),
                                (unsigned long long)(vt - mf->base), mc->leaf.c_str(),
                                (unsigned long long)(core - mc->base));
                    j += b;
                    if (mc->leaf == "core85.dll" || mc->leaf == "core83.dll" ||
                        mc->leaf == "config.dll") {
                        j += ",\"recv\":[";
                        bool firstR2 = true;
                        for (int off = 0x08; off <= 0x60; off += 4) {
                            uintptr_t recv = core - off;
                            if (!IsReadable((void*)recv, 16)) continue;
                            uintptr_t vtr = *(uintptr_t*)recv;
                            const MR* mr = inSpan(fam, vtr);
                            if (!mr) continue;
                            uintptr_t slot3 = ((uintptr_t*)vtr)[3];
                            std::string smod;
                            unsigned long long srva = modRva(slot3, smod);
                            if (!firstR2) j += ",";
                            firstR2 = false;
                            _snprintf_s(b, sizeof(b), _TRUNCATE,
                                        "{\"off\":\"0x%X\",\"vt\":\"%s+0x%llX\","
                                        "\"slot3\":\"%s+0x%llX\"}",
                                        off, mr->leaf.c_str(),
                                        (unsigned long long)(vtr - mr->base), smod.c_str(), srva);
                            j += b;
                        }
                        j += "]";
                    }
                    j += "}";
                    if (++found >= 40) break;
                }
            }
            addr = end == addr ? addr + 8 : end;
        }
        j += "]";
    }

    // QueryInterface pass: objects with real rdata vtables (slots 0..5 point
    // into the same module's .text) are asked about IID_ICommandReceiver —
    // the modern way to obtain the receiver on 8.5, where the core-0x20 trick
    // does not apply. QI is side-effect free; each probe is SEH-guarded.
    {
        struct MR2 { uintptr_t base = 0, size = 0, tlo = 0, thi = 0, rlo = 0, rhi = 0; };
        std::vector<MR2> targets;
        for (const ModuleRange& m : mods) {
            size_t s = m.path.find_last_of(L"\\/");
            std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
            std::string leaf(n.begin(), n.end());
            if (leaf != "frame.dll" && leaf != "config.dll" && leaf != "mngcore.dll")
                continue;
            PeImage im = ParsePe(m.base);
            if (!im.valid) continue;
            MR2 r;
            r.base = m.base;
            r.size = m.size;
            for (const PeSection& sec : im.sections) {
                if (sec.name == ".text") { r.tlo = m.base + sec.va; r.thi = r.tlo + sec.virtualSize; }
                if (sec.name == ".rdata") { r.rlo = m.base + sec.va; r.rhi = r.rlo + sec.virtualSize; }
            }
            if (r.tlo && r.rlo) targets.push_back(r);
        }
        auto inText = [&targets](uintptr_t a) -> bool {
            for (const MR2& r : targets)
                if (a >= r.tlo && a < r.thi) return true;
            return false;
        };
        auto inRdata = [&targets](uintptr_t a) -> bool {
            for (const MR2& r : targets)
                if (a >= r.rlo && a < r.rhi) return true;
            return false;
        };
        static const GUID kIID_CmdRecv = {0x377A2018, 0xC51B, 0x4cf5,
                                          {0xAC, 0x03, 0xA1, 0x50, 0x92, 0x66, 0xDF, 0x2D}};
        j += ",\"qi\":[";
        bool firstQ = true;
        int qfound = 0;
        if (0) {
        uintptr_t addr = 0x10000;
        while (addr < 0x00007FFFFFFFFFFFULL && qfound < 12) {
            MEMORY_BASIC_INFORMATION mi{};
            if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
            uintptr_t end = addr + mi.RegionSize;
            bool usable = mi.State == MEM_COMMIT &&
                          (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                          !(mi.Protect & PAGE_GUARD) && !inRdata((uintptr_t)mi.BaseAddress) &&
                          !inText((uintptr_t)mi.BaseAddress);
            if (usable) {
                uintptr_t cap = mi.RegionSize > 32 * 1024 * 1024 ? 32 * 1024 * 1024
                                                                 : (uintptr_t)mi.RegionSize;
                for (uintptr_t p = (uintptr_t)mi.BaseAddress;
                     p + 48 < (uintptr_t)mi.BaseAddress + cap; p += 8) {
                    uintptr_t vt = *(uintptr_t*)p;
                    if (!inRdata(vt)) continue;
                    bool vok = true;
                    for (int sl = 1; sl <= 5; ++sl)
                        if (!inText(((uintptr_t*)vt)[sl])) { vok = false; break; }
                    if (!vok) continue;
                    void* out = nullptr;
                    int rc = V8iQIProbe((void*)p, &kIID_CmdRecv, &out);
                    if (rc != 0 || !out) continue;
                    if (!firstQ) j += ",";
                    firstQ = false;
                    std::string vmod;
                    unsigned long long vrva = modRva(vt, vmod);
                    uintptr_t trFn = out ? *(uintptr_t*)(*(uintptr_t*)out + 3 * 8) : 0;
                    std::string tmod;
                    unsigned long long trva = trFn ? modRva(trFn, tmod) : 0;
                    _snprintf_s(b, sizeof(b), _TRUNCATE,
                                "{\"obj\":\"0x%llX\",\"vt\":\"%s+0x%llX\","
                                "\"recv\":\"0x%llX\",\"trFn\":\"%s+0x%llX\"}",
                                (unsigned long long)p, vmod.c_str(), vrva,
                                (unsigned long long)(uintptr_t)out, tmod.c_str(), trva);
                    j += b;
                    if (++qfound >= 12) break;
                }
            }
            addr = end == addr ? addr + 8 : end;
        }
        }
        j += "]";
    }

    // SCOM_Process: core85!current_process() returns the process object; its
    // service table (slot 11 = getService, per v8api/process.v) is the
    // documented entry to 1C services. Read-only: dump the object and look for
    // a frame object (rdata vtable in frame/config) among its fields.
    {
        ModuleRange core85;
        bool haveCore = false;
        for (const ModuleRange& m : mods) {
            size_t s = m.path.find_last_of(L"\\/");
            std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
            if (_wcsicmp(n.c_str(), L"core85.dll") == 0) { core85 = m; haveCore = true; break; }
        }
        if (haveCore) {
            // 8.5 zeroes core85's in-memory export directory (exportCount:0),
            // so resolve the export from the on-disk image instead.
            uintptr_t fn = 0;
            std::string probeStr;
            bool fhOk = false;
            long long szPart = 0;
            DWORD gotB = 0;
            uint32_t dbgNNames = 0;
            uint32_t dbgExpRva = 0;
            uint32_t dbgFrva = 0;
            HANDLE fh = CreateFileW(core85.path.c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            fhOk = (fh != INVALID_HANDLE_VALUE);
            if (fh != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER sz{};
                GetFileSizeEx(fh, &sz);
                szPart = sz.QuadPart;
                if (sz.QuadPart > 0 && sz.QuadPart < 64 * 1024 * 1024LL) {
                    DWORD got = 0;
                    std::vector<unsigned char> fbuf((size_t)sz.QuadPart);
                    BOOL rdOk = ReadFile(fh, fbuf.data(), (DWORD)fbuf.size(), &got, nullptr);
                    gotB = got;
                    if (rdOk && got == fbuf.size()) {
                        const unsigned char* fd = fbuf.data();
                        auto r32 = [fd](uintptr_t o) -> uint32_t {
                            return *(const uint32_t*)(fd + o);
                        };
                        uintptr_t dos = fd[0x3C] | (fd[0x3D] << 8) | (fd[0x3E] << 16) | ((uintptr_t)fd[0x3F] << 24);
                        if (dos + 0x100 < fbuf.size()) {
                            uintptr_t nt = dos + 4;
                            uint16_t nsec = *(const uint16_t*)(fd + nt + 2);
                            uint16_t optSize = *(const uint16_t*)(fd + nt + 16);
                            uintptr_t opt = nt + 20;
                            uintptr_t secTab = opt + optSize;
                            // RVA -> file offset via the section table
                            auto toRaw = [&](uint32_t rva) -> uint32_t {
                                for (uint16_t i = 0; i < nsec; ++i) {
                                    uintptr_t sh = secTab + (uintptr_t)i * 40;
                                    if (sh + 40 > fbuf.size()) break;
                                    uint32_t va = r32(sh + 12);
                                    uint32_t vs = r32(sh + 8);
                                    uint32_t raw = r32(sh + 20);
                                    if (rva >= va && rva < va + vs)
                                        return rva - va + raw;
                                }
                                return rva;
                            };
                            // 1C masks the PE magic in core85 (anti-analysis);
                            // infer the format from SizeOfOptionalHeader (224=PE32, 240=PE32+).
                            uintptr_t dd = opt + (optSize != 224 ? 112 : 96);  // export directory
                            if (dd + 8 <= fbuf.size()) {
                                uint32_t expRva = r32(dd);
                                if (expRva && expRva + 40 <= fbuf.size()) {
                                    uint32_t eo = toRaw(expRva);
                                    if (eo + 40 <= fbuf.size()) {
                                        uint32_t names = r32(eo + 32);
                                        uint32_t funcs = r32(eo + 28);
                                        uint32_t ords  = r32(eo + 36);
                                        uint32_t nNames = r32(eo + 24);
                                        dbgNNames = nNames;
                                        dbgExpRva = expRva;
                                        for (uint32_t i = 0; i < nNames && i < 16384; ++i) {
                                            uint32_t np = toRaw(r32(toRaw(names + i * 4)));
                                            if (!np || np + 64 > (uint32_t)fbuf.size()) continue;
                                            const char* nm = (const char*)(fd + np);
                                            if (memcmp(nm, "?current_process@core@@", 23) == 0) {
                                                uint16_t idx = *(const uint16_t*)(fd + toRaw(ords + i * 2));
                                                uint32_t frva = r32(toRaw(funcs + (uint32_t)idx * 4));
                                                fn = core85.base + frva;
                                                dbgFrva = frva;
                                                probeStr.assign(nm, strnlen(nm, 64));
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                CloseHandle(fh);
            }
            j += ",\"process\":{";
            {
                std::string pw;
                for (wchar_t wc : core85.path) pw.push_back((char)wc);
                std::string pwj;
                for (char c : pw) {
                    if (c == '\\' || c == '"') { pwj.push_back('\\'); pwj.push_back(c); }
                    else pwj.push_back(c);
                }
                char nb[360];
                _snprintf_s(nb, sizeof(nb), _TRUNCATE,
                            "\"path\":\"%s\",\"fh\":%d,\"sz\":%lld,\"got\":%u,\"expRva\":%u,\"nNames\":%u,\"frva\":%u,\"probe\":\"%s\"",
                            pwj.c_str(), (int)fhOk, szPart, gotB, dbgExpRva, dbgNNames, dbgFrva, probeStr.c_str());
                j += nb;
            }
            j += ",";
            if (fn) {
                // current_process() crashes off the UI thread (0xC0000005),
                // so run the probe on the UI thread via a momentary subclass
                // of the main 1C window.
                g85_fn = fn;
                g85_proc = g85_procVt = g85_svc = g85_svcVt = 0;
                g85_sawMsg = 0;
                HWND uiWin = nullptr;
                int dbgUiWin = 0, dbgCc = 0, dbgDone = 0;
                {
                    struct UiEnum {
                        static BOOL CALLBACK cb(HWND h, LPARAM lp) {
                            DWORD pid = 0;
                            GetWindowThreadProcessId(h, &pid);
                            if (pid != (DWORD)GetCurrentProcessId()) return TRUE;
                            wchar_t cls[64] = {};
                            GetClassNameW(h, cls, 64);
                            if (wcsncmp(cls, L"V8Window0", 9) == 0) {
                                *(HWND*)lp = h;
                                return FALSE;
                            }
                            return TRUE;
                        }
                    };
                    EnumWindows(UiEnum::cb, (LPARAM)&uiWin);
                }
                if (uiWin) {
                    dbgUiWin = 1;
                    g85_uiWin = (uintptr_t)uiWin;
                    g85_origWndProc = (WNDPROC)SetWindowLongPtrW(uiWin, GWLP_WNDPROC,
                                                                (LONG_PTR)V8iSubclass85);
                    if (g85_origWndProc) {
                        dbgCc = 1;
                        SendMessageW(uiWin, WM_APP + 0x602, 0, 0);
                        SetWindowLongPtrW(uiWin, GWLP_WNDPROC, (LONG_PTR)g85_origWndProc);
                    }
                }
                dbgDone = g85_proc ? 1 : 0;
                std::string pm, sm, sm2, sm3, sm4;
                unsigned long long prva = 0, srva = 0, s2rva = 0, s3rva = 0, s4rva = 0;
                if (g85_procVt) {
                    pm.clear();
                    const ModuleRange* foundM = nullptr;
                    for (const ModuleRange& m : mods)
                        if (g85_procVt >= m.base && g85_procVt < m.base + m.size) {
                            foundM = &m;
                            break;
                        }
                    if (foundM) {
                        for (wchar_t wc : foundM->path) pm.push_back((char)wc);
                        size_t bs = pm.rfind('\\');
                        if (bs != std::string::npos) pm = pm.substr(bs + 1);
                        prva = g85_procVt - foundM->base;
                    }
                }
                if (g85_svcVt) {
                    const ModuleRange* foundM = nullptr;
                    for (const ModuleRange& m : mods)
                        if (g85_svcVt >= m.base && g85_svcVt < m.base + m.size) {
                            foundM = &m;
                            break;
                        }
                    if (foundM) {
                        for (wchar_t wc : foundM->path) sm.push_back((char)wc);
                        size_t bs = sm.rfind('\\');
                        if (bs != std::string::npos) sm = sm.substr(bs + 1);
                        srva = g85_svcVt - foundM->base;
                    }
                }
                if (g85_svc2Vt) {
                    const ModuleRange* foundM = nullptr;
                    for (const ModuleRange& m : mods)
                        if (g85_svc2Vt >= m.base && g85_svc2Vt < m.base + m.size) {
                            foundM = &m;
                            break;
                        }
                    if (foundM) {
                        for (wchar_t wc : foundM->path) sm2.push_back((char)wc);
                        size_t bs = sm2.rfind('\\');
                        if (bs != std::string::npos) sm2 = sm2.substr(bs + 1);
                        s2rva = g85_svc2Vt - foundM->base;
                    }
                }
                auto attrib = [&](uintptr_t vt, std::string& out, unsigned long long& rva) {
                    const ModuleRange* fm = nullptr;
                    for (const ModuleRange& m : mods)
                        if (vt >= m.base && vt < m.base + m.size) { fm = &m; break; }
                    if (fm) {
                        for (wchar_t wc : fm->path) out.push_back((char)wc);
                        size_t bs = out.rfind('\\');
                        if (bs != std::string::npos) out = out.substr(bs + 1);
                        rva = vt - fm->base;
                    }
                };
                attrib(g85_svc3Vt, sm3, s3rva);
                attrib(g85_svc4Vt, sm4, s4rva);
                _snprintf_s(b, sizeof(b), _TRUNCATE,
                            "\"uiWin\":%d,\"cc\":%d,\"saw\":%d,\"done\":%d,\"proc\":\"0x%llX\",\"vt\":\"%s+0x%llX\",\"s14ev\":\"0x%llX\",\"svt\":\"%s+0x%llX\",\"s14cmd\":\"0x%llX\",\"svt2\":\"%s+0x%llX\",\"s15ev\":\"0x%llX\",\"svt3\":\"%s+0x%llX\",\"s15cmd\":\"0x%llX\",\"svt4\":\"%s+0x%llX\"",
                            dbgUiWin, dbgCc, g85_sawMsg, dbgDone,
                            (unsigned long long)g85_proc, pm.c_str(), prva,
                            (unsigned long long)g85_svc, sm.c_str(), srva,
                            (unsigned long long)g85_svc2, sm2.c_str(), s2rva,
                            (unsigned long long)g85_svc3, sm3.c_str(), s3rva,
                            (unsigned long long)g85_svc4, sm4.c_str(), s4rva);
                j += b;
                j += ",\"slots\":[";
                for (int i = 0; i < 12; ++i) {
                    char sb[28];
                    _snprintf_s(sb, sizeof(sb), _TRUNCATE, "%s\"0x%llX\"",
                                i ? "," : "", (unsigned long long)g85_slots[i]);
                    j += sb;
                }
                j += "]";
                {
                    std::string fm, rm;
                    unsigned long long fr2 = 0, rr2 = 0;
                    attrib(g85_frameVt, fm, fr2);
                    attrib(g85_recvVt, rm, rr2);
                    char fb[260];
                    _snprintf_s(fb, sizeof(fb), _TRUNCATE,
                                ",\"frame\":\"0x%llX\",\"fvt\":\"%s+0x%llX\",\"recv\":\"0x%llX\",\"rvt\":\"%s+0x%llX\"",
                                (unsigned long long)g85_frame, fm.c_str(), fr2,
                                (unsigned long long)g85_recv, rm.c_str(), rr2);
                    j += fb;
                }
                {
                    char nb2[520];
                    _snprintf_s(nb2, sizeof(nb2), _TRUNCATE,
                                ",\"evCount\":%ld,\"evFrame\":\"0x%llX\",\"hookOk\":%d,\"cwHits\":%ld,\"subscribed\":%d"
                                "\"qProcFrame\":\"0x%llX\",\"qProcRecv\":\"0x%llX\","
                                "\"qCmdFrame\":\"0x%llX\",\"qCmdRecv\":\"0x%llX\","
                                "\"qEvFrame\":\"0x%llX\",\"qEvRecv\":\"0x%llX\"",
                                g85_evCount, (unsigned long long)g85_evFrame,
                                g_cwHookOk, g_cwHits, g85_subscribed,
                                (unsigned long long)g85_qProcFrame, (unsigned long long)g85_qProcRecv,
                                (unsigned long long)g85_qCmdFrame, (unsigned long long)g85_qCmdRecv,
                                (unsigned long long)g85_qEvFrame, (unsigned long long)g85_qEvRecv);
                    j += nb2;
                }
            } else {
                j += "\"fn\":null";
            }
            j += "}";
        }
    }
    j += "}";
    return j;
}

// "exports85 <module> [--count N]" — all exports of a module, read from disk.
static std::string CmdExports85ToJson(const std::wstring& arg) {
    std::wstring mod = arg;
    int limit = 8192;
    size_t sp = arg.find(L" --count ");
    if (sp != std::wstring::npos) {
        mod = arg.substr(0, sp);
        limit = _wtoi(arg.c_str() + sp + 9);
        if (limit <= 0) limit = 8192;
    }
    while (!mod.empty() && (mod.front() == L' ' || mod.front() == L'\t')) mod.erase(0, 1);
    while (!mod.empty() && (mod.back() == L' ' || mod.back() == L'\t' || mod.back() == L'\r' || mod.back() == L'\n'))
        mod.pop_back();
    if (mod.empty())
        return "{\"status\":\"error\",\"message\":\"usage: exports85 <module> [--count N]\"}";

    ModuleRange m = V8iFindModuleByName(mod.c_str());
    if (!m.base) return "{\"status\":\"error\",\"message\":\"module not loaded in the target process\"}";

    static V8iExportEntry entries[8192];
    int cap = (limit < 8192) ? limit : 8192;
    int n = V8iDumpExportsFromFile(m.path, entries, cap);

    std::string j = "{\"status\":\"ok\",\"module\":\"";
    for (wchar_t c : mod) j += (c < 128) ? (char)c : '?';
    char b[512];
    _snprintf_s(b, sizeof(b), _TRUNCATE,
                "\",\"count\":%d,\"base\":\"0x%llX\",\"exports\":[", n,
                (unsigned long long)m.base);
    j += b;
    for (int i = 0; i < n; ++i) {
        const V8iExportEntry& e = entries[i];
        if (i) j += ",";
        j += "{\"name\":\"";
        for (const char* p = e.name; *p; ++p) {
            if (*p == '"' || *p == '\\') j += '\\';
            j += *p;
        }
        _snprintf_s(b, sizeof(b), _TRUNCATE,
                    "\",\"ordinal\":%u,\"rva\":\"0x%X\",\"va\":\"0x%llX\"}",
                    e.ordinal, e.rva, (unsigned long long)(m.base + e.rva));
        j += b;
    }
    j += "]}";
    return j;
}

// "frames" — what eventCreateFrame handed us: pointer, vtable, module, dump.
static std::string CmdFramesToJson(const std::wstring&) {
    char b[512];
    _snprintf_s(b, sizeof(b), _TRUNCATE,
                "{\"status\":\"ok\",\"count\":%d,\"evCount\":%ld,"
                "\"cbtFired\":%d,\"cbtCalls\":%ld,\"cbtCreates\":%ld,"
                "\"cbtFault\":\"0x%08X\",\"cbtHook\":\"0x%llX\",\"cbtThreadHook\":\"0x%llX\",\"cbtThreadTid\":\"0x%lX\",\"cbtStr\":%ld,"
                "\"cbtFirstClass\":\"%s\",\"cbtLastClass\":\"%s\","
                "\"subscribed\":%d,\"frames\":[",
                g85_evFrame ? 1 : 0, g85_evCount, g_cbtFired, g_cbtCalls, g_cbtCreateCount,
                (unsigned)g_cbtFault, (unsigned long long)(uintptr_t)g_cbtHook,
                (unsigned long long)(uintptr_t)g_cbtThreadHook, g_cbtThreadTid, g_cbtStrCreates,
                g_cbtFirstClass, g_cbtLastClass, g85_subscribed);
    std::string j = b;
    if (!g85_evFrame) {
        j += "]}";
        return j;
    }
    _snprintf_s(b, sizeof(b), _TRUNCATE,
                "{\"ptr\":\"0x%llX\",\"vtable\":\"0x%llX\",\"module\":\"%s\",\"rva\":\"0x%X\",\"dump\":\"",
                (unsigned long long)g85_evFrame, (unsigned long long)g85_frameVt,
                g85_frameMod, g85_frameRva);
    j += b;
    for (int i = 0; i < 64; ++i) {
        _snprintf_s(b, sizeof(b), _TRUNCATE, "%s%02X", i ? " " : "", g85_frameDump[i]);
        j += b;
    }
    _snprintf_s(b, sizeof(b), _TRUNCATE,
                "\",\"dirRecv\":\"0x%llX\",\"dirRecvVt\":\"0x%llX\",\"dirExc\":\"0x%X\","
                "\"qiFrame\":\"0x%llX\",\"qiFrameVt\":\"0x%llX\",\"qiRecv\":\"0x%llX\",\"qiRecvVt\":\"0x%llX\","
                "\"qiExc\":%d,\"qiCallExc\":\"0x%X\"}]}",
                (unsigned long long)g85_dirRecv, (unsigned long long)g85_dirRecvVt,
                (unsigned)g85_dirExc,
                (unsigned long long)g85_qiFrame, (unsigned long long)g85_qiFrameVt,
                (unsigned long long)g85_qiRecv, (unsigned long long)g85_qiRecvVt,
                (int)g85_qiExc, (unsigned)g85_qiCallExc);
    j += b;
    return j;
}

// "cmd85 <num> [sub]" — invoke a designer command on 8.5 through the receiver
// captured by the early subscribe (g85_recv, obtained live: commandReceiver is
// slot 31 of the ITopLevelFrame forwarder vtable; recv->vtbl[0] is
// transmitCommand). Runs on the 1C UI thread through the same kV8iCmdMsg
// marshal as the 8.3 `cmd`. Requires eventCreateFrame to have fired, which on
// 8.5 needs the early injection path (hookcbt / launch) — a post-start attach
// never sees the frame event.
static std::string CmdCmd85ToJson(const std::wstring& args0) {
    std::wstring args = args0;
    while (!args.empty() && (args.front() == L' ' || args.front() == L'\t')) args.erase(0, 1);
    unsigned int num = 0;
    int sub = 0;
    if (swscanf_s(args.c_str(), L"%u %d", &num, &sub) < 1)
        return "{\"status\":\"error\",\"message\":\"usage: cmd85 <num> [sub]\"}";
    return Cmd85SendJson(num, sub, false);
}

static std::string CmdInfoToJson(const std::wstring&) { return CmdInfoToJsonA(); }

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

    // 8.5 runs a different frame geometry: the 8.3 calibration below points at
    // an unrelated config.dll vtable there, and its receiver chain does not
    // exist (live: "no working receiver chain" plus an AV during validation).
    // A loaded core85.dll is the reliable platform marker — route through the
    // 8.5 receiver (slot-31 forwarder), captured post-start when needed.
    ModuleRange core85Probe;
    if (FindModule(L"core85.dll", core85Probe))
        return Cmd85SendJson(num, sub, wantHas);

    ModuleRange cfg;
    if (!FindModule(L"config.dll", cfg))
        return "{\"status\":\"error\",\"message\":\"config.dll not loaded\"}";

    // True when this call reused the cached x86 frame instead of discovering
    // it; only then is a second pass (cache invalidation) worth trying.
    bool usedCachedFrame = false;

#if defined(_WIN64)
    // Re-validate the runtime-discovered frame on every use: 1C destroys
    // transient frames, and a stale object poisons all later calls (its freed
    // memory reads as garbage — live: the "vtable" became a module base).
    if (g_x64FrameObj) {
        uintptr_t vt = IsReadable((void*)g_x64FrameObj, sizeof(void*))
                           ? *(uintptr_t*)g_x64FrameObj : 0;
        uintptr_t core = vt && IsReadable((void*)(g_x64FrameObj + sizeof(void*)), sizeof(void*))
                             ? *(uintptr_t*)(g_x64FrameObj + sizeof(void*)) : 0;
        if (!vt || !core || !X64FrameVtValid(cfg, vt) ||
            !IsReadable((void*)core, sizeof(void*))) {
            LogLine("cmd: discovered frame 0x%llX went stale, re-discovering",
                    (unsigned long long)g_x64FrameObj);
            g_x64FrameObj = 0;
            g_x64DiscoveryDone = false;
        }
    }
    const uintptr_t kFrameVtblRva = 0x2EFB50;   // ITopLevelFrame vtable, 8.3.27.1989 x64
    const uintptr_t kCoreOffset = sizeof(void*);
    const int kTransmitSlot = 3;
    // With a runtime-discovered frame (other 8.3 patches) both the vtable and
    // the receiver offset come from the discovery, not from the constants.
    const uintptr_t vtblPtr = g_x64FrameObj ? *(uintptr_t*)g_x64FrameObj
                                            : cfg.base + kFrameVtblRva;
    uintptr_t kRecvBackOffset = g_x64FrameObj ? g_x64RecvOffset : 0x20;
    if (kFrameVtblRva == 0)
        return "{\"status\":\"error\",\"message\":\"frame vtable not calibrated for this build\"}";
#else
    // x86: calibrate at runtime — no hardcoded RVA. A heap object whose first
    // dword points into config.dll .rdata, whose vtable slots 3..40 all point
    // into config.dll .text, and whose receiver chain (core = obj+4,
    // recv = core - off, recv vtable in frame.dll .rdata) is consistent is the
    // main frame. Discovered once: the scan walks the whole address space, so
    // repeating it per command was both slow and racy (freed pages).
    static const uintptr_t kCoreOffset = sizeof(void*);
    static const int kTransmitSlot = 3;
    usedCachedFrame = g_x86FrameObj != 0;
    if (!g_x86FrameObj) g_x86FrameObj = DiscoverFrameVtblX86(cfg);
    if (!g_x86FrameObj)
        return "{\"status\":\"error\",\"message\":\"no frame vtable found on x86\"}";
    const uintptr_t kRecvBackOffset = g_x86RecvOffset;
    uint32_t vtblVal = 0;
    if (!ReadU32Safe(g_x86FrameObj, &vtblVal) || !vtblVal)
        return "{\"status\":\"error\",\"message\":\"frame vtable unreadable\"}";
    const uintptr_t vtblPtr = vtblVal;   // vtable of the discovered frame
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
    }
#endif
    uintptr_t frameVt = 0;
    if (frame && ReadPtrSafe(frame, &frameVt) && frameVt == vtblPtr) {
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
                    uintptr_t val = 0;
                    if (!ReadPtrSafe(p, &val) || val != vtblPtr) continue;
                    uintptr_t core = 0;
                    uintptr_t coreVt = 0;
                    if (ReadPtrSafe(p + kCoreOffset, &core) &&
                        ReadPtrSafe(core, &coreVt) &&
                        IsReadable((void*)coreVt, 32 * sizeof(void*))) {
                        candidates.push_back(p);
                        if (candidates.size() >= 16) break;
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
    bool forced = false;
    // Diagnostic: `cmd <num> [sub] @<hexrecv> #<slot>` overrides the discovered
    // receiver with an explicit object address + slot (x86 calibration probe).
    const wchar_t* atP = wcschr(args.c_str(), L'@');
    const wchar_t* hashP = wcschr(args.c_str(), L'#');
    if (atP && hashP) {
        uintptr_t fRecv = wcstoull(atP + 1, nullptr, 16);
        int fSlot = (int)wcstoul(hashP + 1, nullptr, 10);
        if (fRecv && fSlot >= 0 && fSlot < 64 && IsReadable((void*)fRecv, sizeof(void*))) {
            uintptr_t fVt = *(uintptr_t*)fRecv;
            if (IsReadable((void*)(fVt + fSlot * sizeof(void*)), sizeof(void*))) {
                void* fFn = ((void**)fVt)[fSlot];
                if (IsReadable(fFn, 1)) {
                    recv = (void*)fRecv;
                    trFn = fFn;
                    usedFrame = 0;
                    forced = true;
                }
            }
        }
        if (!forced)
            return "{\"status\":\"error\",\"message\":\"probe target unreadable\"}";
    }
    // For each candidate the receiver is a fixed distance before coreMainFrame
    // (frame+ptrSize), so no vtable calls are needed to obtain it.
    if (!forced) {
        // Best = receiver answered hasHandler(45) alive; fallback = first
        // structurally valid chain that did not throw. A structurally valid
        // chain can still belong to a sibling class (8.3.27.2342 live: three
        // config-vtable objects pass the static checks, only the main frame's
        // receiver answers a COM call without an exception).
        uintptr_t bestFrame = 0, aliveFrame = 0;
        void* bestRecv = nullptr; void* bestTr = nullptr; uintptr_t bestVt = 0;
        void* aliveRecv = nullptr; void* aliveTr = nullptr; uintptr_t aliveVt = 0;
        for (uintptr_t cand : candidates) {
            uintptr_t core = 0;
            if (!ReadPtrSafe(cand + kCoreOffset, &core) || !core) continue;
            uintptr_t candRecv = core - kRecvBackOffset;
            uintptr_t recvVt = 0;
            if (!ReadPtrSafe(candRecv, &recvVt)) continue;
            if (!IsReadable((void*)(recvVt + 6 * sizeof(void*)), sizeof(void*))) continue;
            void* candTr = ((void**)recvVt)[kTransmitSlot];
            if (!IsReadable(candTr, 1)) continue;

            // Live probe on the UI thread: hasHandler(cmd 45) through the same
            // marshal bridge the transmit uses. Exception / timeout = wrong
            // chain, try the next candidate.
            HWND probeHwnd = nullptr;
            DWORD probeErr = 0;
            const char* probePath = "";
            if (!EnsureCmdUi(&probeHwnd, &probeErr, &probePath)) {
                // no marshal window (yet) — keep the structural pick
                bestFrame = cand; bestRecv = (void*)candRecv; bestTr = candTr;
                bestVt = recvVt;
                break;
            }
            void* probeTr = ((void**)recvVt)[5];              // hasHandler
            if (!IsReadable(probeTr, 1)) continue;
            g_pending.recv = (void*)candRecv;
            g_pending.trFn = probeTr;
            g_pending.mode = 1;
            memcpy(g_pending.u.cmd.group, kConfigGroup, 16);
            g_pending.u.cmd.cmdNum = 45;
            g_pending.u.cmd.param = 0;
            g_pending.u.cmd.object = nullptr;
            g_pending.rc = -2;
            g_pending.exc = 0;
            InterlockedExchange(&g_pending.done, 0);
            DWORD_PTR probeRes = 0;
            if (!SendMessageTimeoutW(probeHwnd, kV8iCmdMsg, 0, 0,
                                     SMTO_ABORTIFHUNG | SMTO_BLOCK, 10000, &probeRes))
                continue;
            if (g_pending.exc != 0 || g_pending.rc < 0) continue;   // wrong chain

            if (bestFrame == 0) {
                bestFrame = cand; bestRecv = (void*)candRecv; bestTr = candTr;
                bestVt = recvVt;
                break;   // alive and claims the command — the strongest match
            }
            if (aliveFrame == 0) {
                aliveFrame = cand; aliveRecv = (void*)candRecv; aliveTr = candTr;
                aliveVt = recvVt;
            }
        }
        if (bestFrame == 0 && aliveFrame != 0) {
            bestFrame = aliveFrame; bestRecv = aliveRecv; bestTr = aliveTr;
            bestVt = aliveVt;
        }
        if (bestFrame != 0) {
            usedFrame = bestFrame;
            recv = bestRecv;
            trFn = bestTr;
            frame = bestFrame;
            if (wantHas) {
                // The caller asked for hasHandler, not transmit: swap the
                // target to slot 5 of the picked receiver's vtable.
                void* hasTr = ((void**)bestVt)[5];
                if (IsReadable(hasTr, 1)) trFn = hasTr;
            }
        }
    }

    if (!trFn) {
#if defined(_WIN64)
        // The hardcoded vtable RVA is calibrated to 8.3.27.1989; other 8.3
        // patches have an unrelated vtable at the same RVA (8.3.27.2342 live).
        // Discover the frame at runtime (live-probed) and re-run with it; the
        // cooldown keeps repeated failing clicks from re-scanning in a loop.
        ULONGLONG now = GetTickCount64();
        if (!g_x64DiscoveryDone || now - g_x64DiscoveryTick > 3000) {
            g_x64DiscoveryDone = true;
            g_x64DiscoveryTick = now;
            g_x64FrameObj = DiscoverFrameVtblX64(cfg);
            if (g_x64FrameObj) return CmdCommandToJson(args0);
        }
#else
        // The cached frame no longer answers: it was freed/recreated with the
        // window. Drop it and rediscover once (the retry starts uncached, so a
        // second failure returns the error instead of recursing forever).
        if (usedCachedFrame) {
            g_x86FrameObj = 0;
            return CmdCommandToJson(args0);
        }
#endif
        return j + ",\"error\":\"no working receiver chain\"}";
    }

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
    memcpy(g_pending.u.cmd.group, kConfigGroup, 16);
    g_pending.u.cmd.cmdNum = num;
    g_pending.u.cmd.param = sub;
    g_pending.u.cmd.object = nullptr;
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

// GetExceptionInformation() is only legal inside the filter expression, so the
// record is captured there and the handler body stays a plain assignment.
static int RecordException(EXCEPTION_POINTERS* ep, unsigned* code, uintptr_t* faultAt) {
    *code = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0;
    *faultAt = ep && ep->ExceptionRecord
                   ? (uintptr_t)ep->ExceptionRecord->ExceptionAddress : 0;
    return EXCEPTION_EXECUTE_HANDLER;
}

static int GuardCall(PackedFn fn, const wchar_t* text, char* out, size_t outCap,
                     size_t* outLen, unsigned* code, uintptr_t* faultAt) {
    int ok = 0;
    __try {
        ok = fn(text, out, outCap, outLen);
    } __except (RecordException(GetExceptionInformation(), code, faultAt)) {
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
    uintptr_t faultAt = 0;
    if (GuardCall(PackedThunk, safe, buffer.data(), buffer.size(), &len, &code, &faultAt))
        return std::string(buffer.data(), len);

    char buf[320];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "{\"status\":\"error\",\"message\":\"command crashed\","
                "\"command\":\"%ls\",\"exception\":\"0x%08X\",\"at\":\"0x%llX\"}",
                what ? what : L"?", code, (unsigned long long)faultAt);
    LogLine("command raised 0x%08X at 0x%llX", code, (unsigned long long)faultAt);
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

        if (wcscmp(g_io->request, L"exports") == 0 ||
            wcsncmp(g_io->request, L"exports ", 8) == 0) {
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

        if (wcsncmp(g_io->request, L"cmd85", 5) == 0) {
            LogLine("cmd85: invoking 8.5 designer command");
            PutResponse(Guarded(L"cmd85", CmdCmd85ToJson, std::wstring(g_io->request).substr(5)));
            LogLine("cmd85: done");
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

        if (wcscmp(g_io->request, L"cmdinfo") == 0) {
            PutResponse(Guarded(L"cmdinfo", CmdInfoToJson, std::wstring()));
            continue;
        }

        if (wcscmp(g_io->request, L"frames") == 0) {
            PutResponse(Guarded(L"frames", CmdFramesToJson, std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"exports85", 9) == 0) {
            std::wstring rest = g_io->request + 9;
            PutResponse(Guarded(L"exports85", CmdExports85ToJson, rest));
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

// One command loop per process. Every attach injects the payload again, and a
// second loop would pick up the same request as the first one: two designer
// commands run in parallel (two dialogs, the second one crashes 8.5 after the
// first command's frames went away). Later probes answer the host handshake
// only; the flag is reset when the loop finishes so a new attach can restart
// it after an "exit".
static volatile LONG g_probeActive = 0;

// A skipping probe still has to report "loaded" to the host that started it,
// but must not touch g_io (the running loop owns it), so write the readiness
// reply through a private mapping of the same block.
static int ReportLoadedOnly(const wchar_t* sharedName) {
    HANDLE hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sharedName);
    if (!hMap) return -2;
    SharedIo* io = (SharedIo*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0,
                                            sizeof(SharedIo));
    if (!io) { CloseHandle(hMap); return -3; }
    static const char kLoaded[] = "{\"status\":\"loaded\"}";
    const size_t n = sizeof(kLoaded) - 1;
    memcpy(io->response, kLoaded, n);
    io->response[n] = 0;
    InterlockedExchange((volatile LONG*)&io->responseLen, (LONG)n);
    InterlockedExchange((volatile LONG*)&io->ready, kStateResponse);
    UnmapViewOfFile(io);
    CloseHandle(hMap);
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

    if (InterlockedCompareExchange(&g_probeActive, 1, 0) != 0) {
        LogLine("v8i_probe: command loop already running, reporting loaded");
        int rc = ReportLoadedOnly(name);
        LogLine("v8i_probe leaving (secondary), rc=%d", rc);
        return rc;
    }

    LogLine("v8i_probe entered, pid=%lu block=%ls",
            GetCurrentProcessId(), name);

    // Arm the WH_CBT hook before the session: on 8.5 the splash screen is the
    // last moment when eventCreateFrame can still be caught (see plan_inj_ext
    // P0-2). The hook itself only records the window; the actual subscribe is
    // retried from a worker once the core is ready.
    V8iArmEarlySubscribe();

    int rc = RunPayload(name);
    LogLine("v8i_probe leaving, rc=%d", rc);
    InterlockedExchange(&g_probeActive, 0);
    return rc;
}

// ---------------------------------------------------------------------------
// GitBar "Выгрузить" button: run the designer's own dump-to-files command
// (cmd 45, preceded by cmd 2 when the configuration is not open yet). Runs on
// a worker thread because transmitCommand blocks while the modal dialog is up.
// ---------------------------------------------------------------------------
// cmd 45 is accepted (rc=1) even when the configuration is closed, so the
// return code cannot tell a shown dialog from an ignored command. Looking for
// the dialog after the call does not work either: on 8.5 the call returns only
// once the modal dialog is closed (so Cancel/OK would look like "no dialog"
// and re-trigger the dump). A watcher polls while the command runs instead —
// any new top-level platform window is the dialog, whatever its class is.
// 8.3 shows the dialog a little after the call returns, hence the grace period.
struct DumpWatch {
    HWND base[32] = {};
    int n = 0;
    HANDLE stop = nullptr;
    volatile LONG seen = 0;
    wchar_t title[256] = {};
    unsigned num = 45;        // 45 = main config, 205 = extension (contextual)
    volatile LONG wrong = 0;  // 205 opened the main-configuration dialog
};

static bool IsPlatformWindow(HWND h) {
    if (!IsWindowVisible(h)) return false;
    wchar_t cls[64] = {};
    if (!GetClassNameW(h, cls, 64)) return false;
    // 8.3 dialog frame, and 8.5's V8Window0.* windows — the designer frame is
    // already in the baseline, so only newly appeared ones count.
    return wcscmp(cls, L"V8NewLocalFrameBaseWnd") == 0 ||
           wcsncmp(cls, L"V8Window0.", 10) == 0;
}

static BOOL CALLBACK CollectPlatformWindows(HWND h, LPARAM lp) {
    DumpWatch* w = (DumpWatch*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid == GetCurrentProcessId() && w->n < 32 && IsPlatformWindow(h))
        w->base[w->n++] = h;
    return TRUE;
}

namespace v8i {
// Defined in gitbar.cpp: shows the bar's status tip from any thread.
void GitBarTipFromWorker(const wchar_t* text);
}

static BOOL CALLBACK FindNewPlatformWindow(HWND h, LPARAM lp) {
    DumpWatch* w = (DumpWatch*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != GetCurrentProcessId() || !IsPlatformWindow(h)) return TRUE;
    for (int i = 0; i < w->n; ++i) {
        if (w->base[i] == h) return TRUE;
    }
    // The title tells the two dump dialogs apart: «Выгрузить файлы
    // конфигурации - ...» (main) vs «... расширения конфигурации - ...».
    GetWindowTextW(h, w->title, _countof(w->title));
    if (w->num == 205 && wcscmp(w->title, L"") != 0 &&
        wcsstr(w->title, L"Выгрузить файлы") && !wcsstr(w->title, L"расширения")) {
        // Command 205 dumps whatever the ACTIVE window shows; the main dialog
        // means the extension window was not active — cancel it right away so
        // a mistaken click cannot dump the whole configuration into the
        // extension's repository. On 8.5 the platform processes the close only
        // when its dump command finally returns, so warn the user immediately
        // instead of waiting for the command channel to time out.
        InterlockedExchange(&w->wrong, 1);
        PostMessageW(h, WM_CLOSE, 0, 0);
        v8i::GitBarTipFromWorker(
            L"Выгрузка расширения отменена: активным было окно конфигурации. "
            L"Откройте «Расширения конфигурации», выберите расширение и повторите.");
    }
    InterlockedExchange(&w->seen, 1);
    return FALSE;
}

static DWORD WINAPI DumpWatchThread(LPVOID lp) {
    DumpWatch* w = (DumpWatch*)lp;
    while (WaitForSingleObject(w->stop, 25) == WAIT_TIMEOUT) {
        EnumWindows(FindNewPlatformWindow, (LPARAM)w);
        if (w->seen) break;
    }
    return 0;
}

// Shared dump-to-files flow: the platform shows a modal dialog with XML/archive
// options and the target directory; GitBar only triggers it (the user confirms).
// "UI thread did not answer" already means the modal dialog held the UI thread
// for the whole timeout — a success, and nothing to retry.
static DWORD GitBarDumpVia(unsigned num) {
    DumpWatch w;
    w.num = num;
    EnumWindows(CollectPlatformWindows, (LPARAM)&w);
    w.stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE watch = w.stop ? CreateThread(nullptr, 0, DumpWatchThread, &w, 0, nullptr) : nullptr;

    wchar_t cmd[16];
    swprintf_s(cmd, L"%u 0", num);
    std::string r = CmdCommandToJson(cmd);
    LogLine("gitbar: cmd %u -> %s", num, r.c_str());

    bool timedOut = r.find("did not answer") != std::string::npos;
    if (!timedOut) {
        for (int i = 0; i < 50 && !w.seen; ++i) Sleep(30);
    }
    if (watch) {
        // The watcher only waits on this event, so the join is immediate; an
        // unbounded wait keeps it from outliving the stack block below.
        SetEvent(w.stop);
        WaitForSingleObject(watch, INFINITE);
        CloseHandle(watch);
    }
    if (w.stop) CloseHandle(w.stop);
    LogLine("gitbar: cmd %u dialog seen=%d timedOut=%d", num, (int)w.seen, timedOut ? 1 : 0);
    if (w.seen) {
        char title[512] = {};
        WideCharToMultiByte(CP_UTF8, 0, w.title, -1, title, sizeof(title), nullptr, nullptr);
        LogLine("gitbar: cmd %u dialog title \"%s\"", num, title);
        if (w.wrong) {
            LogLine("gitbar: 205 opened the MAIN configuration dialog: the "
                    "«Расширения конфигурации» window was not active (dialog closed)");
        }
    }

    if (num == 45 && !timedOut && !w.seen) {
        // No dialog ever showed up: the configuration is closed, so open it
        // first and dump again. (205 needs an active extensions window; opening
        // the main configuration would move the context away from it.)
        std::string r2 = CmdCommandToJson(L"2 0");
        LogLine("gitbar: cmd 2 -> %s", r2.c_str());
        Sleep(800);
        std::string r3 = CmdCommandToJson(L"45 0");
        LogLine("gitbar: cmd 45 (after open) -> %s", r3.c_str());
    }
    return 0;
}

static DWORD WINAPI V8iGitBarDumpThread(LPVOID) { return GitBarDumpVia(45); }
static DWORD WINAPI V8iGitBarDumpExtThread(LPVOID) { return GitBarDumpVia(205); }

extern "C" __declspec(dllexport) void V8iGitBarDump() {
    HANDLE h = CreateThread(nullptr, 0, V8iGitBarDumpThread, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
}

// Extension dump: the same dialog flow, but 1C resolves the dump target from
// the ACTIVE window — command 205 while «Расширения конфигурации» is focused
// dumps the selected extension, while any other active window makes it dump
// the main configuration. GitBar therefore only sends the command; the user
// opens/selects the extension first.
extern "C" __declspec(dllexport) void V8iGitBarDumpExtension() {
    HANDLE h = CreateThread(nullptr, 0, V8iGitBarDumpExtThread, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
}
