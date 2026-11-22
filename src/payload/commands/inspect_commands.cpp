#include "inspect_commands.h"

#include "v8inject/disasm.h"
#include "v8inject/memscan.h"
#include "v8inject/objects.h"
#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"
#include "v8inject/text.h"

#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace v8i {
namespace commands {

// JSON-escape into UTF-8; window titles are often Cyrillic.
std::string EscapeW(const std::wstring& w) {
    return JsonEscapeWide(w);
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

    const wchar_t* fname = wcsrchr(m.path.c_str(), L'\\');
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
                    JsonEscape(s.name).c_str(), s.va, (unsigned long long)(img.base + s.va),
                    s.virtualSize, s.rawSize,
                    s.Readable() ? "R" : "-", s.Writable() ? "W" : "-",
                    s.Executable() ? "X" : "-");
        j += buf;
    }
    j += "]";

    j += ",\"exportCount\":" + std::to_string(img.exports.size());
    j += ",\"exports\":[";
    // A46: the counter was incremented before the limit was checked, so the
    // 201st export left a trailing comma and the reply of a large module
    // (core83, config: hundreds of exports) did not parse at all. The item is
    // also assembled into a std::string now: a mangled name longer than ~100
    // characters used to be cut inside a char[256].
    size_t shown = 0;
    for (const PeExport& e : img.exports) {
        if (shown >= kPeMaxExports) break;
        if (shown) j += ",";
        ++shown;
        char num[128];
        _snprintf_s(num, sizeof(num), _TRUNCATE,
                    "\"rva\":\"0x%X\",\"va\":\"0x%llX\",\"ordinal\":%u", e.rva,
                    (unsigned long long)(img.base + e.rva), e.ordinal);
        j += "{\"name\":\"" + JsonEscape(e.name) + "\"," + num;
        if (e.forwarded) j += ",\"forwarded\":true,\"to\":\"" + JsonEscape(e.forwarder) + "\"";
        j += "}";
    }
    j += "]";
    if (shown < img.exports.size()) j += ",\"exportsTruncated\":true";

    // Only the module names: a full list with bases overflows the response
    // buffer and hides the interesting fields.
    j += ",\"moduleCount\":" + std::to_string(EnumModules().size());
    j += "}";
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
        else if (tok == L"--max") {
            // A83: the old parser cast _wtoi("-1") to size_t, and the scan
            // collected hits until it ran out of address space.
            uintptr_t v = 0;
            if (!v8i::ParseNumber(takeToken(rest), &v) || v > kMaxCount) {
                return "{\"status\":\"error\",\"message\":\"--max must be a number up to " +
                       std::to_string(kMaxCount) + "\"}";
            }
            opt.maxHits = (size_t)v;
        }
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
    size_t       count = 0;                  // per-command default when !haveCount
    std::vector<std::wstring> positional;   // module name, then a filter
    bool         haveAddr = false;
    bool         haveCount = false;          // A110: the preset 64 made every
                                             // per-command default dead
    size_t       offset = 0;                 // --offset, for byhwnd
    bool         haveOffset = false;
    bool         haveFrom = false;
    bool         haveTo = false;
    std::wstring pattern;
    std::string  error;                      // JSON error; the command returns it
};

std::wstring NextToken(std::wstring& in) {
    while (!in.empty() && in.front() == L' ') in.erase(in.begin());
    if (in.empty()) return std::wstring();
    size_t sp = in.find(L' ');
    std::wstring tok = sp == std::wstring::npos ? in : in.substr(0, sp);
    in = sp == std::wstring::npos ? std::wstring() : in.substr(sp);
    return tok;
}

std::string TokenError(const char* flag) {
    return std::string("{\"status\":\"error\",\"message\":\"invalid value for ") + flag + "\"}";
}

void BadValue(ReArgs& a, const char* flag) {
    if (a.error.empty()) a.error = TokenError(flag);
}

void BadAddress(ReArgs& a) {
    if (a.error.empty()) a.error = "{\"status\":\"error\",\"message\":\"invalid address\"}";
}

// Addresses are typed and documented in hexadecimal: "0x1A2B" and "1A2B" are
// both accepted, nothing else is. The old version returned 0 for an empty or
// malformed token, so a typo silently addressed the first page.
bool ParseHexToken(const std::wstring& t, uintptr_t* out) {
    if (!out) return false;
    std::wstring s = t;
    if (s.size() > 2 && s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s = s.substr(2);
    if (s.empty() || s.size() > 16) return false;
    for (wchar_t c : s) {
        const bool digit = (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
                           (c >= L'A' && c <= L'F');
        if (!digit) return false;
    }
    *out = (uintptr_t)_wcstoui64(s.c_str(), nullptr, 16);
    return true;
}

// Counts may be written in hex (0x38) or decimal (56); a sign or a suffix is
// not a number. The upper bound differs per command, so the caller checks it.
bool ParseCountToken(const std::wstring& t, size_t* out) {
    uintptr_t v = 0;
    if (!out || !v8i::ParseNumber(t, &v)) return false;
    *out = (size_t)v;
    return true;
}

ReArgs ParseReArgs(const std::wstring& args, size_t maxCount) {
    ReArgs a;
    std::wstring rest = args;
    for (;;) {
        std::wstring tok = NextToken(rest);
        if (tok.empty()) break;
        if (tok == L"--module") {
            a.module = NextToken(rest);
        } else if (tok == L"--addr") {
            if (!ParseHexToken(NextToken(rest), &a.addr)) BadValue(a, "--addr");
            a.haveAddr = true;
        } else if (tok == L"--from") {
            if (!ParseHexToken(NextToken(rest), &a.from)) BadValue(a, "--from");
            a.haveFrom = true;
        } else if (tok == L"--to") {
            if (!ParseHexToken(NextToken(rest), &a.to)) BadValue(a, "--to");
            a.haveTo = true;
        } else if (tok == L"--count") {
            size_t v = 0;
            if (!ParseCountToken(NextToken(rest), &v)) {
                BadValue(a, "--count");
            } else if (v > maxCount) {
                if (a.error.empty()) {
                    a.error = "{\"status\":\"error\",\"message\":\"--count is limited to " +
                              std::to_string(maxCount) + "\"}";
                }
            } else if (v == 0) {
                // A110: zero used to be silently replaced with the preset 64.
                if (a.error.empty())
                    a.error = "{\"status\":\"error\",\"message\":\"--count must be a positive number\"}";
            } else {
                a.count = v;
                a.haveCount = true;
            }
        } else if (tok == L"--offset") {
            size_t v = 0;
            if (!ParseCountToken(NextToken(rest), &v) || v > kMaxHwndOffset) {
                BadValue(a, "--offset");
            } else {
                a.offset = v;
            }
            a.haveOffset = true;
        } else if (tok == L"--pattern") {
            a.pattern = NextToken(rest);
        } else if (tok[0] != L'-') {
            a.positional.push_back(tok);
        }
    }
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
    ReArgs a = ParseReArgs(args, kMaxCount);
    if (!a.error.empty()) return a.error;
    // disasm [<hex-addr>] [--module m] — a positional hex number is the address.
    for (const std::wstring& p : a.positional) {
        if (p.find(L'.') != std::wstring::npos) { if (a.module.empty()) a.module = p; }
        else if (!a.haveAddr) {
            if (!ParseHexToken(p, &a.addr)) { BadAddress(a); break; }
            a.haveAddr = true;
        }
    }
    if (!a.error.empty()) return a.error;
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
    const size_t maxShown = a.haveCount ? a.count : 64;   // A110
    std::vector<Insn> insns = Disassemble(start, maxShown * 8, maxShown, &stopped, sizeof(void*) == 8);

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
                    JsonEscape(i.mnemonic).c_str(), JsonEscape(i.opStr).c_str());
        j += buf;
    }
    j += "]}";
    return j;
}

std::string ImportsToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args, kMaxCount);
    if (!a.error.empty()) return a.error;
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
        // The filter is matched case-insensitively against ASCII names, so it
        // is lowered and narrowed one character at a time: building a narrow
        // string from the whole wide range would cut every non-ASCII
        // character in half.
        std::string wantA;
        wantA.reserve(want.size());
        for (wchar_t c : want)
            wantA.push_back(c < 128 ? (char)tolower((unsigned char)c) : '?');
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
    // A110: the per-command default lives here now -- ParseReArgs no longer
    // presets count, which turned every `: N` default into dead code.
    const size_t maxShown = a.haveCount ? a.count : 64;
    for (const PeImport& im : img.imports) {
        if (!want.empty()) {
            std::string hayA = im.name;
            for (auto& c : hayA) c = (char)tolower((unsigned char)c);
            std::string dllA = im.dll;
            for (auto& c : dllA) c = (char)tolower((unsigned char)c);
            // The filter is matched case-insensitively against ASCII names,
            // so it is lowered and narrowed one character at a time: building
            // a narrow string from the whole wide range would cut every
            // non-ASCII character in half.
            std::string wantA;
            wantA.reserve(want.size());
            for (wchar_t c : want)
                wantA.push_back(c < 128 ? (char)tolower((unsigned char)c) : '?');
            bool byDll = dllA.find(wantA) != std::string::npos;
            if (!byDll && hayA.find(wantA) == std::string::npos)
                continue;
        }
        if (shown >= maxShown) break;
        if (!first) j += ",";
        ++shown;
        first = false;
        // A111: the element is a std::string like in `pe` (A46) -- a mangled
        // name does not fit 512 bytes and _TRUNCATE cut it inside the JSON
        // string, invalidating the whole document.
        char at[32];
        _snprintf_s(at, sizeof(at), _TRUNCATE, "0x%llX",
                    (unsigned long long)(img.base + im.iatRva));
        j += "{\"dll\":\"" + JsonEscape(im.dll) + "\",\"name\":\"" + JsonEscape(im.name) +
             "\",\"ordinal\":" + std::to_string(im.ordinal) + ",\"iat\":\"" + at + "\"}";
    }
    j += "]}";
    return j;
}

// exports <module> [filter] — the module's export table, matched by name.
// Used to locate engine entry points (autocomplete, editor, ...) by name.
std::string ExportsToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args, kMaxCount);
    if (!a.error.empty()) return a.error;
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
            if (hay.find(NarrowAscii(want)) == std::string::npos) continue;
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
    // A110: the per-command default lives here now.
    const size_t maxShown = a.haveCount ? a.count : 64;
    for (const PeExport& ex : img.exports) {
        if (!want.empty()) {
            std::string hay = ex.name;
            for (auto& c : hay) c = (char)tolower((unsigned char)c);
            if (hay.find(NarrowAscii(want)) == std::string::npos) continue;
        }
        if (shown >= maxShown) break;
        if (!first) j += ",";
        ++shown;
        first = false;
        // A111: the element is a std::string like in `pe` (A46) -- the fixed
        // buffer cut a long mangled name inside the JSON string.
        char at[32];
        _snprintf_s(at, sizeof(at), _TRUNCATE, "0x%llX",
                    (unsigned long long)(img.base + ex.rva));
        char ord[32];
        _snprintf_s(ord, sizeof(ord), _TRUNCATE, "0x%X", ex.rva);
        j += "{\"name\":\"" + JsonEscape(ex.name) + "\",\"rva\":\"" + ord +
             "\",\"addr\":\"" + at + "\",\"ordinal\":" + std::to_string(ex.ordinal);
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
    ReArgs a = ParseReArgs(args, kMaxCount);
    if (!a.error.empty()) return a.error;
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
    const size_t maxShown = a.haveCount ? a.count : 64;   // A110
    for (const ModuleRange& m : all) {
        if (!want.empty()) {
            const wchar_t* leaf = wcsrchr(m.path.c_str(), L'\\');
            std::wstring leafW = leaf ? leaf + 1 : m.path;
            std::wstring hay = leafW;
            for (auto& c : hay) c = (wchar_t)towlower(c);
            if (hay.find(want) == std::wstring::npos) continue;
        }
        if (shown >= maxShown) break;
        if (!first) j += ",";
        ++shown;
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"base\":\"0x%llX\",\"size\":\"0x%llX\",\"name\":\"",
                    (unsigned long long)m.base, (unsigned long long)m.size);
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
    ReArgs a = ParseReArgs(args, kMaxCount);
    if (!a.error.empty()) return a.error;
    // A positional token is an address when it starts with 0x or looks hex,
    // otherwise it is an import name to resolve through the IAT.
    if (!a.haveAddr) {
        for (const std::wstring& p : a.positional) {
            bool hexLike = (p.size() > 2 && p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) ||
                           (p.find(L'.') == std::wstring::npos && p.size() >= 5);
            if (hexLike) {
                uintptr_t v = 0;
                if (ParseHexToken(p, &v) && v) { a.addr = v; a.haveAddr = true; }
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
        std::string want = NarrowAscii(a.pattern);
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

    XrefResult xr = FindXrefsVerbose(from, to, target, sizeof(void*) == 8,
                                     a.haveCount ? a.count : 64);   // A110
    const std::vector<Xref>& hits = xr.hits;

    // Report what was actually scanned: a wrong module here silently produces
    // an empty result that looks like "no references". Every string goes
    // through the JSON escaper (A93): the module name is a path from the
    // target's PEB, not something this code chose.
    const wchar_t* leaf = wcsrchr(m.path.c_str(), L'\\');
    const std::wstring moduleName = leaf ? std::wstring(leaf + 1) : m.path;
    char buf[320];
    std::string j = "{\"status\":\"ok\",\"target\":\"" + JsonEscape(targetKind) + "\"";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                ",\"moduleBase\":\"0x%llX\",\"moduleSize\":%zu"
                ",\"scannedTo\":\"0x%llX\",\"bytesSeen\":%zu,\"badBytes\":%zu%s"
                ",\"from\":\"0x%llX\",\"to\":\"0x%llX\",\"csError\":%d",
                (unsigned long long)img.base, (size_t)m.size,
                (unsigned long long)xr.scannedTo, xr.bytesSeen, xr.badBytes,
                xr.hitLimit ? ",\"hitLimit\":true" : "",
                (unsigned long long)from, (unsigned long long)to, xr.csError);
    j += buf;
    j += ",\"module\":\"" + EscapeW(moduleName) + "\"";
    j += ",\"stop\":\"" + JsonEscape(xr.stopReason ? xr.stopReason : "") + "\"";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                ",\"targetAddr\":\"0x%llX\",\"scanned\":\"0x%llX-0x%llX\",\"hitCount\":%zu,\"xrefs\":[",
                (unsigned long long)target, (unsigned long long)from,
                (unsigned long long)to, hits.size());
    j += buf;

    bool first = true;
    for (const Xref& x : hits) {
        if (!first) j += ",";
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "{\"from\":\"0x%llX\",",
                    (unsigned long long)x.from);
        j += buf;
        j += "\"how\":\"" + JsonEscape(x.how) + "\"}";
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
    ReArgs a = ParseReArgs(args, kMaxMemMapRows);
    if (!a.error.empty()) return a.error;
    size_t cap = a.haveCount ? a.count : 60;   // A110: the preset made this dead

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    struct Reg { uintptr_t base; size_t size; uint32_t protect; uint32_t state; uint32_t type; };
    std::vector<Reg> big;

    // The biggest regions are the interesting ones, but a caller-supplied count
    // must not turn the list into an unbounded allocation either: the collection
    // itself is bounded, and the reply says when it stopped.
    const size_t kMaxCollected = 65536;
    size_t skippedBig = 0;

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
            if (big.size() < kMaxCollected) {
                big.push_back({rb, (size_t)mbi.RegionSize, (uint32_t)mbi.Protect,
                               (uint32_t)mbi.State, (uint32_t)mbi.Type});
            } else {
                ++skippedBig;
            }
        }
        if (re <= rb) break;
        addr = re;
    }

    // Largest first. The old bubble sort was O(n^2) over every committed
    // region (docs/AUDIT.md A83).
    std::sort(big.begin(), big.end(),
              [](const Reg& x, const Reg& y) { return x.size > y.size; });

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
    j += "]";
    if (skippedBig) j += ",\"regionsTruncated\":true";
    j += "}";
    return j;
}

std::string HeapObjectsToJson(const std::wstring& args) {
    ReArgs a = ParseReArgs(args, kMaxHeapObjects);
    if (!a.error.empty()) return a.error;
    for (const std::wstring& p : a.positional)
        if (p.find(L'.') != std::wstring::npos && a.module.empty()) a.module = p;

    ModuleRange m;
    PeImage img;
    if (!ResolveModule(a.module, m, img))
        return "{\"status\":\"error\",\"message\":\"module not found\"}";

    size_t scanned = 0, regions = 0, committed = 0;
    size_t cap = a.haveCount ? a.count : 20000;   // A110: the real default is live again
    std::vector<HeapObject> objs = FindHeapObjects(m.base, m.size, cap, &scanned, &regions,
                                                   &committed);

    // Group by vtable RVA. The linear "seen" scan was O(n^2) in the number of
    // objects: sorting by rva and counting runs is O(n log n) (A83).
    std::sort(objs.begin(), objs.end(),
              [](const HeapObject& x, const HeapObject& y) { return x.vtableRva < y.vtableRva; });
    std::vector<std::pair<uint32_t, size_t>> groups;
    for (const HeapObject& o : objs) {
        if (groups.empty() || groups.back().first != o.vtableRva) {
            groups.push_back({o.vtableRva, 1});
        } else {
            ++groups.back().second;
        }
    }
    // Most frequent first.
    std::sort(groups.begin(), groups.end(),
              [](const std::pair<uint32_t, size_t>& x, const std::pair<uint32_t, size_t>& y) {
                  return x.second > y.second;
              });

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
    ReArgs a = ParseReArgs(args, kMaxCount);
    if (!a.error.empty()) return a.error;

    uint32_t value = 0;
    bool have = false;
    for (const std::wstring& p : a.positional) {
        if (p.find(L'.') != std::wstring::npos) { if (a.module.empty()) a.module = p; }
        else if (!have) {
            uintptr_t v = 0;
            if (!ParseHexToken(p, &v) || v > 0xFFFFFFFFull) {
                a.error = "{\"status\":\"error\",\"message\":\"invalid value\"}";
                break;
            }
            value = (uint32_t)v;
            have = true;
        }
    }
    if (!a.error.empty()) return a.error;
    if (!have) return "{\"status\":\"error\",\"message\":\"value required\"}";

    size_t scanned = 0;
    std::vector<DwordHit> hits = FindDword(value, a.haveCount ? a.count : 32, &scanned);   // A110

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
    ReArgs a = ParseReArgs(args, kMaxByHwndHits);
    if (!a.error.empty()) return a.error;

    uintptr_t hwndVal = 0;
    for (const std::wstring& p : a.positional) {
        if (p.find(L'.') != std::wstring::npos) { if (a.module.empty()) a.module = p; }
        else if (!hwndVal) {
            if (!ParseHexToken(p, &hwndVal) || hwndVal > 0xFFFFFFFFull) {
                a.error = "{\"status\":\"error\",\"message\":\"invalid hwnd\"}";
                break;
            }
        }
    }
    if (!a.error.empty()) return a.error;
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
        FindObjectsByHwnd((HWND)hwndVal, base, size, off, a.haveCount ? a.count : 16,
                          &scanned, &regions);   // A110

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
    ReArgs a = ParseReArgs(args, kMaxCount);
    if (!a.error.empty()) return a.error;
    // around <hex-addr> [--count n] — the address is positional, as in xref.
    for (const std::wstring& p : a.positional) {
        if (p.find(L'.') != std::wstring::npos) continue;   // a module name
        uintptr_t v = 0;
        if (!ParseHexToken(p, &v)) { BadAddress(a); break; }
        if (v) { a.addr = v; a.haveAddr = true; break; }
    }
    if (!a.error.empty()) return a.error;
    if (!a.haveAddr) return "{\"status\":\"error\",\"message\":\"address required\"}";

    // Walk back a little so the caller sees the setup before the call.
    uintptr_t start = a.addr >= 48 ? a.addr - 48 : a.addr;
    uintptr_t stopped = start;
    std::vector<Insn> insns = Disassemble(start, 256, a.haveCount ? a.count : 64, &stopped,
                                          sizeof(void*) == 8);
    // A110: the `: 16` branch here was dead (ParseReArgs preset 64), and the
    // effective default -- which the "here" marker of this command depends on
    // -- was 64. Made explicit instead of silently changing it to 16.

    char buf[320];
    std::string j = "{\"status\":\"ok\",\"around\":\"0x";
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%llX\",\"insns\":[",
                (unsigned long long)a.addr);
    j += buf;

    bool first = true;
    for (const Insn& i : insns) {
        if (!first) j += ",";
        first = false;
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "{\"addr\":\"0x%llX\"",
                    (unsigned long long)i.address);
        j += buf;
        // A93: the disassembled text is escaped like in `disasm` -- a quote or
        // a backslash in an operand must not end the JSON string.
        j += ",\"text\":\"" + JsonEscape(i.mnemonic) + " " + JsonEscape(i.opStr) + "\"";
        if (i.address == a.addr) j += ",\"here\":true";
        j += "}";
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

}  // namespace commands
}  // namespace v8i
