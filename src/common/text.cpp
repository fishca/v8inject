#include "v8inject/text.h"

#include <windows.h>
#include <cwctype>
#include <cstdio>

namespace v8i {

namespace {

// Appends a code point as UTF-8.
void AppendUtf8(std::string& out, unsigned cp) {
    if (cp < 0x80) {
        out += (char)cp;
    } else if (cp < 0x800) {
        out += (char)(0xC0 | (cp >> 6));
        out += (char)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += (char)(0xE0 | (cp >> 12));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    } else {
        out += (char)(0xF0 | (cp >> 18));
        out += (char)(0x80 | ((cp >> 12) & 0x3F));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    }
}

// Reads four hex digits at `pos` into `out`. Returns false when they are not
// hex digits.
bool ReadHex4(const std::string& s, size_t pos, unsigned* out) {
    if (pos + 4 > s.size()) return false;
    unsigned v = 0;
    for (int i = 0; i < 4; ++i) {
        char h = s[pos + i];
        v <<= 4;
        if (h >= '0' && h <= '9') v |= (unsigned)(h - '0');
        else if (h >= 'a' && h <= 'f') v |= (unsigned)(h - 'a' + 10);
        else if (h >= 'A' && h <= 'F') v |= (unsigned)(h - 'A' + 10);
        else return false;
    }
    *out = v;
    return true;
}

}  // namespace

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(),
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n, nullptr, nullptr);
    return out;
}

std::string NarrowAscii(const std::wstring& w) {
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w)
        out.push_back(c < 128 ? (char)c : '?');
    return out;
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if ((unsigned char)c < 0x20) {
                char b[8];
                _snprintf_s(b, sizeof(b), _TRUNCATE, "\\u%04x", (unsigned)(unsigned char)c);
                out += b;
            } else {
                out += c;
            }
        }
    }
    return out;
}

std::string JsonEscapeWide(const std::wstring& w) {
    return JsonEscape(WideToUtf8(w));
}

bool ParseNumber(const wchar_t* text, uintptr_t* out) {
    if (!text || !out) return false;
    return ParseNumber(std::wstring(text), out);
}

bool ParseNumber(const std::wstring& text, uintptr_t* out) {
    if (!out) return false;
    std::wstring t = text;
    // Whitespace around the number is not a number here: the CLI passes the
    // argument as it was typed.
    while (!t.empty() && (t.front() == L' ' || t.front() == L'\t')) t.erase(t.begin());
    while (!t.empty() && (t.back() == L' ' || t.back() == L'\t')) t.pop_back();
    if (t.empty()) return false;

    bool hex = false;
    if (t.size() > 2 && t[0] == L'0' && (t[1] == L'x' || t[1] == L'X')) {
        hex = true;
        t = t.substr(2);
    }
    if (t.empty()) return false;

    uintptr_t v = 0;
    for (wchar_t c : t) {
        int d;
        if (c >= L'0' && c <= L'9') d = c - L'0';
        else if (hex && c >= L'a' && c <= L'f') d = c - L'a' + 10;
        else if (hex && c >= L'A' && c <= L'F') d = c - L'A' + 10;
        else return false;                       // a sign, a suffix, trailing junk
        if (v > (UINTPTR_MAX - (uintptr_t)d) / (hex ? 16u : 10u)) return false;  // overflow
        v = hex ? (v * 16 + (uintptr_t)d) : (v * 10 + (uintptr_t)d);
    }
    *out = v;
    return true;
}

std::wstring UnescapeStrValue(const std::string& v) {
    std::string raw;
    raw.reserve(v.size());
    for (size_t i = 0; i < v.size(); ++i) {
        const char c = v[i];
        if (c != '\\' || i + 1 >= v.size()) { raw += c; continue; }
        const char n = v[i + 1];
        switch (n) {
        case '"':  raw += '"';  ++i; break;
        case '\\': raw += '\\'; ++i; break;
        case '/':  raw += '/';  ++i; break;
        case 'n':  raw += '\n'; ++i; break;
        case 'r':  raw += '\r'; ++i; break;
        case 't':  raw += '\t'; ++i; break;
        case 'u': {
            unsigned cp = 0;
            // A broken escape is kept as it was written: silently dropping
            // the backslash would change the text without a trace.
            if (!ReadHex4(v, i + 2, &cp)) { raw += '\\'; break; }
            i += 5;
            // A surrogate pair: the low half follows the high one.
            if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < v.size() &&
                v[i + 1] == '\\' && i + 2 < v.size() && v[i + 2] == 'u') {
                unsigned low = 0;
                if (ReadHex4(v, i + 3, &low) && low >= 0xDC00 && low <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    i += 6;
                }
            }
            if (cp == 0) break;                     // a NUL cannot travel in a string
            AppendUtf8(raw, cp);
            break;
        }
        default: raw += c; break;
        }
    }
    return Utf8ToWide(raw);
}

std::wstring NormalizePath(const std::wstring& p) {
    wchar_t full[MAX_PATH] = {};
    GetFullPathNameW(p.c_str(), MAX_PATH, full, nullptr);
    std::wstring out = full;
    for (wchar_t& c : out) {
        if (c == L'\\') c = L'/';
        c = (wchar_t)towlower(c);
    }
    while (!out.empty() && out.back() == L'/') out.pop_back();
    return out;
}

}  // namespace v8i
