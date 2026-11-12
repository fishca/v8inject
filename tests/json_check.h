#pragma once
// A minimal JSON validator.
//
// The answers of the payload and of the host are JSON assembled by hand (a
// string here, a number there), and a stray quote in a hook name used to
// break the whole reply. This checker proves that a reply is well-formed.
//
// It is not a general parser: it accepts what JSON producers emit and
// rejects what they must not (raw control characters in a string, trailing
// garbage, a missing colon).

#include <string>

namespace v8i {
namespace test {

class JsonParser {
public:
    explicit JsonParser(const std::string& text) : s_(text) {}

    bool Parse(std::string* err = nullptr) {
        SkipWs();
        if (!Value()) { Set(err, "not a value"); return false; }
        SkipWs();
        if (pos_ != s_.size()) { Set(err, "trailing characters"); return false; }
        return true;
    }

private:
    bool Value() {
        if (pos_ >= s_.size()) return false;
        switch (s_[pos_]) {
        case '{': return Object();
        case '[': return Array();
        case '"': return Str();
        case 't': return Literal("true");
        case 'f': return Literal("false");
        case 'n': return Literal("null");
        default:  return Number();
        }
    }

    bool Object() {
        ++pos_;                                     // '{'
        SkipWs();
        if (pos_ < s_.size() && s_[pos_] == '}') { ++pos_; return true; }
        for (;;) {
            SkipWs();
            if (!Str()) return false;
            SkipWs();
            if (pos_ >= s_.size() || s_[pos_] != ':') return false;
            ++pos_;
            SkipWs();
            if (!Value()) return false;
            SkipWs();
            if (pos_ >= s_.size()) return false;
            if (s_[pos_] == ',') { ++pos_; continue; }
            if (s_[pos_] == '}') { ++pos_; return true; }
            return false;
        }
    }

    bool Array() {
        ++pos_;                                     // '['
        SkipWs();
        if (pos_ < s_.size() && s_[pos_] == ']') { ++pos_; return true; }
        for (;;) {
            SkipWs();
            if (!Value()) return false;
            SkipWs();
            if (pos_ >= s_.size()) return false;
            if (s_[pos_] == ',') { ++pos_; continue; }
            if (s_[pos_] == ']') { ++pos_; return true; }
            return false;
        }
    }

    bool Str() {
        if (pos_ >= s_.size() || s_[pos_] != '"') return false;
        ++pos_;
        while (pos_ < s_.size()) {
            char c = s_[pos_++];
            if (c == '"') return true;
            if ((unsigned char)c < 0x20) return false;   // a raw control char is not allowed
            if (c != '\\') continue;
            if (pos_ >= s_.size()) return false;
            char e = s_[pos_++];
            if (e == 'u') {
                if (pos_ + 4 > s_.size()) return false;
                for (int i = 0; i < 4; ++i) {
                    char h = s_[pos_++];
                    bool hex = (h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') ||
                               (h >= 'A' && h <= 'F');
                    if (!hex) return false;
                }
            } else if (e != '"' && e != '\\' && e != '/' && e != 'b' && e != 'f' &&
                       e != 'n' && e != 'r' && e != 't') {
                return false;
            }
        }
        return false;                                  // unterminated
    }

    bool Number() {
        size_t start = pos_;
        if (pos_ < s_.size() && s_[pos_] == '-') ++pos_;
        bool digits = false;
        while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') { ++pos_; digits = true; }
        if (!digits) return false;
        if (pos_ < s_.size() && s_[pos_] == '.') {
            ++pos_;
            bool frac = false;
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') { ++pos_; frac = true; }
            if (!frac) return false;
        }
        if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
            bool exp = false;
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') { ++pos_; exp = true; }
            if (!exp) return false;
        }
        return pos_ > start;
    }

    bool Literal(const char* lit) {
        size_t n = 0;
        while (lit[n]) ++n;
        if (s_.compare(pos_, n, lit) != 0) return false;
        pos_ += n;
        return true;
    }

    void SkipWs() {
        while (pos_ < s_.size() &&
               (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\n' || s_[pos_] == '\r')) {
            ++pos_;
        }
    }

    static void Set(std::string* err, const char* what) {
        if (err) *err = what;
    }

    const std::string& s_;
    size_t pos_ = 0;
};

// True when the text is a well-formed JSON value.
inline bool JsonValid(const std::string& text, std::string* err = nullptr) {
    JsonParser parser(text);
    return parser.Parse(err);
}

}  // namespace test
}  // namespace v8i
