#include "cli/console_input.h"

#include "v8inject/text.h"

namespace v8i {

LineReader::LineReader(HANDLE in) : in_(in) {
    DWORD mode = 0;
    console_ = GetConsoleMode(in_, &mode) != 0;
}

ConsoleLine LineReader::Next(size_t maxChars) {
    if (eof_) {
        ConsoleLine line;
        line.eof = true;
        return line;
    }
    return console_ ? NextConsole(maxChars) : NextBytes(maxChars);
}

// The console hands out UTF-16: no code page is involved and a Cyrillic filter
// arrives as typed (A94).
ConsoleLine LineReader::NextConsole(size_t maxChars) {
    ConsoleLine line;
    std::wstring text;
    size_t total = 0;
    bool done = false;

    while (!done) {
        wchar_t buf[512];
        DWORD got = 0;
        if (!ReadConsoleW(in_, buf, (DWORD)_countof(buf), &got, nullptr) || got == 0) {
            // A closed console or Ctrl+Z: the session ends. A partial line
            // without a terminator is still a command.
            eof_ = true;
            if (total == 0) {
                line.eof = true;
                return line;
            }
            break;
        }
        for (DWORD i = 0; i < got; ++i) {
            if (buf[i] == L'\r' || buf[i] == L'\n') {
                done = true;
                break;
            }
            ++total;
            // Over the limit the text is not needed: the answer says so. The
            // rest of the line still has to be consumed, or its tail becomes
            // the next command.
            if (total <= maxChars) text.push_back(buf[i]);
        }
    }

    line.chars = total;
    line.tooLong = total > maxChars;
    if (!line.tooLong) line.utf8 = WideToUtf8(text);
    return line;
}

// A pipe or a redirected file: bytes, documented as UTF-8.
ConsoleLine LineReader::NextBytes(size_t maxChars) {
    // A line longer than this many bytes necessarily has more than maxChars
    // characters (UTF-8 never spends more than four bytes on two UTF-16 units),
    // so the text is drained instead of buffered.
    const size_t cap = maxChars * 4 + 8;

    ConsoleLine line;
    std::string raw;
    size_t total = 0;
    bool drained = false;
    bool newline = false;
    char lastByte = 0;

    // Appends the bytes of one chunk up to the terminator; `next` is where the
    // terminator was found, or the end of the chunk.
    auto consume = [&](const char* data, size_t n, size_t& next) {
        for (size_t i = 0; i < n; ++i) {
            const char c = data[i];
            if (c == '\n') {
                newline = true;
                next = i + 1;
                return;
            }
            lastByte = c;
            ++total;
            if (raw.size() < cap) {
                raw.push_back(c);
            } else {
                drained = true;
            }
        }
        next = n;
    };

    // The first line comes from a chunk that already held the next one.
    if (!pending_.empty()) {
        size_t next = 0;
        consume(pending_.data(), pending_.size(), next);
        pending_.erase(0, next);
    }

    while (!newline) {
        char buf[4096];
        DWORD got = 0;
        if (!ReadFile(in_, buf, (DWORD)sizeof(buf), &got, nullptr) || got == 0) {
            eof_ = true;
            break;
        }
        size_t next = 0;
        consume(buf, (size_t)got, next);
        if (newline) pending_.assign(buf + next, (size_t)got - next);
    }

    // The CR of a CRLF terminator is not part of the command.
    if (lastByte == '\r') {
        --total;
        if (!drained && !raw.empty() && raw.back() == '\r') raw.pop_back();
    }

    if (drained) {
        // Nothing to hand to the payload, only the length for the answer.
        line.chars = total;
        line.tooLong = true;
        return line;
    }

    const std::wstring wide = Utf8ToWide(raw);
    line.chars = wide.size();
    line.tooLong = wide.size() > maxChars;
    if (!line.tooLong) line.utf8 = raw;
    return line;
}

}  // namespace v8i
