#pragma once
// One command line of the interactive `attach` session.
//
// A94: the session used to read stdin with fgets into char[4096]. A line longer
// than the buffer came back as two commands - the tail of one command was
// executed as the next one - and a console handed out OEM bytes that were then
// decoded as UTF-8. The reader below reads the console with ReadConsoleW
// (UTF-16, the console code page never enters the picture) and reads a pipe or
// a file as UTF-8 bytes, and it reads a line whole or says that it does not fit.

#include <windows.h>
#include <cstddef>
#include <string>

namespace v8i {

struct ConsoleLine {
    bool eof = false;      // no more input
    bool tooLong = false;  // the line does not fit into `maxChars` characters
    std::string utf8;      // the line itself, terminator removed; empty when eof/tooLong
    size_t chars = 0;      // its length in UTF-16 code units
};

class LineReader {
public:
    // `in` is usually GetStdHandle(STD_INPUT_HANDLE). A console handle is
    // detected on the spot: a pipe cannot be mistaken for one.
    explicit LineReader(HANDLE in);
    LineReader(const LineReader&) = delete;
    LineReader& operator=(const LineReader&) = delete;

    // Reads one line. A line of up to `maxChars` characters is returned
    // decoded; a longer one is drained to its end and reported tooLong, so the
    // next call starts at the next command instead of at the middle of this one.
    ConsoleLine Next(size_t maxChars);

private:
    ConsoleLine NextConsole(size_t maxChars);
    ConsoleLine NextBytes(size_t maxChars);

    HANDLE in_;
    bool console_;
    std::string pending_;   // bytes of the next line, already read from a pipe
    bool eof_ = false;
};

}  // namespace v8i
