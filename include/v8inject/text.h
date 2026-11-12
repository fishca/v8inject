#pragma once
// Text helpers shared by the host, the payload and the tests.
//
// The payload speaks UTF-8, the platform speaks UTF-16, and every conversion
// between them used to be a private copy in each module: three copies of
// Utf8ToWide alone. One place, one behaviour, and unit tests can reach it.

#include <cstdint>
#include <string>

namespace v8i {

// ---- UTF-8 <-> UTF-16 -----------------------------------------------------

std::wstring Utf8ToWide(const std::string& s);
std::string  WideToUtf8(const std::wstring& s);

// Narrows a wide string to ASCII. Module names, export names and window
// classes are ASCII, so a non-ASCII character becomes '?': building a narrow
// string from the whole wide range would cut every such character in half.
std::string NarrowAscii(const std::wstring& w);

// ---- JSON -----------------------------------------------------------------

// Escapes a string for a JSON value. The narrow string is expected to be
// UTF-8 already.
std::string JsonEscape(const std::string& s);

// The same for a wide string: it is converted to UTF-8 first.
std::string JsonEscapeWide(const std::wstring& w);

// ---- numbers and paths ----------------------------------------------------

// Parses a number in the notation of the command line: "0x1A2B" is
// hexadecimal, a bare number is decimal. Returns false when the text is not a
// number at all (empty, a sign, trailing junk) - the old parser accepted
// "-1" and turned it into a huge address.
bool ParseNumber(const wchar_t* text, uintptr_t* out);
bool ParseNumber(const std::wstring& text, uintptr_t* out);

// Unpacks the "value" field of a `str` reply: UTF-8 text with \" \\ \n \r \t
// and \uXXXX escapes, surrogate pairs included.
std::wstring UnescapeStrValue(const std::string& v);

// Normalizes a path for prefix comparison: absolute, forward slashes, lower
// case, without a trailing slash.
std::wstring NormalizePath(const std::wstring& p);

}  // namespace v8i
