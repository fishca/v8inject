#pragma once
// Reading and writing the ini files of the project.
//
// Both the git panel and the tray agent keep their settings in %APPDATA%,
// and both had their own copy of the same three lines - with the difference
// that one of them forgot to create the folder, so on a fresh machine the
// settings were written nowhere and silently lost.

#include <string>

namespace v8i {

// Reads a value from an ini file. Returns an empty string when the key or
// the file is missing.
std::wstring IniGet(const wchar_t* path, const wchar_t* section, const wchar_t* key);

// Reads a value with a fallback for the case of a missing key.
std::wstring IniGet(const wchar_t* path, const wchar_t* section, const wchar_t* key,
                    const wchar_t* fallback);

// Writes a value into an ini file, creating the folder of the file when it is
// missing. Returns false when the file could not be written.
bool IniSet(const wchar_t* path, const wchar_t* section, const wchar_t* key,
            const wchar_t* value);

}  // namespace v8i
