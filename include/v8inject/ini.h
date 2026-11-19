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

// Reads a value without the Win32 profile APIs (GetPrivateProfileStringW).
// The payload must not call those: on a live 8.3.27.2342 they took the calling
// thread down inside KERNELBASE path canonicalization. The file is read as
// bytes and decoded by its byte order mark — UTF-16LE (what IniSet writes),
// UTF-16BE, UTF-8 — and falls back to the ANSI code page for a file without a
// mark. IniSet creates the file as UTF-16, so a raw byte search for the key
// finds nothing there: it stops at the NUL right after the mark (A53).
// `found` (optional) says whether the key was present at all, which lets the
// caller tell "absent" from "set to an empty value".
std::wstring IniGetManual(const wchar_t* path, const wchar_t* section,
                          const wchar_t* key, const wchar_t* fallback,
                          bool* found = nullptr);

}  // namespace v8i
