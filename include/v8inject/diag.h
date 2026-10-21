#pragma once
#include <windows.h>
#include <cstdarg>
#include <cstdio>

namespace v8i {

// Writes diagnostics next to the v8inject binary. Because the payload runs
// inside a foreign process, the only place both sides can agree on is the
// folder the host itself lives in.
//
// The host sets the folder before injecting, so the payload overwrites the
// same file with its own lines.
void SetLogDirectory(const wchar_t* dir);
const wchar_t* GetLogPath();

void LogLine(const char* fmt, ...);

// Convenience: logs one line, expanding the Win32 error code.
void LogError(const char* what);

}  // namespace v8i
