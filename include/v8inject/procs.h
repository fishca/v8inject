#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace v8i {

struct ProcessEntry {
    uint32_t     pid = 0;
    std::wstring name;        // image file name, e.g. "1cv8.exe"
    std::wstring path;        // full path when readable (may be empty)
    bool         is64 = false;
    bool         session0 = false;   // service session: hidden in the GUI
    int          bitness() const { return is64 ? 64 : 32; }
};

// Lists processes the current user can open, newest-first is not guaranteed.
std::vector<ProcessEntry> ListProcesses();

// True when the image at `path` is a 64-bit PE file.
bool IsPe64(const std::wstring& path);

// True when the given process is 64-bit (falls back to a PE header probe).
bool IsProcess64(DWORD pid);

}  // namespace v8i
