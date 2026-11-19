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

// True when these IsWow64Process2 answers describe a 64-bit process.
//
// `processMachine` is the machine of the process image and `nativeMachine` the
// machine of the host OS; they differ for a WOW64 process (I386 image on an
// AMD64 host), and a native 64-bit process reports IMAGE_FILE_MACHINE_UNKNOWN
// as its process machine. Keying off `nativeMachine` alone announced every
// process on 64-bit Windows as 64-bit, which sent an x64 payload at 32-bit
// targets and made `modules` lie (A57/A18).
bool IsMachine64(USHORT processMachine, USHORT nativeMachine);

// True when the given process is 64-bit (falls back to a PE header probe).
bool IsProcess64(DWORD pid);

}  // namespace v8i
