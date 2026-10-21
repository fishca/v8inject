#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace v8i {

// One top-level window of the payload's own process. Everything here is read
// passively: no window messages are sent and no pointers are dereferenced, so
// enumerating cannot disturb the host application.
struct WindowEntry {
    HWND         hwnd = nullptr;
    std::wstring cls;          // window class
    std::wstring title;        // cached window text
    uintptr_t    userData = 0; // GWLP_USERDATA
    bool         readable = false;
};

std::vector<WindowEntry> EnumProcessWindows();

}  // namespace v8i
