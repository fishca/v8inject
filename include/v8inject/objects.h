#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace v8i {

// One top-level window of the payload's own process.
struct WindowEntry {
    HWND        hwnd = nullptr;
    std::wstring cls;          // window class
    std::wstring title;        // window text
    uintptr_t   userData = 0;  // GWLP_USERDATA
};

// What a candidate object turned out to be.
struct ObjectCandidate {
    HWND        hwnd = nullptr;
    std::wstring cls;
    std::wstring title;
    uintptr_t   userData = 0;
    bool        readable = false;   // the pointer is in committed memory
    bool        isUnknown = false;  // QueryInterface(IID_IUnknown) succeeded
    bool        isDispatch = false; // ...(IID_IDispatch) succeeded
    bool        hasTypeInfo = false;// GetTypeInfo returned a type library
    std::wstring typeName;          // ITYPEINFO name, when available
    std::wstring error;             // why it was rejected, when it was
};

// Enumerates top-level windows belonging to the current process.
std::vector<WindowEntry> EnumProcessWindows();

// Probes the GWLP_USERDATA pointer of each window as a COM object.
std::vector<ObjectCandidate> ProbeWindowObjects();

}  // namespace v8i
