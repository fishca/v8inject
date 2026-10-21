#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace v8i {

struct MemoryHit {
    uintptr_t address = 0;
    bool      inModule = false;
    std::wstring module;      // owning module when the hit lies inside one
    std::string bytesBefore;  // up to 16 bytes of context, hex
    std::string bytesAfter;
};

struct FindOptions {
    std::wstring pattern;     // what to look for
    std::wstring module;      // restrict to this module (empty = whole process)
    bool wide = false;        // search the pattern as UTF-16LE
    size_t maxHits = 64;
    bool stopAtFirst = false;
};

// Scans readable, committed memory of the current process for `pattern`.
// Read-only: nothing is written and no code in the process is executed.
std::vector<MemoryHit> FindInMemory(const FindOptions& opt, size_t* scannedBytes);

// Describes the module that owns `addr`, if any.
bool ModuleOfAddress(uintptr_t addr, std::wstring* name, uintptr_t* moduleRva);

// Finds a heap object that owns the given HWND.
//
// 1C stores the window handle inside its frame object at +0x34 but keeps no
// back-pointer in the HWND itself (GWLP_USERDATA is null), so the only reliable
// way back is to scan committed memory for a pointer into `moduleBase` .. +`moduleSize`
// and check the field at `hwndOffset` for a match.
struct HwndOwner {
    uintptr_t address = 0;      // object address
    uintptr_t vtable = 0;       // first dword of the object
    uint32_t  moduleRva = 0;    // rva of the vtable inside the module, if any
    bool      vtableInModule = false;
};

std::vector<HwndOwner> FindObjectsByHwnd(HWND hwnd, uintptr_t moduleBase, size_t moduleSize,
                                        size_t hwndOffset, size_t maxHits,
                                        size_t* scannedBytes = nullptr,
                                        size_t* regions = nullptr);

// Every heap object whose first dword points inside a module — i.e. a C++
// object with a vtable from that module. Grouped by vtable RVA so the classes
// can be counted.
struct HeapObject {
    uintptr_t address = 0;
    uintptr_t vtable = 0;
    uint32_t  vtableRva = 0;
};

std::vector<HeapObject> FindHeapObjects(uintptr_t moduleBase, size_t moduleSize,
                                       size_t maxHits, size_t* scannedBytes = nullptr,
                                       size_t* regions = nullptr,
                                       size_t* committedBytes = nullptr);

// Finds every 4-byte occurrence of `value` in writable committed memory.
// Used to locate the field that stores an HWND inside an object: the offset is
// then foundAddress - nearestObjectStart.
struct DwordHit {
    uintptr_t address = 0;
};

std::vector<DwordHit> FindDword(uint32_t value, size_t maxHits,
                               size_t* scannedBytes = nullptr);

}  // namespace v8i
