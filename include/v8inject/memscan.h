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

}  // namespace v8i
