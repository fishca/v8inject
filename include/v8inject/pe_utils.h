#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace v8i {

struct ModuleRange {
    uintptr_t    base = 0;
    size_t       size = 0;
    std::wstring path;
};

std::vector<ModuleRange> EnumModules();
bool FindModule(const wchar_t* name, ModuleRange& out);

inline uintptr_t Rva(const ModuleRange& m, uintptr_t rva) { return m.base + rva; }

// True when [p, p+len) lies inside committed, readable memory of this process.
bool IsReadable(const void* p, size_t len);

}  // namespace v8i
