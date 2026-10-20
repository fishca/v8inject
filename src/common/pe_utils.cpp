#include "v8inject/pe_utils.h"
#include <winternl.h>

#if defined(_MSC_VER)
#  include <intrin.h>
#endif

namespace v8i {

namespace {

struct V8I_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

PPEB CurrentPeb() {
#if defined(_MSC_VER)
#  if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#  else
    return (PPEB)__readfsdword(0x30);
#  endif
#elif defined(__GNUC__)
#  if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#  else
    return (PPEB)__readfsdword(0x30);
#  endif
#else
    return nullptr;
#endif
}

}  // namespace

std::vector<ModuleRange> EnumModules() {
    std::vector<ModuleRange> result;

    PPEB peb = CurrentPeb();
    if (!peb || !peb->Ldr) return result;

    auto ldr = (PEB_LDR_DATA*)peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* e = head->Flink; e && e != head; e = e->Flink) {
        auto ent = CONTAINING_RECORD(e, V8I_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        ModuleRange mr;
        mr.base = (uintptr_t)ent->DllBase;
        mr.size = ent->SizeOfImage;
        if (ent->FullDllName.Buffer && ent->FullDllName.Length)
            mr.path.assign(ent->FullDllName.Buffer,
                           ent->FullDllName.Length / sizeof(wchar_t));
        result.push_back(std::move(mr));
    }
    return result;
}

bool FindModule(const wchar_t* name, ModuleRange& out) {
    if (!name) return false;
    for (auto& m : EnumModules()) {
        const wchar_t* fname = wcsrchr(m.path.c_str(), L'\\');
        fname = fname ? fname + 1 : m.path.c_str();
        if (_wcsicmp(fname, name) == 0) { out = m; return true; }
    }
    return false;
}

bool IsReadable(const void* p, size_t len) {
    if (!p || !len) return false;
    const unsigned char* cur = (const unsigned char*)p;
    const unsigned char* end = cur + len;
    while (cur < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(cur, &mbi, sizeof(mbi))) return false;
        if (mbi.State != MEM_COMMIT) return false;
        DWORD prot = mbi.Protect & 0xFF;
        bool readable = (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                         prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                         prot == PAGE_EXECUTE_READWRITE ||
                         prot == PAGE_EXECUTE_WRITECOPY);
        if (!readable || (mbi.Protect & PAGE_GUARD)) return false;
        cur = (const unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    }
    return true;
}

}  // namespace v8i
