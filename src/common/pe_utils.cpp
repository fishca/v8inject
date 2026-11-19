#include "v8inject/pe_utils.h"
#include <winternl.h>

#include <algorithm>

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

// The loader list is mutated by every LoadLibrary/LoadLibraryEx in the host
// process, and this walk does not hold the loader lock: a node can be
// unlinked, and its entry/name buffer freed, halfway through the walk. A
// VirtualQuery probe followed by a plain dereference still faults in that
// window, so every read goes through ReadProcessMemory on the current
// process: a bad address is reported as an error instead of raising an AV
// inside the payload (which would take 1C down with it). The entry read
// doubles as the link read: the forward pointer is a field of the entry.
bool ReadSelf(const void* src, void* dst, size_t len) {
    if (!src || !dst || !len) return false;
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), src, dst, len, &got)) return false;
    return got == len;
}

// Bound for the PEB walk. A corrupt list can point to itself, and a healthy
// Configurator loads far fewer modules than this.
constexpr size_t kMaxModuleWalk = 4096;

std::wstring LoaderString(const UNICODE_STRING& us) {
    if (!us.Buffer || us.Length < sizeof(wchar_t)) return std::wstring();
    const size_t chars = us.Length / sizeof(wchar_t);
    std::wstring name(chars, L'\0');
    if (!ReadSelf(us.Buffer, name.data(), chars * sizeof(wchar_t)))
        return std::wstring();
    return name;
}

}  // namespace

std::vector<ModuleRange> EnumModules() {
    std::vector<ModuleRange> result;

    PPEB peb = CurrentPeb();
    if (!peb) return result;

    PEB_LDR_DATA* ldr = nullptr;
    if (!ReadSelf(&peb->Ldr, &ldr, sizeof(ldr)) || !ldr) return result;

    LIST_ENTRY head{};
    if (!ReadSelf(&ldr->InMemoryOrderModuleList, &head, sizeof(head))) return result;

    LIST_ENTRY* const listHead = &ldr->InMemoryOrderModuleList;
    std::vector<LIST_ENTRY*> seen;
    seen.reserve(128);

    LIST_ENTRY* e = head.Flink;
    for (size_t i = 0; i < kMaxModuleWalk && e && e != listHead; ++i) {
        // A corrupt list must end the walk, not loop over the same node.
        if (std::find(seen.begin(), seen.end(), e) != seen.end()) break;
        seen.push_back(e);

        V8I_LDR_DATA_TABLE_ENTRY ent{};
        if (!ReadSelf(CONTAINING_RECORD(e, V8I_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
                      &ent, sizeof(ent)))
            break;

        ModuleRange mr;
        mr.base = (uintptr_t)ent.DllBase;
        mr.size = ent.SizeOfImage;
        mr.path = LoaderString(ent.FullDllName);
        result.push_back(std::move(mr));

        e = ent.InMemoryOrderLinks.Flink;
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
