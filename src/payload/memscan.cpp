#include "v8inject/memscan.h"
#include "v8inject/diag.h"
#include "v8inject/pe_utils.h"

#include <algorithm>
#include <cstring>

namespace v8i {

namespace {

// Builds the byte sequence to search for. Wide mode pads every character with a
// zero byte, which is how MSVC stores L"..." literals in .rdata.
std::string BuildNeedle(const std::wstring& pattern, bool wide) {
    std::string needle;
    if (wide) {
        needle.resize(pattern.size() * sizeof(wchar_t));
        memcpy(&needle[0], pattern.data(), needle.size());
    } else {
        int n = WideCharToMultiByte(CP_UTF8, 0, pattern.c_str(), (int)pattern.size(),
                                    nullptr, 0, nullptr, nullptr);
        if (n > 0) {
            needle.resize((size_t)n);
            WideCharToMultiByte(CP_UTF8, 0, pattern.c_str(), (int)pattern.size(),
                                &needle[0], n, nullptr, nullptr);
        }
    }
    return needle;
}

std::string HexBytes(const unsigned char* p, size_t n) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(kHex[p[i] >> 4]);
        out.push_back(kHex[p[i] & 0xF]);
    }
    return out;
}

// A hit inside a module's file-backed image is far more interesting than one in
// a heap allocation, so record which module owns the address.
bool ModuleContains(const ModuleRange& m, uintptr_t addr) {
    return addr >= m.base && addr < m.base + m.size;
}

}  // namespace

bool ModuleOfAddress(uintptr_t addr, std::wstring* name, uintptr_t* moduleRva) {
    for (const ModuleRange& m : EnumModules()) {
        if (!ModuleContains(m, addr)) continue;
        if (name) {
            const wchar_t* f = wcsrchr(m.path.c_str(), L'\\');
            *name = f ? f + 1 : m.path;
        }
        if (moduleRva) *moduleRva = addr - m.base;
        return true;
    }
    return false;
}

std::vector<MemoryHit> FindInMemory(const FindOptions& opt, size_t* scannedBytes) {
    std::vector<MemoryHit> hits;
    if (scannedBytes) *scannedBytes = 0;
    if (opt.pattern.empty()) return hits;

    const std::string needle = BuildNeedle(opt.pattern, opt.wide);
    if (needle.empty()) return hits;

    // Restricting to one module keeps a scan of 1cv8's 200+ DLLs from taking
    // minutes; the caller almost always knows where to look.
    uintptr_t rangeBase = 0;
    uintptr_t rangeEnd = UINTPTR_MAX;
    if (!opt.module.empty()) {
        ModuleRange m;
        if (!FindModule(opt.module.c_str(), m)) return hits;
        rangeBase = m.base;
        rangeEnd = m.base + m.size;
    }

    const size_t kChunk = 1u << 20;             // 1 MB windows
    const size_t kOverlap = needle.size() > 1 ? needle.size() - 1 : 0;
    std::vector<unsigned char> buf(kChunk + kOverlap);

    uintptr_t addr = rangeBase;
    while (addr < rangeEnd) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;

        uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
        uintptr_t regionEnd = regionBase + mbi.RegionSize;
        if (regionEnd <= addr) break;           // defensive: no forward progress

        bool usable = mbi.State == MEM_COMMIT;
        if (usable) {
            DWORD prot = mbi.Protect & 0xFF;
            usable = prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                     prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                     prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
            if (mbi.Protect & PAGE_GUARD) usable = false;
        }
        if (!usable) {
            addr = regionEnd;
            continue;
        }

        // Walk the region in 1 MB windows so a huge allocation cannot blow
        // the stack and a failing window does not abort the whole scan.
        uintptr_t cur = std::max(addr, regionBase);
        uintptr_t stop = std::min(regionEnd, rangeEnd);
        while (cur < stop) {
            size_t want = (size_t)std::min<uintptr_t>(kChunk + kOverlap, stop - cur);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)cur, buf.data(),
                                   want, &got) || got < needle.size()) {
                cur += kChunk;
                continue;
            }
            if (scannedBytes) *scannedBytes += got;

            const unsigned char* hay = buf.data();
            const unsigned char* hayEnd = buf.data() + got;
            const unsigned char* p = hay;
            while ((p = std::search(p, hayEnd, needle.begin(), needle.end())) != hayEnd) {
                MemoryHit hit;
                hit.address = cur + (uintptr_t)(p - hay);

                size_t before = std::min<size_t>(16, (size_t)(p - hay));
                size_t afterOff = (size_t)(p - hay) + needle.size();
                size_t after = afterOff < got ? std::min<size_t>(16, got - afterOff) : 0;
                hit.bytesBefore = HexBytes(p - before, before);
                if (after) hit.bytesAfter = HexBytes(p + needle.size(), after);

                std::wstring mod;
                uintptr_t rva = 0;
                if (ModuleOfAddress(hit.address, &mod, &rva)) {
                    hit.inModule = true;
                    hit.module = mod;
                }
                hits.push_back(std::move(hit));

                if (opt.stopAtFirst || hits.size() >= opt.maxHits) return hits;
                p += 1;   // allow overlapping matches
            }
            if (got < want) break;   // partial read: end of the region window
            cur += kChunk;
        }
        addr = regionEnd;
    }
    return hits;
}

std::vector<HwndOwner> FindObjectsByHwnd(HWND hwnd, uintptr_t moduleBase, size_t moduleSize,
                                        size_t hwndOffset, size_t maxHits,
                                        size_t* scannedBytes, size_t* regions) {
    std::vector<HwndOwner> out;
    size_t totalScanned = 0, regionCount = 0, skippedBytes = 0;
    (void)skippedBytes;
    const uintptr_t want = (uintptr_t)hwnd;
    const uintptr_t lo = moduleBase;
    const uintptr_t hi = moduleBase + moduleSize;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    // Walk committed private/writable memory: 1C allocates its objects on the heap.
    while (addr < maxAddr && out.size() < maxHits) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;

        const uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
        const uintptr_t regionEnd = regionBase + mbi.RegionSize;

        if (mbi.State == MEM_COMMIT) { ++regionCount; commitTotal += mbi.RegionSize; }
        // ReadProcessMemory works on any committed page that is not guarded,
        // so the protection mask must not narrow the scan to PAGE_READWRITE:
        // 1C keeps parts of its heap in PAGE_EXECUTE_READWRITE and mapped
        // sections.
        const DWORD prot = mbi.Protect & ~(PAGE_NOCACHE | PAGE_WRITECOMBINE);
        const bool usable = mbi.State == MEM_COMMIT &&
                            !(mbi.Protect & PAGE_GUARD) &&
                            !(mbi.Protect & PAGE_NOACCESS) &&
                            (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                             prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                             prot == PAGE_EXECUTE_READWRITE ||
                             prot == PAGE_EXECUTE_WRITECOPY);

        if (!usable || regionEnd <= addr) {
            if (mbi.State == MEM_COMMIT) skippedBytes += mbi.RegionSize;
            addr = regionEnd > addr ? regionEnd : addr + 0x1000;
            continue;
        }

        // Copy in chunks so a page fault mid-region cannot kill the scan.
        const size_t kChunk = 0x10000;
        for (uintptr_t cur = regionBase; cur < regionEnd && out.size() < maxHits; cur += kChunk) {
            size_t want2 = (size_t)std::min<uintptr_t>(kChunk, regionEnd - cur);
            static std::vector<unsigned char> buf;
            buf.resize(want2);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)cur, buf.data(), want2, &got) ||
                got < 4) {
                // Skip only this chunk: one unreadable page must not abandon the
                // whole region, which is what hid the heap from the scan.
                continue;
            }

            totalScanned += got;
            const size_t limit = got >= 4 ? got - 4 : 0;
            for (size_t off = 0; off <= limit; off += 4) {
                const uintptr_t val = *(const uint32_t*)(buf.data() + off);
                if (val <= lo || val >= hi) continue;      // must point inside the module

                // `val` is a candidate object address; the field at +hwndOffset
                // must hold the handle we are looking for.
                const uintptr_t objField = val + hwndOffset;
                uint32_t cand = 0;
                if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)objField, &cand, 4, nullptr))
                    continue;
                if (cand != (uint32_t)want) continue;

                HwndOwner o;
                o.address = val;
                ReadProcessMemory(GetCurrentProcess(), (LPCVOID)val, &o.vtable, 4, nullptr);
                if (o.vtable >= lo && o.vtable < hi) {
                    o.vtableInModule = true;
                    o.moduleRva = (uint32_t)(o.vtable - lo);
                }
                out.push_back(o);
            }
        }
        addr = regionEnd;
    }
    if (scannedBytes) *scannedBytes = totalScanned;
    if (regions) *regions = regionCount;
    return out;
}

std::vector<HeapObject> FindHeapObjects(uintptr_t moduleBase, size_t moduleSize,
                                       size_t maxHits, size_t* scannedBytes,
                                       size_t* regions, size_t* committedBytes) {
    std::vector<HeapObject> out;
    size_t totalScanned = 0, regionCount = 0, skippedBytes = 0, commitTotal = 0;
    const uintptr_t lo = moduleBase;
    const uintptr_t hi = moduleBase + moduleSize;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    while (addr < maxAddr && out.size() < maxHits) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;

        const uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
        const uintptr_t regionEnd = regionBase + mbi.RegionSize;
        if (mbi.State == MEM_COMMIT) ++regionCount;

        // ReadProcessMemory works on any committed page that is not guarded,
        // so the protection mask must not narrow the scan to PAGE_READWRITE:
        // 1C keeps parts of its heap in PAGE_EXECUTE_READWRITE and mapped
        // sections.
        const DWORD prot = mbi.Protect & ~(PAGE_NOCACHE | PAGE_WRITECOMBINE);
        const bool usable = mbi.State == MEM_COMMIT &&
                            !(mbi.Protect & PAGE_GUARD) &&
                            !(mbi.Protect & PAGE_NOACCESS) &&
                            (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                             prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                             prot == PAGE_EXECUTE_READWRITE ||
                             prot == PAGE_EXECUTE_WRITECOPY);

        if (!usable || regionEnd <= addr) {
            if (mbi.State == MEM_COMMIT) { /* skipped */ }
            addr = regionEnd > addr ? regionEnd : addr + 0x1000;
            continue;
        }

        const size_t kChunk = 0x10000;
        for (uintptr_t cur = regionBase; cur < regionEnd && out.size() < maxHits; cur += kChunk) {
            size_t want2 = (size_t)std::min<uintptr_t>(kChunk, regionEnd - cur);
            static std::vector<unsigned char> buf;
            buf.resize(want2);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)cur, buf.data(), want2, &got) ||
                got < 4) continue;
            totalScanned += got;

            for (size_t off = 0; off + 4 <= got; off += 4) {
                const uintptr_t vt = *(const uint32_t*)(buf.data() + off);
                if (vt <= lo || vt >= hi) continue;

                // A real vtable holds pointers into the same module; demand at
                // least three of the first four entries, otherwise the "vtable"
                // is just text or numeric data that happens to look like a code
                // address.
                uint32_t slots[4] = {};
                if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)vt, slots, sizeof(slots),
                                       nullptr)) {
                    continue;
                }
                int inside = 0;
                for (uint32_t v : slots) {
                    if ((uintptr_t)v > lo && (uintptr_t)v < hi) ++inside;
                }
                if (inside < 3) continue;

                HeapObject o;
                o.address = cur + off;
                o.vtable = vt;
                o.vtableRva = (uint32_t)(vt - lo);
                out.push_back(o);
            }
        }
        addr = regionEnd;
    }
    if (scannedBytes) *scannedBytes = totalScanned;
    if (regions) *regions = regionCount + (skippedBytes ? 0 : 0);
    (void)skippedBytes;
    return out;
}

}  // namespace v8i
