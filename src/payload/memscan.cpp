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
                                        size_t* scannedBytes2, size_t* regions) {
    std::vector<HwndOwner> out;
    size_t totalScanned = 0;
    const uint32_t want = (uint32_t)(uintptr_t)hwnd;
    const uintptr_t lo = moduleBase;
    const uintptr_t hi = moduleBase + moduleSize;
    const bool anyModule = (moduleBase == 0);

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    // Mirrors FindInMemory: walk regions, read big windows, and never skip past
    // unreadable space in a way that loses committed memory.
    const size_t kChunk = 1u << 20;
    std::vector<unsigned char> buf(kChunk);
    size_t regionCount = 0;

    while (addr < maxAddr && out.size() < maxHits) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;

        const uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
        const uintptr_t regionEnd = regionBase + mbi.RegionSize;
        if (regionEnd <= addr) break;
        if (mbi.State == MEM_COMMIT) ++regionCount;

        bool usable = mbi.State == MEM_COMMIT;
        if (usable) {
            const DWORD prot = mbi.Protect & 0xFF;
            usable = prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                     prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                     prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
            if (mbi.Protect & PAGE_GUARD) usable = false;
        }
        if (!usable) {
            addr = regionEnd;
            continue;
        }

        uintptr_t cur = std::max(addr, regionBase);
        const uintptr_t stop = std::min(regionEnd, maxAddr);
        while (cur < stop && out.size() < maxHits) {
            const size_t want2 = (size_t)std::min<uintptr_t>(kChunk, stop - cur);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)cur, buf.data(), want2, &got) ||
                got < 8) {
                cur += kChunk;
                continue;
            }
            totalScanned += got;

            // Only slots that hold the handle itself can be the hwnd field.
            // From each slot, walk backwards up to `hwndOffset` bytes to find
            // the nearest slot whose VALUE is a vtable pointer — that is the
            // object start. Different 1C builds put the handle at different
            // offsets inside the object, so asking "is the vtable within N
            // bytes above this handle" works across versions without the caller
            // guessing the exact field offset.
            for (size_t off = 0; off + 4 <= got; off += 4) {
                if (*(const uint32_t*)(buf.data() + off) != want) continue;
                const uintptr_t hitAddr = cur + off;
                if (hitAddr < hwndOffset + 0x100) continue;   // object would underflow

                uintptr_t bestSlot = 0;
                uint32_t  bestVtable = 0;
                size_t    bestDist = hwndOffset + 1;
                std::wstring bestMod;
                uintptr_t bestRva = 0;

                for (size_t back = 0; back <= hwndOffset; back += 4) {
                    const uintptr_t slot = hitAddr - back;
                    uint32_t vtable = 0;
                    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)slot, &vtable, 4,
                                           nullptr))
                        continue;

                    std::wstring mod;
                    uintptr_t rva = 0;
                    if (anyModule) {
                        if (!ModuleOfAddress(vtable, &mod, &rva)) continue;
                    } else if (vtable < lo || vtable >= hi) {
                        continue;
                    } else {
                        rva = vtable - lo;
                    }
                    // The nearest valid object start wins.
                    bestSlot = slot;
                    bestVtable = vtable;
                    bestDist = back;
                    bestMod = mod;
                    bestRva = rva;
                    break;
                }
                if (!bestSlot) continue;

                HwndOwner o;
                o.address = bestSlot;
                o.vtable = bestVtable;
                o.offset = (uint32_t)bestDist;
                o.vtableInModule = true;
                o.moduleRva = (uint32_t)bestRva;
                if (anyModule) o.vtableModule = bestMod;
                out.push_back(o);
            }
            if (got < want2) break;
            cur += kChunk;
        }
        addr = regionEnd;
    }
    if (scannedBytes2) *scannedBytes2 = totalScanned;
    if (regions) *regions = regionCount;
    return out;
}

std::vector<HeapObject> FindHeapObjects(uintptr_t moduleBase, size_t moduleSize,
                                       size_t maxHits, size_t* scannedBytes,
                                       size_t* regions, size_t* committedBytes) {
    std::vector<HeapObject> out;
    size_t totalScanned = 0, regionCount = 0, commitTotal = 0;
    const uintptr_t lo = moduleBase;
    const uintptr_t hi = moduleBase + moduleSize;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    const size_t kChunk = 1u << 20;
    std::vector<unsigned char> buf(kChunk);

    while (addr < maxAddr && out.size() < maxHits) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;

        const uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
        const uintptr_t regionEnd = regionBase + mbi.RegionSize;
        if (regionEnd <= addr) break;
        if (mbi.State == MEM_COMMIT) {
            ++regionCount;
            commitTotal += mbi.RegionSize;
        }

        bool usable = mbi.State == MEM_COMMIT;
        if (usable) {
            const DWORD prot = mbi.Protect & 0xFF;
            usable = prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                     prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                     prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
            if (mbi.Protect & PAGE_GUARD) usable = false;
        }
        if (!usable) {
            addr = regionEnd;
            continue;
        }

        uintptr_t cur = std::max(addr, regionBase);
        const uintptr_t stop = std::min(regionEnd, maxAddr);
        while (cur < stop && out.size() < maxHits) {
            const size_t want = (size_t)std::min<uintptr_t>(kChunk, stop - cur);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)cur, buf.data(), want, &got) ||
                got < 16) {
                cur += kChunk;
                continue;
            }
            totalScanned += got;

            for (size_t off = 0; off + 4 <= got; off += 4) {
                const uintptr_t vt = *(const uint32_t*)(buf.data() + off);
                if (vt <= lo || vt >= hi) continue;

                // A real vtable holds pointers into the same module; demand at
                // least three of the first four entries.
                uint32_t slots[4] = {};
                if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)vt, slots, sizeof(slots),
                                       nullptr)) continue;
                int inside = 0;
                for (uint32_t v : slots) if ((uintptr_t)v > lo && (uintptr_t)v < hi) ++inside;
                if (inside < 3) continue;

                HeapObject o;
                o.address = cur + off;
                o.vtable = vt;
                o.vtableRva = (uint32_t)(vt - lo);
                out.push_back(o);
            }
            if (got < want) break;
            cur += kChunk;
        }
        addr = regionEnd;
    }
    if (scannedBytes) *scannedBytes = totalScanned;
    if (regions) *regions = regionCount;
    if (committedBytes) *committedBytes = commitTotal;
    return out;
}

std::vector<DwordHit> FindDword(uint32_t value, size_t maxHits, size_t* scannedBytes) {
    std::vector<DwordHit> hits;
    size_t totalScanned = 0;

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    const size_t kChunk = 1u << 20;
    std::vector<unsigned char> buf(kChunk);

    while (addr < maxAddr && hits.size() < maxHits) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) break;

        const uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
        const uintptr_t regionEnd = regionBase + mbi.RegionSize;
        if (regionEnd <= addr) break;

        bool usable = mbi.State == MEM_COMMIT;
        if (usable) {
            const DWORD prot = mbi.Protect & 0xFF;
            usable = prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                     prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                     prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
            if (mbi.Protect & PAGE_GUARD) usable = false;
        }
        if (!usable) {
            addr = regionEnd;
            continue;
        }

        uintptr_t cur = std::max(addr, regionBase);
        const uintptr_t stop = std::min(regionEnd, maxAddr);
        while (cur < stop && hits.size() < maxHits) {
            const size_t want = (size_t)std::min<uintptr_t>(kChunk, stop - cur);
            SIZE_T got = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)cur, buf.data(), want, &got) ||
                got < 4) {
                cur += kChunk;
                continue;
            }
            totalScanned += got;

            for (size_t off = 0; off + 4 <= got; off += 4) {
                if (*(const uint32_t*)(buf.data() + off) != value) continue;
                DwordHit hh;
                hh.address = cur + off;
                hits.push_back(hh);
                if (hits.size() >= maxHits) break;
            }
            if (got < want) break;
            cur += kChunk;
        }
        addr = regionEnd;
    }
    if (scannedBytes) *scannedBytes = totalScanned;
    return hits;
}

}  // namespace v8i
