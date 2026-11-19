#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"

#include <cstring>

namespace v8i {

namespace {

// True when rva + delta neither wraps around 2^32 nor leaves the image.
// `rva + 2`/`rva + 4` used to overflow for an RVA near 4 GiB: the wrapped
// small value passed the bound check and the read went to an unrelated
// address. Always compare by subtraction.
bool RvaFits(uint32_t rva, uint32_t delta, uint32_t sizeOfImage) {
    return rva <= sizeOfImage && sizeOfImage - rva >= delta;
}

// How many bytes from `p` (at most `cap`) belong to one committed region of
// readable memory. The region edge comes from VirtualQuery: probing only the
// start of the string is not enough, because the readable run can end in the
// middle of the image (the image is not one big readable region).
size_t ReadableRun(const void* p, size_t cap) {
    if (!p || !cap) return 0;
    if (!IsReadable(p, 1)) return 0;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return 0;
    const uintptr_t start = (uintptr_t)p;
    const uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
    if (start < regionBase || start - regionBase >= mbi.RegionSize) return 0;
    const size_t avail = mbi.RegionSize - (start - regionBase);
    return avail < cap ? avail : cap;
}

// Reads a NUL-terminated ASCII string out of a mapped image, bounded by the
// image size, by `maxLen` and by the readable region the string starts in.
// Every access is guarded: import and export tables can point anywhere, and an
// unguarded read there kills the host process.
std::string SafeAscii(uintptr_t base, uint32_t sizeOfImage, uint32_t rva, size_t maxLen) {
    std::string out;
    if (!base || rva >= sizeOfImage) return out;
    const uint32_t remaining = sizeOfImage - rva;
    const size_t limit = remaining < maxLen ? remaining : maxLen;

    const char* p = (const char*)(base + rva);
    size_t done = 0;
    while (done < limit) {
        const size_t chunk = ReadableRun(p + done, limit - done);
        if (!chunk) break;
        for (size_t i = 0; i < chunk; ++i) {
            const char c = p[done + i];
            if (!c) return out;
            out.push_back(c);
        }
        done += chunk;
    }
    return out;
}

uint16_t SafeU16(uintptr_t base, uint32_t sizeOfImage, uint32_t rva) {
    if (!RvaFits(rva, 2, sizeOfImage)) return 0;
    if (!IsReadable((const void*)(base + rva), 2)) return 0;
    return *(const uint16_t*)(base + rva);
}

uint32_t SafeU32(uintptr_t base, uint32_t sizeOfImage, uint32_t rva) {
    if (!RvaFits(rva, 4, sizeOfImage)) return 0;
    if (!IsReadable((const void*)(base + rva), 4)) return 0;
    return *(const uint32_t*)(base + rva);
}

const char* SectionName(const IMAGE_SECTION_HEADER& s) {
    static thread_local char buf[9];
    memcpy(buf, s.Name, 8);
    buf[8] = 0;
    return buf;
}

}  // namespace

const PeSection* PeImage::SectionOf(uint32_t rva) const {
    for (const PeSection& s : sections) {
        uint32_t span = s.virtualSize ? s.virtualSize : s.rawSize;
        if (rva >= s.va && rva < s.va + span) return &s;
    }
    return nullptr;
}

std::string PeImage::MachineName() const {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386:  return "x86";
    case IMAGE_FILE_MACHINE_AMD64: return "x64";
    case IMAGE_FILE_MACHINE_ARM64: return "arm64";
    default: {
        char b[32];
        _snprintf_s(b, sizeof(b), _TRUNCATE, "0x%04X", machine);
        return b;
    }
    }
}

PeImage ParsePe(uintptr_t base) {
    PeImage img;
    img.base = base;
    if (!base) { img.error = "null base"; return img; }
    if (!IsReadable((const void*)base, sizeof(IMAGE_DOS_HEADER))) {
        img.error = "header not readable";
        return img;
    }

    auto* dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { img.error = "no MZ signature"; return img; }

    if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000) {
        img.error = "implausible e_lfanew";
        return img;
    }

    // The NT headers are parsed with the 32-bit layout on purpose: the fields
    // read below (Machine, NumberOfSections, SizeOfImage, AddressOfEntryPoint,
    // DataDirectory[]) have identical offsets in PE32 and PE32+. The image can
    // only ever be the same bitness as this process, so a host that needed the
    // PE32+ layout would be a different build.
    uintptr_t ntAddr = base + (uint32_t)dos->e_lfanew;
    if (!IsReadable((const void*)ntAddr, sizeof(IMAGE_NT_HEADERS32))) {
        img.error = "NT headers not readable";
        return img;
    }

    // PE32 and PE32+ have different optional-header layouts, and the data
    // directories sit at different offsets (96 in PE32, 112 in PE32+). Reading
    // a 64-bit image with the 32-bit structure therefore looks for the import
    // and export tables in the wrong place and finds nothing at all.
    auto* nt32 = (const IMAGE_NT_HEADERS32*)ntAddr;
    const bool pe32plus = nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    const IMAGE_DATA_DIRECTORY* dirs = nullptr;
    DWORD numDirs = 0;
    const IMAGE_SECTION_HEADER* sections = nullptr;

    if (pe32plus) {
        auto* nt64 = (const IMAGE_NT_HEADERS64*)ntAddr;
        if (nt64->Signature != IMAGE_NT_SIGNATURE) { img.error = "no PE signature"; return img; }
        img.sizeOfImage   = nt64->OptionalHeader.SizeOfImage;
        img.entryPointRva = nt64->OptionalHeader.AddressOfEntryPoint;
        img.imageBaseRva  = nt64->OptionalHeader.ImageBase;
        numDirs           = nt64->OptionalHeader.NumberOfRvaAndSizes;
        dirs              = nt64->OptionalHeader.DataDirectory;
        sections          = IMAGE_FIRST_SECTION(nt64);
    } else {
        if (nt32->Signature != IMAGE_NT_SIGNATURE) { img.error = "no PE signature"; return img; }
        img.sizeOfImage   = nt32->OptionalHeader.SizeOfImage;
        img.entryPointRva = nt32->OptionalHeader.AddressOfEntryPoint;
        img.imageBaseRva  = nt32->OptionalHeader.ImageBase;
        numDirs           = nt32->OptionalHeader.NumberOfRvaAndSizes;
        dirs              = nt32->OptionalHeader.DataDirectory;
        sections          = IMAGE_FIRST_SECTION(nt32);
    }

    img.machine         = nt32->FileHeader.Machine;
    img.characteristics = nt32->FileHeader.Characteristics;
    img.valid           = true;

    const uint32_t sizeOfImage = img.sizeOfImage;

    for (WORD i = 0; i < nt32->FileHeader.NumberOfSections; ++i) {
        if (!IsReadable(sections + i, sizeof(IMAGE_SECTION_HEADER))) break;
        PeSection s;
        s.name             = SectionName(sections[i]);
        s.va               = sections[i].VirtualAddress;
        s.virtualSize      = sections[i].Misc.VirtualSize;
        s.rawSize          = sections[i].SizeOfRawData;
        s.rawPtr           = sections[i].PointerToRawData;
        s.characteristics  = sections[i].Characteristics;
        img.sections.push_back(s);
    }

    // ---- exports ----
    if (numDirs > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        const IMAGE_DATA_DIRECTORY& dir = dirs[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress && dir.Size && dir.VirtualAddress < sizeOfImage) {
            const uint32_t expRva = dir.VirtualAddress;
            if (IsReadable((const void*)(base + expRva), sizeof(IMAGE_EXPORT_DIRECTORY))) {
                auto* exp = (const IMAGE_EXPORT_DIRECTORY*)(base + expRva);

                const uint32_t namesRva = exp->AddressOfNames;
                const uint32_t funcsRva = exp->AddressOfFunctions;
                const uint32_t ordsRva  = exp->AddressOfNameOrdinals;

                for (DWORD i = 0; i < exp->NumberOfNames && i < 8192; ++i) {
                    // The table offsets are added to hostile RVAs: a plain
                    // `namesRva + i * 4` wraps near 4 GiB and reads a random
                    // in-image address, so every sum is checked first.
                    const uint32_t namesDelta = (uint32_t)i * 4u;
                    if (!RvaFits(namesRva, namesDelta, sizeOfImage)) break;
                    uint32_t namePtrRva = SafeU32(base, sizeOfImage, namesRva + namesDelta);
                    if (!namePtrRva) continue;

                    PeExport e;
                    e.name = SafeAscii(base, sizeOfImage, namePtrRva, 512);
                    if (e.name.empty()) continue;

                    const uint32_t ordsDelta = (uint32_t)i * 2u;
                    if (!RvaFits(ordsRva, ordsDelta, sizeOfImage)) break;
                    uint16_t idx = SafeU16(base, sizeOfImage, ordsRva + ordsDelta);

                    const uint32_t funcsDelta = (uint32_t)idx * 4u;
                    if (!RvaFits(funcsRva, funcsDelta, sizeOfImage)) continue;
                    e.rva = SafeU32(base, sizeOfImage, funcsRva + funcsDelta);
                    e.ordinal = (uint32_t)(exp->Base + idx);
                    // An export pointing inside the export directory is a forwarder.
                    if (e.rva >= expRva && e.rva - expRva < dir.Size) {
                        e.forwarded = true;
                        e.forwarder = SafeAscii(base, sizeOfImage, e.rva, 256);
                    }
                    img.exports.push_back(std::move(e));
                }
            }
        }
    }

    // ---- imports ----
    // Every access is bounded by SizeOfImage and by the directory size declared
    // in the header. Walking this table unguarded previously crashed 1C.
    if (numDirs > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        const IMAGE_DATA_DIRECTORY& imp = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imp.VirtualAddress && imp.Size && imp.VirtualAddress < sizeOfImage) {
            const uint32_t descSize = (uint32_t)sizeof(IMAGE_IMPORT_DESCRIPTOR);
            // imp.Size is added to an RVA from the header: clamp instead of
            // letting the 32-bit sum wrap around to a small `dirEnd`.
            const uint32_t dirEnd = imp.Size > sizeOfImage - imp.VirtualAddress
                                        ? sizeOfImage
                                        : imp.VirtualAddress + imp.Size;
            for (int d = 0; d < 1024; ++d) {
                const uint32_t descDelta = (uint32_t)d * descSize;
                if (!RvaFits(imp.VirtualAddress, descDelta, sizeOfImage)) break;
                const uint32_t descRva = imp.VirtualAddress + descDelta;
                if (!RvaFits(descRva, descSize, sizeOfImage)) break;
                if (descRva + descSize > dirEnd) break;
                if (!IsReadable((const void*)(base + descRva), descSize)) break;

                auto* desc = (const IMAGE_IMPORT_DESCRIPTOR*)(base + descRva);
                if (!desc->Name && !desc->FirstThunk) break;   // terminator

                std::string dllName = SafeAscii(base, sizeOfImage, desc->Name, 256);
                if (dllName.empty()) continue;

                uint32_t thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                            : desc->FirstThunk;
                if (thunkRva >= sizeOfImage || desc->FirstThunk >= sizeOfImage) continue;

                // Thunk size follows the image, not the build: on x64 the
                // thunks are 8 bytes (IMAGE_THUNK_DATA64), and reading them as
                // 4-byte entries produced one bogus entry per DLL. Found when
                // the import order of a test binary changed under it.
                constexpr size_t thunkSize = sizeof(void*) == 8 ? sizeof(IMAGE_THUNK_DATA64)
                                                                : sizeof(IMAGE_THUNK_DATA32);
                for (int i = 0; i < 8192; ++i) {
                    const uint32_t thunkDelta = (uint32_t)(i * thunkSize);
                    if (!RvaFits(thunkRva, thunkDelta, sizeOfImage)) break;
                    const uint32_t curThunkRva = thunkRva + thunkDelta;
                    if (!RvaFits(curThunkRva, (uint32_t)thunkSize, sizeOfImage)) break;
                    if (!IsReadable((const void*)(base + curThunkRva), thunkSize)) break;

                    uint64_t value = 0;
                    if constexpr (sizeof(void*) == 8) {
                        value = *(const uint64_t*)(base + curThunkRva);
                    } else {
                        value = *(const uint32_t*)(base + curThunkRva);
                    }
                    if (!value) break;

                    if (!RvaFits(desc->FirstThunk, thunkDelta, sizeOfImage)) break;

                    PeImport pi;
                    pi.dll = dllName;
                    pi.iatRva = desc->FirstThunk + thunkDelta;

                    bool byOrdinal = false;
                    if constexpr (sizeof(void*) == 8) {
                        byOrdinal = (value & 0x8000000000000000ULL) != 0;
                    } else {
                        byOrdinal = (value & 0x80000000u) != 0;
                    }
                    if (byOrdinal) {
                        pi.ordinal = (uint16_t)(value & 0xFFFF);
                    } else {
                        const uint32_t nameRva = (uint32_t)value;
                        // The name starts two bytes past the hint. Check by
                        // subtraction: `nameRva + 2` wraps for a hint near
                        // 4 GiB and then reads an unrelated in-image byte.
                        if (nameRva >= sizeOfImage || sizeOfImage - nameRva <= 2)
                            continue;
                        pi.ordinal = SafeU16(base, sizeOfImage, nameRva);
                        pi.name = SafeAscii(base, sizeOfImage, nameRva + 2, 256);
                    }
                    img.imports.push_back(std::move(pi));
                }
            }
        }
    }

    return img;
}

std::string ReadAsciiString(const PeImage& img, uint32_t rva, size_t maxLen) {
    return SafeAscii(img.base, img.sizeOfImage ? img.sizeOfImage : 0x7FFFFFFFu, rva, maxLen);
}

}  // namespace v8i
