#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"

#include <cstring>

namespace v8i {

namespace {

// Reads a NUL-terminated ASCII string out of a mapped image, bounded by the
// image size and by `maxLen`. Every access is guarded: import and export tables
// can point anywhere, and an unguarded read there kills the host process.
std::string SafeAscii(uintptr_t base, uint32_t sizeOfImage, uint32_t rva, size_t maxLen) {
    std::string out;
    if (!base || rva >= sizeOfImage) return out;
    uint32_t limit = (uint32_t)((sizeOfImage - rva) < maxLen ? (sizeOfImage - rva) : maxLen);
    if (!IsReadable((const void*)(base + rva), 1)) return out;

    const char* p = (const char*)(base + rva);
    for (size_t i = 0; i < limit; ++i) {
        // Cheap page-crossing guard: only probe when moving into a new byte that
        // may be past the readable run.
        if ((i & 0xFF) == 0 && !IsReadable(p + i, 1)) break;
        char c = p[i];
        if (!c) break;
        out.push_back(c);
    }
    return out;
}

uint16_t SafeU16(uintptr_t base, uint32_t sizeOfImage, uint32_t rva) {
    if (rva + 2 > sizeOfImage) return 0;
    if (!IsReadable((const void*)(base + rva), 2)) return 0;
    return *(const uint16_t*)(base + rva);
}

uint32_t SafeU32(uintptr_t base, uint32_t sizeOfImage, uint32_t rva) {
    if (rva + 4 > sizeOfImage) return 0;
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
    auto* nt = (const IMAGE_NT_HEADERS32*)ntAddr;
    if (nt->Signature != IMAGE_NT_SIGNATURE) { img.error = "no PE signature"; return img; }

    img.machine         = nt->FileHeader.Machine;
    img.characteristics = nt->FileHeader.Characteristics;
    img.sizeOfImage     = nt->OptionalHeader.SizeOfImage;
    img.entryPointRva   = nt->OptionalHeader.AddressOfEntryPoint;
    img.imageBaseRva    = (uint32_t)nt->OptionalHeader.ImageBase;
    img.valid           = true;

    const uint32_t sizeOfImage = img.sizeOfImage;

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!IsReadable(sec + i, sizeof(IMAGE_SECTION_HEADER))) break;
        PeSection s;
        s.name             = SectionName(sec[i]);
        s.va               = sec[i].VirtualAddress;
        s.virtualSize      = sec[i].Misc.VirtualSize;
        s.rawSize          = sec[i].SizeOfRawData;
        s.rawPtr           = sec[i].PointerToRawData;
        s.characteristics  = sec[i].Characteristics;
        img.sections.push_back(s);
    }

    // ---- exports ----
    const IMAGE_DATA_DIRECTORY& dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress && dir.Size && dir.VirtualAddress < sizeOfImage) {
        const uint32_t expRva = dir.VirtualAddress;
        if (IsReadable((const void*)(base + expRva), sizeof(IMAGE_EXPORT_DIRECTORY))) {
            auto* exp = (const IMAGE_EXPORT_DIRECTORY*)(base + expRva);

            const uint32_t namesRva = exp->AddressOfNames;
            const uint32_t funcsRva = exp->AddressOfFunctions;
            const uint32_t ordsRva  = exp->AddressOfNameOrdinals;

            for (DWORD i = 0; i < exp->NumberOfNames && i < 8192; ++i) {
                uint32_t namePtrRva = SafeU32(base, sizeOfImage, namesRva + i * 4);
                if (!namePtrRva) continue;

                PeExport e;
                e.name = SafeAscii(base, sizeOfImage, namePtrRva, 512);
                if (e.name.empty()) continue;

                uint16_t idx = SafeU16(base, sizeOfImage, ordsRva + (uint32_t)i * 2);
                e.rva = SafeU32(base, sizeOfImage, funcsRva + (uint32_t)idx * 4);
                e.ordinal = (uint32_t)(exp->Base + idx);
                // An export pointing inside the export directory is a forwarder.
                if (e.rva >= expRva && e.rva < expRva + dir.Size) {
                    e.forwarded = true;
                    e.forwarder = SafeAscii(base, sizeOfImage, e.rva, 256);
                }
                img.exports.push_back(std::move(e));
            }
        }
    }

    // ---- imports ----
    // Every access is bounded by SizeOfImage and by the directory size declared
    // in the header. Walking this table unguarded previously crashed 1C.
    const IMAGE_DATA_DIRECTORY& imp =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp.VirtualAddress && imp.Size && imp.VirtualAddress < sizeOfImage) {
        const uint32_t dirEnd = imp.VirtualAddress + imp.Size;
        for (int d = 0; d < 1024; ++d) {
            uint32_t descRva = imp.VirtualAddress + (uint32_t)(d * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            if (descRva + sizeof(IMAGE_IMPORT_DESCRIPTOR) > sizeOfImage) break;
            if (descRva + sizeof(IMAGE_IMPORT_DESCRIPTOR) > dirEnd) break;
            if (!IsReadable((const void*)(base + descRva), sizeof(IMAGE_IMPORT_DESCRIPTOR))) break;

            auto* desc = (const IMAGE_IMPORT_DESCRIPTOR*)(base + descRva);
            if (!desc->Name && !desc->FirstThunk) break;   // terminator

            std::string dllName = SafeAscii(base, sizeOfImage, desc->Name, 256);
            if (dllName.empty()) continue;

            uint32_t thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                        : desc->FirstThunk;
            if (thunkRva >= sizeOfImage || desc->FirstThunk >= sizeOfImage) continue;

            const size_t thunkSize = sizeof(IMAGE_THUNK_DATA32);
            for (int i = 0; i < 8192; ++i) {
                uint32_t curThunkRva = thunkRva + (uint32_t)(i * thunkSize);
                if (curThunkRva + thunkSize > sizeOfImage) break;
                if (!IsReadable((const void*)(base + curThunkRva), thunkSize)) break;

                uint32_t value = *(const uint32_t*)(base + curThunkRva);
                if (!value) break;

                PeImport pi;
                pi.dll = dllName;
                pi.iatRva = desc->FirstThunk + (uint32_t)(i * thunkSize);

                if (value & 0x80000000u) {
                    pi.ordinal = (uint16_t)(value & 0xFFFF);
                } else {
                    if (value + 2 >= sizeOfImage) continue;
                    pi.ordinal = SafeU16(base, sizeOfImage, value);
                    pi.name = SafeAscii(base, sizeOfImage, value + 2, 256);
                }
                img.imports.push_back(std::move(pi));
            }
        }
    }

    return img;
}

std::string ReadAsciiString(const PeImage& img, uint32_t rva, size_t maxLen) {
    return SafeAscii(img.base, img.sizeOfImage ? img.sizeOfImage : 0x7FFFFFFFu, rva, maxLen);
}

}  // namespace v8i
