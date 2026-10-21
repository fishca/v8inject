#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"

#include <cstring>

namespace v8i {

namespace {

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

    auto* nt = (const IMAGE_NT_HEADERS*)(base + (uint32_t)dos->e_lfanew);
    if (!IsReadable(nt, sizeof(IMAGE_NT_HEADERS))) {
        img.error = "NT headers not readable";
        return img;
    }
    if (nt->Signature != IMAGE_NT_SIGNATURE) { img.error = "no PE signature"; return img; }

    img.machine         = nt->FileHeader.Machine;
    img.characteristics = nt->FileHeader.Characteristics;
    img.sizeOfImage     = nt->OptionalHeader.SizeOfImage;
    img.entryPointRva   = nt->OptionalHeader.AddressOfEntryPoint;
    img.imageBaseRva    = (uint32_t)nt->OptionalHeader.ImageBase;
    img.valid           = true;

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

    // Export directory
    const IMAGE_DATA_DIRECTORY& dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress && dir.Size) {
        auto* exp = (const IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
        if (IsReadable(exp, sizeof(IMAGE_EXPORT_DIRECTORY))) {
            auto* names = (const DWORD*)(base + exp->AddressOfNames);
            auto* funcs = (const DWORD*)(base + exp->AddressOfFunctions);
            auto* ords  = (const WORD*)(base + exp->AddressOfNameOrdinals);

            const DWORD count = exp->NumberOfNames;
            for (DWORD i = 0; i < count && i < 8192; ++i) {
                if (!IsReadable(names + i, sizeof(DWORD))) break;
                PeExport e;
                e.name = ReadAsciiString(img, names[i], 512);
                if (e.name.empty()) continue;
                if (!IsReadable(ords + i, sizeof(WORD))) break;
                WORD idx = ords[i];
                if (!IsReadable(funcs + idx, sizeof(DWORD))) continue;
                e.rva = funcs[idx];
                e.ordinal = exp->Base + idx;
                // An export pointing inside the export directory is a forwarder.
                if (e.rva >= dir.VirtualAddress && e.rva < dir.VirtualAddress + dir.Size) {
                    e.forwarded = true;
                    e.forwarder = ReadAsciiString(img, e.rva, 256);
                }
                img.exports.push_back(std::move(e));
            }
        }
    }
    return img;
}

std::string ReadAsciiString(const PeImage& img, uint32_t rva, size_t maxLen) {
    std::string out;
    if (!img.base) return out;
    const char* p = (const char*)(img.base + rva);
    for (size_t i = 0; i < maxLen; ++i) {
        if (!IsReadable(p + i, 1)) break;
        char c = p[i];
        if (!c) break;
        out.push_back(c);
    }
    return out;
}

}  // namespace v8i
