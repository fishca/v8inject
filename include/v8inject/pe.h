#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace v8i {

struct PeSection {
    std::string  name;
    uint32_t     va = 0;
    uint32_t     virtualSize = 0;
    uint32_t     rawSize = 0;
    uint32_t     rawPtr = 0;
    uint32_t     characteristics = 0;

    bool Executable() const { return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0; }
    bool Readable()   const { return (characteristics & IMAGE_SCN_MEM_READ) != 0; }
    bool Writable()   const { return (characteristics & IMAGE_SCN_MEM_WRITE) != 0; }
};

struct PeExport {
    std::string name;
    uint32_t    rva = 0;
    uint32_t    ordinal = 0;
    bool        forwarded = false;
    std::string forwarder;
};

// Describes a PE image that is already mapped in the current process.
struct PeImage {
    uintptr_t base = 0;
    uint32_t  sizeOfImage = 0;
    uint32_t  entryPointRva = 0;
    uint32_t  imageBaseRva = 0;   // PreferredImageBase (as recorded in headers)
    uint16_t  machine = 0;
    uint16_t  characteristics = 0;
    bool      valid = false;
    std::string error;

    std::vector<PeSection> sections;
    std::vector<PeExport>  exports;

    const PeSection* SectionOf(uint32_t rva) const;
    std::string MachineName() const;
};

// Parses the headers of an image mapped at `base` (usually a module base).
PeImage ParsePe(uintptr_t base);

// Reads a NUL-terminated ASCII string from a mapped image, bounded by `maxLen`.
std::string ReadAsciiString(const PeImage& img, uint32_t rva, size_t maxLen = 256);

}  // namespace v8i
