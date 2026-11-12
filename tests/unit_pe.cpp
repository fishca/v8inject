// PE parsing: the parser reads the headers of an image that is already
// mapped, and every access to it must be bounded - an unbounded read there
// killed the host process before the parser was made defensive.

#include "test_runner.h"

#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"

using namespace v8i;

namespace {

uintptr_t SelfBase() {
    return (uintptr_t)GetModuleHandleW(nullptr);
}

}  // namespace

V8I_TEST(Pe_ParsesItsOwnImage) {
    const uintptr_t base = SelfBase();
    REQUIRE(base != 0);

    const PeImage img = ParsePe(base);
    CHECK(img.valid);
    CHECK(img.error.empty());
    CHECK(img.base == base);
    CHECK(img.sizeOfImage > 0);
    CHECK(img.entryPointRva != 0);
    CHECK(img.entryPointRva < img.sizeOfImage);
    CHECK(!img.sections.empty());

    const std::string machine = img.MachineName();
    CHECK(machine == "x86" || machine == "x64" || machine == "arm64");
}

V8I_TEST(Pe_SectionsLookSane) {
    const PeImage img = ParsePe(SelfBase());
    REQUIRE(img.valid);
    REQUIRE(!img.sections.empty());

    for (const PeSection& s : img.sections) {
        CHECK(!s.name.empty());
        CHECK(s.va != 0);
        CHECK(s.virtualSize > 0 || s.rawSize > 0);
    }

    // The entry point lies in an executable section.
    const PeSection* entry = img.SectionOf(img.entryPointRva);
    CHECK(entry != nullptr);
    if (entry) CHECK(entry->Executable());

    // An RVA outside the image belongs to no section.
    CHECK(img.SectionOf(img.sizeOfImage + 0x1000) == nullptr);
    CHECK(img.SectionOf(0xFFFFFFFFu) == nullptr);
}

V8I_TEST(Pe_ImportsOfTheTestBinary) {
    const PeImage img = ParsePe(SelfBase());
    REQUIRE(img.valid);
    CHECK(!img.imports.empty());

    bool sawKernel32 = false;
    for (const PeImport& i : img.imports) {
        CHECK(!i.dll.empty());
        if (i.dll == "KERNEL32.dll") sawKernel32 = true;
    }
    CHECK(sawKernel32);
}

V8I_TEST(Pe_PrefersTheImageBaseOfItsOwnBitness) {
    const PeImage img = ParsePe(SelfBase());
    REQUIRE(img.valid);

    // The preferred base is a 64-bit value in a PE32+ image: reading it with
    // the 32-bit structure gave 0 (or the high half of the address).
    CHECK(img.imageBaseRva != 0);
#if defined(_M_X64) || defined(_M_ARM64)
    CHECK(img.imageBaseRva > 0xFFFFFFFFull);   // 0x140000000 for x64
#endif
}

V8I_TEST(Pe_RejectsGarbageWithoutCrashing) {
    const PeImage nullBase = ParsePe(0);
    CHECK(!nullBase.valid);
    CHECK(!nullBase.error.empty());

    // A page that is not mapped: the parser must report an error, not fault.
    const PeImage unmapped = ParsePe(0x10000);
    CHECK(!unmapped.valid);
    CHECK(!unmapped.error.empty());

    // A mapped page that is not a PE image at all.
    std::vector<BYTE> junk(4096, 0x41);
    const PeImage notPe = ParsePe((uintptr_t)junk.data());
    CHECK(!notPe.valid);
    CHECK(!notPe.error.empty());
}

V8I_TEST(Pe_ReadAsciiStringIsBounded) {
    const PeImage img = ParsePe(SelfBase());
    REQUIRE(img.valid);

    // An RVA past the end of the image yields nothing (and no crash).
    CHECK(ReadAsciiString(img, img.sizeOfImage + 16).empty());
    CHECK(ReadAsciiString(img, 0xFFFFFFFFu).empty());

    // The import names were read through the same bounded helper: they are
    // ASCII and non-empty.
    for (const PeImport& i : img.imports) {
        if (i.ordinal && i.name.empty()) continue;   // imported by ordinal
        CHECK(!i.name.empty());
        break;
    }
}
