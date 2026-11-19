// PE parsing: the parser reads the headers of an image that is already
// mapped, and every access to it must be bounded - an unbounded read there
// killed the host process before the parser was made defensive.

#include "test_runner.h"

#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"

#include <cstring>

using namespace v8i;

namespace {

uintptr_t SelfBase() {
    return (uintptr_t)GetModuleHandleW(nullptr);
}

#if defined(_WIN64)
// Lays out a minimal PE32+ image at `image`, which must have 0x4000 readable
// bytes. The image declares SizeOfImage = 0xFFFFFFFF and one export named
// "EvilName" at RVA 0x1000; `namesRva`/`ordsRva`/`funcsRva` are copied into
// the export directory so a test can push the tables to the top of the 32-bit
// RVA range. The 64-bit build only: the test that maps the wrapped address
// needs a 4 GiB reservation, which a 32-bit address space cannot provide.
void BuildImageWithTopRvas(BYTE* image, uint32_t namesRva, uint32_t ordsRva,
                           uint32_t funcsRva) {
    memset(image, 0, 0x4000);

    auto* dos = (IMAGE_DOS_HEADER*)image;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    auto* nt = (IMAGE_NT_HEADERS64*)(image + 0x80);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = (WORD)sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.ImageBase = (ULONGLONG)(uintptr_t)image;
    nt->OptionalHeader.SizeOfImage = 0xFFFFFFFFu;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = 0x3000;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = 0x100;

    auto* section = IMAGE_FIRST_SECTION(nt);
    memcpy(section->Name, ".rdata", 6);
    section->VirtualAddress = 0x1000;
    section->Misc.VirtualSize = 0x3000;
    section->SizeOfRawData = 0x3000;

    memcpy(image + 0x1000, "EvilName", 9);   // includes the terminator
    *(uint16_t*)(image + 0x2000) = 0;        // name ordinal
    *(uint32_t*)(image + 0x2004) = 0x1010;   // function RVA
    *(uint32_t*)(image + 0x2008) = 0x1000;   // name RVA

    auto* exp = (IMAGE_EXPORT_DIRECTORY*)(image + 0x3000);
    exp->NumberOfNames = 1;
    exp->Base = 0;
    exp->AddressOfFunctions = funcsRva;
    exp->AddressOfNames = namesRva;
    exp->AddressOfNameOrdinals = ordsRva;
}
#endif

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

V8I_TEST(Pe_ReadAsciiStopsAtTheReadableRegionEdge) {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const size_t page = si.dwPageSize;
    REQUIRE(page >= 0x1000u);

    // Two pages: the second one is made inaccessible, so every read past the
    // first page faults. The old guard probed only every 256th byte and would
    // read into the poisoned page.
    BYTE* mem = (BYTE*)VirtualAlloc(nullptr, page * 2, MEM_RESERVE | MEM_COMMIT,
                                    PAGE_READWRITE);
    REQUIRE(mem != nullptr);
    DWORD oldProtect = 0;
    REQUIRE(VirtualProtect(mem + page, page, PAGE_NOACCESS, &oldProtect) != 0);

    // "ABCDE" starts five bytes before the end of the readable page and has
    // no terminator there.
    const char tail[] = "ABCDE";
    const size_t tailLen = sizeof(tail) - 1;
    memcpy(mem + page - tailLen, tail, tailLen);

    PeImage img;
    img.base = (uintptr_t)mem;
    img.sizeOfImage = (uint32_t)(page * 2);
    const std::string name =
        ReadAsciiString(img, (uint32_t)(page - tailLen), page);
    CHECK_EQ(name, std::string(tail));

    // The deliberately poisoned page is restored before the allocation is
    // released, so cleanup is not affected by the test fixture.
    DWORD restored = 0;
    VirtualProtect(mem + page, page, PAGE_READWRITE, &restored);
    VirtualFree(mem, 0, MEM_RELEASE);
}

V8I_TEST(Pe_ReadAsciiRefusesRvasNearTheTop) {
    BYTE* mem = (BYTE*)VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT,
                                    PAGE_READWRITE);
    REQUIRE(mem != nullptr);
    memcpy(mem, "name", 5);

    PeImage img;
    img.base = (uintptr_t)mem;
    img.sizeOfImage = 0x1000u;
    // Every one of these RVAs is at or beyond SizeOfImage: the bound check
    // must refuse before any base + rva arithmetic can be formed, and it must
    // not wrap a 32-bit sum. The wrap itself is covered by the synthetic image
    // test below.
    CHECK(ReadAsciiString(img, 0xFFFFFFFFu).empty());
    CHECK(ReadAsciiString(img, 0xFFFFFFFEu).empty());
    CHECK(ReadAsciiString(img, 0xFFFFFFFCu).empty());
    CHECK(ReadAsciiString(img, 0x1000u).empty());   // rva == SizeOfImage
    CHECK(ReadAsciiString(img, 0x1001u).empty());   // rva > SizeOfImage

    VirtualFree(mem, 0, MEM_RELEASE);
}

#if defined(_WIN64)
// A86 regression: the export-table RVAs are taken from the image header,
// and rva + 4 / rva + 2 used to wrap at 4 GiB, passing the bound check and
// reading whatever is mapped 4 GiB above the image. Without this protection a
// crafted module made the parser read a bogus export (or a bogus ordinal) at
// an address it never validated.
V8I_TEST(Pe_TopRvasAreRefusedWithoutWrapping) {
    constexpr size_t kArenaSize = static_cast<size_t>(1) << 32;   // 4 GiB
    BYTE* arena = (BYTE*)VirtualAlloc(nullptr, kArenaSize, MEM_RESERVE, PAGE_NOACCESS);
    REQUIRE(arena != nullptr);

    BYTE* image = (BYTE*)VirtualAlloc(arena, 0x4000, MEM_COMMIT, PAGE_READWRITE);
    REQUIRE(image == arena);

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const size_t page = si.dwPageSize;
    REQUIRE(page >= 0x1000u);
    BYTE* tail = (BYTE*)VirtualAlloc(arena + kArenaSize - page, page, MEM_COMMIT,
                                     PAGE_READWRITE);
    REQUIRE(tail != nullptr);

    // AddressOfNames = 0xFFFFFFFC. `rva + 4` wraps to zero, so the old check
    // let SafeU32 read base + 0xFFFFFFFC, which is committed here and holds a
    // valid name RVA: the old parser invented an export.
    *(uint32_t*)(arena + 0xFFFFFFFCu) = 0x1000;
    BuildImageWithTopRvas(arena, 0xFFFFFFFCu, 0x2000, 0x2004);
    PeImage img = ParsePe((uintptr_t)arena);
    CHECK(img.valid);
    CHECK(img.exports.empty());

    // AddressOfNameOrdinals = 0xFFFFFFFE. `rva + 2` wraps; the old read
    // returned the marker 7 from the top page and used it as a name ordinal.
    // The guarded helper returns 0, i.e. the first name in the table.
    *(uint16_t*)(arena + 0xFFFFFFFEu) = 7;
    BuildImageWithTopRvas(arena, 0x2008, 0xFFFFFFFEu, 0x2004);
    img = ParsePe((uintptr_t)arena);
    CHECK(img.valid);
    REQUIRE(img.exports.size() == 1);
    CHECK_EQ(img.exports[0].name, std::string("EvilName"));
    CHECK_EQ(img.exports[0].ordinal, 0u);
    CHECK_EQ(img.exports[0].rva, 0x1010u);

    VirtualFree(arena, 0, MEM_RELEASE);
}
#endif
