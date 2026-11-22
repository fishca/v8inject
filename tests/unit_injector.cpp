// The decision table of the remote LoadLibrary thread (src/host/injector.cpp).
//
// The rule under test: the remote path buffer is released only when the remote
// thread is known to have finished (WAIT_OBJECT_0). Anything else -- a timeout
// or a failed wait -- leaves the buffer allocated, because the thread may
// still be reading the path string. A load that completed after the timeout
// turns the attempt into a success, still without freeing anything: nobody
// confirmed the thread has exited.
//
// The second half of this file is the export walk that produces the address of
// v8i_probe inside the image the target already has (A42). The images under
// test are synthetic: a real "the target holds an older build" cannot be
// produced in a unit test, but the walk over a hand-built image and over a real
// system module (thousands of exports) shows that the address comes from the
// bytes in front of it, not from a delta against the host's copy.

#include "test_runner.h"

#include "v8inject/injector.h"
#include "v8inject/pe_utils.h"

#include <cstring>
#include <vector>

using namespace v8i;
using namespace v8i::test;

V8I_TEST(Injector_RemoteThreadFinishedWithAModule) {
    const RemoteLoadDecision d = EvaluateRemoteLoad(WAIT_OBJECT_0, 0x78000000, false);
    CHECK(d.ok);
    CHECK(d.freeBuffer);
}

V8I_TEST(Injector_RemoteThreadFinishedWithNull) {
    // LoadLibraryW returned NULL: the load failed cleanly, the thread is gone,
    // the unused buffer can go.
    const RemoteLoadDecision d = EvaluateRemoteLoad(WAIT_OBJECT_0, 0, false);
    CHECK(!d.ok);
    CHECK(d.freeBuffer);
}

V8I_TEST(Injector_RemoteThreadFinishedAsStillActive) {
    // Exit code STILL_ACTIVE (259) is not a module handle we trust.
    const RemoteLoadDecision d = EvaluateRemoteLoad(WAIT_OBJECT_0, STILL_ACTIVE, false);
    CHECK(!d.ok);
    CHECK(d.freeBuffer);
}

V8I_TEST(Injector_TimeoutHungInjectionKeepsTheBuffer) {
    // The thread never reported in and no module appeared: refusal, and the
    // buffer stays -- the thread may still be reading the path from it.
    const RemoteLoadDecision d = EvaluateRemoteLoad(WAIT_TIMEOUT, 0, false);
    CHECK(!d.ok);
    CHECK(!d.freeBuffer);
}

V8I_TEST(Injector_TimeoutButModuleLoadedIsASuccess) {
    // The load completed after the timeout fired: the injection succeeded,
    // but the buffer still is not freed -- nobody confirmed the thread exited.
    const RemoteLoadDecision d = EvaluateRemoteLoad(WAIT_TIMEOUT, STILL_ACTIVE, true);
    CHECK(d.ok);
    CHECK(!d.freeBuffer);
}

V8I_TEST(Injector_FailedWaitBehavesLikeATimeout) {
    const RemoteLoadDecision d1 = EvaluateRemoteLoad(WAIT_FAILED, 0, false);
    CHECK(!d1.ok);
    CHECK(!d1.freeBuffer);

    const RemoteLoadDecision d2 = EvaluateRemoteLoad(WAIT_FAILED, 0, true);
    CHECK(d2.ok);
    CHECK(!d2.freeBuffer);
}

namespace {

// A mapped image with one export table, laid out the way the loader would have
// it: DOS header, NT headers, export directory, name/ordinal/function tables
// and the name strings. Two exports, one of them v8i_probe -- the negative
// tests mutate the fields they need.
struct FakeImage {
    static constexpr uint32_t kNt        = 0x80;
    static constexpr uint32_t kExports   = 0x200;
    static constexpr uint32_t kNames     = 0x300;
    static constexpr uint32_t kOrdinals  = 0x310;
    static constexpr uint32_t kFunctions = 0x320;
    static constexpr uint32_t kNameStr   = 0x400;
    static constexpr uint32_t kSize      = 0x2000;
    static constexpr uint32_t kStamp     = 0x5A5A5A5A;
    static constexpr uint32_t kProbeRva  = 0x1234;

    std::vector<uint8_t> bytes;

    explicit FakeImage(uint16_t magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        bytes.assign(kSize, 0);

        IMAGE_DOS_HEADER dos{};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = (LONG)kNt;
        Put(0, &dos, sizeof dos);

        const uint32_t sig = IMAGE_NT_SIGNATURE;
        Put(kNt, &sig, sizeof sig);

        IMAGE_FILE_HEADER fh{};
        fh.Machine = (WORD)(magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
                                ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386);
        fh.NumberOfSections = 1;
        fh.TimeDateStamp = kStamp;
        Put(kNt + 4, &fh, sizeof fh);

        const uint32_t opt = kNt + 4 + (uint32_t)sizeof(IMAGE_FILE_HEADER);
        Put(opt, &magic, sizeof magic);
        const uint32_t sizeOfImage = kSize;
        Put(opt + 56, &sizeOfImage, sizeof sizeOfImage);

        IMAGE_DATA_DIRECTORY dir{};
        dir.VirtualAddress = kExports;
        dir.Size = 0x40;   // covers the directory itself, not the code below
        Put(opt + (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 112u : 96u), &dir, sizeof dir);

        IMAGE_EXPORT_DIRECTORY ed{};
        ed.NumberOfFunctions = 2;
        ed.NumberOfNames = 2;
        ed.AddressOfFunctions = kFunctions;
        ed.AddressOfNames = kNames;
        ed.AddressOfNameOrdinals = kOrdinals;
        Put(kExports, &ed, sizeof ed);

        const uint32_t names[2] = { kNameStr, kNameStr + 8 };
        Put(kNames, names, sizeof names);
        const uint16_t ordinals[2] = { 0, 1 };   // name[0] -> other, name[1] -> probe
        Put(kOrdinals, ordinals, sizeof ordinals);
        const uint32_t functions[2] = { 0x2000, kProbeRva };
        Put(kFunctions, functions, sizeof functions);

        const char other[] = "other\0";
        const char probe[] = "v8i_probe\0";
        Put(kNameStr, other, sizeof other);          // 7 bytes, then the probe
        Put(kNameStr + 8, probe, sizeof probe);
    }

    void Put(uint32_t at, const void* src, size_t n) {
        memcpy(bytes.data() + at, src, n);
    }
    void SetU32(uint32_t at, uint32_t v) { Put(at, &v, sizeof v); }
    void SetU16(uint32_t at, uint16_t v) { Put(at, &v, sizeof v); }

    // Offset of the export directory entry inside the optional header.
    uint32_t DirAt() const {
        const uint32_t opt = kNt + 4 + (uint32_t)sizeof(IMAGE_FILE_HEADER);
        uint16_t magic = 0;
        memcpy(&magic, bytes.data() + opt, sizeof magic);
        return opt + (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 112u : 96u);
    }

    void SetExportName(const char* text) {
        char buf[64] = {};
        strncpy_s(buf, sizeof buf, text, _TRUNCATE);
        memcpy(bytes.data() + kNameStr + 8, buf, sizeof buf);
    }
};

struct BufferSource {
    const std::vector<uint8_t>* bytes;
};

bool ReadBuffer(void* ctx, uint32_t rva, void* dst, size_t bytes) {
    const BufferSource* src = static_cast<const BufferSource*>(ctx);
    if (!src || !src->bytes) return false;
    if ((uint64_t)rva + bytes > src->bytes->size()) return false;
    memcpy(dst, src->bytes->data() + rva, bytes);
    return true;
}

PayloadImage Parse(const std::vector<uint8_t>& bytes) {
    BufferSource src{ &bytes };
    ImageReadFn reader{ ReadBuffer, &src };
    return FindProbeExport(reader);
}

}  // namespace

V8I_TEST(Injector_FindsTheExportInTheImageItIsGiven) {
    const FakeImage x64;
    const PayloadImage a = Parse(x64.bytes);
    CHECK(a.ok);
    CHECK_EQ(a.probeRva, FakeImage::kProbeRva);
    CHECK_EQ(a.timeDateStamp, FakeImage::kStamp);
    CHECK_EQ(a.sizeOfImage, FakeImage::kSize);
    CHECK_EQ(std::string(a.error), std::string(""));

    // The same image as PE32: the export directory sits 16 bytes earlier.
    const FakeImage x86(IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    const PayloadImage b = Parse(x86.bytes);
    CHECK(b.ok);
    CHECK_EQ(b.probeRva, FakeImage::kProbeRva);
    CHECK_EQ(b.sizeOfImage, FakeImage::kSize);
}

V8I_TEST(Injector_TakesTheProbeRvaFromEachImageSeparately) {
    // Two builds of the payload: same export name, different RVAs (a rebuilt
    // DLL moves its functions), different stamps. The answer for each image is
    // that image's own RVA -- the old code would have computed the second one
    // by rebasing the first, and jumped into whatever was there (A42).
    FakeImage target;
    target.SetU32(FakeImage::kFunctions + 4, 0x1500);
    const FakeImage disk;

    const PayloadImage inTarget = Parse(target.bytes);
    const PayloadImage onDisk = Parse(disk.bytes);
    REQUIRE(inTarget.ok);
    CHECK_EQ(std::string(inTarget.error), std::string(""));
    REQUIRE(onDisk.ok);
    CHECK_EQ(inTarget.probeRva, 0x1500u);
    CHECK_EQ(onDisk.probeRva, FakeImage::kProbeRva);
    // Same name, same size, different build: the stamp tells them apart.
    target.SetU32(FakeImage::kNt + 4 + 4 /*TimeDateStamp*/, 0x11111111);
    const PayloadImage rebuilt = Parse(target.bytes);
    CHECK(!PayloadBuildMatches(rebuilt, onDisk));
    CHECK(PayloadBuildMatches(inTarget, onDisk));
}

V8I_TEST(Injector_RefusesAStaleImageWithTheSameExport) {
    // The target image and the file are the same image except for the build
    // stamp: that is exactly "the target holds a payload of another build",
    // and the host must refuse instead of calling into it.
    FakeImage target;
    const FakeImage disk;
    target.SetU32(FakeImage::kNt + 4 + 4, 0x22222222);
    const PayloadImage a = Parse(target.bytes);
    const PayloadImage b = Parse(disk.bytes);
    REQUIRE(a.ok);
    REQUIRE(b.ok);
    CHECK(!PayloadBuildMatches(a, b));

    // A different size of image also means a different build.
    FakeImage resized;
    resized.SetU32(FakeImage::kNt + 4 + (uint32_t)sizeof(IMAGE_FILE_HEADER) + 56, 0x3000);
    const PayloadImage c = Parse(resized.bytes);
    REQUIRE(c.ok);
    CHECK(!PayloadBuildMatches(c, b));

    // An image that could not be parsed never matches.
    const PayloadImage bad{};
    CHECK(!PayloadBuildMatches(bad, b));
    CHECK(!PayloadBuildMatches(b, bad));
}

V8I_TEST(Injector_RefusesAnImageWithoutTheExport) {
    FakeImage img;
    img.SetExportName("v8i_probee");
    const PayloadImage r = Parse(img.bytes);
    CHECK(!r.ok);
    CHECK_EQ(std::string(r.error), std::string("the image does not export v8i_probe"));
}

V8I_TEST(Injector_RefusesAnImageWithoutAnExportDirectory) {
    FakeImage img;
    img.SetU32(img.DirAt(), 0);   // VirtualAddress = 0
    const PayloadImage r = Parse(img.bytes);
    CHECK(!r.ok);
    CHECK(strstr(r.error, "no export directory") != nullptr);
}

V8I_TEST(Injector_RefusesGarbageImages) {
    // Not an image at all: no MZ, no PE signature, an NT offset past the end.
    std::vector<uint8_t> junk(0x200, 0xCC);
    const PayloadImage a = Parse(junk);
    CHECK(!a.ok);
    CHECK(strstr(a.error, "MZ") != nullptr);

    FakeImage noPe;
    const uint32_t bad = 0xDEADBEEF;
    noPe.Put(FakeImage::kNt, &bad, sizeof bad);
    const PayloadImage b = Parse(noPe.bytes);
    CHECK(!b.ok);
    CHECK(strstr(b.error, "PE signature") != nullptr);

    FakeImage badOpt;
    badOpt.SetU16(FakeImage::kNt + 4 + (uint32_t)sizeof(IMAGE_FILE_HEADER), 0x0107);
    const PayloadImage c = Parse(badOpt.bytes);
    CHECK(!c.ok);
    CHECK(strstr(c.error, "neither PE32 nor PE32+") != nullptr);

    FakeImage badSize;
    badSize.SetU32(FakeImage::kNt + 4 + (uint32_t)sizeof(IMAGE_FILE_HEADER) + 56, 0);
    const PayloadImage d = Parse(badSize.bytes);
    CHECK(!d.ok);
    CHECK(strstr(d.error, "image size is implausible") != nullptr);

    // A truncated buffer: the DOS header alone does not fit.
    std::vector<uint8_t> tiny(0x40, 0);
    const PayloadImage e = Parse(tiny);
    CHECK(!e.ok);
}

V8I_TEST(Injector_RefusesATableThatPointsOutsideTheImage) {
    // Ordinal beyond the function table.
    FakeImage ordinal;
    ordinal.SetU16(FakeImage::kOrdinals + 2, 7);
    const PayloadImage a = Parse(ordinal.bytes);
    CHECK(!a.ok);
    CHECK(strstr(a.error, "ordinal leaves the function table") != nullptr);

    // The export points past the image.
    FakeImage outside;
    outside.SetU32(FakeImage::kFunctions + 4, FakeImage::kSize + 0x100);
    const PayloadImage b = Parse(outside.bytes);
    CHECK(!b.ok);
    CHECK(strstr(b.error, "outside the image") != nullptr);

    // Inside the export directory: a forwarder string, not code.
    FakeImage forwarded;
    forwarded.SetU32(FakeImage::kFunctions + 4, FakeImage::kExports + 8);
    const PayloadImage c = Parse(forwarded.bytes);
    CHECK(!c.ok);
    CHECK_EQ(std::string(c.error), std::string("the v8i_probe export is forwarded to another module"));

    // An implausible number of names must not turn into a long walk.
    FakeImage many;
    many.SetU32(FakeImage::kExports + 24 /*NumberOfNames*/, 0xFFFFFFFF);
    const PayloadImage d = Parse(many.bytes);
    CHECK(!d.ok);
    CHECK(strstr(d.error, "implausible") != nullptr);

    // The name table itself cannot be read.
    FakeImage namesOut;
    namesOut.SetU32(FakeImage::kExports + 32 /*AddressOfNames*/, FakeImage::kSize + 0x10);
    const PayloadImage e = Parse(namesOut.bytes);
    CHECK(!e.ok);
    CHECK(strstr(e.error, "name table is unreadable") != nullptr);
}

V8I_TEST(Injector_WalksARealExportTable) {
    // kernel32 exports thousands of names: the walk must survive them and end
    // with a refusal that names the missing export, not with a crash or a
    // truncated name match.
    ModuleRange k32;
    REQUIRE(FindModule(L"kernel32.dll", k32));
    const uint8_t* base = (const uint8_t*)k32.base;
    ImageReadFn reader{ nullptr, nullptr };
    reader.read = [](void* ctx, uint32_t rva, void* dst, size_t bytes) -> bool {
        const uint8_t* b = (const uint8_t*)ctx;
        memcpy(dst, b + rva, bytes);
        return true;
    };
    reader.ctx = (void*)base;

    const PayloadImage r = FindProbeExport(reader);
    CHECK(!r.ok);
    CHECK_EQ(std::string(r.error), std::string("the image does not export v8i_probe"));
    CHECK(r.sizeOfImage > 0);
}

// A143: a crashed remote thread exits with an NTSTATUS (an exception inside
// DllMain or its dependencies), and the old table read any nonzero code as
// "a module handle" -- `inject` printed "injected ok" over a dead 1C. The
// handle is recognized only when it looks like one: 64 KiB aligned, above the
// first 64 KiB, below the user/kernel boundary.
V8I_TEST(Injector_AnNtstatusExitCodeIsNotAModuleHandle) {
    const DWORD codes[] = { 0xC0000005u, 0xC0000135u, 0x80000003u, 0xC0000409u };
    for (const DWORD ec : codes) {
        const RemoteLoadDecision d = EvaluateRemoteLoad(WAIT_OBJECT_0, ec, false);
        CHECK(!d.ok);
        CHECK(d.freeBuffer);
        CHECK(std::string(d.reason).find("died") != std::string::npos);
    }

    // A genuine handle value still passes the table.
    CHECK(EvaluateRemoteLoad(WAIT_OBJECT_0, 0x78000000, false).ok);
    // The user/kernel boundary of the check only binds on x86 (the exit code
    // is a DWORD and can never reach the x64 boundary), so the x86 build gets
    // the boundary case here: aligned, but above the 32-bit user space.
#if !defined(_WIN64)
    CHECK(!EvaluateRemoteLoad(WAIT_OBJECT_0, 0x80000000u, false).ok);
#endif
}
