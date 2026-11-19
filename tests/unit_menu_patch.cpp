// The two hidden writes of the native menu (docs/AUDIT.md A78, A79):
//  * the receiver's vtable is patched transactionally — a failed attempt leaves
//    no slot trapped and never stores our own trap as "original";
//  * the command description is only written when its fields look like the
//    calibrated layout.
//
// The description check is a payload function (mainmenu.cpp, compiled into this
// test binary); it is declared here because the payload has no header for it —
// it is not called from outside the payload.

#include "test_runner.h"

#include "v8inject/ini.h"

#include "../src/payload/menu_patch.h"

#include <windows.h>
#include <cstring>

using namespace v8i;

namespace v8i {
bool MMDescrShapeOk(uintptr_t descr);        // src/payload/mainmenu.cpp
bool MMNativeMenuEnabledFor(const wchar_t* iniPath);   // the [git] nativemenu switch
bool MMPrologueOk(uintptr_t addr);          // src/payload/mainmenu.cpp
}

namespace {

// Three distinct "original" functions of the fake vtable. The values fit a
// 32-bit pointer so the test builds on both architectures.
const uintptr_t kOrig0 = 0x11111111;
const uintptr_t kOrig1 = 0x22222222;
const uintptr_t kOrig2 = 0x33333333;
const uintptr_t kOrig3 = 0x44444444;

struct FakeVt {
    uintptr_t slot[8];
};

FakeVt MakeVt() {
    FakeVt v = {};
    v.slot[3] = kOrig0;
    v.slot[4] = kOrig1;
    v.slot[5] = kOrig2;
    v.slot[6] = kOrig3;
    return v;
}

void HookA(void*) {}
void HookB(void*) {}
void HookC(void*) {}

}  // namespace

V8I_TEST(MenuPatch_TransactionWritesAllSlotsAndKeepsOriginals) {
    FakeVt vt = MakeVt();
    v8i::SlotPatch patches[3] = {
        {3, (void*)&HookA, 0},
        {4, (void*)&HookB, 0},
        {5, (void*)&HookC, 0},
    };
    REQUIRE(v8i::PatchSlotsTransaction(vt.slot, patches, 3));
    CHECK_EQ((uintptr_t)vt.slot[3], (uintptr_t)&HookA);
    CHECK_EQ((uintptr_t)vt.slot[4], (uintptr_t)&HookB);
    CHECK_EQ((uintptr_t)vt.slot[5], (uintptr_t)&HookC);
    CHECK_EQ(patches[0].orig, kOrig0);
    CHECK_EQ(patches[1].orig, kOrig1);
    CHECK_EQ(patches[2].orig, kOrig2);
}

V8I_TEST(MenuPatch_RefusesToPatchItsOwnTrap) {
    // A second run would call the trap from the trap: the patch is refused and
    // `orig` is not overwritten with our own hook (A79).
    FakeVt vt = MakeVt();
    vt.slot[3] = (uintptr_t)&HookA;
    v8i::SlotPatch p = {3, (void*)&HookA, kOrig0};
    CHECK(!v8i::PatchSlot(vt.slot, 3, (void*)&HookA, &p.orig));
    CHECK_EQ(p.orig, kOrig0);                       // untouched
    CHECK_EQ((uintptr_t)vt.slot[3], (uintptr_t)&HookA);
}

V8I_TEST(MenuPatch_FailedTransactionRestoresTheSlotsItWrote) {
    // Slots 3 and 4 are patched, slot 5 already holds our trap: the whole
    // attempt must be rolled back, or the next run would store the trap as the
    // original and recurse into itself.
    FakeVt vt = MakeVt();
    vt.slot[5] = (uintptr_t)&HookC;
    v8i::SlotPatch patches[3] = {
        {3, (void*)&HookA, 0},
        {4, (void*)&HookB, 0},
        {5, (void*)&HookC, 0},
    };
    CHECK(!v8i::PatchSlotsTransaction(vt.slot, patches, 3));
    CHECK_EQ((uintptr_t)vt.slot[3], kOrig0);   // restored
    CHECK_EQ((uintptr_t)vt.slot[4], kOrig1);   // restored
    CHECK_EQ((uintptr_t)vt.slot[5], (uintptr_t)&HookC);   // left as it was

    // A retry from that state is honest again: the originals are the real ones.
    vt.slot[5] = kOrig2;
    CHECK(v8i::PatchSlotsTransaction(vt.slot, patches, 3));
    CHECK_EQ(patches[0].orig, kOrig0);
    CHECK_EQ(patches[1].orig, kOrig1);
    CHECK_EQ(patches[2].orig, kOrig2);
    CHECK_EQ((uintptr_t)vt.slot[5], (uintptr_t)&HookC);
}

V8I_TEST(MenuPatch_NullArgumentsAreRefused) {
    FakeVt vt = MakeVt();
    v8i::SlotPatch p = {3, (void*)&HookA, 0};
    CHECK(!v8i::PatchSlotsTransaction(nullptr, &p, 1));
    CHECK(!v8i::PatchSlotsTransaction(vt.slot, nullptr, 1));
    CHECK(!v8i::PatchSlotsTransaction(vt.slot, &p, 0));
    CHECK(!v8i::PatchSlot(vt.slot, 3, nullptr, &p.orig));   // no hook
    CHECK_EQ((uintptr_t)vt.slot[3], kOrig0);
}

// --- the description shape (A78) -------------------------------------------

namespace {

// A buffer shaped like a command description: [b .. b+0x110), descr = b + 0x70.
struct DescrBuf {
    unsigned char bytes[0x200];
    uintptr_t descr;
};

uintptr_t g_fakeVt[10] = {};        // a readable vtable of a description
wchar_t g_heapStr[64] = L"Heap text";
wchar_t g_url[64] = L"file:///tmp/x.png";

void InitDescr(DescrBuf* d) {
    std::memset(d->bytes, 0, sizeof(d->bytes));
    d->descr = (uintptr_t)d->bytes + 0x70;
    *(uintptr_t*)(d->bytes + 0x70) = (uintptr_t)g_fakeVt;   // descr->vtbl
    g_fakeVt[0] = (uintptr_t)&HookA;
    unsigned char* b = d->bytes;
    // Four short v8string slots in heap form.
    for (uintptr_t off : {uintptr_t(0x08), uintptr_t(0x20), uintptr_t(0x38), uintptr_t(0x50)}) {
        *(uintptr_t*)(b + off) = (uintptr_t)g_heapStr;
        const uintptr_t len = wcslen(g_heapStr);
        *(uintptr_t*)(b + off + 16) = len | ((uintptr_t)1 << (sizeof(uintptr_t) * 8 - 1));
    }
    *(uintptr_t*)(b + 0xB0) = (uintptr_t)g_url;
}

}  // namespace

V8I_TEST(DescrShape_AcceptsTheCalibratedLayout) {
    DescrBuf d;
    InitDescr(&d);
    CHECK(v8i::MMDescrShapeOk(d.descr));
}

V8I_TEST(DescrShape_RejectsAHeapStringThatDoesNotPointAnywhere) {
    DescrBuf d;
    InitDescr(&d);
    *(uintptr_t*)(d.bytes + 0x08) = 0;   // heap capacity, but no data
    CHECK(!v8i::MMDescrShapeOk(d.descr));
}

V8I_TEST(DescrShape_RejectsAnSsoCapacityOutOfRange) {
    DescrBuf d;
    InitDescr(&d);
    unsigned char* s = d.bytes + 0x20;
    *(uintptr_t*)s = 0;
    *(uintptr_t*)(s + 16) = 0;             // SSO form
    *(unsigned short*)(s + 0x16) = 99;     // the "11 - length" word is garbage
    CHECK(!v8i::MMDescrShapeOk(d.descr));
}

V8I_TEST(DescrShape_RejectsAnObjectWithoutAVtable) {
    DescrBuf d;
    InitDescr(&d);
    *(uintptr_t*)(d.bytes + 0x70) = 0;   // descr->vtbl = null
    CHECK(!v8i::MMDescrShapeOk(d.descr));
    CHECK(!v8i::MMDescrShapeOk(0));
}

// --- the emergency switch [git] nativemenu=0 (A53) -------------------------

namespace {

std::wstring TempPath(const wchar_t* name) {
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring p(tmp);
    if (!p.empty() && p.back() != L'\\') p += L'\\';
    p += name;
    return p;
}

}  // namespace

V8I_TEST(NativeMenuSwitch_WorksOnTheUtf16IniThePayloadWrites) {
    // The settings dialog saves through IniSet, which writes UTF-16 with a byte
    // order mark. The switch used to search the raw bytes for "nativemenu" and
    // stopped at the NUL right after the mark, so after the first save the
    // emergency switch did nothing.
    const std::wstring path = TempPath(L"v8i_test_nativemenu.ini");
    DeleteFileW(path.c_str());

    CHECK(v8i::MMNativeMenuEnabledFor(path.c_str()));      // no file: enabled

    REQUIRE(IniSet(path.c_str(), L"git", L"nativemenu", L"0"));
    CHECK(!v8i::MMNativeMenuEnabledFor(path.c_str()));

    CHECK(IniSet(path.c_str(), L"git", L"nativemenu", L"1"));
    CHECK(v8i::MMNativeMenuEnabledFor(path.c_str()));

    CHECK(IniSet(path.c_str(), L"git", L"nativemenu", L"false"));
    CHECK(!v8i::MMNativeMenuEnabledFor(path.c_str()));

    // A missing key in an existing file keeps the default (enabled).
    CHECK(IniSet(path.c_str(), L"git", L"dumpdir", L"E:\\dump"));
    DeleteFileW(path.c_str());
    CHECK(IniSet(path.c_str(), L"git", L"dumpdir", L"E:\\dump"));
    CHECK(v8i::MMNativeMenuEnabledFor(path.c_str()));

    DeleteFileW(path.c_str());
}

// --- the gate against the platform binaries on this machine ----------------
//
// The calibrated RVAs are valid for the build MMSupported accepts and for no
// other one. That is checked against the installed platforms when they are
// there: 8.3.27.2342 has the getService wrapper prologue at both RVAs, while
// 8.3.27.1989 has unrelated mid-function code at the same offsets. Skipped on a
// machine without 1C.

namespace {

// A file mapped read-only for the RVA lookups below.
struct MappedFile {
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE map = nullptr;
    const unsigned char* data = nullptr;
    size_t size = 0;

    ~MappedFile() { Close(); }
    void Close() {
        if (data) UnmapViewOfFile(data);
        if (map) CloseHandle(map);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        data = nullptr;
        map = nullptr;
        file = INVALID_HANDLE_VALUE;
    }
    bool Open(const wchar_t* path) {
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return false;
        file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER len = {};
        if (!GetFileSizeEx(file, &len) || len.QuadPart < 0x400) return false;
        size = (size_t)len.QuadPart;
        map = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!map) return false;
        data = (const unsigned char*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
        return data != nullptr;
    }
    // RVA -> pointer into the mapped raw data (sections, not the loaded image).
    const unsigned char* Rva(uint32_t rva) const {
        if (!data || size < 0x400) return nullptr;
        const uint32_t lf = *(const uint32_t*)(data + 0x3C);
        if (lf + 24 > size) return nullptr;
        const unsigned nsec = *(const unsigned short*)(data + lf + 6);
        const unsigned optSize = *(const unsigned short*)(data + lf + 20);
        const size_t sec = (size_t)lf + 24 + optSize;
        for (unsigned i = 0; i < nsec; ++i) {
            const size_t s = sec + 40 * i;
            if (s + 40 > size) return nullptr;
            const uint32_t va = *(const uint32_t*)(data + s + 12);
            const uint32_t rawSize = *(const uint32_t*)(data + s + 16);
            const uint32_t rawPtr = *(const uint32_t*)(data + s + 20);
            if (rva < va || rva >= va + rawSize) continue;
            const size_t off = (size_t)rawPtr + (rva - va);
            if (off >= size) return nullptr;
            return data + off;
        }
        return nullptr;
    }
};

bool CheckBuild(const wchar_t* build, uint32_t rva, const wchar_t* leaf, bool expect) {
    wchar_t path[MAX_PATH] = {};
    _snwprintf_s(path, _countof(path), _TRUNCATE, L"C:\\Program Files\\1cv8\\%ls\\bin\\%ls",
                 build, leaf);
    MappedFile f;
    if (!f.Open(path)) return true;   // the build is not installed: nothing to check
    const unsigned char* p = f.Rva(rva);
    if (!p) return false;
    const bool ok = v8i::MMPrologueOk((uintptr_t)p) == expect;
    if (!ok) {
        char what[160] = {};
        _snprintf_s(what, sizeof(what), _TRUNCATE, "prologue gate: build %ls rva 0x%X",
                    build, (unsigned)rva);
        v8i::test::Fail(__FILE__, __LINE__, what);
    }
    return ok;
}

}  // namespace

V8I_TEST(MenuPrologue_AcceptsTheCalibratedBuildAndRejectsAnotherOne) {
    // Both wrapper RVAs of the calibrated build must pass, and the same RVAs of
    // another build of the family must fail — that is the whole point of the
    // gate (A52, A78).
    CHECK(CheckBuild(L"8.3.27.2342", 0xBFCB0, L"1cv8.exe", true));
    CHECK(CheckBuild(L"8.3.27.2342", 0xCF320, L"config.dll", true));
    CHECK(CheckBuild(L"8.3.27.1989", 0xBFCB0, L"1cv8.exe", false));
    CHECK(CheckBuild(L"8.3.27.1989", 0xCF320, L"config.dll", false));
}
