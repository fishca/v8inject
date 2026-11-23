// The memory scanners of the payload (docs/AUDIT.md A49).
//
// `heapobjects` and `byhwnd` are the two commands that look for C++ objects in
// the process they run in, and neither was called from a test: on x64 both read
// a 32-bit half of a 64-bit vtable pointer and compared it with a 64-bit module
// range. The image base is above 4 GB there, so the low half of every real
// pointer was below the range and both commands answered "no objects" - always.
//
// A scanner cannot be tested with a hand-built buffer alone: it walks the real
// address space of this process. So the test places a real object with a
// virtual table from this image and a real window on the heap, and asks the
// scanner to find them.

#include "test_runner.h"

#include "v8inject/memscan.h"
#include "v8inject/pe_utils.h"

#include <windows.h>
#include <cstring>
#include <memory>
#include <vector>

using namespace v8i;
using namespace v8i::test;

namespace {

// The layout a 1C window object has: a vtable, more virtual methods, then the
// handle. The first four vtable slots are functions of this image, which is
// what FindHeapObjects requires before it calls a slot a vtable.
class ScanProbe {
public:
    virtual ~ScanProbe() = default;
    virtual int One() { return 1; }
    virtual int Two() { return 2; }
    virtual int Three() { return 3; }
    virtual int Four() { return 4; }
    HWND hwnd = nullptr;
};

// Reads the value the object starts with - its vtable pointer - without
// assuming the class definition: the scanner sees raw memory as well.
uintptr_t FirstPointerOf(const void* obj) {
    uintptr_t v = 0;
    memcpy(&v, obj, sizeof(v));
    return v;
}

// The range of the test binary itself: the module the probe objects belong to.
ModuleRange SelfModule() {
    const uintptr_t base = (uintptr_t)GetModuleHandleW(nullptr);
    for (const ModuleRange& m : EnumModules()) {
        if (m.base == base) return m;
    }
    ModuleRange none;
    none.base = base;
    return none;
}

const wchar_t kProbeWindowClass[] = L"V8iMemScanProbeWindow";

ATOM EnsureProbeWindowClass() {
    static ATOM atom = 0;
    if (atom) return atom;
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = kProbeWindowClass;
    atom = RegisterClassExW(&wc);
    if (!atom && GetLastError() == ERROR_CLASS_ALREADY_EXISTS) atom = 1;
    return atom;
}

HWND CreateProbeWindow() {
    if (!EnsureProbeWindowClass()) return nullptr;
    return CreateWindowExW(0, kProbeWindowClass, L"scan probe", WS_OVERLAPPEDWINDOW, 0, 0, 200,
                           120, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
}

}  // namespace

// A49: a heap object whose vtable belongs to a module is found on both builds.
V8I_TEST(MemScan_HeapObjectsFindsARealObject) {
    const ModuleRange mod = SelfModule();
    REQUIRE(mod.base != 0);
    REQUIRE(mod.size != 0);

    auto probe = std::make_unique<ScanProbe>();
    probe->hwnd = nullptr;
    const uintptr_t probeAddr = (uintptr_t)probe.get();
    const uintptr_t vtable = FirstPointerOf(probe.get());
    // The scanner classifies the slot as a vtable only when it lands inside the
    // module range; a probe that was matched through the wrong half of a pointer
    // would not be inside it on x64.
    CHECK(vtable >= mod.base && vtable < mod.base + mod.size);

    size_t scanned = 0, regions = 0, committed = 0;
    std::vector<HeapObject> objs =
        FindHeapObjects(mod.base, mod.size, 4096, &scanned, &regions, &committed);

    bool found = false;
    for (const HeapObject& o : objs) {
        if (o.address != probeAddr) continue;
        found = true;
        CHECK_EQ((unsigned long long)o.vtable, (unsigned long long)vtable);
        CHECK_EQ((unsigned long long)o.vtableRva, (unsigned long long)(vtable - mod.base));
    }
    CHECK(found);
    CHECK(scanned > 0);
    CHECK(regions > 0);
    CHECK(committed > 0);
}

// A49: byhwnd reports the object that owns a window, its real offset and the
// module of its vtable - in both modes of the command.
V8I_TEST(MemScan_ByHwndFindsTheObjectThatOwnsAWindow) {
    const ModuleRange mod = SelfModule();
    REQUIRE(mod.base != 0);
    REQUIRE(mod.size != 0);

    HWND wnd = CreateProbeWindow();
    REQUIRE(wnd != nullptr);

    auto probe = std::make_unique<ScanProbe>();
    probe->hwnd = wnd;
    const uintptr_t probeAddr = (uintptr_t)probe.get();
    const uintptr_t vtable = FirstPointerOf(probe.get());

    // The handle sits one machine word behind the vtable; the scanner walks a
    // window of 0x40 bytes back from the handle, so the exact offset need not be
    // known to it.
    size_t scanned = 0, regions = 0;
    std::vector<HwndOwner> owners =
        FindObjectsByHwnd(wnd, mod.base, mod.size, 0x40, 64, &scanned, &regions);

    bool found = false;
    for (const HwndOwner& o : owners) {
        if (o.address != probeAddr) continue;
        found = true;
        CHECK_EQ((unsigned long long)o.vtable, (unsigned long long)vtable);
        CHECK_EQ((unsigned long long)o.offset, (unsigned long long)sizeof(void*));
        CHECK_EQ((unsigned long long)o.moduleRva, (unsigned long long)(vtable - mod.base));
        CHECK(o.vtableInModule);
    }
    CHECK(found);
    CHECK(scanned > 0);

    // moduleBase==0 is the documented "the vtable may live in any module" mode
    // of `byhwnd`; this probe's vtable is in this image, so both modes agree.
    std::vector<HwndOwner> any = FindObjectsByHwnd(wnd, 0, 0, 0x40, 64, &scanned, &regions);
    bool foundAny = false;
    for (const HwndOwner& o : any) {
        if (o.address == probeAddr) {
            foundAny = true;
            CHECK_EQ((unsigned long long)o.vtable, (unsigned long long)vtable);
        }
    }
    CHECK(foundAny);

    DestroyWindow(wnd);
}

// A113: a typo in the module name is reported as missing, not as an empty
// scan indistinguishable from "the pattern is not there".
V8I_TEST(MemScan_FindReportsAMissingModule) {
    // Built at runtime so the literal is not sitting in this image's .rdata,
    // where the "loaded module, no match" case below would find it. (REQUIRE
    // stringifies its expression, so even a wide literal elsewhere leaks a
    // narrow copy into the image.)
    std::wstring pattern = L"NO_SUCH";
    pattern += L"_V8I_PATTERN";

    FindOptions opt;
    opt.pattern = pattern;
    opt.module = L"v8i_no_such_module.dll";
    size_t scanned = 12345;
    bool missing = false;
    std::vector<MemoryHit> hits = FindInMemory(opt, &scanned, &missing);
    CHECK(missing);
    CHECK(hits.empty());
    CHECK_EQ((unsigned long long)scanned, 0ULL);   // nothing was walked

    // A loaded module with no match is the opposite case: not missing, empty.
    const ModuleRange self = SelfModule();
    const size_t slash = self.path.find_last_of(L'\\');
    opt.module = slash == std::wstring::npos ? self.path : self.path.substr(slash + 1);
    missing = true;
    hits = FindInMemory(opt, &scanned, &missing);
    CHECK(!missing);
    CHECK(hits.empty());
}

// A114: the cap used to be checked only between 1 MB chunks, so one dense
// chunk returned hundreds of hits for --count 3. A block of fake owners sits
// in a single chunk; the answer must stop at the cap inside it.
V8I_TEST(MemScan_ByHwndStopsAtTheCapInsideAChunk) {
    const ModuleRange mod = SelfModule();
    REQUIRE(mod.base != 0);
    REQUIRE(mod.size != 0);

    HWND wnd = CreateProbeWindow();
    REQUIRE(wnd != nullptr);

    ScanProbe real;
    const uintptr_t vtable = FirstPointerOf(&real);

    struct FakeOwner { uintptr_t vt; HWND hwnd; };
    std::vector<FakeOwner> dense(4096);
    for (FakeOwner& f : dense) { f.vt = vtable; f.hwnd = wnd; }
    CHECK(dense.front().hwnd == wnd);   // the block stays alive for the scan

    // The cap sits above the few stray copies of a fresh handle in window
    // manager structures, but far below the dense block: the old code, which
    // checked the cap only between chunks, returned the whole block at once.
    size_t scanned = 0, regions = 0;
    std::vector<HwndOwner> owners =
        FindObjectsByHwnd(wnd, mod.base, mod.size, 0x40, 256, &scanned, &regions);
    CHECK_EQ(owners.size(), (size_t)256);

    DestroyWindow(wnd);
}

// A114, the same cap for heapobjects: a dense block of slots pointing at a
// real vtable of this image must not overflow the requested count.
V8I_TEST(MemScan_HeapObjectsStopsAtTheCapInsideAChunk) {
    const ModuleRange mod = SelfModule();
    REQUIRE(mod.base != 0);
    REQUIRE(mod.size != 0);

    ScanProbe real;
    const uintptr_t vtable = FirstPointerOf(&real);
    REQUIRE(vtable >= mod.base && vtable < mod.base + mod.size);

    std::vector<uintptr_t> dense(4096, vtable);
    CHECK_EQ((unsigned long long)dense.front(), (unsigned long long)vtable);

    size_t scanned = 0, regions = 0, committed = 0;
    std::vector<HeapObject> objs =
        FindHeapObjects(mod.base, mod.size, 5, &scanned, &regions, &committed);
    CHECK_EQ(objs.size(), (size_t)5);
    CHECK(scanned > 0);
}

// A173: findvalue --module scans the module image only. The probe value lives
// in this image AND on the heap; the heap copy must stay out of the answer.
volatile uint32_t g_dwordProbe = 0x5A17C0DE;

V8I_TEST(MemScan_FindDwordStaysInsideTheModule) {
    const ModuleRange mod = SelfModule();
    REQUIRE(mod.base != 0);
    REQUIRE(mod.size != 0);

    const uintptr_t probeAddr = (uintptr_t)&g_dwordProbe;
    auto heapCopy = std::make_unique<uint32_t>(0x5A17C0DE);
    const uintptr_t heapAddr = (uintptr_t)heapCopy.get();
    REQUIRE(heapAddr < mod.base || heapAddr >= mod.base + mod.size);

    size_t scanned = 0;
    std::vector<DwordHit> hits = FindDword(0x5A17C0DE, 64, &scanned, mod.base, mod.size);
    CHECK(!hits.empty());
    bool foundProbe = false;
    for (const DwordHit& h : hits) {
        CHECK(h.address >= mod.base && h.address < mod.base + mod.size);
        CHECK(h.address != heapAddr);
        if (h.address == probeAddr) foundProbe = true;
    }
    CHECK(foundProbe);
    CHECK(scanned > 0);

    // Without a module the whole process is scanned and the heap copy shows up.
    std::vector<DwordHit> all = FindDword(0x5A17C0DE, 64, &scanned);
    bool foundHeap = false;
    for (const DwordHit& h : all)
        if (h.address == heapAddr) foundHeap = true;
    CHECK(foundHeap);
}
