// Tests for the detour engine and the disassembler helpers it depends on
// (docs/AUDIT.md package 9: A59, A70-A75, A84, A90-A92).
//
// The engine is compiled into this binary, so a hook can be installed on a stub
// inside the test process itself: no injection, no second process, and a
// regression is a red test instead of a dead 1C.

#include "test_runner.h"
#include "json_check.h"

#include "v8inject/disasm.h"
#include "v8inject/hook.h"
#include "v8inject/protocol.h"

#include <windows.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

// A stub in its own executable page: a five-byte frame prologue, then the
// value, then the epilogue.
//   55            push ebp/rbp
//   8B EC         mov ebp, esp      (x86)   /   48 89 E5 mov rbp, rsp (x64)
//   90 [90]       nop padding to exactly five bytes
//   B8 imm32      mov eax, <value>  <- OUTSIDE the stolen window
//   5D            pop ebp/rbp
//   C3            ret
// The value has to be produced after the window the detour steals: the
// trampoline's own jump back clobbers rax, so a stub whose prologue ends in
// `mov eax, value` would return the low half of the jump target instead.
uint8_t* MakeStub(uint8_t value = 42) {
    uint8_t* mem = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;
    size_t o = 0;
    mem[o++] = 0x55;                                  // push ebp/rbp
#if defined(_M_X64)
    mem[o++] = 0x48; mem[o++] = 0x89; mem[o++] = 0xE5;   // mov rbp, rsp
    mem[o++] = 0x90;                                  // nop -> five bytes
#else
    mem[o++] = 0x8B; mem[o++] = 0xEC;                 // mov ebp, esp
    mem[o++] = 0x90; mem[o++] = 0x90;                 // two nops -> five bytes
#endif
    mem[o++] = 0xB8;                                  // mov eax, imm32
    mem[o++] = value;
    mem[o++] = 0; mem[o++] = 0; mem[o++] = 0;
    mem[o++] = 0x5D;                                  // pop ebp/rbp
    mem[o++] = 0xC3;                                  // ret
    FlushInstructionCache(GetCurrentProcess(), mem, o);
    return mem;
}

typedef unsigned (*StubFn)(void);
// The same stub seen through a four-argument signature: the machine code
// ignores the arguments, but the engine captures the registers/stack slots they
// arrive in, which is what the trace test checks.
typedef unsigned (*StubFn4)(unsigned, unsigned, unsigned, unsigned);

// Long long after "key": in a JSON reply, or -1 when the key is absent.
long long NumAfter(const std::string& j, const char* key) {
    const std::string pat = std::string("\"") + key + "\":";
    const size_t p = j.find(pat);
    if (p == std::string::npos) return -1;
    return _strtoi64(j.c_str() + p + pat.size(), nullptr, 10);
}

size_t CountOf(const std::string& j, const char* needle) {
    size_t n = 0;
    for (size_t p = j.find(needle); p != std::string::npos; p = j.find(needle, p + 1)) ++n;
    return n;
}

bool JsonOk(const std::string& j, std::string* why) {
    std::string err;
    if (v8i::test::JsonValid(j, &err)) return true;
    if (why) *why = err + " in: " + j.substr(0, 200);
    return false;
}

// Calls FindXrefsVerbose with a SEH guard around the call: the point of A84 is
// that a page the sweep must not read is skipped instead of faulting, and a
// regression would crash the whole test binary without a word.
//
// The guarded function has no objects with destructors, so MSVC allows __try in
// it (C2712); the call that builds the vectors lives in CallXref, one frame up.
struct XrefJob {
    uintptr_t start;
    uintptr_t end;
    uintptr_t target;
    bool is64;
    size_t maxHits;
    v8i::XrefResult* out;
};

void CallXref(XrefJob* job) {
    *job->out = v8i::FindXrefsVerbose(job->start, job->end, job->target, job->is64,
                                      job->maxHits);
}

int RunXrefUnderSeh(XrefJob* job) {
    __try {
        CallXref(job);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// The same guard around Disassemble, for the same reason: a regression there is
// an access violation inside the test process, and a test that dies without a
// message is worse than one that reports "the function faulted".
struct DisJob {
    uintptr_t start;
    size_t size;
    size_t maxInsns;
    uintptr_t* stopped;
    bool is64;
    std::vector<v8i::Insn>* out;
};

void CallDisassemble(DisJob* job) {
    *job->out = v8i::Disassemble(job->start, job->size, job->maxInsns, job->stopped,
                                 job->is64);
}

int RunDisassembleUnderSeh(DisJob* job) {
    __try {
        CallDisassemble(job);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// A deep call chain for the trace budget test: the hook records up to kMaxFrames
// caller addresses per call, and only a long chain fills the reply.
volatile unsigned g_deepSink = 0;

__declspec(noinline) unsigned DeepCall(int depth, StubFn fn) {
    if (depth <= 0) return fn();
    const unsigned r = DeepCall(depth - 1, fn);
    // Work after the call: without it the compiler is free to turn the
    // recursion into a jump and the recorded chain would be one frame long.
    g_deepSink += r;
    return r;
}

volatile LONG g_observed = 0;
uintptr_t g_observedArgs[4] = {};

extern "C" void ObserveCall(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3) {
    InterlockedIncrement(&g_observed);
    g_observedArgs[0] = a0;
    g_observedArgs[1] = a1;
    g_observedArgs[2] = a2;
    g_observedArgs[3] = a3;
}

}  // namespace

// ---------------------------------------------------------------------------
// A84: the disassembler must never read past the readable mapping
// ---------------------------------------------------------------------------

V8I_TEST(Hook_DisassembleStopsAtTheEndOfTheMapping) {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const size_t page = si.dwPageSize;

    uint8_t* mem = (uint8_t*)VirtualAlloc(nullptr, 2 * page, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    REQUIRE(mem != nullptr);
    DWORD old = 0;
    REQUIRE(VirtualProtect(mem + page, page, PAGE_NOACCESS, &old) != 0);

    // One nop in the last readable byte; the requested range runs 16 bytes into
    // the unreadable page. Copying all 16 first -- what the old code did after
    // checking a single byte -- faults here.
    mem[page - 1] = 0x90;
    FlushInstructionCache(GetCurrentProcess(), mem + page - 1, 1);

    uintptr_t stopped = 0;
    std::vector<v8i::Insn> v;
    DisJob job{ (uintptr_t)(mem + page - 1), 16, 8, &stopped, sizeof(void*) == 8, &v };
    CHECK_EQ(RunDisassembleUnderSeh(&job), 1);
    CHECK_EQ(v.size(), (size_t)1);
    CHECK_EQ((uintptr_t)stopped, (uintptr_t)(mem + page));

    VirtualFree(mem, 0, MEM_RELEASE);
}

V8I_TEST(Hook_XrefSkipsAPageItCannotRead) {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const size_t page = si.dwPageSize;

    uint8_t* mem = (uint8_t*)VirtualAlloc(nullptr, 2 * page, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    REQUIRE(mem != nullptr);
    DWORD old = 0;
    // Executable but not readable: VirtualQuery says "a page", and memcpy from
    // it is an access violation. The sweep has to skip it, not fault.
    REQUIRE(VirtualProtect(mem + page, page, PAGE_EXECUTE, &old) != 0);
    memset(mem, 0xC3, page);

    v8i::XrefResult r;
    XrefJob job{ (uintptr_t)mem, (uintptr_t)(mem + 2 * page), (uintptr_t)mem, sizeof(void*) == 8,
                 16, &r };
    CHECK_EQ(RunXrefUnderSeh(&job), 1);
    // The unreadable page was skipped whole, and the sweep still reached its
    // end: a fault here would have failed the guarded call instead.
    CHECK_EQ((uintptr_t)r.scannedTo, (uintptr_t)(mem + page));
    CHECK_EQ(std::string(r.stopReason), std::string("range exhausted"));

    VirtualFree(mem, 0, MEM_RELEASE);
}

// ---------------------------------------------------------------------------
// A75/A91: what DecodeForCopy reports about the instructions a hook moves
// ---------------------------------------------------------------------------

#if defined(_M_X64)
V8I_TEST(Hook_DecodeForCopyFindsTheRipRelativeOperand) {
    uint8_t* mem = MakeStub();
    REQUIRE(mem != nullptr);
    // mov rax, [rip+disp32]
    mem[0] = 0x48; mem[1] = 0x8B; mem[2] = 0x05;
    mem[3] = mem[4] = mem[5] = mem[6] = 0;
    mem[7] = 0xC3;

    const v8i::CopyInsn ci = v8i::DecodeForCopy((uintptr_t)mem, true);
    CHECK_EQ(ci.size, (size_t)7);
    CHECK(ci.ripRelative);
    CHECK_EQ(ci.dispOffset, (size_t)3);
    CHECK_EQ(ci.dispSize, (size_t)4);
    CHECK(!ci.isBranch);

    VirtualFree(mem, 0, MEM_RELEASE);
}
#endif

#if !defined(_M_X64)
V8I_TEST(Hook_DecodeForCopyRejectsA16BitBranchDisplacement) {
    uint8_t* mem = MakeStub();
    REQUIRE(mem != nullptr);
    // 66 E9 00 00: jmp with a 16-bit displacement. The engine rewrites the
    // immediate as four bytes, so it has to refuse this form (A91: the old code
    // took the "4 bytes" branch and wrote two bytes past the instruction).
    mem[0] = 0x66; mem[1] = 0xE9; mem[2] = 0x00; mem[3] = 0x00;
    mem[4] = 0x90;

    const v8i::CopyInsn ci = v8i::DecodeForCopy((uintptr_t)mem, false);
    CHECK_EQ(ci.immSize, (size_t)2);
    CHECK(ci.isBranch);
    CHECK(ci.unsupportedBranch);

    VirtualFree(mem, 0, MEM_RELEASE);
}
#endif

// ---------------------------------------------------------------------------
// A71: one hook per address, and only our bytes are restored
// ---------------------------------------------------------------------------

V8I_TEST(Hook_RefusesASecondHookOnTheSameTarget) {
    v8i::HookRemoveAll();
    uint8_t* mem = MakeStub();
    REQUIRE(mem != nullptr);

    std::string err;
    const uint32_t id = v8i::HookInstall((uintptr_t)mem, "first", err);
    REQUIRE(id != 0);

    std::string err2;
    CHECK_EQ(v8i::HookInstall((uintptr_t)mem, "second", err2), 0u);
    CHECK(err2.find("already hooked") != std::string::npos);

    // A target just inside the first patch is the same case: the old code would
    // have stacked a jump there and left the tail of it installed forever.
    CHECK_EQ(v8i::HookInstall((uintptr_t)mem + 2, "inside", err2), 0u);
    CHECK(err2.find("already hooked") != std::string::npos);

    CHECK(v8i::HookRemove(id));
    CHECK(v8i::HookInstall((uintptr_t)mem, "third", err2) != 0);
    v8i::HookRemoveAll();
    VirtualFree(mem, 0, MEM_RELEASE);
}

V8I_TEST(Hook_DoesNotRestoreBytesThatAreNoLongerItsPatch) {
    v8i::HookRemoveAll();
    uint8_t* mem = MakeStub();
    REQUIRE(mem != nullptr);
    const uint8_t prologue[5] = { mem[0], mem[1], mem[2], mem[3], mem[4] };

    std::string err;
    const uint32_t id = v8i::HookInstall((uintptr_t)mem, "guarded", err);
    REQUIRE(id != 0);

    // Something else rewrites the first byte: a hooker that ignored our
    // rejection, or a manual patch. Restoring the saved prologue over it would
    // destroy whatever is there now.
    uint8_t saved[5];
    memcpy(saved, mem, 5);
    mem[0] = 0xCC;
    CHECK(!v8i::HookRemove(id));
    std::string why;
    CHECK(JsonOk(v8i::HooksCommandToJson(L""), &why));
    CHECK(v8i::HooksCommandToJson(L"").find("\"count\":1") != std::string::npos);

    // Bytes ours again: the removal goes through, and the prologue is back.
    memcpy(mem, saved, 5);
    CHECK(v8i::HookRemove(id));
    CHECK_EQ(memcmp(mem, prologue, 5), 0);
    CHECK(v8i::HooksCommandToJson(L"").find("\"count\":0") != std::string::npos);

    VirtualFree(mem, 0, MEM_RELEASE);
}

// ---------------------------------------------------------------------------
// The engine end to end: a hook runs, records, and is removed cleanly
// ---------------------------------------------------------------------------

V8I_TEST(Hook_RecordsArgumentsAndRestoresTheFunction) {
    v8i::HookRemoveAll();
    uint8_t* mem = MakeStub(42);
    REQUIRE(mem != nullptr);
    const uint8_t prologue[5] = { mem[0], mem[1], mem[2], mem[3], mem[4] };
    StubFn fn = (StubFn)mem;
    CHECK_EQ(fn(), 42u);                       // before the hook

    v8i::TraceCommandToJson(L"--clear");
    InterlockedExchange(&g_observed, 0);
    std::string err;
    const uint32_t id = v8i::HookInstallObserved((uintptr_t)mem, "stub", ObserveCall, err);
    REQUIRE(id != 0);

    CHECK_EQ(fn(), 42u);
    StubFn4 fn4 = (StubFn4)mem;

    // The observer is called for every hooked call; take it from a clean slate
    // so the arguments it last saw belong to the call that was just made.
    InterlockedExchange(&g_observed, 0);
    CHECK_EQ(fn4(0x1111, 0x2222, 0x3333, 0x4444), 42u);

    CHECK_EQ((long long)g_observed, 1ll);
    CHECK_EQ((unsigned long long)g_observedArgs[0], 0x1111ull);
    CHECK_EQ((unsigned long long)g_observedArgs[1], 0x2222ull);
    CHECK_EQ((unsigned long long)g_observedArgs[2], 0x3333ull);
    CHECK_EQ((unsigned long long)g_observedArgs[3], 0x4444ull);

    const std::string trace = v8i::TraceCommandToJson(L"--count 10");
    std::string why;
    CHECK(JsonOk(trace, &why));
    CHECK(trace.find("\"hook\":" + std::to_string(id)) != std::string::npos);
    CHECK(trace.find("\"0x1111\"") != std::string::npos);
    CHECK(trace.find("\"0x2222\"") != std::string::npos);
    CHECK(trace.find("\"0x3333\"") != std::string::npos);
    CHECK(trace.find("\"0x4444\"") != std::string::npos);
    CHECK(trace.find("\"stack\":[\"0x") != std::string::npos);   // A60: chain is walked

    CHECK(v8i::HookRemove(id));
    CHECK_EQ(memcmp(mem, prologue, 5), 0);
    CHECK_EQ(fn(), 42u);                       // and it still runs

    // A71: nothing is recorded after the removal, not even a call that was in
    // flight (the smoke test checks the same thing from outside).
    const long long head = NumAfter(v8i::TraceCommandToJson(L"--count 1"), "head");
    CHECK_EQ(fn(), 42u);
    const long long head2 = NumAfter(v8i::TraceCommandToJson(L"--count 1"), "head");
    CHECK_EQ(head2, head);

    // A74: the block of a removed hook is kept, and counted.
    const std::string hooks = v8i::HooksCommandToJson(L"");
    CHECK(NumAfter(hooks, "retired") >= 1);

    v8i::HookRemoveAll();
    VirtualFree(mem, 0, MEM_RELEASE);
}

// ---------------------------------------------------------------------------
// A70/A90: the trace reply stays inside its budget and the ring survives a clear
// ---------------------------------------------------------------------------

V8I_TEST(Hook_TraceStaysInsideItsBudget) {
    v8i::HookRemoveAll();
    uint8_t* mem = MakeStub(42);
    REQUIRE(mem != nullptr);
    StubFn fn = (StubFn)mem;

    const std::string cleared = v8i::TraceCommandToJson(L"--clear");
    const long long base = NumAfter(cleared, "head");
    REQUIRE(base >= 0);

    std::string err;
    REQUIRE(v8i::HookInstall((uintptr_t)mem, "deep", err) != 0);

    // 1024 records with a full caller chain: the old builder assembled them all
    // and the shared block then refused the whole answer as too large.
    for (int i = 0; i < 1024; ++i) {
        if (DeepCall(30, fn) != 42) { CHECK(false); break; }
    }

    const std::string j = v8i::TraceCommandToJson(L"--count 1024");
    std::string why;
    CHECK(JsonOk(j, &why));
    CHECK(j.size() <= v8i::TraceReplyBudget());
    CHECK(j.size() < v8i::kResponseBytes);

    const long long head = NumAfter(j, "head");
    const long long since = NumAfter(j, "since");
    CHECK_EQ(head, base + 1024);
    CHECK_EQ(since, base);

    // A reply is either complete or says it was cut -- and a cut one names how
    // many records are missing, so a caller knows to ask again with --since.
    const size_t seqCount = CountOf(j, "\"seq\":");
    if (seqCount == (size_t)(head - since)) {
        CHECK(j.find("\"truncated\":true") == std::string::npos);
        CHECK_EQ(NumAfter(j, "dropped"), (long long)-1);
    } else {
        CHECK(j.find("\"truncated\":true") != std::string::npos);
        CHECK_EQ(NumAfter(j, "dropped"), head - since - (long long)seqCount);
    }

    // The reply has to use the budget rather than jump past it. A record with a
    // full chain is around 700 bytes, so 1024 of them cannot fit on x64 and the
    // answer has to be cut there -- the case the old code turned into
    // "response too large". A 32-bit release build omits frame pointers, the
    // chain stays short and the whole answer may fit; then it must be complete,
    // which the branch above already checks.
    CHECK(seqCount > 0);
    const bool nearBudget = j.size() + 1024 > v8i::TraceReplyBudget();
    if (nearBudget) {
        CHECK(seqCount < (size_t)(head - since));
        CHECK(j.find("\"truncated\":true") != std::string::npos);
    }

    v8i::HookRemoveAll();
    VirtualFree(mem, 0, MEM_RELEASE);
}

V8I_TEST(Hook_TrampolineTailKeepsTheStolenResult) {
    v8i::HookRemoveAll();
    // A body that fits entirely in the five stolen bytes:
    //   B8 2A 00 00 00   mov eax, 42
    //   C3               ret
    // The trampoline replays `mov eax, 42` and then has to jump back without
    // touching a register. The old x64 tail loaded the resume address into rax
    // (`mov rax, imm64; jmp rax`) and the hooked function returned the low half
    // of that address instead of 42 -- exactly what MSVC produces for
    // `if (a == 0) return 11; return 22;` (mov eax, 22 ; cmove eax, edx ; ret).
    uint8_t* mem = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    REQUIRE(mem != nullptr);
    mem[0] = 0xB8; mem[1] = 42; mem[2] = mem[3] = mem[4] = 0;
    mem[5] = 0xC3;
    FlushInstructionCache(GetCurrentProcess(), mem, 6);

    StubFn fn = (StubFn)mem;
    CHECK_EQ(fn(), 42u);
    std::string err;
    const uint32_t id = v8i::HookInstall((uintptr_t)mem, "short", err);
    REQUIRE(id != 0);
    CHECK_EQ(fn(), 42u);
    CHECK(v8i::HookRemove(id));
    CHECK_EQ(fn(), 42u);

    VirtualFree(mem, 0, MEM_RELEASE);
}

#if defined(_M_X64)
V8I_TEST(Hook_KeepsTheVectorArgumentsOfTheHookedFunction) {
    v8i::HookRemoveAll();
    // addsd xmm0, xmm0 ; addsd xmm1 ... ; ret -- the whole body is SSE, and the
    // result comes back in xmm0. V8iHookEnter is ordinary C++ (its trace copy
    // moves the record with SSE), so a thunk that does not save xmm0/xmm1 hands
    // the trampoline whatever the reporter left there (A59).
    uint8_t* mem = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    REQUIRE(mem != nullptr);
    const uint8_t code[] = { 0xF2, 0x0F, 0x58, 0xC0,   // addsd xmm0, xmm0
                             0xF2, 0x0F, 0x58, 0xC1,   // addsd xmm0, xmm1
                             0xC3 };                   // ret
    memcpy(mem, code, sizeof(code));
    FlushInstructionCache(GetCurrentProcess(), mem, sizeof(code));

    typedef double (*DoubleFn)(double, double);
    DoubleFn fn = (DoubleFn)mem;
    CHECK(fn(1.5, 2.25) == 5.25);

    std::string err;
    const uint32_t id = v8i::HookInstall((uintptr_t)mem, "sse", err);
    REQUIRE(id != 0);
    CHECK(fn(1.5, 2.25) == 5.25);
    CHECK(v8i::HookRemove(id));
    CHECK(fn(1.5, 2.25) == 5.25);

    VirtualFree(mem, 0, MEM_RELEASE);
}
#endif

// A59: a member function. On x86 `this` travels in ecx, which the old thunk
// loaded the trampoline pointer into after popad -- the hooked function then
// read its field through a HookCtx*. The call here goes through the ordinary
// member syntax, so the compiler puts `this` in the register the convention
// requires.
namespace {
struct ProbeCounter {
    unsigned bias;
    __declspec(noinline) unsigned Add(unsigned v) const { return bias + v; }
};

void* ProbeMethodAddress(unsigned (ProbeCounter::*pm)(unsigned) const) {
    static_assert(sizeof(pm) == sizeof(void*),
                  "a member-function pointer is expected to be one word here");
    union {
        unsigned (ProbeCounter::*pm)(unsigned) const;
        void* raw;
    } u{};
    u.pm = pm;
    return u.raw;
}
}  // namespace

V8I_TEST(Hook_KeepsTheThisPointerOfAMemberFunction) {
    v8i::HookRemoveAll();
    const ProbeCounter c{100};
    // Called through the member-function pointer, so the call definitely goes
    // to the address the hook is installed on (a direct call may be inlined at
    // /O2 even with noinline, which would make the test prove nothing).
    unsigned (ProbeCounter::*pm)(unsigned) const = &ProbeCounter::Add;
    CHECK_EQ((c.*pm)(7), 107u);

    std::string err;
    const uint32_t id = v8i::HookInstall((uintptr_t)ProbeMethodAddress(pm), "thiscall", err);
    REQUIRE(id != 0);
    CHECK_EQ((c.*pm)(7), 107u);
    // The hook has to be on the function that was actually called: a wrong
    // address would leave the test green while proving nothing.
    CHECK(v8i::HooksCommandToJson(L"").find("\"calls\":1") != std::string::npos);
    CHECK(v8i::HookRemove(id));
    CHECK_EQ((c.*pm)(7), 107u);
}

V8I_TEST(Hook_TraceClearMovesTheStartMarker) {
    v8i::HookRemoveAll();
    uint8_t* mem = MakeStub(42);
    REQUIRE(mem != nullptr);
    StubFn fn = (StubFn)mem;

    v8i::TraceCommandToJson(L"--clear");
    std::string err;
    REQUIRE(v8i::HookInstall((uintptr_t)mem, "clear", err) != 0);

    for (int i = 0; i < 5; ++i) fn();

    // Clearing returns the records that existed and moves the start marker: the
    // slots and their seq numbers stay untouched, so a writer that was filling
    // one during the clear cannot make it look like an old record (A90).
    const std::string cleared = v8i::TraceCommandToJson(L"--clear");
    std::string why;
    CHECK(JsonOk(cleared, &why));
    const long long base = NumAfter(cleared, "head");
    CHECK(base >= 5);

    for (int i = 0; i < 3; ++i) fn();

    const std::string after = v8i::TraceCommandToJson(L"--count 1024");
    CHECK(JsonOk(after, &why));
    CHECK_EQ(NumAfter(after, "since"), base);
    CHECK_EQ(CountOf(after, "\"seq\":"), (size_t)3);
    CHECK_EQ(NumAfter(after, "head"), base + 3);

    // A64-style: the head is a number the reader can use as the next --since.
    const std::string since = v8i::TraceCommandToJson(
        L"--count 10 --since " + std::to_wstring(NumAfter(after, "head")));
    CHECK(JsonOk(since, &why));
    CHECK_EQ(CountOf(since, "\"seq\":"), (size_t)0);
    CHECK_EQ(NumAfter(since, "head"), base + 3);

    v8i::HookRemoveAll();
    VirtualFree(mem, 0, MEM_RELEASE);
}
