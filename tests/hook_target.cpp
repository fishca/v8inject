// Disposable target process for the hook tests.
//
// It prints the address of a function with known arguments and then calls it
// forever, so the test can install a hook from outside, read the recorded
// arguments, and confirm the function still runs after the hook is removed.

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static volatile LONG g_calls = 0;

extern "C" __declspec(noinline) unsigned TargetTick(unsigned a, unsigned b,
                                                    unsigned c, unsigned d) {
    InterlockedIncrement(&g_calls);
    return a + b + c + d;
}

// A conditional in the first bytes, so the trampoline has to re-target a branch
// (and widen it to rel32 when the compiler emitted a rel8).
extern "C" __declspec(noinline) unsigned TargetBranchy(unsigned a) {
    if (a == 0) return 11;
    return 22;
}

// A tail call: with optimisation this becomes a bare jmp in the prologue.
extern "C" __declspec(noinline) unsigned TargetTail(unsigned a) {
    return TargetBranchy(a);
}

// A59: a function with double arguments. On x64 they arrive in xmm0-xmm2, which
// the reporter (ordinary C++) is free to destroy; a thunk that does not save
// them lets the trampoline replay the prologue with whatever the reporter left
// in the vector registers. The result is checked in the loop, so a broken thunk
// fails the run instead of passing silently.
extern "C" __declspec(noinline) double TargetDouble(double a, double b, double c) {
    InterlockedIncrement(&g_calls);
    return a * 2.0 + b + c;   // TargetDouble(1.5, 2.25, 0.25) == 5.5
}

// A59: a `__thiscall` member function. On x86 the `this` pointer travels in
// ecx, which the thunk used to load the trampoline pointer into after popad --
// so the hooked function read its field through a HookCtx pointer.
struct Counter {
    unsigned bias;
    __declspec(noinline) unsigned Add(unsigned v) const { return bias + v; }
};

// The address of a non-virtual member function, for `hook <addr>`. A pointer to
// member is one machine word for a single-inheritance non-virtual method, which
// is what the union asserts at compile time.
static void* MethodAddress(unsigned (Counter::*pm)(unsigned) const) {
    static_assert(sizeof(pm) == sizeof(void*),
                  "a member-function pointer is expected to be one word here");
    union {
        unsigned (Counter::*pm)(unsigned) const;
        void* raw;
    } u{};
    u.pm = pm;
    return u.raw;
}

// The compiler is free to turn a conditional into a cmove, so the branch
// relocation cases are covered by a stub whose bytes are known exactly:
//
//   +0   EB 01        jmp short +1       (rel8 branch whose target is INSIDE the
//                                         stolen window: it has to be widened to
//                                         rel32 and mapped to the trampoline
//                                         copy of the instruction it jumps to)
//   +2   90           nop                (skipped by the jmp)
//   +3   E8 rel32     call helper        (rel32 branch, external target)
//   +8   B8 2A000000  mov eax, 42
//   +13  90 ...       nops
//   +19  C3           ret
//   +32  C3           helper: a bare ret
//
// It returns 42, which is what the loop checks.
typedef unsigned (*StubFn)(void);

static StubFn MakeBranchStub() {
    uint8_t* mem = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;

    size_t o = 0;
    mem[o++] = 0xEB; mem[o++] = 0x01;      // jmp short +1 -> +3
    mem[o++] = 0x90;                       // nop
    mem[o++] = 0xE8;                       // call rel32 (immediate filled below)
    const size_t callImm = o;
    o += 4;
    mem[o++] = 0xB8; mem[o++] = 0x2A;      // mov eax, 42
    mem[o++] = 0x00; mem[o++] = 0x00; mem[o++] = 0x00;
    for (int i = 0; i < 6; ++i) mem[o++] = 0x90;   // padding
    mem[o++] = 0xC3;                       // ret

    const size_t helper = 32;
    mem[helper] = 0xC3;                    // helper: ret

    const int32_t rel = (int32_t)((intptr_t)(mem + helper) - (intptr_t)(mem + callImm + 4));
    memcpy(mem + callImm, &rel, 4);
    FlushInstructionCache(GetCurrentProcess(), mem, 64);
    return (StubFn)mem;
}

// A75: a prologue with a RIP-relative operand, which no generated function in
// this file is guaranteed to have. The bytes are fixed, so the relocation
// formula (disp + ripDelta - shift) is exercised exactly:
//
//   +0   EB 01             jmp short +1     (rel8, widened to rel32 when moved)
//   +2   90                nop              (skipped by the jmp)
//   +3   48 8B 05 disp32   mov rax, [rip+disp]  (rip-relative data load)
//   +10  C3                ret
//   +32  qword 43          the datum the operand points at
//
// It returns 43. Installing a hook here steals all ten bytes: the relocated
// load has to read the same datum from the trampoline, and the widening of the
// jmp shifts the load by three bytes inside that trampoline.
#if defined(_M_X64)
static StubFn MakeRipStub() {
    uint8_t* mem = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;

    mem[0] = 0xEB; mem[1] = 0x01;          // jmp short +1 -> +3
    mem[2] = 0x90;                         // nop
    mem[3] = 0x48; mem[4] = 0x8B; mem[5] = 0x05;   // mov rax, [rip+disp32]
    const size_t dispAt = 6;
    mem[10] = 0xC3;                        // ret

    const size_t data = 32;
    const uint64_t value = 43;
    memcpy(mem + data, &value, sizeof(value));

    // The displacement is relative to the end of the instruction (mem + 10).
    const int32_t disp = (int32_t)((intptr_t)(mem + data) - (intptr_t)(mem + 3 + 7));
    memcpy(mem + dispAt, &disp, 4);

    FlushInstructionCache(GetCurrentProcess(), mem, 64);
    return (StubFn)mem;
}
#endif  // _M_X64

static void Fail(const char* what, unsigned got, unsigned want) {
    printf("self-check failed: %s got=%u want=%u\n", what, got, want);
    fflush(stdout);
    exit(3);
}

static void FailDouble(const char* what, double got, double want) {
    printf("self-check failed: %s got=%f want=%f\n", what, got, want);
    fflush(stdout);
    exit(3);
}

// ---- stress mode -----------------------------------------------------------
//
// --stress <ms> turns the target into a multi-threaded hammer: worker threads
// call TargetTick in a tight loop while the main thread keeps the self-checks.
// The stress test on the host side installs and removes hooks while these
// threads run, so the detour engine has to cope with calls arriving from
// several threads at once. A wrong return value in a worker -- the signature
// of a mis-relocated trampoline -- fails the run with exit code 3, like any
// other self-check.

static volatile LONG g_stressStop = 0;
static StubFn g_stub = nullptr;   // set by main before RunStress
static StubFn g_rip = nullptr;    // x64 only

// Every value the loop depends on, in one place so the stress mode and the
// plain mode check exactly the same things. A trampoline that lands on the
// wrong instruction, or a thunk that clobbers an argument register, shows up
// here as a wrong result and fails the run with exit code 3.
static void SelfCheck() {
    if (TargetBranchy(0) != 11) { Fail("TargetBranchy(0)", 0, 11); }
    if (TargetBranchy(5) != 22) { Fail("TargetBranchy(5)", 0, 22); }
    if (TargetTail(0) != 11)    { Fail("TargetTail(0)", 0, 11); }
    if (g_stub() != 42)         { Fail("branch stub", 0, 42); }
#if defined(_M_X64)
    // A75: only x64 has a RIP-relative form to relocate.
    if (g_rip && g_rip() != 43) { Fail("rip-relative stub", 0, 43); }
#endif
    // A59: the double arguments arrive in xmm0-xmm2, the `this` pointer of the
    // member function in ecx on x86.
    const double d = TargetDouble(1.5, 2.25, 0.25);
    if (d != 5.5) FailDouble("TargetDouble", d, 5.5);
    const Counter c{100};
    if (c.Add(7) != 107) Fail("Counter::Add", 0, 107);
}

static DWORD WINAPI StressThread(LPVOID) {
    unsigned mismatches = 0;
    for (unsigned i = 0; !g_stressStop; ++i) {
        const unsigned r = TargetTick(1, 2, 3, 4);
        if (r != 10 && mismatches++ < 3) {
            printf("stress thread saw a wrong result %u\n", r);
            fflush(stdout);
        }
        // Yield now and then so four spinning threads do not starve the main
        // thread (and its self-checks) on a single-core CI runner.
        if ((i & 15) == 0) Sleep(0);
    }
    return mismatches ? 1 : 0;
}

static int RunStress(int durationMs) {
    HANDLE threads[4] = {};
    for (HANDLE& t : threads) t = CreateThread(nullptr, 0, StressThread, nullptr, 0, nullptr);
    for (HANDLE t : threads) {
        if (!t) { printf("cannot start a stress thread\n"); return 5; }
    }

    const DWORD until = GetTickCount() + (DWORD)durationMs;
    while (GetTickCount() < until) {
        // The same self-checks as the plain loop: a trampoline that lands on
        // the wrong instruction fails the run even without the workers.
        SelfCheck();
        Sleep(20);
    }

    InterlockedExchange(&g_stressStop, 1);
    int bad = 0;
    for (HANDLE t : threads) {
        WaitForSingleObject(t, 5000);
        DWORD code = 0;
        GetExitCodeThread(t, &code);
        if (code != 0) ++bad;
        CloseHandle(t);
    }
    printf("stress done calls=%lu mismatches=%d\n",
           (unsigned long)g_calls, bad);
    fflush(stdout);
    return bad ? 6 : 0;
}

int main(int argc, char** argv) {
    // --delay <ms> keeps the function idle after start-up, which is what lets a
    // diagnostic session inspect the generated stub and trampoline before the
    // first hooked call happens.
    // --stress <ms> runs the multi-threaded hammer for that long, then exits
    // (exit code 0 on success) -- the stress test hooks and unhooks while the
    // workers run, and needs the target to finish on its own.
    int delayMs = 0;
    int stressMs = 0;
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--delay") == 0)  delayMs = atoi(argv[i + 1]);
        if (strcmp(argv[i], "--stress") == 0) stressMs = atoi(argv[i + 1]);
    }

    StubFn stub = MakeBranchStub();
    if (!stub) { printf("cannot allocate the test stub\n"); return 4; }
    g_stub = stub;

#if defined(_M_X64)
    g_rip = MakeRipStub();
    if (!g_rip) { printf("cannot allocate the rip-relative stub\n"); return 4; }
#endif

    // The addresses have to be known to the test, and taking them also
    // guarantees the functions are not folded away. %p alone prints bare hex on
    // MSVC, so the 0x prefix is written out: the CLI parses addresses with it.
    // `rip` is 0 on x86, where the case does not exist.
    printf("pid=%lu tick=0x%p branchy=0x%p tail=0x%p stub=0x%p rip=0x%p dbl=0x%p thisptr=0x%p\n",
           (unsigned long)GetCurrentProcessId(),
           (void*)&TargetTick, (void*)&TargetBranchy, (void*)&TargetTail, (void*)stub,
           (void*)g_rip, (void*)&TargetDouble, MethodAddress(&Counter::Add));
    fflush(stdout);

    if (delayMs > 0) Sleep((DWORD)delayMs);

    if (stressMs > 0) return RunStress(stressMs);

    for (;;) {
        TargetTick(0x1111, 0x2222, 0x3333, 0x4444);

        // A trampoline that lands on the wrong instruction would not necessarily
        // crash, so every result is checked: exit code 3 fails the test.
        SelfCheck();

        Sleep(20);
    }
}
