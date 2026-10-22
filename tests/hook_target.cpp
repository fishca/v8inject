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

static void Fail(const char* what, unsigned got, unsigned want) {
    printf("self-check failed: %s got=%u want=%u\n", what, got, want);
    fflush(stdout);
    exit(3);
}

int main(int argc, char** argv) {
    // --delay <ms> keeps the function idle after start-up, which is what lets a
    // diagnostic session inspect the generated stub and trampoline before the
    // first hooked call happens.
    int delayMs = 0;
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--delay") == 0) delayMs = atoi(argv[i + 1]);
    }

    StubFn stub = MakeBranchStub();
    if (!stub) { printf("cannot allocate the test stub\n"); return 4; }

    // The addresses have to be known to the test, and taking them also
    // guarantees the functions are not folded away. %p alone prints bare hex on
    // MSVC, so the 0x prefix is written out: the CLI parses addresses with it.
    printf("pid=%lu tick=0x%p branchy=0x%p tail=0x%p stub=0x%p\n",
           (unsigned long)GetCurrentProcessId(),
           (void*)&TargetTick, (void*)&TargetBranchy, (void*)&TargetTail, (void*)stub);
    fflush(stdout);

    if (delayMs > 0) Sleep((DWORD)delayMs);

    for (;;) {
        TargetTick(0x1111, 0x2222, 0x3333, 0x4444);

        // A trampoline that lands on the wrong instruction would not necessarily
        // crash, so every result is checked: exit code 3 fails the test.
        unsigned b0 = TargetBranchy(0);
        if (b0 != 11) Fail("TargetBranchy(0)", b0, 11);
        unsigned b5 = TargetBranchy(5);
        if (b5 != 22) Fail("TargetBranchy(5)", b5, 22);

        unsigned t = TargetTail(0);
        if (t != 11) Fail("TargetTail(0)", t, 11);

        // The hand-written stub: exercises rel32 call, rel8 jmp widening and an
        // internal branch target. A mis-relocated trampoline shows up here.
        unsigned s = stub();
        if (s != 42) Fail("branch stub", s, 42);

        Sleep(20);
    }
}
