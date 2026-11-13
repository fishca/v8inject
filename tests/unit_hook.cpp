// The trampoline tail must not touch a register the stolen prologue left live.
//
// The 1C reader thunks are shaped exactly like the stub below:
//
//   mov rax, [rcx]           ; the pointer comes from the argument   <- stolen
//   nop
//   nop
//   jmp qword ptr [rax+8]    ; the next original instruction uses rax <- stays
//
// With a tail of `mov rax, resume; jmp rax` the pointer was overwritten on the
// way back into the function, and `jmp [rax+8]` read through a code address:
// 0xC0000005 inside the target process, which is precisely how the hook broke
// 1C. A tail of `jmp qword ptr [rip+0]` plus an inline address slot changes no
// register at all; this test calls the same shape through HookInstall.

#include "test_runner.h"

#include "v8inject/hook.h"

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <string>

using namespace v8i;

namespace {

constexpr unsigned kSentinel = 0x5A5A1234u;

// The vtable slot the stub tail-calls. rcx is still the object pointer, the
// callee does not care about it: the point is to return a recognisable value.
unsigned VtEntry(void* /*self*/) { return kSentinel; }

// The object layout the stub assumes: [object] -> table, table[1] -> VtEntry.
struct Table {
    void* unused;
    unsigned (*entry)(void*);
};

struct Object {
    Table* table;
};

// 5 bytes are stolen (mov + two nops); the `jmp [rax+8]` stays in the function
// and is the instruction that consumes rax after the trampoline returns.
const uint8_t kStub[] = {
    0x48, 0x8B, 0x01,   // mov rax, qword ptr [rcx]
    0x90, 0x90,         // nop; nop  (pad the stolen window to 5 bytes)
    0xFF, 0x60, 0x08,   // jmp qword ptr [rax+8]
    0xC3,               // ret (not reached; keeps the buffer well-formed)
};

typedef unsigned (*StubFn)(void*);

uint8_t* MakeStub() {
    uint8_t* mem = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;
    memcpy(mem, kStub, sizeof(kStub));
    FlushInstructionCache(GetCurrentProcess(), mem, sizeof(kStub));
    return mem;
}

}  // namespace

V8I_TEST(Hook_TrampolineTailKeepsLiveRax) {
    uint8_t* mem = MakeStub();
    REQUIRE(mem != nullptr);

    Table table = {nullptr, &VtEntry};
    Object obj = {&table};

    StubFn fn = (StubFn)mem;

    // Sanity: without a hook the stub itself returns the sentinel.
    CHECK_EQ(fn(&obj), kSentinel);

    std::string error;
    const uint32_t id = HookInstall((uintptr_t)mem, "rax_live", error);
    if (!id) printf("HookInstall failed: %s\n", error.c_str());
    REQUIRE(id != 0);

    // Through the hook: stub -> trace thunk -> trampoline (mov + nops) -> tail
    // -> `jmp [rax+8]`. rax has to still be obj.table here.
    CHECK_EQ(fn(&obj), kSentinel);

    CHECK(HookRemove(id));
    CHECK_EQ(fn(&obj), kSentinel);

    VirtualFree(mem, 0, MEM_RELEASE);
}
