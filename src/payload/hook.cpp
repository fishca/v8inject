#include "v8inject/hook.h"

#include "v8inject/diag.h"
#include "v8inject/disasm.h"
#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"
#include "v8inject/text.h"

#include <windows.h>
#include <tlhelp32.h>

// x64 has no inline assembly, so the caller chain is unwound from a context
// built from the hook frame; _AddressOfReturnAddress() is how that frame finds
// its own return-address slot. The unwind itself uses the kernel32 unwind
// primitives declared by winnt.h (RtlLookupFunctionEntry/RtlVirtualUnwind).
#include <intrin.h>

#include <cstdio>
#include <cstring>
#include <new>
#include <string>

namespace v8i {

namespace {

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

#if defined(_M_X64)
// jmp rel32. The stub is always allocated within +-2 GB of the target
// (AllocNear), so a 32-bit displacement reaches it and a 12-byte absolute jump
// would only overwrite more of the function than necessary.
constexpr size_t kPatchLen = 5;
#else
// jmp rel32 -- the stub has to live within +-2 GB of the target.
constexpr size_t kPatchLen = 5;
#endif

// A prologue longer than this is not a prologue we want to move.
constexpr size_t kMaxStolen = 24;

// Fixed limits instead of growable containers: the payload is a guest in another
// process, so its registry must not depend on dynamic initialisation or on the
// heap working the same way there.
constexpr int kMaxHooks = 64;
constexpr int kMaxPlan = 16;      // instructions in one stolen prologue

// One block per hook: stub at 0, indirect slot at 32, trampoline at 64.
// Everything the hook needs sits in a single allocation near the target. The
// request is 256 bytes, but a block is always a whole VirtualAlloc'ed page
// (4 KiB) -- the comment here used to call 256 bytes "a page-sized block",
// which made the cost of a retired hook look 16x smaller than it is (A74).
constexpr size_t kBlockSize = 256;
constexpr size_t kSlotOffset = 32;
constexpr size_t kTrampOffset = 64;

constexpr size_t kTraceCapacity = 1024;

// Budget for one trace reply. The shared block holds kResponseBytes (512 KiB)
// and a reply that does not fit is refused whole, so 1024 records with full
// caller chains would turn a working --count 1024 into "response too large".
// The reply is therefore cut here, with "truncated":true in the answer (A70).
// 448 KiB leaves room for the envelope and the last record.
constexpr size_t kTraceBudget = 448 * 1024;

// Caller frames recorded per trace slot. This is the budget of the frame walk
// and of the JSON report: one number, so the walk can never outrun the record.
constexpr int kMaxFrames = 24;

#if defined(_M_X64)
extern "C" void V8iThunkX64();
#define V8I_THUNK V8iThunkX64
#else
extern "C" void V8iThunkX86();
#define V8I_THUNK V8iThunkX86
#endif

// ---------------------------------------------------------------------------
// Trace ring
//
// Written from arbitrary threads inside the target process, so it is a seqlock
// per slot: the writer bumps seq to an odd value, fills the record, bumps it
// back to even. A reader takes a whole copy between the two reads of seq and
// throws it away when they differ, instead of blocking anyone. A lost record is
// acceptable; a stalled hooked function is not.
//
// Both counters are 64-bit and monotonic (A90): the old `LONG` head wrapped at
// 2^31 records, after which the whole ring looked empty, and `trace --clear`
// used to zero the head and every seq -- while a writer was mid-record that set
// a slot's generation back a full wrap, so the slot could be read as valid one
// generation late. Clearing now only moves `base` forward; writers are never
// disturbed and old records are simply out of range.
// ---------------------------------------------------------------------------

struct TraceSlot {
    volatile LONG64 seq;      // odd while a writer is filling the slot
    uint64_t  idx;            // absolute record number this slot holds
    uint32_t  id;
    uint32_t  tid;
    uint64_t  tick;
    uintptr_t retAddr;
    uintptr_t args[4];
    // Return-address chain above the hooked function's caller: frame[0] is the
    // address its caller returns to, frame[1] the address that frame returns
    // to, and so on -- it maps WHO called the hooked function and their
    // callers, each attributable to a module. Filled by WalkFramesX64 or
    // WalkFramesX86, both of which truncate the chain instead of faulting.
    uintptr_t frame[kMaxFrames];
    int       frameCount;
};

// One record, copied out of a slot between two reads of its seq.
struct TraceRecord {
    uint64_t  idx;
    uint32_t  id;
    uint32_t  tid;
    uint64_t  tick;
    uintptr_t retAddr;
    uintptr_t args[4];
    uintptr_t frame[kMaxFrames];
    int       frameCount;
};

TraceSlot      g_slots[kTraceCapacity];
volatile LONG64 g_head = 0;       // records ever written, also the next index
volatile LONG64 g_base = 0;       // first record a reader may still see

struct HookCtx {
    void*     trampoline = nullptr;   // offset 0: the thunks read [ctx]
    uintptr_t stub = 0;
    void*     block = nullptr;
    uintptr_t target = 0;
    size_t    stolen = 0;
    uint32_t  id = 0;
    volatile LONG logged = 0;   // disk-logged hits (capped to avoid flooding)
    volatile LONG active = 0;    // read by V8iHookEnter on arbitrary threads
    HookObserver obs = nullptr;   // optional per-hook observer
    uint8_t   original[kMaxStolen + 8] = {};
    uint8_t   patch[kPatchLen] = {};   // what we wrote, to verify before restore
    char      name[64] = {};
    volatile LONG calls = 0;
};

// A plain SRW lock, not std::mutex: the payload runs inside a foreign process
// that may already have loaded its own (older) MSVCP140, and the C++ mutex
// then faults inside that DLL's _Mtx_lock. SRWLOCK lives in kernel32, needs no
// constructor, and is zero-initialised by the loader.
SRWLOCK               g_lock = SRWLOCK_INIT;
HookCtx*              g_hooks[kMaxHooks];
int                   g_hookCount = 0;
volatile LONG         g_nextId = 1;   // ids are taken before the bytes change

// Blocks handed out to hooks. They are never freed (a thread may still be
// inside a trampoline when the detour is removed), so this list is append-only
// and can be read by the fault logger without a lock: it exists to answer one
// question -- is this fault inside code the engine owns -- and a stale entry is
// harmless because the memory is still mapped.
constexpr int kMaxBlockRanges = 512;
struct BlockRange {
    uintptr_t lo = 0;
    uintptr_t hi = 0;
};
BlockRange            g_blockRanges[kMaxBlockRanges];
volatile LONG         g_blockRangeCount = 0;

// A74: retirement accounting. Every removed hook keeps its block (4 KiB) and
// its HookCtx for the rest of the process lifetime, which is the price of not
// freeing memory a thread may be executing. Cheap for a session that installs a
// handful of hooks, unbounded for a script that installs and removes in a loop
// -- so both counters are reported by the `hooks` command and logged on every
// removal instead of being silently paid.
volatile LONG         g_retiredBlocks = 0;
volatile LONG64       g_retiredBytes = 0;

struct LockGuard {
    LockGuard() { AcquireSRWLockExclusive(&g_lock); }
    ~LockGuard() { ReleaseSRWLockExclusive(&g_lock); }
    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;
};

// A100: install and remove both suspend EVERY thread of the process inside
// their window, and three payload threads can start them (the command loop,
// the native-menu worker, the early-subscribe worker). Run in parallel, two
// windows suspend each other mid-cycle and deadlock with the frozen 1C threads
// behind them. The window itself is serialized: the second operation waits in
// kernel space and proceeds right after the first one has resumed everything.
// Never held together with g_lock from the other side (the registry lock is
// taken inside this one, never before it).
SRWLOCK g_patchLock = SRWLOCK_INIT;
struct PatchWindowGuard {
    PatchWindowGuard() { AcquireSRWLockExclusive(&g_patchLock); }
    ~PatchWindowGuard() { ReleaseSRWLockExclusive(&g_patchLock); }
    PatchWindowGuard(const PatchWindowGuard&) = delete;
    PatchWindowGuard& operator=(const PatchWindowGuard&) = delete;
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

#if defined(_M_X64)
inline uintptr_t IpOf(const CONTEXT& c) { return (uintptr_t)c.Rip; }
#else
inline uintptr_t IpOf(const CONTEXT& c) { return (uintptr_t)c.Eip; }
#endif

std::string Narrow(const std::wstring& w) {
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w) out.push_back(c < 0x80 ? (char)c : '?');
    return out;
}

uintptr_t ParseHexToken(const std::wstring& t) {
    std::wstring s = t;
    if (s.size() > 2 && s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s = s.substr(2);
    return (uintptr_t)_wcstoui64(s.c_str(), nullptr, 16);
}

// Splits on spaces. The payload owns the command grammar, so every command
// handler carries its own tiny tokenizer.
struct Tokenizer {
    std::wstring rest;
    explicit Tokenizer(const std::wstring& s) : rest(s) {}
    std::wstring Next() {
        while (!rest.empty() && (rest.front() == L' ' || rest.front() == L'\t')) rest.erase(rest.begin());
        if (rest.empty()) return std::wstring();
        size_t sp = rest.find(L' ');
        std::wstring t = sp == std::wstring::npos ? rest : rest.substr(0, sp);
        rest = sp == std::wstring::npos ? std::wstring() : rest.substr(sp);
        return t;
    }
};

// Pauses every other thread of this process for the duration of the patch, and
// refuses to patch when one of them is executing the bytes about to be
// overwritten -- resuming such a thread would land it in the middle of a jump
// we just wrote.
//
// Lifecycle audit (plan_roadmap Ф1.4, 2026-11-14). The risks of suspending a
// process to patch its code, and what became of each:
//
// 1. A thread *inside* the stolen window at snapshot time is caught by the IP
//    check below; the patch is refused and the caller reports "try again".
// 2. A thread created *after* the snapshot but before the write is not in the
//    list. The window between the snapshot and the 5-byte write is a few
//    microseconds; the residual risk is documented and accepted for a
//    diagnostic tool whose targets are chosen by the user, not hot internal
//    functions of 1C. The stress test (tests/hook_stress.ps1) hammers the
//    target from four threads across repeated install/remove cycles to keep
//    this honest.
// 3. A thread already executing the trampoline when a hook is removed is
//    safe: the trampoline block is deliberately never freed (HookRemove).
// 4. The heap lock: nothing allocates between Suspend and ResumeAll -- the
//    fixed handles_ array exists for exactly that reason, and the failure
//    reasons below are return codes rather than std::string (A72): building a
//    >15-character error text allocates, and it used to happen *before*
//    ResumeAll, while every other thread was still frozen holding whatever
//    lock the allocator needed.
class Suspender {
public:
    enum class Result {
        ok,
        snapshotFailed,
        threadInPrologue,
        tooManyThreads,
    };

    ~Suspender() { ResumeAll(); }

    Result Suspend(uintptr_t lo, uintptr_t hi) {
        DWORD self = GetCurrentThreadId();
        DWORD pid = GetCurrentProcessId();

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            ResumeAll();
            return Result::snapshotFailed;
        }

        Result result = Result::ok;
        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                if (te.th32ThreadID == self) continue;

                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                      FALSE, te.th32ThreadID);
                if (!h) continue;
                if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); continue; }

                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(h, &ctx)) {
                    uintptr_t ip = IpOf(ctx);
                    if (ip >= lo && ip < hi) {
                        ResumeThread(h);
                        CloseHandle(h);
                        result = Result::threadInPrologue;
                        break;
                    }
                }
                if (count_ >= kMaxThreads) {
                    // More threads than we can track: put this one back and fail
                    // rather than patch with a thread left suspended.
                    ResumeThread(h);
                    CloseHandle(h);
                    result = Result::tooManyThreads;
                    break;
                }
                handles_[count_++] = h;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);

        // Every thread we suspended goes back before the caller builds an
        // error text: see point 4 above (A72).
        if (result != Result::ok) ResumeAll();
        return result;
    }

    void ResumeAll() {
        for (int i = 0; i < count_; ++i) {
            ResumeThread(handles_[i]);
            CloseHandle(handles_[i]);
        }
        count_ = 0;
    }

private:
    // A fixed array, not std::vector: push_back would allocate while the other
    // threads are already suspended, and one of them may hold the heap lock.
    static constexpr int kMaxThreads = 1024;
    HANDLE handles_[kMaxThreads] = {};
    int    count_ = 0;
};

// Why a patch was refused, as a message. Called only after every thread is
// running again, so the allocation it does is safe.
const char* SuspendReason(Suspender::Result r) {
    switch (r) {
    case Suspender::Result::ok:               return "";
    case Suspender::Result::snapshotFailed:   return "thread snapshot failed";
    case Suspender::Result::threadInPrologue: return "a thread is executing the prologue; try again";
    case Suspender::Result::tooManyThreads:   return "too many threads to suspend safely";
    }
    return "thread suspension failed";
}

// Nothing inside this window may allocate or log: the other threads are paused,
// and one of them may hold the heap lock.
bool PatchBytes(uintptr_t addr, const void* bytes, size_t len) {
    DWORD old = 0;
    if (!VirtualProtect((void*)addr, len, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy((void*)addr, bytes, len);
    FlushInstructionCache(GetCurrentProcess(), (void*)addr, len);
    DWORD ignored = 0;
    VirtualProtect((void*)addr, len, old, &ignored);
    return true;
}

// Reserves a page within +-2 GB of `anchor`. Both architectures need that: x86
// reaches the stub with rel32, and a relocated rip-relative operand only works
// while the trampoline sits inside the +-2 GB its disp32 can address.
// (`near` would be a bad name here: windef.h still defines it as a macro.)
void* AllocNear(uintptr_t anchor, size_t size) {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    uintptr_t base = anchor & ~(gran - 1);

    for (uintptr_t delta = gran; delta < 0x40000000ULL; delta += gran) {
        for (int dir = 0; dir < 2; ++dir) {
            uintptr_t cand = dir == 0 ? (base > delta ? base - delta : 0) : base + delta;
            if (!cand) continue;
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery((void*)cand, &mbi, sizeof(mbi)) != sizeof(mbi)) continue;
            if (mbi.State != MEM_FREE) continue;
            void* p = VirtualAlloc((void*)cand, size, MEM_RESERVE | MEM_COMMIT,
                                   PAGE_EXECUTE_READWRITE);
            if (p) return p;
        }
    }
    return nullptr;
}

// Builds the stub: the per-hook trampoline into the shared thunk, carrying the
// hook context so the thunk knows which record to write.
size_t BuildStub(uint8_t* block, void* ctx) {
#if defined(_M_X64)
    uint8_t* p = block;
    p[0] = 0x50;                                  // push rax (the thunk restores it)
    p[1] = 0x48; p[2] = 0xB8;                     // mov rax, imm64
    uint64_t c = (uint64_t)(uintptr_t)ctx;
    memcpy(p + 3, &c, 8);
    p[11] = 0xFF; p[12] = 0x25;                   // jmp qword ptr [rip+0]
    p[13] = p[14] = p[15] = p[16] = 0;
    uint64_t thunk = (uint64_t)(uintptr_t)&V8I_THUNK;
    memcpy(p + 17, &thunk, 8);
    return 25;
#else
    uint8_t* p = block;
    p[0] = 0x68;                                  // push imm32 (ctx)
    uint32_t c = (uint32_t)(uintptr_t)ctx;
    memcpy(p + 1, &c, 4);
    p[5] = 0xFF; p[6] = 0x25;                     // jmp dword ptr [imm32]
    uint32_t slot = (uint32_t)(uintptr_t)(block + kSlotOffset);
    memcpy(p + 7, &slot, 4);
    // The thunk lives in the payload DLL, which may sit outside the +-2 GB a
    // relative jmp can reach, so the address goes through an indirect slot.
    uint32_t thunk = (uint32_t)(uintptr_t)&V8I_THUNK;
    memcpy(block + kSlotOffset, &thunk, 4);
    return 11;
#endif
}

// Bytes that take control from the trampoline back to the first untouched
// instruction. Returns 0 when the jump cannot be encoded (the caller then drops
// the hook instead of installing one that would jump to the wrong place).
size_t BuildTrampolineTail(uint8_t* at, uintptr_t resume) {
#if defined(_M_X64)
    // A relative jump, not `mov rax, imm64 / jmp rax`: the register form
    // destroys rax, which the stolen prologue may still be carrying. MSVC
    // compiles `if (a == 0) return 11; return 22;` to
    //   mov eax, 22 ; mov edx, 11 ; cmove eax, edx ; ret
    // so the return value is *in rax* when the trampoline takes over; the old
    // tail made the hooked function return the low half of the jump target
    // instead. The block is allocated within +-1 GB of the target (AllocNear)
    // and `resume` is a few bytes past it, so a rel32 always reaches.
    const int64_t rel = (int64_t)resume - (int64_t)(at + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) return 0;
    at[0] = 0xE9;
    int32_t r = (int32_t)rel;
    memcpy(at + 1, &r, 4);
    return 5;
#else
    at[0] = 0xE9;
    int32_t rel = (int32_t)((intptr_t)resume - (intptr_t)(at + 5));
    memcpy(at + 1, &rel, 4);
    return 5;
#endif
}

}  // namespace

// ---------------------------------------------------------------------------
// Caller chain (audit item A60)
//
// The record keeps up to kMaxFrames return addresses of the frames above the
// hooked function. Two properties matter here:
//
//  * A range check is only a snapshot: IsReadable() asks the kernel about the
//    protection right now, and the memory can still go away -- or the second
//    word can sit past the end of the mapping -- before the read lands. So the
//    walk lives in a POD-only helper under __try/__except: a fault truncates
//    the chain instead of taking the host process down. POD-only because MSVC
//    refuses __try in a function that needs C++ unwinding (C2712), and because
//    a frame abandoned by SEH must not own C++ objects.
//
//  * On x64 rbp is not a frame pointer: MSVC addresses locals through rsp and
//    keeps rbp as an ordinary callee-saved register, so the rbp captured at
//    hook entry is an arbitrary value that must never be dereferenced as [rbp].
//    The chain is unwound the way Windows unwinds its own: RtlLookupFunctionEntry
//    plus RtlVirtualUnwind from the caller's context. Those are kernel32 exports
//    (checked with dumpbin: kernel32.lib exports both for x64), so no extra
//    library -- DbgHelp and StackWalk64 are not needed. x86 keeps the ebp walk.
// ---------------------------------------------------------------------------

namespace {

#if defined(_M_X64)

// The stack frame hook_thunk_x64.asm builds between its `call V8iHookEnter` and
// the hooked function's entry point: the thunk reserves 0x100 bytes (it also
// saves xmm0-5 for A59) and the stub pushes the caller's rax. This is a layout
// contract with the .asm file, so the walk validates it instead of trusting it:
// if the two no longer agree with the real stack (a thunk that saves more
// registers, say), the return-address check below fails and the chain is
// reported empty rather than walked over garbage.
constexpr uintptr_t kX64ThunkFrame = 0x100;
constexpr uintptr_t kX64StubPush   = sizeof(uintptr_t);

// Fills out[] with the return addresses of the frames above the hooked
// function's caller. `retSlot` is the address of V8iHookEnter's own return
// address (_AddressOfReturnAddress, taken in V8iHookEnter itself -- inside this
// helper it would be this helper's slot), `entryRb` is rbp at hook entry, which
// is the caller's rbp at the call site.
int WalkFramesX64(uintptr_t retAddr, uintptr_t retSlot, uintptr_t entryRb,
                  uintptr_t* out, int maxFrames) {
    int n = 0;
    __try {
        // The thunk's rsp at its `call V8iHookEnter` is one word above the slot
        // that call wrote; the hooked function's entry rsp is kX64ThunkFrame
        // plus the stub's push above that.
        const uintptr_t entryRsp =
            retSlot + sizeof(uintptr_t) + kX64ThunkFrame + kX64StubPush;
        if (retAddr && IsReadable((const void*)entryRsp, sizeof(uintptr_t)) &&
            *(const uintptr_t*)entryRsp == retAddr) {
            // The caller's state at the instant its call to the hooked function
            // returned: rip is where it resumes, rsp is what it has after the
            // call popped the return address, rbp is the value it had at the
            // call site (the hooked function's prologue has not run yet, and
            // rbp is callee-saved, so the thunk's copy is that same value).
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            ctx.Rip = (DWORD64)retAddr;
            ctx.Rsp = (DWORD64)(entryRsp + sizeof(uintptr_t));
            ctx.Rbp = (DWORD64)entryRb;

            for (; n < maxFrames; ++n) {
                DWORD64 imageBase = 0;
                PRUNTIME_FUNCTION fn =
                    RtlLookupFunctionEntry((DWORD64)ctx.Rip, &imageBase, nullptr);
                const DWORD64 frameRsp = ctx.Rsp;
                if (fn) {
                    PVOID handlerData = nullptr;
                    DWORD64 establisher = 0;
                    RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, (DWORD64)ctx.Rip, fn,
                                     &ctx, &handlerData, &establisher, nullptr);
                } else {
                    // No unwind data: treat it as a leaf frame, whose return
                    // address is the first word of its stack frame.
                    if (!IsReadable((const void*)(uintptr_t)ctx.Rsp, sizeof(uintptr_t))) break;
                    ctx.Rip = *(const DWORD64*)(uintptr_t)ctx.Rsp;
                    ctx.Rsp += sizeof(uintptr_t);
                }
                // A frame that does not move the stack up, or that unwinds to
                // nothing, is the end of the usable chain.
                if (ctx.Rsp <= frameRsp || !ctx.Rip) break;
                out[n] = (uintptr_t)ctx.Rip;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Whatever was collected before the fault is the result: a truncated
        // chain is the contract, a crash in the host process is not.
    }
    return n;
}

#else

// x86: rbp is a real frame pointer, so the chain still walks the ebp records.
// The range check covers both words a step reads -- [fp] and [fp+4] -- because
// a frame record can straddle the end of a mapping, and virtual memory does not
// guarantee that the second word is mapped just because the first one is.
int WalkFramesX86(uintptr_t entryEb, uintptr_t* out, int maxFrames) {
    int n = 0;
    __try {
        uintptr_t fp = entryEb;
        for (; n < maxFrames; ++n) {
            if (!fp || !IsReadable((const void*)fp, 2 * sizeof(uintptr_t))) break;
            const uintptr_t next = *(const uintptr_t*)fp;
            if (next <= fp || next > fp + 0x200000) break;  // must ascend, bounded
            out[n] = *(const uintptr_t*)(fp + sizeof(uintptr_t));
            fp = next;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Truncated chain, same contract as the x64 walk.
    }
    return n;
}

#endif

}  // namespace

// ---------------------------------------------------------------------------
// The recording entry point. Called from assembly on every hooked call.
// ---------------------------------------------------------------------------

extern "C" void V8iHookEnter(void* ctx, void* retAddr, uintptr_t entryEb,
                             uintptr_t a0, uintptr_t a1, uintptr_t a2,
                             uintptr_t a3) {
    HookCtx* c = (HookCtx*)ctx;
    if (!c) return;
    // A hook can be removed while a thread is on its way through the stub: the
    // bytes are restored, but this call is already inside the engine. It must
    // not record anything then -- an in-flight call would show up in a trace
    // taken after `unhook all` (A71).
    if (InterlockedCompareExchange(&c->active, 0, 0) == 0) return;

    // The observer runs first: it is the reason some hooks exist at all (the
    // 8.5 early subscription watches for the designer's first window), and it
    // has to see the call before the function does anything with it.
    if (c->obs) c->obs(a0, a1, a2, a3);

    InterlockedIncrement(&c->calls);

    const LONG64 idx = InterlockedIncrement64(&g_head) - 1;
    TraceSlot& s = g_slots[(uint64_t)idx % kTraceCapacity];

    InterlockedIncrement64(&s.seq);               // odd: write in progress
    s.idx = (uint64_t)idx;
    s.id = c->id;
    s.tid = GetCurrentThreadId();
    s.tick = GetTickCount64();
    s.retAddr = (uintptr_t)retAddr;
    s.args[0] = a0;
    s.args[1] = a1;
    s.args[2] = a2;
    s.args[3] = a3;
    // Walk the caller chain. Each architecture uses the mechanism it actually
    // has: x64 unwinds through the exception directory from the caller's
    // context, because there is no frame pointer to follow; x86 follows the ebp
    // records. Both run inside a POD-only SEH frame, so a range check that went
    // stale (or a frame record cut by the end of a mapping) costs the rest of
    // the chain and nothing else.
    int n = 0;
#if defined(_M_X64)
    // _AddressOfReturnAddress() has to be read here, in this function's frame:
    // inside the helper it would name the helper's own return-address slot.
    n = WalkFramesX64((uintptr_t)retAddr, (uintptr_t)_AddressOfReturnAddress(),
                      entryEb, s.frame, kMaxFrames);
#else
    n = WalkFramesX86(entryEb, s.frame, kMaxFrames);
#endif
    s.frameCount = n;
    InterlockedIncrement64(&s.seq);               // even: record complete

    // Disk trace: the target process may die inside the hooked function (a
    // crash there leaves the in-memory ring unreadable), so persist the first
    // few hits with their arguments and caller frames. Uncapped logging inside
    // a hot hook (e.g. CreateWindowExW) floods the log and stalls the payload.
    // A101: the counter is signed and incremented on every call -- after 2^31
    // hits of a hot function it wrapped negative and the cap stopped working,
    // every call logging two lines again until the next wrap. Compare unsigned.
    if ((unsigned)InterlockedIncrement(&c->logged) > 3u) return;
    LogLine("hit id=%u target=%p ret=%p a0=%p a1=%p a2=%p a3=%p",
            (unsigned)c->id, (void*)c->target, (void*)retAddr,
            (void*)a0, (void*)a1, (void*)a2, (void*)a3);
    LogLine("  frames: %p %p %p %p",
            (void*)(n > 0 ? s.frame[0] : 0), (void*)(n > 1 ? s.frame[1] : 0),
            (void*)(n > 2 ? s.frame[2] : 0), (void*)(n > 3 ? s.frame[3] : 0));
}

// ---------------------------------------------------------------------------
// Fault diagnostics
//
// A crash inside a hooked function is invisible to the host: the process simply
// disappears and the log stops mid-command. A vectored handler that only
// records the context turns that into a line the log can explain.
//
// A73: the handler sees every exception of the host process, and a real 1C
// probes SEH paths routinely (and raises AVs on purpose). Logging each one
// filled the log and slowed the host down. Two limits now apply: a fault that
// lands inside code the engine owns is always logged (it is the signal this
// handler exists for), everything else is capped at a fixed number of entries
// and then summarised once.
// ---------------------------------------------------------------------------

namespace {

constexpr LONG kMaxForeignFaults = 32;   // logged, then suppressed
constexpr LONG kMaxOwnFaults     = 16;   // faults inside our own blocks

// True when `p` lies inside a block the engine allocated. Reads only immutable
// numbers: blocks are never freed, so a stale entry is still a mapped range and
// conservative in the right direction.
bool InOwnedBlock(uintptr_t p) {
    if (!p) return false;
    LONG n = InterlockedCompareExchange(&g_blockRangeCount, 0, 0);
    if (n > kMaxBlockRanges) n = kMaxBlockRanges;
    for (LONG i = 0; i < n; ++i) {
        if (p >= g_blockRanges[i].lo && p < g_blockRanges[i].hi) return true;
    }
    return false;
}

LONG CALLBACK FaultLogger(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;
    EXCEPTION_RECORD* r = ep->ExceptionRecord;
    if (r->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
        r->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION &&
        r->ExceptionCode != EXCEPTION_PRIV_INSTRUCTION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    uintptr_t av = 0;
    if (r->NumberParameters >= 2) av = (uintptr_t)r->ExceptionInformation[1];
    const uintptr_t at = (uintptr_t)r->ExceptionAddress;

    static volatile LONG foreign = 0;
    static volatile LONG own = 0;
    const bool ours = InOwnedBlock(at) || InOwnedBlock(av);
    if (ours) {
        const LONG n = InterlockedIncrement(&own);
        if (n > kMaxOwnFaults) {
            // A103: mirror the foreign branch — a series of faults in hook code
            // must not look like "it healed itself" after the 16th entry.
            if (n == kMaxOwnFaults + 1) {
                LogLine("fault logging: %ld more hook-code faults suppressed",
                        kMaxOwnFaults);
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }
    } else {
        const LONG n = InterlockedIncrement(&foreign);
        if (n > kMaxForeignFaults) {
            // One line, once: the host's own SEH traffic is not our business,
            // but a reader of the log should know it was dropped.
            if (n == kMaxForeignFaults + 1) {
                LogLine("fault logging: %ld more host faults suppressed (no hook involved)",
                        kMaxForeignFaults);
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    CONTEXT* c = ep->ContextRecord;
#if defined(_M_X64)
    LogLine("fault%s code=0x%08lX at rip=%p av=%p rax=%p rcx=%p rdx=%p rsp=%p rbp=%p",
            ours ? " (in hook code)" : "", r->ExceptionCode, r->ExceptionAddress, (void*)av,
            (void*)c->Rax, (void*)c->Rcx, (void*)c->Rdx, (void*)c->Rsp, (void*)c->Rbp);
#else
    LogLine("fault%s code=0x%08lX at eip=%p av=%p eax=%08lX ecx=%08lX edx=%08lX esp=%08lX ebp=%08lX",
            ours ? " (in hook code)" : "", r->ExceptionCode, r->ExceptionAddress, (void*)av,
            c->Eax, c->Ecx, c->Edx, c->Esp, c->Ebp);
#endif
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

void HookInstallFaultLogger() {
    static bool installed = false;
    if (installed) return;
    installed = true;
    AddVectoredExceptionHandler(1, FaultLogger);
}

// ---------------------------------------------------------------------------
// Install / remove
// ---------------------------------------------------------------------------

uint32_t HookInstall(uintptr_t target, const char* name, std::string& error) {
    return HookInstallObserved(target, name, nullptr, error);
}

namespace {

// A71: two hooks may not overlap. The second one used to be installed on top
// of the first -- its "original" bytes were the first hook's jump, so `unhook
// all` restored the true prologue for the first and the patched bytes for the
// second, and the target stayed patched for the rest of the process.
// Caller holds g_lock.
const HookCtx* FindOverlappingLocked(uintptr_t target, size_t len) {
    for (int i = 0; i < g_hookCount; ++i) {
        const HookCtx* h = g_hooks[i];
        const uintptr_t lo = h->target;
        const uintptr_t hi = h->target + (h->stolen ? h->stolen : kPatchLen);
        if (target < hi && lo < target + len) return h;
    }
    return nullptr;
}

// Remembers a block so the fault logger can recognise a fault inside the engine.
void RecordBlockRange(void* block) {
    const LONG i = InterlockedIncrement(&g_blockRangeCount) - 1;
    if (i >= kMaxBlockRanges) return;
    g_blockRanges[i].lo = (uintptr_t)block;
    g_blockRanges[i].hi = (uintptr_t)block + kBlockSize;
}

}  // namespace

// Why the guarded verify-and-restore of `unhook` refused. Every refusal keeps
// the hook registered (a hook that is still patched must stay visible to
// `hooks`) and the caller reports the reason.
enum PrologueRestore {
    kRestoreOk = 0,
    kRestoreUnreadable,    // the target is no longer readable: the module with
                           // the hook in it was unloaded (A99)
    kRestoreForeignBytes,  // the prologue is no longer our patch (A71)
    kRestorePatchFailed,   // VirtualProtect/memcpy back refused
    kRestoreFaulted,       // SEH caught a fault inside the window (A99)
};

// POD-only frame of the verify-and-restore window (C2712: no C++ object that
// needs unwinding may live where __try does). The bytes are read while every
// other thread of the process is suspended, and a module with a hook in it may
// have been unloaded since the hook was installed -- so the read is guarded and
// the SEH frame sits BELOW the Suspender frame: whatever faults here, control
// comes back and the caller resumes the threads instead of leaving the whole
// process frozen behind a dead frame (A99).
struct PrologueRestoreCall {
    uintptr_t target;
    const uint8_t* patch;
    const uint8_t* original;
    size_t stolen;
    uint8_t nowBytes[kMaxStolen];
    PrologueRestore status;
};

static void RestorePrologueUnderSeh(PrologueRestoreCall* call) {
    __try {
        const void* p = (const void*)call->target;
        if (!IsReadable(p, call->stolen)) {
            call->status = kRestoreUnreadable;
            return;
        }
        memcpy(call->nowBytes, p, call->stolen);
        if (memcmp(call->nowBytes, call->patch, kPatchLen) != 0) {
            call->status = kRestoreForeignBytes;
            return;
        }
        call->status = PatchBytes(call->target, call->original, call->stolen)
                           ? kRestoreOk : kRestorePatchFailed;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        call->status = kRestoreFaulted;
    }
}

uint32_t HookInstallObserved(uintptr_t target, const char* name, HookObserver obs,
                             std::string& error) {
    if (!target) { error = "null target"; return 0; }
    if (g_hookCount >= kMaxHooks) { error = "hook limit reached"; return 0; }

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((void*)target, &mbi, sizeof(mbi))) { error = "VirtualQuery failed"; return 0; }
    if (mbi.State != MEM_COMMIT) { error = "target is not committed memory"; return 0; }
    if (!((mbi.Protect & 0xFF) & 0xF0)) { error = "target is not executable"; return 0; }

    // Cheap first pass, before any allocation: the same address twice is the
    // common mistake (a script that hooks the same export in two commands).
    {
        LockGuard guard;
        if (const HookCtx* h = FindOverlappingLocked(target, kPatchLen)) {
            char b[160];
            _snprintf_s(b, sizeof(b), _TRUNCATE,
                        "target is already hooked (id %u at 0x%llX, %zu bytes)",
                        h->id, (unsigned long long)h->target, h->stolen);
            error = b;
            return 0;
        }
    }

    // Steal whole instructions: a jump written into the middle of one would
    // leave the remainder as garbage that the trampoline then executes. Each
    // stolen instruction keeps its own record, because moving it changes the
    // meaning of three things: rip-relative operands, relative branches, and
    // 8-bit branch displacements that no longer fit where they land.
    struct PlanInsn {
        size_t   origOffset;
        size_t   origSize;
        size_t   newOffset;   // where it lands in the trampoline
        size_t   newSize;     // larger than origSize when a rel8 is widened
        CopyInsn ci;
    };

    uint8_t original[kMaxStolen + 8] = {};
    PlanInsn plan[kMaxPlan] = {};
    int planCount = 0;
    size_t stolen = 0;
    while (stolen < kPatchLen) {
        if (stolen + 16 > sizeof(original) || planCount >= kMaxPlan) {
            error = "prologue is too long";
            return 0;
        }
        CopyInsn ci = DecodeForCopy(target + stolen, sizeof(void*) == 8);
        if (!ci.size) {
            char b[128];
            _snprintf_s(b, sizeof(b), _TRUNCATE, "cannot decode the prologue at 0x%llX",
                        (unsigned long long)(target + stolen));
            error = b;
            return 0;
        }
        if (ci.unsupportedBranch) {
            error = "prologue contains " + ci.text +
                    ", which has no 32-bit displacement form to widen into";
            return 0;
        }
        if (ci.ripRelative && ci.dispSize != 4) {
            error = "prologue has a rip-relative operand with unsupported displacement (" +
                    ci.text + ")";
            return 0;
        }
        // A ret or a jump away from the prologue means the function's own code
        // stops here: the bytes after it may belong to something else, and
        // overwriting them would corrupt it. A jump that stays inside the
        // prologue is fine -- it is a forward/backward branch within the prefix
        // being copied, and its target is remapped in the trampoline.
        if (ci.terminal) {
            const bool inPrologue = ci.isBranch &&
                                    ci.branchTarget >= target &&
                                    ci.branchTarget < target + kMaxStolen;
            if (!inPrologue && stolen + ci.size < kPatchLen) {
                error = "the function's code ends before the patch fits (" + ci.text + ")";
                return 0;
            }
        }

        size_t newSize = ci.size;
        if (ci.isBranch && ci.immSize == 1) {
            newSize = ci.text.compare(0, 3, "jmp") == 0 ? 5 : 6;   // E9 rel32 / 0F 8x rel32
        }
        plan[planCount++] = {stolen, ci.size, 0, newSize, ci};
        stolen += ci.size;
    }
    memcpy(original, (const void*)target, stolen);

    // Second pass with the real stolen length: the target may start just before
    // an existing hook, so the five-byte check above is not enough.
    {
        LockGuard guard;
        if (const HookCtx* h = FindOverlappingLocked(target, stolen)) {
            char b[160];
            _snprintf_s(b, sizeof(b), _TRUNCATE,
                        "target is already hooked (id %u at 0x%llX, %zu bytes)",
                        h->id, (unsigned long long)h->target, h->stolen);
            error = b;
            return 0;
        }
    }

    // Lay the trampoline out first: widening an instruction shifts everything
    // that follows it, so no displacement can be computed before this pass.
    size_t trampLen = 0;
    for (int i = 0; i < planCount; ++i) {
        plan[i].newOffset = trampLen;
        trampLen += plan[i].newSize;
    }

    HookCtx* ctx = new (std::nothrow) HookCtx();
    if (!ctx) { error = "out of memory"; return 0; }
    ctx->target = target;
    ctx->stolen = stolen;
    ctx->obs = obs;
    memcpy(ctx->original, original, stolen);
    _snprintf_s(ctx->name, sizeof(ctx->name), _TRUNCATE, "%s", name ? name : "");

    void* block = AllocNear(target, kBlockSize);
    if (!block) {
        delete ctx;
        error = "cannot allocate executable memory near the target";
        return 0;
    }
    ctx->block = block;
    ctx->stub = (uintptr_t)block;
    ctx->trampoline = (uint8_t*)block + kTrampOffset;

    BuildStub((uint8_t*)block, ctx);

    // Trampoline: every stolen instruction re-emitted, then a jump back to the
    // first byte we did not overwrite. An instruction is rewritten only when
    // moving it would change what it means; everything else is copied verbatim.
    uint8_t* tramp = (uint8_t*)block + kTrampOffset;

    auto fail = [&](const std::string& why) -> uint32_t {
        VirtualFree(block, 0, MEM_RELEASE);
        delete ctx;
        error = why;
        return 0;
    };

    const int32_t ripDelta = (int32_t)((intptr_t)target - (intptr_t)tramp);
    for (int i = 0; i < planCount; ++i) {
        const PlanInsn& p = plan[i];
        const uint8_t* src = original + p.origOffset;
        uint8_t* dst = tramp + p.newOffset;
        const uintptr_t dstAddr = (uintptr_t)dst;

        if (p.ci.isBranch) {
            // A target inside the stolen window moved with the instruction; a
            // target outside it did not.
            uintptr_t tgt = p.ci.branchTarget;
            if (tgt >= target && tgt < target + stolen) {
                const size_t off = (size_t)(tgt - target);
                const PlanInsn* moved = nullptr;
                for (int k = 0; k < planCount; ++k) {
                    if (plan[k].origOffset == off) { moved = &plan[k]; break; }
                }
                if (!moved) {
                    return fail("prologue branch lands inside another instruction (" + p.ci.text + ")");
                }
                tgt = (uintptr_t)(tramp + moved->newOffset);
            }

            const int64_t disp = (int64_t)tgt - (int64_t)(dstAddr + p.newSize);
            if (p.ci.immSize == 1) {
                // A rel8 cannot reach a trampoline up to a gigabyte away, so the
                // instruction is re-emitted in its rel32 form.
                if (disp < INT32_MIN || disp > INT32_MAX) {
                    return fail("a widened branch is out of reach of a 32-bit displacement (" +
                                p.ci.text + ")");
                }
                if (p.ci.text.compare(0, 3, "jmp") == 0) {
                    dst[0] = 0xE9;
                    int32_t d = (int32_t)disp;
                    memcpy(dst + 1, &d, 4);
                } else {
                    dst[0] = 0x0F;
                    dst[1] = (uint8_t)(0x80 | (src[0] & 0x0F));   // same condition code
                    int32_t d = (int32_t)disp;
                    memcpy(dst + 2, &d, 4);
                }
            } else {
                if (disp < INT32_MIN || disp > INT32_MAX) {
                    return fail("prologue branch is out of reach of a 32-bit displacement (" +
                                p.ci.text + ")");
                }
                memcpy(dst, src, p.origSize);
                int32_t d = (int32_t)disp;
                memcpy(dst + p.ci.immOffset, &d, 4);
            }
        } else {
            memcpy(dst, src, p.origSize);
            if (p.ci.ripRelative) {
                // A RIP-relative operand is relative to the end of the
                // instruction, so it moves by the distance between the two
                // instruction ends. The instruction may also have shifted
                // inside the trampoline: a branch ahead of it, widened from
                // rel8 to rel32, takes more bytes and pushes everything after
                // it forward. Without that shift the operand would point a few
                // bytes off the intended address -- in the target process, on
                // data that has nothing to do with the hook.
                int32_t disp = 0;
                memcpy(&disp, src + p.ci.dispOffset, 4);
                int64_t d = (int64_t)disp + (int64_t)ripDelta -
                            (int64_t)(p.newOffset - p.origOffset);
                if (d < INT32_MIN || d > INT32_MAX) {
                    return fail("a rip-relative operand is out of reach of a 32-bit displacement (" +
                                p.ci.text + ")");
                }
                int32_t d32 = (int32_t)d;
                memcpy(dst + p.ci.dispOffset, &d32, 4);
            }
        }
    }
    if (!BuildTrampolineTail(tramp + trampLen, target + stolen)) {
        return fail("the trampoline's jump back does not fit a 32-bit displacement");
    }
    FlushInstructionCache(GetCurrentProcess(), tramp, trampLen + 16);

    // The patch itself: a rel32 jump to the stub, on both architectures.
    uint8_t patch[kPatchLen] = {};
    patch[0] = 0xE9;
    {
        int32_t rel = (int32_t)((intptr_t)ctx->stub - (intptr_t)(target + 5));
        memcpy(patch + 1, &rel, 4);
    }
    memcpy(ctx->patch, patch, kPatchLen);

    // Id and `active` are set before the bytes change: the first call that goes
    // through the new jump must be recorded (and seen by the observer), and a
    // thread that reaches the thunk between the write and the registry insert
    // would otherwise find the hook inactive.
    ctx->id = (uint32_t)InterlockedIncrement(&g_nextId);
    InterlockedExchange(&ctx->active, 1);

    {
        PatchWindowGuard pw;   // A100: one install/remove window at a time
        Suspender sus;
        const Suspender::Result sr = sus.Suspend(target, target + stolen);
        if (sr != Suspender::Result::ok) {
            InterlockedExchange(&ctx->active, 0);
            VirtualFree(block, 0, MEM_RELEASE);
            delete ctx;
            error = SuspendReason(sr);
            return 0;
        }
        if (!PatchBytes(target, patch, kPatchLen)) {
            sus.ResumeAll();
            InterlockedExchange(&ctx->active, 0);
            VirtualFree(block, 0, MEM_RELEASE);
            delete ctx;
            error = "cannot change the protection of the target page";
            return 0;
        }
        sus.ResumeAll();
    }

    bool limitReached = false;
    {
        LockGuard guard;
        // A102: the entry check is lock-free, so two installs racing at the
        // limit must not both write the registry. The loser rolls its patch
        // back below instead of writing g_hooks[kMaxHooks].
        if (g_hookCount >= kMaxHooks) limitReached = true;
        else g_hooks[g_hookCount++] = ctx;
    }
    if (limitReached) {
        InterlockedExchange(&ctx->active, 0);
        {
            PatchWindowGuard pw;
            Suspender sus;
            if (sus.Suspend(target, target + stolen) == Suspender::Result::ok) {
                PrologueRestoreCall rc{};
                rc.target = target;
                rc.patch = ctx->patch;
                rc.original = ctx->original;
                rc.stolen = stolen;
                RestorePrologueUnderSeh(&rc);
                sus.ResumeAll();
                if (rc.status != kRestoreOk) {
                    LogLine("hook limit rollback: prologue at %p not restored (status %d)",
                            (void*)target, (int)rc.status);
                }
            }
        }
        // The block and ctx stay mapped: a call may already be inside the
        // trampoline, exactly as for a removed hook (A74).
        RecordBlockRange(block);
        InterlockedIncrement(&g_retiredBlocks);
        InterlockedExchangeAdd64(&g_retiredBytes, (LONG64)kBlockSize + sizeof(HookCtx));
        error = "hook limit reached";
        return 0;
    }
    RecordBlockRange(block);

    LogLine("hook %u installed: %p -> stub %p trampoline %p stolen %zu",
            ctx->id, (void*)target, (void*)ctx->stub, ctx->trampoline, stolen);
    return ctx->id;
}

bool HookRemove(uint32_t id) {
    HookCtx* ctx = nullptr;
    {
        LockGuard guard;
        for (int i = 0; i < g_hookCount; ++i) {
            if (g_hooks[i]->id == id) {
                ctx = g_hooks[i];
                break;
            }
        }
    }
    if (!ctx) return false;

    // Stop recording first: a call that is already on its way through the
    // thunk must not show up in a trace taken after `unhook' (A71). Any
    // failure below puts the flag back -- the hook is still live then.
    InterlockedExchange(&ctx->active, 0);

    {
        PatchWindowGuard pw;   // A100: one install/remove window at a time
        Suspender sus;
        const Suspender::Result sr = sus.Suspend(ctx->target, ctx->target + ctx->stolen);
        if (sr != Suspender::Result::ok) {
            // The restore was refused (a thread is executing the prologue).
            // Dropping the hook from the registry while its detour is still
            // patched would hide a live hook: keep it registered and report
            // the refusal -- the caller can try again (plan_roadmap Ф1.4).
            InterlockedExchange(&ctx->active, 1);
            LogLine("hook %u not removed: %s", id, SuspendReason(sr));
            return false;
        }

        // A71: restore only bytes that are still ours. Something else -- another
        // packer, a manual patch, a hooker that ignored our rejection -- may
        // have rewritten the prologue since; copying our saved bytes over it
        // would destroy whatever is there now. A99: the whole window is
        // guarded -- an unreadable or faulting read refuses the removal
        // instead of killing the frame that owes the resume.
        PrologueRestoreCall rc{};
        rc.target = ctx->target;
        rc.patch = ctx->patch;
        rc.original = ctx->original;
        rc.stolen = ctx->stolen;
        RestorePrologueUnderSeh(&rc);
        if (rc.status != kRestoreOk) {
            sus.ResumeAll();
            InterlockedExchange(&ctx->active, 1);
            switch (rc.status) {
            case kRestoreUnreadable:
                LogLine("hook %u not removed: the target %p is no longer readable "
                        "(module unloaded?)", id, (void*)ctx->target);
                break;
            case kRestoreForeignBytes:
                LogLine("hook %u not removed: the bytes at %p are no longer the patch "
                        "(now %02X %02X %02X %02X %02X)",
                        id, (void*)ctx->target, rc.nowBytes[0], rc.nowBytes[1],
                        rc.nowBytes[2], rc.nowBytes[3], rc.nowBytes[4]);
                break;
            case kRestorePatchFailed:
                LogLine("hook %u not removed: cannot restore the original bytes", id);
                break;
            default:
                LogLine("hook %u not removed: fault while restoring the prologue", id);
                break;
            }
            return false;
        }
        sus.ResumeAll();
    }

    {   // taken out of the registry only once the original bytes are back
        LockGuard guard;
        for (int i = 0; i < g_hookCount; ++i) {
            if (g_hooks[i] == ctx) {
                g_hooks[i] = g_hooks[--g_hookCount];
                break;
            }
        }
    }

    // The block is deliberately not freed: a thread that was already inside the
    // trampoline when the patch was reverted would jump into released memory.
    // The real cost of that decision is a 4 KiB page plus the context per
    // removed hook, kept for the rest of the process lifetime -- counted and
    // logged here instead of being silently paid (A74).
    const LONG retired = InterlockedIncrement(&g_retiredBlocks);
    const LONG64 bytes = InterlockedExchangeAdd64(&g_retiredBytes, (LONG64)kBlockSize + sizeof(HookCtx)) +
                         (LONG64)kBlockSize + sizeof(HookCtx);
    LogLine("hook %u removed: %p (retired blocks: %ld, %.1f KiB)",
            id, (void*)ctx->target, retired, (double)bytes / 1024.0);
    return true;
}

size_t HookRemoveAll() {
    uint32_t ids[kMaxHooks];
    int n = 0;
    {
        LockGuard guard;
        for (int i = 0; i < g_hookCount; ++i) ids[n++] = g_hooks[i]->id;
    }
    size_t removed = 0;
    for (int i = 0; i < n; ++i) if (HookRemove(ids[i])) ++removed;
    return removed;
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

namespace {

bool ResolveHookTarget(const std::wstring& spec, uintptr_t& addr, std::string& error) {
    if (spec.empty()) { error = "empty target"; return false; }

    size_t bang = spec.find(L'!');
    if (bang != std::wstring::npos) {
        std::wstring mod = spec.substr(0, bang);
        std::wstring sym = spec.substr(bang + 1);
        ModuleRange m;
        if (!FindModule(mod.c_str(), m)) { error = "module not found: " + Narrow(mod); return false; }
        PeImage img = ParsePe(m.base);
        if (!img.valid) { error = "cannot parse the PE of " + Narrow(mod); return false; }

        std::string want = Narrow(sym);
        for (const PeExport& e : img.exports) {
            if (e.name == want) { addr = m.base + e.rva; return true; }
        }
        for (auto& c : want) c = (char)tolower((unsigned char)c);
        for (const PeExport& e : img.exports) {
            std::string have = e.name;
            for (auto& c : have) c = (char)tolower((unsigned char)c);
            if (have == want) { addr = m.base + e.rva; return true; }
        }

        // Third pass: substring. MSVC-mangled engine names are unreadable, so
        // `core83.dll!findMethod` is the practical way to name a function. An
        // ambiguous substring is reported with its candidates instead of being
        // guessed at -- hooking the wrong overload would be silent.
        const PeExport* hits[8] = {};
        int hitCount = 0;
        int total = 0;
        for (const PeExport& e : img.exports) {
            std::string have = e.name;
            for (auto& c : have) c = (char)tolower((unsigned char)c);
            if (have.find(want) == std::string::npos) continue;
            ++total;
            if (hitCount < 8) hits[hitCount++] = &e;
        }
        if (total == 1) {
            addr = m.base + hits[0]->rva;
            return true;
        }
        if (total > 1) {
            std::string list;
            for (int i = 0; i < hitCount; ++i) {
                char b[48];
                _snprintf_s(b, sizeof(b), _TRUNCATE, "0x%X", hits[i]->rva);
                if (i) list += ", ";
                list += hits[i]->name + std::string(" (") + b + ")";
            }
            if (total > hitCount) list += ", ...";
            error = "export name is ambiguous (" + std::to_string(total) +
                    " matches): " + list + "; use module+0xRVA to pick one";
            return false;
        }

        error = "export not found: " + Narrow(sym) + " in " + Narrow(mod);
        return false;
    }

    size_t plus = spec.find(L'+');
    if (plus != std::wstring::npos) {
        std::wstring mod = spec.substr(0, plus);
        ModuleRange m;
        if (!FindModule(mod.c_str(), m)) { error = "module not found: " + Narrow(mod); return false; }
        addr = m.base + ParseHexToken(spec.substr(plus + 1));
        return true;
    }

    addr = ParseHexToken(spec);
    if (!addr) { error = "cannot parse target: " + Narrow(spec); return false; }
    return true;
}

std::string HexStr(uintptr_t v) {
    char b[32];
    _snprintf_s(b, sizeof(b), _TRUNCATE, "0x%llX", (unsigned long long)v);
    return b;
}

// Escapes a string for a JSON value. A hook name or an error message goes
// into the answer verbatim, and a quote or a backslash in it would break the
// whole response for the host. The escaping itself lives in v8i_common
// (see v8inject/text.h).

}  // namespace

std::string HookCommandToJson(const std::wstring& args) {
    Tokenizer t(args);
    std::wstring target = t.Next();
    if (target.empty()) {
        return "{\"status\":\"error\",\"message\":\"usage: hook <addr|module!Export|module+0xRVA> "
               "[--name <text>]\"}";
    }

    std::wstring name;
    for (;;) {
        std::wstring tok = t.Next();
        if (tok.empty()) break;
        if (tok == L"--name") name = t.Next();
    }

    uintptr_t addr = 0;
    std::string err;
    if (!ResolveHookTarget(target, addr, err)) {
        return "{\"status\":\"error\",\"message\":\"" + JsonEscape(err) + "\"}";
    }

    std::string label = name.empty() ? Narrow(target) : Narrow(name);
    uint32_t id = HookInstall(addr, label.c_str(), err);
    if (!id) return "{\"status\":\"error\",\"message\":\"" + JsonEscape(err) + "\"}";

    // Report what the hook actually did, so a caller can see the stolen bytes
    // without a second command.
    std::string j = "{\"status\":\"ok\",\"id\":" + std::to_string(id) +
                    ",\"target\":\"" + HexStr(addr) + "\",\"name\":\"" +
                    JsonEscape(label) + "\"";
    {
        LockGuard guard;
        for (int i = 0; i < g_hookCount; ++i) {
            HookCtx* c = g_hooks[i];
            if (c->id != id) continue;
            j += ",\"stolen\":" + std::to_string(c->stolen);
            j += ",\"stub\":\"" + HexStr(c->stub) + "\"";
            j += ",\"trampoline\":\"" + HexStr((uintptr_t)c->trampoline) + "\"";
            char b[8];
            j += ",\"original\":\"";
            for (size_t k = 0; k < c->stolen; ++k) {
                _snprintf_s(b, sizeof(b), _TRUNCATE, "%02X", c->original[k]);
                j += b;
            }
            j += "\"";
            break;
        }
    }
    j += "}";
    return j;
}

std::string UnhookCommandToJson(const std::wstring& args) {
    Tokenizer t(args);
    std::wstring what = t.Next();
    if (what.empty()) return "{\"status\":\"error\",\"message\":\"usage: unhook <id|all>\"}";

    auto countHooks = [] {
        LockGuard guard;
        return (size_t)g_hookCount;
    };

    if (what == L"all") {
        size_t n = HookRemoveAll();
        const size_t left = countHooks();
        std::string j = "{\"status\":\"ok\",\"removed\":" + std::to_string(n);
        // A71: a removal can be refused (a thread sits in the prologue, or the
        // bytes are no longer ours). Saying only "removed: 3" would hide a hook
        // that is still patched.
        if (left) j += ",\"failed\":" + std::to_string(left);
        j += "}";
        return j;
    }
    uint32_t id = (uint32_t)_wtoi(what.c_str());
    if (!id) return "{\"status\":\"error\",\"message\":\"hook id must be a number or 'all'\"}";

    const bool had = [&] {
        LockGuard guard;
        for (int i = 0; i < g_hookCount; ++i) {
            if (g_hooks[i]->id == id) return true;
        }
        return false;
    }();
    if (!had) return "{\"status\":\"error\",\"message\":\"no hook with id " + std::to_string(id) + "\"}";

    if (!HookRemove(id)) {
        return "{\"status\":\"error\",\"message\":\"hook " + std::to_string(id) +
               " is still installed: the removal was refused, see the payload log\"}";
    }
    return "{\"status\":\"ok\",\"removed\":1}";
}

std::string HooksCommandToJson(const std::wstring&) {
    LockGuard guard;
    std::string j = "{\"status\":\"ok\",\"count\":" + std::to_string(g_hookCount) + ",\"hooks\":[";
    bool first = true;
    for (int i = 0; i < g_hookCount; ++i) {
        HookCtx* c = g_hooks[i];
        if (!first) j += ",";
        first = false;
        j += "{\"id\":" + std::to_string(c->id);
        j += ",\"name\":\"" + JsonEscape(std::string(c->name)) + "\"";
        j += ",\"target\":\"" + HexStr(c->target) + "\"";
        j += ",\"stolen\":" + std::to_string(c->stolen);
        // A101: unsigned -- a hot hook past 2^31 calls used to print a
        // negative number here.
        j += ",\"calls\":" + std::to_string((unsigned)c->calls);
        j += "}";
    }
    j += "]";
    // A74: blocks of removed hooks are never freed, so the cost of a hook/unhook
    // loop is visible here instead of being an invisible leak.
    j += ",\"retired\":" + std::to_string((long)g_retiredBlocks);
    j += ",\"retiredKiB\":" +
         std::to_string((long long)(InterlockedCompareExchange64(&g_retiredBytes, 0, 0) / 1024));
    j += "}";
    return j;
}

std::string TraceCommandToJson(const std::wstring& args) {
    size_t want = 20;
    LONG64 since = 0;
    bool clear = false;

    Tokenizer t(args);
    for (;;) {
        std::wstring tok = t.Next();
        if (tok.empty()) break;
        if (tok == L"--count")      want = (size_t)_wcstoi64(t.Next().c_str(), nullptr, 10);
        else if (tok == L"--since") since = _wcstoi64(t.Next().c_str(), nullptr, 10);
        else if (tok == L"--clear") clear = true;
    }
    if (want == 0 || want > kTraceCapacity) want = kTraceCapacity;
    if (since < 0) since = 0;

    const LONG64 head = InterlockedCompareExchange64(&g_head, 0, 0);
    const LONG64 base = InterlockedCompareExchange64(&g_base, 0, 0);
    LONG64 first = head > (LONG64)kTraceCapacity ? head - (LONG64)kTraceCapacity : 0;
    if (base > first) first = base;
    if (since < first) since = first;
    LONG64 start = (head - since) > (LONG64)want ? head - (LONG64)want : since;
    if (start < first) start = first;
    if (start > head) start = head;

    char headBuf[192];
    _snprintf_s(headBuf, sizeof(headBuf), _TRUNCATE,
                "{\"status\":\"ok\",\"head\":%lld,\"capacity\":%zu,\"since\":%lld,\"records\":[",
                (long long)head, kTraceCapacity, (long long)start);
    std::string j = headBuf;

    size_t emitted = 0;
    bool truncated = false;
    LONG64 stoppedAt = start;
    for (LONG64 idx = start; idx < head; ++idx) {
        TraceSlot& s = g_slots[(uint64_t)idx % kTraceCapacity];

        // A90: take a whole copy between two reads of seq and throw it away if
        // they differ. The old reader copied the fields first and read
        // frameCount afterwards, so a record could pair one call's arguments
        // with another call's frames. seq is even exactly when no write is in
        // flight, and the absolute index in the slot catches a slot that was
        // overwritten despite an even seq.
        const LONG64 s1 = s.seq;
        if (s1 & 1) continue;
        TraceRecord r;
        r.idx = s.idx;
        r.id = s.id;
        r.tid = s.tid;
        r.tick = s.tick;
        r.retAddr = s.retAddr;
        for (int a = 0; a < 4; ++a) r.args[a] = s.args[a];
        for (int f = 0; f < kMaxFrames; ++f) r.frame[f] = s.frame[f];
        r.frameCount = s.frameCount;
        if (s.seq != s1 || r.idx != (uint64_t)idx) continue;

        // Built separately so the budget is checked before anything is
        // appended: a half-written record would be an invalid document.
        std::string rec;
        rec.reserve(256);
        rec += "{\"seq\":" + std::to_string((long long)idx);
        rec += ",\"hook\":" + std::to_string(r.id);
        rec += ",\"tid\":" + std::to_string(r.tid);
        rec += ",\"tick\":" + std::to_string((unsigned long long)r.tick);
        rec += ",\"ret\":\"" + HexStr(r.retAddr) + "\"";
        rec += ",\"args\":[\"" + HexStr(r.args[0]) + "\",\"" + HexStr(r.args[1]) + "\",\"" +
               HexStr(r.args[2]) + "\",\"" + HexStr(r.args[3]) + "\"]";
        rec += ",\"stack\":[";
        int fc = r.frameCount;
        if (fc < 0) fc = 0;
        if (fc > kMaxFrames) fc = kMaxFrames;
        for (int fi = 0; fi < fc; ++fi) {
            if (fi) rec += ",";
            rec += "\"" + HexStr(r.frame[fi]) + "\"";
        }
        rec += "]}";

        if (j.size() + rec.size() + 64 > kTraceBudget) { truncated = true; break; }
        if (emitted++) j += ",";
        j += rec;
        stoppedAt = idx + 1;
    }

    j += "]";
    if (truncated) {
        // A70: the reply is cut here, inside the budget, and says so. The old
        // answer was assembled whole and then refused by the shared block as
        // "response too large", so `trace --count 1024` on a real 1C returned
        // nothing at all.
        j += ",\"truncated\":true,\"dropped\":";
        j += std::to_string((long long)(head - stoppedAt));
    }
    j += "}";

    if (clear) {
        // A90: move the start marker instead of zeroing the ring. Writers keep
        // their slots and their seq values, so a record that was in flight
        // during the clear is not mistaken for one from a full wrap earlier.
        const LONG64 now = InterlockedCompareExchange64(&g_head, 0, 0);
        InterlockedExchange64(&g_base, now);
        LogLine("trace cleared up to %lld", (long long)now);
    }
    return j;
}

size_t TraceReplyBudget() { return kTraceBudget; }

}  // namespace v8i
