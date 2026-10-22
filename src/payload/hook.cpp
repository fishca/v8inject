#include "v8inject/hook.h"

#include "v8inject/diag.h"
#include "v8inject/disasm.h"
#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"

#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstring>
#include <mutex>
#include <new>
#include <string>
#include <vector>

namespace v8i {

namespace {

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

#if defined(_M_X64)
// mov rax, imm64; jmp rax -- reaches anywhere in the 64-bit address space.
constexpr size_t kPatchLen = 12;
#else
// jmp rel32 -- the stub has to live within +-2 GB of the target.
constexpr size_t kPatchLen = 5;
#endif

// A prologue longer than this is not a prologue we want to move.
constexpr size_t kMaxStolen = 24;

// One page-sized block per hook: stub at 0, indirect slot at 32, trampoline at
// 64. Everything the hook needs sits in a single allocation near the target.
constexpr size_t kBlockSize = 256;
constexpr size_t kSlotOffset = 32;
constexpr size_t kTrampOffset = 64;

constexpr size_t kTraceCapacity = 1024;

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
// back to even. A reader that sees an odd or changed seq skips the slot instead
// of blocking anyone. A lost record is acceptable; a stalled hooked function is
// not.
// ---------------------------------------------------------------------------

struct TraceSlot {
    volatile LONG seq;
    uint32_t  id;
    uint32_t  tid;
    uint64_t  tick;
    uintptr_t retAddr;
    uintptr_t args[4];
};

TraceSlot      g_slots[kTraceCapacity];
volatile LONG  g_head = 0;        // records ever written, also the next index

struct HookCtx {
    void*     trampoline = nullptr;   // offset 0: the thunks read [ctx]
    uintptr_t stub = 0;
    void*     block = nullptr;
    uintptr_t target = 0;
    size_t    stolen = 0;
    uint32_t  id = 0;
    bool      active = false;
    uint8_t   original[kMaxStolen + 8] = {};
    char      name[64] = {};
    volatile LONG calls = 0;
};

std::mutex            g_lock;
std::vector<HookCtx*> g_hooks;
uint32_t              g_nextId = 1;

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
class Suspender {
public:
    ~Suspender() { ResumeAll(); }

    bool Suspend(uintptr_t lo, uintptr_t hi, std::string& error) {
        DWORD self = GetCurrentThreadId();
        DWORD pid = GetCurrentProcessId();

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) { error = "thread snapshot failed"; return false; }

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
                        CloseHandle(snap);
                        error = "a thread is executing the prologue; try again";
                        ResumeAll();
                        return false;
                    }
                }
                handles_.push_back(h);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        return true;
    }

    void ResumeAll() {
        for (HANDLE h : handles_) {
            ResumeThread(h);
            CloseHandle(h);
        }
        handles_.clear();
    }

private:
    std::vector<HANDLE> handles_;
};

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

// Bytes that take control from the stub back to the first untouched instruction.
size_t BuildTrampolineTail(uint8_t* at, uintptr_t resume) {
#if defined(_M_X64)
    at[0] = 0x48; at[1] = 0xB8;
    uint64_t r = (uint64_t)resume;
    memcpy(at + 2, &r, 8);
    at[10] = 0xFF; at[11] = 0xE0;                 // jmp rax
    return 12;
#else
    at[0] = 0xE9;
    int32_t rel = (int32_t)((intptr_t)resume - (intptr_t)(at + 5));
    memcpy(at + 1, &rel, 4);
    return 5;
#endif
}

}  // namespace

// ---------------------------------------------------------------------------
// The recording entry point. Called from assembly on every hooked call.
// ---------------------------------------------------------------------------

extern "C" void V8iHookEnter(void* ctx, void* retAddr, uintptr_t a0, uintptr_t a1,
                             uintptr_t a2, uintptr_t a3) {
    HookCtx* c = (HookCtx*)ctx;
    if (!c) return;

    InterlockedIncrement(&c->calls);

    LONG idx = InterlockedIncrement(&g_head) - 1;
    TraceSlot& s = g_slots[(uint32_t)idx % kTraceCapacity];

    InterlockedIncrement(&s.seq);                 // odd: write in progress
    s.id = c->id;
    s.tid = GetCurrentThreadId();
    s.tick = GetTickCount64();
    s.retAddr = (uintptr_t)retAddr;
    s.args[0] = a0;
    s.args[1] = a1;
    s.args[2] = a2;
    s.args[3] = a3;
    InterlockedIncrement(&s.seq);                 // even: record complete
}

// ---------------------------------------------------------------------------
// Fault diagnostics
//
// A crash inside a hooked function is invisible to the host: the process simply
// disappears and the log stops mid-command. A vectored handler that only
// records the context turns that into a line the log can explain.
// ---------------------------------------------------------------------------

namespace {

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

    CONTEXT* c = ep->ContextRecord;
#if defined(_M_X64)
    LogLine("fault code=0x%08lX at rip=%p av=%p rax=%p rcx=%p rdx=%p rsp=%p rbp=%p",
            r->ExceptionCode, r->ExceptionAddress, (void*)av, (void*)c->Rax, (void*)c->Rcx,
            (void*)c->Rdx, (void*)c->Rsp, (void*)c->Rbp);
#else
    LogLine("fault code=0x%08lX at eip=%p av=%p eax=%08lX ecx=%08lX edx=%08lX esp=%08lX ebp=%08lX",
            r->ExceptionCode, r->ExceptionAddress, (void*)av, c->Eax, c->Ecx, c->Edx,
            c->Esp, c->Ebp);
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
    if (!target) { error = "null target"; return 0; }

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((void*)target, &mbi, sizeof(mbi))) { error = "VirtualQuery failed"; return 0; }
    if (mbi.State != MEM_COMMIT) { error = "target is not committed memory"; return 0; }
    if (!((mbi.Protect & 0xFF) & 0xF0)) { error = "target is not executable"; return 0; }

    // Steal whole instructions: a jump written into the middle of one would
    // leave the remainder as garbage that the trampoline then executes.
    // Keep a per-instruction plan so the trampoline can relocate rip-relative
    // operands whose meaning would otherwise change when the bytes move.
    struct StolenInsn {
        size_t offset;
        size_t size;
        bool   ripRelative;
        size_t dispOffset;
    };

    uint8_t original[kMaxStolen + 8] = {};
    std::vector<StolenInsn> plan;
    size_t stolen = 0;
    while (stolen < kPatchLen) {
        if (stolen + 16 > sizeof(original)) { error = "prologue is too long"; return 0; }
        CopyInsn ci = DecodeForCopy(target + stolen, sizeof(void*) == 8);
        if (!ci.size) {
            char b[128];
            _snprintf_s(b, sizeof(b), _TRUNCATE, "cannot decode the prologue at 0x%llX",
                        (unsigned long long)(target + stolen));
            error = b;
            return 0;
        }
        if (ci.positionDependent) {
            error = "prologue contains a position-dependent instruction (" + ci.text +
                    "); not hookable yet";
            return 0;
        }
        if (ci.ripRelative && ci.dispSize != 4) {
            error = "prologue has a rip-relative operand with unsupported displacement (" +
                    ci.text + ")";
            return 0;
        }
        if (ci.terminal) {
            error = "target looks like a jump stub or ends immediately (" + ci.text +
                    "); resolve the real function first";
            return 0;
        }
        plan.push_back({stolen, ci.size, ci.ripRelative, ci.dispOffset});
        stolen += ci.size;
    }
    memcpy(original, (const void*)target, stolen);

    HookCtx* ctx = new (std::nothrow) HookCtx();
    if (!ctx) { error = "out of memory"; return 0; }
    ctx->target = target;
    ctx->stolen = stolen;
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

    // Trampoline: the stolen bytes, then a jump back to the first instruction we
    // did not overwrite. rip-relative operands get their displacement rewritten:
    // the operand addresses target + (size after the disp), so the correction
    // is the same for every instruction in the plan -- how far the trampoline
    // sits from the original prologue.
    uint8_t* tramp = (uint8_t*)block + kTrampOffset;
    memcpy(tramp, original, stolen);
    {
        int32_t delta = (int32_t)((intptr_t)target - (intptr_t)tramp);
        for (const StolenInsn& si : plan) {
            if (!si.ripRelative) continue;
            int32_t disp = 0;
            memcpy(&disp, original + si.offset + si.dispOffset, 4);
            disp += delta;
            memcpy(tramp + si.offset + si.dispOffset, &disp, 4);
        }
    }
    BuildTrampolineTail(tramp + stolen, target + stolen);
    FlushInstructionCache(GetCurrentProcess(), tramp, stolen + 16);

    // The patch itself.
    uint8_t patch[kPatchLen] = {};
#if defined(_M_X64)
    patch[0] = 0x48; patch[1] = 0xB8;
    uint64_t s = (uint64_t)ctx->stub;
    memcpy(patch + 2, &s, 8);
    patch[10] = 0xFF; patch[11] = 0xE0;           // jmp rax
#else
    patch[0] = 0xE9;
    int32_t rel = (int32_t)((intptr_t)ctx->stub - (intptr_t)(target + 5));
    memcpy(patch + 1, &rel, 4);
#endif

    {
        Suspender sus;
        std::string why;
        if (!sus.Suspend(target, target + stolen, why)) {
            VirtualFree(block, 0, MEM_RELEASE);
            delete ctx;
            error = why;
            return 0;
        }
        if (!PatchBytes(target, patch, kPatchLen)) {
            sus.ResumeAll();
            VirtualFree(block, 0, MEM_RELEASE);
            delete ctx;
            error = "cannot change the protection of the target page";
            return 0;
        }
        sus.ResumeAll();
    }

    std::lock_guard<std::mutex> guard(g_lock);
    ctx->id = g_nextId++;
    ctx->active = true;
    g_hooks.push_back(ctx);

    LogLine("hook %u installed: %p -> stub %p trampoline %p stolen %zu",
            ctx->id, (void*)target, (void*)ctx->stub, ctx->trampoline, stolen);
    return ctx->id;
}

bool HookRemove(uint32_t id) {
    HookCtx* ctx = nullptr;
    {
        std::lock_guard<std::mutex> guard(g_lock);
        for (size_t i = 0; i < g_hooks.size(); ++i) {
            if (g_hooks[i]->id == id) {
                ctx = g_hooks[i];
                g_hooks.erase(g_hooks.begin() + (ptrdiff_t)i);
                break;
            }
        }
    }
    if (!ctx) return false;

    {
        Suspender sus;
        std::string why;
        if (sus.Suspend(ctx->target, ctx->target + ctx->stolen, why)) {
            PatchBytes(ctx->target, ctx->original, ctx->stolen);
            sus.ResumeAll();
        }
    }
    ctx->active = false;

    // The block is deliberately not freed: a thread that was already inside the
    // trampoline when the patch was reverted would jump into released memory.
    // 256 bytes per removed hook is a cheap price for that race.
    LogLine("hook %u removed: %p", id, (void*)ctx->target);
    return true;
}

size_t HookRemoveAll() {
    std::vector<uint32_t> ids;
    {
        std::lock_guard<std::mutex> guard(g_lock);
        for (HookCtx* c : g_hooks) ids.push_back(c->id);
    }
    size_t n = 0;
    for (uint32_t id : ids) if (HookRemove(id)) ++n;
    return n;
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
        return "{\"status\":\"error\",\"message\":\"" + err + "\"}";
    }

    std::string label = name.empty() ? Narrow(target) : Narrow(name);
    uint32_t id = HookInstall(addr, label.c_str(), err);
    if (!id) return "{\"status\":\"error\",\"message\":\"" + err + "\"}";

    // Report what the hook actually did, so a caller can see the stolen bytes
    // without a second command.
    std::string j = "{\"status\":\"ok\",\"id\":" + std::to_string(id) +
                    ",\"target\":\"" + HexStr(addr) + "\",\"name\":\"" + label + "\"";
    {
        std::lock_guard<std::mutex> guard(g_lock);
        for (HookCtx* c : g_hooks) {
            if (c->id != id) continue;
            j += ",\"stolen\":" + std::to_string(c->stolen);
            j += ",\"stub\":\"" + HexStr(c->stub) + "\"";
            j += ",\"trampoline\":\"" + HexStr((uintptr_t)c->trampoline) + "\"";
            char b[8];
            j += ",\"original\":\"";
            for (size_t i = 0; i < c->stolen; ++i) {
                _snprintf_s(b, sizeof(b), _TRUNCATE, "%02X", c->original[i]);
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

    if (what == L"all") {
        size_t n = HookRemoveAll();
        return "{\"status\":\"ok\",\"removed\":" + std::to_string(n) + "}";
    }
    uint32_t id = (uint32_t)_wtoi(what.c_str());
    if (!id) return "{\"status\":\"error\",\"message\":\"hook id must be a number or 'all'\"}";
    if (!HookRemove(id)) {
        return "{\"status\":\"error\",\"message\":\"no hook with id " + std::to_string(id) + "\"}";
    }
    return "{\"status\":\"ok\",\"removed\":1}";
}

std::string HooksCommandToJson(const std::wstring&) {
    std::lock_guard<std::mutex> guard(g_lock);
    std::string j = "{\"status\":\"ok\",\"count\":" + std::to_string(g_hooks.size()) + ",\"hooks\":[";
    bool first = true;
    for (HookCtx* c : g_hooks) {
        if (!first) j += ",";
        first = false;
        j += "{\"id\":" + std::to_string(c->id);
        j += ",\"name\":\"" + std::string(c->name) + "\"";
        j += ",\"target\":\"" + HexStr(c->target) + "\"";
        j += ",\"stolen\":" + std::to_string(c->stolen);
        j += ",\"calls\":" + std::to_string((long)c->calls);
        j += "}";
    }
    j += "]}";
    return j;
}

std::string TraceCommandToJson(const std::wstring& args) {
    size_t want = 20;
    LONG since = 0;
    bool clear = false;

    Tokenizer t(args);
    for (;;) {
        std::wstring tok = t.Next();
        if (tok.empty()) break;
        if (tok == L"--count")      want = (size_t)_wtoi(t.Next().c_str());
        else if (tok == L"--since") since = (LONG)_wtoi(t.Next().c_str());
        else if (tok == L"--clear") clear = true;
    }
    if (want == 0 || want > kTraceCapacity) want = kTraceCapacity;

    LONG head = InterlockedCompareExchange(&g_head, 0, 0);
    LONG first = head > (LONG)kTraceCapacity ? head - (LONG)kTraceCapacity : 0;
    if (since > first) first = since;
    LONG start = (head - first) > (LONG)want ? head - (LONG)want : first;
    if (start < first) start = first;

    std::string j = "{\"status\":\"ok\",\"head\":" + std::to_string((long)head);
    j += ",\"capacity\":" + std::to_string((long)kTraceCapacity);
    j += ",\"since\":" + std::to_string((long)start);
    j += ",\"records\":[";

    size_t emitted = 0;
    for (LONG idx = start; idx < head; ++idx) {
        TraceSlot& s = g_slots[(uint32_t)idx % kTraceCapacity];
        // Generation check: a slot is only valid for the wrap it was written in,
        // and seq is even exactly when no write is in flight.
        LONG expect = (LONG)(2 * ((uint64_t)idx / kTraceCapacity + 1));
        LONG s1 = s.seq;
        if (s1 != expect) continue;

        uint32_t id = s.id;
        uint32_t tid = s.tid;
        uint64_t tick = s.tick;
        uintptr_t ret = s.retAddr;
        uintptr_t a0 = s.args[0], a1 = s.args[1], a2 = s.args[2], a3 = s.args[3];
        if (s.seq != s1) continue;

        if (emitted++) j += ",";
        j += "{\"seq\":" + std::to_string((long)idx);
        j += ",\"hook\":" + std::to_string(id);
        j += ",\"tid\":" + std::to_string(tid);
        j += ",\"tick\":" + std::to_string((unsigned long long)tick);
        j += ",\"ret\":\"" + HexStr(ret) + "\"";
        j += ",\"args\":[\"" + HexStr(a0) + "\",\"" + HexStr(a1) + "\",\"" +
             HexStr(a2) + "\",\"" + HexStr(a3) + "\"]}";
    }
    j += "]}";

    if (clear) {
        for (size_t i = 0; i < kTraceCapacity; ++i)
            InterlockedExchange(&g_slots[i].seq, 0);
        InterlockedExchange(&g_head, 0);
        LogLine("trace cleared");
    }
    return j;
}

}  // namespace v8i
