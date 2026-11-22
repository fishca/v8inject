#include "platform_commands.h"
#include "cmdinfo_json.h"
#include "pending_slot.h"

#include "v8inject/diag.h"
#include "v8inject/hook.h"
#include "v8inject/objects.h"
#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"
#include "v8inject/text.h"

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace v8i {
namespace platform {
namespace {

// A diagnostic dump next to the payload log. These files used to point at a
// path hardcoded to the author's machine: on anyone else's computer the
// directory did not exist, so the dumps were silently never written.
//
// Plain buffers instead of std::wstring: the callers sit inside __try
// blocks, where a function that needs unwinding is not allowed.
bool LogSideFile(const wchar_t* name, wchar_t* out, size_t cch) {
    const wchar_t* log = GetLogPath();
    if (log && log[0] && wcscmp(log, L"(unset)") != 0) {
        _snwprintf_s(out, cch, _TRUNCATE, L"%s.%s", log, name);
        return true;
    }
    wchar_t tmp[MAX_PATH] = {};
    DWORD n = GetTempPathW(MAX_PATH, tmp);
    if (n == 0 || n >= MAX_PATH) return false;
    _snwprintf_s(out, cch, _TRUNCATE, L"%s%s", tmp, name);
    return true;
}

// A file in the real temp directory: the file-driven command channel is the
// only way to reach a payload that was loaded without a Client session.
bool TempFile(const wchar_t* name, wchar_t* out, size_t cch) {
    wchar_t tmp[MAX_PATH] = {};
    DWORD n = GetTempPathW(MAX_PATH, tmp);
    if (n == 0 || n >= MAX_PATH) return false;
    _snwprintf_s(out, cch, _TRUNCATE, L"%s%s", tmp, name);
    return true;
}

}  // namespace


// "cmd <num> [sub]" — invoke a designer command of the Config group
// {F10CBB81-F679-11D4-9DD3-0050BAE2BC79} on the main frame, exactly like
// Snegopat's sendCommand. Calibrated chain on 8.3.27.1989 (x64):
//   frame object (heap) -> [0] = ITopLevelFrame vtable (config.dll+0x2EFB50)
//   frame+8             -> coreMainFrame; ICommandReceiver = core - 0x20
//   recv->vtbl[3]       -> transmitCommand(Command*, bool)
// The transmit runs on the 1C UI thread via a frame-window subclass +
// PostMessage (see EnsureCmdUi); 1C UI code must not be called cross-thread.
// The frame is located by scanning committed writable memory for the vtable
// pointer; the result is cached and re-validated for subsequent calls.
// (A118: the separate g_cmdFrameCache slot was never written -- the discovered
// frame objects below are the only cache, revalidated per use.)
namespace {
#if !defined(_WIN64)
uintptr_t g_x86FrameObj = 0;   // discovered frame object (x86 runtime calibration)
#else
uintptr_t g_x64FrameObj = 0;   // discovered frame object (x64 runtime calibration)
uintptr_t g_x64RecvOffset = 0x20;
bool g_x64DiscoveryDone = false;       // discovery attempted this session
ULONGLONG g_x64DiscoveryTick = 0;      // cooldown gate for re-discovery
#endif
}

// SEH cannot live in a function that needs C++ unwinding (MSVC C2712); the
// transmit call is isolated in a POD-only helper.
#if defined(_WIN64)
typedef int(__fastcall* V8iTransmitFn)(void*, const void*, uint8_t);
#else
// 1C x86 interface methods are C-style: self is the FIRST STACK argument and
// the callee pops it (ret 0xC for transmitCommand) — verified against
// frame.dll+0x8980A0 (`ret 0xc`, reads [ebp+8]=self, [ebp+0xC]=cmd,
// [ebp+0x10]=deactivate).
typedef int(__stdcall* V8iTransmitFn)(void*, const void*, int);
#endif
#if defined(_WIN64)
typedef int(__fastcall* V8iHasFn)(void*, const void*);
#else
typedef int(__stdcall* V8iHasFn)(void*, const void*);
#endif
typedef void(__fastcall* V8iRecvFn)(void*, void**);

namespace {
LONG g_cmdLastExc = 0;
int TransmitGuarded(void* trFn, void* recv, const void* cmd) {
    int rc = 0;
    __try {
        // deactivate=true mirrors Snegopat's sendCommand default; commands that
        // open modal dialogs expect the current UI to be deactivated first.
        rc = ((V8iTransmitFn)trFn)(recv, cmd, 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_cmdLastExc = GetExceptionCode();
        return -1;
    }
    return rc;
}
int HasGuarded(void* fn, void* recv, const void* id) {
    int rc = 0;
    __try {
        rc = ((V8iHasFn)fn)(recv, id);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_cmdLastExc = GetExceptionCode();
        return -1;
    }
    return rc;
}
}  // namespace

// Command { CommandID id; int param; void* object; }, CommandID { Guid; uint }
// (x64 layout: 16 + 4 + 4 + 8 = 32 bytes)
struct __declspec(align(8)) V8Cmd {
    unsigned char group[16];
    unsigned int cmdNum;
    int param;
    void* object;
#if !defined(_WIN64)
    // On x86 the platform's Command is 28 bytes, but align(8) rounds the
    // struct up to 32. The padding is spelled out so the layout is the same
    // on both architectures and the compiler does not warn about it.
    unsigned int pad;
#endif
};
static const unsigned char kConfigGroup[16] = {
    0x81, 0xBB, 0x0C, 0xF1, 0x79, 0xF6, 0xD4, 0x11,
    0x9D, 0xD3, 0x00, 0x50, 0xBA, 0xE2, 0xBC, 0x79};

// Designer commands must run on the 1C UI thread. The payload subclasses the
// frame window once; a posting thread fills the pending slot and posts a
// custom message, the UI thread's WndProc executes transmitCommand and flips
// the done flag. Pod-only state; no calls from the io thread into 1C UI.
// 8.5 command receiver, captured from the slot-31 forwarder of a live
// ITopLevelFrame (declared here: the marshal bridges below read them).
static uintptr_t g85_recv = 0;
static uintptr_t g85_recvVt = 0;
static uintptr_t g85_recvFrame = 0;   // frame object the receiver was captured from
static void V8iCaptureCmdRecv(void* obj);   // 8.5 slot-31 walk, defined below
namespace {
const UINT kV8iCmdMsg = kPendingMsg;
// The slot itself (request id, cancelled flag, result id) is in
// platform/pending_slot.h: the io thread and the native-menu worker share it,
// and a message that arrives after its timeout must not run the next request
// (A50, A51). The command bytes are shared by both platform layouts at the same
// address: 8.3 transmits V8Cmd (32 bytes), 8.5 expects the RECON-85 layout
// (CommandID padded to 24, param at 24, object at 32 — 40 bytes). The sender
// zeroes raw first, so either interpretation of the padding reads param=0 /
// object=nullptr; hasHandler (CommandID, 20 bytes) is identical in both.
V8iPendingSlot g_pending = {};
// The pending slot is shared by the io thread (cmd commands) and the
// native-menu worker (functor steps) — fill+send+wait sections hold it.
SRWLOCK g_pendingLock = SRWLOCK_INIT;
HWND g_cmdHwnd = NULL;
bool g_cmdSubclassed = false;
bool g_cmdViaSubclass = false;
LONG_PTR g_cmdOldWndProc = 0;

typedef LRESULT(CALLBACK* V8iSubclassProc)(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);
typedef LRESULT(WINAPI* V8iDefSubclassProcFn)(HWND, UINT, WPARAM, LPARAM);
// Функция-получатель DefSubclassProc вынесена из V8iCmdSubclass: там __try,
// а локальный статик с guard-объектом требует раскрутки (C2712).
V8iDefSubclassProcFn V8iDefSubclassProcFnGet() {
    static V8iDefSubclassProcFn defFn = []() -> V8iDefSubclassProcFn {
        HMODULE ctl = GetModuleHandleW(L"comctl32.dll");
        return ctl ? (V8iDefSubclassProcFn)GetProcAddress(ctl, "DefSubclassProc") : nullptr;
    }();
    return defFn;
}

// The one executor of the pending slot, called on the 1C UI thread by both
// paths that can own it (the comctl32 subclass and the WndProc replacement):
// each request runs exactly once, whichever hook the platform tolerated.
// `s` was already claimed for `msgId` by the caller.
void V8iExecuteClaimed(V8iPendingSlot* s, UINT_PTR msgId) {
    // Copy the request out of the shared slot before running it: the sender
    // starts the next request as soon as it holds the lock again, and reading
    // the fields afterwards would mix two requests. The id is re-checked after
    // the copy, so a torn snapshot is dropped instead of executed (A51).
    void* recv = s->recv;
    void* trFn = s->trFn;
    void (*fun)(void*) = s->fun;
    void* funArg = s->funArg;
    const int mode = s->mode;
    unsigned char raw[48];
    memcpy(raw, s->raw, sizeof(raw));
    if (!PendingClaim(s, msgId)) return;   // retired while copying: do not run

    int rc = -1;
    LONG exc = 0;
    if (mode == 2) {
        // The slot-31 walk calls into core85, which on 8.5 only answers on the
        // UI thread — so the capture rides the same marshal bridge.
        V8iCaptureCmdRecv(recv);
        rc = g85_recv ? 0 : -1;
    } else if (mode == 3) {
        // UI-thread functor (native-menu build steps). An exception here must
        // not kill 1C: caught and reported through rc.
        __try {
            fun(funArg);
            rc = 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            rc = (int)GetExceptionCode();
        }
    } else {
        rc = mode == 1 ? HasGuarded(trFn, recv, raw) : TransmitGuarded(trFn, recv, raw);
        if (rc < 0) exc = g_cmdLastExc;
    }
    PendingPublish(s, msgId, rc, exc);
}

LRESULT CALLBACK V8iCmdSubclass(HWND h, UINT m, WPARAM w, LPARAM l,
                                UINT_PTR id, DWORD_PTR data) {
    (void)id;   // the subclass id is not used: one window, one pending slot
    (void)l;
    if (m == kV8iCmdMsg) {
        V8iPendingSlot* p = (V8iPendingSlot*)data;
        const UINT_PTR msgId = (UINT_PTR)w;
        if (PendingClaim(p, msgId)) V8iExecuteClaimed(p, msgId);
        return 0;   // a stale message is dropped: its sender already timed out
    }
    V8iDefSubclassProcFn defFn = V8iDefSubclassProcFnGet();
    return defFn ? defFn(h, m, w, l) : DefWindowProcW(h, m, w, l);
}

LRESULT CALLBACK V8iCmdWndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    (void)l;
    if (m == kV8iCmdMsg) {
        const UINT_PTR msgId = (UINT_PTR)w;
        if (PendingClaim(&g_pending, msgId)) V8iExecuteClaimed(&g_pending, msgId);
        return 0;
    }
    return CallWindowProcW((WNDPROC)g_cmdOldWndProc, h, m, w, l);
}

bool EnsureCmdUi(HWND* outHwnd, DWORD* outErr, const char** outPath) {
    // 1C recreates its top-level windows (toolbar/title changes) and can drop a
    // replaced WndProc; re-verify and re-install on every call unless the
    // comctl32 subclass chain is our installation.
    if (g_cmdSubclassed && g_cmdHwnd && IsWindow(g_cmdHwnd)) {
        // A121: a recreated 1C window can get the same HWND back for a window
        // of another class. Marshal into it and the message goes nowhere while
        // SendMessageTimeout reports success -- "did not answer" forever, with
        // the re-enumeration below never reached. The class is the identity
        // check: no longer a 1C frame here means reset and re-discover.
        wchar_t cls[64] = {};
        const bool ourFrame = GetClassNameW(g_cmdHwnd, cls, 64) > 0 &&
                              (wcscmp(cls, L"V8TopLevelFrame") == 0 ||
                               wcsncmp(cls, L"V8Window0", 9) == 0);
        if (!ourFrame) {
            LogLine("cmd: hwnd 0x%llX is now class %ls, not a 1C frame -- re-discovering",
                    (unsigned long long)(uintptr_t)g_cmdHwnd, cls);
            g_cmdSubclassed = false;
            g_cmdViaSubclass = false;
            g_cmdHwnd = nullptr;
            g_cmdOldWndProc = 0;
        } else {
            if (!g_cmdViaSubclass) {
                // Re-assert our WndProc right before every send: 1C re-creates its
                // toolbar/UI and re-sets the frame WndProc while a config opens.
                LONG_PTR old = SetWindowLongPtrW(g_cmdHwnd, GWLP_WNDPROC, (LONG_PTR)V8iCmdWndProc);
                if (!old) return false;
                if (old != (LONG_PTR)V8iCmdWndProc) g_cmdOldWndProc = old;
                *outPath = "wndproc";
            } else {
                *outPath = "subclass";
            }
            *outHwnd = g_cmdHwnd;
            return true;
        }
    }
    std::vector<WindowEntry> wins = EnumProcessWindows();
    HWND frame = nullptr;
    for (const WindowEntry& w : wins)
        if (w.cls == L"V8TopLevelFrame" ||
            w.cls.rfind(L"V8Window0", 0) == 0) { frame = w.hwnd; break; }
    if (!frame) { *outErr = 0xFFFFFF01; return false; }

    // Preferred: comctl32 SetWindowSubclass (chains cleanly with 1C's own).
    HMODULE ctl = GetModuleHandleW(L"comctl32.dll");
    if (ctl) {
        typedef BOOL(WINAPI* V8iSetWindowSubclassFn)(HWND, V8iSubclassProc, UINT_PTR, DWORD_PTR);
        V8iSetWindowSubclassFn setFn =
            (V8iSetWindowSubclassFn)GetProcAddress(ctl, "SetWindowSubclass");
        if (setFn && setFn(frame, V8iCmdSubclass, 1, (DWORD_PTR)&g_pending)) {
            g_cmdHwnd = frame;
            g_cmdSubclassed = true;
            g_cmdViaSubclass = true;
            *outHwnd = frame;
            *outPath = "subclass";
            return true;
        }
    }

    // Fallback: classic WndProc replacement, chaining via CallWindowProcW.
    LONG_PTR old = SetWindowLongPtrW(frame, GWLP_WNDPROC, (LONG_PTR)V8iCmdWndProc);
    if (!old || old == (LONG_PTR)V8iCmdWndProc) {
        *outErr = GetLastError();
        return false;
    }
    g_cmdOldWndProc = old;
    g_cmdHwnd = frame;
    g_cmdSubclassed = true;
    g_cmdViaSubclass = false;
    *outHwnd = frame;
    *outPath = "wndproc";
    return true;
}

// One request for the marshal bridge: what the 1C UI thread should do.
struct V8iRequest {
    int mode = 1;                  // see V8iPendingSlot::mode
    void* recv = nullptr;
    void* trFn = nullptr;
    void (*fun)(void*) = nullptr;
    void* funArg = nullptr;
    const void* cmd = nullptr;     // command bytes, copied into the slot
    size_t cmdSize = 0;
};

struct V8iMarshalResult {
    int status;   // 0 answered, -98 no marshal window, -97 not delivered,
                  // -96 timeout (the request was retired: it will not run)
    int rc;
    LONG exc;
};

// Fills the slot, hands the request to the 1C UI thread and waits for the
// answer. This is the only writer of the slot: it holds g_pendingLock for the
// whole fill/send/read, so no two requests can interleave (A50), and it stamps
// the message with the request id (A51).
V8iMarshalResult V8iMarshal(const V8iRequest& r, DWORD timeoutMs, bool abortIfHung) {
    V8iMarshalResult res{-98, 0, 0};
    HWND cmdHwnd = nullptr;
    DWORD ensureErr = 0;
    const char* marshalPath = "";
    if (!EnsureCmdUi(&cmdHwnd, &ensureErr, &marshalPath)) return res;

    AcquireSRWLockExclusive(&g_pendingLock);
    g_pending.recv = r.recv;
    g_pending.trFn = r.trFn;
    g_pending.fun = r.fun;
    g_pending.funArg = r.funArg;
    g_pending.mode = r.mode;
    memset(g_pending.raw, 0, sizeof(g_pending.raw));
    if (r.cmd && r.cmdSize) {
        const size_t n = r.cmdSize > sizeof(g_pending.raw) ? sizeof(g_pending.raw)
                                                          : r.cmdSize;
        memcpy(g_pending.raw, r.cmd, n);
    }
    const UINT_PTR id = PendingBegin(&g_pending);

    // Synchronous cross-thread dispatch: blocks until the UI thread's WndProc
    // runs (SMTO_BLOCK) or the target is hung (capped by the timeout).
    DWORD_PTR smRes = 0;
    const DWORD flags = abortIfHung ? (SMTO_ABORTIFHUNG | SMTO_BLOCK) : SMTO_BLOCK;
    const LRESULT sent = SendMessageTimeoutW(cmdHwnd, kV8iCmdMsg, (WPARAM)id, 0,
                                            flags, timeoutMs, &smRes);
    if (!sent) {
        PendingAbandon(&g_pending, id);
        res.status = -97;
    } else if (!PendingAnswered(&g_pending, id)) {
        // The message is still out there: 1C delivers it after the timeout.
        // Retire the id so it finds nothing to run instead of executing the
        // next request (A51).
        PendingAbandon(&g_pending, id);
        res.status = -96;
    } else {
        res.status = 0;
        res.rc = g_pending.rc;
        res.exc = g_pending.exc;
        // The request is over: retire the id so a duplicate message cannot run
        // it a second time.
        PendingRetire(&g_pending, id);
    }
    ReleaseSRWLockExclusive(&g_pendingLock);
    return res;
}

}  // namespace

// A67: a heap page can be freed between VirtualQuery and the read (1C
// allocates constantly), so a scan must not dereference memory it has just
// described as committed. Defined with the x86 scanner below; declared here
// because the x64 scanners above are at namespace scope.
static bool ReadPtrSafe(uintptr_t addr, uintptr_t* out);

#if defined(_WIN64)
// True when `vt` is a config.dll .rdata table whose slots 3..40 point into
// config.dll .text — the shape shared by the ITopLevelFrame vtable family.
// Used both by the discovery and to re-validate the cached frame object:
// 1C destroys transient frames, and freed memory reads as garbage (live:
// a stale object's "vtable" was a module base).
static bool X64FrameVtValid(const ModuleRange& cfg, uintptr_t vt) {
    if (!vt) return false;
    PeImage cfgImg = ParsePe(cfg.base);
    if (!cfgImg.valid) return false;
    const PeSection* textSec = nullptr;
    const PeSection* rdataSec = nullptr;
    for (const PeSection& s : cfgImg.sections) {
        if (s.Executable() && s.name == ".text") textSec = &s;
        if (s.Readable() && !s.Executable() && s.name == ".rdata") rdataSec = &s;
    }
    if (!textSec || !rdataSec) return false;
    const uintptr_t textLo = cfg.base + textSec->va;
    const uintptr_t textHi = textLo + textSec->virtualSize;
    const uintptr_t rdataLo = cfg.base + rdataSec->va;
    const uintptr_t rdataHi = rdataLo + rdataSec->virtualSize;
    if (vt < rdataLo || vt >= rdataHi) return false;
    if (!IsReadable((void*)vt, 41 * sizeof(void*))) return false;
    for (int s = 3; s <= 40; ++s) {
        uintptr_t fn = ((uintptr_t*)vt)[s];
        if (fn < textLo || fn >= textHi) return false;
    }
    return true;
}

// x64 runtime calibration: the hardcoded ITopLevelFrame vtable RVA below is
// valid for 8.3.27.1989 only — on other 8.3 patches (8.3.27.2342, live) an
// unrelated vtable sits at the same RVA, the scan finds a wrong object and
// the receiver chain fails ("no working receiver chain"). Same heuristics as
// the x86 discovery: a heap object whose vtable lives in config.dll .rdata
// with slots 3..40 pointing into config.dll .text, and whose receiver chain
// (core = obj+8, recv = core - off, recvVt readable, transmit slot readable
// inside a loaded module) validates. POD-only reads; no calls into 1C.
static uintptr_t DiscoverFrameVtblX64(const ModuleRange& cfg) {
    PeImage cfgImg = ParsePe(cfg.base);
    if (!cfgImg.valid) return 0;
    const PeSection* rdataSec = nullptr;
    for (const PeSection& s : cfgImg.sections) {
        if (s.Readable() && !s.Executable() && s.name == ".rdata") rdataSec = &s;
    }
    if (!rdataSec) return 0;
    const uintptr_t rdataLo = cfg.base + rdataSec->va;
    const uintptr_t rdataHi = rdataLo + rdataSec->virtualSize;

    std::vector<ModuleRange> mods;
    for (const ModuleRange& m : EnumModules()) mods.push_back(m);
    auto insideModule = [&mods](uintptr_t a) {
        for (const ModuleRange& m : mods)
            if (a >= m.base && a < m.base + m.size) return true;
        return false;
    };

    // one heap walk: objects whose first qword is a config.dll .rdata vtable
    std::vector<uintptr_t> objs;
    uintptr_t addr = 0x10000;
    while (addr < 0x00007FFFFFFFFFFFULL) {
        MEMORY_BASIC_INFORMATION mi = {};
        if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
        uintptr_t end = addr + mi.RegionSize;
        bool usable = mi.State == MEM_COMMIT &&
                      (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                      !(mi.Protect & PAGE_GUARD);
        if (usable) {
            const uintptr_t cap = mi.RegionSize > 64 * 1024 * 1024
                                      ? 64 * 1024 * 1024 : (uintptr_t)mi.RegionSize;
            for (uintptr_t p = (uintptr_t)mi.BaseAddress;
                 p < (uintptr_t)mi.BaseAddress + cap; p += sizeof(void*)) {
                uintptr_t v = 0;
                if (!ReadPtrSafe(p, &v)) continue;
                if (v < rdataLo || v >= rdataHi) continue;
                if (!X64FrameVtValid(cfg, v)) continue;
                objs.push_back(p);
                if (objs.size() >= 64) break;
            }
        }
        if (objs.size() >= 64) break;
        addr = end == addr ? addr + sizeof(void*) : end;
    }

    // receiver chain must validate; try the documented offset first. The
    // structural checks alone are NOT enough (8.3.27.2342 live: nine heap
    // slots pass them, the first pick was garbage that died within 21 ms) —
    // every candidate is probed live: hasHandler(45) on the UI thread through
    // the marshal bridge. Only a receiver that answers without an exception
    // is trusted; the first alive-but-silent one is the fallback.
    static const uintptr_t kRecvOffs[] = {0x20, 0x10, 0x18, 0x28, 0x30, 0x38, 0x40, 0x08};
    uintptr_t fallbackObj = 0, fallbackOff = 0;
    for (uintptr_t obj : objs) {
        uintptr_t core = 0;
        if (!ReadPtrSafe(obj + sizeof(void*), &core) || !core) continue;
        if (!IsReadable((void*)core, sizeof(void*))) continue;
        for (uintptr_t off : kRecvOffs) {
            uintptr_t recv = core - off;
            if (!IsReadable((void*)recv, sizeof(void*))) continue;
            uintptr_t recvVt = 0;
            if (!ReadPtrSafe(recv, &recvVt)) continue;
            if (!IsReadable((void*)recvVt, 6 * sizeof(void*))) continue;
            if (!insideModule(recvVt)) continue;
            uintptr_t tr = 0;
            if (!ReadPtrSafe(recvVt + 3 * sizeof(void*), &tr)) continue;
            if (!insideModule(tr)) continue;
            if (!IsReadable((void*)tr, 32)) continue;
            if (*(const unsigned char*)tr == 0xCC) continue;   // int3 padding, not code

            // live probe: hasHandler(45), mode 1, SEH on the UI thread
            void* hasTr = (void*)((uintptr_t*)recvVt)[5];
            if (!IsReadable(hasTr, 1)) continue;
            V8Cmd probeCmd = {};
            memcpy(probeCmd.group, kConfigGroup, 16);
            probeCmd.cmdNum = 45;
            V8iRequest req;
            req.mode = 1;
            req.recv = (void*)recv;
            req.trFn = hasTr;
            req.cmd = &probeCmd;
            req.cmdSize = sizeof(probeCmd);
            const V8iMarshalResult mr = V8iMarshal(req, 10000, true);
            if (mr.status == -98) break;   // no frame window yet — structural pick
            if (mr.status != 0) continue;
            if (mr.exc != 0 || mr.rc < 0) continue;   // wrong chain
            bool probedOk = mr.exc == 0 && mr.rc >= 0 && mr.rc == 0;
            if (probedOk && fallbackObj == 0) {
                fallbackObj = obj; fallbackOff = off;   // alive, no handler yet
                continue;
            }
            g_x64RecvOffset = off;
            LogLine("cmd x64 discovery: frame=0x%llX recvOff=0x%llX recv=0x%llX probed=1",
                    (unsigned long long)obj, (unsigned long long)off,
                    (unsigned long long)recv);
            return obj;
        }
    }
    if (fallbackObj) {
        g_x64RecvOffset = fallbackOff;
        LogLine("cmd x64 discovery: frame=0x%llX recvOff=0x%llX (fallback, alive)",
                (unsigned long long)fallbackObj, (unsigned long long)fallbackOff);
        return fallbackObj;
    }
    return 0;
}
#endif

static bool ReadPtrSafe(uintptr_t addr, uintptr_t* out) {
    __try {
        *out = *(uintptr_t*)addr;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

#if !defined(_WIN64)
// x86 runtime calibration: find the ITopLevelFrame vtable without hardcoded
// constants. Returns 0 when not found. POD-only reads; no calls into 1C.
static uintptr_t g_x86RecvOffset = 0x20;

// A heap page can be freed between VirtualQuery and the read (1C allocates
// constantly), and a vtable near the end of .rdata can overrun into a page the
// loader did not commit. Both faults used to take down the payload io thread.
static bool ReadU32Safe(uintptr_t addr, uint32_t* out) {
    __try {
        *out = *(uint32_t*)addr;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static uintptr_t DiscoverFrameVtblX86(const ModuleRange& cfg) {
    PeImage cfgImg = ParsePe(cfg.base);
    if (!cfgImg.valid) return 0;
    const PeSection* textSec = nullptr;
    const PeSection* rdataSec = nullptr;
    for (const PeSection& s : cfgImg.sections) {
        if (s.Executable() && s.name == ".text") textSec = &s;
        if (s.Readable() && !s.Executable() && s.name == ".rdata") rdataSec = &s;
    }
    if (!textSec || !rdataSec) return 0;
    const uintptr_t textLo = cfg.base + textSec->va;
    const uintptr_t textHi = textLo + textSec->virtualSize;
    const uintptr_t rdataLo = cfg.base + rdataSec->va;
    const uintptr_t rdataHi = rdataLo + rdataSec->virtualSize;

    ModuleRange frame;
    bool haveFrame = FindModule(L"frame.dll", frame);
    uintptr_t frameRdataLo = 0, frameRdataHi = 0, frameTextLo = 0, frameTextHi = 0;
    if (haveFrame) {
        PeImage fImg = ParsePe(frame.base);
        for (const PeSection& s : fImg.sections) {
            if (s.Executable() && s.name == ".text") {
                frameTextLo = frame.base + s.va;
                frameTextHi = frameTextLo + s.virtualSize;
            }
            if (s.Readable() && !s.Executable() && s.name == ".rdata") {
                frameRdataLo = frame.base + s.va;
                frameRdataHi = frameRdataLo + s.virtualSize;
            }
        }
    }

    // walk heap once, remember (object -> vtable) where vtable is in config .rdata
    std::vector<uintptr_t> objs;
    uintptr_t addr = 0x10000;
    while (addr < 0x7FFFFFFF) {
        MEMORY_BASIC_INFORMATION mi = {};
        if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
        uintptr_t end = addr + mi.RegionSize;
        bool usable = mi.State == MEM_COMMIT &&
                      (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                      !(mi.Protect & PAGE_GUARD);
        if (usable) {
            const uintptr_t cap = mi.RegionSize > 64 * 1024 * 1024 ? 64 * 1024 * 1024 : (uintptr_t)mi.RegionSize;
            for (uintptr_t p = (uintptr_t)mi.BaseAddress; p < (uintptr_t)mi.BaseAddress + cap; p += 4) {
                uint32_t v = 0;
                if (!ReadU32Safe(p, &v)) continue;
                if (v < (uint32_t)rdataLo || v >= (uint32_t)rdataHi) continue;
                // vtable start must satisfy: no header dwords (IUnknown trio) — slots 3..40 in .text
                bool ok = true;
                for (int s = 3; s <= 40; ++s) {
                    uint32_t fn = 0;
                    if (!ReadU32Safe((uintptr_t)v + s * 4, &fn) ||
                        fn < (uint32_t)textLo || fn >= (uint32_t)textHi) { ok = false; break; }
                }
                if (!ok) continue;
                objs.push_back(p);
            }
        }
        addr = end == addr ? addr + 4 : end;
    }

    // try each (object, vtable) — receiver chain must land in frame.dll
    static const uintptr_t kRecvOffs[] = {0x10, 0x20, 0x1C, 0x18, 0x14, 0x24, 0x28,
                                          0x0C, 0x08, 0x04, 0x30, 0x34, 0x38, 0x3C, 0x40};
    for (size_t i = 0; i < objs.size(); ++i) {
        uint32_t core32 = 0;
        if (!ReadU32Safe(objs[i] + 4, &core32) || !core32) continue;
        uintptr_t core = core32;
        if (!IsReadable((void*)core, 4)) continue;
        for (size_t off = 0; off < sizeof(kRecvOffs) / sizeof(kRecvOffs[0]); ++off) {
            uintptr_t recv = core - kRecvOffs[off];
            uint32_t recvVt = 0;
            if (!ReadU32Safe(recv, &recvVt)) continue;
            if (!haveFrame) continue;
            if (recvVt < (uint32_t)frameRdataLo || recvVt >= (uint32_t)frameRdataHi) continue;
            uint32_t tr = 0;
            if (!ReadU32Safe((uintptr_t)recvVt + 3 * 4, &tr)) continue;
            if (tr < (uint32_t)frameTextLo || tr >= (uint32_t)frameTextHi) continue;
            // transmitCommand is a real method (thiscall, 2 stack args -> ret 8),
            // NOT a 6-byte property getter `mov eax,[ebp+8]; mov eax,[eax+off]; pop ebp; ret 4`
            // (several interface wrapper vtables near the frame use those).
            const unsigned char* code = (const unsigned char*)tr;
            if (!IsReadable((void*)code, 0x60)) continue;
            static const unsigned char kGetter[] = {0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x40};
            if (memcmp(code, kGetter, sizeof(kGetter)) == 0) continue;
            bool sawRet = false;
            for (int b = 0; b < 0x100; ++b) {
                if (code[b] == 0xC2 && b + 2 < 0x100 &&
                    ((code[b + 1] == 0x08 && code[b + 2] == 0x00) ||   // 2 stack args
                     (code[b + 1] == 0x0C && code[b + 2] == 0x00))) {  // 3 stack args (self, cmd, deact)
                    sawRet = true;
                    break;
                }
            }
            if (!sawRet) continue;
            g_x86RecvOffset = kRecvOffs[off];
            return objs[i];  // the frame object itself (vtable validated above)
        }
    }
    return 0;
}
#endif

typedef HRESULT(__stdcall* V8iQIFn)(void*, const GUID*, void**);
static int V8iQIProbe(void* obj, const GUID* iid, void** out) {
    int rc = -1;
    __try {
        rc = ((V8iQIFn)(*(void**)obj))(obj, iid, out);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        rc = -2;
    }
    return rc;
}

// --- 8.5 UI-thread bridge ---
// 1C 8.5 crashes (0xC0000005) when core85 functions are called from a foreign
// thread. To run them on the UI thread we subclass the main window for a
// moment and post WM_APP+0x602; the subclass proc executes
// current_process() -> getService(IID_IEventService) and caches the results.
// (g85_recv / g85_recvVt live near the top of the file, next to the marshal
// bridge that reads them.)
static uintptr_t g85_fn = 0;
static uintptr_t g85_proc = 0;
static uintptr_t g85_procVt = 0;
static uintptr_t g85_svc = 0;
static uintptr_t g85_svcVt = 0;
static uintptr_t g85_svc2 = 0;
static uintptr_t g85_svc2Vt = 0;
static uintptr_t g85_svc3 = 0;
static uintptr_t g85_svc3Vt = 0;
static uintptr_t g85_svc4 = 0;
static uintptr_t g85_svc4Vt = 0;
static int g85_svcSlot = -1;
static int g85_svc2Slot = -1;
static uintptr_t g85_frame = 0;
static uintptr_t g85_frameVt = 0;
static uintptr_t g85_frames[4] = {};
static int g85_nFrames = 0;
static uintptr_t g85_qProcFrame = 0, g85_qProcRecv = 0;
static uintptr_t g85_qCmdFrame = 0, g85_qCmdRecv = 0;
static uintptr_t g85_qEvFrame = 0, g85_qEvRecv = 0;
static int g85_sawMsg = 0;
static volatile int g85_subscribed = 0;
static uintptr_t g85_slots[24] = {};
static uintptr_t g85_uiWin = 0;
static uintptr_t g85_evFrame = 0;
static volatile long g85_evCount = 0;
static const GUID g85_kExitEv = {0x18B3F170, 0x4979, 0x11D6,
                                 {0xB2, 0x2B, 0x00, 0x50, 0xBA, 0xE2, 0xBC, 0x79}};
// eventCreateFrame: fired when the platform creates a frame; the event object
// IS the ITopLevelFrame (verified live on 8.5.1.1529 — object vtable
// config.dll+0x2ED3B0, and its vtbl[30] gives the command receiver).
static const GUID g85_kCreateFrameEv = {0x3573FFE0, 0x2FFF, 0x11D5,
                                        {0xBF, 0x5E, 0x00, 0x50, 0xBA, 0xE2, 0xBC, 0x79}};
static volatile long g85_exitEvCount = 0;
static volatile unsigned long g85_attachTick = 0;
// Diagnostic split of the two candidate receiver chains — one live run settles
// which is real on 8.5 (the code comment below claimed A; the skill's later
// live finding is B):
//   A) obj IS ITopLevelFrame         -> obj->vtbl[30] = commandReceiver
//   B) obj is an IUnknown wrapper   -> QI(obj, IID_ITopLevelFrame) = frame
//                                        -> frame->vtbl[30] = commandReceiver
// Both results are kept so cmdinfo/frames can report them without guessing.
static const GUID g85_kIID_TopFrame = {0xDE300901, 0xA120, 0x11d4,
                                       {0x94, 0x29, 0x00, 0x80, 0x48, 0xDA, 0x11, 0xF9}};
static uintptr_t g85_dirRecv = 0, g85_dirRecvVt = 0;       // path A: obj->vtbl[30]
static uintptr_t g85_qiFrame = 0, g85_qiFrameVt = 0;       // path B: QI(obj) result
static uintptr_t g85_qiRecv = 0, g85_qiRecvVt = 0;         // path B: frame->vtbl[30]
static long g85_dirExc = 0;    // exception from calling vtbl[30] on obj (A)
static long g85_qiExc = 0;     // error code from QI(obj) (B)
static long g85_qiCallExc = 0; // exception from vtbl[30] on the QI'd frame (B)
static uintptr_t g85_dump[4] = {};                       // obj qwords (layout)

typedef void* (__cdecl* V8iCurProcFn)();
typedef void* (__cdecl* V8iGetSvcFn)(void*, const GUID*);
static WNDPROC g85_origWndProc = nullptr;

static void V8iScanFrame85();

// Releases one reference through slot 2 (Release) of a 1C object.
static void V8iReleaseRef(uintptr_t obj) {
    if (!obj || !IsReadable((void*)obj, sizeof(void*))) return;
    __try {
        void** vt = *(void***)obj;
        if (vt && IsReadable((void*)vt, 3 * sizeof(void*)) && vt[2])
            ((void(__stdcall*)(void*))vt[2])((void*)obj);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// The diagnostic QI probes take a reference each. The subscribe chain runs
// them on every attempt (up to 4000 at 50 ms), and the results used to be kept
// forever - one leaked reference per probe per attempt, keeping 1C objects
// alive for the whole session (A66). Every attempt now releases what the
// previous one took.
static void V8iReleaseDiagRefs() {
    V8iReleaseRef(g85_qProcFrame); g85_qProcFrame = 0;
    V8iReleaseRef(g85_qProcRecv);  g85_qProcRecv = 0;
    V8iReleaseRef(g85_qCmdFrame);  g85_qCmdFrame = 0;
    V8iReleaseRef(g85_qCmdRecv);   g85_qCmdRecv = 0;
    V8iReleaseRef(g85_qEvFrame);   g85_qEvFrame = 0;
    V8iReleaseRef(g85_qEvRecv);    g85_qEvRecv = 0;
}
// How many attempts still run the probes: they only feed the cmdinfo
// diagnostics, and the first ones already say whether the layout matches.
static volatile long g85_diagRuns = 0;
constexpr long kG85DiagRuns = 64;

static LRESULT CALLBACK V8iSubclass85(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_APP + 0x602) {
        g85_sawMsg = 1;
        void* proc = nullptr;
        __try {
            proc = ((V8iCurProcFn)g85_fn)();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            proc = nullptr;
        }
        g85_proc = (uintptr_t)proc;
        g85_procVt = proc ? *(uintptr_t*)proc : 0;
        for (int i = 0; i < 24; ++i) {
            g85_slots[i] = 0;
            __try { g85_slots[i] = ((uintptr_t*)g85_procVt)[i]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { g85_slots[i] = 0; }
        }
        if (proc && g85_procVt) {
            static const GUID kIID_EventService = {0xEBF766AA, 0xF32C, 0x11D3,
                                                   {0x98, 0x51, 0x00, 0x80, 0x48, 0xDA, 0x12, 0x52}};
            static const GUID kIID_CmdService = {0x8F885821, 0xD353, 0x11D3,
                                                 {0x8A, 0x57, 0x00, 0x80, 0x48, 0xDA, 0x06, 0xDF}};
            void* svc = nullptr;
            void* svc2 = nullptr;
            void* svc3 = nullptr;
            void* svc4 = nullptr;
            int svcSlot = -1, svc2Slot = -1;
            __try {
                for (int slot : {14, 15}) {
                    uintptr_t f = 0;
                    __try { f = ((uintptr_t*)g85_procVt)[slot]; }
                    __except (EXCEPTION_EXECUTE_HANDLER) { f = 0; }
                    if (!f) continue;
                    void* r1 = nullptr, * r2 = nullptr;
                    __try { r1 = ((V8iGetSvcFn)f)(proc, &kIID_EventService); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { r1 = (void*)-1; }
                    __try { r2 = ((V8iGetSvcFn)f)(proc, &kIID_CmdService); }
                    __except (EXCEPTION_EXECUTE_HANDLER) { r2 = (void*)-1; }
                    if (slot == 14) { svc = r1; svc2 = r2; svcSlot = (r1 && r1 != (void*)-1) ? 14 : -1; svc2Slot = (r2 && r2 != (void*)-1) ? 14 : -1; }
                    else { svc3 = r1; svc4 = r2; }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                svc = nullptr;
            }
            g85_svc = (uintptr_t)svc;
            g85_svcVt = svc && svc != (void*)-1 ? *(uintptr_t*)svc : 0;
            g85_svc2 = (uintptr_t)svc2;
            g85_svc2Vt = svc2 && svc2 != (void*)-1 ? *(uintptr_t*)svc2 : 0;
            g85_svc3 = (uintptr_t)svc3;
            g85_svc3Vt = svc3 && svc3 != (void*)-1 ? *(uintptr_t*)svc3 : 0;
            g85_svc4 = (uintptr_t)svc4;
            g85_svc4Vt = svc4 && svc4 != (void*)-1 ? *(uintptr_t*)svc4 : 0;
            g85_svcSlot = svcSlot;
            g85_svc2Slot = svc2Slot;

            // QI the objects we already hold for ITopLevelFrame/ICommandReceiver.
            // A66: release what the previous attempt took (the pointers stay
            // empty when the probes are skipped, so cmdinfo never reports a
            // stale object), and stop running pure diagnostics after the first
            // attempts — the chain itself keeps retrying below.
            V8iReleaseDiagRefs();
            if (InterlockedIncrement(&g85_diagRuns) <= kG85DiagRuns) {
                static const GUID kIID_TopFrame = {0xDE300901, 0xA120, 0x11d4,
                                                   {0x94, 0x29, 0x00, 0x80, 0x48, 0xDA, 0x11, 0xF9}};
                static const GUID kIID_CmdRecv = {0x377A2018, 0xC51B, 0x4cf5,
                                                  {0xAC, 0x03, 0xA1, 0x50, 0x92, 0x66, 0xDF, 0x2D}};
                struct { uintptr_t obj; uintptr_t* out; } probes[] = {
                    {g85_proc, &g85_qProcFrame}, {g85_proc, &g85_qProcRecv},
                    {g85_svc2, &g85_qCmdFrame}, {g85_svc2, &g85_qCmdRecv},
                    {g85_svc, &g85_qEvFrame}, {g85_svc, &g85_qEvRecv},
                };
                const GUID* iids[] = {&kIID_TopFrame, &kIID_CmdRecv, &kIID_TopFrame,
                                      &kIID_CmdRecv, &kIID_TopFrame, &kIID_CmdRecv};
                for (int i = 0; i < 6; ++i) {
                    *probes[i].out = 0;
                    if (!probes[i].obj || !IsReadable((void*)probes[i].obj, 16)) continue;
                    void* out = nullptr;
                    if (V8iQIProbe((void*)probes[i].obj, iids[i], &out) == 0 && out)
                        *probes[i].out = (uintptr_t)out;
                }

                // QI the window's OLE drop target — it is a real 1C object
                if (g85_uiWin) {
                    uintptr_t dt = (uintptr_t)GetPropW((HWND)g85_uiWin, L"OleDropTargetInterface");
                    if (dt && IsReadable((void*)dt, 16)) {
                        void* o1 = nullptr;
                        void* o2 = nullptr;
                        if (V8iQIProbe((void*)dt, &kIID_TopFrame, &o1) == 0 && o1) {
                            V8iReleaseRef(g85_qProcFrame);   // replace, do not stack refs
                            g85_qProcFrame = (uintptr_t)o1;
                        }
                        if (V8iQIProbe((void*)dt, &kIID_CmdRecv, &o2) == 0 && o2) {
                            V8iReleaseRef(g85_qProcRecv);
                            g85_qProcRecv = (uintptr_t)o2;
                        }
                    }
                }
            }

            // Slot 27 copies {ptr, refcount} from [rcx+0x148] — looks like a
            // getTopLevelFrame-style getter. Try it, then QI the result for
            // ICommandReceiver.
            if (proc) {
                struct { void* p; void* rc; } fr{};
                __try {
                    uintptr_t f27 = ((uintptr_t*)g85_procVt)[27];
                    if (f27)
                        ((void(__cdecl*)(void*, void*))f27)(proc, &fr);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    fr.p = nullptr;
                }
                g85_frame = (uintptr_t)fr.p;
                g85_frameVt = fr.p ? *(uintptr_t*)fr.p : 0;
                if (fr.p) {
                    static const GUID kIID_CmdRecv = {0x377A2018, 0xC51B, 0x4cf5,
                                                      {0xAC, 0x03, 0xA1, 0x50, 0x92, 0x66, 0xDF, 0x2D}};
                    void* recv = nullptr;
                    __try {
                        uintptr_t qi = 0;
                        __try { qi = ((uintptr_t*)*(uintptr_t*)fr.p)[0]; }
                        __except (EXCEPTION_EXECUTE_HANDLER) { qi = 0; }
                        if (qi)
                            ((HRESULT(__stdcall*)(void*, const GUID*, void**))qi)(
                                fr.p, &kIID_CmdRecv, &recv);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        recv = nullptr;
                    }
                    g85_recv = (uintptr_t)recv;
                    g85_recvVt = recv ? *(uintptr_t*)recv : 0;
                }
            }

            // Heap QI scan for IID_ITopLevelFrame — done in a helper that avoids
            // __try/C++ object conflicts; QI goes through the SEH probe.
            V8iScanFrame85();
            // Trace which stage the subscribe chain reached, for the early-path
            // diagnosis (hookcbt loads the payload without a cmdinfo run).
            {
                FILE* tf = nullptr;
                wchar_t subPath[MAX_PATH] = {};
                if (LogSideFile(L"subscribe.txt", subPath, _countof(subPath)) &&
                    _wfopen_s(&tf, subPath, L"a") == 0 && tf) {
                    fprintf(tf, "dt=%lu fn=%llx proc=%llx procVt=%llx svc=%llx svcVt=%llx "
                                "subscribed=%d evCount=%ld exitEv=%ld evFrame=%llx\n",
                            GetTickCount() - g85_attachTick, (unsigned long long)g85_fn,
                            (unsigned long long)g85_proc, (unsigned long long)g85_procVt,
                            (unsigned long long)g85_svc, (unsigned long long)g85_svcVt,
                            g85_subscribed, g85_evCount, g85_exitEvCount,
                            (unsigned long long)g85_evFrame);
                    fclose(tf);
                }
            }
        }
        return 0;
    }
    // Restoring "our own proc as the original" would make CallWindowProcW call
    // V8iSubclass85 again: the first ordinary message after that is an endless
    // recursion (0xC00000FD) in the UI thread of 1C. Ownership is enforced
    // where the subclass is installed; this is the last line of defence.
    if (g85_origWndProc && g85_origWndProc == (WNDPROC)V8iSubclass85)
        return DefWindowProcW(h, m, w, l);
    return g85_origWndProc ? CallWindowProcW(g85_origWndProc, h, m, w, l) : 0;
}

// Startup watch: the payload may be injected before 1C creates its main
// window. A worker polls for the window and, the moment it exists, runs the
// subscribe chain on the UI thread (through the subclass bridge) — early
// enough for the platform to deliver eventCreateFrame to us.
static BOOL CALLBACK V8iFindMainWindow(HWND w, LPARAM lp) {
    wchar_t cls[64] = {};
    GetClassNameW(w, cls, 64);
    if (wcsncmp(cls, L"V8Window0", 9) == 0 || wcsncmp(cls, L"V8TopLevelFrame", 15) == 0) {
        *(HWND*)lp = w;
        return FALSE;
    }
    return TRUE;
}

static LRESULT CALLBACK V8iCbtProc(int nCode, WPARAM wParam, LPARAM lParam);
static HHOOK g_cbtThreadHook;
static volatile long g_cbtThreadTid;
static volatile int g_cbtFired = 0;   // any 1C window creation was seen
static void V8iResolveCore85Proc(uintptr_t* outBase, uint32_t* outRva);

// Runs the subscribe attempt on the UI thread of the given window: the
// subclass is installed for the duration of one message, so the platform
// code runs on its own thread. The early path (the CBT hook, the inline
// CreateWindowExW hook), the polling watcher and "cmdinfo" can all reach this
// point, hence the lock: an overlapping attempt would capture the subclass proc
// as the "original" one and leave the window subclassed for good.
//
// A44: this function is the only owner of the subclass. "cmdinfo" used to do
// the same SetWindowLongPtrW dance by hand, bypassing both the lock and this
// check, while its own startup watcher installed the same subclass through
// here - the race captured V8iSubclass85 as g85_origWndProc, i.e. a window
// proc calling itself.
static volatile LONG g_subclassBusy = 0;
static bool V8iSubscribeOnUiThread(HWND h) {
    if (!h) return false;
    if (InterlockedCompareExchange(&g_subclassBusy, 1, 0) != 0) return false;
    bool installed = false;
    // Ask before setting: if the window already carries our proc (an earlier
    // attempt that has not been restored, or a concurrent one that won), there
    // is nothing to install and nothing to restore.
    WNDPROC cur = (WNDPROC)GetWindowLongPtrW(h, GWLP_WNDPROC);
    if (cur && cur != (WNDPROC)V8iSubclass85) {
        WNDPROC old = (WNDPROC)SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)V8iSubclass85);
        if (old == (WNDPROC)V8iSubclass85) {
            // Somebody else installed it between the two calls: leave it alone,
            // it will be restored by its owner.
        } else if (old) {
            g85_origWndProc = old;
            installed = true;
            SendMessageW(h, WM_APP + 0x602, 0, 0);
            SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)old);
        }
    }
    InterlockedExchange(&g_subclassBusy, 0);
    return installed;
}

// The thread-scoped CBT hook has done its job once any 1C window creation was
// seen (g_cbtFired): it is removed here rather than from inside the hook
// procedure, so no window creation keeps paying for it (A68).
static void V8iDropThreadCbt() {
    HHOOK h = g_cbtThreadHook;
    if (!h) return;
    g_cbtThreadHook = nullptr;
    g_cbtThreadTid = -1;
    if (!UnhookWindowsHookEx(h))
        LogLine("cbt: thread hook 0x%llX not removed (err %lu)", (unsigned long long)(uintptr_t)h,
                GetLastError());
}

static DWORD WINAPI V8iStartupWatchThread(LPVOID) {
    for (int i = 0; i < 4000 && !g85_subscribed; ++i) {
        if (g_cbtFired) V8iDropThreadCbt();   // the first window was seen: not needed
        HWND h = nullptr;
        EnumWindows(V8iFindMainWindow, (LPARAM)&h);
        if (h) {
            g85_uiWin = (uintptr_t)h;
            V8iSubscribeOnUiThread(h);
            // The global CBT hook never fires in 8.5 (cbtCalls stays 0 even for
            // newly opened windows), so try a thread-scoped one on the UI thread.
            if (!g_cbtThreadHook && !g_cbtFired) {
                DWORD tid = GetWindowThreadProcessId(h, nullptr);
                HINSTANCE self = nullptr;
                GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCWSTR)&V8iCbtProc, &self);
                HHOOK th = SetWindowsHookExW(WH_CBT, (HOOKPROC)&V8iCbtProc, self, tid);
                if (th) {
                    g_cbtThreadHook = th;
                    g_cbtThreadTid = (long)tid;
                }
            }
            // The core is not ready the instant the window appears, so keep
            // retrying until the subscribe chain actually succeeds.
            if (g85_subscribed) {
                V8iDropThreadCbt();
                return 0;
            }
            Sleep(50);
            continue;
        }
        Sleep(5);
    }
    V8iDropThreadCbt();
    return 0;
}

// --- early subscribe (plan_inj_ext P0-2) -----------------------------------
// Snegopat catches window creation with a WH_CBT hook and subscribes while the
// platform DLLs are loaded but the main window does not exist yet. Subscribing
// inside the hook itself crashes 1C (the core is not ready at that point), so
// the hook only remembers the window and starts a worker that retries the
// subscribe chain on that window's UI thread until the core answers.
static HHOOK g_cbtHook = nullptr;
static volatile long g_cbtFault = 0;
static volatile long g_cbtCalls = 0;
static volatile long g_cbtLastCode = -1;
static volatile long g_cbtCreateCount = 0;
static volatile long g_cbtStrCreates = 0;
static volatile long g_cbtWrites = 0;     // lines already written to cbt.txt
constexpr long kCbtDumpLines = 8;         // enough to see the class sequence
static char g_cbtFirstClass[96] = {};
static char g_cbtLastClass[96] = {};
static DWORD g_ownerPid = 0;

static DWORD WINAPI V8iEarlySubscribeThread(LPVOID);

// True when the current process is a 1C:Enterprise Configurator. The hook is
// loaded into every GUI process by the global WH_CBT, but only 1C is worth
// arming. Works even before the session sets g_ownerPid (the hook fires while
// the payload is still being loaded by Windows itself).
bool V8iIsTargetProcess() {
    wchar_t path[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    const wchar_t* leaf = wcsrchr(path, L'\\');
    leaf = leaf ? leaf + 1 : path;
    return _wcsicmp(leaf, L"1cv8.exe") == 0 ||
           _wcsicmp(leaf, L"1cv8c.exe") == 0;
}

static LRESULT CALLBACK V8iCbtProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // A fault inside a hook callback terminates the whole process
    // (0xC000041D), and during 1C start-up almost nothing is safe to call, so
    // the whole body sits under SEH: a failure must not kill the Configurator.
    __try {
        InterlockedIncrement(&g_cbtCalls);
        // Ignore non-1C processes the global hook is also delivered to
        // (Explorer etc). The pid filter alone is wrong: when the payload is
        // pulled in by the hook itself g_ownerPid is still 0.
        if (!V8iIsTargetProcess())
            return CallNextHookEx(g_cbtHook, nCode, wParam, lParam);
        if (nCode == HCBT_CREATEWND) {
            InterlockedIncrement(&g_cbtCreateCount);
            HWND hwnd = (HWND)wParam;
            CBT_CREATEWNDW* cw = (CBT_CREATEWNDW*)lParam;
            const wchar_t* cls = (cw && cw->lpcs) ? cw->lpcs->lpszClass : nullptr;
            // Remember what actually arrives, so the filter can be fixed from
            // real data instead of guesses.
            g_cbtLastCode = nCode;
            // IsReadable() covers bytes, the loop below reads wchar_t: 96
            // bytes are 48 characters, and the last one would be a half-word
            // past the checked range.
            constexpr size_t kClassBytes = 96;
            const size_t maxChars = kClassBytes / sizeof(wchar_t) - 1;
            if (cls && cls > (const wchar_t*)0x10000 && IsReadable(cls, kClassBytes)) {
                size_t k = 0;
                for (; k < maxChars && k < sizeof(g_cbtLastClass) - 1 && cls[k]; ++k)
                    g_cbtLastClass[k] = (char)((cls[k] < 128) ? cls[k] : '?');
                g_cbtLastClass[k] = 0;
                if (InterlockedIncrement(&g_cbtStrCreates) == 1 && k)
                    memcpy(g_cbtFirstClass, g_cbtLastClass, sizeof(g_cbtFirstClass));
                // Dump the classes that reach the hook, so we can see whether
                // the main window "V8Window0.xxx" passes through here at all.
                // Only the first few creations: a hook that fires for every
                // window in the process must not do file I/O for each one
                // (A68). The file goes next to the payload log: a hardcoded
                // path would point into a directory that does not exist on
                // another machine.
                if (InterlockedIncrement(&g_cbtWrites) <= kCbtDumpLines) {
                    wchar_t dumpPath[MAX_PATH] = {};
                    if (LogSideFile(L"cbt.txt", dumpPath, _countof(dumpPath))) {
                        FILE* cf = nullptr;
                        if (_wfopen_s(&cf, dumpPath, L"a") == 0 && cf) {
                            fprintf(cf, "%s\n", g_cbtLastClass);
                            fclose(cf);
                        }
                    }
                }
            } else {
                g_cbtLastClass[0] = 0;
            }
            // On 8.5 the main window is created with a numeric class in
            // CREATESTRUCT.lpszClass, so "V8Window0.xxx" never shows up here
            // (it is only visible via GetClassName on the finished window).
            // Exactly why Snegopat is force-patched on 8.5 to take the first
            // window. Only the first window of the Configurator is needed to
            // arm the subscribe chain — take it and unhook so nothing can
            // re-enter.
            if (!g_cbtFired) {
                g_cbtFired = 1;
                g85_uiWin = (uintptr_t)hwnd;
                HHOOK h = g_cbtHook;
                g_cbtHook = nullptr;
                if (h) UnhookWindowsHookEx(h);
                CreateThread(nullptr, 0, V8iEarlySubscribeThread, (LPVOID)hwnd, 0, nullptr);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_cbtFault = GetExceptionCode();
    }
    return CallNextHookEx(g_cbtHook, nCode, wParam, lParam);
}

// Installs the inline hook from a worker thread: the detour engine suspends
// the threads of the process while it patches the entry, and that must not
// happen under the loader lock (DllMain arms the early path).
static bool V8iInstallCreateWindowHook();
static DWORD WINAPI V8iInstallCreateWindowThread(LPVOID) {
    // Only the Configurator: the payload can be loaded into any process, and
    // the hook would otherwise sit on every window creation of that process.
    if (!V8iIsTargetProcess()) return 0;
    // The hook exists to catch the designer's main window before it exists.
    // If the window is already there, the polling watcher handles it and the
    // hook would only add overhead to every window creation in 1C.
    HWND h = nullptr;
    EnumWindows(V8iFindMainWindow, (LPARAM)&h);
    if (h) return 0;
    V8iInstallCreateWindowHook();
    return 0;
}

// Installs the hook; called from v8i_probe before the session starts, so the
// splash screen is still ahead.
bool V8iArmEarlySubscribe() {
    if (g_cbtHook) return true;
    g_ownerPid = GetCurrentProcessId();
    HMODULE self = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)&V8iCbtProc, &self)) return false;
    g_cbtHook = SetWindowsHookExW(WH_CBT, (HOOKPROC)&V8iCbtProc, self, 0);
    // The global CBT hook never fires in 8.5 (cbtCalls stays zero), so the
    // designer's main window is watched through an inline hook on
    // CreateWindowExW instead: that one sees every window creation.
    CreateThread(nullptr, 0, V8iInstallCreateWindowThread, nullptr, 0, nullptr);
    return g_cbtHook != nullptr;
}

// C linkage: the host installs this as a *global* WH_CBT hook (hMod = payload),
// so Windows loads the payload into the target before 1C creates its main
// window, and DllMain then arms the in-process hook as well.
static volatile long g_cbtExportCalls = 0;
extern "C" __declspec(dllexport) LRESULT CALLBACK V8iCbtProcExport(
    int nCode, WPARAM wParam, LPARAM lParam) {
    // Marker: does the global hook actually reach a 1C process?
    if (InterlockedIncrement(&g_cbtExportCalls) == 1) {
        wchar_t p[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, p, MAX_PATH);
        const wchar_t* leaf = wcsrchr(p, L'\\');
        leaf = leaf ? leaf + 1 : p;
        FILE* f = nullptr;
        wchar_t hitPath[MAX_PATH] = {};
        if (LogSideFile(L"cbt_hit.txt", hitPath, _countof(hitPath)) &&
            _wfopen_s(&f, hitPath, L"a") == 0 && f) {
            fprintf(f, "%lu %ls nCode=%d cbtCalls=%ld fired=%d\n",
                    GetCurrentProcessId(), p, nCode, g_cbtCalls, g_cbtFired);
            fclose(f);
        }
    }
    return V8iCbtProc(nCode, wParam, lParam);
}

static DWORD WINAPI V8iEarlySubscribeThread(LPVOID param) {
    HWND h = (HWND)param;
    // The hook fires on the very first 1C window, but the core (and its
    // services) are not initialized that early — subscribing immediately
    // crashes 1C. Wait for the platform to settle before the first attempt.
    // The cmdinfo command fills in g85_fn; with the hook path it must be
    // resolved here (static file resolution, safe at any time).
    if (!g85_fn) {
        uintptr_t base = 0;
        uint32_t rva = 0;
        V8iResolveCore85Proc(&base, &rva);
        if (base && rva) g85_fn = base + rva;
    }
    // eventCreateFrame fires when the MAIN window is created (~0.81s after
// launch; verified: with a 31ms subscribe it arrives, with a 3s subscribe it
// is long gone). So subscribe FAST. The early subscribe does not crash 1C —
// the "crash at start" seen earlier was a busy infobase (leftover process).
Sleep(0);
    for (int i = 0; i < 600 && !g85_subscribed; ++i) {
        Sleep(10);
        if (!IsWindow(h)) break;
        DWORD tid = GetWindowThreadProcessId(h, nullptr);
        if (tid && tid != GetCurrentThreadId()) {
            V8iSubscribeOnUiThread(h);
        }
        if (g85_subscribed) break;
    }
    LogLine("early subscribe: done, subscribed=%d", g85_subscribed);
    return 0;
}

// C linkage so DllMain can arm the hook the moment the payload is loaded —
// before 1C reaches its main window (the session in v8i_probe starts later).
extern "C" __declspec(dllexport) void V8iArmEarly() {
    g85_attachTick = GetTickCount();
    V8iArmEarlySubscribe();
}

void V8iStartStartupWatch() {
    // The inline hook on CreateWindowExW is armed by the early path (see
    // V8iArmEarlySubscribe) and only while the designer's main window does
    // not exist yet. This watcher is the working way to reach that window
    // once it is there: it polls, subclasses it and retries the subscribe
    // chain on the UI thread.
    CreateThread(nullptr, 0, V8iStartupWatchThread, nullptr, 0, nullptr);
}

// Runs on the 1C UI thread (called from the subclass proc).
// Subscribes to eventCreateFrame so the next frame creation hands us an
// ITopLevelFrame; a recipient object with a 4-slot vtable lives here.
static unsigned char g85_frameDump[64] = {};
static char g85_frameMod[40] = {};
static uint32_t g85_frameRva = 0;
static ULONG __stdcall V8iRecipAddRef(void*) { return 1; }
static ULONG __stdcall V8iRecipRelease(void*) { return 1; }
// ---------------------------------------------------------------------------
// 8.5: ITopLevelFrame -> ICommandReceiver.  Runs INSIDE the event callback, i.e.
// on the 1C UI thread: on 8.5 every core85 call from a foreign thread returns
// 0 (or crashes the process), so the receiver is captured exactly when the
// platform hands us the frame — the same moment Snegopat's
// `mainFrame.getCoreTopLevelFrame(coreMainFrame)` runs.
//   obj            = ITopLevelFrame (vtable config.dll+0x2ED3B0 on 8.5.1.1529)
//   obj->vtbl[30]  = commandReceiver(out ICommandReceiver*)   (v8api/window.v)
//   recv->vtbl[0]  = transmitCommand(const Command&, bool), [1] updateState,
//                   [2] hasHandler(const CommandID&)          (v8api/command.v)
// POD + SEH only: no std containers in this frame (MSVC C2712).
// ---------------------------------------------------------------------------
// --- 8.5 command send via the early-captured receiver ---------------------
// V8iCmd85Send sends a designer command through g85_recv on the 1C UI thread
// (kV8iCmdMsg marshal). rc: >=0 transmit result, -99 no receiver/unreadable,
// -98 no marshal window, -97 UI thread did not answer, -96 timeout.
// `has` queries ICommandReceiver::hasHandler instead of transmitting.
// The v8api slot numbering EXCLUDES IUnknown: the live vtable is
// [0]=QI, [1]=AddRef, [2]=Release (verified by disasm on 8.5.1.1529 —
// slot 0 compares its arg against IID_IUnknown and writes *out; "has" via
// slot 2 was a false positive: AddRef just returns 1). Real slots are +3,
// same as the 8.3 chain (kTransmitSlot=3): transmit=[3], hasHandler=[5].
// The 8.5 receiver was captured from one frame object; 1C destroys frames when
// a window closes, and a stale receiver would be a write into freed memory
// (A65 — the 8.3 chain re-validates its frame on every use, this path did not).
// The frame is re-checked against the calibrated ITopLevelFrame vtable and the
// receiver against the vtable it had when captured; on any failure the capture
// is dropped so the caller re-runs the slot-31 walk.
static bool V8iRecv85Alive() {
    if (!g85_recv || !g85_recvVt || !g85_recvFrame) return false;
    ModuleRange cfg;
    if (!FindModule(L"config.dll", cfg)) return false;
    const uintptr_t frameVtbl = cfg.base + 0x2ED3B0;
    uintptr_t fvt = 0;
    if (!ReadPtrSafe(g85_recvFrame, &fvt) || fvt != frameVtbl) return false;
    uintptr_t rvt = 0;
    if (!ReadPtrSafe(g85_recv, &rvt) || rvt != g85_recvVt) return false;
    return IsReadable((void*)g85_recvVt, 6 * sizeof(void*));
}

// Drops the 8.5 capture: the frame it came from is gone (or was never known).
static void V8iDropRecv85() {
    if (g85_recv) LogLine("cmd85: receiver 0x%llX went stale, dropping",
                          (unsigned long long)g85_recv);
    g85_recv = 0;
    g85_recvVt = 0;
    g85_recvFrame = 0;
}

// Sends a designer command through g85_recv on the 1C UI thread (kV8iCmdMsg
// marshal). rc: >=0 transmit result, -99 no receiver/unreadable, -98 no marshal
// window, -97 UI thread did not answer, -96 timeout. `has` queries
// ICommandReceiver::hasHandler instead of transmitting.
// The v8api slot numbering EXCLUDES IUnknown: the live vtable is
// [0]=QI, [1]=AddRef, [2]=Release (verified by disasm on 8.5.1.1529 —
// slot 0 compares its arg against IID_IUnknown and writes *out; "has" via
// slot 2 was a false positive: AddRef just returns 1). Real slots are +3,
// same as the 8.3 chain (kTransmitSlot=3): transmit=[3], hasHandler=[5].
static int V8iCmd85Send(unsigned int num, int sub, bool has, LONG* excOut) {
    if (excOut) *excOut = 0;
    if (!V8iRecv85Alive()) {
        V8iDropRecv85();
        return -99;
    }
    uintptr_t tr = ((uintptr_t*)g85_recvVt)[has ? 5 : 3];
    if (!tr || !IsReadable((void*)tr, 1)) return -99;
    // 8.5 Command layout (RECON-85 §3.3): CommandID { GUID, num } padded to
    // 24, param at 24, object at 32 — 40 bytes total. The sender zeroes the
    // slot first, so the 8.3 32-byte interpretation of the same buffer reads
    // param from the pad (0) and object from the first zeroed qword.
    unsigned char raw[40] = {};
    memcpy(raw, kConfigGroup, 16);
    *(unsigned int*)(raw + 16) = num;
    *(int*)(raw + 24) = sub;
    V8iRequest req;
    req.mode = has ? 1 : 0;
    req.recv = (void*)g85_recv;
    req.trFn = (void*)tr;
    req.cmd = raw;
    req.cmdSize = sizeof(raw);
    const V8iMarshalResult mr = V8iMarshal(req, 30000, true);
    if (excOut) *excOut = mr.exc;
    if (mr.status != 0) return mr.status;
    return mr.rc;
}

// Post-start receiver capture for 8.5: the eventCreateFrame path only runs
// when the payload subscribed before the frames existed (hookcbt/launch).
// For a plain post-start inject (`v8inject gitbar ...`) nothing hands us the
// frame, so: scan the heap for the live-calibrated ITopLevelFrame vtable and
// marshal the slot-31 walk onto the UI thread (mode 2) — the only context
// where 8.5 answers. The static check (slot 31 is readable code inside
// config.dll) keeps bogus candidates from executing random bytes; SEH covers
// the rest.
static bool V8iCaptureRecv85Late() {
    if (g85_recv && g85_recvVt) return true;
    ModuleRange cfg;
    if (!FindModule(L"config.dll", cfg)) return false;
    const uintptr_t kFrameVtbl = cfg.base + 0x2ED3B0;  // ITopLevelFrame, live-calibrated on 8.5.1.1529

    std::vector<ModuleRange> mods;
    for (const ModuleRange& m : EnumModules()) mods.push_back(m);
    auto insideCfg = [&](uintptr_t a) {
        return a >= cfg.base && a < cfg.base + cfg.size;
    };

    uintptr_t addr = 0x10000;
    while (addr < 0x00007FFFFFFFFFFFULL) {
        MEMORY_BASIC_INFORMATION mi = {};
        if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
        uintptr_t end = addr + mi.RegionSize;
        bool usable = mi.State == MEM_COMMIT &&
                      (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                      !(mi.Protect & PAGE_GUARD) &&
                      !insideCfg((uintptr_t)mi.BaseAddress);
        if (usable) {
            const uintptr_t cap = mi.RegionSize > 64 * 1024 * 1024
                                      ? 64 * 1024 * 1024 : (uintptr_t)mi.RegionSize;
            for (uintptr_t p = (uintptr_t)mi.BaseAddress;
                 p < (uintptr_t)mi.BaseAddress + cap; p += sizeof(void*)) {
                uintptr_t fvt = 0;
                if (!ReadPtrSafe(p, &fvt) || fvt != kFrameVtbl) continue;
                uintptr_t fn31 = 0;
                if (!ReadPtrSafe(fvt + 31 * sizeof(void*), &fn31)) continue;
                if (!fn31 || !IsReadable((void*)fn31, 1) || !insideCfg(fn31)) continue;

                // The slot-31 walk needs the UI thread; V8iMarshal reports -98
                // when there is no marshal window yet.
                V8iRequest req;
                req.mode = 2;            // capture the receiver from the frame
                req.recv = (void*)p;
                const V8iMarshalResult mr = V8iMarshal(req, 10000, true);
                if (mr.status == -98) return false;
                if (mr.status != 0) break;   // UI thread hung: stop scanning
                if (g85_recv && g85_recvVt) {
                    g85_recvFrame = p;
                    LogLine("cmd85 late capture: frame=0x%llX recv=0x%llX rvt=0x%llX",
                            (unsigned long long)p, (unsigned long long)g85_recv,
                            (unsigned long long)g85_recvVt);
                    return true;
                }
            }
        }
        addr = end == addr ? addr + sizeof(void*) : end;
    }
    LogLine("cmd85 late capture: no frame with vtable config.dll+0x2ED3B0 found");
    return false;
}

// Shared JSON front for the 8.5 send path: `cmd85 ...` and `cmd ...` on 8.5
// both land here. Captures the receiver post-start when it is missing, so a
// plain post-start GitBar dump button works without hookcbt/launch.
void RestoreFramesAfterFailedTransmit(HWND marshalTo);   // 8.3 chain below (A133)

static std::string Cmd85SendJson(unsigned int num, int sub, bool has) {
    if (!g85_recv && !V8iCaptureRecv85Late())
        return "{\"status\":\"error\",\"message\":\"no 8.5 receiver captured — "
               "needs early subscribe (hookcbt/launch) or a live frame\"}";
    LONG exc = 0;
    int rc = V8iCmd85Send(num, sub, has, &exc);
    char nb[256];
    if (rc == -99)
        return "{\"status\":\"error\",\"message\":\"receiver vtbl[0] unreadable\"}";
    if (rc == -98)
        return "{\"status\":\"error\",\"message\":\"marshaling setup failed\"}";
    if (rc == -97)
        return "{\"status\":\"error\",\"message\":\"UI thread did not answer\"}";
    if (rc == -96)
        return "{\"status\":\"error\",\"message\":\"timeout waiting for UI thread\"}";
    if (rc < 0) {
        // A133: the 8.3 path brings the frame back after a transmit fault
        // (the platform disables it before the command's dialog appears); the
        // 8.5 path used to return without it, leaving the Configurator deaf
        // even though the same window classes are in play here.
        RestoreFramesAfterFailedTransmit(g_cmdHwnd);
        _snprintf_s(nb, sizeof(nb), _TRUNCATE,
                    "{\"status\":\"error\",\"message\":\"transmit exception\",\"exc\":\"0x%X\"}",
                    (unsigned)exc);
        return nb;
    }
    if (has)
        _snprintf_s(nb, sizeof(nb), _TRUNCATE,
                    "{\"status\":\"ok\",\"num\":%u,\"sub\":%d,\"recv\":\"0x%llX\",\"has\":%s}",
                    num, sub, (unsigned long long)g85_recv, rc == 0 ? "false" : "true");
    else
        _snprintf_s(nb, sizeof(nb), _TRUNCATE,
                    "{\"status\":\"ok\",\"num\":%u,\"sub\":%d,\"recv\":\"0x%llX\",\"rvt\":\"0x%llX\",\"rc\":%d}",
                    num, sub, (unsigned long long)g85_recv, (unsigned long long)g85_recvVt, rc);
    return nb;
}

// File-driven command sender: lets a host drive 8.5 designer commands without a
// Client session (the hookcbt-loaded payload is sessionless). Watches
// %TEMP%\v8i_cmd85_req.txt ("<num> [sub]"), sends each request once (file is
// consumed), appends the result to %TEMP%\v8i_cmd85_res.txt.
static DWORD WINAPI V8iCmd85PollThread(LPVOID) {
    // The real temp directory: the old path pointed at the author's machine,
    // where the channel could not work anywhere else.
    wchar_t reqPath[MAX_PATH] = {};
    wchar_t resPath[MAX_PATH] = {};
    if (!TempFile(L"v8i_cmd85_req.txt", reqPath, _countof(reqPath)) ||
        !TempFile(L"v8i_cmd85_res.txt", resPath, _countof(resPath))) {
        LogLine("cmd85: no temp directory for the file channel");
        return 1;
    }
    for (int i = 0; i < 900; ++i) {          // 900 * 200 ms = 3 min
        Sleep(200);
        FILE* f = nullptr;
        if (_wfopen_s(&f, reqPath, L"r") == 0 && f) {
            unsigned num = 0;
            int sub = 0;
            int matched = fscanf_s(f, "%u %d", &num, &sub);
            fclose(f);
            if (matched >= 1) {
                _wremove(reqPath);
                int rc = V8iCmd85Send(num, sub, false, nullptr);
                FILE* rf = nullptr;
                if (_wfopen_s(&rf, resPath, L"a") == 0 && rf) {
                    fprintf(rf, "num=%u sub=%d rc=%d\n", num, sub, rc);
                    fclose(rf);
                }
            }
        }
    }
    return 0;
}

// The config.dll range through POD out-parameters: the __try frames of the
// capture cannot hold a ModuleRange local (it carries a std::wstring, C2712).
static bool Config85Range(uintptr_t* base, size_t* size) {
    ModuleRange cfg;
    if (!FindModule(L"config.dll", cfg)) return false;
    if (base) *base = cfg.base;
    if (size) *size = cfg.size;
    return true;
}

static void V8iCaptureCmdRecv(void* obj) {
    if (!obj) return;
    uintptr_t fvt = 0;
    __try { fvt = *(uintptr_t*)obj; } __except (EXCEPTION_EXECUTE_HANDLER) { fvt = 0; }
    if (!fvt) {
        LogLine("cmdrecv: frame has no vtable");
        return;
    }
    // A119: slot 31 runs platform code on the UI thread, so the object is
    // gated before any state change and before the call -- the same gate the
    // late capture and V8iRecv85Alive apply. 1C destroys transient frames, and
    // an event may arrive for a freed-and-reused object: its "vtable" is
    // garbage, and calling a garbage slot executes arbitrary code. A foreign
    // object also must not reset an existing, still-alive capture (sends
    // re-validate it via V8iRecv85Alive). The module range comes through POD
    // out-parameters: this frame owns __try, and ModuleRange carries a
    // std::wstring -- C2712.
    uintptr_t cfgBase = 0, cfgSize = 0;
    if (!Config85Range(&cfgBase, &cfgSize) || fvt != cfgBase + 0x2ED3B0) {
        LogLine("cmdrecv85: obj 0x%llX vt 0x%llX is not the calibrated ITopLevelFrame "
                "(config.dll+0x2ED3B0), capture skipped",
                (unsigned long long)(uintptr_t)obj, (unsigned long long)fvt);
        return;
    }
    // Live-calibrated on 8.5.1.1529: the event's obj IS the ITopLevelFrame
    // (vtable config.dll+0x2ED3B0, a forwarder table; slot 0 = init, NOT QI —
    // no IUnknown cast is needed). commandReceiver = slot 31, NOT 30 (slot 30
    // is a different method and raises 0xC0000005). The slot-31 forwarder
    // reads inner = [obj+8] and dispatches [inner->vt + 0xF8]; the receiver
    // returned sits 0x20 before that inner object (the same geometry as the
    // 8.3 "recv = core - 0x20"). recv->vtbl[0] = transmitCommand.
    uintptr_t fn31 = 0;
    __try { fn31 = ((uintptr_t*)fvt)[31]; } __except (EXCEPTION_EXECUTE_HANDLER) { fn31 = 0; }
    g85_recv = 0;
    g85_recvVt = 0;
    g85_recvFrame = 0;
    long exc = 0;
    if (fn31 && IsReadable((void*)fn31, 1) &&
        fn31 >= cfgBase && fn31 < cfgBase + cfgSize) {
        void* recv = nullptr;
        __try {
            ((void(__cdecl*)(void*, void**))fn31)(obj, &recv);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            exc = GetExceptionCode();
            recv = nullptr;
        }
        if (recv && IsReadable(recv, 4 * sizeof(void*))) {
            g85_recv = (uintptr_t)recv;
            g85_recvFrame = (uintptr_t)obj;   // A65: re-validated before every send
            __try { g85_recvVt = *(uintptr_t*)recv; }
            __except (EXCEPTION_EXECUTE_HANDLER) { g85_recvVt = 0; }
            LogLine("cmdrecv85: OK recv=0x%llX rvt=0x%llX",
                    (unsigned long long)(uintptr_t)recv, (unsigned long long)g85_recvVt);
        } else {
            LogLine("cmdrecv85: slot31 no receiver (exc=0x%X)", (unsigned)exc);
        }
    }
    // Marker file: the only channel when the payload was loaded by the global
    // CBT hook (sessionless, no command readback).
    {
        FILE* cf = nullptr;
        wchar_t recvPath[MAX_PATH] = {};
        if (LogSideFile(L"cmdrecv.txt", recvPath, _countof(recvPath)) &&
            _wfopen_s(&cf, recvPath, L"a") == 0 && cf) {
            fprintf(cf, "obj=%llx vt=%llx recv31=%llx recvVt31=%llx exc=%x\n",
                    (unsigned long long)(uintptr_t)obj, (unsigned long long)fvt,
                    (unsigned long long)g85_recv, (unsigned long long)g85_recvVt, (unsigned)exc);
            fclose(cf);
        }
    }
    // One-shot: spawn the file-driven command sender (host drives 8.5 command
    // sends without a Client session; end-to-end proof of the receiver chain).
    {
        static bool s_cmd85PollSpawned = false;
        if (!s_cmd85PollSpawned && g85_recv) {
            s_cmd85PollSpawned = true;
            CreateThread(nullptr, 0, V8iCmd85PollThread, nullptr, 0, nullptr);
        }
    }
}

// The frame is handed to us on the 1C UI thread and the receiver chain must be
// walked right there (8.5 refuses cross-thread calls into core85, so deferring
// to a worker thread silently yields 0). No std containers in this frame —
// EnumModules() (std::vector) is called from the caller, not from here.
static void V8iTakeFrame85(void* obj) {
    g85_evFrame = (uintptr_t)obj;
    for (int i = 0; i < 4; ++i) g85_dump[i] = 0;
    if (IsReadable(obj, 16)) {
        g85_frameVt = *(uintptr_t*)obj;
        for (int i = 0; i < 4; ++i) {
            __try { g85_dump[i] = ((uintptr_t*)obj)[i]; }
            __except (EXCEPTION_EXECUTE_HANDLER) { g85_dump[i] = 0; }
        }
        if (IsReadable(obj, 64)) memcpy(g85_frameDump, obj, 64);
    }
    if (!g85_subscribed) return;   // only the eventCreateFrame path owns a frame
    V8iCaptureCmdRecv(obj);        // always: diagnose both chains in one shot
}

static HRESULT __stdcall V8iRecipOnEvent(void*, const GUID* ev, long, void* obj) {
    ++g85_evCount;
    if (ev && memcmp(ev, &g85_kExitEv, 16) == 0)
        ++g85_exitEvCount;
    bool isCreateFrame = ev && memcmp(ev, &g85_kCreateFrameEv, 16) == 0;
    // Diagnostic trail (append-only; a marker file is the only channel that
    // also works when the payload was loaded by the global CBT hook, i.e.
    // without any Client session to answer commands).
    {
        FILE* rf = nullptr;
        wchar_t recipPath[MAX_PATH] = {};
        if (LogSideFile(L"recip.txt", recipPath, _countof(recipPath)) &&
            _wfopen_s(&rf, recipPath, L"a") == 0 && rf) {
            fprintf(rf, "ev=%d create=%d exit=%d obj=%llx evid=%02x%02x%02x%02x-%02x%02x-%02x%02x"
                        "-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                    g85_evCount, isCreateFrame ? 1 : 0, g85_exitEvCount,
                    (unsigned long long)(uintptr_t)obj,
                    ev ? ev->Data1 & 0xFF : 0, ev ? (ev->Data1 >> 8) & 0xFF : 0,
                    ev ? (ev->Data1 >> 16) & 0xFF : 0, ev ? (ev->Data1 >> 24) & 0xFF : 0,
                    ev ? ev->Data2 & 0xFF : 0, ev ? (ev->Data2 >> 8) & 0xFF : 0,
                    ev ? ev->Data3 & 0xFF : 0, ev ? (ev->Data3 >> 8) & 0xFF : 0,
                    ev ? ev->Data4[0] : 0, ev ? ev->Data4[1] : 0,
                    ev ? ev->Data4[2] : 0, ev ? ev->Data4[3] : 0,
                    ev ? ev->Data4[4] : 0, ev ? ev->Data4[5] : 0,
                    ev ? ev->Data4[6] : 0, ev ? ev->Data4[7] : 0);
            fclose(rf);
        }
    }
    if (isCreateFrame && obj) V8iTakeFrame85(obj);
    return 0;
}
// The exact IEventRecipient slot layout is not documented for 8.5: the 1C
// event interface appears to be IUnknown-derived (QI/AddRef/Release first),
// but ICommandReceiver-like pure interfaces put their single method at slot 0.
// To not guess, every slot dispatches onEvent — whichever one the platform
// calls (0, 3, …), we see the event.
static void* g85_recipVt[8] = {
    (void*)V8iRecipOnEvent,  // slot 0: pure-interface layout (onEvent)
    (void*)V8iRecipAddRef,   // slot 1
    (void*)V8iRecipRelease,  // slot 2
    (void*)V8iRecipOnEvent,  // slot 3: IUnknown-derived layout (onEvent)
    (void*)V8iRecipOnEvent,
    (void*)V8iRecipOnEvent,
    (void*)V8iRecipOnEvent,
    (void*)V8iRecipOnEvent,
};
static struct V8iRecip { void** vt; } g85_recip = {g85_recipVt};

static void V8iScanFrame85() {
    static const GUID kEvCreateFrame = {0x3573FFE0, 0x2FFF, 0x11D5,
                                        {0xBF, 0x5E, 0x00, 0x50, 0xBA, 0xE2, 0xBC, 0x79}};
    if (!g85_svc || !g85_svcVt) return;
    uintptr_t f1 = 0;
    __try { f1 = ((uintptr_t*)g85_svcVt)[1]; }
    __except (EXCEPTION_EXECUTE_HANDLER) { f1 = 0; }
    if (!f1) return;
    typedef void(__cdecl* SubFn)(void*, const GUID*, void*, const char*, int);
    // 8.5: slot 4 = _subscribe, slot 3 = notify, slot 5 = unsubscribe
    // (all three do a GUID lookup; 0..2 are interface thunks).
    {
        uintptr_t f = 0;
        __try { f = ((uintptr_t*)g85_svcVt)[4]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { f = 0; }
        if (f) {
            __try {
                ((SubFn)f)((void*)g85_svc, &kEvCreateFrame, (void*)&g85_recip, "v8inject", 0);
                // Also subscribe to an event that always fires at close, to
                // prove the platform delivers to *our* recipient at all.
                ((SubFn)f)((void*)g85_svc, &g85_kExitEv, (void*)&g85_recip, "v8inject", 0);
                g85_subscribed = 1;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
    {
        uintptr_t f = 0;
        __try { f = ((uintptr_t*)g85_svcVt)[3]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { f = 0; }
        if (f) {
            __try {
                ((void(__cdecl*)(void*, const GUID*, long, void*))f)(
                    (void*)g85_svc, &kEvCreateFrame, 0, nullptr);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
}

// --- inline hook on user32!CreateWindowExW -------------------------------
// The only moment where eventCreateFrame can still be caught: the UI thread
// calls CreateWindowExW for the main window, the core is already loaded and
// the window does not exist yet. Runs current_process -> getService ->
// subscribe right there, then lets the original call proceed.
static uintptr_t V8iResolveExportFromFile(const std::wstring& modulePath,
                                          const char* namePrefix, size_t prefixLen) {
    HANDLE fh = CreateFileW(modulePath.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER sz{};
    GetFileSizeEx(fh, &sz);
    uintptr_t result = 0;
    if (sz.QuadPart > 0 && sz.QuadPart < 64 * 1024 * 1024LL) {
        std::vector<unsigned char> fbuf((size_t)sz.QuadPart);
        DWORD got = 0;
        if (ReadFile(fh, fbuf.data(), (DWORD)fbuf.size(), &got, nullptr) && got == fbuf.size()) {
            const unsigned char* fd = fbuf.data();
            auto r32 = [fd](uintptr_t o) -> uint32_t { return *(const uint32_t*)(fd + o); };
            uintptr_t dos = fd[0x3C] | (fd[0x3D] << 8) | (fd[0x3E] << 16) | ((uintptr_t)fd[0x3F] << 24);
            if (dos + 0x100 < fbuf.size()) {
                uintptr_t nt = dos + 4;
                uint16_t nsec = *(const uint16_t*)(fd + nt + 2);
                uint16_t optSize = *(const uint16_t*)(fd + nt + 16);
                uintptr_t opt = nt + 20;
                uintptr_t secTab = opt + optSize;
                auto toRaw = [&](uint32_t rva) -> uint32_t {
                    for (uint16_t i = 0; i < nsec; ++i) {
                        uintptr_t sh = secTab + (uintptr_t)i * 40;
                        if (sh + 40 > fbuf.size()) break;
                        uint32_t va = r32(sh + 12);
                        uint32_t vs = r32(sh + 8);
                        uint32_t raw = r32(sh + 20);
                        if (rva >= va && rva < va + vs) return rva - va + raw;
                    }
                    return rva;
                };
                uintptr_t dd = opt + (optSize != 224 ? 112 : 96);
                uint32_t expRva = (dd + 8 <= fbuf.size()) ? r32(dd) : 0;
                if (expRva && expRva + 40 <= fbuf.size()) {
                    uint32_t eo = toRaw(expRva);
                    if (eo + 40 <= fbuf.size()) {
                        uint32_t names = r32(eo + 32);
                        uint32_t funcs = r32(eo + 28);
                        uint32_t ords = r32(eo + 36);
                        uint32_t nNames = r32(eo + 24);
                        for (uint32_t i = 0; i < nNames && i < 16384; ++i) {
                            uint32_t np = toRaw(r32(toRaw(names + i * 4)));
                            if (!np || np + prefixLen + 1 > (uint32_t)fbuf.size()) continue;
                            if (memcmp(fd + np, namePrefix, prefixLen) != 0) continue;
                            uint16_t idx = *(const uint16_t*)(fd + toRaw(ords + i * 2));
                            result = r32(toRaw(funcs + (uint32_t)idx * 4));
                            break;
                        }
                    }
                }
            }
        }
    }
    CloseHandle(fh);
    return result;  // RVA
}

// ---------------------------------------------------------------------------
// exports85: dump every export of a module straight from the file on disk.
// 8.5 zeroes the export directory in memory, so this is the only reliable
// source of names and RVAs.
// ---------------------------------------------------------------------------

struct V8iExportEntry {
    char name[256];
    uint32_t ordinal;
    uint32_t rva;
};

static int V8iDumpExportsFromFile(const std::wstring& modulePath,
                                  V8iExportEntry* out, int maxEntries) {
    if (!out || maxEntries <= 0) return 0;
    HANDLE fh = CreateFileW(modulePath.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (fh == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER sz{};
    GetFileSizeEx(fh, &sz);
    int count = 0;
    if (sz.QuadPart > 0 && sz.QuadPart < 128 * 1024 * 1024LL) {
        std::vector<unsigned char> fbuf((size_t)sz.QuadPart);
        DWORD got = 0;
        if (ReadFile(fh, fbuf.data(), (DWORD)fbuf.size(), &got, nullptr) && got == fbuf.size()) {
            const unsigned char* fd = fbuf.data();
            auto r32 = [fd](uintptr_t o) -> uint32_t { return *(const uint32_t*)(fd + o); };
            uintptr_t dos = fd[0x3C] | (fd[0x3D] << 8) | (fd[0x3E] << 16) | ((uintptr_t)fd[0x3F] << 24);
            if (dos + 0x100 < fbuf.size()) {
                uintptr_t nt = dos + 4;
                uint16_t nsec = *(const uint16_t*)(fd + nt + 2);
                uint16_t optSize = *(const uint16_t*)(fd + nt + 16);
                uintptr_t opt = nt + 20;
                uintptr_t secTab = opt + optSize;
                auto toRaw = [&](uint32_t rva) -> uint32_t {
                    for (uint16_t i = 0; i < nsec; ++i) {
                        uintptr_t sh = secTab + (uintptr_t)i * 40;
                        if (sh + 40 > fbuf.size()) break;
                        uint32_t va = r32(sh + 12);
                        uint32_t vs = r32(sh + 8);
                        uint32_t raw = r32(sh + 20);
                        if (rva >= va && rva < va + vs) return rva - va + raw;
                    }
                    return rva;
                };
                uintptr_t dd = opt + (optSize != 224 ? 112 : 96);
                uint32_t expRva = (dd + 8 <= fbuf.size()) ? r32(dd) : 0;
                if (expRva && expRva + 40 <= fbuf.size()) {
                    uint32_t eo = toRaw(expRva);
                    if (eo + 40 <= fbuf.size()) {
                        uint32_t names = r32(eo + 32);
                        uint32_t funcs = r32(eo + 28);
                        uint32_t ords = r32(eo + 36);
                        uint32_t nNames = r32(eo + 24);
                        for (uint32_t i = 0; i < nNames && count < maxEntries; ++i) {
                            uint32_t nameRva = r32(toRaw(names + i * 4));
                            if (!nameRva) continue;
                            uint32_t np = toRaw(nameRva);
                            if (np + 2 >= (uint32_t)fbuf.size()) continue;
                            const char* nm = (const char*)(fd + np);
                            size_t len = strnlen_s(nm, 255);
                            if (len == 0) continue;
                            uint16_t idx = *(const uint16_t*)(fd + toRaw(ords + i * 2));
                            V8iExportEntry& e = out[count++];
                            memcpy(e.name, nm, len);
                            e.name[len] = 0;
                            e.ordinal = idx;
                            e.rva = r32(toRaw(funcs + (uint32_t)idx * 4));
                        }
                    }
                }
            }
        }
    }
    CloseHandle(fh);
    return count;
}

static ModuleRange V8iFindModuleByName(const wchar_t* leaf) {
    for (const ModuleRange& m : EnumModules()) {
        size_t s = m.path.find_last_of(L"\\/");
        std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
        if (_wcsicmp(n.c_str(), leaf) == 0) return m;
    }
    return ModuleRange{};
}

// current_process -> getService(IEventService) -> subscribe(eventCreateFrame)
static void V8iResolveCore85Proc(uintptr_t* outBase, uint32_t* outRva) {
    *outBase = 0;
    *outRva = 0;
    for (const ModuleRange& m : EnumModules()) {
        size_t s = m.path.find_last_of(L"\\/");
        std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
        if (_wcsicmp(n.c_str(), L"core85.dll") != 0) continue;
        *outBase = m.base;
        *outRva = (uint32_t)V8iResolveExportFromFile(m.path, "?current_process@core@@", 23);
        return;
    }
}

static volatile int g_cwHookOk = 0;
static volatile long g_cwHits = 0;
static volatile LONG g_cwTriggered = 0;

// The window is created *inside* CreateWindowExW, so the hook runs before the
// window exists: the worker waits for it and hands it to the early subscribe
// routine, the same one the CBT path uses.
static DWORD WINAPI V8iCwEarlyWorker(LPVOID) {
    for (int i = 0; i < 400 && !g85_subscribed; ++i) {
        HWND h = nullptr;
        EnumWindows(V8iFindMainWindow, (LPARAM)&h);
        if (h) {
            V8iEarlySubscribeThread(h);
            return 0;
        }
        Sleep(5);
    }
    LogLine("createwindow hook: the main frame never appeared");
    return 0;
}

// Observer of the CreateWindowExW hook: the class name of the window being
// created arrives as the second argument (rdx on x64).
static void V8iObserveCreateWindow(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3) {
    (void)a0; (void)a2; (void)a3;   // only the class name (a1) matters here
    InterlockedIncrement(&g_cwHits);
    if (g85_subscribed) return;
    // The class of the designer's main frame. On 8.5 it is "V8TopLevelFrame"
    // (the CBT dump of a live Configurator shows it), and such a window is
    // created on the UI thread - the only thread allowed to call core85.
    //
    // A43: lpClassName is not necessarily a string pointer. Win32 allows an
    // atom (MAKEINTATOM), and 8.5 really does create its frame with a numeric
    // class, so wcsncmp on 0x8002 is an AV on the UI thread of 1C. The same
    // guard as the CBT hook above: a pointer-shaped value and a readable
    // buffer are the minimum before the class can be compared.
    const wchar_t* cls = (const wchar_t*)a1;
    if (!cls || cls <= (const wchar_t*)0x10000) return;
    constexpr size_t kClassBytes = 96;
    if (!IsReadable(cls, kClassBytes)) return;
    if (wcsncmp(cls, L"V8TopLevelFrame", 15) != 0 &&
        wcsncmp(cls, L"V8Window0", 9) != 0) return;
    if (InterlockedExchange(&g_cwTriggered, 1) != 0) return;
    // The core is not ready at the moment the window is created, and
    // subscribing right here crashes 1C. The worker waits for the window and
    // retries the subscribe chain on its UI thread until the core answers.
    CreateThread(nullptr, 0, V8iCwEarlyWorker, nullptr, 0, nullptr);
}

// Installs the hook on user32!CreateWindowExW through the shared detour
// engine. The earlier hand-written version called the original through a
// C++ detour, and that call shifted the stack by eight bytes: the copied
// prologue captured "mov r11, rsp" from a frame that was not the original
// one, and user32 addresses its shadow space through that register -- the
// return value landed eight bytes off and the caller's frame was touched.
// The engine's thunk restores the stack before it enters the trampoline, so
// the copied prologue sees exactly the frame the original function would.
// A48: the counters of the 8.5 path as one member list. Every member carries
// its own comma here, so a field cannot be joined to the next one by accident
// -- which is what happened between "subscribed" and "qProcFrame", and the
// reply of an 8.5 process was not JSON at all.
std::string CmdInfoTailJson(const CmdInfoTail& t) {
    char buf[640];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                ",\"evCount\":%ld,\"evFrame\":\"0x%llX\",\"hookOk\":%d,\"cwHits\":%ld,"
                "\"subscribed\":%d,\"qProcFrame\":\"0x%llX\",\"qProcRecv\":\"0x%llX\","
                "\"qCmdFrame\":\"0x%llX\",\"qCmdRecv\":\"0x%llX\","
                "\"qEvFrame\":\"0x%llX\",\"qEvRecv\":\"0x%llX\"",
                t.evCount, t.evFrame, t.hookOk, t.cwHits, t.subscribed, t.qProcFrame,
                t.qProcRecv, t.qCmdFrame, t.qCmdRecv, t.qEvFrame, t.qEvRecv);
    return std::string(buf);
}

static bool V8iInstallCreateWindowHook() {
    if (g_cwHookOk) return true;
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    if (!u32) u32 = LoadLibraryW(L"user32.dll");
    if (!u32) return false;
    void* target = (void*)GetProcAddress(u32, "CreateWindowExW");
    if (!target) return false;
    // Prologue of user32!CreateWindowExW on this build:
    //   4C 8B DC              mov  r11, rsp
    //   48 81 EC 88 00 00 00  sub  rsp, 0x88
    //   33 C0                 xor  eax, eax
    //   66 89 44 24 78        mov  [rsp+78h], ax
    // The check is x64-specific, so on x86 the hook is not installed.
    const BYTE expect[8] = {0x4C, 0x8B, 0xDC, 0x48, 0x81, 0xEC, 0x88, 0x00};
    if (memcmp(target, expect, sizeof(expect)) != 0) return false;
    std::string err;
    uint32_t id = HookInstallObserved((uintptr_t)target, "CreateWindowExW",
                                      &V8iObserveCreateWindow, err);
    if (!id) {
        LogLine("CreateWindowExW: hook failed: %s", err.c_str());
        return false;
    }
    g_cwHookOk = 1;
    LogLine("CreateWindowExW: hooked (id=%u)", id);
    return true;
}

// "cmdinfo" — read-only diagnostics: how the command receiver can be located
// on THIS platform. 8.3 carries config.dll with the calibrated ITopLevelFrame
// vtable; 8.5 has core85/frame/mngcore instead, so the chain must be
// discovered: window -> GWLP_USERDATA object -> core (obj+8) ->
// ICommandReceiver (core - offset). No 1C code is called here.
std::string CmdInfoToJsonA() {
    // Arm the startup watcher on every call: if the main window does not exist
    // yet, the worker subscribes the moment it appears (before the platform
    // dispatches eventCreateFrame).
    {
        static bool armed = false;
        if (!armed) { armed = true; V8iStartStartupWatch(); }
    }
    struct WinRec { HWND h; std::wstring cls; std::wstring title; };
    std::vector<WinRec> wins;
    struct Ctx { std::vector<WinRec>* v; DWORD pid; };
    Ctx ctx{ &wins, GetCurrentProcessId() };
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        Ctx* c = (Ctx*)lp;
        DWORD pid = 0;
        GetWindowThreadProcessId(h, &pid);
        if (pid != c->pid) return TRUE;
        wchar_t cls[128] = {}, ttl[128] = {};
        GetClassNameW(h, cls, 128);
        GetWindowTextW(h, ttl, 128);
        if (!ttl[0]) return TRUE;
        WinRec r;
        r.h = h;
        r.cls = cls;
        r.title = ttl;
        c->v->push_back(r);
        return TRUE;
    }, (LPARAM)&ctx);

    std::vector<ModuleRange> mods;
    for (const ModuleRange& m : EnumModules()) mods.push_back(m);
    auto modAt = [&mods](uintptr_t a) -> const ModuleRange* {
        for (const ModuleRange& m : mods)
            if (a >= m.base && a < m.base + m.size) return &m;
        return nullptr;
    };
    auto modRva = [&mods](uintptr_t a, std::string& mod) -> unsigned long long {
        for (const ModuleRange& m : mods) {
            if (a >= m.base && a < m.base + m.size) {
                size_t s = m.path.find_last_of(L"\\/");
                std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
                mod = NarrowAscii(n);
                return (unsigned long long)(a - m.base);
            }
        }
        mod = "?";
        return 0;
    };
    auto isFrameMod = [](const std::string& m) {
        return m == "frame.dll" || m == "mngcore.dll" || m == "mngui.dll" ||
               m == "config.dll" || m == "frmcore.dll";
    };

    std::string j = "{\"status\":\"ok\",\"windows\":[";
    bool first = true;
    char b[768];
    int frameCount = 0;
    for (const WinRec& w : wins) {
        uintptr_t obj = (uintptr_t)GetWindowLongPtrW(w.h, GWLP_USERDATA);
        if (!obj || !IsReadable((void*)obj, 16)) continue;
        uintptr_t vt = *(uintptr_t*)obj;
        std::string mod;
        unsigned long long rva = modRva(vt, mod);
        if (!first) j += ",";
        first = false;
        _snprintf_s(b, sizeof(b), _TRUNCATE,
                    "{\"hwnd\":\"0x%llX\",\"cls\":\"%s\",\"obj\":\"0x%llX\",\"vt\":\"%s+0x%llX\"",
                    (unsigned long long)(uintptr_t)w.h,
                    NarrowAscii(w.cls).c_str(),
                    (unsigned long long)obj, mod.c_str(), rva);
        j += b;
        if (!isFrameMod(mod)) {
            j += ",\"frame\":false}";
            continue;
        }
        uintptr_t core = *(uintptr_t*)(obj + 8);
        std::string cmod;
        unsigned long long crva = modRva(core, cmod);
        _snprintf_s(b, sizeof(b), _TRUNCATE,
                    ",\"frame\":true,\"core\":\"0x%llX %s+0x%llX\",\"recv\":[",
                    (unsigned long long)core, cmod.c_str(), crva);
        j += b;
        bool firstR = true;
        for (int off = 0x08; off <= 0x60; off += 4) {
            uintptr_t recv = core - off;
            if (!IsReadable((void*)recv, 16)) continue;
            uintptr_t vtr = *(uintptr_t*)recv;
            std::string rmod;
            unsigned long long rrva = modRva(vtr, rmod);
            if (!isFrameMod(rmod)) continue;
            uintptr_t slot3 = ((uintptr_t*)vtr)[3];
            std::string smod;
            unsigned long long srva = modRva(slot3, smod);
            if (!firstR) j += ",";
            firstR = false;
            _snprintf_s(b, sizeof(b), _TRUNCATE,
                        "{\"off\":\"0x%X\",\"vt\":\"%s+0x%llX\",\"slot3\":\"%s+0x%llX\"}",
                        off, rmod.c_str(), rrva, smod.c_str(), srva);
            j += b;
        }
        j += "]}";
        if (isFrameMod(mod)) ++frameCount;
    }
    j += "]";

    // 8.5 does not keep the frame object in GWLP_USERDATA: fall back to a heap
    // scan. Look for objects whose vtable lies in a frame-related module and
    // whose second word points at a core object (core85/config/mngcore).
    if (frameCount == 0) {
        struct MR { uintptr_t base = 0, size = 0; std::string leaf; };
        std::vector<MR> fam, cores;
        for (const ModuleRange& m : mods) {
            size_t s = m.path.find_last_of(L"\\/");
            std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
            std::string leaf = NarrowAscii(n);
            if (leaf == "frame.dll" || leaf == "mngcore.dll" || leaf == "mngui.dll" ||
                leaf == "frmcore.dll" || leaf == "config.dll")
                fam.push_back({ m.base, m.size, leaf });
            if (leaf == "core85.dll" || leaf == "core83.dll" || leaf == "config.dll" ||
                leaf == "mngcore.dll")
                cores.push_back({ m.base, m.size, leaf });
        }
        auto inSpan = [](const std::vector<MR>& v, uintptr_t a) -> const MR* {
            for (const MR& r : v)
                if (a >= r.base && a < r.base + r.size) return &r;
            return nullptr;
        };
        j += ",\"scan\":[";
        bool firstS = true;
        int found = 0;
        uintptr_t addr = 0x10000;
        while (addr < 0x00007FFFFFFFFFFFULL && found < 40) {
            MEMORY_BASIC_INFORMATION mi{};
            if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
            uintptr_t end = addr + mi.RegionSize;
            bool usable = mi.State == MEM_COMMIT &&
                          (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                          !(mi.Protect & PAGE_GUARD) &&
                          !inSpan(fam, (uintptr_t)mi.BaseAddress) &&
                          !inSpan(cores, (uintptr_t)mi.BaseAddress);
            if (usable) {
                uintptr_t cap = mi.RegionSize > 32 * 1024 * 1024 ? 32 * 1024 * 1024
                                                                 : (uintptr_t)mi.RegionSize;
                for (uintptr_t p = (uintptr_t)mi.BaseAddress;
                     p + 16 < (uintptr_t)mi.BaseAddress + cap; p += 8) {
                    uintptr_t vt = 0;
                    if (!ReadPtrSafe(p, &vt)) continue;
                    const MR* mf = inSpan(fam, vt);
                    if (!mf) continue;
                    uintptr_t core = 0;
                    if (!ReadPtrSafe(p + 8, &core)) continue;
                    const MR* mc = inSpan(cores, core);
                    if (!mc) continue;
                    if (!firstS) j += ",";
                    firstS = false;
                    _snprintf_s(b, sizeof(b), _TRUNCATE,
                                "{\"obj\":\"0x%llX\",\"vt\":\"%s+0x%llX\",\"core\":\"%s+0x%llX\"",
                                (unsigned long long)p, mf->leaf.c_str(),
                                (unsigned long long)(vt - mf->base), mc->leaf.c_str(),
                                (unsigned long long)(core - mc->base));
                    j += b;
                    if (mc->leaf == "core85.dll" || mc->leaf == "core83.dll" ||
                        mc->leaf == "config.dll") {
                        j += ",\"recv\":[";
                        bool firstR2 = true;
                        for (int off = 0x08; off <= 0x60; off += 4) {
                            uintptr_t recv = core - off;
                            if (!IsReadable((void*)recv, 16)) continue;
                            uintptr_t vtr = 0;
                            if (!ReadPtrSafe(recv, &vtr)) continue;
                            const MR* mr = inSpan(fam, vtr);
                            if (!mr) continue;
                            uintptr_t slot3 = 0;
                            if (!ReadPtrSafe(vtr + 3 * sizeof(void*), &slot3)) continue;
                            std::string smod;
                            unsigned long long srva = modRva(slot3, smod);
                            if (!firstR2) j += ",";
                            firstR2 = false;
                            _snprintf_s(b, sizeof(b), _TRUNCATE,
                                        "{\"off\":\"0x%X\",\"vt\":\"%s+0x%llX\","
                                        "\"slot3\":\"%s+0x%llX\"}",
                                        off, mr->leaf.c_str(),
                                        (unsigned long long)(vtr - mr->base), smod.c_str(), srva);
                            j += b;
                        }
                        j += "]";
                    }
                    j += "}";
                    if (++found >= 40) break;
                }
            }
            addr = end == addr ? addr + 8 : end;
        }
        j += "]";
    }

    // QueryInterface pass: objects with real rdata vtables (slots 0..5 point
    // into the same module's .text) are asked about IID_ICommandReceiver —
    // the modern way to obtain the receiver on 8.5, where the core-0x20 trick
    // does not apply. QI is side-effect free; each probe is SEH-guarded.
    {
        struct MR2 { uintptr_t base = 0, size = 0, tlo = 0, thi = 0, rlo = 0, rhi = 0; };
        std::vector<MR2> targets;
        for (const ModuleRange& m : mods) {
            size_t s = m.path.find_last_of(L"\\/");
            std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
            std::string leaf = NarrowAscii(n);
            if (leaf != "frame.dll" && leaf != "config.dll" && leaf != "mngcore.dll")
                continue;
            PeImage im = ParsePe(m.base);
            if (!im.valid) continue;
            MR2 r;
            r.base = m.base;
            r.size = m.size;
            for (const PeSection& sec : im.sections) {
                if (sec.name == ".text") { r.tlo = m.base + sec.va; r.thi = r.tlo + sec.virtualSize; }
                if (sec.name == ".rdata") { r.rlo = m.base + sec.va; r.rhi = r.rlo + sec.virtualSize; }
            }
            if (r.tlo && r.rlo) targets.push_back(r);
        }
        auto inText = [&targets](uintptr_t a) -> bool {
            for (const MR2& r : targets)
                if (a >= r.tlo && a < r.thi) return true;
            return false;
        };
        auto inRdata = [&targets](uintptr_t a) -> bool {
            for (const MR2& r : targets)
                if (a >= r.rlo && a < r.rhi) return true;
            return false;
        };
        static const GUID kIID_CmdRecv = {0x377A2018, 0xC51B, 0x4cf5,
                                          {0xAC, 0x03, 0xA1, 0x50, 0x92, 0x66, 0xDF, 0x2D}};
        j += ",\"qi\":[";
        bool firstQ = true;
        int qfound = 0;
        if (0) {
        uintptr_t addr = 0x10000;
        while (addr < 0x00007FFFFFFFFFFFULL && qfound < 12) {
            MEMORY_BASIC_INFORMATION mi{};
            if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
            uintptr_t end = addr + mi.RegionSize;
            bool usable = mi.State == MEM_COMMIT &&
                          (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                          !(mi.Protect & PAGE_GUARD) && !inRdata((uintptr_t)mi.BaseAddress) &&
                          !inText((uintptr_t)mi.BaseAddress);
            if (usable) {
                uintptr_t cap = mi.RegionSize > 32 * 1024 * 1024 ? 32 * 1024 * 1024
                                                                 : (uintptr_t)mi.RegionSize;
                for (uintptr_t p = (uintptr_t)mi.BaseAddress;
                     p + 48 < (uintptr_t)mi.BaseAddress + cap; p += 8) {
                    uintptr_t vt = *(uintptr_t*)p;
                    if (!inRdata(vt)) continue;
                    bool vok = true;
                    for (int sl = 1; sl <= 5; ++sl)
                        if (!inText(((uintptr_t*)vt)[sl])) { vok = false; break; }
                    if (!vok) continue;
                    void* out = nullptr;
                    int rc = V8iQIProbe((void*)p, &kIID_CmdRecv, &out);
                    if (rc != 0 || !out) continue;
                    if (!firstQ) j += ",";
                    firstQ = false;
                    std::string vmod;
                    unsigned long long vrva = modRva(vt, vmod);
                    uintptr_t trFn = out ? *(uintptr_t*)(*(uintptr_t*)out + 3 * 8) : 0;
                    std::string tmod;
                    unsigned long long trva = trFn ? modRva(trFn, tmod) : 0;
                    _snprintf_s(b, sizeof(b), _TRUNCATE,
                                "{\"obj\":\"0x%llX\",\"vt\":\"%s+0x%llX\","
                                "\"recv\":\"0x%llX\",\"trFn\":\"%s+0x%llX\"}",
                                (unsigned long long)p, vmod.c_str(), vrva,
                                (unsigned long long)(uintptr_t)out, tmod.c_str(), trva);
                    j += b;
                    if (++qfound >= 12) break;
                }
            }
            addr = end == addr ? addr + 8 : end;
        }
        }
        j += "]";
    }

    // SCOM_Process: core85!current_process() returns the process object; its
    // service table (slot 11 = getService, per v8api/process.v) is the
    // documented entry to 1C services. Read-only: dump the object and look for
    // a frame object (rdata vtable in frame/config) among its fields.
    {
        ModuleRange core85;
        bool haveCore = false;
        for (const ModuleRange& m : mods) {
            size_t s = m.path.find_last_of(L"\\/");
            std::wstring n = (s == std::wstring::npos) ? m.path : m.path.substr(s + 1);
            if (_wcsicmp(n.c_str(), L"core85.dll") == 0) { core85 = m; haveCore = true; break; }
        }
        if (haveCore) {
            // 8.5 zeroes core85's in-memory export directory (exportCount:0),
            // so resolve the export from the on-disk image instead.
            uintptr_t fn = 0;
            std::string probeStr;
            bool fhOk = false;
            long long szPart = 0;
            DWORD gotB = 0;
            uint32_t dbgNNames = 0;
            uint32_t dbgExpRva = 0;
            uint32_t dbgFrva = 0;
            HANDLE fh = CreateFileW(core85.path.c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            fhOk = (fh != INVALID_HANDLE_VALUE);
            if (fh != INVALID_HANDLE_VALUE) {
                LARGE_INTEGER sz{};
                GetFileSizeEx(fh, &sz);
                szPart = sz.QuadPart;
                if (sz.QuadPart > 0 && sz.QuadPart < 64 * 1024 * 1024LL) {
                    DWORD got = 0;
                    std::vector<unsigned char> fbuf((size_t)sz.QuadPart);
                    BOOL rdOk = ReadFile(fh, fbuf.data(), (DWORD)fbuf.size(), &got, nullptr);
                    gotB = got;
                    if (rdOk && got == fbuf.size()) {
                        const unsigned char* fd = fbuf.data();
                        auto r32 = [fd](uintptr_t o) -> uint32_t {
                            return *(const uint32_t*)(fd + o);
                        };
                        uintptr_t dos = fd[0x3C] | (fd[0x3D] << 8) | (fd[0x3E] << 16) | ((uintptr_t)fd[0x3F] << 24);
                        if (dos + 0x100 < fbuf.size()) {
                            uintptr_t nt = dos + 4;
                            uint16_t nsec = *(const uint16_t*)(fd + nt + 2);
                            uint16_t optSize = *(const uint16_t*)(fd + nt + 16);
                            uintptr_t opt = nt + 20;
                            uintptr_t secTab = opt + optSize;
                            // RVA -> file offset via the section table
                            auto toRaw = [&](uint32_t rva) -> uint32_t {
                                for (uint16_t i = 0; i < nsec; ++i) {
                                    uintptr_t sh = secTab + (uintptr_t)i * 40;
                                    if (sh + 40 > fbuf.size()) break;
                                    uint32_t va = r32(sh + 12);
                                    uint32_t vs = r32(sh + 8);
                                    uint32_t raw = r32(sh + 20);
                                    if (rva >= va && rva < va + vs)
                                        return rva - va + raw;
                                }
                                return rva;
                            };
                            // 1C masks the PE magic in core85 (anti-analysis);
                            // infer the format from SizeOfOptionalHeader (224=PE32, 240=PE32+).
                            uintptr_t dd = opt + (optSize != 224 ? 112 : 96);  // export directory
                            if (dd + 8 <= fbuf.size()) {
                                uint32_t expRva = r32(dd);
                                if (expRva && expRva + 40 <= fbuf.size()) {
                                    uint32_t eo = toRaw(expRva);
                                    if (eo + 40 <= fbuf.size()) {
                                        uint32_t names = r32(eo + 32);
                                        uint32_t funcs = r32(eo + 28);
                                        uint32_t ords  = r32(eo + 36);
                                        uint32_t nNames = r32(eo + 24);
                                        dbgNNames = nNames;
                                        dbgExpRva = expRva;
                                        for (uint32_t i = 0; i < nNames && i < 16384; ++i) {
                                            uint32_t np = toRaw(r32(toRaw(names + i * 4)));
                                            if (!np || np + 64 > (uint32_t)fbuf.size()) continue;
                                            const char* nm = (const char*)(fd + np);
                                            if (memcmp(nm, "?current_process@core@@", 23) == 0) {
                                                uint16_t idx = *(const uint16_t*)(fd + toRaw(ords + i * 2));
                                                uint32_t frva = r32(toRaw(funcs + (uint32_t)idx * 4));
                                                fn = core85.base + frva;
                                                dbgFrva = frva;
                                                probeStr.assign(nm, strnlen(nm, 64));
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                CloseHandle(fh);
            }
            j += ",\"process\":{";
            {
                std::string pw;
                for (wchar_t wc : core85.path) pw.push_back((char)wc);
                std::string pwj;
                for (char c : pw) {
                    if (c == '\\' || c == '"') { pwj.push_back('\\'); pwj.push_back(c); }
                    else pwj.push_back(c);
                }
                char nb[360];
                _snprintf_s(nb, sizeof(nb), _TRUNCATE,
                            "\"path\":\"%s\",\"fh\":%d,\"sz\":%lld,\"got\":%u,\"expRva\":%u,\"nNames\":%u,\"frva\":%u,\"probe\":\"%s\"",
                            pwj.c_str(), (int)fhOk, szPart, gotB, dbgExpRva, dbgNNames, dbgFrva, probeStr.c_str());
                j += nb;
            }
            j += ",";
            if (fn) {
                // current_process() crashes off the UI thread (0xC0000005),
                // so run the probe on the UI thread via a momentary subclass
                // of the main 1C window.
                g85_fn = fn;
                g85_proc = g85_procVt = g85_svc = g85_svcVt = 0;
                g85_sawMsg = 0;
                HWND uiWin = nullptr;
                int dbgUiWin = 0, dbgCc = 0, dbgDone = 0;
                {
                    struct UiEnum {
                        static BOOL CALLBACK cb(HWND h, LPARAM lp) {
                            DWORD pid = 0;
                            GetWindowThreadProcessId(h, &pid);
                            if (pid != (DWORD)GetCurrentProcessId()) return TRUE;
                            wchar_t cls[64] = {};
                            GetClassNameW(h, cls, 64);
                            if (wcsncmp(cls, L"V8Window0", 9) == 0) {
                                *(HWND*)lp = h;
                                return FALSE;
                            }
                            return TRUE;
                        }
                    };
                    EnumWindows(UiEnum::cb, (LPARAM)&uiWin);
                }
                if (uiWin) {
                    dbgUiWin = 1;
                    g85_uiWin = (uintptr_t)uiWin;
                    // A44: the subclass is installed only by its owner. This
                    // used to be a hand-written SetWindowLongPtrW pair, racing
                    // the startup watcher armed just above; losing that race
                    // left g85_origWndProc == V8iSubclass85 (a window proc
                    // calling itself, 0xC00000FD on the first message).
                    dbgCc = V8iSubscribeOnUiThread(uiWin) ? 1 : 0;
                }
                dbgDone = g85_proc ? 1 : 0;
                std::string pm, sm, sm2, sm3, sm4;
                unsigned long long prva = 0, srva = 0, s2rva = 0, s3rva = 0, s4rva = 0;
                if (g85_procVt) {
                    pm.clear();
                    const ModuleRange* foundM = nullptr;
                    for (const ModuleRange& m : mods)
                        if (g85_procVt >= m.base && g85_procVt < m.base + m.size) {
                            foundM = &m;
                            break;
                        }
                    if (foundM) {
                        for (wchar_t wc : foundM->path) pm.push_back((char)wc);
                        size_t bs = pm.rfind('\\');
                        if (bs != std::string::npos) pm = pm.substr(bs + 1);
                        prva = g85_procVt - foundM->base;
                    }
                }
                if (g85_svcVt) {
                    const ModuleRange* foundM = nullptr;
                    for (const ModuleRange& m : mods)
                        if (g85_svcVt >= m.base && g85_svcVt < m.base + m.size) {
                            foundM = &m;
                            break;
                        }
                    if (foundM) {
                        for (wchar_t wc : foundM->path) sm.push_back((char)wc);
                        size_t bs = sm.rfind('\\');
                        if (bs != std::string::npos) sm = sm.substr(bs + 1);
                        srva = g85_svcVt - foundM->base;
                    }
                }
                if (g85_svc2Vt) {
                    const ModuleRange* foundM = nullptr;
                    for (const ModuleRange& m : mods)
                        if (g85_svc2Vt >= m.base && g85_svc2Vt < m.base + m.size) {
                            foundM = &m;
                            break;
                        }
                    if (foundM) {
                        for (wchar_t wc : foundM->path) sm2.push_back((char)wc);
                        size_t bs = sm2.rfind('\\');
                        if (bs != std::string::npos) sm2 = sm2.substr(bs + 1);
                        s2rva = g85_svc2Vt - foundM->base;
                    }
                }
                auto attrib = [&](uintptr_t vt, std::string& out, unsigned long long& rva) {
                    const ModuleRange* fm = nullptr;
                    for (const ModuleRange& m : mods)
                        if (vt >= m.base && vt < m.base + m.size) { fm = &m; break; }
                    if (fm) {
                        for (wchar_t wc : fm->path) out.push_back((char)wc);
                        size_t bs = out.rfind('\\');
                        if (bs != std::string::npos) out = out.substr(bs + 1);
                        rva = vt - fm->base;
                    }
                };
                attrib(g85_svc3Vt, sm3, s3rva);
                attrib(g85_svc4Vt, sm4, s4rva);
                _snprintf_s(b, sizeof(b), _TRUNCATE,
                            "\"uiWin\":%d,\"cc\":%d,\"saw\":%d,\"done\":%d,\"proc\":\"0x%llX\",\"vt\":\"%s+0x%llX\",\"s14ev\":\"0x%llX\",\"svt\":\"%s+0x%llX\",\"s14cmd\":\"0x%llX\",\"svt2\":\"%s+0x%llX\",\"s15ev\":\"0x%llX\",\"svt3\":\"%s+0x%llX\",\"s15cmd\":\"0x%llX\",\"svt4\":\"%s+0x%llX\"",
                            dbgUiWin, dbgCc, g85_sawMsg, dbgDone,
                            (unsigned long long)g85_proc, pm.c_str(), prva,
                            (unsigned long long)g85_svc, sm.c_str(), srva,
                            (unsigned long long)g85_svc2, sm2.c_str(), s2rva,
                            (unsigned long long)g85_svc3, sm3.c_str(), s3rva,
                            (unsigned long long)g85_svc4, sm4.c_str(), s4rva);
                j += b;
                j += ",\"slots\":[";
                for (int i = 0; i < 12; ++i) {
                    char sb[28];
                    _snprintf_s(sb, sizeof(sb), _TRUNCATE, "%s\"0x%llX\"",
                                i ? "," : "", (unsigned long long)g85_slots[i]);
                    j += sb;
                }
                j += "]";
                {
                    std::string fm, rm;
                    unsigned long long fr2 = 0, rr2 = 0;
                    attrib(g85_frameVt, fm, fr2);
                    attrib(g85_recvVt, rm, rr2);
                    char fb[260];
                    _snprintf_s(fb, sizeof(fb), _TRUNCATE,
                                ",\"frame\":\"0x%llX\",\"fvt\":\"%s+0x%llX\",\"recv\":\"0x%llX\",\"rvt\":\"%s+0x%llX\"",
                                (unsigned long long)g85_frame, fm.c_str(), fr2,
                                (unsigned long long)g85_recv, rm.c_str(), rr2);
                    j += fb;
                }
                {
                    // A48: one builder, one comma per member.
                    CmdInfoTail t;
                    t.evCount = g85_evCount;
                    t.evFrame = (unsigned long long)g85_evFrame;
                    t.hookOk = g_cwHookOk;
                    t.cwHits = g_cwHits;
                    t.subscribed = g85_subscribed;
                    t.qProcFrame = (unsigned long long)g85_qProcFrame;
                    t.qProcRecv = (unsigned long long)g85_qProcRecv;
                    t.qCmdFrame = (unsigned long long)g85_qCmdFrame;
                    t.qCmdRecv = (unsigned long long)g85_qCmdRecv;
                    t.qEvFrame = (unsigned long long)g85_qEvFrame;
                    t.qEvRecv = (unsigned long long)g85_qEvRecv;
                    j += CmdInfoTailJson(t);
                }
            } else {
                j += "\"fn\":null";
            }
            j += "}";
        }
    }
    j += "}";
    return j;
}

// "exports85 <module> [--count N]" — all exports of a module, read from disk.
std::string CmdExports85ToJson(const std::wstring& arg) {
    std::wstring mod = arg;
    int limit = 8192;
    size_t sp = arg.find(L" --count ");
    if (sp != std::wstring::npos) {
        mod = arg.substr(0, sp);
        limit = _wtoi(arg.c_str() + sp + 9);
        if (limit <= 0) limit = 8192;
    }
    while (!mod.empty() && (mod.front() == L' ' || mod.front() == L'\t')) mod.erase(0, 1);
    while (!mod.empty() && (mod.back() == L' ' || mod.back() == L'\t' || mod.back() == L'\r' || mod.back() == L'\n'))
        mod.pop_back();
    if (mod.empty())
        return "{\"status\":\"error\",\"message\":\"usage: exports85 <module> [--count N]\"}";

    ModuleRange m = V8iFindModuleByName(mod.c_str());
    if (!m.base) return "{\"status\":\"error\",\"message\":\"module not loaded in the target process\"}";

    static V8iExportEntry entries[8192];
    int cap = (limit < 8192) ? limit : 8192;
    int n = V8iDumpExportsFromFile(m.path, entries, cap);

    std::string j = "{\"status\":\"ok\",\"module\":\"";
    for (wchar_t c : mod) j += (c < 128) ? (char)c : '?';
    char b[512];
    _snprintf_s(b, sizeof(b), _TRUNCATE,
                "\",\"count\":%d,\"base\":\"0x%llX\",\"exports\":[", n,
                (unsigned long long)m.base);
    j += b;
    for (int i = 0; i < n; ++i) {
        const V8iExportEntry& e = entries[i];
        if (i) j += ",";
        j += "{\"name\":\"";
        for (const char* p = e.name; *p; ++p) {
            if (*p == '"' || *p == '\\') j += '\\';
            j += *p;
        }
        _snprintf_s(b, sizeof(b), _TRUNCATE,
                    "\",\"ordinal\":%u,\"rva\":\"0x%X\",\"va\":\"0x%llX\"}",
                    e.ordinal, e.rva, (unsigned long long)(m.base + e.rva));
        j += b;
    }
    j += "]}";
    return j;
}

// "frames" — what eventCreateFrame handed us: pointer, vtable, module, dump.
std::string CmdFramesToJson(const std::wstring&) {
    char b[512];
    _snprintf_s(b, sizeof(b), _TRUNCATE,
                "{\"status\":\"ok\",\"count\":%d,\"evCount\":%ld,"
                "\"cbtFired\":%d,\"cbtCalls\":%ld,\"cbtCreates\":%ld,"
                "\"cbtFault\":\"0x%08X\",\"cbtHook\":\"0x%llX\",\"cbtThreadHook\":\"0x%llX\",\"cbtThreadTid\":\"0x%lX\",\"cbtStr\":%ld,"
                "\"cbtFirstClass\":\"%s\",\"cbtLastClass\":\"%s\","
                "\"subscribed\":%d,\"frames\":[",
                g85_evFrame ? 1 : 0, g85_evCount, g_cbtFired, g_cbtCalls, g_cbtCreateCount,
                (unsigned)g_cbtFault, (unsigned long long)(uintptr_t)g_cbtHook,
                (unsigned long long)(uintptr_t)g_cbtThreadHook, g_cbtThreadTid, g_cbtStrCreates,
                g_cbtFirstClass, g_cbtLastClass, g85_subscribed);
    std::string j = b;
    if (!g85_evFrame) {
        j += "]}";
        return j;
    }
    _snprintf_s(b, sizeof(b), _TRUNCATE,
                "{\"ptr\":\"0x%llX\",\"vtable\":\"0x%llX\",\"module\":\"%s\",\"rva\":\"0x%X\",\"dump\":\"",
                (unsigned long long)g85_evFrame, (unsigned long long)g85_frameVt,
                g85_frameMod, g85_frameRva);
    j += b;
    for (int i = 0; i < 64; ++i) {
        _snprintf_s(b, sizeof(b), _TRUNCATE, "%s%02X", i ? " " : "", g85_frameDump[i]);
        j += b;
    }
    _snprintf_s(b, sizeof(b), _TRUNCATE,
                "\",\"dirRecv\":\"0x%llX\",\"dirRecvVt\":\"0x%llX\",\"dirExc\":\"0x%X\","
                "\"qiFrame\":\"0x%llX\",\"qiFrameVt\":\"0x%llX\",\"qiRecv\":\"0x%llX\",\"qiRecvVt\":\"0x%llX\","
                "\"qiExc\":%d,\"qiCallExc\":\"0x%X\"}]}",
                (unsigned long long)g85_dirRecv, (unsigned long long)g85_dirRecvVt,
                (unsigned)g85_dirExc,
                (unsigned long long)g85_qiFrame, (unsigned long long)g85_qiFrameVt,
                (unsigned long long)g85_qiRecv, (unsigned long long)g85_qiRecvVt,
                (int)g85_qiExc, (unsigned)g85_qiCallExc);
    j += b;
    return j;
}

// "cmd85 <num> [sub]" — invoke a designer command on 8.5 through the receiver
// captured by the early subscribe (g85_recv, obtained live: commandReceiver is
// slot 31 of the ITopLevelFrame forwarder vtable; recv->vtbl[0] is
// transmitCommand). Runs on the 1C UI thread through the same kV8iCmdMsg
// marshal as the 8.3 `cmd`. Requires eventCreateFrame to have fired, which on
// 8.5 needs the early injection path (hookcbt / launch) — a post-start attach
// never sees the frame event.
std::string CmdCmd85ToJson(const std::wstring& args0) {
    std::wstring args = args0;
    while (!args.empty() && (args.front() == L' ' || args.front() == L'\t')) args.erase(0, 1);
    unsigned int num = 0;
    int sub = 0;
    if (swscanf_s(args.c_str(), L"%u %d", &num, &sub) < 1)
        return "{\"status\":\"error\",\"message\":\"usage: cmd85 <num> [sub]\"}";
    return Cmd85SendJson(num, sub, false);
}

std::string CmdInfoToJson(const std::wstring&) { return CmdInfoToJsonA(); }

// A failed transmitCommand leaves the designer mid-modal. The platform disables
// its main frame before it creates the command's dialog, so an exception inside
// the command means the dialog never appears and nothing ever re-enables the
// frame: the whole Configurator stops taking input while every thread keeps
// pumping (8.3.27.2342 live: cmd 45 faults, the frame stays WS_DISABLED and
// clicking the bar does nothing because a disabled parent swallows the input).
// The failure is ours to clean up, and the frame is the same window class on
// 8.3 and 8.5.
//
// A120: the restore used to sweep every disabled V8 frame of the process --
// a parallel command's legitimately modal state (the platform disables the
// owner for the duration of its own dialog) was broken by a foreign failure.
// The marshal knows the frame it addressed: only that window is brought back,
// and only when it is a 1C frame class.
void RestoreFramesAfterFailedTransmit(HWND marshalTo) {
    if (!marshalTo || !IsWindow(marshalTo) || IsWindowEnabled(marshalTo)) return;
    wchar_t cls[64] = {};
    if (!GetClassNameW(marshalTo, cls, 64) ||
        (wcscmp(cls, L"V8TopLevelFrame") != 0 && wcsncmp(cls, L"V8Window0", 9) != 0))
        return;
    EnableWindow(marshalTo, TRUE);
    LogLine("cmd: re-enabled frame 0x%llX that the platform disabled before the fault",
            (unsigned long long)(uintptr_t)marshalTo);
}

std::string CmdCommandToJson(const std::wstring& args0) {
    std::wstring args = args0;
    bool wantHas = false;
    if (args.rfind(L"has ", 0) == 0) {
        wantHas = true;
        args = args.substr(4);
    }
    unsigned int num = 0;
    int sub = 0;
    if (swscanf_s(args.c_str(), L"%u %d", &num, &sub) < 1)
        return "{\"status\":\"error\",\"message\":\"usage: cmd <num> [sub]\"}";

    // 8.5 runs a different frame geometry: the 8.3 calibration below points at
    // an unrelated config.dll vtable there, and its receiver chain does not
    // exist (live: "no working receiver chain" plus an AV during validation).
    // A loaded core85.dll is the reliable platform marker — route through the
    // 8.5 receiver (slot-31 forwarder), captured post-start when needed.
    ModuleRange core85Probe;
    if (FindModule(L"core85.dll", core85Probe))
        return Cmd85SendJson(num, sub, wantHas);

    ModuleRange cfg;
    if (!FindModule(L"config.dll", cfg))
        return "{\"status\":\"error\",\"message\":\"config.dll not loaded\"}";

#if defined(_WIN64)
    // Re-validate the runtime-discovered frame on every use: 1C destroys
    // transient frames, and a stale object poisons all later calls (its freed
    // memory reads as garbage — live: the "vtable" became a module base).
    if (g_x64FrameObj) {
        uintptr_t vt = IsReadable((void*)g_x64FrameObj, sizeof(void*))
                           ? *(uintptr_t*)g_x64FrameObj : 0;
        uintptr_t core = vt && IsReadable((void*)(g_x64FrameObj + sizeof(void*)), sizeof(void*))
                             ? *(uintptr_t*)(g_x64FrameObj + sizeof(void*)) : 0;
        if (!vt || !core || !X64FrameVtValid(cfg, vt) ||
            !IsReadable((void*)core, sizeof(void*))) {
            LogLine("cmd: discovered frame 0x%llX went stale, re-discovering",
                    (unsigned long long)g_x64FrameObj);
            g_x64FrameObj = 0;
            g_x64DiscoveryDone = false;
        }
    }
    const uintptr_t kFrameVtblRva = 0x2EFB50;   // ITopLevelFrame vtable, 8.3.27.1989 x64
    const uintptr_t kCoreOffset = sizeof(void*);
    const int kTransmitSlot = 3;
    // With a runtime-discovered frame (other 8.3 patches) both the vtable and
    // the receiver offset come from the discovery, not from the constants.
    const uintptr_t vtblPtr = g_x64FrameObj ? *(uintptr_t*)g_x64FrameObj
                                            : cfg.base + kFrameVtblRva;
    uintptr_t kRecvBackOffset = g_x64FrameObj ? g_x64RecvOffset : 0x20;
    // The RVA above is calibrated for one 8.3 build; on another build the
    // runtime discovery has to find the frame, and only then is this path
    // taken. (A zero RVA used to be checked here, but the constant made that
    // branch dead code.)
#else
    // x86: calibrate at runtime — no hardcoded RVA. A heap object whose first
    // dword points into config.dll .rdata, whose vtable slots 3..40 all point
    // into config.dll .text, and whose receiver chain (core = obj+4,
    // recv = core - off, recv vtable in frame.dll .rdata) is consistent is the
    // main frame. Discovered once: the scan walks the whole address space, so
    // repeating it per command was both slow and racy (freed pages).
    static const uintptr_t kCoreOffset = sizeof(void*);
    static const int kTransmitSlot = 3;
    // True when this call reused the cached x86 frame instead of discovering
    // it; only then is a second pass (cache invalidation) worth trying.
    bool usedCachedFrame = g_x86FrameObj != 0;
    if (!g_x86FrameObj) g_x86FrameObj = DiscoverFrameVtblX86(cfg);
    if (!g_x86FrameObj)
        return "{\"status\":\"error\",\"message\":\"no frame vtable found on x86\"}";
    const uintptr_t kRecvBackOffset = g_x86RecvOffset;
    uint32_t vtblVal = 0;
    if (!ReadU32Safe(g_x86FrameObj, &vtblVal) || !vtblVal)
        return "{\"status\":\"error\",\"message\":\"frame vtable unreadable\"}";
    const uintptr_t vtblPtr = vtblVal;   // vtable of the discovered frame
#endif

    char numBuf[256];
    std::string j = "{\"status\":\"ok\"";
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"num\":%u,\"sub\":%d,\"vtbl\":\"0x%llX\"",
                num, sub, (unsigned long long)vtblPtr);
    j += numBuf;

    uintptr_t frame = 0;
    bool cached = false;
    std::vector<uintptr_t> candidates;
    // A118: the discovery pass already validated the frame object (on x64 it
    // was revalidated above) and the exact receiver offset; use it directly
    // instead of re-scanning the address space on every command -- the x86
    // path has done so all along, while the x64 one kept re-walking gigabytes
    // per call because the cache slot it read (g_cmdFrameCache) was never
    // written.
#if defined(_WIN64)
    if (g_x64FrameObj) {
        frame = g_x64FrameObj;
        cached = true;
    }
#else
    if (g_x86FrameObj) {
        frame = g_x86FrameObj;
        cached = true;
    }
#endif
    uintptr_t frameVt = 0;
    if (frame && ReadPtrSafe(frame, &frameVt) && frameVt == vtblPtr) {
        cached = true;
        candidates.push_back(frame);
    } else {
        frame = 0;
        // Walk the address space, skip module images, and look for heap objects
        // whose first word is the ITopLevelFrame vtable. Both the shell frame and
        // the core frame share this vtable; any of them routes to the receiver.
        std::vector<ModuleRange> mods;
        for (const ModuleRange& m : EnumModules()) mods.push_back(m);
        auto insideModule = [&mods](uintptr_t a) {
            for (const ModuleRange& m : mods)
                if (a >= m.base && a < m.base + m.size) return true;
            return false;
        };
        uintptr_t addr = 0x10000;
        uint64_t scanned = 0;
        while (addr < 0x00007FFFFFFFFFFFULL) {
            MEMORY_BASIC_INFORMATION mi = {};
            if (VirtualQuery((void*)addr, &mi, sizeof(mi)) == 0) break;
            uintptr_t end = addr + mi.RegionSize;
            bool usable = mi.State == MEM_COMMIT &&
                          (mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)) &&
                          !(mi.Protect & PAGE_GUARD) && !insideModule((uintptr_t)mi.BaseAddress);
            if (usable) {
                const uintptr_t cap = mi.RegionSize > 64 * 1024 * 1024
                                          ? 64 * 1024 * 1024 : (uintptr_t)mi.RegionSize;
                for (uintptr_t p = (uintptr_t)mi.BaseAddress; p < (uintptr_t)mi.BaseAddress + cap;
                     p += sizeof(void*)) {
                    ++scanned;
                    uintptr_t val = 0;
                    if (!ReadPtrSafe(p, &val) || val != vtblPtr) continue;
                    uintptr_t core = 0;
                    uintptr_t coreVt = 0;
                    if (ReadPtrSafe(p + kCoreOffset, &core) &&
                        ReadPtrSafe(core, &coreVt) &&
                        IsReadable((void*)coreVt, 32 * sizeof(void*))) {
                        candidates.push_back(p);
                        if (candidates.size() >= 16) break;
                    }
                }
            }
            if (candidates.size() >= 16) break;
            addr = end == addr ? addr + sizeof(void*) : end;
        }
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"scan\":{\"cached\":%s,\"scanned\":%llu,\"candidates\":%zu}",
                    cached ? "true" : "false", (unsigned long long)scanned, candidates.size());
        j += numBuf;
    }

    void* recv = nullptr;
    void* trFn = nullptr;
    uintptr_t usedFrame = 0;
    bool forced = false;
    // Diagnostic: `cmd <num> [sub] @<hexrecv> #<slot>` overrides the discovered
    // receiver with an explicit object address + slot (x86 calibration probe).
    const wchar_t* atP = wcschr(args.c_str(), L'@');
    const wchar_t* hashP = wcschr(args.c_str(), L'#');
    if (atP && hashP) {
        uintptr_t fRecv = (uintptr_t)wcstoull(atP + 1, nullptr, 16);
        int fSlot = (int)wcstoul(hashP + 1, nullptr, 10);
        if (fRecv && fSlot >= 0 && fSlot < 64 && IsReadable((void*)fRecv, sizeof(void*))) {
            uintptr_t fVt = *(uintptr_t*)fRecv;
            if (IsReadable((void*)(fVt + fSlot * sizeof(void*)), sizeof(void*))) {
                void* fFn = ((void**)fVt)[fSlot];
                if (IsReadable(fFn, 1)) {
                    recv = (void*)fRecv;
                    trFn = fFn;
                    usedFrame = 0;
                    forced = true;
                }
            }
        }
        if (!forced)
            return "{\"status\":\"error\",\"message\":\"probe target unreadable\"}";
    }
    // For each candidate the receiver is a fixed distance before coreMainFrame
    // (frame+ptrSize), so no vtable calls are needed to obtain it.
    if (!forced) {
        // Best = receiver answered hasHandler(45) alive; fallback = first
        // structurally valid chain that did not throw. A structurally valid
        // chain can still belong to a sibling class (8.3.27.2342 live: three
        // config-vtable objects pass the static checks, only the main frame's
        // receiver answers a COM call without an exception).
        uintptr_t bestFrame = 0, aliveFrame = 0;
        void* bestRecv = nullptr; void* bestTr = nullptr; uintptr_t bestVt = 0;
        void* aliveRecv = nullptr; void* aliveTr = nullptr; uintptr_t aliveVt = 0;
        for (uintptr_t cand : candidates) {
            uintptr_t core = 0;
            if (!ReadPtrSafe(cand + kCoreOffset, &core) || !core) continue;
            uintptr_t candRecv = core - kRecvBackOffset;
            uintptr_t recvVt = 0;
            if (!ReadPtrSafe(candRecv, &recvVt)) continue;
            if (!IsReadable((void*)(recvVt + 6 * sizeof(void*)), sizeof(void*))) continue;
            void* candTr = ((void**)recvVt)[kTransmitSlot];
            if (!IsReadable(candTr, 1)) continue;

            // Live probe on the UI thread: hasHandler(cmd 45) through the same
            // marshal bridge the transmit uses. Exception / timeout = wrong
            // chain, try the next candidate.
            void* probeTr = ((void**)recvVt)[5];              // hasHandler
            if (!IsReadable(probeTr, 1)) continue;
            V8Cmd probeCmd = {};
            memcpy(probeCmd.group, kConfigGroup, 16);
            probeCmd.cmdNum = 45;
            V8iRequest req;
            req.mode = 1;
            req.recv = (void*)candRecv;
            req.trFn = probeTr;
            req.cmd = &probeCmd;
            req.cmdSize = sizeof(probeCmd);
            const V8iMarshalResult mr = V8iMarshal(req, 10000, true);
            if (mr.status == -98) {
                // no marshal window (yet) — keep the structural pick
                bestFrame = cand; bestRecv = (void*)candRecv; bestTr = candTr;
                bestVt = recvVt;
                break;
            }
            if (mr.status != 0) continue;              // timeout: try the next one
            if (mr.exc != 0 || mr.rc < 0) continue;    // wrong chain

            if (bestFrame == 0) {
                bestFrame = cand; bestRecv = (void*)candRecv; bestTr = candTr;
                bestVt = recvVt;
                break;   // alive and claims the command — the strongest match
            }
            if (aliveFrame == 0) {
                aliveFrame = cand; aliveRecv = (void*)candRecv; aliveTr = candTr;
                aliveVt = recvVt;
            }
        }
        if (bestFrame == 0 && aliveFrame != 0) {
            bestFrame = aliveFrame; bestRecv = aliveRecv; bestTr = aliveTr;
            bestVt = aliveVt;
        }
        if (bestFrame != 0) {
            usedFrame = bestFrame;
            recv = bestRecv;
            trFn = bestTr;
            frame = bestFrame;
            if (wantHas) {
                // The caller asked for hasHandler, not transmit: swap the
                // target to slot 5 of the picked receiver's vtable.
                void* hasTr = ((void**)bestVt)[5];
                if (IsReadable(hasTr, 1)) trFn = hasTr;
            }
        }
    }

    if (!trFn) {
#if defined(_WIN64)
        // The hardcoded vtable RVA is calibrated to 8.3.27.1989; other 8.3
        // patches have an unrelated vtable at the same RVA (8.3.27.2342 live).
        // Discover the frame at runtime (live-probed) and re-run with it; the
        // cooldown keeps repeated failing clicks from re-scanning in a loop.
        ULONGLONG now = GetTickCount64();
        if (!g_x64DiscoveryDone || now - g_x64DiscoveryTick > 3000) {
            g_x64DiscoveryDone = true;
            g_x64DiscoveryTick = now;
            g_x64FrameObj = DiscoverFrameVtblX64(cfg);
            if (g_x64FrameObj) return CmdCommandToJson(args0);
        }
#else
        // The cached frame no longer answers: it was freed/recreated with the
        // window. Drop it and rediscover once (the retry starts uncached, so a
        // second failure returns the error instead of recursing forever).
        if (usedCachedFrame) {
            g_x86FrameObj = 0;
            return CmdCommandToJson(args0);
        }
#endif
        return j + ",\"error\":\"no working receiver chain\"}";
    }

    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"frame\":\"0x%llX\",\"recv\":\"0x%llX\"",
                (unsigned long long)usedFrame, (unsigned long long)(uintptr_t)recv);
    j += numBuf;

    // Marshal onto the 1C UI thread: fill the pending slot, post a message to
    // the frame window; its WndProc (our subclass) runs on the UI thread and
    // executes transmitCommand there.
    HWND cmdHwnd = nullptr;
    DWORD ensureErr = 0;
    const char* marshalPath = "";
    if (!EnsureCmdUi(&cmdHwnd, &ensureErr, &marshalPath)) {
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE,
                    ",\"error\":\"marshaling setup failed\",\"code\":\"0x%X\"", (unsigned)ensureErr);
        return j + numBuf + "}";
    }
    j += std::string(",\"marshal\":\"") + marshalPath + "\"";
    (void)cmdHwnd;   // the marshal re-resolves the window itself

    // Synchronous cross-thread dispatch: blocks until the UI thread's WndProc
    // runs (SMTO_BLOCK) or the target is hung (capped by the timeout).
    V8Cmd cmd = {};
    memcpy(cmd.group, kConfigGroup, 16);
    cmd.cmdNum = num;
    cmd.param = sub;
    V8iRequest req;
    req.mode = wantHas ? 1 : 0;
    req.recv = recv;
    req.trFn = trFn;
    req.cmd = &cmd;
    req.cmdSize = sizeof(cmd);
    const V8iMarshalResult mr = V8iMarshal(req, 30000, true);
    if (mr.status == -97) {
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE,
                    ",\"error\":\"UI thread did not answer (0x%X)\"", (unsigned)GetLastError());
        return j + numBuf + "}";
    }
    if (mr.status != 0)
        return j + ",\"error\":\"timeout waiting for UI thread\"}";

    int rc = mr.rc;
    if (rc < 0) {
        // The fault stopped the platform between "disable the owner" and "show
        // the dialog": put the frame back before reporting, or the Configurator
        // stays dead until someone re-enables it from outside. A120: only the
        // frame this command was marshaled to.
        RestoreFramesAfterFailedTransmit(g_cmdHwnd);
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"error\":\"transmit exception 0x%X\"",
                    (unsigned)mr.exc);
        return j + numBuf + "}";
    }
    if (wantHas) {
        _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"has\":%s",
                    rc == 0 ? "false" : "true");
        return j + numBuf + "}";
    }
    _snprintf_s(numBuf, sizeof(numBuf), _TRUNCATE, ",\"sent\":true,\"rc\":%d", rc);
    j += numBuf;
    return j + "}";
}

}  // namespace platform
}  // namespace v8i

namespace v8i {
using namespace platform;

// The command receiver of the main frame, for the native-menu hooks
// (src/payload/mainmenu.cpp). Runs the same discovery the cmd chain uses and
// validates the chain with a live hasHandler(45) probe through the marshal.
// 8.3 only: the 8.5 receiver is captured on the cmd85 path and its vtable
// layout is not wired for the menu yet.
bool V8iGetCommandReceiver(void** recvOut, uintptr_t** recvVtOut,
                                int* transmitSlot, int* updateSlot, int* hasSlot,
                                void** coreOut, void** frameObjOut) {
    ModuleRange cfg;
    if (!FindModule(L"config.dll", cfg)) return false;
    if (FindModule(L"core85.dll", cfg)) return false;   // 8.5: not wired yet

    uintptr_t frame = 0;
    uintptr_t recvBack = 0;
#if defined(_WIN64)
    if (!g_x64FrameObj) g_x64FrameObj = DiscoverFrameVtblX64(cfg);
    frame = g_x64FrameObj;
    // A117: the discovery found the frame AND the receiver offset it works
    // with -- the cmd chain uses it (g_x64RecvOffset, 0x20 on the calibration
    // build), and this receiver must match: a hard 0x20 built a receiver for
    // the wrong offset on any build the discovery calibrated differently.
    recvBack = g_x64RecvOffset;
#else
    if (!g_x86FrameObj) g_x86FrameObj = DiscoverFrameVtblX86(cfg);
    frame = g_x86FrameObj;
    recvBack = g_x86RecvOffset;
#endif
    if (!frame) return false;

    uintptr_t core = 0;
    if (!ReadPtrSafe(frame + sizeof(void*), &core) || !core) return false;
    void* recv = (void*)(core - recvBack);
    uintptr_t vt = 0;
    if (!ReadPtrSafe((uintptr_t)recv, &vt) || !IsReadable((void*)vt, 8 * sizeof(void*)))
        return false;
    void* hasTr = ((void**)vt)[5];   // hasHandler
    if (!IsReadable(hasTr, 1)) return false;

    // Live probe: the same hasHandler(45) the cmd chain uses to tell the main
    // frame's receiver from its siblings (8.3.27.2342 live: three config
    // vtable objects pass the static checks, only the main frame answers).
    V8Cmd probeCmd = {};
    memcpy(probeCmd.group, kConfigGroup, 16);
    probeCmd.cmdNum = 45;
    V8iRequest req;
    req.mode = 1;
    req.recv = recv;
    req.trFn = hasTr;
    req.cmd = &probeCmd;
    req.cmdSize = sizeof(probeCmd);
    const V8iMarshalResult mr = V8iMarshal(req, 10000, true);
    if (mr.status != 0 || mr.exc != 0 || mr.rc < 0) return false;

    *recvOut = recv;
    *recvVtOut = (uintptr_t*)vt;
    *transmitSlot = 3;
    *updateSlot = 4;
    *hasSlot = 5;
    if (coreOut) *coreOut = (void*)core;
    if (frameObjOut) *frameObjOut = (void*)frame;
    return true;
}

// Runs a functor on the 1C UI thread through the cmd marshal. Used by the
// native-menu build steps (src/payload/mainmenu.cpp): the same bridge the cmd
// chain uses, with its WndProc re-assertion and fallbacks, instead of a
// private subclass that duplicates them.
bool V8iRunOnUi(void (*fn)(void*), void* arg, int timeoutMs) {
    V8iRequest req;
    req.mode = 3;
    req.fun = fn;
    req.funArg = arg;
    // No SMTO_ABORTIFHUNG: while the base loads, the UI thread does not pump
    // for tens of seconds — that is business, not a hang.
    const V8iMarshalResult mr = V8iMarshal(req, (DWORD)timeoutMs, false);
    if (mr.status == -98) return false;   // no marshal window yet
    if (mr.status != 0) return false;     // timed out: the request was retired
    if (mr.rc != 0)
        LogLine("mainmenu/UI: шаг упал (0x%08X)", (unsigned)mr.rc);
    return mr.rc == 0;
}

}  // namespace v8i
