#include "v8inject/diag.h"
#include "v8inject/v8i_export.h"
#include "v8inject/hook.h"
#include "v8inject/menu.h"
#include "v8inject/gitbar.h"
#include "v8inject/objects.h"
#include "v8inject/disasm.h"
#include "v8inject/memscan.h"
#include "v8inject/pe.h"
#include "v8inject/pe_utils.h"
#include "v8inject/protocol.h"
#include "v8inject/typeinfo_utils.h"
#include "v8inject/report.h"
#include "v8inject/text.h"
#include "commands/inspect_commands.h"
#include "platform/platform_commands.h"
#include "reply_fit.h"

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <new>
#include <string>

using namespace v8i;
using namespace v8i::commands;
using namespace v8i::platform;

namespace {

SharedIo* g_io = nullptr;

// Sequence number of the request the payload is answering right now. The command
// loop is single-threaded, so a plain variable is enough; PutResponse publishes
// the reply only while that same request is still the one the host waits for
// (A45).
LONG g_curSeq = 0;

// Log folder comes from the shared block, so host and payload always agree.
void InitPayloadLog(const wchar_t* dirFromBlock) {
    if (dirFromBlock && dirFromBlock[0]) {
        SetLogDirectory(dirFromBlock);
        return;
    }
    // Fallback: next to the payload DLL itself.
    HMODULE me = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)&InitPayloadLog, &me) && me) {
        wchar_t self[MAX_PATH] = {};
        GetModuleFileNameW(me, self, MAX_PATH);
        wchar_t* slash = wcsrchr(self, L'\\');
        if (slash) *slash = 0;
        SetLogDirectory(self);
    }
}

// The "loaded" reply of the handshake is not an answer to a request -- nothing
// has been posted yet -- so it is published unconditionally. The sequence stamp
// plays no part in it: the host takes the reply and puts the word back to idle.
void PublishHandshakeReply(SharedIo* io, const std::string& json) {
    if (!io) return;
    size_t n = json.size();
    if (n > kResponseBytes - 1) n = kResponseBytes - 1;
    memcpy(io->response, json.data(), n);
    io->response[n] = 0;
    InterlockedExchange((volatile LONG*)&io->responseLen, (LONG)n);
    InterlockedExchange((volatile LONG*)&io->ready, kStateResponse);
}

bool PutResponse(const std::string& json) {
    return g_io && V8iPublishReply(g_io, g_curSeq, json.data(), json.size());
}

// A41: the address comes from the command line, so it may point at anything at
// all. Calling QueryInterface on such a "COM object" is a call through an
// arbitrary qword inside the 1C process; the cheap and honest gate is that the
// qword (the vtable) lies in the executable part of a mapped image. A string,
// a request buffer or a heap node is rejected before any target code runs.
static bool LooksLikeComObject(const void* p, uintptr_t* vtable) {
    if (!p || !IsReadable(p, sizeof(uintptr_t))) return false;
    uintptr_t vt = 0;
    memcpy(&vt, p, sizeof(vt));
    if (!vt) return false;

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery((const void*)vt, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE) return false;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    const DWORD exec = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!(mbi.Protect & exec)) return false;
    *vtable = vt;
    return true;
}

enum class ScanStatus {
    ok,
    badUsage,
    noModule,
    notReadable,
    notComObject,
    noTypeInfo,
    crashed,
};

static const wchar_t* ScanStatusText(ScanStatus st) {
    switch (st) {
    case ScanStatus::badUsage:     return L"usage: scan <module> <addrHex>";
    case ScanStatus::noModule:     return L"module not found";
    case ScanStatus::notReadable:  return L"address is not readable";
    case ScanStatus::notComObject: return L"address does not look like a COM object";
    case ScanStatus::noTypeInfo:   return L"no ITypeInfo at the address";
    case ScanStatus::crashed:      return L"scan crashed inside the target";
    case ScanStatus::ok:           break;
    }
    return L"scan failed";
}

// "scan <moduleName> <addrHex>"
static ScanStatus RunScanImpl(const wchar_t* cmd, TypeInfoReport& rep) {
    wchar_t moduleName[64] = {};
    unsigned long long addr = 0;
    int matched = swscanf_s(cmd, L"scan %63s %llx", moduleName,
                            (unsigned)_countof(moduleName), &addr);
    if (matched != 2) return ScanStatus::badUsage;

    ModuleRange mr;
    if (!FindModule(moduleName, mr)) return ScanStatus::noModule;

    rep.moduleName = moduleName;
    rep.moduleBase = mr.base;

    const void* p = (const void*)(uintptr_t)addr;
    if (!IsReadable(p, sizeof(uintptr_t))) return ScanStatus::notReadable;
    uintptr_t vt = 0;
    if (!LooksLikeComObject(p, &vt)) return ScanStatus::notComObject;

    // From here on the call runs code of the target process: the SEH frame
    // around the whole scan turns any fault into a JSON error.
    ITypeInfo* ti = nullptr;
    HRESULT hr = GetTypeInfoFromUnknown((IUnknown*)p, &ti);
    if (FAILED(hr) || !ti) return ScanStatus::noTypeInfo;
    hr = ScanTypeInfo(ti, rep);
    ti->Release();
    return SUCCEEDED(hr) ? ScanStatus::ok : ScanStatus::noTypeInfo;
}

// POD-only frame around the whole scan: the parsers and the module walk touch
// memory of a foreign process as well, and one AV anywhere in them must still
// come back as a JSON error. (C2712: no C++ object that needs unwinding may
// live in the frame that owns __try, hence the pointer-only struct.)
struct ScanCall {
    const wchar_t* cmd;
    TypeInfoReport* rep;
    ScanStatus* status;
};

static int RunScanUnderSeh(ScanCall* call) {
    __try {
        *call->status = RunScanImpl(call->cmd, *call->rep);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *call->status = ScanStatus::crashed;
        return 0;
    }
}

static ScanStatus RunScan(const wchar_t* cmd, TypeInfoReport& rep) {
    ScanStatus st = ScanStatus::ok;
    ScanCall call{ cmd, &rep, &st };
    RunScanUnderSeh(&call);
    return st;
}

// MSVC C2712: __try cannot live in a function that needs C++ unwinding, so the
// guarded body takes only POD pointers. The command text is copied into a
// stack buffer before the call; the result is written into an out-parameter.
typedef std::string (*CommandFn)(const std::wstring&);

// SEH cannot protect a frame that needs C++ unwinding (MSVC C2712), so the
// guarded function receives no C++ objects at all: it calls a POD-shaped
// thunk that writes into a raw buffer and reports a status code.
typedef int (*PackedFn)(const wchar_t* text, char* out, size_t outCap, size_t* outLen);

// GetExceptionInformation() is only legal inside the filter expression, so the
// record is captured there and the handler body stays a plain assignment.
static int RecordException(EXCEPTION_POINTERS* ep, unsigned* code, uintptr_t* faultAt) {
    *code = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0;
    *faultAt = ep && ep->ExceptionRecord
                   ? (uintptr_t)ep->ExceptionRecord->ExceptionAddress : 0;
    return EXCEPTION_EXECUTE_HANDLER;
}

static int GuardCall(PackedFn fn, const wchar_t* text, char* out, size_t outCap,
                     size_t* outLen, unsigned* code, uintptr_t* faultAt) {
    int ok = 0;
    __try {
        ok = fn(text, out, outCap, outLen);
    } __except (RecordException(GetExceptionInformation(), code, faultAt)) {
        ok = 0;
    }
    return ok;
}

// Runs one command under SEH. A crash becomes a JSON error reply instead of
// taking the host process down with it.
namespace {

// Carries the real command function through a POD-only interface.
struct ThunkCtx {
    CommandFn fn;
};
ThunkCtx g_thunk{};

// Why the packer returned 0 (no reply landed in the buffer). A crash of the
// command is not the only way there: a C++ exception thrown by the command --
// std::bad_alloc above all, when a scan wants a vector it cannot have -- used
// to escape the packer and terminate the payload thread with no answer at all
// (A69).
enum PackReason {
    kPackNone = 0,
    kPackOutOfMemory,
    kPackThrew,
};
PackReason g_packReason = kPackNone;

int PackedThunk(const wchar_t* text, char* out, size_t outCap, size_t* outLen) {
    if (!g_thunk.fn) return 0;
    g_packReason = kPackNone;
    try {
        // A69: the reply is no longer cut to the buffer. `tmp` lives in this
        // frame, which is unwound without C++ destructors if the command
        // faults -- the request is answered with an error and the one buffer
        // is what the crash costs.
        std::string tmp = g_thunk.fn(std::wstring(text ? text : L""));
        return (int)payload::FitReply(tmp, out, outCap, outLen);
    } catch (const std::bad_alloc&) {
        g_packReason = kPackOutOfMemory;
    } catch (...) {
        g_packReason = kPackThrew;
    }
    *outLen = 0;
    return 0;
}

}  // namespace

static std::string Guarded(const wchar_t* what, CommandFn fn, const std::wstring& args) {
    // A69: the request holds kRequestChars (4096) wide characters, and the
    // argument used to be copied into wchar_t[1024]: a long command line was
    // answered for its first quarter, silently. The guarded frame takes only a
    // pointer, and `args` outlives the call, so it is passed as it is.
    //
    // The response goes into a buffer of exactly the size the block has: the
    // copy either fits whole or is refused (see reply_fit.h).
    static char buffer[kResponseBytes];

    g_thunk.fn = fn;
    g_packReason = kPackNone;
    size_t len = 0;
    unsigned code = 0;
    uintptr_t faultAt = 0;
    const int fit = GuardCall(PackedThunk, args.c_str(), buffer, sizeof(buffer), &len, &code,
                              &faultAt);
    if (fit == payload::kReplyFits) return std::string(buffer, len);

    char buf[320];
    if (fit == payload::kReplyTooLarge) {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"status\":\"error\",\"message\":\"response too large\","
                    "\"command\":\"%ls\",\"bytes\":%llu,\"limit\":%d}",
                    what ? what : L"?", (unsigned long long)len, (int)(kResponseBytes - 1));
        LogLine("command refused: %llu-byte reply does not fit %d bytes", (unsigned long long)len,
                (int)(kResponseBytes - 1));
        return buf;
    }
    if (g_packReason == kPackOutOfMemory) {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"status\":\"error\",\"message\":\"out of memory in command\","
                    "\"command\":\"%ls\"}",
                    what ? what : L"?");
        LogLine("command ran out of memory");
        return buf;
    }
    if (g_packReason == kPackThrew) {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "{\"status\":\"error\",\"message\":\"command raised a C++ exception\","
                    "\"command\":\"%ls\"}",
                    what ? what : L"?");
        LogLine("command threw an exception");
        return buf;
    }

    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "{\"status\":\"error\",\"message\":\"command crashed\","
                "\"command\":\"%ls\",\"exception\":\"0x%08X\",\"at\":\"0x%llX\"}",
                what ? what : L"?", code, (unsigned long long)faultAt);
    LogLine("command raised 0x%08X at 0x%llX", code, (unsigned long long)faultAt);
    return buf;
}

}  // namespace

bool v8i::V8iPublishReply(SharedIo* io, LONG requestSeq, const char* data, size_t len) {
    if (!io || !data) return false;

    // The host owns the state word from idle to request; a reply may only be
    // published while that same request is still the current one. Checked
    // before the buffer is touched: a host that timed out has already taken the
    // word back, and the next request owns `response` now (A45).
    if (InterlockedCompareExchange((volatile LONG*)&io->ready, 0, 0) != kStateRequest) return false;
    if (InterlockedCompareExchange((volatile LONG*)&io->seq, 0, 0) != requestSeq) {
        LogLine("reply for seq %ld dropped: the host moved on to %ld",
                (long)requestSeq, (long)io->seq);
        return false;
    }

    const size_t n = len > kResponseBytes - 1 ? kResponseBytes - 1 : len;
    memcpy(io->response, data, n);
    io->response[n] = 0;
    InterlockedExchange((volatile LONG*)&io->responseLen, (LONG)n);
    InterlockedExchange((volatile LONG*)&io->respSeq, requestSeq);

    // Request -> Response, not a blind store: when the host reset the word (or
    // the host-gone watchdog did) between the check and here, the reply is
    // dropped and the state stays what the host chose. The other order cannot
    // lose an exit: the watchdog's plain store always wins over this CAS.
    if (InterlockedCompareExchange((volatile LONG*)&io->ready, kStateResponse, kStateRequest) !=
        kStateRequest) {
        LogLine("reply for seq %ld dropped: state changed while publishing", (long)requestSeq);
        return false;
    }
    return true;
}

V8I_API int V8I_CALL v8i_version() {
    return 1;
}

static int RunPayload(const wchar_t* sharedName) {
    if (!sharedName) return -1;

    HANDLE hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sharedName);
    if (!hMap) {
        InitPayloadLog(nullptr);
        LogLine("OpenFileMapping(%ls) failed, win32=%lu", sharedName, GetLastError());
        return kDiagNoBlock;
    }

    g_io = (SharedIo*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
    if (!g_io) {
        // The block is smaller than this build's SharedIo: it was created by a
        // host of an older protocol. There is nothing to write the reason into
        // -- that is the mismatch -- so it only reaches the log and the host
        // sees "no reply".
        const DWORD err = GetLastError();
        CloseHandle(hMap);
        InitPayloadLog(nullptr);
        LogLine("MapViewOfFile(%ls, %llu) failed, win32=%lu: the block was created "
                "by a host of another protocol version", sharedName,
                (unsigned long long)sizeof(SharedIo), err);
        return kDiagNoView;
    }

    InitPayloadLog(g_io->logDir);
    HookInstallFaultLogger();
    LogLine("RunPayload started, pid=%lu arch=%s", GetCurrentProcessId(),
            sizeof(void*) == 8 ? "x64" : "x86");
    LogLine("MapViewOfFile -> %p", (void*)g_io);

    // A96: refuse a block laid out for another protocol before promising
    // anything. The host stamps the version it created the block for; the stamp
    // this payload echoes is what tells the host which build answered.
    const LONG hostAbi = g_io->abiVersion;
    const LONG hostSize = g_io->structSize;
    if (hostAbi != kProtocolAbi || hostSize != (LONG)sizeof(SharedIo)) {
        LogLine("protocol mismatch: block speaks abi=%ld size=%ld, payload speaks "
                "abi=%ld size=%d", hostAbi, hostSize, kProtocolAbi, (int)sizeof(SharedIo));
        InterlockedExchange((volatile LONG*)&g_io->diag, kDiagAbiMismatch);
        InterlockedExchange((volatile LONG*)&g_io->ready, kStateExit);
        UnmapViewOfFile(g_io);
        g_io = nullptr;
        CloseHandle(hMap);
        return kDiagAbiMismatch;
    }
    InterlockedExchange((volatile LONG*)&g_io->payloadAbi, kProtocolAbi);

    // Native «GitBar» item in the Configurator menu (8.3.27/8.5 layout, see
    // src/payload/mainmenu.cpp). Outside 1C (the tests) this is a no-op.
    if (V8iIsTargetProcess()) v8i::V8iStartNativeMenu();

    // Report readiness before anything that can fail.
    PublishHandshakeReply(g_io, "{\"status\":\"loaded\"}");

    const int rc = V8iRunCommandLoop(g_io);
    UnmapViewOfFile(g_io);
    g_io = nullptr;
    CloseHandle(hMap);
    return rc;
}

// A45: a payload must not outlive its host. The host's pid is in the block; when
// that process is gone nobody reads a reply any more, and the named block keeps
// the next host out with ERROR_ALREADY_EXISTS for good. The watchdog asks the
// command loop to leave instead, which releases the mapping (and with it the
// block) once the running command returns.
struct HostWatch {
    HANDLE host = nullptr;   // SYNCHRONIZE on the host process
    HANDLE stop = nullptr;   // set by the loop before it unmaps the block
    SharedIo* io = nullptr;
};

static DWORD WINAPI HostGoneThread(LPVOID arg) {
    HostWatch* w = (HostWatch*)arg;
    HANDLE waits[2] = { w->stop, w->host };
    const DWORD r = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    if (r == WAIT_OBJECT_0 + 1) {
        LogLine("host process is gone: asking the command loop to leave");
        // A plain store, not a CAS: the loop must see it whatever state the word
        // is in. A reply that is being published loses against it, which is the
        // point -- nobody reads that reply any more.
        InterlockedExchange((volatile LONG*)&w->io->ready, kStateExit);
    }
    return 0;
}

int v8i::V8iRunCommandLoop(SharedIo* io) {
    if (!io) return -1;
    g_io = io;

    HostWatch watch;
    watch.io = io;
    const DWORD hostPid = (DWORD)InterlockedCompareExchange((volatile LONG*)&io->hostPid, 0, 0);
    if (hostPid) {
        watch.host = OpenProcess(SYNCHRONIZE, FALSE, hostPid);
        if (!watch.host) {
            const DWORD err = GetLastError();
            if (err == ERROR_INVALID_PARAMETER) {
                // The host died before the payload got here: nothing will ever
                // be read from this block, so leave right away.
                LogLine("host pid %lu is already gone: leaving", hostPid);
                InterlockedExchange((volatile LONG*)&io->ready, kStateExit);
            } else {
                LogLine("cannot watch host pid %lu (win32=%lu): the payload will "
                        "not notice the host leaving", hostPid, err);
            }
        }
    }
    watch.stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE watcher = nullptr;
    if (watch.host && watch.stop)
        watcher = CreateThread(nullptr, 0, HostGoneThread, &watch, 0, nullptr);

    LogLine("waiting for commands, ready=%ld hostPid=%lu", (long)g_io->ready, hostPid);
    for (;;) {
        // The state word is read through an interlocked operation: it is the
        // acquire barrier that pairs with the host's release store of the
        // request, so the request text is visible once the state says
        // "request".
        LONG state = InterlockedCompareExchange((volatile LONG*)&g_io->ready, 0, 0);
        if (state == kStateExit) break;
        if (state != kStateRequest) {
            Sleep(15);
            continue;
        }
        // The reply of this request is published only while it is still the
        // current one: the host may have given up on it and posted another
        // request meanwhile (A45).
        g_curSeq = (LONG)InterlockedCompareExchange((volatile LONG*)&g_io->seq, 0, 0);
        LogLine("command received: %ls (ready=%ld seq=%ld)", g_io->request, (long)state,
                (long)g_curSeq);
        if (wcscmp(g_io->request, L"exit") == 0) break;

        if (wcscmp(g_io->request, L"version") == 0) {
            char buf[128] = {};
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "{\"status\":\"ok\",\"api\":%d,\"pointerSize\":%d}",
                        v8i_version(), (int)sizeof(void*));
            PutResponse(buf);
            continue;
        }

        if (wcsncmp(g_io->request, L"disasm", 6) == 0) {
            LogLine("disasm: decoding");
            PutResponse(Guarded(L"disasm", DisasmToJson, std::wstring(g_io->request).size() > 7
                                   ? std::wstring(g_io->request).substr(7)
                                   : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"imports", 7) == 0) {
            PutResponse(Guarded(L"imports", ImportsToJson, std::wstring(g_io->request).size() > 8
                                    ? std::wstring(g_io->request).substr(8)
                                    : std::wstring()));
            continue;
        }

        if (wcscmp(g_io->request, L"exports") == 0 ||
            wcsncmp(g_io->request, L"exports ", 8) == 0) {
            PutResponse(Guarded(L"exports", ExportsToJson,
                                std::wstring(g_io->request).size() > 8
                                    ? std::wstring(g_io->request).substr(8)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"mods", 4) == 0) {
            PutResponse(Guarded(L"mods", ModsToJson,
                                std::wstring(g_io->request).size() > 5
                                    ? std::wstring(g_io->request).substr(5)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"memmap", 6) == 0) {
            PutResponse(Guarded(L"memmap", MemMapToJson, std::wstring(g_io->request).size() > 7
                                                            ? std::wstring(g_io->request).substr(7)
                                                            : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"heapobjects", 10) == 0) {
            PutResponse(Guarded(L"heapobjects", HeapObjectsToJson,
                                std::wstring(g_io->request).size() > 11
                                    ? std::wstring(g_io->request).substr(11)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"findvalue", 9) == 0) {
            PutResponse(Guarded(L"findvalue", FindValueToJson,
                                std::wstring(g_io->request).size() > 10
                                    ? std::wstring(g_io->request).substr(10)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"byhwnd", 6) == 0) {
            PutResponse(Guarded(L"byhwnd", ByHwndToJson, std::wstring(g_io->request).size() > 7
                                                             ? std::wstring(g_io->request).substr(7)
                                                             : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"around", 6) == 0) {
            PutResponse(Guarded(L"around", AroundToJson, std::wstring(g_io->request).size() > 7
                                                              ? std::wstring(g_io->request).substr(7)
                                                              : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"xref", 4) == 0) {
            LogLine("xref: scanning code");
            PutResponse(Guarded(L"xref", XrefToJson, std::wstring(g_io->request).size() > 5
                                 ? std::wstring(g_io->request).substr(5)
                                 : std::wstring()));
            LogLine("xref: done");
            continue;
        }

        if (wcsncmp(g_io->request, L"find ", 5) == 0) {
            LogLine("find: starting scan");
            PutResponse(Guarded(L"find", FindToJson, std::wstring(g_io->request + 5)));
            LogLine("find: done");
            continue;
        }

        if (wcsncmp(g_io->request, L"peek ", 5) == 0) {
            PutResponse(Guarded(L"peek", PeekToJson, std::wstring(g_io->request + 5)));
            continue;
        }

        if (wcsncmp(g_io->request, L"pe", 2) == 0) {
            const wchar_t* arg = g_io->request + 2;
            while (*arg == L' ') ++arg;
            PutResponse(Guarded(L"pe", PeToJson, std::wstring(arg)));
            continue;
        }

        if (wcscmp(g_io->request, L"objects") == 0) {
            LogLine("objects: enumerating windows");
            PutResponse(Guarded(L"objects", ObjectsToJson, std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"cmd ", 4) == 0) {
            LogLine("cmd: invoking designer command");
            PutResponse(Guarded(L"cmd", CmdCommandToJson, std::wstring(g_io->request).substr(4)));
            LogLine("cmd: done");
            continue;
        }

        if (wcsncmp(g_io->request, L"cmd85", 5) == 0) {
            LogLine("cmd85: invoking 8.5 designer command");
            PutResponse(Guarded(L"cmd85", CmdCmd85ToJson, std::wstring(g_io->request).substr(5)));
            LogLine("cmd85: done");
            continue;
        }

        // ---- extension layer: hooks and call tracing ----
        if (wcscmp(g_io->request, L"hooks") == 0) {
            PutResponse(Guarded(L"hooks", HooksCommandToJson, std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"hook ", 5) == 0) {
            LogLine("hook: installing");
            PutResponse(Guarded(L"hook", HookCommandToJson, std::wstring(g_io->request + 5)));
            continue;
        }

        if (wcsncmp(g_io->request, L"unhook", 6) == 0) {
            LogLine("unhook: restoring");
            PutResponse(Guarded(L"unhook", UnhookCommandToJson,
                                std::wstring(g_io->request).size() > 7
                                    ? std::wstring(g_io->request).substr(7)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"trace", 5) == 0) {
            PutResponse(Guarded(L"trace", TraceCommandToJson,
                                std::wstring(g_io->request).size() > 6
                                    ? std::wstring(g_io->request).substr(6)
                                    : std::wstring()));
            continue;
        }

        if (wcscmp(g_io->request, L"cmdinfo") == 0) {
            PutResponse(Guarded(L"cmdinfo", CmdInfoToJson, std::wstring()));
            continue;
        }

        if (wcscmp(g_io->request, L"frames") == 0) {
            PutResponse(Guarded(L"frames", CmdFramesToJson, std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"exports85", 9) == 0) {
            std::wstring rest = g_io->request + 9;
            PutResponse(Guarded(L"exports85", CmdExports85ToJson, rest));
            continue;
        }

        if (wcsncmp(g_io->request, L"gitbar", 6) == 0) {
            PutResponse(Guarded(L"gitbar", GitBarCommandToJson,
                                std::wstring(g_io->request).size() > 7
                                    ? std::wstring(g_io->request).substr(7)
                                    : std::wstring()));
            continue;
        }

        if (wcscmp(g_io->request, L"menu") == 0 ||
            wcsncmp(g_io->request, L"menu ", 5) == 0) {
            PutResponse(Guarded(L"menu", MenuCommandToJson,
                                std::wstring(g_io->request).size() > 5
                                    ? std::wstring(g_io->request).substr(5)
                                    : std::wstring()));
            continue;
        }

        if (wcsncmp(g_io->request, L"str ", 4) == 0) {
            PutResponse(Guarded(L"str", StrToJson,
                                std::wstring(g_io->request).substr(4)));
            continue;
        }

        if (wcsncmp(g_io->request, L"menucmd", 7) == 0) {
            PutResponse(Guarded(L"menucmd", MenuCmdToJson,
                                std::wstring(g_io->request).size() > 8
                                    ? std::wstring(g_io->request).substr(8)
                                    : std::wstring()));
            continue;
        }

        TypeInfoReport rep;
        const ScanStatus st = RunScan(g_io->request, rep);
        if (st != ScanStatus::ok) {
            char buf[256] = {};
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "{\"status\":\"error\",\"command\":\"scan\",\"message\":\"%ls\"}",
                        ScanStatusText(st));
            PutResponse(buf);
            LogLine("scan rejected: %ls", ScanStatusText(st));
            continue;
        }
        PutResponse(ToJson(rep));
        LogLine("response sent, %zu bytes", rep.funcs.size());
    }

    // Stop the host watch before the caller unmaps the block: the watchdog
    // touches the state word, so it must be gone before the view is.
    if (watch.stop) SetEvent(watch.stop);
    if (watcher) {
        WaitForSingleObject(watcher, INFINITE);
        CloseHandle(watcher);
    }
    if (watch.stop) CloseHandle(watch.stop);
    if (watch.host) CloseHandle(watch.host);

    // Hooks must be gone before the DLL that owns their thunks is unloaded.
    {
        size_t removed = HookRemoveAll();
        if (removed) LogLine("payload exit: %zu hook(s) restored", removed);
    }

    InterlockedExchange((volatile LONG*)&g_io->ready, kStateExit);
    return 0;
}

// One command loop per process. Every attach injects the payload again, and a
// second loop would pick up the same request as the first one: two designer
// commands run in parallel (two dialogs, the second one crashes 8.5 after the
// first command's frames went away). Later probes answer the host handshake
// only; the flag is reset when the loop finishes so a new attach can restart
// it after an "exit".
static volatile LONG g_probeActive = 0;

// A skipping probe still has to report "loaded" to the host that started it,
// but must not touch g_io (the running loop owns it), so write the readiness
// reply through a private mapping of the same block.
static int ReportLoadedOnly(const wchar_t* sharedName) {
    HANDLE hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sharedName);
    if (!hMap) return kDiagNoBlock;
    SharedIo* io = (SharedIo*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0,
                                            sizeof(SharedIo));
    if (!io) { CloseHandle(hMap); return kDiagNoView; }
    PublishHandshakeReply(io, "{\"status\":\"loaded\"}");
    UnmapViewOfFile(io);
    CloseHandle(hMap);
    return 0;
}

// The host starts this on a remote thread. The shared-memory name is derived
// from our own PID, so nothing has to be marshalled across the process
// boundary: a bad pointer in a remote thread is the classic way to lose the
// argument, and we do not need one at all.
V8I_API int V8I_CALL v8i_probe(const wchar_t* /*ignored*/) {
    InitPayloadLog(nullptr);          // provisional, refined after mapping

    wchar_t name[64] = {};
    _snwprintf_s(name, _countof(name), _TRUNCATE, L"Local\\v8inject.%lu",
                 GetCurrentProcessId());

    if (InterlockedCompareExchange(&g_probeActive, 1, 0) != 0) {
        LogLine("v8i_probe: command loop already running, reporting loaded");
        int rc = ReportLoadedOnly(name);
        LogLine("v8i_probe leaving (secondary), rc=%d", rc);
        return rc;
    }

    LogLine("v8i_probe entered, pid=%lu block=%ls",
            GetCurrentProcessId(), name);

    // Arm the WH_CBT hook before the session: on 8.5 the splash screen is the
    // last moment when eventCreateFrame can still be caught (see plan_inj_ext
    // P0-2). The hook itself only records the window; the actual subscribe is
    // retried from a worker once the core is ready.
    V8iArmEarlySubscribe();

    int rc = RunPayload(name);
    LogLine("v8i_probe leaving, rc=%d", rc);
    InterlockedExchange(&g_probeActive, 0);
    return rc;
}

// ---------------------------------------------------------------------------
// GitBar "Выгрузить" button: run the designer's own dump-to-files command
// (cmd 45, preceded by cmd 2 when the configuration is not open yet). Runs on
// a worker thread because transmitCommand blocks while the modal dialog is up.
// ---------------------------------------------------------------------------
// cmd 45 is accepted (rc=1) even when the configuration is closed, so the
// return code cannot tell a shown dialog from an ignored command. Looking for
// the dialog after the call does not work either: on 8.5 the call returns only
// once the modal dialog is closed (so Cancel/OK would look like "no dialog"
// and re-trigger the dump). A watcher polls while the command runs instead —
// any new top-level platform window is the dialog, whatever its class is.
// 8.3 shows the dialog a little after the call returns, hence the grace period.
struct DumpWatch {
    HWND base[32] = {};
    int n = 0;
    HANDLE stop = nullptr;
    volatile LONG seen = 0;
    wchar_t title[256] = {};
    unsigned num = 45;        // 45 = main config, 205 = extension (contextual)
    volatile LONG wrong = 0;  // 205 opened the main-configuration dialog
};

static bool IsPlatformWindow(HWND h) {
    if (!IsWindowVisible(h)) return false;
    wchar_t cls[64] = {};
    if (!GetClassNameW(h, cls, 64)) return false;
    // 8.3 dialog frame, and 8.5's V8Window0.* windows — the designer frame is
    // already in the baseline, so only newly appeared ones count.
    return wcscmp(cls, L"V8NewLocalFrameBaseWnd") == 0 ||
           wcsncmp(cls, L"V8Window0.", 10) == 0;
}

static BOOL CALLBACK CollectPlatformWindows(HWND h, LPARAM lp) {
    DumpWatch* w = (DumpWatch*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid == GetCurrentProcessId() && w->n < 32 && IsPlatformWindow(h))
        w->base[w->n++] = h;
    return TRUE;
}

namespace v8i {
// Defined in gitbar.cpp: shows the bar's status tip from any thread.
void GitBarTipFromWorker(const wchar_t* text);
}

static BOOL CALLBACK FindNewPlatformWindow(HWND h, LPARAM lp) {
    DumpWatch* w = (DumpWatch*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != GetCurrentProcessId() || !IsPlatformWindow(h)) return TRUE;
    for (int i = 0; i < w->n; ++i) {
        if (w->base[i] == h) return TRUE;
    }
    // The title tells the two dump dialogs apart: «Выгрузить файлы
    // конфигурации - ...» (main) vs «... расширения конфигурации - ...».
    GetWindowTextW(h, w->title, _countof(w->title));
    if (w->num == 205 && wcscmp(w->title, L"") != 0 &&
        wcsstr(w->title, L"Выгрузить файлы") && !wcsstr(w->title, L"расширения")) {
        // Command 205 dumps whatever the ACTIVE window shows; the main dialog
        // means the extension window was not active — cancel it right away so
        // a mistaken click cannot dump the whole configuration into the
        // extension's repository. On 8.5 the platform processes the close only
        // when its dump command finally returns, so warn the user immediately
        // instead of waiting for the command channel to time out.
        InterlockedExchange(&w->wrong, 1);
        PostMessageW(h, WM_CLOSE, 0, 0);
        v8i::GitBarTipFromWorker(
            L"Выгрузка расширения отменена: активным было окно конфигурации. "
            L"Откройте «Расширения конфигурации», выберите расширение и повторите.");
    }
    // A dialog that opens behind the user's windows reads as "1C hung": the
    // frame it disabled stops taking input and nothing on screen responds.
    // Pull the dialog forward so the click visibly does something.
    SetForegroundWindow(h);
    BringWindowToTop(h);

    InterlockedExchange(&w->seen, 1);
    return FALSE;
}

static DWORD WINAPI DumpWatchThread(LPVOID lp) {
    DumpWatch* w = (DumpWatch*)lp;
    while (WaitForSingleObject(w->stop, 25) == WAIT_TIMEOUT) {
        EnumWindows(FindNewPlatformWindow, (LPARAM)w);
        if (w->seen) break;
    }
    return 0;
}

// Shared dump-to-files flow: the platform shows a modal dialog with XML/archive
// options and the target directory; GitBar only triggers it (the user confirms).
// "UI thread did not answer" already means the modal dialog held the UI thread
// for the whole timeout — a success, and nothing to retry.
static DWORD GitBarDumpVia(unsigned num) {
    DumpWatch w;
    w.num = num;
    EnumWindows(CollectPlatformWindows, (LPARAM)&w);
    w.stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE watch = w.stop ? CreateThread(nullptr, 0, DumpWatchThread, &w, 0, nullptr) : nullptr;

    wchar_t cmd[16];
    swprintf_s(cmd, L"%u 0", num);
    std::string r = CmdCommandToJson(cmd);
    LogLine("gitbar: cmd %u -> %s", num, r.c_str());

    // The marshal can answer and still fail: the platform faults inside the
    // command (8.3.27.2342: transmit exception 0x C0000005 on cmd 45). Then no
    // dialog will ever appear, and the "configuration is closed" fallback below
    // would send a second command into a platform that is already stuck
    // mid-modal — report the failure and leave the platform alone.
    const bool timedOut = r.find("did not answer") != std::string::npos;
    // "did not answer" arrives with an "error" field too, but it is the success
    // case on 8.3: the command blocks the UI thread for as long as its modal
    // dialog is open, so only a fault/marshal error while the thread answered
    // counts as a failed dump.
    const bool replyError = !timedOut && r.find("\"error\":") != std::string::npos;
    if (!timedOut && !replyError) {
        for (int i = 0; i < 50 && !w.seen; ++i) Sleep(30);
    }
    if (watch) {
        // The watcher only waits on this event, so the join is immediate; an
        // unbounded wait keeps it from outliving the stack block below.
        SetEvent(w.stop);
        WaitForSingleObject(watch, INFINITE);
        CloseHandle(watch);
    }
    if (w.stop) CloseHandle(w.stop);
    LogLine("gitbar: cmd %u dialog seen=%d timedOut=%d", num, (int)w.seen, timedOut ? 1 : 0);
    if (w.seen) {
        char title[512] = {};
        WideCharToMultiByte(CP_UTF8, 0, w.title, -1, title, sizeof(title), nullptr, nullptr);
        LogLine("gitbar: cmd %u dialog title \"%s\"", num, title);
        if (w.wrong) {
            LogLine("gitbar: 205 opened the MAIN configuration dialog: the "
                    "«Расширения конфигурации» window was not active (dialog closed)");
        }
    }

    if (replyError) {
        // Show why the button did nothing: "transmit exception 0x..." today,
        // the marshal's own text whenever a different step fails.
        std::string msg = "команда отклонена";
        const size_t p = r.find("\"error\":\"");
        if (p != std::string::npos) {
            const size_t e = r.find('"', p + 9);
            if (e != std::string::npos && e > p + 9) msg = r.substr(p + 9, e - p - 9);
        }
        LogLine("gitbar: cmd %u failed: %s", num, msg.c_str());
        std::wstring tip = L"Выгрузка не удалась: ";
        tip.append(msg.begin(), msg.end());
        tip += L". Платформа не приняла команду — выгрузите через меню "
               L"«Конфигурация → Выгрузить конфигурацию в файлы».";
        v8i::GitBarTipFromWorker(tip.c_str());
        return 0;
    }

    if (num == 45 && !timedOut && !w.seen) {
        // No dialog ever showed up: the configuration is closed, so open it
        // first and dump again. (205 needs an active extensions window; opening
        // the main configuration would move the context away from it.)
        std::string r2 = CmdCommandToJson(L"2 0");
        LogLine("gitbar: cmd 2 -> %s", r2.c_str());
        Sleep(800);
        std::string r3 = CmdCommandToJson(L"45 0");
        LogLine("gitbar: cmd 45 (after open) -> %s", r3.c_str());
    }
    return 0;
}

static DWORD WINAPI V8iGitBarDumpThread(LPVOID) { return GitBarDumpVia(45); }
static DWORD WINAPI V8iGitBarDumpExtThread(LPVOID) { return GitBarDumpVia(205); }

extern "C" __declspec(dllexport) void V8iGitBarDump() {
    HANDLE h = CreateThread(nullptr, 0, V8iGitBarDumpThread, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
}

// Extension dump: the same dialog flow, but 1C resolves the dump target from
// the ACTIVE window — command 205 while «Расширения конфигурации» is focused
// dumps the selected extension, while any other active window makes it dump
// the main configuration. GitBar therefore only sends the command; the user
// opens/selects the extension first.
extern "C" __declspec(dllexport) void V8iGitBarDumpExtension() {
    HANDLE h = CreateThread(nullptr, 0, V8iGitBarDumpExtThread, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
}
