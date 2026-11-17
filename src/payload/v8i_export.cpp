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

#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

using namespace v8i;
using namespace v8i::commands;
using namespace v8i::platform;

namespace {

SharedIo* g_io = nullptr;

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

void PutResponse(const std::string& json) {
    if (!g_io) return;
    size_t n = json.size();
    if (n > kResponseBytes - 1) n = kResponseBytes - 1;
    memcpy(g_io->response, json.data(), n);
    g_io->response[n] = 0;
    InterlockedExchange((volatile LONG*)&g_io->responseLen, (LONG)n);
    InterlockedExchange((volatile LONG*)&g_io->ready, kStateResponse);
}

// SEH helper: __try cannot live in a function that needs C++ unwinding,
// so the guarded call is isolated in a POD-only function.
HRESULT ScanGuarded(ITypeInfo* ti, TypeInfoReport* rep) {
    HRESULT hr = E_UNEXPECTED;
    __try {
        hr = ScanTypeInfo(ti, *rep);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hr = E_UNEXPECTED;
    }
    return hr;
}

// "scan <moduleName> <addrHex>"
bool RunScan(const wchar_t* cmd, TypeInfoReport& rep) {
    wchar_t moduleName[64] = {};
    unsigned long long addr = 0;
    int matched = swscanf_s(cmd, L"scan %63s %llx", moduleName,
                            (unsigned)_countof(moduleName), &addr);
    if (matched != 2) return false;

    ModuleRange mr;
    if (!FindModule(moduleName, mr)) return false;

    rep.moduleName = moduleName;
    rep.moduleBase = mr.base;

    void* p = (void*)(uintptr_t)addr;
    if (!IsReadable(p, sizeof(void*))) return false;

    IUnknown* unk = (IUnknown*)p;
    ITypeInfo* ti = nullptr;
    if (FAILED(GetTypeInfoFromUnknown(unk, &ti)) || !ti) return false;

    HRESULT hr = ScanGuarded(ti, &rep);
    ti->Release();
    return SUCCEEDED(hr);
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

int PackedThunk(const wchar_t* text, char* out, size_t outCap, size_t* outLen) {
    if (!g_thunk.fn) return 0;
    std::string tmp = g_thunk.fn(std::wstring(text ? text : L""));
    size_t n = tmp.size();
    if (n > outCap - 1) n = outCap - 1;
    memcpy(out, tmp.data(), n);
    out[n] = 0;
    *outLen = n;
    return 1;
}

}  // namespace

static std::string Guarded(const wchar_t* what, CommandFn fn, const std::wstring& args) {
    wchar_t safe[1024] = {};
    wcsncpy_s(safe, _countof(safe), args.c_str(), _TRUNCATE);

    static std::vector<char> buffer(512 * 1024);
    buffer.resize(512 * 1024);

    g_thunk.fn = fn;
    size_t len = 0;
    unsigned code = 0;
    uintptr_t faultAt = 0;
    if (GuardCall(PackedThunk, safe, buffer.data(), buffer.size(), &len, &code, &faultAt))
        return std::string(buffer.data(), len);

    char buf[320];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "{\"status\":\"error\",\"message\":\"command crashed\","
                "\"command\":\"%ls\",\"exception\":\"0x%08X\",\"at\":\"0x%llX\"}",
                what ? what : L"?", code, (unsigned long long)faultAt);
    LogLine("command raised 0x%08X at 0x%llX", code, (unsigned long long)faultAt);
    return buf;
}

}  // namespace

V8I_API int V8I_CALL v8i_version() {
    return 1;
}

static int RunPayload(const wchar_t* sharedName) {
    if (!sharedName) return -1;

    HANDLE hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sharedName);
    if (!hMap) {
        InitPayloadLog(nullptr);
        LogLine("OpenFileMapping(%ls) failed, win32=%lu", sharedName, GetLastError());
        return -2;
    }

    g_io = (SharedIo*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
    if (!g_io) { CloseHandle(hMap); return -3; }

    InitPayloadLog(g_io->logDir);
    HookInstallFaultLogger();
    LogLine("RunPayload started, pid=%lu arch=%s", GetCurrentProcessId(),
            sizeof(void*) == 8 ? "x64" : "x86");
    LogLine("MapViewOfFile -> %p", (void*)g_io);

    // Native «GitBar» item in the Configurator menu (8.3.27/8.5 layout, see
    // src/payload/mainmenu.cpp). Outside 1C (the tests) this is a no-op.
    if (V8iIsTargetProcess()) v8i::V8iStartNativeMenu();

    // Report readiness before anything that can fail.
    PutResponse("{\"status\":\"loaded\"}");

    const int rc = V8iRunCommandLoop(g_io);
    UnmapViewOfFile(g_io);
    g_io = nullptr;
    CloseHandle(hMap);
    return rc;
}

int v8i::V8iRunCommandLoop(SharedIo* io) {
    if (!io) return -1;
    g_io = io;

    LogLine("waiting for commands, ready=%ld", (long)g_io->ready);
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
        LogLine("command received: %ls (ready=%ld)", g_io->request, (long)state);
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
        if (!RunScan(g_io->request, rep)) {
            PutResponse("{\"status\":\"error\",\"message\":\"scan failed\"}");
            continue;
        }
        PutResponse(ToJson(rep));
        LogLine("response sent, %zu bytes", rep.funcs.size());
    }

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
    if (!hMap) return -2;
    SharedIo* io = (SharedIo*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0,
                                            sizeof(SharedIo));
    if (!io) { CloseHandle(hMap); return -3; }
    static const char kLoaded[] = "{\"status\":\"loaded\"}";
    const size_t n = sizeof(kLoaded) - 1;
    memcpy(io->response, kLoaded, n);
    io->response[n] = 0;
    InterlockedExchange((volatile LONG*)&io->responseLen, (LONG)n);
    InterlockedExchange((volatile LONG*)&io->ready, kStateResponse);
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

    bool timedOut = r.find("did not answer") != std::string::npos;
    if (!timedOut) {
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
