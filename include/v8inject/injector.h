#pragma once
#include <windows.h>
#include <string>

namespace v8i {

DWORD FindProcessByName(const wchar_t* exeName);

// Base address of a DLL loaded in another process (nullptr when absent).
HMODULE FindModuleInProcess(HANDLE hProc, const std::wstring& dllPath);
bool  IsProcess64(DWORD pid);
bool  InjectLibrary(DWORD pid, const std::wstring& dllPath);

// Stage codes returned through `stageOut` so the CLI can explain failures.
enum StartStage : int {
    kStageOk              = 0,
    kStageOpenProcess     = 1,
    kStageLoadLibrary     = 2,   // remote LoadLibraryW failed
    kStageLocalLoad       = 3,   // LoadLibrary of our own copy failed
    kStageGetProcAddress  = 4,   // payload has no v8i_probe export
    kStageCreateThread    = 7,
    kStageResolveKernel32 = 8,   // kernel32 not found in the target, or
                                 // LoadLibraryW could not be rebased
};

// The verdict on a remote LoadLibraryW attempt. Made by a pure function so
// the unit tests pin the decision table down (tests/unit_injector.cpp).
struct RemoteLoadDecision {
    bool        ok;         // count the injection as successful
    bool        freeBuffer; // the remote path buffer may be released
    const char* reason;     // stable text, for the log
};

// `wait` is what WaitForSingleObject returned for the remote thread,
// `exitCode` its exit code (meaningful only after WAIT_OBJECT_0),
// `modulePresent` says whether the DLL appeared in the target despite the
// timeout. The rule for everything except WAIT_OBJECT_0: the buffer stays
// allocated. A remote thread that never reported in may still be reading the
// path string, and freeing it under such a thread is a use-after-free in the
// target process -- a few hundred leaked bytes are the cheap side of that
// trade.
RemoteLoadDecision EvaluateRemoteLoad(DWORD wait, DWORD exitCode, bool modulePresent);

// Injects `payloadDll` into `pid` via remote LoadLibraryW, then starts a remote
// thread calling `v8i_probe(sharedName)`. It does NOT wait for the payload:
// the probe takes over the calling thread (the remote thread) and blocks there.
// On success the caller owns hProcess/hThread; the payload derives the block
// name from its own pid, so there are no remote allocations to track.
bool StartPayloadThread(DWORD pid,
                        const std::wstring& payloadDll,
                        const wchar_t* sharedName,
                        HANDLE& hProcessOut,
                        HANDLE& hThreadOut,
                        int& stageOut,
                        DWORD& win32ErrorOut);

}  // namespace v8i
