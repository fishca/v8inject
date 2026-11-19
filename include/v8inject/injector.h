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
    kStageGetProcAddress  = 4,   // our copy has no usable v8i_probe export
    kStageCreateThread    = 7,
    kStageResolveKernel32 = 8,   // kernel32 not found in the target, or
                                 // LoadLibraryW could not be rebased
    kStageTargetImage     = 9,   // the payload image resident in the target
                                 // could not be read or parsed
    kStagePayloadMismatch = 10,  // the target runs a payload of another build
};

// A reader over one mapped PE image: fills `dst` with `bytes` read at image
// offset `rva`. The target's image is read with ReadProcessMemory, the host's
// own copy straight from memory; the walker below is the same code for both.
struct ImageReadFn {
    bool (*read)(void* ctx, uint32_t rva, void* dst, size_t bytes) = nullptr;
    void* ctx = nullptr;
};

// What the host needs to know about a mapped payload image: its build identity
// and the RVA of the v8i_probe export in it.
struct PayloadImage {
    bool        ok = false;
    uint32_t    timeDateStamp = 0;   // PE stamp: identifies the build
    uint32_t    sizeOfImage = 0;
    uint32_t    probeRva = 0;        // RVA of v8i_probe in THIS image
    const char* error = "";          // stable text when !ok
};

// Walks the export table of a mapped image and finds v8i_probe in it.
//
// The address must be taken from the image the target actually has, not from
// the host's copy of the file (A42): when the target already holds an older
// build, LoadLibraryW returns that resident module and the RVAs of the two
// builds differ -- rebasing the local export by the module delta then starts
// the payload thread on foreign code (live 2026-11-15: that killed the target).
//
// Every offset is bounded by the image's own SizeOfImage, so a corrupt header
// cannot turn the walk into a read of unrelated process memory; reads outside
// the image are refused by the reader itself.
PayloadImage FindProbeExport(const ImageReadFn& image);

// True when the image the target holds is the same build as the file on disk.
// Two builds can differ in their export RVAs while still being told apart by
// the stamp alone, so the stamp and the size are compared; a mismatch means the
// target keeps an old payload loaded and can only be helped by a restart.
bool PayloadBuildMatches(const PayloadImage& target, const PayloadImage& file);

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
//
// `detailOut`, when given, receives the user-facing explanation of a refusal
// that is not a plain Win32 error (a stale payload image in the target, an
// image without the export); `win32ErrorOut` stays 0 in that case.
bool StartPayloadThread(DWORD pid,
                        const std::wstring& payloadDll,
                        const wchar_t* sharedName,
                        HANDLE& hProcessOut,
                        HANDLE& hThreadOut,
                        int& stageOut,
                        DWORD& win32ErrorOut,
                        std::wstring* detailOut = nullptr);

}  // namespace v8i
