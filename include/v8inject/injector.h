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
    kStageAllocName       = 5,
    kStageAllocArgs       = 6,
    kStageCreateThread    = 7,
};

// Injects `payloadDll` into `pid` via remote LoadLibraryW, then starts a remote
// thread calling `v8i_probe(sharedName)`. It does NOT wait for the payload:
// the probe takes over the calling thread (the remote thread) and blocks there.
// On success the caller owns hProcess/hThread and must not free the remote
// allocations until the thread has finished.
bool StartPayloadThread(DWORD pid,
                        const std::wstring& payloadDll,
                        const wchar_t* sharedName,
                        HANDLE& hProcessOut,
                        HANDLE& hThreadOut,
                        void*& remoteNameOut,
                        void*& remoteArgsOut,
                        int& stageOut,
                        DWORD& win32ErrorOut);

}  // namespace v8i
