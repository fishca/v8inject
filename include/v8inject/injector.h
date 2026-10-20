#pragma once
#include <windows.h>
#include <string>

namespace v8i {

DWORD FindProcessByName(const wchar_t* exeName);
bool  IsProcess64(DWORD pid);
bool  InjectLibrary(DWORD pid, const std::wstring& dllPath);

// Injects `payloadDll` into `pid` via remote LoadLibraryW, then spawns a
// remote thread that calls `v8i_probe(sharedName)` and blocks until the
// payload returns. Ownership of the opened process/thread handles and of the
// remote allocations passes to the caller (needed to keep the thread alive).
bool StartPayloadThread(DWORD pid,
                        const std::wstring& payloadDll,
                        const wchar_t* sharedName,
                        HANDLE& hProcessOut,
                        HANDLE& hThreadOut,
                        void*& remoteNameOut,
                        void*& remoteArgsOut);

}  // namespace v8i
