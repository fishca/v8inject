#pragma once
#include "v8inject/protocol.h"
#include <string>

namespace v8i {

// Host-side handle for a session with an injected payload.
class Client {
public:
    Client() = default;
    ~Client();

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // Creates the shared block and starts the payload thread in the target
    // process. Path to the payload DLL must match the target bitness.
    bool Open(uint32_t pid, const std::wstring& payloadDll, int timeoutMs = 15000);

    // Sends one command and returns the raw JSON reply.
    // Returns false on timeout or protocol error.
    bool Call(const std::wstring& command, std::string& response, int timeoutMs = 15000);

    // Asks the payload to unload and waits for it.
    void Close(int timeoutMs = 5000);

    bool IsOpen() const { return hMap_ != nullptr; }
    LONG LastDiag() const { return lastDiag_; }
    // Last handshake failure text, empty when Open succeeded.
    const wchar_t* LastError() const { return lastError_; }
    const wchar_t* SharedName() const { return sharedName_; }

private:
    bool WaitForState(LONG expected, int timeoutMs);
    void ReleaseHandles();

    HANDLE        hMap_ = nullptr;
    SharedIo*     io_   = nullptr;
    HANDLE        hThread_ = nullptr;
    void*         remoteName_ = nullptr;
    void*         remoteArgs_ = nullptr;
    HANDLE        hProc_ = nullptr;
    LONG          seq_ = 0;
    LONG          lastDiag_ = 0;
    wchar_t       lastError_[256] = {};
    wchar_t       sharedName_[64] = {};
};

}  // namespace v8i
