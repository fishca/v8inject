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
    // logDir is written into the shared block before the payload starts, so the
    // payload can log next to the host binary instead of %TEMP%.
    bool Open(uint32_t pid, const std::wstring& payloadDll,
              const std::wstring& logDir, int timeoutMs = 15000);

    // Creates the shared block alone, without touching the target process:
    // whoever answers the block may be anywhere. The tests use it with their
    // own fake payload; the production path is Open() = OpenBlock() plus the
    // injection and the handshake.
    //
    // A block that already exists is only reused when the host that created it
    // is gone (a crashed host leaves its payload behind, and that payload is
    // on its way out once it notices -- A45). A live host is refused.
    bool OpenBlock(uint32_t pid, const std::wstring& logDir);

    // Sends one command and returns the raw JSON reply.
    //
    // A command that runs past timeoutMs gets a grace period of the same length
    // (capped) before it is declared lost: the heavy scans finish a little late
    // more often than they never finish, and a late answer is still the right
    // one. A command that is really lost does not kill the session: the state
    // word is taken back, the payload drops its late reply, and the next Call
    // works normally (A45).
    bool Call(const std::wstring& command, std::string& response, int timeoutMs = 15000);

    // Asks the payload to unload and waits for it.
    //
    // Returns true only when the payload confirmed it left (the injected thread
    // ended). A payload that is still inside a long command is told to leave and
    // will do so once the command returns; the call reports that as a failure
    // with LastError() explaining it, instead of freeing the handles silently
    // (A45).
    bool Close(int timeoutMs = 5000);

    bool IsOpen() const { return hMap_ != nullptr; }
    LONG LastDiag() const { return lastDiag_; }
    int  LastStage() const { return lastStage_; }
    DWORD LastWin32Error() const { return lastWin32_; }
    // Last refusal text: a failed Open/OpenBlock, a refused or timed-out Call,
    // a Close that could not confirm the payload left. Empty after a success.
    const wchar_t* LastError() const { return lastError_; }
    const wchar_t* SharedName() const { return sharedName_; }

private:
    // Outcome of waiting for the payload's reply.
    enum class Await {
        arrived,   // the reply of this request is in the block
        timeout,   // nothing arrived within the budget
        lost,      // the payload left (exit state) and will not answer
        foreign,   // somebody else's reply: wrong sequence number
    };

    Await AwaitResponse(int timeoutMs, LONG expectedSeq);
    void  TakeResponse(std::string& response);
    bool  WaitForState(LONG expected, int timeoutMs);
    bool  WaitThreadExit(int timeoutMs);
    void  ReleaseHandles();
    void  SetErrorText(const wchar_t* fmt, ...);

    HANDLE        hMap_ = nullptr;
    SharedIo*     io_   = nullptr;
    HANDLE        hThread_ = nullptr;
    HANDLE        hProc_ = nullptr;
    LONG          seq_ = 0;
    LONG          lastDiag_ = 0;
    int           lastStage_ = 0;
    DWORD         lastWin32_ = 0;
    wchar_t       lastError_[256] = {};
    wchar_t       sharedName_[64] = {};
};

// Checks the protocol handshake of a block the payload answered: returns an
// empty string when the payload speaks this build's protocol, or the text to
// show the user when the target still runs a payload of another build (A96).
// The payload stamps its version only after accepting the block, so a payload
// that predates the check answers the handshake and leaves the stamp at 0.
std::wstring CheckProtocolHandshake(const SharedIo* io);

}  // namespace v8i
