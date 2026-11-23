#include "v8inject/client.h"
#include "v8inject/diag.h"
#include "v8inject/injector.h"

#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <sddl.h>
#include <thread>
#include <vector>

namespace v8i {

namespace {

using Clock = std::chrono::steady_clock;

// A block that already exists is reused only after the host that created it is
// gone; the payload of that host notices and leaves, which takes a few
// milliseconds, so the host retries for a bounded time instead of failing on a
// race with a dying payload (A45).
constexpr DWORD kStaleBlockWaitMs = 3000;
constexpr DWORD kStaleBlockPollMs = 25;

// Extra time a command gets after the caller's timeout before the session is
// declared lost: the scans over the whole address space finish a little late
// more often than they never finish, and a late answer is still the right one.
constexpr int kCallGraceMs = 5000;

int GraceMs(int timeoutMs) {
    if (timeoutMs <= 0) return 0;
    return (std::min)(timeoutMs, kCallGraceMs);
}

std::wstring DirectoryOf(const std::wstring& path) {
    size_t pos = path.find_last_of(L'\\');
    return pos == std::wstring::npos ? std::wstring() : path.substr(0, pos + 1);
}

std::wstring FileNameOf(const std::wstring& path) {
    size_t pos = path.find_last_of(L'\\');
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

// Security descriptor for the shared block: full access for the user who
// created it and for SYSTEM, nobody else. The block's name is predictable
// (Local\v8inject.<pid>), so without a DACL another process of the session
// could open it, pose as the payload and answer the host.
//
// Fail closed: when the descriptor cannot be built, the block is not created
// at all. A default-DACL block would be a silent downgrade of the protection
// the protocol relies on -- refusing is the honest answer (see plan_roadmap
// Ф1.3).
bool MakeBlockSecurityDescriptor(PSECURITY_DESCRIPTOR* out) {
    *out = nullptr;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buf(size);
    bool ok = false;
    if (size && GetTokenInformation(token, TokenUser, buf.data(), size, &size)) {
        TOKEN_USER* tu = (TOKEN_USER*)buf.data();
        wchar_t* sidText = nullptr;
        if (ConvertSidToStringSidW(tu->User.Sid, &sidText)) {
            std::wstring sddl = L"D:P(A;;GA;;;" + std::wstring(sidText) + L")(A;;GA;;;SY)";
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
                *out = sd;
                ok = true;
            }
            LocalFree(sidText);
        }
    }
    CloseHandle(token);
    return ok;
}

// The state word is the handshake between the two processes: reading it
// through an interlocked operation gives the acquire barrier that pairs with
// the release barrier of the write (the response text must be visible before
// the state says it is there).
LONG ReadState(volatile LONG* p) {
    return InterlockedCompareExchange(p, 0, 0);
}

// What a block that is already there belongs to.
enum class StaleBlock {
    vanished,        // the block is gone: the next create attempt can succeed
    hostGone,        // its host died; the payload leaves and the block goes too
    hostAlive,       // another live host is talking to that process
    foreignProtocol, // the block belongs to another build of the protocol
    unreadable,      // the block exists but cannot be inspected
};

// Looks at an existing block (A45/A96) without touching the payload: the host
// has to tell "another live host" from "a host that crashed and left its
// payload behind". Only the block of *this* protocol version is trusted; a
// block of another build has no readable host pid, so it is reported as is.
StaleBlock ProbeExistingBlock(const wchar_t* name, DWORD* hostPidOut, LONG* protocolOut) {
    *hostPidOut = 0;
    *protocolOut = 0;

    HANDLE h = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
    if (!h) {
        const DWORD err = GetLastError();
        return err == ERROR_FILE_NOT_FOUND ? StaleBlock::vanished : StaleBlock::unreadable;
    }
    const SharedIo* io = (const SharedIo*)MapViewOfFile(h, FILE_MAP_READ, 0, 0, sizeof(SharedIo));
    if (!io) {
        // A block smaller than this build's block: the appended fields are not
        // there at all, which is exactly what an older protocol looks like.
        const DWORD err = GetLastError();
        CloseHandle(h);
        return err == ERROR_BAD_LENGTH ? StaleBlock::foreignProtocol : StaleBlock::unreadable;
    }

    StaleBlock kind = StaleBlock::foreignProtocol;
    const LONG abi = io->abiVersion;
    const LONG size = io->structSize;
    *protocolOut = abi;
    if (abi == kProtocolAbi && size == (LONG)sizeof(SharedIo)) {
        const DWORD hostPid = (DWORD)io->hostPid;
        *hostPidOut = hostPid;
        if (!hostPid) {
            kind = StaleBlock::foreignProtocol;
        } else {
            // The host is the process that created the block: it is alive until
            // its process object is signaled. Access denied means "cannot tell",
            // and guessing "gone" would kick a live host out of its session.
            HANDLE hp = OpenProcess(SYNCHRONIZE, FALSE, hostPid);
            if (!hp) {
                kind = GetLastError() == ERROR_INVALID_PARAMETER ? StaleBlock::hostGone
                                                                 : StaleBlock::hostAlive;
            } else {
                kind = WaitForSingleObject(hp, 0) == WAIT_OBJECT_0 ? StaleBlock::hostGone
                                                                  : StaleBlock::hostAlive;
                CloseHandle(hp);
            }
        }
    }

    UnmapViewOfFile((LPVOID)io);
    CloseHandle(h);
    return kind;
}

}  // namespace

Client::~Client() {
    Close(1000);
}

void Client::SetErrorText(const wchar_t* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(lastError_, _countof(lastError_), _TRUNCATE, fmt, ap);
    va_end(ap);
}

void Client::ReleaseHandles() {
    if (io_)          { UnmapViewOfFile(io_); io_ = nullptr; }
    if (hMap_)        { CloseHandle(hMap_);   hMap_ = nullptr; }
    if (hThread_)     { CloseHandle(hThread_); hThread_ = nullptr; }
    if (hProc_) {
        CloseHandle(hProc_);
        hProc_ = nullptr;
    }
}

bool Client::WaitForState(LONG expected, int timeoutMs) {
    if (!io_) return false;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    for (;;) {
        if (ReadState(&io_->ready) == expected) return true;
        if (Clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool Client::WaitThreadExit(int timeoutMs) {
    if (!hThread_) return true;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    for (;;) {
        DWORD code = 0;
        if (GetExitCodeThread(hThread_, &code) && code != STILL_ACTIVE) return true;
        if (Clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool Client::OpenBlock(uint32_t pid, const std::wstring& logDir) {
    lastError_[0] = 0;
    if (hMap_) {
        SetErrorText(L"the session is already open (%ls)", sharedName_);
        return false;
    }

    MakeSharedName(sharedName_, _countof(sharedName_), pid);
    LogLine("Client::OpenBlock pid=%u name=%ls logDir=%ls", pid, sharedName_, logDir.c_str());

    // The block is sizeof(SharedIo) (533040 bytes, see protocol.h); only
    // touched pages become resident.
    // No fallback to a default DACL: without the expected rights the block is
    // not created (fail closed) -- a stranger answering it would be worse than
    // a refused session.
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!MakeBlockSecurityDescriptor(&sd)) {
        SetErrorText(L"failed to build the security descriptor of the shared "
                     L"block; refusing to create it with default rights");
        LogLine("Client::OpenBlock: security descriptor failed");
        return false;
    }
    SECURITY_ATTRIBUTES sa{ sizeof(sa), sd, FALSE };

    const DWORD deadline = GetTickCount() + kStaleBlockWaitMs;
    for (;;) {
        SetLastError(ERROR_SUCCESS);
        hMap_ = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE,
                                   0, (DWORD)sizeof(SharedIo), sharedName_);
        if (!hMap_) {
            const DWORD err = GetLastError();
            SetErrorText(L"cannot create the shared block %ls of %llu bytes "
                         L"(win32=%lu)", sharedName_,
                         (unsigned long long)sizeof(SharedIo), err);
            LogLine("Client::OpenBlock: CreateFileMapping failed, win32=%lu", err);
            LocalFree(sd);
            return false;
        }
        if (GetLastError() != ERROR_ALREADY_EXISTS) break;
        CloseHandle(hMap_);
        hMap_ = nullptr;

        // Somebody got there first. A block left behind by a host that crashed
        // is not a reason to refuse: its payload is on its way out and the
        // block disappears in a moment (A45). A live host is a different story
        // -- two hosts would fight over one payload.
        DWORD hostPid = 0;
        LONG protocol = 0;
        const StaleBlock stale = ProbeExistingBlock(sharedName_, &hostPid, &protocol);
        if (stale == StaleBlock::foreignProtocol) {
            SetErrorText(L"the shared block %ls already exists and carries protocol "
                         L"%ld (this build speaks %ld): the target or another host "
                         L"still has a payload of another build -- restart the target "
                         L"application", sharedName_, protocol, kProtocolAbi);
            LogLine("Client::OpenBlock: %ls is held by protocol %ld", sharedName_, protocol);
            LocalFree(sd);
            return false;
        }
        if (stale == StaleBlock::hostAlive) {
            if (hostPid == GetCurrentProcessId()) {
                SetErrorText(L"the shared block %ls is still held by a payload of a "
                             L"previous session of this process (pid %lu); it leaves "
                             L"when that session is closed or when this process "
                             L"exits -- restart the target application to get a "
                             L"fresh payload", sharedName_, hostPid);
            } else {
                SetErrorText(L"the shared block %ls already exists: host pid %lu is "
                             L"connected to this process (another v8inject is "
                             L"attached?)", sharedName_, hostPid);
            }
            LogLine("Client::OpenBlock: %ls held by live host pid=%lu", sharedName_, hostPid);
            LocalFree(sd);
            return false;
        }
        if (stale == StaleBlock::unreadable) {
            SetErrorText(L"the shared block %ls already exists and cannot be "
                         L"inspected; another process of this user holds it",
                         sharedName_);
            LocalFree(sd);
            return false;
        }
        if (GetTickCount() > deadline) {
            SetErrorText(L"the shared block %ls is still there after %lu ms: the "
                         L"payload of the crashed host pid %lu has not left yet "
                         L"(restart the target application if this repeats)",
                         sharedName_, kStaleBlockWaitMs, hostPid);
            LocalFree(sd);
            return false;
        }
        LogLine("Client::OpenBlock: %ls left behind by pid=%lu, retrying", sharedName_, hostPid);
        std::this_thread::sleep_for(std::chrono::milliseconds(kStaleBlockPollMs));
    }
    LocalFree(sd);

    io_ = (SharedIo*)MapViewOfFile(hMap_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
    if (!io_) {
        const DWORD err = GetLastError();
        SetErrorText(L"cannot map the shared block %ls (win32=%lu)", sharedName_, err);
        LogLine("Client::OpenBlock: MapViewOfFile failed, win32=%lu", err);
        ReleaseHandles();
        return false;
    }
    LogLine("Client: shared block mapped at %p (size=%llu)",
            (void*)io_, (unsigned long long)sizeof(SharedIo));

    InterlockedExchange((volatile LONG*)&io_->ready, kStateIdle);
    io_->requestLen = 0;
    io_->responseLen = 0;
    io_->seq = 0;
    io_->diag = 0;
    io_->abiVersion = kProtocolAbi;
    io_->structSize = (LONG)sizeof(SharedIo);
    io_->hostPid = (LONG)GetCurrentProcessId();
    io_->payloadAbi = 0;
    io_->respSeq = 0;
    wcsncpy_s(io_->logDir, MAX_PATH, logDir.c_str(), _TRUNCATE);
    io_->request[0] = 0;
    io_->response[0] = 0;
    return true;
}

std::wstring CheckProtocolHandshake(const SharedIo* io) {
    if (!io) return L"no shared block";
    wchar_t msg[256] = {};
    if (io->abiVersion != kProtocolAbi || io->structSize != (LONG)sizeof(SharedIo)) {
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                     L"the shared block was created for protocol %ld/%ld but this "
                     L"build speaks %ld/%d; it does not belong to this host",
                     (long)io->abiVersion, (long)io->structSize, kProtocolAbi,
                     (int)sizeof(SharedIo));
        return msg;
    }
    // The acquire barrier was the read of the state word that announced the
    // reply, so a plain read of the stamp is enough.
    const LONG payloadAbi = io->payloadAbi;
    if (payloadAbi != kProtocolAbi) {
        // An older payload never writes the stamp, so 0 means "another build"
        // rather than "did not start": the handshake reply is what proves the
        // payload is alive (A96).
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                     L"the payload answered the handshake with protocol %ld, this "
                     L"build speaks %ld: the target still runs a payload from "
                     L"another build -- restart the target application (a loaded "
                     L"DLL cannot be replaced in place)",
                     (long)payloadAbi, kProtocolAbi);
        return msg;
    }
    return std::wstring();
}

bool Client::Open(uint32_t pid, const std::wstring& payloadDll,
                  const std::wstring& logDir, int timeoutMs) {
    lastError_[0] = 0;
    if (!OpenBlock(pid, logDir)) return false;

    // Copy the payload into the target and start v8i_probe on its own thread.
    // The injector explains refusals that are not plain Win32 errors (a stale
    // payload image in the target, an image without the export) -- A42.
    std::wstring startupDetail;
    if (!StartPayloadThread(pid, payloadDll, sharedName_,
                            hProc_, hThread_, lastStage_, lastWin32_,
                            &startupDetail)) {
        if (!startupDetail.empty()) {
            wcsncpy_s(lastError_, startupDetail.c_str(), _TRUNCATE);
        } else {
            SetErrorText(L"start-up failed at stage %d (win32=%lu)", lastStage_, lastWin32_);
        }
        LogLine("start-up refused: %ls", lastError_);
        ReleaseHandles();
        return false;
    }

    // Payload reports readiness by writing a "loaded" reply.
    LONG st = ReadState(&io_->ready);
    LogLine("handshake wait: ready=%ld", (long)st);
    if (!WaitForState(kStateResponse, timeoutMs)) {
        lastDiag_ = io_->diag;
        if (lastDiag_ == kDiagAbiMismatch) {
            SetErrorText(L"the payload refused the shared block: it speaks another "
                         L"protocol version than this build (probably a payload DLL "
                         L"from another build directory)");
        } else if (lastDiag_ != 0) {
            SetErrorText(L"payload thread exited with diagnostic %ld "
                         L"(check: is the payload DLL on the target's disk? "
                         L"does its bitness match? did LoadLibrary fail?)",
                         lastDiag_);
        } else {
            SetErrorText(L"no reply from payload: the remote thread never reported "
                         L"in (DLL not executed, wrong bitness, or target still "
                         L"loading)");
        }
        LogLine("handshake failed: %ls", lastError_);
        // A108: the payload may still be starting (a slow AV scan of the DLL
        // copy can outlast the timeout). Leaving the block as it is means the
        // late handshake reply puts the payload to sleep with the block busy
        // forever -- every further Open to this target is refused until 1C is
        // restarted. Park the word in Exit: the late payload publishes nothing
        // (PublishHandshakeReply refuses non-Idle states) and leaves on its
        // first loop iteration, so the block becomes reusable.
        InterlockedExchange((volatile LONG*)&io_->ready, kStateExit);
        ReleaseHandles();
        return false;
    }

    // A payload of another build can answer the handshake and still speak a
    // layout this host would misread: ask which protocol it understood before
    // the first command is sent (A96).
    const std::wstring complaint = CheckProtocolHandshake(io_);
    if (!complaint.empty()) {
        wcsncpy_s(lastError_, complaint.c_str(), _TRUNCATE);
        LogLine("handshake rejected: %ls", lastError_);
        ReleaseHandles();
        return false;
    }

    // Consume the readiness reply: without this the very next Call sees a
    // kStateResponse block and refuses with "busy".
    LogLine("handshake ok, ready=%ld resuming idle", (long)io_->ready);
    InterlockedExchange((volatile LONG*)&io_->ready, kStateIdle);
    return true;
}

Client::Await Client::AwaitResponse(int timeoutMs, LONG expectedSeq) {
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    for (;;) {
        const LONG state = ReadState(&io_->ready);
        if (state == kStateResponse) {
            const LONG got = InterlockedCompareExchange((volatile LONG*)&io_->respSeq, 0, 0);
            if (got == expectedSeq) return Await::arrived;
            // The reply belongs to another request (or to a payload of another
            // build that does not stamp the sequence at all). Reading it as the
            // answer to this command would hand the caller somebody else's
            // bytes, so it is dropped instead.
            InterlockedCompareExchange((volatile LONG*)&io_->ready, kStateIdle, kStateResponse);
            SetErrorText(L"the payload answered request %ld while %ld was expected: "
                         L"it runs another protocol version or lost the request",
                         (long)got, (long)expectedSeq);
            LogLine("Call: foreign reply seq=%ld expected=%ld", (long)got, (long)expectedSeq);
            return Await::foreign;
        }
        if (state == kStateExit) return Await::lost;
        if (Clock::now() >= deadline) return Await::timeout;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void Client::TakeResponse(std::string& response) {
    lastDiag_ = io_->diag;
    LONG len = io_->responseLen;
    if (len < 0 || (size_t)len >= kResponseBytes) len = (LONG)(kResponseBytes - 1);
    response.assign(io_->response, (size_t)len);
}

bool Client::Call(const std::wstring& command, std::string& response, int timeoutMs) {
    lastError_[0] = 0;
    if (!io_) {
        SetErrorText(L"the session is not open");
        return false;
    }
    if (command.size() + 1 > kRequestChars) {
        SetErrorText(L"the command is %zu characters long, the block holds %zu",
                     command.size(), kRequestChars - 1);
        return false;
    }

    // Everything the payload must see is written before the state word: the
    // interlocked store of `ready` is the release barrier (A27).
    wcscpy_s(io_->request, kRequestChars, command.c_str());
    io_->requestLen = (LONG)(command.size() + 1);
    io_->responseLen = 0;
    io_->response[0] = 0;
    const LONG seq = InterlockedIncrement(&seq_);
    InterlockedExchange((volatile LONG*)&io_->seq, seq);

    // Idle -> Request. Anything else means the word is not ours to take: a
    // reply nobody read, or a request another caller posted.
    const LONG prev = InterlockedCompareExchange((volatile LONG*)&io_->ready, kStateRequest, kStateIdle);
    LogLine("Call(%ls): seq=%ld ready was %ld -> %s", command.c_str(), (long)seq, (long)prev,
            prev == kStateIdle ? "request posted" : "BUSY");
    if (prev != kStateIdle) {
        SetErrorText(L"the payload is not idle (state %ld): the previous request was "
                     L"never answered; nothing was sent", (long)prev);
        return false;
    }

    Await r = AwaitResponse(timeoutMs, seq);
    if (r == Await::timeout) {
        // The command may simply be slow: give it the same budget again (capped)
        // before declaring it lost.
        LogLine("Call(%ls): no answer in %d ms, grace period", command.c_str(), timeoutMs);
        r = AwaitResponse(GraceMs(timeoutMs), seq);
    }
    if (r == Await::arrived) {
        TakeResponse(response);
        LogLine("Call(%ls): got %zu bytes: %.120s", command.c_str(), response.size(),
                response.c_str());
        InterlockedExchange((volatile LONG*)&io_->ready, kStateIdle);
        return true;
    }
    if (r == Await::lost) {
        SetErrorText(L"the payload is gone: the target unloaded it or the process "
                     L"exited while the command was running");
        LogLine("Call(%ls): payload lost", command.c_str());
        return false;
    }
    if (r == Await::foreign) return false;  // the text is already set

    // Timeout: take the state word back so the session stays usable (A45). The
    // payload may still be working on this request; its reply carries the
    // sequence and is dropped by the payload instead of being published over
    // the next request.
    const LONG taken = InterlockedCompareExchange((volatile LONG*)&io_->ready, kStateIdle, kStateRequest);
    if (taken == kStateRequest) {
        LogLine("Call(%ls): seq=%ld abandoned, state reset to idle", command.c_str(), (long)seq);
    } else if (taken == kStateResponse) {
        // It answered between the last poll and the reset: take the answer.
        const LONG got = InterlockedCompareExchange((volatile LONG*)&io_->respSeq, 0, 0);
        LogLine("Call(%ls): late reply seq=%ld (wanted %ld)", command.c_str(), (long)got, (long)seq);
        if (got == seq) {
            TakeResponse(response);
            InterlockedExchange((volatile LONG*)&io_->ready, kStateIdle);
            return true;
        }
        InterlockedExchange((volatile LONG*)&io_->ready, kStateIdle);
    } else if (taken == kStateExit) {
        SetErrorText(L"the payload left while the command was running");
        return false;
    }
    SetErrorText(L"no answer in %d ms: the request was abandoned and the session "
                 L"reset to idle (the payload drops the late reply)", timeoutMs);
    return false;
}

bool Client::Close(int timeoutMs) {
    if (!io_) {
        ReleaseHandles();
        return true;
    }
    lastError_[0] = 0;
    bool clean = true;
    bool abandoned = false;

    LONG state = ReadState(&io_->ready);
    if (state == kStateRequest || state == kStateResponse) {
        // Let a command that is still running finish, so the exit request is not
        // stuck behind it. A reply nobody is waiting for is taken back at once.
        if (WaitForState(kStateIdle, timeoutMs)) {
            state = kStateIdle;
        } else {
            state = ReadState(&io_->ready);
            if (state == kStateRequest || state == kStateResponse) {
                if (InterlockedCompareExchange((volatile LONG*)&io_->ready, kStateIdle, state) == state) {
                    LogLine("Close: state %ld abandoned after %d ms", (long)state, timeoutMs);
                    abandoned = true;
                    state = kStateIdle;
                } else {
                    state = ReadState(&io_->ready);
                }
            }
        }
    }

    if (state == kStateIdle) {
        wcscpy_s(io_->request, kRequestChars, L"exit");
        io_->requestLen = 5;
        const LONG prev = InterlockedCompareExchange((volatile LONG*)&io_->ready, kStateExit, kStateIdle);
        if (prev == kStateIdle) {
            LogLine("Close: exit requested%s", abandoned ? " (command still running)" : "");
        } else {
            clean = false;
            SetErrorText(L"the payload left the idle state while the exit request "
                         L"was being posted (state %ld): the command loop may still "
                         L"be running inside the target", (long)prev);
        }
    } else if (state != kStateExit) {
        clean = false;
        SetErrorText(L"the payload did not become idle within %d ms (state %ld): the "
                     L"command it is running is still inside the target, so the exit "
                     L"request was not delivered; the payload leaves when the command "
                     L"finishes or when the target exits", timeoutMs, (long)state);
    }

    if (clean && abandoned) {
        // The exit request went out, but the command it was queued behind is
        // still running: the payload leaves when that returns, which this call
        // could not wait for. Reporting success here would hide exactly the case
        // that A45 is about.
        clean = false;
        SetErrorText(L"the payload was busy for more than %d ms: the exit request is "
                     L"queued behind a command that is still running inside the "
                     L"target; the payload leaves when it returns", timeoutMs);
    }

    // The injected thread ends when the payload's command loop returns, and that
    // is the only proof the payload is gone. A block of one's own (the tests, a
    // foreign payload) has no thread to wait for: the exit request is as far as
    // the host can go there.
    if (clean && !WaitThreadExit(timeoutMs)) {
        clean = false;
        SetErrorText(L"the payload accepted the exit request but its thread is still "
                     L"running after %d ms; the shared block stays mapped until the "
                     L"command finishes", timeoutMs);
    }

    if (!clean) LogLine("Close: %ls", lastError_);
    ReleaseHandles();
    return clean;
}

}  // namespace v8i
