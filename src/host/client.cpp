#include "v8inject/client.h"
#include "v8inject/diag.h"
#include "v8inject/injector.h"

#include <chrono>
#include <sddl.h>
#include <thread>
#include <vector>

namespace v8i {

namespace {

using Clock = std::chrono::steady_clock;

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

}  // namespace

Client::~Client() {
    Close();
}

void Client::ReleaseHandles() {
    if (io_)          { UnmapViewOfFile(io_); io_ = nullptr; }
    if (hMap_)        { CloseHandle(hMap_);   hMap_ = nullptr; }
    if (hThread_)     { CloseHandle(hThread_); hThread_ = nullptr; }
    if (hProc_) {
        if (remoteName_) VirtualFreeEx(hProc_, remoteName_, 0, MEM_RELEASE);
        if (remoteArgs_) VirtualFreeEx(hProc_, remoteArgs_, 0, MEM_RELEASE);
        CloseHandle(hProc_);
        hProc_ = nullptr;
    }
    remoteName_ = nullptr;
    remoteArgs_ = nullptr;
}

bool Client::WaitForState(LONG expected, int timeoutMs) {
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    for (;;) {
        if (ReadState(&io_->ready) == expected) return true;
        if (Clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
}

bool Client::OpenBlock(uint32_t pid, const std::wstring& logDir) {
    if (hMap_) return false;

    MakeSharedName(sharedName_, _countof(sharedName_), pid);
    LogLine("Client::OpenBlock pid=%u name=%ls logDir=%ls", pid, sharedName_, logDir.c_str());

    // 2 GB block is virtual; only touched pages become resident.
    PSECURITY_DESCRIPTOR sd = nullptr;
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, FALSE };
    if (MakeBlockSecurityDescriptor(&sd)) sa.lpSecurityDescriptor = sd;
    hMap_ = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE,
                               0, (DWORD)sizeof(SharedIo), sharedName_);
    if (sd) LocalFree(sd);
    if (!hMap_) return false;
    // A block with that name already existed: another host is already talking
    // to this pid, or somebody else got there first and the payload would
    // attach to a stranger's block. Both are reasons to stop.
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        _snwprintf_s(lastError_, _countof(lastError_), _TRUNCATE,
                     L"the shared block %ls already exists (another host is "
                     L"already connected to this process?)",
                     sharedName_);
        LogLine("Client::Open: %ls already exists", sharedName_);
        ReleaseHandles();
        return false;
    }

    io_ = (SharedIo*)MapViewOfFile(hMap_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
    LogLine("Client: shared block mapped at %p (size=%llu)",
            (void*)io_, (unsigned long long)sizeof(SharedIo));
    if (!io_) { ReleaseHandles(); return false; }

    InterlockedExchange((volatile LONG*)&io_->ready, kStateIdle);
    io_->requestLen = 0;
    io_->responseLen = 0;
    io_->seq = 0;
    io_->diag = 0;
    wcsncpy_s(io_->logDir, MAX_PATH, logDir.c_str(), _TRUNCATE);
    io_->request[0] = 0;
    io_->response[0] = 0;
    return true;
}

bool Client::Open(uint32_t pid, const std::wstring& payloadDll,
                  const std::wstring& logDir, int timeoutMs) {
    if (!OpenBlock(pid, logDir)) return false;

    // Copy the payload into the target and start v8i_probe on its own thread.
    if (!StartPayloadThread(pid, payloadDll, sharedName_,
                            hProc_, hThread_, remoteName_, remoteArgs_,
                            lastStage_, lastWin32_)) {
        _snwprintf_s(lastError_, _countof(lastError_), _TRUNCATE,
                     L"start-up failed at stage %d (win32=%lu)",
                     lastStage_, lastWin32_);
        ReleaseHandles();
        return false;
    }

    // Payload reports readiness by writing a "loaded" reply.
    LONG st = ReadState(&io_->ready);
    LogLine("handshake wait: ready=%ld", (long)st);
    if (!WaitForState(kStateResponse, timeoutMs)) {
        lastDiag_ = io_->diag;
        if (lastDiag_ != 0) {
            _snwprintf_s(lastError_, _countof(lastError_), _TRUNCATE,
                         L"payload thread exited with diagnostic %ld "
                         L"(check: is the payload DLL on the target's disk? "
                         L"does its bitness match? did LoadLibrary fail?)",
                         lastDiag_);
        } else {
            wcscpy_s(lastError_, L"no reply from payload: the remote thread "
                                 L"never reported in (DLL not executed, "
                                 L"wrong bitness, or target still loading)");
        }
        ReleaseHandles();
        return false;
    }

    // Consume the readiness reply: without this the very next Call sees a
    // kStateResponse block and refuses with "busy".
    LogLine("handshake ok, ready=%ld resuming idle", (long)io_->ready);
    InterlockedExchange((volatile LONG*)&io_->ready, kStateIdle);
    return true;
}

bool Client::Call(const std::wstring& command, std::string& response, int timeoutMs) {
    if (!io_) return false;
    if (command.size() + 1 > kRequestChars) return false;

    wcscpy_s(io_->request, kRequestChars, command.c_str());
    io_->requestLen = (LONG)(command.size() + 1);
    io_->responseLen = 0;
    io_->response[0] = 0;
    InterlockedIncrement(&seq_);
    InterlockedExchange((volatile LONG*)&io_->seq, seq_);

    // Idle -> Request. If the payload is still busy we treat it as an error
    // rather than racing on a half-written buffer.
    LONG prev = InterlockedCompareExchange((volatile LONG*)&io_->ready, kStateRequest, kStateIdle);
    LogLine("Call(%ls): ready was %ld -> %s", command.c_str(), (long)prev,
            prev == kStateIdle ? "request posted" : "BUSY");
    if (prev != kStateIdle) return false;

    if (!WaitForState(kStateResponse, timeoutMs)) {
        LogLine("Call(%ls): timeout, ready=%ld diag=%ld", command.c_str(),
                (long)io_->ready, (long)io_->diag);
        return false;
    }

    lastDiag_ = io_->diag;
    LONG len = io_->responseLen;
    if (len < 0 || (size_t)len >= kResponseBytes) len = (LONG)(kResponseBytes - 1);
    response.assign(io_->response, (size_t)len);
    LogLine("Call(%ls): got %ld bytes: %.120s", command.c_str(), (long)len,
            response.c_str());

    InterlockedExchange((volatile LONG*)&io_->ready, kStateIdle);
    return true;
}

void Client::Close(int timeoutMs) {
    if (io_) {
        wcscpy_s(io_->request, kRequestChars, L"exit");
        io_->requestLen = 5;
        if (InterlockedCompareExchange((volatile LONG*)&io_->ready, kStateExit, kStateIdle) == kStateIdle) {
            auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
            while (Clock::now() < deadline) {
                if (!hThread_) break;
                DWORD code = 0;
                if (GetExitCodeThread(hThread_, &code) && code != STILL_ACTIVE) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(15));
            }
        }
    }
    ReleaseHandles();
}

}  // namespace v8i
