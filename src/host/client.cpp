#include "v8inject/client.h"
#include "v8inject/injector.h"

#include <chrono>
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
        if (io_->ready == expected) return true;
        if (Clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
}

bool Client::Open(uint32_t pid, const std::wstring& payloadDll,
                  const std::wstring& logDir, int timeoutMs) {
    if (hMap_) return false;

    MakeSharedName(sharedName_, _countof(sharedName_), pid);

    // 2 GB block is virtual; only touched pages become resident.
    hMap_ = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                               0, (DWORD)sizeof(SharedIo), sharedName_);
    if (!hMap_) return false;

    io_ = (SharedIo*)MapViewOfFile(hMap_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
    if (!io_) { ReleaseHandles(); return false; }

    io_->ready = kStateIdle;
    io_->requestLen = 0;
    io_->responseLen = 0;
    io_->seq = 0;
    io_->diag = 0;
    wcsncpy_s(io_->logDir, MAX_PATH, logDir.c_str(), _TRUNCATE);
    io_->request[0] = 0;
    io_->response[0] = 0;

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
    io_->seq = seq_;

    // Idle -> Request. If the payload is still busy we treat it as an error
    // rather than racing on a half-written buffer.
    if (InterlockedCompareExchange((volatile LONG*)&io_->ready, kStateRequest, kStateIdle) != kStateIdle)
        return false;

    if (!WaitForState(kStateResponse, timeoutMs)) return false;

    lastDiag_ = io_->diag;
    LONG len = io_->responseLen;
    if (len < 0 || (size_t)len >= kResponseBytes) len = (LONG)(kResponseBytes - 1);
    response.assign(io_->response, (size_t)len);

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
