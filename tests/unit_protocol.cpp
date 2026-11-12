// The host side of the protocol.
//
// The host and the payload talk through a shared block: the host writes a
// request and flips the state word, the payload answers and flips it back.
// Both sides live in different processes, so the handshake is the place where
// a mistake shows up as a hang or as an answer from the wrong peer.
//
// The test plays the payload: a thread of its own answers the block, so the
// real host code (the state machine, the busy path, the timeout, the
// truncation of a long answer) is exercised without a live 1C.

#include "json_check.h"
#include "test_runner.h"

#include "v8inject/client.h"
#include "v8inject/protocol.h"

#include <atomic>
#include <mutex>
#include <thread>

using namespace v8i;
using namespace v8i::test;

namespace {

// A payload stand-in: it maps the block by name and answers the requests.
class FakePayload {
public:
    ~FakePayload() { Stop(); }

    // Maps the block and starts the answering thread.
    bool Start(uint32_t pid) {
        wchar_t name[64] = {};
        MakeSharedName(name, _countof(name), pid);

        hMap_ = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (!hMap_) return false;
        io_ = (SharedIo*)MapViewOfFile(hMap_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
        if (!io_) { CloseHandle(hMap_); hMap_ = nullptr; return false; }

        thread_ = std::thread([this] { Loop(); });
        return true;
    }

    void Stop() {
        if (!thread_.joinable()) return;
        InterlockedExchange((volatile LONG*)&io_->ready, kStateExit);
        thread_.join();
        if (io_) { UnmapViewOfFile(io_); io_ = nullptr; }
        if (hMap_) { CloseHandle(hMap_); hMap_ = nullptr; }
    }

    // What the fake payload answers. An empty string means "stay silent" -
    // that is how the timeout is provoked.
    void SetReply(const std::string& reply) {
        std::lock_guard<std::mutex> lock(mutex_);
        reply_ = reply;
    }

    void SetSilent(bool silent) {
        std::lock_guard<std::mutex> lock(mutex_);
        silent_ = silent;
    }

    std::wstring LastRequest() {
        std::lock_guard<std::mutex> lock(mutex_);
        return lastRequest_;
    }

    int Requests() const { return requests_.load(); }

private:
    void Loop() {
        for (;;) {
            const LONG state = InterlockedCompareExchange((volatile LONG*)&io_->ready, 0, 0);
            if (state == kStateExit) break;
            if (state != kStateRequest) { Sleep(5); continue; }

            std::string reply;
            bool silent = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                lastRequest_ = io_->request;
                reply = reply_;
                silent = silent_;
            }
            requests_.fetch_add(1);

            if (silent) continue;          // the host must time out

            // The answer is written before the state says it is there.
            strncpy_s(io_->response, kResponseBytes, reply.c_str(), _TRUNCATE);
            io_->responseLen = (LONG)reply.size();
            InterlockedExchange((volatile LONG*)&io_->ready, kStateResponse);
        }
    }

    HANDLE hMap_ = nullptr;
    SharedIo* io_ = nullptr;
    std::thread thread_;
    std::mutex mutex_;
    std::string reply_;
    std::wstring lastRequest_;
    bool silent_ = false;
    std::atomic<int> requests_{ 0 };
};

// A pid that is not in use, so the block name cannot clash with a live one.
uint32_t TestPid() {
    return GetCurrentProcessId() + 0x7000;
}

std::wstring TempLogDir() {
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    return tmp;
}

}  // namespace

V8I_TEST(Protocol_RoundTrip) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    CHECK(client.IsOpen());

    FakePayload payload;
    REQUIRE(payload.Start(pid));

    payload.SetReply("{\"status\":\"ok\",\"api\":3,\"pointerSize\":8}");
    std::string response;
    CHECK(client.Call(L"version", response, 5000));
    CHECK(response == "{\"status\":\"ok\",\"api\":3,\"pointerSize\":8}");
    CHECK(payload.LastRequest() == L"version");
    CHECK_EQ(payload.Requests(), 1);
}

V8I_TEST(Protocol_SeveralCommandsInARow) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    FakePayload payload;
    REQUIRE(payload.Start(pid));
    payload.SetReply("{\"status\":\"ok\"}");

    for (int i = 0; i < 5; ++i) {
        std::string response;
        CHECK(client.Call(L"probe", response, 5000));
        CHECK(response == "{\"status\":\"ok\"}");
    }
    CHECK_EQ(payload.Requests(), 5);
}

V8I_TEST(Protocol_BusyPayloadIsRefused) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    FakePayload payload;
    REQUIRE(payload.Start(pid));

    // The payload never answers, so the first call is still in flight when the
    // second one starts: the second must be refused, not queued.
    payload.SetSilent(true);
    std::string response;
    CHECK(!client.Call(L"version", response, 400));
    CHECK(!client.Call(L"version", response, 400));
    CHECK(payload.Requests() >= 1);
}

V8I_TEST(Protocol_TimeoutIsReported) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    FakePayload payload;
    REQUIRE(payload.Start(pid));
    payload.SetSilent(true);

    const DWORD started = GetTickCount();
    std::string response;
    CHECK(!client.Call(L"version", response, 300));
    CHECK(GetTickCount() - started >= 250);
}

V8I_TEST(Protocol_LongRequestIsRefused) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    FakePayload payload;
    REQUIRE(payload.Start(pid));
    payload.SetReply("{\"status\":\"ok\"}");

    // A command longer than the block can hold is refused before it is sent.
    const std::wstring tooLong(kRequestChars + 16, L'x');
    std::string response;
    CHECK(!client.Call(tooLong, response, 500));
    CHECK_EQ(payload.Requests(), 0);
}

V8I_TEST(Protocol_LongAnswerIsTruncated) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    FakePayload payload;
    REQUIRE(payload.Start(pid));

    // An answer that does not fit into the block: the host must take what
    // fits instead of reading past the end.
    payload.SetReply(std::string(kResponseBytes + 1000, 'x'));
    std::string response;
    CHECK(client.Call(L"find", response, 5000));
    CHECK_EQ(response.size(), (size_t)(kResponseBytes - 1));
}

V8I_TEST(Protocol_ExitStopsThePayload) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    FakePayload payload;
    REQUIRE(payload.Start(pid));
    payload.SetReply("{\"status\":\"ok\"}");

    std::string response;
    CHECK(client.Call(L"version", response, 5000));

    client.Close();
    // The payload saw the exit state and stopped.
    CHECK_EQ(payload.Requests(), 1);
}

V8I_TEST(Protocol_SecondHostOnTheSamePidIsRefused) {
    const uint32_t pid = TestPid();
    Client first;
    REQUIRE(first.OpenBlock(pid, TempLogDir()));

    // The block name is derived from the pid, so a second host would attach
    // to somebody else's block. It has to be refused.
    Client second;
    CHECK(!second.OpenBlock(pid, TempLogDir()));
    CHECK(second.LastError() != nullptr && second.LastError()[0] != 0);
}
