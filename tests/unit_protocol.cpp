// The host side of the protocol.
//
// The host and the payload talk through a shared block: the host writes a
// request and flips the state word, the payload answers and flips it back.
// Both sides live in different processes, so the handshake is the place where
// a mistake shows up as a hang or as an answer from the wrong peer.
//
// The test plays the payload: a thread of its own answers the block through the
// real publish rule (V8iPublishReply), so the host is checked against the
// protocol the payload actually speaks -- the state machine, the busy path, the
// timeout and its recovery, the sequence stamp, the truncation of a long answer
// -- without a live 1C.
//
// A45 lives here as well: a timed-out command must not kill the session, a
// payload must not publish a reply nobody waits for, a payload must not outlive
// its host, and a block left behind by a crashed host must be reusable.

#include "test_runner.h"

#include "v8inject/client.h"
#include "v8inject/protocol.h"
#include "v8inject/v8i_export.h"

#include <atomic>
#include <mutex>
#include <string>
#include <vector>
#include <thread>

using namespace v8i;
using namespace v8i::test;

namespace {

// The block as the payload side sees it: mapped by name, no answering thread.
const char kOkReply[] = "{\"status\":\"ok\"}";
const char kStaleReply[] = "{\"status\":\"stale\"}";

class RawBlock {
public:
    ~RawBlock() { Close(); }

    // Makes a block of its own (the state a host crash leaves behind: the host
    // is gone, the block still exists because somebody else maps it).
    bool Create(const wchar_t* name) {
        h_ = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                                (DWORD)sizeof(SharedIo), name);
        if (!h_) return false;
        io_ = (SharedIo*)MapViewOfFile(h_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
        if (!io_) { CloseHandle(h_); h_ = nullptr; return false; }
        io_->ready = kStateIdle;
        io_->abiVersion = kProtocolAbi;
        io_->structSize = (LONG)sizeof(SharedIo);
        io_->payloadAbi = kProtocolAbi;
        return true;
    }

    // Maps a block that already exists, the way the payload does.
    bool Attach(const wchar_t* name) {
        h_ = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
        if (!h_) return false;
        io_ = (SharedIo*)MapViewOfFile(h_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
        if (!io_) { CloseHandle(h_); h_ = nullptr; return false; }
        return true;
    }

    void Close() {
        if (io_) { UnmapViewOfFile(io_); io_ = nullptr; }
        if (h_) { CloseHandle(h_); h_ = nullptr; }
    }

    SharedIo* io() const { return io_; }

private:
    HANDLE h_ = nullptr;
    SharedIo* io_ = nullptr;
};

// A payload stand-in: it maps the block by name and answers the requests through
// V8iPublishReply, the same gate the real command loop uses.
class FakePayload {
public:
    ~FakePayload() { Stop(); }

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

    void SetReply(const std::string& reply) {
        std::lock_guard<std::mutex> lock(mutex_);
        reply_ = reply;
    }

    // The payload never answers, as if it were busy with the request.
    void SetSilent(bool silent) {
        std::lock_guard<std::mutex> lock(mutex_);
        silent_ = silent;
    }

    std::wstring LastRequest() {
        std::lock_guard<std::mutex> lock(mutex_);
        return lastRequest_;
    }

    int Requests() const { return requests_.load(); }
    LONG State() const {
        return io_ ? InterlockedCompareExchange((volatile LONG*)&io_->ready, 0, 0) : -1;
    }

    // A reply that shows up after the host gave up: carries the sequence of the
    // request the payload is (still) looking at.
    bool PublishLate(const std::string& reply) {
        const LONG seq = InterlockedCompareExchange((volatile LONG*)&io_->seq, 0, 0);
        return V8iPublishReply(io_, seq, reply.data(), reply.size());
    }

    std::string Response() const {
        return io_ ? std::string(io_->response) : std::string();
    }

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
            const LONG seq = InterlockedCompareExchange((volatile LONG*)&io_->seq, 0, 0);

            if (silent) {
                // Busy with the request: nothing is published, and the payload
                // keeps looking at the word it was given. It moves on as soon as
                // the host takes it back or queues the next request (the real
                // loop drops the stale reply by its sequence, A45).
                const LONG seqAtStart = seq;
                while (InterlockedCompareExchange((volatile LONG*)&io_->ready, 0, 0) == kStateRequest &&
                       InterlockedCompareExchange((volatile LONG*)&io_->seq, 0, 0) == seqAtStart)
                    Sleep(5);
                continue;
            }
            V8iPublishReply(io_, seq, reply.data(), reply.size());
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

// A pid that is certainly gone: a process of its own, waited for and released.
DWORD DeadPid() {
    wchar_t comspec[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(L"ComSpec", comspec, MAX_PATH)) return 0;
    std::wstring line = std::wstring(L"\"") + comspec + L"\" /c exit 0";
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, &line[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi))
        return 0;
    WaitForSingleObject(pi.hProcess, 5000);
    const DWORD pid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return pid;
}

}  // namespace

V8I_TEST(Protocol_RoundTrip) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    CHECK(client.IsOpen());
    CHECK(client.LastError()[0] == 0);

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
    // The caller's timeout plus the grace period: a slow command gets one more
    // chance before it is declared lost.
    CHECK(GetTickCount() - started >= 250);
    CHECK(client.LastError()[0] != 0);
}

V8I_TEST(Protocol_TimeoutLeavesTheSessionUsable) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    FakePayload payload;
    REQUIRE(payload.Start(pid));

    payload.SetSilent(true);
    std::string response;
    CHECK(!client.Call(L"heapobjects", response, 300));
    // A45: the state word is taken back, so the next command is not answered
    // with "busy" for the rest of the session.
    CHECK_EQ((int)payload.State(), (int)kStateIdle);

    payload.SetSilent(false);
    payload.SetReply("{\"status\":\"ok\",\"after\":\"timeout\"}");
    CHECK(client.Call(L"version", response, 5000));
    CHECK(response == "{\"status\":\"ok\",\"after\":\"timeout\"}");
}

V8I_TEST(Protocol_LateReplyIsDroppedAfterTimeout) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    FakePayload payload;
    REQUIRE(payload.Start(pid));

    payload.SetSilent(true);
    std::string response;
    CHECK(!client.Call(L"version", response, 300));
    REQUIRE(payload.State() == kStateIdle);

    // The payload finishes the abandoned command and publishes: the reply
    // belongs to a request nobody waits for, so it must not land in the block
    // (the next command would read it as its own answer).
    CHECK(!payload.PublishLate("{\"status\":\"late\"}"));
    CHECK_EQ((int)payload.State(), (int)kStateIdle);
    CHECK(payload.Response().empty());

    payload.SetSilent(false);
    payload.SetReply("{\"status\":\"ok\",\"fresh\":true}");
    CHECK(client.Call(L"version", response, 5000));
    CHECK(response == "{\"status\":\"ok\",\"fresh\":true}");
}

V8I_TEST(Protocol_ReplyIsNotPublishedOverExit) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    RawBlock block;
    REQUIRE(block.Attach(client.SharedName()));

    // The host asked the payload to unload while a command was still running: a
    // reply published now would overwrite the exit request and keep the payload
    // alive (A45).
    InterlockedExchange((volatile LONG*)&block.io()->ready, kStateExit);
    CHECK(!V8iPublishReply(block.io(), 0, kOkReply, sizeof(kOkReply) - 1));
    CHECK_EQ((int)block.io()->ready, (int)kStateExit);
    CHECK(block.io()->response[0] == 0);
}

V8I_TEST(Protocol_ReplyOfAnotherRequestIsDropped) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    RawBlock block;
    REQUIRE(block.Attach(client.SharedName()));

    InterlockedExchange((volatile LONG*)&block.io()->ready, kStateRequest);
    InterlockedExchange((volatile LONG*)&block.io()->seq, 7);

    // The reply of request 6 must not be published over request 7.
    CHECK(!V8iPublishReply(block.io(), 6, kStaleReply, sizeof(kStaleReply) - 1));
    CHECK_EQ((int)block.io()->ready, (int)kStateRequest);
    CHECK(block.io()->response[0] == 0);

    // The reply of the request that is current goes through, stamped with its
    // sequence so the host can tell the answer belongs to it.
    CHECK(V8iPublishReply(block.io(), 7, kOkReply, sizeof(kOkReply) - 1));
    CHECK_EQ((int)block.io()->ready, (int)kStateResponse);
    CHECK_EQ((int)block.io()->respSeq, 7);
    CHECK(std::string(block.io()->response) == "{\"status\":\"ok\"}");
}

// A106: a reply larger than the block is refused, not silently truncated into
// an invalid document. The old code cut the reply at kResponseBytes-1 and
// published the cut half -- this test is red on that code (the publish
// "succeeded") and green on the refusal.
V8I_TEST(Protocol_OversizedReplyIsRefusedNotTruncated) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    RawBlock block;
    REQUIRE(block.Attach(client.SharedName()));

    InterlockedExchange((volatile LONG*)&block.io()->ready, kStateRequest);
    InterlockedExchange((volatile LONG*)&block.io()->seq, 9);

    std::vector<char> big(kResponseBytes + 64, 'x');
    CHECK(!V8iPublishReply(block.io(), 9, big.data(), big.size()));
    CHECK_EQ((int)block.io()->ready, (int)kStateRequest);
    CHECK(block.io()->response[0] == 0);

    // The block survived the refusal: a fitting reply still goes through.
    CHECK(V8iPublishReply(block.io(), 9, kOkReply, sizeof(kOkReply) - 1));
    CHECK_EQ((int)block.io()->respSeq, 9);
}

V8I_TEST(Protocol_UnconsumedReplyBlocksTheNextCall) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    RawBlock block;
    REQUIRE(block.Attach(client.SharedName()));

    // A reply nobody read: the word is not the host's to take, and a command
    // sent now would race with whoever owns that reply.
    InterlockedExchange((volatile LONG*)&block.io()->ready, kStateResponse);
    std::string response;
    CHECK(!client.Call(L"version", response, 300));
    CHECK(wcsstr(client.LastError(), L"idle") != nullptr);
}

V8I_TEST(Protocol_CloseWhileBusyReportsFailure) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    FakePayload payload;
    REQUIRE(payload.Start(pid));
    RawBlock block;
    REQUIRE(block.Attach(client.SharedName()));
    payload.SetSilent(true);

    // The payload is inside a command: the exit request cannot be honoured
    // before it returns, and the host has to say so instead of reporting a
    // clean close (A45).
    std::string response;
    CHECK(!client.Call(L"version", response, 300));
    // A request is in flight again, as a payload that is still busy leaves the
    // word it was given.
    InterlockedExchange((volatile LONG*)&block.io()->ready, kStateRequest);

    CHECK(!client.Close(300));
    CHECK(client.LastError()[0] != 0);
    CHECK(!client.IsOpen());
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

    CHECK(client.Close());
    // The payload saw the exit state and stopped.
    CHECK_EQ(payload.Requests(), 1);
    CHECK_EQ((int)payload.State(), (int)kStateExit);
}

V8I_TEST(Protocol_SecondHostOnTheSamePidIsRefused) {
    const uint32_t pid = TestPid();
    Client first;
    REQUIRE(first.OpenBlock(pid, TempLogDir()));

    // The block name is derived from the pid, so a second host would attach
    // to somebody else's block. It has to be refused, and it has to say whose
    // block that is (A96).
    Client second;
    CHECK(!second.OpenBlock(pid, TempLogDir()));
    CHECK(second.LastError()[0] != 0);
    CHECK(wcsstr(second.LastError(), L"pid") != nullptr);
}

V8I_TEST(Protocol_StaleBlockOfACrashedHostIsReused) {
    const uint32_t pid = TestPid();
    const DWORD deadHost = DeadPid();
    REQUIRE(deadHost != 0);

    wchar_t name[64] = {};
    MakeSharedName(name, _countof(name), pid);

    // What a host crash leaves behind: the block exists (the payload still maps
    // it), the payload is on its way out because its host is gone, and nothing
    // says that to the next host except the block itself.
    RawBlock block;
    REQUIRE(block.Create(name));
    block.io()->hostPid = (LONG)deadHost;
    block.io()->ready = kStateIdle;

    // The payload side keeps the block alive while the new host waits.
    RawBlock payloadSide;
    REQUIRE(payloadSide.Attach(name));

    Client fresh;
    bool opened = false;
    std::thread attempt([&] { opened = fresh.OpenBlock(pid, TempLogDir()); });
    Sleep(200);                       // the host is polling the stale block
    block.Close();                    // the crashed host's own handles are gone
    Sleep(200);                       // the payload has not noticed yet: no block yet
    payloadSide.Close();              // and now the block disappears
    attempt.join();

    CHECK(opened);
    CHECK(fresh.IsOpen());
}

V8I_TEST(Protocol_PayloadLeavesWhenItsHostIsGone) {
    const uint32_t pid = TestPid();
    const DWORD deadHost = DeadPid();
    REQUIRE(deadHost != 0);

    wchar_t name[64] = {};
    MakeSharedName(name, _countof(name), pid);
    RawBlock block;
    REQUIRE(block.Create(name));
    block.io()->hostPid = (LONG)deadHost;

    // The real command loop: nobody will ever read a reply from this block, so
    // the loop has to leave on its own instead of living in the target forever
    // (A45 -- a payload that stays keeps the block and blocks the next host).
    std::atomic<bool> finished{ false };
    std::thread payload([&] {
        V8iRunCommandLoop(block.io());
        finished = true;
    });
    for (int i = 0; i < 200 && !finished.load(); ++i) Sleep(10);
    const bool left = finished.load();
    const int state = (int)block.io()->ready;
    if (!left) InterlockedExchange((volatile LONG*)&block.io()->ready, kStateExit);
    payload.join();

    CHECK(left);
    CHECK_EQ(state, (int)kStateExit);
}

V8I_TEST(Protocol_HandshakeRejectsAPayloadOfAnotherBuild) {
    const uint32_t pid = TestPid();
    Client client;
    REQUIRE(client.OpenBlock(pid, TempLogDir()));
    RawBlock block;
    REQUIRE(block.Attach(client.SharedName()));

    // A payload of another build answers "loaded" but cannot know the protocol
    // stamp: that is what tells it apart from one that never started (A96).
    block.io()->payloadAbi = 0;
    const std::wstring missing = CheckProtocolHandshake(block.io());
    CHECK(!missing.empty());
    CHECK(missing.find(L"protocol") != std::wstring::npos);

    // A block created for another layout is refused as well.
    block.io()->structSize = 1234;
    CHECK(!CheckProtocolHandshake(block.io()).empty());

    // This build's payload: nothing to report.
    block.io()->structSize = (LONG)sizeof(SharedIo);
    block.io()->payloadAbi = kProtocolAbi;
    CHECK(CheckProtocolHandshake(block.io()).empty());
}
