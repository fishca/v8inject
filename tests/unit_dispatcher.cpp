// The command dispatcher of the payload.
//
// The payload answers about forty commands, and every one of them was
// reachable only through a live 1C. The command loop takes the shared block
// as an argument, so the test can run the real dispatcher against a block of
// its own - and then the answers can be checked as what they are: JSON.
//
// The commands that need the platform (the designer commands, the menu) are
// not checked here: without a Configurator behind them they answer with an
// error, and that error is the expected behaviour anyway.

#include "json_check.h"
#include "test_runner.h"

#include "v8inject/protocol.h"
#include "v8inject/v8i_export.h"

#include <atomic>
#include <thread>

using namespace v8i;
using namespace v8i::test;

namespace {

// Runs the payload's command loop on a block of the test's own and plays the
// host against it.
class Dispatcher {
public:
    ~Dispatcher() { Stop(); }

    bool Start() {
        wchar_t name[64] = {};
        MakeSharedName(name, _countof(name), GetCurrentProcessId() + 0x7100);

        hMap_ = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                   0, (DWORD)sizeof(SharedIo), name);
        if (!hMap_) return false;
        io_ = (SharedIo*)MapViewOfFile(hMap_, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedIo));
        if (!io_) { CloseHandle(hMap_); hMap_ = nullptr; return false; }
        io_->ready = kStateIdle;
        io_->request[0] = 0;
        io_->response[0] = 0;

        thread_ = std::thread([this] { V8iRunCommandLoop(io_); });
        return true;
    }

    void Stop() {
        if (!thread_.joinable()) return;
        InterlockedExchange((volatile LONG*)&io_->ready, kStateExit);
        thread_.join();
        if (io_) { UnmapViewOfFile(io_); io_ = nullptr; }
        if (hMap_) { CloseHandle(hMap_); hMap_ = nullptr; }
    }

    // Sends a command and waits for the answer.
    bool Ask(const wchar_t* command, std::string& reply, int timeoutMs = 5000) {
        size_t n = 0;
        while (command[n] && n + 1 < kRequestChars) { io_->request[n] = command[n]; ++n; }
        io_->request[n] = 0;
        io_->requestLen = (LONG)(n + 1);
        io_->responseLen = 0;
        io_->response[0] = 0;
        InterlockedExchange((volatile LONG*)&io_->ready, kStateRequest);

        const DWORD deadline = GetTickCount() + (DWORD)timeoutMs;
        for (;;) {
            const LONG state = InterlockedCompareExchange((volatile LONG*)&io_->ready, 0, 0);
            if (state == kStateResponse) break;
            if (state == kStateExit) return false;
            if (GetTickCount() > deadline) return false;
            Sleep(2);
        }
        LONG len = io_->responseLen;
        if (len < 0 || (size_t)len >= kResponseBytes) len = (LONG)(kResponseBytes - 1);
        reply.assign(io_->response, (size_t)len);
        return true;
    }

    // True when the payload has left the loop (it sets the exit state).
    bool Exited() const {
        return InterlockedCompareExchange((volatile LONG*)&io_->ready, 0, 0) == kStateExit;
    }

private:
    HANDLE hMap_ = nullptr;
    SharedIo* io_ = nullptr;
    std::thread thread_;
};

}  // namespace

V8I_TEST(Dispatcher_Version) {
    Dispatcher d;
    REQUIRE(d.Start());

    std::string reply;
    REQUIRE(d.Ask(L"version", reply));
    CHECK(reply.find("\"status\":\"ok\"") != std::string::npos);
    CHECK(reply.find("\"pointerSize\":") != std::string::npos);
}

V8I_TEST(Dispatcher_EveryAnswerIsValidJson) {
    Dispatcher d;
    REQUIRE(d.Start());

    // The read-only commands: they work without a Configurator behind them.
    const wchar_t* commands[] = {
        L"version",
        L"cmdinfo",
        L"frames",
        L"mods",
        L"memmap",
        L"imports",
        L"exports",
        L"find",
        L"peek",
        L"pe",
        L"objects",
        L"hooks",
        L"trace",
        L"gitbar",
        L"menu",
    };

    for (const wchar_t* cmd : commands) {
        std::string reply;
        const DWORD started = GetTickCount();
        // The heavy commands (a scan of the whole address space) need more
        // than the default: on a slow CI runner they do not fit into a few
        // seconds.
        const int timeout = (wcscmp(cmd, L"find") == 0) ? 60000 : 10000;
        const bool answered = d.Ask(cmd, reply, timeout);
        const DWORD spent = GetTickCount() - started;
        std::printf("      %-10s %s in %u ms\n", cmd, answered ? "answered" : "no answer",
                    spent);
        if (!answered) {
            CHECK(reply.size() > 0);           // no answer at all
            continue;
        }
        std::string err;
        size_t offset = 0;
        if (!JsonValid(reply, &err, &offset)) {
            // The name of the command and the place of the break are the
            // whole point of the message.
            std::string what = "answer to ";
            for (const wchar_t* p = cmd; *p; ++p) what += (char)*p;
            what += " is not valid JSON: ";
            what += err;
            CHECK(false);
            const size_t from = offset > 70 ? offset - 70 : 0;
            std::printf("      %s\n      near: [%s]\n      byte at %zu: %d\n", what.c_str(),
                        reply.substr(from, 150).c_str(), offset,
                        offset < reply.size() ? (int)(unsigned char)reply[offset] : -1);
            // The whole answer goes to a file: a broken answer is worth
            // looking at with another parser.
            wchar_t tmp[MAX_PATH] = {};
            GetTempPathW(MAX_PATH, tmp);
            std::wstring path = std::wstring(tmp) + L"v8i_bad_answer.json";
            for (const wchar_t* p = cmd; *p; ++p) {
                if (*p == L' ') path += L'_';
                else path += (wchar_t)tolower(*p);
            }
            path += L".json";
            FILE* f = nullptr;
            if (_wfopen_s(&f, path.c_str(), L"wb") == 0 && f) {
                fwrite(reply.data(), 1, reply.size(), f);
                fclose(f);
                std::printf("      saved to %ls\n", path.c_str());
            }
        }
        // The answer has to say something about itself.
        CHECK(reply.find("\"status\"") != std::string::npos);
    }
}

V8I_TEST(Dispatcher_UnknownCommandIsAnError) {
    Dispatcher d;
    REQUIRE(d.Start());

    std::string reply;
    REQUIRE(d.Ask(L"nosuchcommand", reply));
    CHECK(reply.find("\"status\":\"error\"") != std::string::npos);
}

V8I_TEST(Dispatcher_ImportsOfTheTestBinary) {
    Dispatcher d;
    REQUIRE(d.Start());

    // The payload reads the PE of the module it is asked about: the test
    // binary is right there.
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    const std::wstring leaf(self);

    std::string reply;
    REQUIRE(d.Ask(L"imports", reply));
    CHECK(reply.find("\"status\":\"ok\"") != std::string::npos);
    // The imports of the test binary are in the answer.
    CHECK(reply.find("KERNEL32") != std::string::npos ||
          reply.find("kernel32") != std::string::npos);
}

V8I_TEST(Dispatcher_ExitEndsTheLoop) {
    Dispatcher d;
    REQUIRE(d.Start());

    std::string reply;
    REQUIRE(d.Ask(L"version", reply));

    // "exit" ends the loop without an answer: the payload sets the exit
    // state and stops, and the host waits for the thread, not for a reply.
    d.Ask(L"exit", reply, 500);
    bool ended = false;
    for (int i = 0; i < 200 && !ended; ++i) {
        ended = d.Exited();
        if (!ended) Sleep(5);
    }
    CHECK(ended);
}
