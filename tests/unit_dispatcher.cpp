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
//
// What is checked here is the shape of the answers that broke in practice: a
// module with more exports than the reply can carry (A46), a real menu with
// Cyrillic items and separators (A47), the 8.5 counter block of `cmdinfo`
// (A48), and a command line longer than the argument used to survive (A69).

#include "json_check.h"
#include "test_runner.h"

#include "v8inject/protocol.h"
#include "v8inject/text.h"
#include "v8inject/v8i_export.h"

// The bounds and the fragments the dispatcher answers with: the test drives the
// same code the payload runs, not a copy of it.
#include "../src/payload/commands/inspect_commands.h"
#include "../src/payload/platform/cmdinfo_json.h"
#include "../src/payload/reply_fit.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
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
    //
    // The wait pumps this thread's messages. The `menu` command reads windows
    // of this process, and the payload thread runs on its own: GetWindowTextW
    // on a window of another thread is a SendMessage, so a caller that only
    // sleeps deadlocks the payload thread (and the test with it). In 1C the UI
    // thread pumps anyway - this is what the host of the payload looks like.
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
            MSG msg;
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            const LONG state = InterlockedCompareExchange((volatile LONG*)&io_->ready, 0, 0);
            if (state == kStateResponse) break;
            if (state == kStateExit) return false;
            if (GetTickCount() > deadline) return false;
            MsgWaitForMultipleObjects(0, nullptr, FALSE, 2, QS_ALLINPUT);
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

// ---- windows with a real menu bar, for the `menu` command (A47) ----------

const wchar_t kMenuFrameClass[] = L"V8iTestMenuFrame";

ATOM EnsureMenuFrameClass() {
    static ATOM atom = 0;
    if (atom) return atom;
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = kMenuFrameClass;
    atom = RegisterClassExW(&wc);
    return atom;
}

// A window of this process that the payload's `menu` enumerates. `title` may be
// empty: such a window is never taken for the frame, but it still appears in
// the list.
HWND CreateMenuFrame(const wchar_t* title, HWND owner) {
    EnsureMenuFrameClass();
    HWND h = CreateWindowExW(0, kMenuFrameClass, title, WS_OVERLAPPEDWINDOW, 0, 0, 400, 300,
                             owner, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (h && !owner) {
        // The frame is "the first window with a title": the test has to know
        // which one that is.
        SetWindowPos(h, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }
    return h;
}

int CountOf(const std::string& s, const char* needle) {
    int n = 0;
    for (size_t at = s.find(needle); at != std::string::npos; at = s.find(needle, at + 1)) ++n;
    return n;
}

// Validates an answer and, when it does not parse, shows where the break is:
// every defect in this file ends in "the reply is not a JSON document".
void ExpectJson(const char* what, const std::string& reply) {
    std::string err;
    size_t offset = 0;
    if (JsonValid(reply, &err, &offset)) return;
    const size_t from = offset > 120 ? offset - 120 : 0;
    std::printf("      %s is not valid JSON: %s\n      near: [%s]\n", what, err.c_str(),
                reply.substr(from, 260).c_str());
    CHECK(false);
}

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
        // The name of the command is wide, the format is narrow: it goes
        // through the same conversion the rest of the project uses.
        std::wstring cmdWide(cmd);
        std::string cmdNarrow;
        for (wchar_t c : cmdWide) cmdNarrow += (char)(c < 128 ? c : '?');
        std::printf("      %-10s %s in %u ms\n", cmdNarrow.c_str(),
                    answered ? "answered" : "no answer", spent);
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

V8I_TEST(Dispatcher_ScanRejectsBadAddresses) {
    Dispatcher d;
    REQUIRE(d.Start());

    // A41: "scan" takes an address from the command line and calls a vtable
    // there. Every rejection below must come back as a JSON error while the
    // dispatcher - and in a real process, 1C - stays alive.
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    const wchar_t* leaf = wcsrchr(self, L'\\');
    leaf = leaf ? leaf + 1 : self;

    std::wstring cmd = L"scan ";
    cmd += leaf;

    std::string reply;

    // 1) Not mapped at all: the first pages of the address space are free.
    REQUIRE(d.Ask((cmd + L" 1000").c_str(), reply));
    CHECK(reply.find("\"status\":\"error\"") != std::string::npos);
    CHECK(reply.find("not readable") != std::string::npos);

    // 2) Readable, but not a COM object: a static zeroed buffer. Its first
    //    qword is not a pointer at all, let alone a vtable in an image.
    static const char kPlainData[64] = {};
    wchar_t addr[64] = {};
    _snwprintf_s(addr, _countof(addr), _TRUNCATE, L" 0x%llX",
                 (unsigned long long)(uintptr_t)kPlainData);
    REQUIRE(d.Ask((cmd + addr).c_str(), reply));
    CHECK(reply.find("\"status\":\"error\"") != std::string::npos);
    CHECK(reply.find("COM object") != std::string::npos);

    // 3) An unknown module is an error as well.
    REQUIRE(d.Ask(L"scan nosuchmodule.dll 1000", reply));
    CHECK(reply.find("module not found") != std::string::npos);

    // Every answer was valid JSON, and the loop survived all three.
    CHECK(JsonValid(reply));
    REQUIRE(d.Ask(L"version", reply));
    CHECK(reply.find("\"status\":\"ok\"") != std::string::npos);
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

// ---------------------------------------------------------------------------
// A46: `pe` of a module with more exports than the reply carries
// ---------------------------------------------------------------------------

V8I_TEST(Dispatcher_PeOfAModuleWithManyExportsIsJson) {
    Dispatcher d;
    REQUIRE(d.Start());

    // kernel32 is in every process and has well over a thousand exports. The
    // old loop incremented the counter before checking the limit, so the 201st
    // export left a trailing comma: the answer ended with "},]" and a large
    // platform module (core83, config) could not be inspected at all.
    std::string reply;
    REQUIRE(d.Ask(L"pe kernel32.dll", reply, 20000));
    ExpectJson("pe kernel32.dll", reply);
    CHECK(reply.find("\"status\":\"ok\"") != std::string::npos);

    // The reply says that the list is not complete, and carries exactly the
    // documented number of complete items.
    CHECK(reply.find("\"exportCount\":") != std::string::npos);
    CHECK(reply.find("\"exportsTruncated\":true") != std::string::npos);
    CHECK_EQ(CountOf(reply, "\"ordinal\":"), (int)commands::kPeMaxExports);
    // Every item is closed: a truncated list used to end with "},]".
    CHECK(reply.find(",]") == std::string::npos);
}

// ---------------------------------------------------------------------------
// A47: a real menu with Cyrillic text, separators and a submenu
// ---------------------------------------------------------------------------

V8I_TEST(Dispatcher_MenuHidesNothingFromTheJsonDocument) {
    Dispatcher d;
    REQUIRE(d.Start());

    HWND frame = CreateMenuFrame(L"Тест — Конфигурация", nullptr);
    REQUIRE(frame != nullptr);
    // A second window of this process: it is in the list the reply walks, and
    // with an empty title it is never mistaken for the frame.
    HWND other = CreateMenuFrame(L"", frame);
    REQUIRE(other != nullptr);

    HMENU bar = CreateMenu();
    HMENU file = CreatePopupMenu();
    REQUIRE(bar != nullptr && file != nullptr);
    AppendMenuW(file, MF_STRING, 101, L"Открыть конфигурацию");
    AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(file, MF_STRING | MF_GRAYED, 102, L"Закрыть");
    AppendMenuW(bar, MF_POPUP, (UINT_PTR)file, L"Файл");
    AppendMenuW(bar, MF_SEPARATOR, 0, nullptr);
    // A file-base path: the backslashes have to arrive escaped, the old code
    // pasted the text into the JSON string as it was.
    AppendMenuW(bar, MF_STRING, 201, L"База: C:\\Базы\\МояБаза");
    REQUIRE(SetMenu(frame, bar));

    // The visible text of the first item is 22 characters: the whole fragment
    // used to be formatted into a char[64] (a 39-byte prefix plus the text), so
    // even this one was cut inside the string - and mid-character inside a
    // Cyrillic word, because UTF-8 takes two bytes per letter.
    const std::string open = WideToUtf8(L"Открыть конфигурацию");
    const std::string base = WideToUtf8(L"МояБаза");
    const std::string frame_title = WideToUtf8(L"Тест — Конфигурация");

    std::string reply;
    REQUIRE(d.Ask(L"menu", reply, 10000));
    ExpectJson("menu", reply);

    CHECK(reply.find(open) != std::string::npos);
    CHECK(reply.find(base) != std::string::npos);
    CHECK(reply.find(frame_title) != std::string::npos);
    // Escaped, not raw: a backslash inside a JSON string breaks the document.
    CHECK(reply.find("C:\\\\Базы") != std::string::npos);
    // The submenu is nested under its popup, the greyed item says so.
    CHECK(reply.find("\"kind\":\"submenu\"") != std::string::npos);
    CHECK(reply.find("\"depth\":1") != std::string::npos);
    CHECK(reply.find("\"enabled\":false") != std::string::npos);
    // A separator leaves no comma behind.
    CHECK(reply.find(",,") == std::string::npos);
    CHECK(reply.find("[,") == std::string::npos);
    CHECK(reply.find(",]") == std::string::npos);

    // A filter that keeps the frame: the earlier window is dropped and must
    // not leave its comma behind (the old code wrote the comma first).
    std::string by_class;
    REQUIRE(d.Ask((std::wstring(L"menu ") + kMenuFrameClass).c_str(), by_class, 10000));
    ExpectJson("menu <class>", by_class);
    CHECK(by_class.find("\"windows\":[]") == std::string::npos);
    CHECK(by_class.find(",,") == std::string::npos);

    // A filter that matches nothing: an empty list is still a JSON document.
    // The old code answered "[,]": the comma of the second window stayed.
    std::string none;
    REQUIRE(d.Ask(L"menu zzz-nothing-matches-zzz", none, 10000));
    ExpectJson("menu <no match>", none);
    CHECK(none.find("\"windows\":[]") != std::string::npos);

    // The filter is UTF-8 now: a Cyrillic title can be selected by its own text.
    // The window above the frame is dropped here, and the frame that follows it
    // keeps the document valid (the old code answered "[,{...}]").
    std::string cyrillic;
    REQUIRE(d.Ask((std::wstring(L"menu ") + std::wstring(L"Тест")).c_str(), cyrillic, 10000));
    ExpectJson("menu <cyrillic>", cyrillic);
    CHECK(cyrillic.find(frame_title) != std::string::npos);
    CHECK(cyrillic.find(open) != std::string::npos);
    CHECK(cyrillic.find(",,") == std::string::npos);

    DestroyWindow(other);
    DestroyWindow(frame);   // the bar goes with the window
}

// ---------------------------------------------------------------------------
// A48: the counter block of the 8.5 `cmdinfo` reply
// ---------------------------------------------------------------------------

V8I_TEST(CmdInfo_TailOfThe85ReplyIsJson) {
    // The 8.5 branch is only reachable inside a live Configurator; the fragment
    // it appends is a builder of its own, so the test feeds it the values a
    // live 8.5 fills in. "subscribed" used to be followed directly by
    // "qProcFrame" - no comma - and the whole reply of an 8.5 process was
    // therefore unparsable, which is exactly the case the command exists for.
    platform::CmdInfoTail t;
    t.evCount = 17;
    t.evFrame = 0x000001D2A3B4C5D6ULL;
    t.hookOk = 1;
    t.cwHits = 3;
    t.subscribed = 1;
    t.qProcFrame = 0x000001D2A3B4C5E0ULL;
    t.qProcRecv = 0x000001D2A3B4C5E8ULL;
    t.qCmdFrame = 0x000001D2A3B4C5F0ULL;
    t.qCmdRecv = 0x000001D2A3B4C5F8ULL;
    t.qEvFrame = 0x000001D2A3B4C600ULL;
    t.qEvRecv = 0x000001D2A3B4C608ULL;

    const std::string tail = platform::CmdInfoTailJson(t);
    REQUIRE(!tail.empty());
    CHECK(tail[0] == ',');

    // The document as the 8.5 dispatcher builds it: the process object with the
    // resolved `current_process` export, then the counters.
    const std::string doc =
        "{\"status\":\"ok\",\"process\":{\"fn\":\"core85.dll+0x12AB34\",\"path\":"
        "\"C:\\\\Program Files\\\\1cv8\\\\8.5.1.1529\\\\bin\\\\core85.dll\"" +
        tail + "}}";
    ExpectJson("cmdinfo (8.5)", doc);
    CHECK(doc.find("\"subscribed\":1,\"qProcFrame\":") != std::string::npos);
    CHECK(doc.find("\"qProcRecv\":\"0x") != std::string::npos);
    CHECK(doc.find("\"qEvRecv\":\"0x") != std::string::npos);
}

// ---------------------------------------------------------------------------
// A69: a reply is never cut in the middle
// ---------------------------------------------------------------------------

V8I_TEST(ReplyFit_KeepsTheDocumentWholeOrRefusesIt) {
    std::string body(100, 'x');
    char out[128];
    size_t len = 0;

    CHECK(payload::FitReply(body, out, sizeof(out), &len) == payload::kReplyFits);
    CHECK_EQ(len, (size_t)100);
    CHECK(std::string(out) == body);
    CHECK_EQ(std::strlen(out), (size_t)100);

    // Everything the buffer can hold with the terminating NUL fits, one byte
    // more does not: the reply that does not fit is left out entirely.
    std::string edge(sizeof(out) - 1, 'z');
    CHECK(payload::FitReply(edge, out, sizeof(out), &len) == payload::kReplyFits);
    CHECK_EQ(len, sizeof(out) - 1);
    CHECK_EQ(std::strlen(out), sizeof(out) - 1);

    std::string over(sizeof(out), 'z');
    memset(out, 0x7F, sizeof(out));
    CHECK(payload::FitReply(over, out, sizeof(out), &len) == payload::kReplyTooLarge);
    CHECK_EQ(len, sizeof(out));                 // the size is reported for the error
    CHECK_EQ((int)(unsigned char)out[0], 0x7F); // and the buffer is untouched
}

V8I_TEST(Dispatcher_LongCommandLineIsNotCutShort) {
    Dispatcher d;
    REQUIRE(d.Start());

    // A69: the request carries kRequestChars (4096) characters, and the
    // argument used to be copied into wchar_t[1024]. Anything longer was
    // answered for its first quarter, silently: the payload looked like it
    // searched for something else.
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    const wchar_t* leaf = wcsrchr(self, L'\\');
    leaf = leaf ? leaf + 1 : self;

    std::wstring pattern(1500, L'A');
    pattern += L"QZXJKTAIL";
    std::wstring cmd = L"find ";
    cmd += pattern;
    cmd += L" --max 1 --module ";
    cmd += leaf;
    REQUIRE(cmd.size() < kRequestChars);

    std::string reply;
    REQUIRE(d.Ask(cmd.c_str(), reply, 30000));
    ExpectJson("find <1509 characters>", reply);
    // The marker sits past the old 1024-character copy.
    CHECK(reply.find("QZXJKTAIL") != std::string::npos);
    CHECK(reply.find("\"hitCount\":0") != std::string::npos);
}

V8I_TEST(Dispatcher_TooLargeReplyIsAnErrorNotACutDocument) {
    Dispatcher d;
    REQUIRE(d.Start());

    // The response buffer holds kResponseBytes. `find` over one module for the
    // most common byte of a binary finds far more hits than fit: the old code
    // copied the first 511 KB and the host received a document cut in the
    // middle, which it reported as "no answer".
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    const wchar_t* leaf = wcsrchr(self, L'\\');
    leaf = leaf ? leaf + 1 : self;

    std::wstring cmd = L"find \" \" --max 8000 --module ";
    cmd += leaf;

    std::string reply;
    REQUIRE(d.Ask(cmd.c_str(), reply, 60000));
    ExpectJson("find <too many hits>", reply);
    CHECK(reply.find("\"status\":\"error\"") != std::string::npos);
    CHECK(reply.find("response too large") != std::string::npos);

    // The error names what did not fit and the limit it hit.
    const size_t at = reply.find("\"bytes\":");
    REQUIRE(at != std::string::npos);
    const long long bytes = _atoi64(reply.c_str() + at + 8);
    CHECK(bytes > (long long)kResponseBytes - 1);
    CHECK(reply.find("\"limit\":") != std::string::npos);
}


// ---------------------------------------------------------------------------
// A49/A83: the object scanners of the payload on this build
// ---------------------------------------------------------------------------

namespace {

// A real C++ object with a vtable from this image: both scanners classify a
// vtable pointer by asking "does it land inside a module", so the probe has to
// be genuinely virtual. The handle at the end is what `byhwnd` searches for.
class ScanProbe {
public:
    virtual ~ScanProbe() = default;
    virtual int One() { return 1; }
    virtual int Two() { return 2; }
    virtual int Three() { return 3; }
    virtual int Four() { return 4; }
    HWND hwnd = nullptr;
};

uintptr_t FirstPointerOf(const void* obj) {
    uintptr_t v = 0;
    memcpy(&v, obj, sizeof(v));
    return v;
}

std::string HexAddress(uintptr_t v) {
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%llX", (unsigned long long)v);
    return buf;
}

}  // namespace

V8I_TEST(Dispatcher_ScannerCountsRejectNegative) {
    Dispatcher d;
    REQUIRE(d.Start());

    std::string reply;

    // A83: "-1" used to be cast to size_t and became SIZE_MAX, so `find --max
    // -1` collected hits until the address space ran out. It is a usage error
    // now, and the answer names the flag.
    REQUIRE(d.Ask(L"find QZXJKNOSUCHPATTERN --max -1", reply, 30000));
    ExpectJson("find --max -1", reply);
    REQUIRE(reply.find("\"status\":\"error\"") != std::string::npos);
    CHECK(reply.find("--max") != std::string::npos);

    // The same parser serves the scanner commands; each refuses a count that is
    // not a plain number before it starts walking memory.
    REQUIRE(d.Ask(L"memmap --count -1", reply, 10000));
    ExpectJson("memmap --count -1", reply);
    CHECK(reply.find("\"status\":\"error\"") != std::string::npos);

    REQUIRE(d.Ask(L"heapobjects --count -1", reply, 10000));
    ExpectJson("heapobjects --count -1", reply);
    CHECK(reply.find("\"status\":\"error\"") != std::string::npos);

    REQUIRE(d.Ask(L"findvalue 0x7F4D2E0B --count -1", reply, 30000));
    ExpectJson("findvalue --count -1", reply);
    CHECK(reply.find("\"status\":\"error\"") != std::string::npos);

    // `--offset -1` used to make the backward walk of byhwnd iterate to
    // SIZE_MAX: refusing it before the scan is the only safe answer.
    REQUIRE(d.Ask(L"byhwnd 1 --offset -1", reply, 10000));
    ExpectJson("byhwnd --offset -1", reply);
    CHECK(reply.find("\"status\":\"error\"") != std::string::npos);

    // A count past the per-command cap is refused as well, not silently
    // clamped: the caller has to know that the reply would not be what it asked.
    REQUIRE(d.Ask(L"find QZXJKNOSUCHPATTERN --max 999999", reply, 10000));
    CHECK(reply.find("\"status\":\"error\"") != std::string::npos);
    REQUIRE(d.Ask(L"byhwnd 1 --offset 0x2000", reply, 10000));
    CHECK(reply.find("\"status\":\"error\"") != std::string::npos);

    // The dispatcher survives all of it.
    REQUIRE(d.Ask(L"version", reply));
    CHECK(reply.find("\"status\":\"ok\"") != std::string::npos);
}

V8I_TEST(Dispatcher_HeapObjectsFindsObjectsOnThisBuild) {
    Dispatcher d;
    REQUIRE(d.Start());

    // The probe stays alive while the command runs: heapobjects scans this very
    // process, and the object carries a vtable of the test image.
    auto probe = std::make_unique<ScanProbe>();
    const uintptr_t probeAddr = (uintptr_t)probe.get();
    CHECK(probeAddr != 0);
    CHECK(FirstPointerOf(probe.get()) != 0);

    std::string reply;
    REQUIRE(d.Ask(L"heapobjects --count 100000", reply, 60000));
    ExpectJson("heapobjects", reply);
    CHECK(reply.find("\"status\":\"ok\"") != std::string::npos);

    // The x64 bug answered "objects":0 / "classes":0 for every module: the
    // 32-bit read of a 64-bit vtable pointer could never fall inside the image.
    CHECK(reply.find("\"objects\":0") == std::string::npos);
    CHECK(reply.find("\"classes\":0") == std::string::npos);
}

V8I_TEST(Dispatcher_ByHwndFindsTheOwnerOnThisBuild) {
    Dispatcher d;
    REQUIRE(d.Start());

    HWND frame = CreateMenuFrame(L"V8i byhwnd probe", nullptr);
    REQUIRE(frame != nullptr);
    auto probe = std::make_unique<ScanProbe>();
    probe->hwnd = frame;

    // The handle is written in the same hex notation the command documents.
    wchar_t hwndHex[32] = {};
    _snwprintf_s(hwndHex, _countof(hwndHex), _TRUNCATE, L"0x%llX",
                 (unsigned long long)(uintptr_t)frame);

    std::wstring cmd = L"byhwnd ";
    cmd += hwndHex;
    cmd += L" --count 64";
    std::string reply;
    REQUIRE(d.Ask(cmd.c_str(), reply, 60000));
    ExpectJson("byhwnd", reply);
    CHECK(reply.find("\"status\":\"ok\"") != std::string::npos);

    // The reply names the object address and the real distance from the handle
    // back to it: one machine word.
    const std::string addr = "\"addr\":\"0x" + HexAddress((uintptr_t)probe.get()) + "\"";
    CHECK(reply.find(addr) != std::string::npos);
    char off[40];
    _snprintf_s(off, sizeof(off), _TRUNCATE, "\"offset\":%llu",
                (unsigned long long)sizeof(void*));
    CHECK(reply.find(off) != std::string::npos);

    DestroyWindow(frame);
}
