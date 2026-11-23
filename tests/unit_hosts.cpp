// The hosts: the CLI watcher, the GUI and the tray agent (docs/AUDIT.md A56,
// A61, A62, A64, A80, A81, A82).
//
//  * `watch` fires once per dump, not once per run (A56);
//  * the settings dialog of the GUI does not eat the WM_QUIT of the main
//    window, and it disables the main window while it is up (A61);
//  * the modal loop, the worker thread of the GUI and the DPI scaling are
//    exercised on real windows: no 1C is needed for any of them (A61, A80,
//    A81);
//  * the agent tells a reused pid apart, retries a failed attempt and reads its
//    autostart checkbox from the registry (A62, A82);
//  * the GitBar settings of the GUI go through v8i::IniSet, so a fresh profile
//    gets the folder and a UTF-16 file, and a failed write is reported (A64).

#include "test_runner.h"

#include "cli/watch_state.h"
#include "host/agent_state.h"
#include "host/autostart.h"
#include "host/gui_settings.h"
#include "host/ui_job.h"
#include "host/ui_layout.h"
#include "host/ui_loop.h"

#include <windows.h>

#include <functional>
#include <string>
#include <vector>

using namespace v8i;
using namespace v8i::test;

namespace {

// --- a test window that reports what happened to it -------------------------

constexpr UINT kMsgQuery = WM_APP + 50;   // asks the window to look around
constexpr UINT kMsgJobDone = WM_APP + 60; // the completion message of a job

struct HostsTestState {
    UiJob* job = nullptr;
    HWND owner = nullptr;
    bool done = false;
    WPARAM doneParam = 0;
    bool ownerEnabledAtQuery = true;
    bool destroyOnQuery = false;
};

HostsTestState g_ht;

LRESULT CALLBACK HostsTestProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case kMsgQuery:
        g_ht.ownerEnabledAtQuery = g_ht.owner ? IsWindowEnabled(g_ht.owner) != FALSE : true;
        if (g_ht.destroyOnQuery) DestroyWindow(h);
        return 0;

    case kMsgJobDone:
        g_ht.doneParam = wp;
        if (g_ht.job && g_ht.job->Finish(wp, kMsgJobDone)) g_ht.done = true;
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

HWND MakeHostsWindow() {
    static bool registered = false;
    if (!registered) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = HostsTestProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"V8iHostsTest";
        if (!RegisterClassW(&wc))
            std::fprintf(stderr, "RegisterClass: win32=%lu\n", GetLastError());
        registered = true;
    }
    return CreateWindowExW(0, L"V8iHostsTest", L"hosts test", WS_POPUP, 0, 0, 20, 20,
                           nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
}

// Pumps this thread's messages until `done()` or the timeout.
bool PumpUntil(const std::function<bool()>& done, int timeoutMs) {
    const ULONGLONG start = GetTickCount64();
    MSG msg{};
    while (GetTickCount64() - start < (ULONGLONG)timeoutMs) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) return done();
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if (done()) return true;
        Sleep(5);
    }
    return done();
}

std::wstring TempDir() {
    wchar_t buf[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, buf);
    std::wstring dir = buf;
    while (!dir.empty() && dir.back() == L'\\') dir.pop_back();
    return dir;
}

std::wstring ScratchRoot(const wchar_t* leaf) {
    wchar_t name[128];
    _snwprintf_s(name, _countof(name), _TRUNCATE, L"v8i_hosts_%lu_%ls",
                 GetCurrentProcessId(), leaf);
    return TempDir() + L"\\" + name;
}

}  // namespace

// ---------------------------------------------------------------------------
// A56: the watcher rearms after every dump
// ---------------------------------------------------------------------------

V8I_TEST(Watch_FiresOncePerDumpAndRearms) {
    WatchGate gate;
    gate.Match(1000);
    CHECK(!gate.Due(1000, 8000));
    CHECK(!gate.Due(1000 + 8000, 8000));      // exactly the debounce: not quiet yet
    CHECK(gate.Due(1000 + 8001, 8000));
    gate.Fired();
    CHECK(!gate.Due(20000, 8000));            // the command of this dump has run

    // Without the rearm the second dump was watched but never fired, and the
    // process sat until --timeout-sec (A56).
    gate.Rearm();
    CHECK(!gate.Due(30000, 8000));            // no new writes yet
    gate.Match(30000);
    CHECK(!gate.Due(30000 + 8000, 8000));
    CHECK(gate.Due(30000 + 8001, 8000));
    gate.Fired();
    CHECK_EQ(gate.fireCount, 2);
}

V8I_TEST(Watch_DoesNotFireWhileTheDumpKeepsWriting) {
    WatchGate gate;
    for (int i = 0; i < 50; ++i) {
        const uint64_t now = 1000 + (uint64_t)i * 200;
        gate.Match(now);
        CHECK(!gate.Due(now, 8000));
    }
    CHECK_EQ(gate.matchCount, 50);
    CHECK(gate.Due(1000 + 49 * 200 + 8001, 8000));
}

V8I_TEST(Watch_OnceIsNotRearmed) {
    WatchGate gate;
    gate.Match(1000);
    CHECK(gate.Due(9001, 8000));
    gate.Fired();
    gate.Match(20000);          // --once stops here; nothing is rearmed
    CHECK(!gate.Due(40000, 8000));
    CHECK_EQ(gate.fireCount, 1);
}

V8I_TEST(Watch_CacheRetriesAFailedDecodeAfterItsWindow) {
    WatchPathCache cache;
    cache.Store(0x1000, std::wstring(), 1000);      // `str` failed
    CHECK_EQ(cache.Size(), (size_t)1);

    const std::wstring* p = cache.Find(0x1000, 1000 + 10);
    REQUIRE(p != nullptr);                          // known bad: no second call
    CHECK(p->empty());
    CHECK(cache.Find(0x1000, 1000 + WatchPathCache::kRetryMs + 1) == nullptr);
    CHECK(cache.Find(0x2000, 1000) == nullptr);   // never asked

    cache.Store(0x1000, L"C:\\dump\\main.txt", 40000);
    p = cache.Find(0x1000, 40010);
    REQUIRE(p != nullptr);
    CHECK_EQ(*p, std::wstring(L"C:\\dump\\main.txt"));
}

V8I_TEST(Watch_CacheEvictsTheLeastRecentlyUsedAndStaysBounded) {
    WatchPathCache cache;
    const size_t n = WatchPathCache::kCapacity;
    for (size_t i = 1; i <= n; ++i) cache.Store(i, L"path" + std::to_wstring(i), 1000);
    CHECK_EQ(cache.Size(), n);

    // Touch the first entry, so the second one is the least recently used.
    CHECK(cache.Find(1, 2000) != nullptr);
    cache.Store(n + 1, L"new", 3000);
    CHECK_EQ(cache.Size(), n);                       // no growth
    CHECK(cache.Find(1, 2000) != nullptr);           // the touched one stayed
    CHECK(cache.Find(2, 2000) == nullptr);   // ... and the LRU went
    CHECK(cache.Find(n + 1, 2000) != nullptr);
}

// ---------------------------------------------------------------------------
// A61: the modal loop of the GUI keeps the owner off and hands the quit back
// ---------------------------------------------------------------------------

V8I_TEST(Gui_ModalLoopHandsTheQuitBackToTheMainLoop) {
    HWND owner = MakeHostsWindow();
    HWND dlg = MakeHostsWindow();
    REQUIRE(owner != nullptr);
    REQUIRE(dlg != nullptr);
    g_ht.owner = owner;
    g_ht.destroyOnQuery = false;

    PostQuitMessage(9);   // what WM_DESTROY of the main window posts
    CHECK_EQ(PumpOwnedModalLoop(dlg, owner), 9);
    CHECK(IsWindow(dlg) != FALSE);                   // the dialog is left alone
    CHECK(IsWindowEnabled(owner) != FALSE);          // and the owner is on again

    // The quit is still in the queue: the old loop ate it, and the main loop
    // then waited forever with no window left (A61).
    MSG msg{};
    bool found = false;
    while (PeekMessageW(&msg, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
        found = true;
        CHECK_EQ((int)msg.wParam, 9);
    }
    CHECK(found);

    g_ht.owner = nullptr;
    DestroyWindow(dlg);
    DestroyWindow(owner);
}

V8I_TEST(Gui_ModalLoopDisablesTheOwnerWhileTheDialogIsUp) {
    HWND owner = MakeHostsWindow();
    HWND dlg = MakeHostsWindow();
    REQUIRE(owner != nullptr);
    REQUIRE(dlg != nullptr);
    EnableWindow(owner, TRUE);
    g_ht.owner = owner;
    g_ht.ownerEnabledAtQuery = true;
    g_ht.destroyOnQuery = true;

    PostMessageW(dlg, kMsgQuery, 0, 0);   // dispatched by the loop, then it closes
    CHECK_EQ(PumpOwnedModalLoop(dlg, owner), 0);
    CHECK(!g_ht.ownerEnabledAtQuery);                 // the buttons were off
    CHECK(IsWindowEnabled(owner) != FALSE);           // ... and are back after
    CHECK(!IsWindow(dlg));

    g_ht.owner = nullptr;
    g_ht.destroyOnQuery = false;
    DestroyWindow(owner);
}

V8I_TEST(Gui_ModalLoopReturnsWhenTheDialogDies) {
    HWND owner = MakeHostsWindow();
    HWND dlg = MakeHostsWindow();
    REQUIRE(owner != nullptr);
    REQUIRE(dlg != nullptr);
    g_ht.owner = owner;
    g_ht.destroyOnQuery = true;

    PostMessageW(dlg, kMsgQuery, 0, 0);
    CHECK_EQ(PumpOwnedModalLoop(dlg, owner), 0);
    CHECK(!IsWindow(dlg));
    CHECK(IsWindowEnabled(owner) != FALSE);

    g_ht.owner = nullptr;
    g_ht.destroyOnQuery = false;
    DestroyWindow(owner);
}

// ---------------------------------------------------------------------------
// A80: a blocking job runs on a worker thread and reports with a message
// ---------------------------------------------------------------------------

V8I_TEST(Gui_JobRunsOffTheUiThreadAndReportsBack) {
    HWND h = MakeHostsWindow();
    REQUIRE(h != nullptr);

    UiJob job;
    g_ht.job = &job;
    g_ht.done = false;
    g_ht.doneParam = 0;
    const DWORD uiThread = GetCurrentThreadId();
    DWORD workerThread = 0;
    int result = 0;

    const ULONGLONG t0 = GetTickCount64();
    REQUIRE(job.Start(h, kMsgJobDone, [&]() {
        Sleep(300);
        workerThread = GetCurrentThreadId();
        result = 42;
    }));
    CHECK(GetTickCount64() - t0 < 150);   // the caller did not wait for the work
    CHECK(job.Busy());

    CHECK(PumpUntil([] { return g_ht.done; }, 5000));
    CHECK(workerThread != uiThread);   // the work ran on another thread
    CHECK_EQ(result, 42);
    CHECK(!job.Busy());
    // A second Finish of the same message finds nothing to join.
    CHECK(!job.Finish(g_ht.doneParam, kMsgJobDone));

    g_ht.job = nullptr;
    DestroyWindow(h);
}

V8I_TEST(Gui_SecondJobIsRefusedWhileTheFirstRuns) {
    HWND h = MakeHostsWindow();
    REQUIRE(h != nullptr);
    UiJob job;
    g_ht.job = &job;
    g_ht.done = false;

    REQUIRE(job.Start(h, kMsgJobDone, [] { Sleep(200); }));
    CHECK(!job.Start(h, kMsgJobDone, [] {}));
    CHECK(PumpUntil([] { return g_ht.done; }, 5000));
    CHECK(!job.Busy());

    g_ht.job = nullptr;
    DestroyWindow(h);
}

V8I_TEST(Gui_StopWaitsForTheRunningJob) {
    HWND h = MakeHostsWindow();
    REQUIRE(h != nullptr);
    UiJob job;
    g_ht.job = &job;
    g_ht.done = false;

    REQUIRE(job.Start(h, kMsgJobDone, [] { Sleep(200); }));
    const ULONGLONG t0 = GetTickCount64();
    job.Stop();
    CHECK(GetTickCount64() - t0 >= 150);   // it waited for the worker
    CHECK(!job.Busy());

    // The completion message may already be in the queue: drop it before the
    // job (and the window it points at) goes away.
    MSG msg{};
    while (PeekMessageW(&msg, nullptr, kMsgJobDone, kMsgJobDone, PM_REMOVE)) {
    }
    g_ht.job = nullptr;
    DestroyWindow(h);
}

// ---------------------------------------------------------------------------
// A81: the layout follows the DPI of the monitor
// ---------------------------------------------------------------------------

V8I_TEST(Gui_DpiScaleFollowsTheMonitor) {
    CHECK_EQ(DpiScale(12, 96), 12);
    CHECK_EQ(DpiScale(12, 144), 18);      // 150%
    CHECK_EQ(DpiScale(12, 192), 24);      // 200%
    CHECK_EQ(DpiScale(12, 0), 12);        // an unknown DPI means 96
    CHECK_EQ(DpiScale(1, 144), 2);        // MulDiv rounds to the nearest pixel
    CHECK(WindowDpi(nullptr) > 0);
}

V8I_TEST(Gui_AnchorsAreScaledToTheDpi) {
    HWND parent = MakeHostsWindow();
    REQUIRE(parent != nullptr);
    HWND child = CreateWindowExW(0, L"STATIC", L"x", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10,
                                 parent, nullptr, GetModuleHandleW(nullptr), nullptr);
    REQUIRE(child != nullptr);

    const std::vector<UiAnchor> anchors = { { child, 10, 20, 30, 40 } };
    RECT rc{};
    ApplyAnchors(anchors, 96);
    GetWindowRect(child, &rc);
    CHECK_EQ((int)(rc.right - rc.left), 30);
    CHECK_EQ((int)(rc.bottom - rc.top), 40);

    // 200%: the box doubles, the form looks the same.
    ApplyAnchors(anchors, 192);
    GetWindowRect(child, &rc);
    CHECK_EQ((int)(rc.left), 20);
    CHECK_EQ((int)(rc.top), 40);
    CHECK_EQ((int)(rc.right - rc.left), 60);
    CHECK_EQ((int)(rc.bottom - rc.top), 80);

    DestroyWindow(child);
    DestroyWindow(parent);
}

// ---------------------------------------------------------------------------
// A62: the agent forgets a gone process and notices a reused pid
// ---------------------------------------------------------------------------

V8I_TEST(Agent_ReusedPidIsANewProcess) {
    AgentTracker tr;
    const uint32_t pid = 4321;
    const uint64_t first = 1000000;
    const uint64_t second = 2000000;   // another process on the same pid

    CHECK(tr.Decide(pid, first, 0) == AgentDecision::Inject);
    tr.Injected(pid, first);
    CHECK(tr.Decide(pid, first, 0) == AgentDecision::Skip);
    CHECK(tr.WasInjected(pid, first));
    // The reused pid used to be skipped forever as "already injected" (A62).
    CHECK(tr.Decide(pid, second, 0) == AgentDecision::Inject);
    CHECK(!tr.WasInjected(pid, second));
}

// A152: an entry born without a creation time (the process was still starting)
// adopts the first valid one, so a reused pid does not inherit the exhausted
// failure count of its predecessor.
V8I_TEST(Agent_FailedEntryAdoptsTheFirstCreationTime) {
    AgentTracker tr;
    const uint32_t pid = 555;
    const uint64_t created = 9000000;

    for (int i = 0; i < AgentTracker::kMaxFailures; ++i) tr.Failed(pid, 0, 1000);
    CHECK(tr.Decide(pid, 0, 60000) == AgentDecision::Skip);   // gave up on the unknown

    tr.Failed(pid, created, 60000);   // the creation time is readable at last
    const AgentEntry* e = tr.Find(pid);
    REQUIRE(e != nullptr);
    CHECK_EQ((unsigned long long)e->created, (unsigned long long)created);

    // A different creation time on the same pid is a new process, not the
    // predecessor that exhausted its retries.
    CHECK(tr.Decide(pid, created + 1, 60000) == AgentDecision::Inject);
}

V8I_TEST(Agent_ATransientFailureIsRetriedWithABackoff) {
    AgentTracker tr;
    const uint32_t pid = 777;
    const uint64_t created = 42;

    CHECK(tr.Decide(pid, created, 1000) == AgentDecision::Inject);
    tr.Failed(pid, created, 1000);
    CHECK_EQ((long long)tr.BackoffMs(1), 2000);
    CHECK(tr.Decide(pid, created, 1000) == AgentDecision::WaitForRetry);
    CHECK(tr.Decide(pid, created, 2999) == AgentDecision::WaitForRetry);
    CHECK(tr.Decide(pid, created, 3000) == AgentDecision::Inject);   // 1C has started

    for (int i = 0; i < AgentTracker::kMaxFailures; ++i) tr.Failed(pid, created, 5000);
    CHECK(tr.Decide(pid, created, 60000) == AgentDecision::Skip);    // gave up, bounded
    CHECK(!tr.WasInjected(pid, created));

    tr.Injected(pid, created);
    CHECK(tr.WasInjected(pid, created));
    CHECK_EQ(tr.Size(), (size_t)1);
}

V8I_TEST(Agent_PruneDropsGoneAndReusedProcesses) {
    const uint32_t pid = GetCurrentProcessId();
    const uint64_t created = ProcessCreated(pid);
    REQUIRE(created != 0);
    CHECK(ProcessAlive(pid, created));
    CHECK(!ProcessAlive(pid, created + 1));    // the pid is not the process
    CHECK(!ProcessAlive(0, 0));

    AgentTracker tr;
    tr.Injected(pid, created);
    CHECK_EQ(tr.Prune({ pid }), (size_t)0);
    CHECK_EQ(tr.Size(), (size_t)1);

    tr.Injected(pid, created + 1);             // stale: the pid was reused
    CHECK_EQ(tr.Prune({ pid }), (size_t)1);
    CHECK_EQ(tr.Size(), (size_t)0);

    tr.Injected(pid, created);
    CHECK_EQ(tr.Prune({ pid + 1 }), (size_t)1);   // not in the process list at all
    CHECK_EQ(tr.Size(), (size_t)0);
}

// ---------------------------------------------------------------------------
// A82: the Run value is quoted, checked and read back from the registry
// ---------------------------------------------------------------------------

V8I_TEST(Agent_RunValueIsQuotedWhenThePathNeedsIt) {
    // A path without blanks stays as it is: a quoted switch is not a switch.
    CHECK_EQ(AutostartCommandLine(L"C:\\Tools\\v8inject-agent.exe"),
             std::wstring(L"C:\\Tools\\v8inject-agent.exe"));
    // This one used to start "C:\\Program.exe" and the agent never came up.
    CHECK_EQ(AutostartCommandLine(L"C:\\Program Files\\v8inject\\v8inject-agent.exe"),
             std::wstring(L"\"C:\\Program Files\\v8inject\\v8inject-agent.exe\""));
    // A trailing backslash is doubled inside the quotes, as CommandLineToArgvW
    // expects.
    CHECK_EQ(AutostartCommandLine(L"C:\\dir with space\\"),
             std::wstring(L"\"C:\\dir with space\\\\\""));
    CHECK(AutostartCommandLine(L"").empty());
}

V8I_TEST(Agent_RunKeyIsWrittenAndReadBack) {
    wchar_t sub[512];
    _snwprintf_s(sub, _countof(sub), _TRUNCATE, L"Software\\v8inject-tests\\run-%lu",
                 GetCurrentProcessId());
    RegDeleteTreeW(HKEY_CURRENT_USER, sub);

    const std::wstring exe = L"C:\\Program Files\\v8inject\\x64\\v8inject-agent.exe";
    std::wstring error;
    CHECK(AutostartSet(HKEY_CURRENT_USER, sub, kRunValueName, exe, true, &error));
    CHECK(error.empty());
    CHECK(AutostartActive(HKEY_CURRENT_USER, sub, kRunValueName));
    CHECK_EQ(AutostartValue(HKEY_CURRENT_USER, sub, kRunValueName),
             std::wstring(L"\"C:\\Program Files\\v8inject\\x64\\v8inject-agent.exe\""));

    // The checkbox reads the registry: written means on, removed means off.
    CHECK(AutostartSet(HKEY_CURRENT_USER, sub, kRunValueName, exe, false, &error));
    CHECK(error.empty());
    CHECK(!AutostartActive(HKEY_CURRENT_USER, sub, kRunValueName));
    CHECK(AutostartValue(HKEY_CURRENT_USER, sub, kRunValueName).empty());

    RegDeleteTreeW(HKEY_CURRENT_USER, sub);
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\v8inject-tests");
}

V8I_TEST(Agent_RunKeyFailureIsReported) {
    std::wstring error;
    // No root, no key: the caller must learn that nothing was written (A82).
    CHECK(!AutostartSet(nullptr, L"Software\\x", kRunValueName, L"C:\\a.exe", true, &error));
    CHECK(!error.empty());
    CHECK(!AutostartSet(HKEY_CURRENT_USER, nullptr, kRunValueName, L"C:\\a.exe", true, &error));
    CHECK(!error.empty());
    CHECK(!AutostartSet(HKEY_CURRENT_USER, L"Software\\v8inject-tests\\empty", kRunValueName,
                        L"", true, &error));
    CHECK(!error.empty());
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\v8inject-tests");
}

// ---------------------------------------------------------------------------
// A64: the GitBar settings of the GUI are written through v8i::IniSet
// ---------------------------------------------------------------------------

V8I_TEST(Gui_SettingsAreWrittenIntoAMissingFolder) {
    const std::wstring root = ScratchRoot(L"settings");
    const std::wstring folder = root + L"\\scratch";
    const std::wstring ini = folder + L"\\gitbar.ini";
    DeleteFileW(ini.c_str());
    RemoveDirectoryW(folder.c_str());
    RemoveDirectoryW(root.c_str());

    GitBarSettings s;
    s.gitPath = L"C:\\Program Files\\Git\\cmd\\git.exe";
    s.dumpDir = L"E:\\выгрузка\\конфигурации";
    s.commitMessage = L"Выгрузка конфигурации";
    s.remote = L"origin";
    std::wstring error;
    // On a fresh profile the folder did not exist: every WritePrivateProfile
    // call failed and the dialog said "saved" anyway (A64).
    CHECK(SaveGitBarSettings(ini.c_str(), s, &error));
    CHECK(error.empty());
    CHECK(GetFileAttributesW(ini.c_str()) != INVALID_FILE_ATTRIBUTES);

    HANDLE f = CreateFileW(ini.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    unsigned char head[2] = {};
    DWORD got = 0;
    CHECK(ReadFile(f, head, 2, &got, nullptr) != FALSE);
    CloseHandle(f);
    CHECK_EQ((int)head[0], 0xFF);   // UTF-16 with a byte order mark, as IniSet writes
    CHECK_EQ((int)head[1], 0xFE);

    const GitBarSettings back = LoadGitBarSettings(ini.c_str());
    CHECK_EQ(back.gitPath, s.gitPath);
    CHECK_EQ(back.dumpDir, s.dumpDir);
    CHECK_EQ(back.commitMessage, s.commitMessage);
    CHECK_EQ(back.remote, s.remote);

    DeleteFileW(ini.c_str());
    RemoveDirectoryW(folder.c_str());
    RemoveDirectoryW(root.c_str());
}

V8I_TEST(Gui_SettingsFailureIsReported) {
    const std::wstring root = ScratchRoot(L"blocked");
    CreateDirectoryW(root.c_str(), nullptr);
    const std::wstring blocker = root + L"\\blocker";
    HANDLE f = CreateFileW(blocker.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    CloseHandle(f);

    GitBarSettings s;
    s.gitPath = L"git";
    std::wstring error;
    // The path goes through a file: nothing can be created there.
    CHECK(!SaveGitBarSettings((blocker + L"\\gitbar.ini").c_str(), s, &error));
    CHECK(!error.empty());
    CHECK(!SaveGitBarSettings(L"", s, &error));
    CHECK(!error.empty());

    DeleteFileW(blocker.c_str());
    RemoveDirectoryW(root.c_str());
}

V8I_TEST(Gui_IniPathPointsIntoTheAppDataFolder) {
    const std::wstring path = GitBarIniPath();
    REQUIRE(!path.empty());
    CHECK(path.find(L"v8inject") != std::wstring::npos);
    CHECK(path.size() >= 10 &&
          path.compare(path.size() - 10, 10, L"gitbar.ini") == 0);
}
