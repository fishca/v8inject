// GitBar data safety (docs/AUDIT.md A54, A55, A58, A76, A77).
//
// Four promises of the panel are checked here against the real implementation
// the payload compiles into this binary:
//  * a `git status --porcelain` line never leaks its status letters into the
//    path that is handed to `git add/reset/checkout` (A54);
//  * a modal window of the panel hands WM_QUIT back to the bar thread instead
//    of swallowing it, so `gitbar hide` during a dialog still ends the thread
//    (A55);
//  * nothing that writes runs unless the dump folder is the repository root,
//    because git walks up into a foreign repository (A58);
//  * the git runner has a wall-clock deadline that holds while git keeps
//    printing, kills the whole child tree and caps its output (A76, A77);
//  * the commit-patch cache used by the history window stays bounded (A77).

#include "test_runner.h"

#include "../src/payload/gitbar/git_lists.h"
#include "../src/payload/gitbar/git_service.h"
#include "../src/payload/gitbar/git_ui.h"

#include <windows.h>
#include <string>

using namespace v8i;
using namespace v8i::gitbar;

namespace {

// --- A76: the runner is exercised on cmd.exe -------------------------------
// The runner is generic (RunProcess), so the tests use the shell that is always
// there instead of requiring git on the machine.
GitResult RunCmd(const std::wstring& command, DWORD timeoutMs, size_t cap = kGitOutCap) {
    std::vector<std::wstring> args;
    args.push_back(L"/c");
    args.push_back(command);
    return RunProcess(L"cmd.exe", args, timeoutMs, cap);
}

// This very binary, started in its "--flood" mode: it writes 64 KiB blocks as
// fast as the pipe takes them, so the pipe never goes empty while the parent
// reads. Only such a child reproduces the old bug: cmd.exe is too slow and left
// the pipe empty often enough for the old deadline check to fire (A76).
GitResult RunSelfFlood(DWORD timeoutMs, size_t cap) {
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::vector<std::wstring> args;
    args.push_back(L"--flood");
    return RunProcess(self, args, timeoutMs, cap);
}

// An empty scratch folder under %TEMP%, removed by the test that made it.
std::wstring MakeScratchDir(const wchar_t* tag) {
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    const std::wstring dir =
        std::wstring(tmp) + L"v8i_gitbar_" + tag + L"_" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

void RemoveScratchDir(const std::wstring& dir) {
    RemoveDirectoryW((dir + L"\\.git").c_str());
    RemoveDirectoryW(dir.c_str());
}

unsigned long long FileSize(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fa{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fa)) return 0;
    return ((unsigned long long)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
}

// --- A55: a throwaway window with a close message --------------------------
LRESULT CALLBACK ModalTestProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_APP + 1) {
        DestroyWindow(h);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

HWND MakeModalTestWindow() {
    static bool registered = false;
    if (!registered) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = ModalTestProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"V8iGitBarModalTest";
        RegisterClassW(&wc);
        registered = true;
    }
    return CreateWindowExW(0, L"V8iGitBarModalTest", L"modal test", WS_POPUP, 0, 0, 20, 20,
                           nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
}

}  // namespace

// ---------------------------------------------------------------------------
// A54: the status letters must not become part of the path
// ---------------------------------------------------------------------------

V8I_TEST(GitBar_PorcelainPathStripsBothStatusColumns) {
    // " M" is a file changed but not staged -- the normal state of a dump, and
    // the case the old `find(' ')` split got wrong.
    CHECK_EQ(PorcelainPath(L" M src/main.txt"), std::wstring(L"src/main.txt"));
    CHECK_EQ(PorcelainPath(L"M  src/staged.txt"), std::wstring(L"src/staged.txt"));
    CHECK_EQ(PorcelainPath(L"MM src/both.txt"), std::wstring(L"src/both.txt"));
    CHECK_EQ(PorcelainPath(L"A  added.txt"), std::wstring(L"added.txt"));
    CHECK_EQ(PorcelainPath(L"D  gone.txt"), std::wstring(L"gone.txt"));
    CHECK_EQ(PorcelainPath(L"?? new file.txt"), std::wstring(L"new file.txt"));
    // Rename: git takes the new name.
    CHECK_EQ(PorcelainPath(L"R  old.txt -> new.txt"), std::wstring(L"new.txt"));
    // A name that itself contains " -> " keeps everything after the separator.
    CHECK_EQ(PorcelainPath(L"?? a -> b.txt"), std::wstring(L"b.txt"));
}

V8I_TEST(GitBar_PorcelainPathRejectsLinesThatAreNotPorcelain) {
    CHECK(PorcelainPath(L"").empty());
    CHECK(PorcelainPath(L"M").empty());
    CHECK(PorcelainPath(L"??").empty());
    CHECK(PorcelainPath(L"M  ").empty());          // status columns, no path
    CHECK(PorcelainPath(L"MMfile.txt").empty());   // no separator after "MM"
    CHECK_EQ(PorcelainPath(L"?? a"), std::wstring(L"a"));
}

// ---------------------------------------------------------------------------
// A55: the modal loops of the panel do not swallow WM_QUIT
// ---------------------------------------------------------------------------

V8I_TEST(GitBar_ModalLoopStopsWhenItsDialogDies) {
    HWND h = MakeModalTestWindow();
    REQUIRE(h != nullptr);
    // The close arrives as an ordinary message: the loop dispatches it and then
    // sees that the window is gone -- the way every dialog of the panel closes.
    PostMessageW(h, WM_APP + 1, 0, 0);
    CHECK_EQ(PumpModalLoop(h, false), 0);
    CHECK(!IsWindow(h));
}

V8I_TEST(GitBar_ModalLoopRepostsQuitToTheBarLoop) {
    HWND h = MakeModalTestWindow();
    REQUIRE(h != nullptr);
    PostQuitMessage(7);   // what WM_DESTROY of the bar posts (gitbar hide)
    CHECK_EQ(PumpModalLoop(h, false), 7);
    // The dialog is left alone, as the old loops did.
    CHECK(IsWindow(h) != FALSE);
    DestroyWindow(h);
    // And the quit is still in the queue: swallowing it here is what left the
    // bar thread alive with a dead window and made the panel impossible to show
    // again (A55).
    MSG msg{};
    bool found = false;
    while (PeekMessageW(&msg, nullptr, WM_QUIT, WM_QUIT, PM_REMOVE)) {
        found = true;
        CHECK_EQ((int)msg.wParam, 7);
    }
    CHECK(found);
}

// ---------------------------------------------------------------------------
// A58: the dump folder must own its repository
// ---------------------------------------------------------------------------

V8I_TEST(GitBar_SamePathIgnoresCaseAndTrailingSeparator) {
    CHECK(SamePath(L"E:\\work\\proj\\dump\\", L"e:\\WORK\\proj\\dump"));
    CHECK(SamePath(L"E:\\work\\proj\\dump", L"E:\\work\\proj\\dump"));
    CHECK(!SamePath(L"E:\\work\\proj\\dump", L"E:\\work\\proj\\dump2"));
    CHECK(!SamePath(L"", L"E:\\work\\proj"));
}

V8I_TEST(GitBar_IsSubPathNeedsAComponentBoundary) {
    CHECK(IsSubPath(L"E:\\work\\proj\\dump", L"E:\\work\\proj"));
    CHECK(IsSubPath(L"E:\\work\\proj", L"E:\\work\\proj"));
    CHECK(IsSubPath(L"E:\\work\\proj\\dump\\", L"E:\\work\\proj\\"));
    // "projx" is not inside "proj": a bare prefix test would merge two projects.
    CHECK(!IsSubPath(L"E:\\work\\projx", L"E:\\work\\proj"));
    CHECK(!IsSubPath(L"E:\\work\\proj", L"E:\\work\\proj\\dump"));
}

V8I_TEST(GitBar_ClassifyRepoRootTellsAForeignRepositoryApart) {
    CHECK(ClassifyRepoRoot(L"E:\\work\\proj\\dump", L"E:\\work\\proj") ==
          RepoRootCheck::InsideOther);
    CHECK(ClassifyRepoRoot(L"E:\\work\\proj\\dump", L"E:\\work\\proj\\dump") ==
          RepoRootCheck::IsRoot);
    CHECK(ClassifyRepoRoot(L"E:\\work\\proj\\dump\\", L"e:\\WORK\\proj\\dump") ==
          RepoRootCheck::IsRoot);
    CHECK(ClassifyRepoRoot(L"E:\\work\\proj\\dump", L"E:\\other") == RepoRootCheck::Elsewhere);
    // git said nothing (not a repository, or git.exe is not where the ini says).
    CHECK(ClassifyRepoRoot(L"E:\\work\\proj\\dump", L"") == RepoRootCheck::NoRepo);
    CHECK(ClassifyRepoRoot(L"", L"E:\\work\\proj") == RepoRootCheck::NoRepo);
}

V8I_TEST(GitBar_HasDotGitSeesADirectoryAndAWorktreeFile) {
    const std::wstring dir = MakeScratchDir(L"dotgit");
    REQUIRE(!dir.empty());
    CHECK(!HasDotGit(dir));   // plain folder
    CHECK(!HasDotGit(dir + L"\\missing"));
    CHECK(!HasDotGit(L""));

    // A repository has .git as a directory; a linked worktree as a file.
    CHECK(CreateDirectoryW((dir + L"\\.git").c_str(), nullptr) != FALSE);
    CHECK(HasDotGit(dir));
    CHECK(HasDotGit(dir + L"\\"));   // trailing separator is the same folder
    RemoveDirectoryW((dir + L"\\.git").c_str());

    HANDLE f = CreateFileW((dir + L"\\.git").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    CloseHandle(f);
    CHECK(HasDotGit(dir));
    DeleteFileW((dir + L"\\.git").c_str());
    RemoveScratchDir(dir);
}

V8I_TEST(GitBar_RepoGateRefusesAFolderWithoutRepository) {
    const std::wstring dir = MakeScratchDir(L"gate");
    REQUIRE(!dir.empty());
    RepoRootCheck kind = RepoRootCheck::IsRoot;
    std::wstring why;
    CHECK(!DumpRepoRootOk(dir, &kind, &why));
    CHECK(kind == RepoRootCheck::NoRepo);
    CHECK(why.find(dir) != std::wstring::npos);   // the message names the folder
    RemoveScratchDir(dir);

    why.clear();
    kind = RepoRootCheck::IsRoot;
    CHECK(!DumpRepoRootOk(L"", &kind, &why));
    CHECK(kind == RepoRootCheck::NoRepo);
    CHECK(!why.empty());
}

// ---------------------------------------------------------------------------
// A76: deadline, child tree, output cap, and what the caller is told
// ---------------------------------------------------------------------------

V8I_TEST(GitBar_RunProcessReportsExitCodeAndOutput) {
    const GitResult r = RunCmd(L"echo hello & exit 3", 10000);
    CHECK(r.started);
    REQUIRE(r.Finished());
    CHECK_EQ((int)r.exitCode, 3);
    CHECK(r.out.find(L"hello") != std::wstring::npos);
    CHECK(!r.timedOut);
    CHECK(!r.truncated);
}

V8I_TEST(GitBar_RunProcessChecksTheDeadlineBeforeThePipe) {
    // The old loop looked at the deadline only when the pipe was empty, so a git
    // that never stopped printing was never stopped: it ran until it was done or
    // until the output cap fired. An already expired deadline must stop the child
    // before a megabyte of its output is collected -- and the pipe here is never
    // empty (the child writes 64 KiB blocks), so a loop that waits for an empty
    // pipe collects the megabyte first and reports "truncated".
    const ULONGLONG started = GetTickCount64();
    const GitResult r = RunSelfFlood(0, 1u << 20);
    const ULONGLONG spent = GetTickCount64() - started;
    CHECK(r.started);
    CHECK(r.timedOut);
    CHECK(!r.truncated);
    CHECK(r.out.size() < 16 * 1024);   // stopped at once, not after reading the pipe
    CHECK(spent < 8000);
}

V8I_TEST(GitBar_RunProcessStopsAtTheOutputCap) {
    const ULONGLONG started = GetTickCount64();
    const GitResult r = RunSelfFlood(60000, 64 * 1024);
    const ULONGLONG spent = GetTickCount64() - started;
    CHECK(r.started);
    CHECK(r.truncated);
    CHECK(!r.Finished());
    CHECK(r.out.size() <= 64 * 1024);
    CHECK(spent < 8000);       // stopped at the cap instead of reading forever
}

V8I_TEST(GitBar_RunProcessKillsTheChildTree) {
    // cmd spawns ping and redirects it into a file. TerminateProcess on cmd alone
    // leaves ping writing: the size would keep growing after the runner returned.
    wchar_t cwd[MAX_PATH] = {};
    REQUIRE(GetCurrentDirectoryW(MAX_PATH, cwd) != 0);
    const std::wstring name =
        L"v8i_gitbar_kill_" + std::to_wstring(GetCurrentProcessId()) + L".txt";
    const std::wstring file = std::wstring(cwd) + L"\\" + name;
    DeleteFileW(file.c_str());

    const GitResult r = RunCmd(L"ping -n 60 127.0.0.1 > " + name, 1500);
    CHECK(r.started);
    CHECK(r.timedOut);

    const unsigned long long before = FileSize(file);
    if (before > 0) {
        Sleep(1500);
        // ping writes about one line per second: after the kill the file is
        // frozen. 1.5 s is enough for one more line if the child survived.
        CHECK_EQ(FileSize(file), before);
    }
    DeleteFileW(file.c_str());
}

V8I_TEST(GitBar_GitFailureTextNamesTheDeadlineAndTheCap) {
    GitResult timedOut;
    timedOut.started = true;
    timedOut.timedOut = true;
    const std::wstring t = GitFailureText(timedOut, 120000);
    CHECK(t.find(L"120") != std::wstring::npos);
    CHECK(t.find(L"<timeout>") == std::wstring::npos);

    GitResult capped;
    capped.started = true;
    capped.truncated = true;
    CHECK(GitFailureText(capped, 120000, 1u << 20).find(L"1 МБ") != std::wstring::npos);

    // A plain failure shows git's own text; an empty answer shows the exit code.
    GitResult failed;
    failed.started = true;
    failed.exitCode = 1;
    failed.out = L"fatal: not a git repository\r\n";
    CHECK_EQ(GitFailureText(failed, 1000), std::wstring(L"fatal: not a git repository"));

    GitResult silent;
    silent.started = true;
    silent.exitCode = 2;
    CHECK(GitFailureText(silent, 1000).find(L"2") != std::wstring::npos);

    GitResult never;
    never.error = L"<cannot start git.exe (win32 2)>";
    CHECK_EQ(GitFailureText(never, 1000), std::wstring(L"<cannot start git.exe (win32 2)>"));
}

// ---------------------------------------------------------------------------
// A77: the patch cache of the history window stays bounded
// ---------------------------------------------------------------------------

V8I_TEST(GitBar_PatchCacheEvictsTheLeastRecentlyUsed) {
    PatchCache cache(64, 3);
    std::wstring got;
    CHECK(!cache.Get(L"a", &got));   // empty cache

    cache.Put(L"a", std::wstring(10, L'a'));
    CHECK_EQ(cache.Count(), (size_t)1);
    REQUIRE(cache.Get(L"a", &got));
    CHECK_EQ(got.size(), (size_t)10);

    cache.Put(L"b", std::wstring(10, L'b'));
    cache.Put(L"c", std::wstring(10, L'c'));
    CHECK_EQ(cache.Count(), (size_t)3);
    CHECK_EQ(cache.Chars(), (size_t)30);

    // Reading "a" makes it the most recent, so "b" is the next one to go.
    CHECK(cache.Get(L"a", &got));
    cache.Put(L"d", std::wstring(10, L'd'));
    CHECK_EQ(cache.Count(), (size_t)3);
    CHECK(cache.Get(L"a", &got));
    CHECK(cache.Get(L"c", &got));
    CHECK(cache.Get(L"d", &got));
    CHECK(!cache.Get(L"b", &got));
}

V8I_TEST(GitBar_PatchCacheRespectsTheCharBudget) {
    PatchCache cache(40, 8);
    std::wstring got;
    cache.Put(L"a", std::wstring(25, L'a'));
    cache.Put(L"b", std::wstring(25, L'b'));   // 50 > 40: the oldest one goes
    CHECK_EQ(cache.Count(), (size_t)1);
    CHECK_EQ(cache.Chars(), (size_t)25);
    CHECK(!cache.Get(L"a", &got));
    CHECK(cache.Get(L"b", &got));

    // A patch that does not fit the whole budget is not cached: it would evict
    // everything and be dropped on the next call anyway.
    cache.Put(L"big", std::wstring(41, L'x'));
    CHECK_EQ(cache.Count(), (size_t)1);
    CHECK(!cache.Get(L"big", &got));

    // Replacing a key does not count twice.
    cache.Put(L"b", std::wstring(5, L'b'));
    CHECK_EQ(cache.Count(), (size_t)1);
    CHECK_EQ(cache.Chars(), (size_t)5);

    cache.Clear();
    CHECK_EQ(cache.Count(), (size_t)0);
    CHECK_EQ(cache.Chars(), (size_t)0);
}
