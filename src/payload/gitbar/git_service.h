#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace v8i {
namespace gitbar {

// gitbar.ini: [git] section, shared with the settings dialog.
const wchar_t* GitIniPath();
std::wstring GitIniGet(const wchar_t* key, const wchar_t* fallback = L"");
bool GitIniSet(const wchar_t* key, const wchar_t* value);

// Client width below which the full strip collapses to a menu button.
int CompactThreshold();

std::wstring GitExe();
std::wstring TrimForTip(const std::wstring& s, size_t maxLen = 160);
std::wstring TrimWs(const std::wstring& s);

// Log helpers: git output is UTF-8 and often Cyrillic.
void LogGit(const wchar_t* what, const std::wstring& text);

// How long one git operation may run. Long enough for a big push over a slow
// link, short enough that a git waiting for credentials in a console nobody can
// see stops on its own instead of holding the panel forever.
const DWORD kGitTimeoutMs = 120000;
// More output than this is a runaway (a 300 MB patch, a log that never ends):
// the child is stopped and the text is cut at the limit (A76, A77).
const size_t kGitOutCap = 4u << 20;
// The history pane pulls one commit's patch at a time; a smaller budget keeps
// the copies inside the 1C process cheap and the pane responsive (A77).
const DWORD kGitPatchTimeoutMs = 20000;
const size_t kGitPatchCap = 1u << 20;

// One finished child process. The text alone cannot tell a timeout from an empty
// answer from a normal exit, and callers used to treat all three as success
// (A76).
struct GitResult {
    std::wstring out;        // stdout + stderr, converted to UTF-16
    std::wstring error;      // why the process never started (started == false)
    DWORD exitCode = 0;
    bool started = false;
    bool timedOut = false;   // stopped at the wall-clock deadline
    bool truncated = false;  // stopped at the output cap
    // Ran to completion: started, no deadline, no cap, exit code 0.
    bool Ok() const { return started && !timedOut && !truncated && exitCode == 0; }
    // Ran to completion with any exit code (git reports "nothing to commit" that
    // way) -- the deadline and the cap are the failures that lose data.
    bool Finished() const { return started && !timedOut && !truncated; }
};

// Runs "<exe> <args>" with stdout and stderr merged into one pipe. The child is
// created suspended and put into a job object with kill-on-close, so the
// deadline and the output cap kill the whole git tree (credential helper, ssh,
// hooks), not just git.exe itself.
GitResult RunProcess(const std::wstring& exe, const std::vector<std::wstring>& args,
                     DWORD timeoutMs, size_t maxBytes);

// Runs "<gitpath> <args>" (RunProcess with the configured git).
GitResult RunGitEx(const std::vector<std::wstring>& args,
                   DWORD timeoutMs = kGitTimeoutMs, size_t maxBytes = kGitOutCap);

// Text-only form for read-only queries (status, branch list, log, rev-parse). A
// stopped git appends "<timeout>" / "<truncated>" so a tooltip is never silently
// empty; mutating commands use RunGitEx and look at the flags instead.
std::wstring RunGit(const std::vector<std::wstring>& args, DWORD timeoutMs = kGitTimeoutMs);

// What to show when a mutating command did not succeed: the deadline and the
// output cap get their own words, everything else is git's own message.
std::wstring GitFailureText(const GitResult& r, DWORD timeoutMs,
                            size_t byteCap = kGitOutCap);

// --- A58: the dump folder must own its repository ----------------------------
// "git -C dir add -A" / commit / push walk up to the enclosing repository, so a
// dump folder that is merely *inside* somebody else's working copy would commit
// and push that project's files. Before every operation that writes, the tool
// asks git for the top level and requires it to be the dump folder itself.
enum class RepoRootCheck {
    NoRepo,       // no .git and no enclosing repository
    IsRoot,       // rev-parse --show-toplevel is this very folder: safe
    InsideOther,  // the top level is a parent folder: a foreign repository
    Elsewhere,    // some other folder entirely (worktrees, junctions)
    Unknown,      // .git exists but git could not name the top level
};

// Absolute path with the trailing separator removed ("E:\dump\" -> "E:\dump";
// a drive root keeps its slash).
std::wstring NormalizeDir(const std::wstring& dir);
bool SamePath(const std::wstring& a, const std::wstring& b);
// True when `child` is `parent` or lies below it. Component-aware: "E:\projx"
// is not inside "E:\proj".
bool IsSubPath(const std::wstring& child, const std::wstring& parent);
bool HasDotGit(const std::wstring& dir);
// `git -C dir rev-parse --show-toplevel`, trimmed; empty when git says nothing.
std::wstring RepoTopLevel(const std::wstring& dir);
// Pure decision: what the reported top level means for `dir`.
RepoRootCheck ClassifyRepoRoot(const std::wstring& dir, const std::wstring& toplevel);
// True when a writing command may touch `dir`. Otherwise `kind` says whether
// offering "git init" makes sense and `why` is the sentence for the user.
bool DumpRepoRootOk(const std::wstring& dir, RepoRootCheck* kind, std::wstring* why);

// --- A77: bounded cache of one commit's patch -------------------------------
// The history window runs "git show" again every time the selection lands on a
// row, so a big commit would be pulled through the pipe and re-parsed on every
// move. The cache keeps a few patches by hash, most recently used last, within a
// budget counted in characters of the patch text (2 bytes each here), so long
// sessions do not grow without bound.
class PatchCache {
public:
    PatchCache(size_t maxChars = 768u << 10, size_t maxEntries = 8);

    // Moves a hit to the "most recently used" end.
    bool Get(const std::wstring& hash, std::wstring* patch);
    // Ignores a patch larger than the whole budget: it would evict everything
    // and be dropped on the next call anyway.
    void Put(const std::wstring& hash, const std::wstring& patch);

    size_t Chars() const { return chars_; }
    size_t Count() const { return entries_.size(); }
    void Clear();

private:
    struct Entry {
        std::wstring hash;
        std::wstring patch;
    };
    std::vector<Entry> entries_;   // least recently used first
    size_t chars_ = 0;
    size_t maxChars_ = 0;
    size_t maxEntries_ = 0;
};

std::wstring NowStamp();
std::wstring TempMsgPath();
bool WriteUtf8File(const std::wstring& path, const std::wstring& text);

// Main Configurator frame of this process.
HWND FindFrame();

}  // namespace gitbar
}  // namespace v8i
