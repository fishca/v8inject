#pragma once
// Bookkeeping of the tray agent: which processes it already injected into and
// which ones it is still retrying.
//
// The agent used to keep two `unordered_set<DWORD>` that were only ever added
// to, so one transient failure (1C still starting, an access-denied while the
// window station is being set up) disabled the auto-injection for that window
// forever, and a reused pid was silently skipped as "already injected" (A62).
// A process is now identified by pid AND creation time, and a failure is
// retried a few times with a backoff.

#include <windows.h>
#include <cstdint>
#include <map>
#include <vector>

namespace v8i {

// Creation time of the process in the 100 ns units of GetProcessTimes; 0 when
// the process is gone or cannot be opened. A pid alone is not an identity:
// Windows reuses pid numbers (A62).
uint64_t ProcessCreated(uint32_t pid);

// True when the pid is alive and, when both times are known, is the same
// process as `created`.
bool ProcessAlive(uint32_t pid, uint64_t created);

enum class AgentDecision {
    Inject,        // a new process, or the backoff of a failed attempt has passed
    WaitForRetry,  // a recent attempt failed; try again later
    Skip,          // already injected, or the attempts ran out
};

struct AgentEntry {
    uint32_t pid = 0;
    uint64_t created = 0;
    bool injected = false;
    int failures = 0;
    uint64_t retryAt = 0;   // GetTickCount64 ticks; 0 = no failure yet
};

class AgentTracker {
public:
    // How many attempts one process gets before the agent gives up on it. Four
    // attempts with the backoff below cover ~14 s, enough for 1C to finish
    // starting while the agent keeps the tray responsive.
    static constexpr int kMaxFailures = 4;

    // 2 s, 4 s, 8 s, ... capped at 30 s.
    static uint64_t BackoffMs(int failures);

    AgentDecision Decide(uint32_t pid, uint64_t created, uint64_t now) const;
    void Injected(uint32_t pid, uint64_t created);
    void Failed(uint32_t pid, uint64_t created, uint64_t now);

    // True when this exact process (pid and creation time) was injected into
    // already: the manual "inject into the running 1C" skips those and retries
    // the rest regardless of their backoff.
    bool WasInjected(uint32_t pid, uint64_t created) const;

    // Drops the entries whose process is gone or whose pid now belongs to
    // another process. `alive` is the pid list of the current snapshot; when it
    // is empty the process list is not consulted and only the creation time
    // decides. Returns the number of dropped entries.
    size_t Prune(const std::vector<uint32_t>& alive);

    void Clear();
    size_t Size() const { return entries_.size(); }

    // The entry of a pid, for tests and for the log; nullptr when unknown.
    const AgentEntry* Find(uint32_t pid) const;

private:
    std::map<uint32_t, AgentEntry> entries_;
};

}  // namespace v8i
