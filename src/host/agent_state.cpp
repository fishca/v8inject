#include "agent_state.h"

namespace v8i {

uint64_t ProcessCreated(uint32_t pid) {
    if (!pid) return 0;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return 0;
    FILETIME created{}, exited{}, kernel{}, user{};
    uint64_t out = 0;
    if (GetProcessTimes(h, &created, &exited, &kernel, &user)) {
        out = ((uint64_t)created.dwHighDateTime << 32) | created.dwLowDateTime;
    }
    CloseHandle(h);
    return out;
}

bool ProcessAlive(uint32_t pid, uint64_t created) {
    const uint64_t current = ProcessCreated(pid);
    if (!current) return false;             // gone, or nothing we could inject into
    if (!created) return true;              // identity unknown: the pid is what we have
    return current == created;
}

uint64_t AgentTracker::BackoffMs(int failures) {
    if (failures < 1) return 0;
    if (failures > 5) return 30000;
    const uint64_t ms = 2000ULL << (failures - 1);
    return ms > 30000 ? 30000 : ms;
}

AgentDecision AgentTracker::Decide(uint32_t pid, uint64_t created,
                                   uint64_t now) const {
    const auto it = entries_.find(pid);
    if (it == entries_.end()) return AgentDecision::Inject;

    const AgentEntry& e = it->second;
    // A different creation time is a different process that inherited the pid:
    // exactly the case the old sets could not see (A62).
    if (created && e.created && created != e.created) return AgentDecision::Inject;
    if (e.injected) return AgentDecision::Skip;
    if (e.failures >= kMaxFailures) return AgentDecision::Skip;
    if (e.retryAt && now < e.retryAt) return AgentDecision::WaitForRetry;
    return AgentDecision::Inject;
}

void AgentTracker::Injected(uint32_t pid, uint64_t created) {
    AgentEntry& e = entries_[pid];
    e.pid = pid;
    e.created = created;
    e.injected = true;
    e.failures = 0;
    e.retryAt = 0;
}

void AgentTracker::Failed(uint32_t pid, uint64_t created, uint64_t now) {
    auto it = entries_.find(pid);
    if (it == entries_.end() || (created && it->second.created && created != it->second.created)) {
        AgentEntry e;
        e.pid = pid;
        e.created = created;
        e.failures = 1;
        e.retryAt = now + BackoffMs(1);
        entries_[pid] = e;
        return;
    }
    AgentEntry& e = it->second;
    if (e.injected) e.injected = false;    // a failed re-inject reopens the window
    ++e.failures;
    e.retryAt = now + BackoffMs(e.failures);
}

bool AgentTracker::WasInjected(uint32_t pid, uint64_t created) const {
    const auto it = entries_.find(pid);
    if (it == entries_.end()) return false;
    const AgentEntry& e = it->second;
    if (!e.injected) return false;
    if (created && e.created && created != e.created) return false;
    return true;
}

size_t AgentTracker::Prune(const std::vector<uint32_t>& alive) {
    size_t dropped = 0;
    for (auto it = entries_.begin(); it != entries_.end();) {
        bool present = alive.empty();
        for (uint32_t pid : alive) {
            if (pid == it->first) {
                present = true;
                break;
            }
        }
        const bool sameProcess = present && ProcessAlive(it->first, it->second.created);
        if (!present || !sameProcess) {
            it = entries_.erase(it);
            ++dropped;
        } else {
            ++it;
        }
    }
    return dropped;
}

void AgentTracker::Clear() { entries_.clear(); }

const AgentEntry* AgentTracker::Find(uint32_t pid) const {
    const auto it = entries_.find(pid);
    return it == entries_.end() ? nullptr : &it->second;
}

}  // namespace v8i
