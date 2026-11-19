#include "watch_state.h"

namespace v8i {

void WatchGate::Match(uint64_t now) {
    ++matchCount;
    lastActive = now;
}

bool WatchGate::Due(uint64_t now, int debounceMs) const {
    if (fired || matchCount == 0 || lastActive == 0) return false;
    if (now <= lastActive) return false;
    return now - lastActive > (uint64_t)debounceMs;
}

void WatchGate::Fired() {
    fired = true;
    ++fireCount;
}

void WatchGate::Rearm() {
    fired = false;
    matchCount = 0;
    lastActive = 0;
}

const std::wstring* WatchPathCache::Find(uint64_t addr, uint64_t now) {
    for (auto& e : entries_) {
        if (e.addr != addr) continue;
        if (e.resolved) {
            e.used = ++clock_;
            return &e.path;
        }
        if (now < e.retryAt) {
            e.used = ++clock_;
            return &e.path;   // known bad, not retried yet
        }
        return nullptr;       // the retry window has passed: ask again
    }
    return nullptr;
}

void WatchPathCache::Store(uint64_t addr, std::wstring path, uint64_t now) {
    const bool resolved = !path.empty();
    const uint64_t retryAt = resolved ? 0 : now + kRetryMs;

    for (auto& e : entries_) {
        if (e.addr != addr) continue;
        e.path = std::move(path);
        e.resolved = resolved;
        e.retryAt = retryAt;
        e.used = ++clock_;
        return;
    }

    if (entries_.size() >= kCapacity) {
        // The least recently used entry makes room; replacing it in place keeps
        // the vector stable for the pointers handed out by Find.
        size_t oldest = 0;
        for (size_t i = 1; i < entries_.size(); ++i)
            if (entries_[i].used < entries_[oldest].used) oldest = i;
        Entry& e = entries_[oldest];
        e.addr = addr;
        e.path = std::move(path);
        e.resolved = resolved;
        e.retryAt = retryAt;
        e.used = ++clock_;
        return;
    }

    Entry e;
    e.addr = addr;
    e.path = std::move(path);
    e.resolved = resolved;
    e.retryAt = retryAt;
    e.used = ++clock_;
    entries_.push_back(std::move(e));
}

void WatchPathCache::Clear() {
    entries_.clear();
    clock_ = 0;
}

}  // namespace v8i
