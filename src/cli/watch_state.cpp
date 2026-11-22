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

bool ParseTraceRecordHead(const std::string& resp, size_t pos, TraceRecordHead& out,
                          size_t* next) {
    static const char kSeq[] = "\"seq\":";
    static const char kHook[] = ",\"hook\":";
    static const char kArgs[] = "\"args\":[";
    if (next) *next = pos;
    if (resp.compare(pos, 6, kSeq) != 0) return false;
    size_t p = pos + 6;

    auto digits = [&resp](size_t& p, uint64_t& value) {
        size_t n = 0;
        value = 0;
        while (p < resp.size() && resp[p] >= '0' && resp[p] <= '9') {
            value = value * 10 + (uint64_t)(resp[p] - '0');
            ++p;
            ++n;
        }
        return n > 0;
    };

    if (!digits(p, out.seq)) return false;
    if (resp.compare(p, 8, kHook) != 0) return false;
    p += 8;
    if (!digits(p, out.hook)) return false;

    // `"ret":"0x…","args":[` -- searched forward but bounded by the next
    // record: none of the fields between can hold `"args":[`, and a later
    // record starts with `{"seq":`.
    size_t bound = resp.find("{\"seq\":", p);
    if (bound == std::string::npos) bound = resp.size();
    size_t a = resp.find(kArgs, p);
    if (a == std::string::npos || a > bound) return false;
    size_t q1 = resp.find('"', a + 8);    // opening quote of args[0]
    if (q1 == std::string::npos) return false;
    size_t q2 = resp.find('"', q1 + 1);   // closing quote of args[0]
    if (q2 == std::string::npos) return false;

    out.arg0 = resp.substr(q1 + 1, q2 - q1 - 1);
    if (next) *next = q2;
    return true;
}

}  // namespace v8i
