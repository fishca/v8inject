#pragma once
// The state of `v8inject watch`: when a burst of writes under the dump folder
// goes quiet, the configured command runs; then the watcher rearms so the next
// dump fires again.
//
// `fired` used to be set once and never cleared, and the rearm branch only
// zeroed `lastActive`: the second dump was watched but never fired, and the
// process waited for --timeout-sec (ten minutes by default) printing
// "timeout" (A56). The address -> path cache had the matching problem: it grew
// without a limit and remembered a failed `str` as an empty path forever.

#include <cstdint>
#include <string>
#include <vector>

namespace v8i {

// Pure bookkeeping of one watcher: no clock, no I/O, so the tests can drive it.
struct WatchGate {
    int matchCount = 0;
    int fireCount = 0;
    bool fired = false;
    uint64_t lastActive = 0;   // tick of the last matching write, 0 = none

    // A write under the dump folder was seen at `now`.
    void Match(uint64_t now);

    // True when the burst has been quiet for `debounceMs` and the command of
    // this dump has not run yet.
    bool Due(uint64_t now, int debounceMs) const;

    // The command was started.
    void Fired();

    // Ready for the next dump (--once stops the watcher instead).
    void Rearm();
};

// Address -> path of a CreateFileW argument. Bounded both ways: at most
// `kCapacity` entries (the least recently used one is dropped), and a failed
// decode is retried after `kRetryMs` instead of being remembered as "no path"
// forever.
class WatchPathCache {
public:
    static constexpr size_t kCapacity = 4096;
    static constexpr uint64_t kRetryMs = 30000;

    // The cached path, or nullptr when the address has to be asked about. A
    // failed entry inside its retry window comes back empty.
    const std::wstring* Find(uint64_t addr, uint64_t now);

    // Stores the result of a `str` call; an empty `path` is a failure.
    void Store(uint64_t addr, std::wstring path, uint64_t now);

    size_t Size() const { return entries_.size(); }
    void Clear();

private:
    struct Entry {
        uint64_t addr = 0;
        std::wstring path;
        bool resolved = false;
        uint64_t retryAt = 0;
        uint64_t used = 0;   // LRU stamp
    };
    std::vector<Entry> entries_;
    uint64_t clock_ = 0;
};

}  // namespace v8i
