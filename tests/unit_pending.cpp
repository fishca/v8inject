// The marshal slot: one request at a time, one executor, and no double
// execution after a timeout (docs/AUDIT.md A50, A51).
//
// The state machine is plain pod + interlocked operations, so it is driven here
// directly on both architectures. The last test runs the real bridge against a
// window of this process: the marshal finds a "V8TopLevelFrame" window, the
// subclass executes the request on the window's thread, and a message that
// arrives after the request is over must not run anything.

#include "test_runner.h"

#include "v8inject/v8i_export.h"

#include "../src/payload/platform/pending_slot.h"

#include <windows.h>
#include <atomic>

using namespace v8i::platform;

namespace {

V8iPendingSlot FreshSlot() {
    V8iPendingSlot s = {};
    return s;
}

}  // namespace

V8I_TEST(Pending_FreshSlotClaimsNothing) {
    V8iPendingSlot s = FreshSlot();
    CHECK(!PendingClaim(&s, 0));   // a message without an id never runs
    CHECK(!PendingClaim(&s, 1));   // and neither does one for a slot with no request
    CHECK(!PendingAnswered(&s, 1));
}

V8I_TEST(Pending_IdsAreUniqueAndLiveWhileTheSenderWaits) {
    V8iPendingSlot s = FreshSlot();
    const UINT_PTR a = PendingBegin(&s);
    CHECK(a != 0);
    CHECK(PendingClaim(&s, a));
    // A message for an id that was never published is not the live request.
    CHECK(!PendingClaim(&s, a + 1));
    PendingRetire(&s, a);
    const UINT_PTR b = PendingBegin(&s);
    CHECK(b != a);
    CHECK(PendingClaim(&s, b));
    // The previous request is gone: its message cannot run the new one.
    CHECK(!PendingClaim(&s, a));
    PendingRetire(&s, b);
}

V8I_TEST(Pending_ResultBelongsToItsRequest) {
    V8iPendingSlot s = FreshSlot();
    const UINT_PTR a = PendingBegin(&s);
    PendingPublish(&s, a, 7, 0);
    CHECK(PendingAnswered(&s, a));
    CHECK_EQ(s.rc, 7);
    PendingRetire(&s, a);

    const UINT_PTR b = PendingBegin(&s);
    CHECK(!PendingAnswered(&s, b));
    // A late answer to the finished request must not satisfy the new one.
    PendingPublish(&s, a, 9, 0);
    CHECK(!PendingAnswered(&s, b));
    CHECK_EQ(s.rc, -2);   // still "not executed"
    PendingPublish(&s, b, 4, 0);
    CHECK(PendingAnswered(&s, b));
    CHECK_EQ(s.rc, 4);
    PendingRetire(&s, b);
}

V8I_TEST(Pending_TimeoutRetiresTheRequest) {
    V8iPendingSlot s = FreshSlot();
    const UINT_PTR a = PendingBegin(&s);
    CHECK(PendingClaim(&s, a));
    // SendMessageTimeout gave up: the message is still queued.
    PendingAbandon(&s, a);
    CHECK(!PendingClaim(&s, a));          // the late message runs nothing
    CHECK(!PendingAnswered(&s, a));
    CHECK(!s.reqId);

    // The next request is safe: the stale message carries the old id.
    const UINT_PTR b = PendingBegin(&s);
    CHECK(PendingClaim(&s, b));
    CHECK(!PendingClaim(&s, a));
    PendingPublish(&s, b, 1, 0);
    CHECK(PendingAnswered(&s, b));
    PendingRetire(&s, b);
}

V8I_TEST(Pending_StaleMessageCannotRunTheNextRequest) {
    // The defect behind A51: the sender timed out, the slot moved on, and the
    // queued message executed the NEXT request a second time.
    V8iPendingSlot s = FreshSlot();
    const UINT_PTR first = PendingBegin(&s);
    s.mode = 0;
    s.recv = (void*)0x1234;
    PendingAbandon(&s, first);

    const UINT_PTR second = PendingBegin(&s);
    s.mode = 1;
    s.recv = (void*)0x5678;
    // A handler that received the old message: claim must refuse it.
    CHECK(!PendingClaim(&s, first));
    CHECK(PendingClaim(&s, second));
    CHECK_EQ((uintptr_t)s.recv, (uintptr_t)0x5678);
    PendingRetire(&s, second);
}

V8I_TEST(Pending_TornSnapshotIsDetected) {
    // The executor copies the fields and re-checks the id (seqlock). Here the
    // slot is reissued between the claim and the check, as a fast sender can
    // do: the copied request must be dropped instead of executed.
    V8iPendingSlot s = FreshSlot();
    s.mode = 0;
    s.recv = (void*)0xAA;
    const UINT_PTR a = PendingBegin(&s);
    CHECK(PendingClaim(&s, a));
    // The sender moved on (it may only do that from another thread, but the
    // check is what matters).
    PendingAbandon(&s, a);
    const UINT_PTR b = PendingBegin(&s);
    s.recv = (void*)0xBB;
    CHECK(!PendingClaim(&s, a));   // the re-check fails: nothing is executed
    CHECK(PendingClaim(&s, b));
    PendingRetire(&s, b);
}

V8I_TEST(Pending_ConcurrentUseNeverMixesRequests) {
    // One thread fills the slot, the other plays the 1C UI thread (reads the
    // live id without the lock, claims, copies, publishes). The invariant: the
    // receiver a claim exposes always belongs to the id it was read with — a
    // mixed snapshot (the defect behind A50) shows up as a mismatch.
    struct Ctx {
        V8iPendingSlot* s;
        std::atomic<int> executed;
        std::atomic<int> mismatched;
        std::atomic<bool> stop;
    };
    static V8iPendingSlot slot;
    slot = FreshSlot();
    Ctx ctx{&slot, 0, 0, false};
    HANDLE ui = CreateThread(
        nullptr, 0,
        [](LPVOID arg) -> DWORD {
            Ctx* c = (Ctx*)arg;
            UINT_PTR last = 0;   // one message per request, like the WndProc
            while (!c->stop.load()) {
                const UINT_PTR id = c->s->reqId;
                if (!id || id == last || !PendingClaim(c->s, id)) continue;
                last = id;
                const uintptr_t recv = (uintptr_t)c->s->recv;
                // The sender's own record: recv == id (see the loop below).
                if (recv != id) c->mismatched.fetch_add(1);
                PendingPublish(c->s, id, (int)id, 0);
                c->executed.fetch_add(1);
            }
            return 0;
        },
        &ctx, 0, nullptr);
    REQUIRE(ui != nullptr);

    // Bounded wait for the UI thread's answer: the wait is what freezes the
    // payload for the executor (the lock in platform_commands.cpp holds the
    // sender there; a claim without an answer is the timeout path, covered by
    // the deterministic tests above).
    int rounds = 0;
    for (int i = 1; i <= 5000; ++i) {
        // Payload first, id last — the order the marshal uses (A50).
        slot.recv = (void*)(uintptr_t)i;
        const UINT_PTR id = PendingBegin(&slot);
        CHECK_EQ((int)(DWORD)id, i);   // a fresh slot numbers its requests from 1
        int spins = 0;
        while (!PendingAnswered(&slot, id) && ++spins < 200000) Sleep(0);
        PendingRetire(&slot, id);
        if (spins >= 200000) break;   // the UI thread was starved: not a result
        ++rounds;
    }
    ctx.stop.store(true);
    WaitForSingleObject(ui, 5000);
    CloseHandle(ui);

    CHECK_EQ(ctx.mismatched.load(), 0);
    CHECK(rounds > 0);
    CHECK(ctx.executed.load() > 0);
}

// --- the real bridge -------------------------------------------------------

namespace {

std::atomic<int> g_runs{0};
std::atomic<DWORD> g_runThread{0};

void CountingFn(void*) {
    g_runs.fetch_add(1);
    g_runThread.store(GetCurrentThreadId());
}

std::atomic<int> g_plainCalls{0};
LRESULT CALLBACK PlainProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_NCCREATE) g_plainCalls.fetch_add(1);
    return DefWindowProcW(h, m, w, l);
}

}  // namespace
V8I_TEST(Pending_MarshalRunsOnTheWindowThreadAndIgnoresStaleMessages) {
    // The payload finds its marshal window by class name (V8TopLevelFrame).
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = PlainProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"V8TopLevelFrame";
    const ATOM cls = RegisterClassExW(&wc);
    REQUIRE(cls != 0);
    HWND hwnd = CreateWindowExW(0, L"V8TopLevelFrame", L"v8i marshal test",
                                0, 0, 0, 100, 100, nullptr, nullptr,
                                GetModuleHandleW(nullptr), nullptr);
    REQUIRE(hwnd != nullptr);

    g_runs = 0;
    g_runThread = 0;
    REQUIRE(v8i::V8iRunOnUi(CountingFn, nullptr, 5000));
    CHECK_EQ(g_runs.load(), 1);
    CHECK_EQ((int)(DWORD)g_runThread.load(), (int)GetCurrentThreadId());   // the window's thread

    // The request is over: its id is retired. A message that is still in the
    // queue (or a duplicate of the completed request) must execute nothing.
    // The first request of the process is id 1.
    SendMessageW(hwnd, kPendingMsg, (WPARAM)1, 0);
    CHECK_EQ(g_runs.load(), 1);
    // A message with no id at all is not a request either.
    SendMessageW(hwnd, kPendingMsg, 0, 0);
    CHECK_EQ(g_runs.load(), 1);

    // The next request gets a fresh id and runs once.
    REQUIRE(v8i::V8iRunOnUi(CountingFn, nullptr, 5000));
    CHECK_EQ(g_runs.load(), 2);
    // ... and a duplicate of the FIRST request still does nothing.
    SendMessageW(hwnd, kPendingMsg, (WPARAM)1, 0);
    CHECK_EQ(g_runs.load(), 2);

    DestroyWindow(hwnd);
}

// A120: after a failed transmit only the frame the marshal addressed is
// brought back -- the old sweep re-enabled every disabled V8 frame of the
// process, including the owner of a parallel command's legitimate modal state.
namespace v8i {
namespace platform {
void RestoreFramesAfterFailedTransmit(HWND marshalTo);   // src/payload/platform/platform_commands.cpp
}
}

V8I_TEST(Pending_FailedTransmitRestoresOnlyTheMarshalFrame) {
    // The frame class is registered by the marshal test above; a second
    // registration attempt fails with ERROR_CLASS_EXISTS and is fine.
    WNDCLASSEXW fc = {};
    fc.cbSize = sizeof(fc);
    fc.lpfnWndProc = PlainProc;
    fc.hInstance = GetModuleHandleW(nullptr);
    fc.lpszClassName = L"V8TopLevelFrame";
    RegisterClassExW(&fc);
    HWND frame = CreateWindowExW(0, L"V8TopLevelFrame", L"v8i restore test",
                                 0, 0, 0, 100, 100, nullptr, nullptr,
                                 GetModuleHandleW(nullptr), nullptr);
    REQUIRE(frame != nullptr);
    WNDCLASSEXW other = {};
    other.cbSize = sizeof(other);
    other.lpfnWndProc = PlainProc;
    other.hInstance = GetModuleHandleW(nullptr);
    other.lpszClassName = L"v8i_restore_other";
    RegisterClassExW(&other);   // may already exist on a rerun -- fine
    HWND foreign = CreateWindowExW(0, L"v8i_restore_other", L"v8i restore other",
                                   0, 0, 0, 100, 100, nullptr, nullptr,
                                   GetModuleHandleW(nullptr), nullptr);
    REQUIRE(foreign != nullptr);

    EnableWindow(frame, FALSE);
    EnableWindow(foreign, FALSE);

    // The marshal's frame comes back...
    v8i::platform::RestoreFramesAfterFailedTransmit(frame);
    CHECK(IsWindowEnabled(frame));
    // ...the foreign-class window does not: it is not the frame the marshal
    // addressed, so a modal state that belongs to someone else stays as is.
    CHECK(!IsWindowEnabled(foreign));
    v8i::platform::RestoreFramesAfterFailedTransmit(foreign);
    CHECK(!IsWindowEnabled(foreign));

    // No crash and no change on null, garbage and an enabled window.
    v8i::platform::RestoreFramesAfterFailedTransmit(nullptr);
    v8i::platform::RestoreFramesAfterFailedTransmit((HWND)(uintptr_t)0xDEADBEEF);
    v8i::platform::RestoreFramesAfterFailedTransmit(foreign);
    CHECK(!IsWindowEnabled(foreign));

    DestroyWindow(frame);
    DestroyWindow(foreign);
}
