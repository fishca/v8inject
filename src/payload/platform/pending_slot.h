#pragma once
// The cross-thread command slot of the payload (the "marshal").
//
// The io thread (cmd/cmd85) and the native-menu worker both need code to run on
// the 1C UI thread: the sender fills this slot and posts kV8iCmdMsg to a frame
// window, whose WndProc executes the slot and publishes the result.
//
// Two defects this protocol is designed against (docs/AUDIT.md A50, A51):
//  * the slot used to be written by callers that did not hold the lock, so the
//    UI thread could execute a receiver/function of one request with a command
//    of another;
//  * a message carried no identity. SendMessageTimeout gives up waiting after
//    its timeout but the message is still delivered later (Raymond Chen,
//    "What happens when a message times out", 2011-09-15), so by then the slot
//    could hold the next request - the UI thread executed that one a second
//    time, or reported success for a step it never ran.
//
// The protocol: under the sender's lock a request gets a fresh id and the slot
// is written before the id is published; the UI thread runs a message only
// when its id is still the live one and the request was not abandoned; a
// timeout abandons the request (id retired, cancelled set) so a late message is
// ignored instead of running a newer request; the result is published with its
// id as well, so a sender can never be satisfied by the answer to another
// request.
//
// Plain pod and interlocked operations only: the same header is driven by the
// payload and by the unit tests, so the state machine is tested on both
// architectures instead of only on a live Configurator.

#include <windows.h>

namespace v8i {
namespace platform {

// The private window message the marshal posts to the frame window. The
// message carries the request id in wParam.
constexpr UINT kPendingMsg = WM_APP + 0x2F11;

struct V8iPendingSlot {
    // Request payload: written by the sender while it holds the slot lock,
    // before the id is published.
    void* recv;
    void* trFn;
    void (*fun)(void*);
    void* funArg;
    int mode;              // 0 transmit, 1 hasHandler, 2 capture 8.5 recv,
                           // 3 run fun(funArg) on the UI thread
    unsigned char raw[48]; // command bytes; the tail is zeroed by the sender
    // Result: written by the UI thread.
    int rc;
    LONG exc;
    // Protocol state.
    volatile LONG cancelled;   // the sender gave up on this request
    volatile LONG seq;         // id source; bumped only under the slot lock
    volatile UINT_PTR reqId;   // live request; 0 = free or retired
    volatile UINT_PTR resultId; // id whose result is in rc/exc; 0 = none
};

// A single atomic exchange of a pointer-sized id.
inline UINT_PTR PendingXchgId(volatile UINT_PTR* p, UINT_PTR v) {
#if defined(_WIN64)
    return (UINT_PTR)InterlockedExchange64((volatile LONG64*)p, (LONG64)v);
#else
    return (UINT_PTR)(unsigned)InterlockedExchange((volatile LONG*)p, (LONG)(unsigned)v);
#endif
}

// Sender, holding the slot lock and after the request fields are written:
// publishes the request and returns its id (never 0).
inline UINT_PTR PendingBegin(V8iPendingSlot* s) {
    LONG raw = 0;
    do {
        raw = InterlockedIncrement(&s->seq);
    } while (raw == 0);
    InterlockedExchange(&s->cancelled, 0);
    PendingXchgId(&s->resultId, 0);
    s->rc = -2;   // "not executed": what a slot nobody ran reports
    s->exc = 0;
    const UINT_PTR id = (UINT_PTR)(unsigned)raw;
    s->reqId = id;   // published last: from here the UI thread may run it
    return id;
}

// UI thread: may a message with this id run? Only the live request, and only
// while the sender has not given up on it. A stale message (the slot moved to
// another request, or was retired after a timeout) is ignored.
inline bool PendingClaim(const V8iPendingSlot* s, UINT_PTR msgId) {
    if (!msgId || s->reqId != msgId) return false;
    return InterlockedCompareExchange((volatile LONG*)&s->cancelled, 0, 0) == 0;
}

// UI thread, after the request has run: publishes the outcome. Dropped when the
// slot moved on (the sender abandoned this request), so a late answer can never
// satisfy the sender of a newer request.
inline void PendingPublish(V8iPendingSlot* s, UINT_PTR msgId, int rc, LONG exc) {
    if (!PendingClaim(s, msgId)) return;
    s->rc = rc;
    s->exc = exc;
    PendingXchgId(&s->resultId, msgId);
}

// Sender: did THIS request answer?
inline bool PendingAnswered(const V8iPendingSlot* s, UINT_PTR id) {
    return s->resultId == id;
}

// Sender: the request is over either way. Retiring the id means no message
// that is still in the queue (a duplicate, or one delivered after a timeout
// that has just expired) can run it again.
inline void PendingRetire(V8iPendingSlot* s, UINT_PTR id) {
    if (s->reqId == id) s->reqId = 0;
}

// Sender: the message did not complete (timeout, or it was not delivered).
// Retires the id and marks the request cancelled, so a message that arrives
// after the timeout executes nothing.
inline void PendingAbandon(V8iPendingSlot* s, UINT_PTR id) {
    if (s->reqId != id) return;
    InterlockedExchange(&s->cancelled, 1);
    s->reqId = 0;
    PendingXchgId(&s->resultId, 0);
}

}  // namespace platform
}  // namespace v8i
