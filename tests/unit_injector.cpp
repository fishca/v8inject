// The decision table of the remote LoadLibrary thread (src/host/injector.cpp).
//
// The rule under test: the remote path buffer is released only when the remote
// thread is known to have finished (WAIT_OBJECT_0). Anything else -- a timeout
// or a failed wait -- leaves the buffer allocated, because the thread may
// still be reading the path string. A load that completed after the timeout
// turns the attempt into a success, still without freeing anything: nobody
// confirmed the thread has exited.

#include "test_runner.h"

#include "v8inject/injector.h"

using namespace v8i;
using namespace v8i::test;

V8I_TEST(Injector_RemoteThreadFinishedWithAModule) {
    const RemoteLoadDecision d = EvaluateRemoteLoad(WAIT_OBJECT_0, 0x78000000, false);
    CHECK(d.ok);
    CHECK(d.freeBuffer);
}

V8I_TEST(Injector_RemoteThreadFinishedWithNull) {
    // LoadLibraryW returned NULL: the load failed cleanly, the thread is gone,
    // the unused buffer can go.
    const RemoteLoadDecision d = EvaluateRemoteLoad(WAIT_OBJECT_0, 0, false);
    CHECK(!d.ok);
    CHECK(d.freeBuffer);
}

V8I_TEST(Injector_RemoteThreadFinishedAsStillActive) {
    // Exit code STILL_ACTIVE (259) is not a module handle we trust.
    const RemoteLoadDecision d = EvaluateRemoteLoad(WAIT_OBJECT_0, STILL_ACTIVE, false);
    CHECK(!d.ok);
    CHECK(d.freeBuffer);
}

V8I_TEST(Injector_TimeoutHungInjectionKeepsTheBuffer) {
    // The thread never reported in and no module appeared: refusal, and the
    // buffer stays -- the thread may still be reading the path from it.
    const RemoteLoadDecision d = EvaluateRemoteLoad(WAIT_TIMEOUT, 0, false);
    CHECK(!d.ok);
    CHECK(!d.freeBuffer);
}

V8I_TEST(Injector_TimeoutButModuleLoadedIsASuccess) {
    // The load completed after the timeout fired: the injection succeeded,
    // but the buffer still is not freed -- nobody confirmed the thread exited.
    const RemoteLoadDecision d = EvaluateRemoteLoad(WAIT_TIMEOUT, STILL_ACTIVE, true);
    CHECK(d.ok);
    CHECK(!d.freeBuffer);
}

V8I_TEST(Injector_FailedWaitBehavesLikeATimeout) {
    const RemoteLoadDecision d1 = EvaluateRemoteLoad(WAIT_FAILED, 0, false);
    CHECK(!d1.ok);
    CHECK(!d1.freeBuffer);

    const RemoteLoadDecision d2 = EvaluateRemoteLoad(WAIT_FAILED, 0, true);
    CHECK(d2.ok);
    CHECK(!d2.freeBuffer);
}
