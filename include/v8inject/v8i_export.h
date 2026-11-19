#pragma once

#include "v8inject/protocol.h"
#include <cstdint>

#ifdef V8I_PAYLOAD_EXPORTS
#  define V8I_API extern "C" __declspec(dllexport)
#else
#  define V8I_API extern "C" __declspec(dllimport)
#endif

#define V8I_CALL __stdcall

namespace v8i {

// The command loop of the payload, on a shared block the caller provides.
// The payload runs it on the block it was given; the tests run it on a block
// of their own, which is how the dispatcher and the protocol are checked
// without a live 1C behind them.
//
// Returns 0 when the loop ends normally (the host asked the payload to
// leave), a negative value when it could not start.
//
// The loop also watches the host process named in the block: a payload must not
// outlive its host, or its block keeps the next host out with
// ERROR_ALREADY_EXISTS forever (A45).
int V8iRunCommandLoop(SharedIo* io);

// Publishes one reply into the block, if and only if the request it answers is
// still the one the host waits for: `requestSeq` must match the block's seq and
// the state must still be "request". A host that timed out has taken the state
// word back, and a later request carries its own sequence, so a stale reply is
// dropped instead of being handed to the next command (A45).
//
// Exposed so the protocol tests check the host against the real publish rule
// instead of a simplified copy of it. Returns true when the reply was published.
bool V8iPublishReply(SharedIo* io, LONG requestSeq, const char* data, size_t len);

// The command receiver of the main frame, for the native-menu hooks
// (src/payload/mainmenu.cpp). Runs the same discovery and live hasHandler
// probe the cmd chain uses; returns the receiver, its vtable and the
// platform slot numbers of transmit/updateState/hasHandler, plus the core
// and frame COM objects of the chain (for QueryInterface experiments).
// Returns false when nothing valid is captured yet (platform not ready,
// unsupported layout, 8.5 wiring not done).
bool V8iGetCommandReceiver(void** recvOut, uintptr_t** recvVtOut,
                           int* transmitSlot, int* updateSlot, int* hasSlot,
                           void** coreOut = nullptr, void** frameObjOut = nullptr);

// Starts the native-menu worker thread (a no-op outside 1C or when disabled
// by [git] nativemenu=0). Called once from the payload start-up.
void V8iStartNativeMenu();

// Runs a functor on the 1C UI thread through the cmd marshal (EnsureCmdUi +
// the shared pending slot). Returns false when the marshal is not ready (the
// frame window does not exist yet), the step crashed (logged), or the send
// timed out.
bool V8iRunOnUi(void (*fn)(void*), void* arg, int timeoutMs = 30000);

}  // namespace v8i
