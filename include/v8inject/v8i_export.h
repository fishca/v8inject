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
int V8iRunCommandLoop(SharedIo* io);

// The command receiver of the main frame, for the native-menu hooks
// (src/payload/mainmenu.cpp). Runs the same discovery and live hasHandler
// probe the cmd chain uses; returns the receiver, its vtable and the
// platform slot numbers of transmit/updateState/hasHandler. Returns false
// when nothing valid is captured yet (platform not ready, unsupported
// layout, 8.5 wiring not done).
bool V8iGetCommandReceiver(void** recvOut, uintptr_t** recvVtOut,
                           int* transmitSlot, int* updateSlot, int* hasSlot);

// Starts the native-menu worker thread (a no-op outside 1C or when disabled
// by [git] nativemenu=0). Called once from the payload start-up.
void V8iStartNativeMenu();

}  // namespace v8i
