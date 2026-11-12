#pragma once

#include "v8inject/protocol.h"

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

}  // namespace v8i
