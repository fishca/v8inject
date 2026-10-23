#pragma once
#include <cstdint>
#include <string>

namespace v8i {

// ---------------------------------------------------------------------------
// Inline detour engine (payload side).
//
// The first kPatchLen bytes of a function are overwritten with a jump to a
// per-hook stub. The stub forwards the original registers to a shared thunk,
// which records the call and then continues into a trampoline holding the
// bytes that were overwritten plus a jump back into the function.
//
// This is the layer the extension features build on: once a call can be
// observed and the original can still run, the same machinery can replace a
// function's behaviour instead of only tracing it.
// ---------------------------------------------------------------------------

// Installs a detour on `target` (function entry). `name` is only for reporting.
// Returns a hook id (> 0), or 0 with `error` filled in.
uint32_t HookInstall(uintptr_t target, const char* name, std::string& error);

// Restores the original bytes of one hook, or of every hook when id == 0.
size_t HookRemoveAll();
bool   HookRemove(uint32_t id);

// Records unexpected faults in the payload log. Called once when the payload
// starts, so a crash in a hooked function leaves a trace instead of silence.
void HookInstallFaultLogger();

// Called from the assembly thunks. Must stay POD-only, no exceptions, no
// allocation: it runs inside arbitrary threads of the target process.
extern "C" void V8iHookEnter(void* ctx, void* retAddr, uintptr_t entryEb,
                             uintptr_t a0, uintptr_t a1, uintptr_t a2,
                             uintptr_t a3);

// ---- payload commands -----------------------------------------------------

// hook <hex-addr | module!Export | module+0xRVA> [--name <text>]
std::string HookCommandToJson(const std::wstring& args);
// unhook <id | all>
std::string UnhookCommandToJson(const std::wstring& args);
// hooks
std::string HooksCommandToJson(const std::wstring& args);
// trace [--count N] [--since N] [--clear]
std::string TraceCommandToJson(const std::wstring& args);

}  // namespace v8i
