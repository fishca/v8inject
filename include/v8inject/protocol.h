#pragma once
#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <cstdio>

namespace v8i {

// Shared block used to talk to the injected payload.
// Plain old data only: it is written by one process and read by another,
// possibly of a different bitness. Fixed-width types everywhere.
//
//   ready == kStateIdle     payload waits for a request
//   ready == kStateRequest  host asked for `request`
//   ready == kStateResponse payload filled `response`
//   ready == kStateExit     payload should unload
constexpr LONG kStateIdle     = 0;
constexpr LONG kStateRequest  = 1;
constexpr LONG kStateResponse = 2;
constexpr LONG kStateExit     = 3;

constexpr size_t kRequestChars  = 4096;
constexpr size_t kResponseBytes = 1024 * 512;

#pragma pack(push, 4)
struct SharedIo {
    volatile LONG ready;
    LONG          requestLen;
    LONG          responseLen;
    LONG          seq;              // host increments per request
    LONG          diag;             // payload diagnostics: why it failed
    wchar_t       request[kRequestChars];
    char          response[kResponseBytes];
};
#pragma pack(pop)

// Names and sizes are built from the pid so several hosts can run at once.
inline void MakeSharedName(wchar_t* buf, size_t cch, uint32_t pid) {
    _snwprintf_s(buf, cch, _TRUNCATE, L"Local\\v8inject.%u", pid);
}

// Payload entry point. Returns 0 on clean shutdown.
using FnProbe = int (__stdcall*)(const wchar_t* sharedName);

}  // namespace v8i
