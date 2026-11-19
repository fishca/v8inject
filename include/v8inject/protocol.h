#pragma once
#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <cstdio>

namespace v8i {

// Shared block used to talk to the injected payload.
//
// Plain old data only: it is written by one process and read by another,
// possibly of a different bitness. Fixed-width types everywhere.
//
//   ready == kStateIdle     payload waits for a request
//   ready == kStateRequest  host asked for `request`
//   ready == kStateResponse payload filled `response`
//   ready == kStateExit     payload should unload
//
// The state word is the handshake: the host moves it Idle -> Request, the
// payload Request -> Response, the host Response -> Idle. Both sides only ever
// write it from the state they expect, so a host that gave up (a timed-out
// command) can take the word back without racing a reply into the next
// request.
//
// Protocol ABI. The block layout is versioned (A96): the host stamps the
// version and its own sizeof(SharedIo) into the block it creates, the payload
// echoes the version it understood, and a disagreement is reported as a
// protocol mismatch instead of being read as an answer. Fields added later are
// appended, so the offsets of the original block never move and a payload of
// another build is told apart from a payload that never started.
constexpr LONG kStateIdle     = 0;
constexpr LONG kStateRequest  = 1;
constexpr LONG kStateResponse = 2;
constexpr LONG kStateExit     = 3;

constexpr LONG kProtocolAbi = 2;

// What the payload writes into `diag` when it cannot serve the session. The
// host reports these instead of a generic "no reply from payload".
constexpr LONG kDiagNoBlock     = -1;  // OpenFileMappingW failed
constexpr LONG kDiagNoView      = -2;  // MapViewOfFile failed: block of another size
constexpr LONG kDiagAbiMismatch = -3;  // block stamps a protocol this payload does not speak

constexpr size_t kRequestChars  = 4096;
constexpr size_t kResponseBytes = 1024 * 512;

#pragma pack(push, 4)
struct SharedIo {
    volatile LONG ready;
    LONG          requestLen;
    LONG          responseLen;
    LONG          seq;              // host increments per request
    LONG          diag;             // payload diagnostics: why it failed
    wchar_t       logDir[MAX_PATH]; // where the payload should write its log
    wchar_t       request[kRequestChars];
    char          response[kResponseBytes];

    // ---- appended in ABI 2: the offsets above are frozen (A96) ----
    LONG abiVersion;   // host: kProtocolAbi it created the block for
    LONG structSize;   // host: sizeof(SharedIo) as the host built it
    LONG hostPid;      // host: creator pid; the payload leaves when it is gone
    LONG payloadAbi;   // payload: kProtocolAbi once it accepted the block
    LONG respSeq;      // payload: seq of the request this reply answers
};
#pragma pack(pop)

// ABI 1 offsets and size are what an already injected payload of an older build
// expects to find; they must not move, ever.
static_assert(offsetof(SharedIo, ready) == 0, "ABI 1: ready must stay at 0");
static_assert(offsetof(SharedIo, requestLen) == 4, "ABI 1: requestLen at 4");
static_assert(offsetof(SharedIo, responseLen) == 8, "ABI 1: responseLen at 8");
static_assert(offsetof(SharedIo, seq) == 12, "ABI 1: seq at 12");
static_assert(offsetof(SharedIo, diag) == 16, "ABI 1: diag at 16");
static_assert(offsetof(SharedIo, logDir) == 20, "ABI 1: logDir at 20");
static_assert(offsetof(SharedIo, request) == 20 + MAX_PATH * sizeof(wchar_t),
              "ABI 1: request starts after logDir");
static_assert(offsetof(SharedIo, response) ==
                  20 + MAX_PATH * sizeof(wchar_t) + kRequestChars * sizeof(wchar_t),
              "ABI 1: response starts after request");
// ABI 2 fields: an older payload never writes them and an older host never reads
// them, so they live behind the ABI 1 prefix.
static_assert(offsetof(SharedIo, abiVersion) ==
                  20 + MAX_PATH * sizeof(wchar_t) +
                      kRequestChars * sizeof(wchar_t) + kResponseBytes,
              "ABI 2: the new fields are appended");
static_assert(sizeof(SharedIo) == 533040, "the block size is part of the protocol");
static_assert(sizeof(SharedIo) % 4 == 0, "pack(4) keeps the block 4-byte aligned");

// Names and sizes are built from the pid so several hosts can run at once.
inline void MakeSharedName(wchar_t* buf, size_t cch, uint32_t pid) {
    _snwprintf_s(buf, cch, _TRUNCATE, L"Local\\v8inject.%u", pid);
}

// Window/object discovery is done through a dedicated request kind: the payload
// enumerates top-level windows of its own process, walks GWLP_USERDATA on the
// classical 1C frame class, and probes each candidate as IUnknown/IDispatch.

// Payload entry point. Returns 0 on clean shutdown.
using FnProbe = int (__stdcall*)(const wchar_t* sharedName);

}  // namespace v8i
