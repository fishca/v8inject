#pragma once
// Fitting a reply into the shared block's response buffer (docs/AUDIT.md A69).
//
// The buffer holds kResponseBytes, the payload's own assembly of the reply does
// not know that limit, and the old code simply copied the first cap-1 bytes:
// the host then received a JSON document cut in the middle and reported "no
// answer", so a command that worked looked like a dead 1C. A reply that does
// not fit is now an error the host can read, with the real size in it.
//
// The check lives in a header because the command loop is not the only user:
// the dispatcher test drives it directly with a body of known size.

#include <cstddef>
#include <cstring>
#include <string>

namespace v8i {
namespace payload {

enum ReplyFit {
    // 1 and 2 on purpose, not 0 and 1: the packer's "no reply at all" is 0 and
    // the crash path is 0 as well, and a truncated document must never be
    // mistaken for either.
    kReplyFits = 1,
    kReplyTooLarge = 2,
};

// Copies `body` into `out` with its terminating NUL, or reports that it does
// not fit. `*outLen` always receives the size the body had, so the caller can
// name it in the error; on kReplyTooLarge `out` is left untouched.
inline ReplyFit FitReply(const std::string& body, char* out, size_t outCap, size_t* outLen) {
    *outLen = body.size();
    if (!out || outCap < 2) return kReplyTooLarge;
    if (body.size() + 1 > outCap) return kReplyTooLarge;
    memcpy(out, body.data(), body.size());
    out[body.size()] = 0;
    return kReplyFits;
}

}  // namespace payload
}  // namespace v8i
