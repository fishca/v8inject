#pragma once
// The tail of the `cmdinfo` reply (docs/AUDIT.md A48).
//
// On 8.5 the reply grows a block of counters that only a live Configurator can
// fill, which is why the block used to be formatted in place, and why nobody
// noticed that "subscribed" was followed directly by "qProcFrame": the reply of
// an 8.5 process did not parse -- exactly the scenario the command exists for.
// The fragment is built from plain values here, so the dispatcher test can feed
// it a real 8.5 sample and validate the document.

#include <string>

namespace v8i {
namespace platform {

struct CmdInfoTail {
    long               evCount = 0;
    unsigned long long evFrame = 0;
    int                hookOk = 0;
    long               cwHits = 0;
    int                subscribed = 0;
    unsigned long long qProcFrame = 0;
    unsigned long long qProcRecv = 0;
    unsigned long long qCmdFrame = 0;
    unsigned long long qCmdRecv = 0;
    unsigned long long qEvFrame = 0;
    unsigned long long qEvRecv = 0;
};

// The members as they go into the reply object: a leading comma, no braces.
std::string CmdInfoTailJson(const CmdInfoTail& t);

}  // namespace platform
}  // namespace v8i
