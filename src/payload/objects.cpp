#include "v8inject/objects.h"
#include "v8inject/diag.h"
#include "v8inject/pe_utils.h"

#include <vector>

namespace v8i {

namespace {

struct EnumCtx {
    DWORD pid = 0;
    std::vector<WindowEntry>* out = nullptr;
};

// Passive only: nothing here calls into the target's own code. Sending window
// messages or probing pointers as COM objects from a remote thread can crash a
// process that keeps its own SEH handlers and object graph, so those actions
// live behind the explicit `probe-obj` command instead.
BOOL CALLBACK EnumProc(HWND hwnd, LPARAM lp) {
    auto* ctx = (EnumCtx*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != ctx->pid) return TRUE;

    WindowEntry e;
    e.hwnd = hwnd;

    wchar_t cls[256] = {};
    if (RealGetWindowClassW(hwnd, cls, _countof(cls)) > 0) e.cls = cls;
    else {
        cls[0] = 0;
        if (GetClassNameW(hwnd, cls, _countof(cls)) > 0) e.cls = cls;
    }

    // GetWindowTextW reads the cached caption for windows of other threads and
    // never blocks on their message queue.
    wchar_t title[512] = {};
    if (GetWindowTextW(hwnd, title, _countof(title)) > 0) e.title = title;

    e.userData = (uintptr_t)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (e.userData && !IsReadable((const void*)e.userData, sizeof(void*))) {
        e.readable = false;
    } else {
        e.readable = e.userData != 0;
    }
    ctx->out->push_back(e);
    return TRUE;
}

}  // namespace

std::vector<WindowEntry> EnumProcessWindows() {
    std::vector<WindowEntry> out;
    EnumCtx ctx{GetCurrentProcessId(), &out};
    EnumWindows(EnumProc, (LPARAM)&ctx);
    return out;
}

}  // namespace v8i
