#include "v8inject/objects.h"
#include "v8inject/diag.h"
#include "v8inject/pe_utils.h"

#include <oaidl.h>
#include <oleauto.h>
#include <vector>

namespace v8i {

namespace {

struct EnumCtx {
    DWORD pid = 0;
    std::vector<WindowEntry>* out = nullptr;
};

BOOL CALLBACK EnumProc(HWND hwnd, LPARAM lp) {
    auto* ctx = (EnumCtx*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != ctx->pid) return TRUE;

    WindowEntry e;
    e.hwnd = hwnd;

    // RealGetWindowClass works across threads and does not depend on the
    // message queue of the owning thread.
    wchar_t cls[256] = {};
    if (RealGetWindowClassW(hwnd, cls, _countof(cls)) > 0) e.cls = cls;
    else {
        cls[0] = 0;
        if (GetClassNameW(hwnd, cls, _countof(cls)) > 0) e.cls = cls;
    }

    // GetWindowTextW silently returns 0 for windows owned by another thread;
    // ask explicitly with a short timeout and a zeroed buffer so a failure
    // cannot leak stale bytes into the report.
    wchar_t title[512] = {};
    DWORD_PTR copied = 0;
    if (SendMessageTimeoutW(hwnd, WM_GETTEXT, _countof(title),
                            (LPARAM)title, SMTO_ABORTIFHUNG | SMTO_BLOCK,
                            100, &copied) == 0 || copied == 0) {
        title[0] = 0;
    }
    e.title = title;
    e.userData = (uintptr_t)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
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

namespace {

// SEH cannot be mixed with C++ unwinding, so every dereference of a foreign
// pointer happens in a POD-only helper.

bool GuardedQueryInterface(void* obj, const IID& iid) {
    bool ok = false;
    __try {
        IUnknown* unk = (IUnknown*)obj;
        void* got = nullptr;
        HRESULT hr = unk->QueryInterface(iid, &got);
        ok = SUCCEEDED(hr) && got != nullptr;
        if (ok) ((IUnknown*)got)->Release();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

// Returns true when the object yields a type library with a readable name.
bool GuardedTypeInfoName(void* obj, wchar_t* nameOut, size_t cch) {
    bool ok = false;
    __try {
        IDispatch* disp = (IDispatch*)obj;
        ITypeInfo* ti = nullptr;
        UINT count = 0;
        if (SUCCEEDED(disp->GetTypeInfoCount(&count)) && count > 0) {
            HRESULT hr = disp->GetTypeInfo(0, 0, &ti);
            if (SUCCEEDED(hr) && ti) {
                ITypeLib* tl = nullptr;
                UINT idx = 0;
                if (SUCCEEDED(ti->GetContainingTypeLib(&tl, &idx)) && tl) {
                    BSTR bstr = nullptr;
                    if (SUCCEEDED(tl->GetDocumentation(-1, &bstr, nullptr, nullptr, nullptr)) && bstr) {
                        lstrcpynW(nameOut, bstr, (int)cch);
                        SysFreeString(bstr);
                        ok = nameOut[0] != 0;
                    }
                    tl->Release();
                }
                ti->Release();
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    return ok;
}

}  // namespace

std::vector<ObjectCandidate> ProbeWindowObjects() {
    std::vector<ObjectCandidate> out;

    for (const WindowEntry& w : EnumProcessWindows()) {
        ObjectCandidate c;
        c.hwnd = w.hwnd;
        c.cls = w.cls;
        c.title = w.title;
        c.userData = w.userData;

        if (!w.userData) { c.error = L"GWLP_USERDATA is null"; out.push_back(c); continue; }
        if (!IsReadable((const void*)w.userData, sizeof(void*))) {
            c.error = L"GWLP_USERDATA is not readable";
            out.push_back(c);
            continue;
        }
        c.readable = true;

        void* obj = (void*)w.userData;
        c.isUnknown  = GuardedQueryInterface(obj, IID_IUnknown);
        c.isDispatch = GuardedQueryInterface(obj, IID_IDispatch);
        if (c.isDispatch) {
            wchar_t name[256] = {};
            c.hasTypeInfo = GuardedTypeInfoName(obj, name, _countof(name));
            if (c.hasTypeInfo) c.typeName = name;
        }
        out.push_back(c);
    }
    return out;
}

}  // namespace v8i
