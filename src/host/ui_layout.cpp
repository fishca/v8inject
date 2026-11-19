#include "ui_layout.h"

namespace v8i {

int DpiScale(int px, int dpi) {
    if (dpi <= 0) dpi = 96;
    return MulDiv(px, dpi, 96);
}

RECT ScaleRect(const RECT& base, int dpi) {
    RECT rc;
    rc.left = DpiScale(base.left, dpi);
    rc.top = DpiScale(base.top, dpi);
    rc.right = DpiScale(base.right, dpi);
    rc.bottom = DpiScale(base.bottom, dpi);
    return rc;
}

int WindowDpi(HWND hwnd) {
    using FnGetDpiForWindow = UINT(WINAPI*)(HWND);
    static FnGetDpiForWindow fn = nullptr;
    static bool resolved = false;
    if (!resolved) {
        resolved = true;
        HMODULE user32 = GetModuleHandleW(L"user32.dll");
        if (user32) fn = (FnGetDpiForWindow)GetProcAddress(user32, "GetDpiForWindow");
    }
    if (fn && hwnd) {
        const UINT dpi = fn(hwnd);
        if (dpi >= 48) return (int)dpi;
    }
    HDC dc = GetDC(nullptr);
    const int dpi = dc ? GetDeviceCaps(dc, LOGPIXELSY) : 0;
    if (dc) ReleaseDC(nullptr, dc);
    return dpi >= 48 ? dpi : 96;
}

void ApplyAnchors(const std::vector<UiAnchor>& anchors, int dpi) {
    for (const UiAnchor& a : anchors) {
        if (!a.hwnd) continue;
        SetWindowPos(a.hwnd, nullptr, DpiScale(a.x, dpi), DpiScale(a.y, dpi),
                     DpiScale(a.w, dpi), DpiScale(a.h, dpi),
                     SWP_NOZORDER | SWP_NOACTIVATE);
    }
}

}  // namespace v8i
