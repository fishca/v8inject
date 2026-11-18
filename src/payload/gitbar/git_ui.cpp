#include "git_ui.h"

#include <windows.h>

namespace v8i {
namespace gitbar {

RECT CapCloseRect(const RECT& rc) {
    RECT r{ rc.right - 26, 3, rc.right - 4, 21 };
    return r;
}

// The platform draws its dialog captions itself; our windows are plain Win32,
// so the gray band with the title and the X is painted in the client area.
void DrawCaption(HDC dc, HWND h, HFONT font, bool hoverX) {
    RECT rc{};
    GetClientRect(h, &rc);
    RECT band{ 0, 0, rc.right, kCapH };
    HBRUSH cb = CreateSolidBrush(kDlgCaption);
    FillRect(dc, &band, cb);
    DeleteObject(cb);
    HPEN lp = CreatePen(PS_SOLID, 1, kDlgBorder);
    HPEN olp = (HPEN)SelectObject(dc, lp);
    MoveToEx(dc, 0, kCapH - 1, nullptr);
    LineTo(dc, rc.right, kCapH - 1);
    SelectObject(dc, olp);
    DeleteObject(lp);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, kDlgText);
    HFONT of = (HFONT)SelectObject(dc, font);
    wchar_t t[256] = {};
    GetWindowTextW(h, t, 256);
    RECT tr{ 8, 0, rc.right - 30, kCapH - 1 };
    DrawTextW(dc, t, -1, &tr,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    SelectObject(dc, of);
    RECT xr = CapCloseRect(rc);
    if (hoverX) {
        HBRUSH hb = CreateSolidBrush(kDlgPress);
        FillRect(dc, &xr, hb);
        DeleteObject(hb);
    }
    HPEN xp = CreatePen(PS_SOLID, 1, kDlgText);
    HPEN oxp = (HPEN)SelectObject(dc, xp);
    MoveToEx(dc, xr.left + 6, xr.top + 5, nullptr);
    LineTo(dc, xr.right - 6, xr.bottom - 5);
    MoveToEx(dc, xr.right - 6, xr.top + 5, nullptr);
    LineTo(dc, xr.left + 6, xr.bottom - 5);
    SelectObject(dc, oxp);
    DeleteObject(xp);
}

// WS_POPUP ignores CW_USEDEFAULT, so place the dialog over its owner frame.
void CenterOnOwner(HWND h, HWND owner) {
    HWND root = owner ? GetAncestor(owner, GA_ROOTOWNER) : nullptr;
    if (!root || root == h) root = GetDesktopWindow();
    RECT ro{};
    GetWindowRect(root, &ro);
    RECT rd{};
    GetWindowRect(h, &rd);
    int w = rd.right - rd.left, hh = rd.bottom - rd.top;
    int x = ro.left + ((ro.right - ro.left) - w) / 2;
    int y = ro.top + ((ro.bottom - ro.top) - hh) / 2;
    RECT wa{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    if (x + w > wa.right) x = wa.right - w;
    if (y + hh > wa.bottom) y = wa.bottom - hh;
    if (x < wa.left) x = wa.left;
    if (y < wa.top) y = wa.top;
    SetWindowPos(h, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

// Dragging by the painted caption; the X stays a client hit so the window proc
// can close on WM_LBUTTONDOWN. Sizing borders keep their default hit codes.
LRESULT CapHitTest(HWND h, WPARAM wp, LPARAM lp) {
    LRESULT r = DefWindowProcW(h, WM_NCHITTEST, wp, lp);
    if (r != HTCLIENT) return r;
    POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
    ScreenToClient(h, &pt);
    RECT rc{};
    GetClientRect(h, &rc);
    if (pt.y >= 0 && pt.y < kCapH) {
        RECT xr = CapCloseRect(rc);
        if (!PtInRect(&xr, pt)) return HTCAPTION;
    }
    return r;
}

HFONT CreateDlgFont() {
    HDC dc = GetDC(nullptr);
    int h = -MulDiv(8, GetDeviceCaps(dc, LOGPIXELSY), 72);
    ReleaseDC(nullptr, dc);
    return CreateFontW(h, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Tahoma");
}

HBRUSH UiBgBrush() {
    static HBRUSH b = CreateSolidBrush(kDlgBg);
    return b;
}

// The menu face is a different cream than the dialog face: F5F2DD, sampled
// from a live «Сервис» dropdown. The dialog face FCFAEB reads wrong next to
// the platform's own menus.
HBRUSH UiMenuBrush() {
    static HBRUSH b = CreateSolidBrush(kMenuBg);
    return b;
}

// The icon gutter strip on the left of the menu: a beige strip running the
// full height of the popup, as sampled from a live 1C submenu.
HBRUSH UiGutterBrush() {
    static HBRUSH b = CreateSolidBrush(kSubGutterBg);
    return b;
}

HBRUSH UiFieldBrush() {
    static HBRUSH b = CreateSolidBrush(kDlgFieldBg);
    return b;
}

void UiFrame(HDC dc, const RECT& rc, COLORREF color) {
    HPEN pen = CreatePen(PS_SOLID, 1, color);
    HGDIOBJ op = SelectObject(dc, pen);
    HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(pen);
}

void UiDrawButton(HDC dc, const RECT& rc, const wchar_t* text, HFONT font,
                  bool hover, bool press) {
    HBRUSH face = CreateSolidBrush(press ? kDlgPress : hover ? kDlgHover : kDlgBtnFace);
    FillRect(dc, &rc, face);
    DeleteObject(face);
    UiFrame(dc, rc, kDlgBorder);
    HGDIOBJ oldFont = SelectObject(dc, font);
    int oldMode = SetBkMode(dc, TRANSPARENT);
    COLORREF oldColor = SetTextColor(dc, kDlgText);
    RECT tr = rc;
    DrawTextW(dc, text, -1, &tr,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SetTextColor(dc, oldColor);
    SetBkMode(dc, oldMode);
    SelectObject(dc, oldFont);
}

COLORREF Blend(COLORREF fg, COLORREF bg, int alpha) {
    int r = (GetRValue(fg) * alpha + GetRValue(bg) * (255 - alpha)) / 255;
    int g = (GetGValue(fg) * alpha + GetGValue(bg) * (255 - alpha)) / 255;
    int b = (GetBValue(fg) * alpha + GetBValue(bg) * (255 - alpha)) / 255;
    return RGB(r, g, b);
}

// Ownerdraw buttons would otherwise stay flat grey: the subclass only tracks
// hover (the press state arrives as ODS_SELECTED) and redraws on change.
const wchar_t* kBtnOldProc = L"v8i.oldBtnProc";

LRESULT CALLBACK ThemedButtonProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    WNDPROC old = (WNDPROC)GetPropW(h, kBtnOldProc);
    switch (msg) {
    case WM_MOUSEMOVE:
        if (!GetWindowLongPtrW(h, GWLP_USERDATA)) {
            SetWindowLongPtrW(h, GWLP_USERDATA, 1);
            TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, h, 0 };
            TrackMouseEvent(&tme);
            InvalidateRect(h, nullptr, FALSE);
        }
        break;
    case WM_MOUSELEAVE:
        SetWindowLongPtrW(h, GWLP_USERDATA, 0);
        InvalidateRect(h, nullptr, FALSE);
        break;
    }
    return CallWindowProcW(old, h, msg, wp, lp);
}

void ThemedButton(HWND btn, HFONT font) {
    if (!btn) return;
    WNDPROC old = (WNDPROC)SetWindowLongPtrW(btn, GWLP_WNDPROC, (LONG_PTR)ThemedButtonProc);
    SetPropW(btn, kBtnOldProc, (HANDLE)old);
    SendMessageW(btn, WM_SETFONT, (WPARAM)font, TRUE);
}

bool UiDrawOwnerButton(const DRAWITEMSTRUCT* dis, HFONT font) {
    if (!dis || dis->CtlType != ODT_BUTTON) return false;
    wchar_t text[256] = {};
    GetWindowTextW(dis->hwndItem, text, 256);
    bool press = (dis->itemState & ODS_SELECTED) != 0;
    bool hover = GetWindowLongPtrW(dis->hwndItem, GWLP_USERDATA) != 0;
    UiDrawButton(dis->hDC, dis->rcItem, text, font, hover, press);
    if (dis->itemState & ODS_FOCUS) {
        RECT fr = dis->rcItem;
        InflateRect(&fr, -3, -3);
        DrawFocusRect(dis->hDC, &fr);
    }
    return true;
}

// PromptCtx is declared in git_ui.h: PromptText in gitbar.cpp builds it.
LRESULT CALLBACK PromptDlgProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    PromptCtx* c = (PromptCtx*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (msg) {
    case WM_CTLCOLORDLG:
        return (LRESULT)UiBgBrush();
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, kDlgLabel);
        return (LRESULT)UiBgBrush();
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp;
        SetBkColor(dc, kDlgFieldBg);
        SetTextColor(dc, kDlgText);
        return (LRESULT)UiFieldBrush();
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT rc;
        GetClientRect(h, &rc);
        FillRect(dc, &rc, UiBgBrush());
        if (c) DrawCaption(dc, h, c->font, c->hoverX);
        // the edit sits 1px inside this frame and erases its own interior
        RECT field = { 12, 34 + kCapH, 442, 58 + kCapH };
        UiFrame(dc, field, kDlgFieldBorder);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_NCHITTEST:
        return CapHitTest(h, wp, lp);
    case WM_MOUSEMOVE: {
        if (!c) break;
        if (!c->trackedLeave) {
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, h, 0 };
            TrackMouseEvent(&tme);
            c->trackedLeave = true;
        }
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        RECT rc;
        GetClientRect(h, &rc);
        RECT capRect = CapCloseRect(rc);
        bool hv = PtInRect(&capRect, pt) != 0;
        if (hv != c->hoverX) { c->hoverX = hv; InvalidateRect(h, nullptr, FALSE); }
        return 0;
    }
    case WM_MOUSELEAVE:
        if (c) {
            c->trackedLeave = false;
            if (c->hoverX) { c->hoverX = false; InvalidateRect(h, nullptr, FALSE); }
        }
        return 0;
    case WM_LBUTTONDOWN: {
        if (!c) break;
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        RECT rc;
        GetClientRect(h, &rc);
        RECT capRect = CapCloseRect(rc);
        if (PtInRect(&capRect, pt)) { DestroyWindow(h); return 0; }
        break;
    }
    case WM_DRAWITEM:
        if (c && UiDrawOwnerButton((const DRAWITEMSTRUCT*)lp, c->font)) return TRUE;
        break;
    case DM_GETDEFID:   // IsDialogMessageW turns Enter into this button
        return MAKELRESULT(IDOK, DC_HASDEFID);
    case WM_COMMAND:
        if (c && LOWORD(wp) == IDOK) {
            wchar_t b[1024] = {};
            GetWindowTextW(c->ed, b, 1024);
            *c->out = b;
            c->accepted = true;
            DestroyWindow(h);
            return 0;
        }
        if (c && LOWORD(wp) == IDCANCEL) { DestroyWindow(h); return 0; }
        break;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    }
    return DefDlgProcW(h, msg, wp, lp);
}

// Pale-blue rounded hover with a vertical gradient, as in 1C submenus.
void DrawSubHover(HDC dc, const RECT& rc) {
    HRGN rgn = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1, 7, 7);
    SelectClipRgn(dc, rgn);
    TRIVERTEX v[2] = {
        { rc.left, rc.top, 0xE300, 0xF000, 0xFF00, 0 },
        { rc.right, rc.bottom, 0xCC00, 0xE300, 0xFF00, 0 },
    };
    GRADIENT_RECT g{ 0, 1 };
    GradientFill(dc, v, 2, &g, 1, GRADIENT_FILL_RECT_V);
    SelectClipRgn(dc, nullptr);
    DeleteObject(rgn);
    HPEN pen = CreatePen(PS_SOLID, 1, kMenuHoverBorder);
    HGDIOBJ op = SelectObject(dc, pen);
    HGDIOBJ ob = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, rc.left, rc.top, rc.right + 1, rc.bottom + 1, 7, 7);
    SelectObject(dc, op);
    SelectObject(dc, ob);
    DeleteObject(pen);
}

}  // namespace gitbar
}  // namespace v8i
