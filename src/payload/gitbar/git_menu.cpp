#include "git_menu.h"

#include <windows.h>
#include <commctrl.h>
// WIN32_LEAN_AND_MEAN keeps windows.h from pulling ole2.h, and uiautomation.h
// needs the COM `interface` macro it defines (gitbar.cpp got it via shlobj.h).
#include <ole2.h>
#include <uiautomation.h>
#include <algorithm>
#include <string>
#include <vector>

#include "git_service.h"
#include "git_ui.h"

namespace v8i {
namespace gitbar {

namespace {

// ---------------------------------------------------------------------------
// Main-menu overlay: a «GitBar» item painted into the designer's menu row right
// after «Сервис». The row is custom-painted (no HMENU), but UI Automation
// exposes it as a ToolBar with Button children carrying exact screen rects. We
// cover the tail of the row with a top-level owned popup, paint «GitBar» plus
// shifted copies of the buttons that followed «Сервис» (Окна, Справка), and
// route clicks: GitBar opens the action list, a replica forwards a real click
// to the original 1C button underneath (the menu buttons expose no UIA
// patterns, so they cannot be invoked programmatically). If UIA finds no menu
// toolbar the feature stays absent.
// ---------------------------------------------------------------------------

struct MenuButton {
    std::wstring text;
    RECT rect{};                 // original screen rect
};

constexpr int kMaxShiftedPopups = 8;   // menu panels slid right per pause

struct GitMenu {
    HWND hwnd = nullptr;
    HFONT font = nullptr;
    IUIAutomation* uia = nullptr;
    IUIAutomationElement* toolbar = nullptr;
    IUIAutomationCondition* toolbarCond = nullptr;   // ControlType == ToolBar
    IUIAutomationCondition* buttonCond = nullptr;    // ControlType == Button
    std::vector<MenuButton> tail;   // buttons after «Сервис», repainted shifted
    int anchorRight = 0;         // screen x where «GitBar» starts (Сервис.right)
    int rowTop = 0, rowH = 21;   // menu-row screen top / height
    int ourW = 0, width = 0;     // GitBar item width / whole overlay width
    int hover = -1;              // 0 = GitBar, 1.. = tail index, -1 = none
    bool trackedLeave = false;
    bool valid = false;
    RECT lastFrame{};
    int tick = 0;
    // GetTickCount() of the last click forwarded to a native menu button. The
    // click opens 1C's native menu, which tracks in a modal loop on this very
    // thread; for 10 s after it the tick leaves the overlay alone (no UIA, no
    // raising) -- a UIA re-query in that window froze 1C on a live 8.3.27.2342.
    DWORD forwardedAt = 0;
    // The native rect of the button whose replica was forwarded. Only a panel
    // anchored at THIS rect is slid right (timer 4): panels of menus opened
    // natively elsewhere on the row must stay where 1C put them.
    RECT forwardedRect{};
    // Menu panels of this pause that were slid right (timer 4), so each is
    // moved once. Cleared when the pause lifts and on every new forward.
    HWND shifted[kMaxShiftedPopups] = {};
    int  shiftedCount = 0;
};

GitMenu g_menu;

void MenuReleaseTail() {
    g_menu.tail.clear();
}

bool MenuEnsureUia() {
    if (!g_menu.uia) {
        HRESULT hr = CoCreateInstance(CLSID_CUIAutomation, nullptr,
                                      CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&g_menu.uia));
        if (FAILED(hr) || !g_menu.uia) { g_menu.uia = nullptr; return false; }
    }
    if (!g_menu.toolbarCond) {
        VARIANT v; VariantInit(&v);
        v.vt = VT_I4; v.lVal = UIA_ToolBarControlTypeId;
        g_menu.uia->CreatePropertyCondition(UIA_ControlTypePropertyId, v, &g_menu.toolbarCond);
    }
    if (!g_menu.buttonCond) {
        VARIANT v; VariantInit(&v);
        v.vt = VT_I4; v.lVal = UIA_ButtonControlTypeId;
        g_menu.uia->CreatePropertyCondition(UIA_ControlTypePropertyId, v, &g_menu.buttonCond);
    }
    return g_menu.toolbarCond && g_menu.buttonCond;
}

// The menu toolbar is the one whose children include «Файл»; matching by content
// rather than by the localized «Главное меню» name survives other languages.
bool MenuFindToolbar(HWND frame) {
    IUIAutomationElement* root = nullptr;
    if (FAILED(g_menu.uia->ElementFromHandle(frame, &root)) || !root) return false;
    IUIAutomationElementArray* bars = nullptr;
    HRESULT hr = root->FindAll(TreeScope_Descendants, g_menu.toolbarCond, &bars);
    root->Release();
    if (FAILED(hr) || !bars) return false;
    int n = 0; bars->get_Length(&n);
    bool found = false;
    for (int i = 0; i < n && !found; ++i) {
        IUIAutomationElement* bar = nullptr;
        bars->GetElement(i, &bar);
        if (!bar) continue;
        IUIAutomationElementArray* kids = nullptr;
        if (SUCCEEDED(bar->FindAll(TreeScope_Children, g_menu.buttonCond, &kids)) && kids) {
            int kn = 0; kids->get_Length(&kn);
            for (int j = 0; j < kn; ++j) {
                IUIAutomationElement* k = nullptr;
                kids->GetElement(j, &k);
                if (!k) continue;
                BSTR name = nullptr; k->get_CurrentName(&name);
                bool isFile = name && wcscmp(name, L"Файл") == 0;
                if (name) SysFreeString(name);
                k->Release();
                if (isFile) { g_menu.toolbar = bar; bar = nullptr; found = true; break; }
            }
            kids->Release();
        }
        if (bar) bar->Release();
    }
    bars->Release();
    return found;
}

bool MenuQueryLayout(HWND frame) {
    if (!MenuEnsureUia()) return false;
    if (!g_menu.toolbar && !MenuFindToolbar(frame)) return false;

    IUIAutomationElementArray* arr = nullptr;
    HRESULT hr = g_menu.toolbar->FindAll(TreeScope_Children, g_menu.buttonCond, &arr);
    if (FAILED(hr) || !arr) {
        // The cached toolbar went stale (1C rebuilt its menu): resolve again.
        g_menu.toolbar->Release(); g_menu.toolbar = nullptr;
        if (!MenuFindToolbar(frame)) return false;
        hr = g_menu.toolbar->FindAll(TreeScope_Children, g_menu.buttonCond, &arr);
        if (FAILED(hr) || !arr) return false;
    }

    struct B { std::wstring text; RECT r; IUIAutomationElement* el; };
    std::vector<B> buttons;
    int n = 0; arr->get_Length(&n);
    for (int i = 0; i < n; ++i) {
        IUIAutomationElement* el = nullptr;
        arr->GetElement(i, &el);
        if (!el) continue;
        BSTR name = nullptr; el->get_CurrentName(&name);
        B b; b.text = name ? name : L"";
        if (name) SysFreeString(name);
        el->get_CurrentBoundingRectangle(&b.r);
        b.el = el;
        buttons.push_back(b);
    }
    arr->Release();
    if (buttons.empty()) return false;

    int svc = -1;
    for (int i = 0; i < (int)buttons.size(); ++i)
        if (buttons[i].text == L"Сервис") { svc = i; break; }

    MenuReleaseTail();
    if (svc >= 0) {
        g_menu.anchorRight = buttons[svc].r.right;
        for (int i = svc + 1; i < (int)buttons.size(); ++i) {
            MenuButton mb;
            mb.text = buttons[i].text;
            mb.rect = buttons[i].r;
            g_menu.tail.push_back(mb);
        }
    } else {
        // No «Сервис» (other locale/layout): append after the last button.
        g_menu.anchorRight = buttons.back().r.right;
    }
    for (B& b : buttons) b.el->Release();

    RECT tr{}; g_menu.toolbar->get_CurrentBoundingRectangle(&tr);
    g_menu.rowTop = tr.top;
    g_menu.rowH = (tr.bottom > tr.top) ? (tr.bottom - tr.top) : 21;

    if (!g_menu.font) g_menu.font = CreateDlgFont();
    HDC dc = GetDC(nullptr);
    HFONT old = (HFONT)SelectObject(dc, g_menu.font);
    SIZE sz{}; GetTextExtentPoint32W(dc, L"GitBar", 6, &sz);
    SelectObject(dc, old);
    ReleaseDC(nullptr, dc);
    g_menu.ourW = sz.cx + 16;
    int tailW = g_menu.tail.empty() ? 0 : (g_menu.tail.back().rect.right - g_menu.anchorRight);
    g_menu.width = g_menu.ourW + tailW;
    return true;
}

void MenuDrawItem(HDC dc, int x, int w, const wchar_t* text, bool hover) {
    RECT item{ x, 1, x + w, g_menu.rowH - 1 };
    // The same pale-blue gradient box the submenus use, as on the live row.
    if (hover) DrawSubHover(dc, item);
    COLORREF tc = hover ? kMenuHoverText : kMenuText;
    SetTextColor(dc, tc);
    DrawTextW(dc, text, -1, &item, DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX);
    // The platform underlines the mnemonic of the hovered item only; a plain
    // row shows no underline.
    if (hover && text[0]) {
        int len = (int)wcslen(text);
        SIZE full{}, first{};
        GetTextExtentPoint32W(dc, text, len, &full);
        GetTextExtentPoint32W(dc, text, 1, &first);
        int tx = x + (w - full.cx) / 2;
        int ty = item.top + ((item.bottom - item.top) - full.cy) / 2 + full.cy - 1;
        HPEN up = CreatePen(PS_SOLID, 1, tc);
        HGDIOBJ op = SelectObject(dc, up);
        MoveToEx(dc, tx, ty, nullptr);
        LineTo(dc, tx + first.cx, ty);
        SelectObject(dc, op);
        DeleteObject(up);
    }
}

void MenuPaint(HWND h) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(h, &ps);
    RECT rc{}; GetClientRect(h, &rc);
    HBRUSH bg = CreateSolidBrush(kMenuBg);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);
    HFONT old = (HFONT)SelectObject(dc, g_menu.font);
    SetBkMode(dc, TRANSPARENT);
    MenuDrawItem(dc, 0, g_menu.ourW, L"GitBar", g_menu.hover == 0);
    for (int i = 0; i < (int)g_menu.tail.size(); ++i) {
        int bx = g_menu.ourW + (g_menu.tail[i].rect.left - g_menu.anchorRight);
        int bw = g_menu.tail[i].rect.right - g_menu.tail[i].rect.left;
        MenuDrawItem(dc, bx, bw, g_menu.tail[i].text.c_str(), g_menu.hover == i + 1);
    }
    SelectObject(dc, old);
    EndPaint(h, &ps);
}

int MenuHitTest(POINT pt) {
    if (pt.y < 0 || pt.y >= g_menu.rowH) return -1;
    if (pt.x >= 0 && pt.x < g_menu.ourW) return 0;
    for (int i = 0; i < (int)g_menu.tail.size(); ++i) {
        int bx = g_menu.ourW + (g_menu.tail[i].rect.left - g_menu.anchorRight);
        int bw = g_menu.tail[i].rect.right - g_menu.tail[i].rect.left;
        if (pt.x >= bx && pt.x < bx + bw) return i + 1;
    }
    return -1;
}

// 1C's menu buttons expose no UIA patterns, so a replica cannot be invoked
// through UIA. Instead make the overlay click-through for a moment and send a
// real click at the ORIGINAL button position underneath; timer 3 restores
// hit-testing once the injected click has been dispatched.
void MenuForwardClick(const RECT& orig) {
    if (!g_menu.hwnd) return;
    // The click opens 1C's native menu, which tracks in a modal loop on this
    // very thread. Until it is over, the tick must not re-query UIA or raise
    // the overlay (see MenuReposition). The panel will anchor at THIS rect,
    // and only a panel anchored here may be slid right (MenuShiftPopups).
    g_menu.forwardedAt = GetTickCount();
    g_menu.forwardedRect = orig;
    g_menu.shiftedCount = 0;   // a new forward expects a new panel
    POINT save{}; GetCursorPos(&save);
    LONG_PTR ex = GetWindowLongPtrW(g_menu.hwnd, GWL_EXSTYLE);
    SetWindowLongPtrW(g_menu.hwnd, GWL_EXSTYLE, ex | WS_EX_TRANSPARENT);
    SetWindowPos(g_menu.hwnd, nullptr, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    POINT c{ (orig.left + orig.right) / 2, (orig.top + orig.bottom) / 2 };
    SetCursorPos(c.x, c.y);
    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
    // Keep the cursor on the replica the user clicked, not on the original
    // button underneath (which maps to a different replica).
    SetCursorPos(save.x, save.y);
    SetTimer(g_menu.hwnd, 3, 120, nullptr);
    // Timer 4 slides the native menu panel right while it is open (see
    // MenuShiftPopups); killed when the pause lifts in MenuReposition.
    SetTimer(g_menu.hwnd, 4, 30, nullptr);
}

// The native dropdown anchors to the NATIVE button's rect, which sits ourW to
// the LEFT of the replica the user sees and clicks (replicas are painted
// shifted right to make room for the GitBar item) -- so without help the
// «Справка» panel opens under «Окна» (live 8.3.27.2342). Timer 4 polls while
// the pause after a forwarded click is active and slides the panel right by
// ourW. Only the panel of the forwarded button is touched: the match is the
// panel's left edge against the forwarded button's left (±12 px) -- panels of
// menus the user opened natively elsewhere on the row stay where 1C put them.
// Top-level windows only: if 1C's panel ever turns out to be a child window,
// this degrades to the old misplaced opening.
bool MenuShiftPopups() {
    if (!g_menu.hwnd || g_menu.ourW <= 0 || g_menu.tail.empty()) return false;
    if (g_menu.forwardedRect.left == 0 && g_menu.forwardedRect.right == 0) return false;
    HWND frame = GetWindow(g_menu.hwnd, GW_OWNER);
    if (!frame) return false;
    struct Ctx { GitMenu* m; HWND frame; } ctx = { &g_menu, frame };
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        Ctx* c = (Ctx*)lp;
        if (GetWindow(h, GW_OWNER) != c->frame) return TRUE;
        if (!IsWindowVisible(h)) return TRUE;
        wchar_t cls[64] = {};
        GetClassNameW(h, cls, 64);
        // Standard menus and tooltips, and everything of our own: not the panel.
        if (cls[0] == L'#' || wcsncmp(cls, L"V8i", 3) == 0 ||
            wcsncmp(cls, L"tooltips", 8) == 0) return TRUE;
        RECT r{};
        if (!GetWindowRect(h, &r)) return TRUE;
        // The panel opens right under the menu row, anchored at the forwarded
        // button's left edge (±12 px). Anything else owned by the frame --
        // panels of natively opened menus, tooltips -- stays where 1C put it.
        if (r.top < c->m->rowTop || r.top > c->m->rowTop + c->m->rowH + 80) return TRUE;
        if (abs(r.left - c->m->forwardedRect.left) > 12) return TRUE;
        for (int i = 0; i < c->m->shiftedCount; ++i)
            if (c->m->shifted[i] == h) return TRUE;   // already slid
        SetWindowPos(h, nullptr, r.left + c->m->ourW, r.top, 0, 0,
                     SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        if (c->m->shiftedCount < kMaxShiftedPopups)
            c->m->shifted[c->m->shiftedCount++] = h;
        return TRUE;
    }, (LPARAM)&ctx);
    return true;
}

// [git] menuoverlay=0 turns the main-menu replica off entirely: the overlay is
// never created and the row is left to 1C. A stability switch for builds where
// the UIA replica misbehaves (added after the «Окна»-menu hang on a live
// 8.3.27.2342); read once, applied on the next GitBar creation.
static volatile LONG g_nativeMenu = 0;   // the native menu item is rendered

bool MenuOverlayEnabled() {
    if (g_nativeMenu) return false;   // the platform draws the item itself
    static const bool enabled = GitIniGet(L"menuoverlay", L"1") != L"0";
    return enabled;
}

}  // namespace

LRESULT CALLBACK MenuWndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_PAINT:
        MenuPaint(h);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_MEASUREITEM: {
        LPMEASUREITEMSTRUCT m = (LPMEASUREITEMSTRUCT)lp;
        if (m->CtlType == ODT_MENU) { ActionMenuMeasure(m); return TRUE; }
        break;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT d = (LPDRAWITEMSTRUCT)lp;
        if (d->CtlType == ODT_MENU) { ActionMenuDraw(d); return TRUE; }
        break;
    }
    case WM_MOUSEMOVE: {
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        int hit = MenuHitTest(pt);
        if (hit != g_menu.hover) { g_menu.hover = hit; InvalidateRect(h, nullptr, FALSE); }
        if (!g_menu.trackedLeave) {
            TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, h, 0 };
            TrackMouseEvent(&tme);
            g_menu.trackedLeave = true;
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        g_menu.trackedLeave = false;
        if (g_menu.hover != -1) { g_menu.hover = -1; InvalidateRect(h, nullptr, FALSE); }
        return 0;
    case WM_LBUTTONDOWN: {
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        int hit = MenuHitTest(pt);
        if (hit == 0) {
            ShowActionMenu(h);
        } else if (hit > 0 && hit <= (int)g_menu.tail.size()) {
            MenuForwardClick(g_menu.tail[hit - 1].rect);
        }
        return 0;
    }
    case WM_TIMER:
        if (wp == 3) {
            KillTimer(h, 3);
            LONG_PTR ex = GetWindowLongPtrW(h, GWL_EXSTYLE);
            SetWindowLongPtrW(h, GWL_EXSTYLE, ex & ~WS_EX_TRANSPARENT);
            SetWindowPos(h, nullptr, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        }
        if (wp == 4) {
            MenuShiftPopups();
            return 0;
        }
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

// Called from the bar's 500ms reposition tick. Re-queries UIA only when the
// frame moved/resized or every few seconds; otherwise just keeps the overlay
// raised above the frame's own painting.
void MenuReposition(HWND frame) {
    if (!MenuOverlayEnabled()) {
        if (g_menu.hwnd) ShowWindow(g_menu.hwnd, SW_HIDE);
        return;
    }
    if (!frame || !IsWindowVisible(frame)) {
        if (g_menu.hwnd) ShowWindow(g_menu.hwnd, SW_HIDE);
        return;
    }
    // Our modal dialogs cover the menu row; the topmost replica would float
    // over them, so hide it while one is open.
    if (g_modalDepth > 0) {
        if (g_menu.hwnd) ShowWindow(g_menu.hwnd, SW_HIDE);
        return;
    }
    // Frame position first: it is needed both by the pause (following the
    // frame during a drag) and by the normal path (change detection).
    RECT fr{}; GetWindowRect(frame, &fr);
    const bool frameChanged = (fr.left != g_menu.lastFrame.left || fr.top != g_menu.lastFrame.top ||
                               fr.right != g_menu.lastFrame.right || fr.bottom != g_menu.lastFrame.bottom);
    const POINT frameDelta{ fr.left - g_menu.lastFrame.left, fr.top - g_menu.lastFrame.top };
    g_menu.lastFrame = fr;

    // While the mouse is captured by a modal loop on this thread (1C's native
    // menu tracking after a forwarded click, our own popups, a drag), or right
    // after a forwarded click, leave the overlay strictly alone: do not re-query
    // UIA, do not raise it, do not hide it. A UIA re-query from the UI thread
    // re-enters 1C's provider while that thread runs the menu's modal loop, and
    // on a live 8.3.27.2342 that froze the Configurator when the user opened
    // the native «Окна» menu from the overlay replica. The overlay itself stays
    // up -- hiding it would pull the «GitBar» item off the row together with
    // the replicas (that was the first attempt: no hang, but the item visibly
    // vanished for the whole pause). While the menu keeps the capture the
    // overlay receives no mouse input anyway, so the replicas just sit there
    // until the menu closes. The pause lifts after 10 s.
    if (GetCapture() != nullptr ||
        (g_menu.forwardedAt != 0 && GetTickCount() - g_menu.forwardedAt < 10000)) {
        // A title-bar drag also holds the capture: without a follow-up the
        // overlay would stay at the old screen position and separate from the
        // row while the frame moves away (live 8.3.27.2342). Slide the overlay
        // by the frame's delta -- GetWindowRect and SetWindowPos on our own
        // window, no UIA, so the modal-loop freeze does not apply. When the
        // drag ends, the normal path re-queries UIA and snaps to the exact
        // anchor.
        if (g_menu.hwnd && (frameDelta.x != 0 || frameDelta.y != 0)) {
            RECT mr{};
            if (GetWindowRect(g_menu.hwnd, &mr))
                SetWindowPos(g_menu.hwnd, nullptr, mr.left + frameDelta.x, mr.top + frameDelta.y,
                             0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
        return;
    }
    // The pause is over: no menu panel to slide any more.
    if (g_menu.hwnd) KillTimer(g_menu.hwnd, 4);
    g_menu.shiftedCount = 0;
    g_menu.forwardedRect = RECT{};
    ++g_menu.tick;
    if (!g_menu.valid || frameChanged || (g_menu.tick % 8) == 0) {
        if (!MenuQueryLayout(frame)) {
            g_menu.valid = false;
            if (g_menu.hwnd) ShowWindow(g_menu.hwnd, SW_HIDE);
            return;
        }
        g_menu.valid = true;
        if (!g_menu.hwnd) {
            g_menu.hwnd = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED,
                                          L"V8iGitMenu", L"GitBarMenu",
                                          WS_POPUP, 0, 0, g_menu.width, g_menu.rowH,
                                          frame, nullptr, GetModuleHandleW(nullptr), nullptr);
            if (g_menu.hwnd) SetLayeredWindowAttributes(g_menu.hwnd, 0, 255, LWA_ALPHA);
        }
    }
    if (!g_menu.hwnd) return;
    SetWindowPos(g_menu.hwnd, HWND_TOP, g_menu.anchorRight, g_menu.rowTop,
                 g_menu.width, g_menu.rowH, SWP_NOACTIVATE | SWP_SHOWWINDOW);
}

void MenuShutdown() {
    if (g_menu.hwnd) { DestroyWindow(g_menu.hwnd); g_menu.hwnd = nullptr; }
    MenuReleaseTail();
    if (g_menu.toolbar) { g_menu.toolbar->Release(); g_menu.toolbar = nullptr; }
    if (g_menu.toolbarCond) { g_menu.toolbarCond->Release(); g_menu.toolbarCond = nullptr; }
    if (g_menu.buttonCond) { g_menu.buttonCond->Release(); g_menu.buttonCond = nullptr; }
    if (g_menu.uia) { g_menu.uia->Release(); g_menu.uia = nullptr; }
    if (g_menu.font) { DeleteObject(g_menu.font); g_menu.font = nullptr; }
    g_menu.valid = false;
    g_menu.hover = -1;
    g_menu.tick = 0;
}

}  // namespace gitbar

// Called from mainmenu.cpp when the platform really painted the native item:
// the row replica becomes redundant.
void V8iGitBarSetNativeMenu() {
    InterlockedExchange(&gitbar::g_nativeMenu, 1);
    if (gitbar::g_menu.hwnd) ShowWindow(gitbar::g_menu.hwnd, SW_HIDE);
}

}  // namespace v8i