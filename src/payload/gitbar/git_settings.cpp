#include "git_settings.h"

#include "git_service.h"
#include "git_ui.h"

#include <windows.h>
#include <shlobj.h>
#include <string>

namespace v8i {
namespace gitbar {


// ---------------------------------------------------------------------------
// GitBar settings dialog in the 1C classic look.
// Everything is drawn by hand (cream background, white input fields, thin
// borders, flat buttons) the same way the GitBar itself is drawn: child
// controls of a foreign frame render unreliably, and the user wants the box
// to look like a native 1C window.
// ---------------------------------------------------------------------------

namespace {

const wchar_t* kFieldLabels[4] = { L"git.exe", L"папка выгрузки",
                                   L"комментарий к коммиту", L"remote origin (не обяз.)" };
const wchar_t* kFieldIni[4]    = { L"gitpath", L"dumpdir", L"commitmsg", L"remote" };

// Standard shell folder picker for the "..." button. Runs its own modal loop,
// same contract as the MessageBoxes this dialog already uses. COM is
// initialized for the BIF_NEWDIALOGSTYLE UI and released right after.
std::wstring PickFolder(HWND owner) {
    std::wstring res;
    bool comHere = SUCCEEDED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED));
    BROWSEINFOW bi = {};
    bi.hwndOwner = owner;
    bi.lpszTitle = L"Папка выгрузки конфигурации";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        wchar_t buf[MAX_PATH] = {};
        if (SHGetPathFromIDListW(pidl, buf)) res = buf;
        CoTaskMemFree(pidl);
    }
    if (comHere) CoUninitialize();
    return res;
}

struct SettingsCtx {
    std::wstring fields[4];
    size_t caret[4] = {};
    int    active = 0;
    RECT   fieldRects[4];
    RECT   browseRect;          // "..." next to the dumpdir field
    RECT   okRect, cancelRect;
    int    hoverBtn = -1;   // 0 = OK, 1 = Отмена, 2 = "...", -1 = none
    int    pressBtn = -1;
    HFONT  font = nullptr;
    bool   trackedLeave = false;
    bool   hoverX = false;
};

void SettingsLayout(HWND h, SettingsCtx* c) {
    RECT rc;
    GetClientRect(h, &rc);
    const int fx = 150, fw = rc.right - fx - 14, fh = 22;
    for (int i = 0; i < 4; ++i)
        SetRect(&c->fieldRects[i], fx, kCapH + 20 + i * 34, fx + fw, kCapH + 20 + i * 34 + fh);
    // The dumpdir row shrinks to make room for the folder-picker button in
    // the same line (the button rect covers the freed gap, no overlap).
    c->fieldRects[1].right -= 32;
    SetRect(&c->browseRect, fx + fw - 28, kCapH + 20 + 1 * 34, fx + fw, kCapH + 20 + 1 * 34 + fh);
    SetRect(&c->okRect,     fx, kCapH + 166, fx + 84, kCapH + 190);
    SetRect(&c->cancelRect, fx + 94, kCapH + 166, fx + 178, kCapH + 190);
}

int TextWidthTo(HDC dc, HFONT f, const std::wstring& s, size_t n) {
    if (n > s.size()) n = s.size();
    HGDIOBJ old = SelectObject(dc, f);
    SIZE sz{};
    ::GetTextExtentPoint32W(dc, s.c_str(), (int)n, &sz);
    SelectObject(dc, old);
    return sz.cx;
}

size_t CaretFromX(SettingsCtx* c, HWND h, int x) {
    HDC dc = GetDC(h);
    HGDIOBJ old = SelectObject(dc, c->font);
    SIZE sz{};
    size_t best = 0;
    for (size_t i = 0; i <= c->fields[c->active].size(); ++i) {
        ::GetTextExtentPoint32W(dc, c->fields[c->active].c_str(), (int)i, &sz);
        if (c->fieldRects[c->active].left + 4 + sz.cx >= x) { best = i; break; }
        best = i;
    }
    SelectObject(dc, old);
    ReleaseDC(h, dc);
    return best;
}

void UpdateCaretPix(HWND h, SettingsCtx* c) {
    RECT& r = c->fieldRects[c->active];
    HDC dc = GetDC(h);
    int x = r.left + 4 + TextWidthTo(dc, c->font, c->fields[c->active], c->caret[c->active]);
    ReleaseDC(h, dc);
    ::SetCaretPos(x, r.top + 3);
}

void SettingsInvalidateField(HWND h, SettingsCtx* c, int i) {
    InvalidateRect(h, &c->fieldRects[i], FALSE);
}

int SettingsHitButton(SettingsCtx* c, POINT pt) {
    if (PtInRect(&c->okRect, pt)) return 0;
    if (PtInRect(&c->cancelRect, pt)) return 1;
    if (PtInRect(&c->browseRect, pt)) return 2;
    return -1;
}

void SettingsSave(HWND h, SettingsCtx* c) {
    bool ok = true;
    if (!c->fields[0].empty()) ok = GitIniSet(L"gitpath", c->fields[0].c_str()) && ok;
    if (!c->fields[1].empty()) ok = GitIniSet(L"dumpdir", c->fields[1].c_str()) && ok;
    ok = GitIniSet(L"commitmsg", c->fields[2].c_str()) && ok;   // empty = auto "chore: 1c dump <stamp>"
    ok = GitIniSet(L"remote", c->fields[3].c_str()) && ok;
    LogGit(L"settings saved to", GitIniPath());
    if (!ok) {
        MessageBoxW(h, L"Не удалось записать настройки.\nПроверьте права на папку профиля "
                       L"(%APPDATA%\\v8inject).",
                    L"GitBar", MB_ICONERROR);
    }
    DestroyWindow(h);
}

LRESULT CALLBACK SettingsWndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    SettingsCtx* c = (SettingsCtx*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (msg) {
    case WM_PAINT: {
        if (!c) break;
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        HideCaret(h);
        RECT rc;
        GetClientRect(h, &rc);
        HBRUSH bg = CreateSolidBrush(kDlgBg);
        FillRect(dc, &rc, bg);
        DeleteObject(bg);
        HGDIOBJ oldFont = SelectObject(dc, c->font);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, kDlgText);
        // outer frame (1px)
        HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
        HPEN border = CreatePen(PS_SOLID, 1, kDlgBorder);
        HGDIOBJ oldPen = SelectObject(dc, border);
        Rectangle(dc, 0, 0, rc.right - 1, rc.bottom - 1);
        SelectObject(dc, oldPen);
        DeleteObject(border);
        SelectObject(dc, oldBrush);
        DrawCaption(dc, h, c->font, c->hoverX);
        // fields + labels
        for (int i = 0; i < 4; ++i) {
            RECT& fr = c->fieldRects[i];
            HBRUSH fb = CreateSolidBrush(kDlgFieldBg);
            FillRect(dc, &fr, fb);
            DeleteObject(fb);
            HPEN fp = CreatePen(PS_SOLID, 1, kDlgFieldBorder);
            HPEN ofp = (HPEN)SelectObject(dc, fp);
            HBRUSH ofb = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
            Rectangle(dc, fr.left, fr.top, fr.right, fr.bottom);
            SelectObject(dc, ofb);
            SelectObject(dc, ofp);
            DeleteObject(fp);
            RECT tr = fr;
            tr.left += 4;
            tr.right -= 2;
            DrawTextW(dc, c->fields[i].c_str(), (int)c->fields[i].size(), &tr,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            RECT lr = { 12, fr.top, 146, fr.bottom };
            SetTextColor(dc, kDlgLabel);
            DrawTextW(dc, kFieldLabels[i], -1, &lr,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SetTextColor(dc, kDlgText);
        }
        // buttons
        for (int b = 0; b < 2; ++b) {
            RECT& br = b ? c->cancelRect : c->okRect;
            UiDrawButton(dc, br, b ? L"Отмена" : L"OK", c->font,
                         c->hoverBtn == b, c->pressBtn == b);
        }
        // "..." opens the shell folder picker for the dumpdir row
        UiDrawButton(dc, c->browseRect, L"...", c->font,
                     c->hoverBtn == 2, c->pressBtn == 2);
        SelectObject(dc, oldFont);
        ShowCaret(h);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;                             // painted fully in WM_PAINT
    case WM_SETFOCUS:
        if (c) {
            CreateCaret(h, nullptr, 2, 16);
            UpdateCaretPix(h, c);
            ShowCaret(h);
        }
        return 0;
    case WM_KILLFOCUS:
        HideCaret(h);
        DestroyCaret();
        return 0;
    case WM_CHAR:
        if (c && wp >= 32 && c->fields[c->active].size() < 9000) {
            std::wstring& s = c->fields[c->active];
            size_t at = c->caret[c->active];
            s.insert(at, 1, (wchar_t)wp);
            c->caret[c->active] = at + 1;
            UpdateCaretPix(h, c);
            SettingsInvalidateField(h, c, c->active);
            InvalidateRect(h, &c->okRect, FALSE);   // redraw 'OK' in case of
            InvalidateRect(h, &c->cancelRect, FALSE);
        }
        return 0;
    case WM_KEYDOWN:
        if (!c) break;
        if (wp == VK_RETURN) { SettingsSave(h, c); return 0; }
        if (wp == VK_ESCAPE) { DestroyWindow(h); return 0; }
        {
            std::wstring& s = c->fields[c->active];
            size_t& at = c->caret[c->active];
            switch (wp) {
            case VK_BACK:
                if (at > 0) { s.erase(at - 1, 1); --at; }
                break;
            case VK_DELETE:
                if (at < s.size()) s.erase(at, 1);
                break;
            case VK_LEFT:  if (at > 0) --at; break;
            case VK_RIGHT: if (at < s.size()) ++at; break;
            case VK_HOME:  at = 0; break;
            case VK_END:   at = s.size(); break;
            case VK_TAB: {
                int dir = (GetKeyState(VK_SHIFT) & 0x8000) ? -1 : 1;
                c->active = (c->active + dir + 4) % 4;
                UpdateCaretPix(h, c);
                InvalidateRect(h, nullptr, FALSE);
                return 0;
            }
            case 'A':
                if (GetKeyState(VK_CONTROL) & 0x8000) at = s.size();
                break;
            case 'V':
                if (GetKeyState(VK_CONTROL) & 0x8000) {
                    if (OpenClipboard(h)) {
                        HANDLE g = GetClipboardData(CF_UNICODETEXT);
                        if (g) {
                            const wchar_t* t = (const wchar_t*)GlobalLock(g);
                            if (t) {
                                std::wstring p(t);
                                size_t gl = GlobalSize(g) / sizeof(wchar_t);
                                size_t took = wcslen(t);
                                if (gl > 0 && took > gl - 1) took = gl - 1;
                                p = std::wstring(t, took);
                                if (!p.empty()) {
                                    s.insert(at, p);
                                    at += p.size();
                                }
                                GlobalUnlock(g);
                            }
                        }
                        CloseClipboard();
                    }
                }
                break;
            default:
                return 0;
            }
            UpdateCaretPix(h, c);
            SettingsInvalidateField(h, c, c->active);
        }
        return 0;
    case WM_LBUTTONDOWN: {
        if (!c) break;
        SetFocus(h);
        POINT pt = { (int)(short)LOWORD(lp), (int)(short)HIWORD(lp) };
        RECT rc;
        GetClientRect(h, &rc);
        RECT capRect = CapCloseRect(rc);
        if (PtInRect(&capRect, pt)) { DestroyWindow(h); return 0; }
        for (int i = 0; i < 4; ++i) {
            if (PtInRect(&c->fieldRects[i], pt)) {
                if (c->active != i) {
                    c->active = i;
                    InvalidateRect(h, nullptr, FALSE);
                }
                c->caret[i] = CaretFromX(c, h, pt.x);
                UpdateCaretPix(h, c);
                return 0;
            }
        }
        int b = SettingsHitButton(c, pt);
        if (b >= 0) { c->pressBtn = b; c->hoverBtn = b; InvalidateRect(h, nullptr, FALSE); }
        return 0;
    }
    case WM_LBUTTONUP: {
        if (!c || c->pressBtn < 0) break;
        POINT pt = { (int)(short)LOWORD(lp), (int)(short)HIWORD(lp) };
        int b = SettingsHitButton(c, pt);
        if (b == c->pressBtn && b == 0) { c->pressBtn = -1; SettingsSave(h, c); return 0; }
        if (b == c->pressBtn && b == 1) { c->pressBtn = -1; DestroyWindow(h); return 0; }
        if (b == c->pressBtn && b == 2) {
            c->pressBtn = -1;
            std::wstring dir = PickFolder(h);
            if (!dir.empty()) {
                c->fields[1] = dir;
                c->caret[1] = dir.size();
                if (c->active == 1) UpdateCaretPix(h, c);
                SettingsInvalidateField(h, c, 1);
            }
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }
        c->pressBtn = -1;
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    }
    case WM_MOUSEMOVE: {
        if (!c) break;
        if (!c->trackedLeave) {
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, h, 0 };
            TrackMouseEvent(&tme);
            c->trackedLeave = true;
        }
        POINT pt = { (int)(short)LOWORD(lp), (int)(short)HIWORD(lp) };
        int b = SettingsHitButton(c, pt);
        if (b != c->hoverBtn) { c->hoverBtn = b; InvalidateRect(h, nullptr, FALSE); }
        RECT rc;
        GetClientRect(h, &rc);
        RECT capRect = CapCloseRect(rc);
        bool hv = PtInRect(&capRect, pt) != 0;
        if (hv != c->hoverX) { c->hoverX = hv; InvalidateRect(h, nullptr, FALSE); }
        return 0;
    }
    case WM_MOUSELEAVE:
        if (c) {
            c->hoverBtn = -1; c->trackedLeave = false; c->hoverX = false;
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    case WM_NCHITTEST:
        return CapHitTest(h, wp, lp);
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

}  // namespace

bool g_settingsClassRegistered = false;

void ShowSettings(HWND owner) {
    if (!g_settingsClassRegistered) {
        WNDCLASSW wc = {};
        wc.lpfnWndProc = SettingsWndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = L"V8iGitBarSettings";
        if (!RegisterClassW(&wc)) return;
        g_settingsClassRegistered = true;
    }

    SettingsCtx ctx;
    ctx.font = CreateDlgFont();
    ctx.fields[0] = GitExe();
    if (ctx.fields[0] == L"git.exe" && GetFileAttributesW(L"C:\\Program Files\\Git\\cmd\\git.exe")
                                         != INVALID_FILE_ATTRIBUTES) {
        ctx.fields[0] = L"C:\\Program Files\\Git\\cmd\\git.exe";
    }
    ctx.fields[1] = GitIniGet(L"dumpdir");
    ctx.fields[2] = GitIniGet(L"commitmsg");
    ctx.fields[3] = GitIniGet(L"remote");

    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"V8iGitBarSettings", L"GitBar — настройки",
                               WS_POPUP | WS_VISIBLE,
                               CW_USEDEFAULT, CW_USEDEFAULT, 460, 232 + kCapH, owner, nullptr,
                               GetModuleHandleW(nullptr), nullptr);
    if (!dlg) { DeleteObject(ctx.font); return; }
    CenterOnOwner(dlg, owner);
    SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)&ctx);
    SettingsLayout(dlg, &ctx);

    SetForegroundWindow(dlg);
    SetFocus(dlg);

    ModalEnter();
    PumpModalLoop(dlg, false);
    if (IsWindow(dlg)) DestroyWindow(dlg);
    DeleteObject(ctx.font);
    ModalLeave(true);
}

}  // namespace gitbar
}  // namespace v8i
