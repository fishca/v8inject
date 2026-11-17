#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <uiautomation.h>
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "v8inject/diag.h"
#include "v8inject/ini.h"
#include "v8inject/text.h"
#include "icons.h"
#include "gitbar/git_service.h"
#include "gitbar/git_ui.h"
#include "gitbar/git_log.h"
#include "gitbar/git_lists.h"

#include <cstdlib>
#include <cstring>

extern "C" void V8iGitBarDump();  // v8i_export.cpp
extern "C" void V8iGitBarDumpExtension();

// Git toolbar ("GitBar") for the running 1C configurator.
//
// The designer's UI is fully custom-painted (no Win32 menus), so the git
// controls live in a real Win32 window created INSIDE the 1C process and
// parented to the configurator frame, docked at the right end of the toolbar
// row. Everything is drawn by hand in WM_PAINT: owner-drawn BUTTON children
// were invisible here (the frame's own toolbar children paint over them and
// the WM_DRAWITEM round-trip is unreliable in a foreign message loop), so the
// strip draws its five 16px glyphs itself and hit-tests clicks.
//
//   [1] dump   -- 1C dumps the configuration to files (designer command 45)
//   [2] init   -- git init in the dump folder (+ optional 'origin' remote)
//   [3] commit -- git add -A + git commit -F <msg>; asks for the message
//   [4] push   -- git push (offers to commit a dirty tree first)
//   [5] gear   -- settings
//
//   gitbar            -- show the toolbar (creates the window + thread)
//   gitbar hide       -- destroy it
// Config: %APPDATA%\v8inject\gitbar.ini
//   [git] gitpath=<full path to git.exe>
//        dumpdir=<folder the user dumps the config into>
//        commitmsg=<default commit message, asked at every commit>
//        remote=<origin URL, used by 'init' (optional)>
//        compactwidth=<client width below which the bar collapses to a menu
//                      button; default 900, 0 disables the compact mode>

#ifndef TTM_POPUP
#define TTM_POPUP (WM_USER + 34)
#endif

namespace v8i {

using namespace v8i::gitbar;

namespace {
// ---------------------------------------------------------------------------
// Hand-drawn 1C-style strip: everything painted in WM_PAINT, clicks hit-tested.
// ---------------------------------------------------------------------------

const int kCell = 24;       // per-button cell width
const int kCells = 12;      // action cells
// The strip ends with an overflow cell (the same ellipsis as in compact mode):
// the popup menu is the only place where clone lives, and on a wide window the
// full strip has no other way to open it.
const int kBarW = 2 + (kCells + 1) * kCell + 2;
const int kCompactW = 2 + kCell + 2;   // collapsed: one chevron cell
const int kBarH = 24;
const int kDockY = 28;      // toolbar row, just under the menu
const int kWinIdDump = 1, kWinIdInit = 2, kWinIdCommit = 3,
          kWinIdPush = 4, kWinIdSettings = 5, kWinIdLog = 6,
          kWinIdPull = 7, kWinIdFetch = 8, kWinIdBranches = 9,
          kWinIdStash = 10, kWinIdTags = 11, kWinIdStatus = 12;
// Clone has no cell of its own: it only exists in the popup action list, next
// to git init (init for an empty folder, clone for a repository already on the
// server).
const int kWinIdClone = 13;
// Extension dump has no cell of its own either: it only makes sense with the
// «Расширения конфигурации» window active, so it lives in the action list.
const int kWinIdDumpExt = 14;
const int kWinIdMenu = 100; // overflow/compact chevron; opens the action list

int MenuCellX() { return 2 + kCells * kCell; }

// Indexed by cell id - 1, so the table must stay aligned with the ids.
const wchar_t* kCellTexts[kCells] = {
    L"Выгрузить исходники: конфигурация в файлы (команда 45)",
    L"git init в папке выгрузки (+ origin из настроек)",
    L"Коммит изменений (спросит комментарий)",
    L"Пуш в удалённый репозиторий",
    L"Настройки: git.exe, папка выгрузки, комментарий, remote",
    L"История коммитов (git log --graph)",
    L"Забрать изменения из удалённого репозитория (git pull)",
    L"Получить изменения без слияния (git fetch --all --prune)",
    L"Ветки: переключить или удалить (git branch -a)",
    L"Отложенные изменения: применить или удалить (git stash list)",
    L"Теги: удалить или отправить в origin (git tag -n1)",
    L"Рабочая копия: индексировать, снять, коммит (git status)",
};
const wchar_t* kCompactTip = L"GitBar свёрнута: все команды — в меню";
const wchar_t* kMenuTip = L"Все команды GitBar: клонирование, ветки, теги, stash, настройки";

struct GitBar {
    HWND hwnd = nullptr;
    HWND tooltip = nullptr;
    HWND statusTip = nullptr;   // separate tracking tip for action feedback
    int hover = 0;          // cell index under the cursor (1..kCells), 0 = none
    bool pressed = false;
    bool dragging = false;
    bool compact = false;   // one chevron instead of the 12 cells
    bool menuOpen = false;  // TrackPopupMenu is modal: pause repositioning
    POINT pressPt{};
    RECT lastFrame{};
    DWORD threadId = 0;
    HANDLE thread = nullptr;
};

GitBar g_bar;
// True on 8.5+: the designer paints its client through DWM, so a child window
// never shows; the bar is a top-level owned window there instead.
bool g_topLevelDwm = false;
// >0 while one of our modal dialogs pumps its own message loop; the menu
// overlay must hide then, it would float over the dialog otherwise.
int g_modalDepth = 0;

int CellX(int id) { return 2 + (id - 1) * kCell; }

int IdFromPoint(POINT pt) {
    if (pt.y < 0 || pt.y >= kBarH) return 0;
    if (g_bar.compact) return pt.x >= 0 && pt.x < kCompactW ? kWinIdMenu : 0;
    for (int id = 1; id <= kCells; ++id) {
        int x = CellX(id);
        if (pt.x >= x && pt.x < x + kCell) return id;
    }
    int mx = MenuCellX();
    if (pt.x >= mx && pt.x < mx + kCell) return kWinIdMenu;
    return 0;
}

void SetCompact(bool compact) {
    if (g_bar.compact == compact) return;
    g_bar.compact = compact;
    g_bar.hover = 0;
    if (g_bar.tooltip && g_bar.hwnd) {
        // Tool 1 covers the chevron once the bar shrinks to one cell.
        TOOLINFOW ti{ sizeof(ti) };
        ti.hwnd = g_bar.hwnd;
        ti.uId = 1;
        ti.lpszText = (LPWSTR)(compact ? kCompactTip : kCellTexts[0]);
        SendMessageW(g_bar.tooltip, TTM_UPDATETIPTEXTW, 0, (LPARAM)&ti);
    }
    if (g_bar.hwnd) InvalidateRect(g_bar.hwnd, nullptr, FALSE);
}

int BarW() { return g_bar.compact ? kCompactW : kBarW; }

// Every glyph is a 1C toolbar picture, baked to premultiplied BGRA by
// tools/gen_icons.py: hand-drawn GDI shapes never matched the platform's look,
// and these do because they come from the same resource bundles.
const unsigned char* IconFor(int id) {
    switch (id) {
    case kWinIdDump: return icons::kIconDump;
    case kWinIdInit: return icons::kIconInit;
    case kWinIdCommit: return icons::kIconCommit;
    case kWinIdPush: return icons::kIconPush;
    case kWinIdSettings: return icons::kIconSettings;
    case kWinIdLog: return icons::kIconLog;
    case kWinIdPull: return icons::kIconPull;
    case kWinIdFetch: return icons::kIconFetch;
    case kWinIdBranches: return icons::kIconBranches;
    case kWinIdStash: return icons::kIconStash;
    case kWinIdTags: return icons::kIconTags;
    case kWinIdStatus: return icons::kIconStatus;
    // Menu-only actions: no PNG of their own yet, so borrow the closest glyph.
    case kWinIdClone: return icons::kIconBranches;   // the whole repo tree
    case kWinIdDumpExt: return icons::kIconDump;     // same operation, extension
    }
    return nullptr;
}

void DrawIcon(HDC dc, const unsigned char* px, int ox, int oy) {
    if (!px) return;
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = icons::kSize;
    bi.bmiHeader.biHeight = -icons::kSize;  // top-down, same as the array
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HBITMAP bmp = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!bmp || !bits) {
        if (bmp) DeleteObject(bmp);
        return;
    }
    memcpy(bits, px, (size_t)icons::kSize * icons::kSize * 4);

    HDC mem = CreateCompatibleDC(dc);
    HGDIOBJ old = SelectObject(mem, bmp);
    BLENDFUNCTION bf{ AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    AlphaBlend(dc, ox, oy, icons::kSize, icons::kSize, mem, 0, 0,
               icons::kSize, icons::kSize, bf);
    SelectObject(mem, old);
    DeleteDC(mem);
    DeleteObject(bmp);
}

// The overflow cell: three dots, the same glyph in the compact bar and at the
// end of the full strip.
void PaintMenuCell(HDC dc, const RECT& cell) {
    if (g_bar.hover == kWinIdMenu) {
        HBRUSH hl = CreateSolidBrush(g_bar.pressed ? kDlgPress : kDlgHover);
        FillRect(dc, &cell, hl);
        DeleteObject(hl);
    }
    HBRUSH dot = CreateSolidBrush(kDlgText);
    int cx = (cell.left + cell.right) / 2, cy = (cell.top + cell.bottom) / 2;
    for (int i = -1; i <= 1; ++i) {
        RECT r{ cx + i * 6 - 1, cy - 1, cx + i * 6 + 2, cy + 2 };
        FillRect(dc, &r, dot);
    }
    DeleteObject(dot);
}

void Paint(HWND hwnd) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);
    RECT rc{};
    GetClientRect(hwnd, &rc);

    // Panel background and a 1C-ish border, so the strip reads as a toolbar.
    HBRUSH bg = CreateSolidBrush(kDlgBg);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);
    HPEN border = CreatePen(PS_SOLID, 1, kDlgBorder);
    HGDIOBJ oldPen = SelectObject(dc, border);
    HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, rc.left, rc.top, rc.right, rc.bottom);
    // The pen and the brush have to be put back before they are deleted:
    // a deleted object that is still selected in the DC is a dangling handle
    // for every later draw with that DC.
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(border);

    if (g_bar.compact) {
        // One cell with an ellipsis: the actions live in its popup menu.
        RECT cell{ 0, 1, kCompactW, kBarH - 1 };
        PaintMenuCell(dc, cell);
        EndPaint(hwnd, &ps);
        return;
    }

    for (int id = 1; id <= kCells; ++id) {
        int x = CellX(id);
        RECT cell{ x, 1, x + kCell, kBarH - 1 };
        if (id == g_bar.hover) {
            HBRUSH hl = CreateSolidBrush(g_bar.pressed ? kDlgPress : kDlgHover);
            FillRect(dc, &cell, hl);
            DeleteObject(hl);
            HPEN pen = CreatePen(PS_SOLID, 1, kDlgBorder);
            HGDIOBJ cellPen = SelectObject(dc, pen);
            HGDIOBJ cellBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
            Rectangle(dc, cell.left, cell.top, cell.right, cell.bottom);
            SelectObject(dc, cellBrush);
            SelectObject(dc, cellPen);
            DeleteObject(pen);
        }
        DrawIcon(dc, IconFor(id), x + (kCell - icons::kSize) / 2,
                 (kBarH - icons::kSize) / 2);
    }
    RECT menuCell{ MenuCellX(), 1, MenuCellX() + kCell, kBarH - 1 };
    PaintMenuCell(dc, menuCell);
    EndPaint(hwnd, &ps);
}

// Docks the bar at the right end of the toolbar row unless the user dragged
// it; keeps it raised above the frame's own toolbar children, which 1C
// re-creates and would otherwise paint over us.
void MenuReposition(HWND frame);   // main-menu overlay, defined below

void Reposition(bool forceDock) {
    HWND frame = GetParent(g_bar.hwnd);
    if (!frame) { frame = FindFrame(); if (frame) SetParent(g_bar.hwnd, frame); }
    if (!frame) { MenuReposition(nullptr); return; }

    RECT cr{};
    GetClientRect(frame, &cr);
    int w = cr.right - cr.left;
    int h = cr.bottom - cr.top;

    // The full strip is ~300px wide; on a narrow designer window it would sit
    // on top of 1C's own toolbar buttons, so below the ini threshold it
    // collapses into a single chevron cell.
    int threshold = CompactThreshold();
    bool compact = threshold > 0 && w < threshold;
    bool modeChanged = (compact != g_bar.compact);
    SetCompact(compact);
    if (g_bar.menuOpen) return;   // the popup follows the bar on the next tick
    int barW = BarW();

    RECT cur{};
    GetWindowRect(g_bar.hwnd, &cur);
    POINT tl{ cur.left, cur.top };
    bool hiddenMinimized = false;
    if (g_topLevelDwm) {
        // 8.5 renders its client through DWM: a child window is reported
        // visible but never painted. The bar must be a top-level owned window;
        // follow the frame in screen coordinates and hide with it.
        POINT origin{ 0, 0 };
        ClientToScreen(frame, &origin);      // client (0,0) in screen space
        tl.x = origin.x + (w - barW - 4);
        if (tl.x < origin.x) tl.x = origin.x;
        tl.y = origin.y + kDockY;
        if (!IsWindowVisible(frame)) { ShowWindow(g_bar.hwnd, SW_HIDE); hiddenMinimized = true; }
        else if (!IsWindowVisible(g_bar.hwnd)) { ShowWindow(g_bar.hwnd, SW_SHOWNOACTIVATE); }
    } else {
        ScreenToClient(frame, &tl);
        bool frameChanged = (cr.right != g_bar.lastFrame.right ||
                             cr.bottom != g_bar.lastFrame.bottom);
        g_bar.lastFrame = cr;
        if (forceDock || frameChanged || modeChanged) {
            tl.x = w - barW - 4;
            tl.y = kDockY;
        }
        if (tl.x < 0) tl.x = 0;
        if (tl.y < 0) tl.y = 0;
        int maxX = w - barW; if (maxX < 0) maxX = 0;
        int maxY = h - kBarH; if (maxY < 0) maxY = 0;
        if (tl.x > maxX) tl.x = maxX;
        if (tl.y > maxY) tl.y = maxY;
    }
    if (hiddenMinimized) { MenuReposition(frame); return; }
    // The size is always passed along: a mode switch while the frame was
    // minimized must still resize the (hidden) window.
    SetWindowPos(g_bar.hwnd, HWND_TOP, tl.x, tl.y, barW, kBarH,
                 SWP_NOACTIVATE | (g_topLevelDwm ? 0 : SWP_SHOWWINDOW));
    MenuReposition(frame);
}

// The per-button tools are TTF_SUBCLASS and must stay silent unless hovered, so
// action feedback uses its own tracking tool: it is placed under the bar and
// switched off by timer 2.
const UINT_PTR kStatusTipId = 100;

void HideStatusTip() {
    if (!g_bar.statusTip || !g_bar.hwnd) return;
    TOOLINFOW ti{ sizeof(ti), TTF_TRACK };
    ti.hwnd = g_bar.hwnd;
    ti.uId = kStatusTipId;
    SendMessageW(g_bar.statusTip, TTM_TRACKACTIVATE, FALSE, (LPARAM)&ti);
}

void ShowTip(const std::wstring& text) {
    if (!g_bar.statusTip || !g_bar.hwnd) return;
    TOOLINFOW ti{ sizeof(ti), TTF_TRACK };
    ti.hwnd = g_bar.hwnd;
    ti.uId = kStatusTipId;
    ti.lpszText = (LPWSTR)text.c_str();
    SendMessageW(g_bar.statusTip, TTM_UPDATETIPTEXTW, 0, (LPARAM)&ti);
    POINT pt{ 0, kBarH + 2 };
    ClientToScreen(g_bar.hwnd, &pt);
    SendMessageW(g_bar.statusTip, TTM_TRACKPOSITION, 0, MAKELPARAM(pt.x, pt.y));
    SendMessageW(g_bar.statusTip, TTM_TRACKACTIVATE, TRUE, (LPARAM)&ti);
    KillTimer(g_bar.hwnd, 2);
    SetTimer(g_bar.hwnd, 2, 3000, nullptr);
    LogGit(L"tip", text);
}

bool PromptText(HWND owner, const wchar_t* title, const wchar_t* label,
                const std::wstring& initial, std::wstring* out) {
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"#32770", title,
                               WS_POPUP | WS_VISIBLE,
                               CW_USEDEFAULT, CW_USEDEFAULT, 470, 160 + kCapH, owner, nullptr,
                               GetModuleHandleW(nullptr), nullptr);
    if (!dlg) return false;
    CenterOnOwner(dlg, owner);

    PromptCtx ctx;
    ctx.out = out;
    ctx.font = CreateDlgFont();
    SetWindowLongPtrW(dlg, GWLP_WNDPROC, (LONG_PTR)PromptDlgProc);
    SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)&ctx);

    HWND label1 = CreateWindowExW(0, L"STATIC", label, WS_CHILD | WS_VISIBLE | SS_LEFT,
                                  12, 12 + kCapH, 430, 18, dlg, nullptr,
                                  GetModuleHandleW(nullptr), nullptr);
    SendMessageW(label1, WM_SETFONT, (WPARAM)ctx.font, TRUE);
    // borderless: PromptDlgProc paints the 1C field frame around it
    HWND ed = CreateWindowExW(0, L"EDIT", L"",
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                              13, 35 + kCapH, 428, 22, dlg, (HMENU)1001,
                              GetModuleHandleW(nullptr), nullptr);
    SendMessageW(ed, WM_SETFONT, (WPARAM)ctx.font, TRUE);
    SendMessageW(ed, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                 MAKELPARAM(2, 2));
    ctx.ed = ed;
    SetWindowTextW(ed, initial.c_str());
    SendMessageW(ed, EM_SETSEL, 0, -1);
    HWND ok = CreateWindowExW(0, L"BUTTON", L"OK",
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                              BS_DEFPUSHBUTTON | BS_OWNERDRAW,
                              252, 72 + kCapH, 90, 26, dlg, (HMENU)(INT_PTR)IDOK,
                              GetModuleHandleW(nullptr), nullptr);
    HWND cancel = CreateWindowExW(0, L"BUTTON", L"Отмена",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                                  352, 72 + kCapH, 90, 26, dlg, (HMENU)(INT_PTR)IDCANCEL,
                                  GetModuleHandleW(nullptr), nullptr);
    ThemedButton(ok, ctx.font);
    ThemedButton(cancel, ctx.font);

    SetForegroundWindow(dlg);
    SetFocus(ed);

    // IsDialogMessageW gives Tab / Enter (default button) / Esc for free; it
    // posts nothing into this loop, it drives the dialog proc above directly.
    MSG msg;
    // The menu overlay of the designer hides itself while a modal dialog of
    // the panel is up: the overlay is a separate top-level window and would
    // otherwise float above the dialog.
    ++g_modalDepth;
    MenuReposition(nullptr);
    for (;;) {
        if (!IsWindow(dlg)) break;
        if (!GetMessageW(&msg, nullptr, 0, 0)) break;   // WM_QUIT: the bar is going away
        if (IsDialogMessageW(dlg, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    --g_modalDepth;
    if (IsWindow(dlg)) DestroyWindow(dlg);
    if (ctx.font) DeleteObject(ctx.font);
    Reposition(true);
    return ctx.accepted;
}

// Commit message: the ini value is only a default — it is asked every time.
bool AskCommitMessage(std::wstring* msg) {
    std::wstring def = GitIniGet(L"commitmsg");
    if (def.empty()) def = L"chore: 1c dump " + NowStamp();
    if (!PromptText(g_bar.hwnd, L"GitBar — комментарий к коммиту",
                    L"Комментарий (git commit -m):", def, msg)) {
        ShowTip(L"коммит отменён");
        return false;
    }
    if (msg->empty()) *msg = def;
    GitIniSet(L"commitmsg", msg->c_str());
    return true;
}

// git add -A + git commit -F <utf8 file>. Returns git's output.
std::wstring DoCommit(const std::wstring& dir, const std::wstring& msg) {
    RunGit({ L"-C", dir, L"add", L"-A" });
    std::wstring file = TempMsgPath();
    if (WriteUtf8File(file, msg)) {
        return RunGit({ L"-C", dir, L"commit", L"-F", file });
    }
    return RunGit({ L"-C", dir, L"commit", L"-m", msg });
}

std::wstring LocalBranch(const std::wstring& dir) {
    std::wstring b = TrimWs(RunGit({ L"-C", dir, L"rev-parse", L"--abbrev-ref", L"HEAD" }));
    return b == L"HEAD" ? std::wstring() : b;
}

// GitHub names the first branch either main or master, and a repository created
// with a README has its commit on that branch. Pull requests must use that name,
// not the local one: pulling origin/master from a main-only repository fails.
std::wstring RemoteDefaultBranch(const std::wstring& dir) {
    std::wstring refs = RunGit({ L"-C", dir, L"ls-remote", L"--symref", L"origin", L"HEAD" });
    const std::wstring prefix = L"ref: refs/heads/";
    size_t p = refs.find(prefix);
    if (p == std::wstring::npos) return std::wstring();
    size_t start = p + prefix.size();
    size_t end = refs.find_first_of(L"\r\n\t ", start);
    return refs.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
}

std::wstring UpstreamBranch(const std::wstring& dir) {
    std::wstring u = TrimWs(RunGit({ L"-C", dir, L"rev-parse", L"--abbrev-ref",
                                     L"--symbolic-full-name", L"@{u}" }));
    const std::wstring prefix = L"origin/";
    if (u.rfind(prefix, 0) != 0) return std::wstring();
    return u.substr(prefix.size());
}

// The branch to pull from and push to: the upstream once it exists, then the
// branch GitHub already has, then the local name.
std::wstring PullTarget(const std::wstring& dir) {
    std::wstring b = UpstreamBranch(dir);
    if (!b.empty()) return b;
    b = RemoteDefaultBranch(dir);
    if (!b.empty()) return b;
    return LocalBranch(dir);
}

// Pull that also works right after git init (no upstream yet) and against a
// repository with an unrelated history — GitHub's initial README commit.
std::wstring PullOrigin(const std::wstring& dir, bool allowUnrelated) {
    std::wstring target = PullTarget(dir);

    if (!allowUnrelated) {
        std::wstring out = TrimWs(RunGit({ L"-C", dir, L"pull", L"--no-edit" }));
        if (out.find(L"no tracking information") == std::wstring::npos &&
            out.find(L"no configured push destination") == std::wstring::npos) {
            return out;
        }
        if (target.empty()) return out;
        out = TrimWs(RunGit({ L"-C", dir, L"pull", L"--no-edit", L"origin", target }));
        if (out.find(L"unrelated histories") == std::wstring::npos) return out;
    }
    if (target.empty()) return L"не удалось определить ветку origin";
    return TrimWs(RunGit({ L"-C", dir, L"pull", L"--no-edit",
                           L"--allow-unrelated-histories", L"origin", target }));
}

bool DirHasEntries(const std::wstring& dir) {
    std::wstring pattern = dir;
    if (pattern.empty() || pattern.back() != L'\\') pattern += L'\\';
    pattern += L'*';
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool any = false;
    do {
        if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
            any = true;
            break;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return any;
}

int CALLBACK BrowseInitProc(HWND h, UINT msg, LPARAM, LPARAM data) {
    if (msg == BFFM_INITIALIZED && data)
        SendMessageW(h, BFFM_SETSELECTIONW, TRUE, data);
    return 0;
}

bool PickFolder(HWND owner, const wchar_t* title, const std::wstring& initial,
                std::wstring* out) {
    BROWSEINFOW bi{};
    bi.hwndOwner = owner;
    bi.lpszTitle = title;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_EDITBOX;
    bi.lpfn = BrowseInitProc;
    bi.lParam = (LPARAM)(initial.empty() ? nullptr : initial.c_str());
    LPITEMIDLIST idl = SHBrowseForFolderW(&bi);
    if (!idl) return false;
    wchar_t path[MAX_PATH] = {};
    bool ok = SHGetPathFromIDListW(idl, path) != FALSE;
    CoTaskMemFree(idl);
    if (ok) *out = path;
    return ok;
}

// A repository created on GitHub (with README, .gitignore, license) exists
// before the configuration is dumped anywhere. Cloning it into the dump folder
// makes the folder a normal clone, so the first push is a fast-forward and the
// unrelated-histories merge is not needed at all.
void RunClone() {
    std::wstring def = GitIniGet(L"remote");
    std::wstring remote;
    if (!PromptText(g_bar.hwnd, L"GitBar — клонирование репозитория",
                    L"URL репозитория (git clone):", def, &remote)) {
        ShowTip(L"клонирование отменено");
        return;
    }
    if (remote.empty()) { ShowTip(L"не указан URL репозитория"); return; }

    std::wstring dir;
    for (;;) {
        // BIF_NEWDIALOGSTYLE needs COM on this thread; the bar thread never
        // initializes it for anything else.
        HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        std::wstring pick;
        bool picked = PickFolder(g_bar.hwnd, L"Куда клонировать (папка должна быть пустой)",
                                 GitIniGet(L"dumpdir"), &pick);
        if (SUCCEEDED(hr)) CoUninitialize();
        if (!picked) { ShowTip(L"клонирование отменено"); return; }

        if (DirHasEntries(pick)) {
            if (MessageBoxW(g_bar.hwnd,
                            (L"Папка не пуста:\n" + pick +
                             L"\n\ngit clone разворачивается только в пустую "
                             L"или ещё не созданную папку. Выбрать другую?").c_str(),
                            L"GitBar — клонирование",
                            MB_OKCANCEL | MB_ICONINFORMATION) != IDOK) {
                ShowTip(L"клонирование отменено");
                return;
            }
            continue;
        }
        dir = pick;
        break;
    }

    ShowTip(L"git clone…");
    std::wstring out = RunGit({ L"clone", remote, dir }, 600000);
    LogGit(L"clone", TrimForTip(out, 400));
    std::wstring gitDir = dir;
    if (gitDir.empty() || gitDir.back() != L'\\') gitDir += L'\\';
    if (GetFileAttributesW((gitDir + L".git").c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wstring tip = TrimForTip(out, 200);
        ShowTip(tip.empty() ? L"clone: ошибка" : tip);
        return;
    }

    GitIniSet(L"dumpdir", dir.c_str());
    GitIniSet(L"remote", remote.c_str());
    ShowTip(L"клонировано: " + dir);

    // The clone is only the container for the dump: offer the next step at once.
    if (MessageBoxW(g_bar.hwnd,
                    (L"Репозиторий склонирован в:\n" + dir +
                     L"\n\nВыгрузить конфигурацию в файлы сейчас?").c_str(),
                    L"GitBar — клонирование", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        ShowTip(L"выгрузка конфигурации в файлы…");
        V8iGitBarDump();
    }
}

void RunInit() {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) { ShowTip(L"нет папки выгрузки (Настройки)"); return; }
    DWORD attr = GetFileAttributesW(dir.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        ShowTip(L"папка выгрузки не найдена: " + dir);
        return;
    }

    ShowTip(L"git init…");
    std::wstring out = RunGit({ L"-C", dir, L"init" });
    LogGit(L"init", TrimForTip(out, 400));

    // An 'origin' makes the push button usable right after init; a stale one
    // is corrected instead of failing with "remote origin already exists".
    std::wstring remote = GitIniGet(L"remote");
    if (!remote.empty()) {
        std::wstring add = RunGit({ L"-C", dir, L"remote", L"add", L"origin", remote });
        if (add.find(L"already exists") != std::wstring::npos) {
            RunGit({ L"-C", dir, L"remote", L"set-url", L"origin", remote });
        }
        LogGit(L"remote origin", remote);
    }

    std::wstring tip = TrimForTip(out);
    if (tip.empty()) tip = L"git init: готово";
    ShowTip(tip);
}

void RunCommit() {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) { ShowTip(L"нет папки выгрузки (Настройки)"); return; }
    std::wstring msg;
    if (!AskCommitMessage(&msg)) return;

    ShowTip(L"git add/commit…");
    std::wstring out = DoCommit(dir, msg);
    LogGit(L"commit", TrimForTip(out, 400));
    std::wstring tip = TrimForTip(out);
    if (tip.empty()) tip = L"коммит: готово";
    ShowTip(tip);
}

void RunPush() {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) { ShowTip(L"нет папки выгрузки (Настройки)"); return; }

    // git push takes no message of its own, so a dirty tree is where the
    // comment belongs: offer to commit it with the same prompt, then push.
    std::wstring status = RunGit({ L"-C", dir, L"status", L"--porcelain" });
    if (!TrimForTip(status, 8).empty()) {
        if (MessageBoxW(g_bar.hwnd,
                        L"В папке выгрузки есть незакоммиченные изменения.\n"
                        L"Закоммитить их с комментарием и запушить?",
                        L"GitBar — пуш", MB_YESNO | MB_ICONQUESTION) == IDYES) {
            std::wstring msg;
            if (AskCommitMessage(&msg)) {
                std::wstring c = DoCommit(dir, msg);
                LogGit(L"commit before push", TrimForTip(c, 400));
            }
        }
    }

    ShowTip(L"git push…");
    std::wstring out = RunGit({ L"-C", dir, L"push" });
    if (out.find(L"no upstream") != std::wstring::npos ||
        out.find(L"no configured push destination") != std::wstring::npos) {
        // First push: land on the branch the remote already has (main/master),
        // otherwise a README's branch and the dump would become two heads.
        std::wstring target = PullTarget(dir);
        out = target.empty()
                  ? RunGit({ L"-C", dir, L"push", L"-u", L"origin", L"HEAD" })
                  : RunGit({ L"-C", dir, L"push", L"-u", L"origin", L"HEAD:" + target });
    }
    // The merge above records origin/main as the upstream of the local master.
    // push.default=simple refuses such a pair because the branch names differ,
    // so the upstream target has to be spelled out.
    if (out.find(L"upstream branch of your current branch does not match") !=
        std::wstring::npos) {
        std::wstring target = PullTarget(dir);
        if (!target.empty())
            out = RunGit({ L"-C", dir, L"push", L"origin", L"HEAD:" + target });
    }

    // A repo created on GitHub with a README already has a commit, so the very
    // first push is rejected: the histories are unrelated until they are merged.
    bool rejected = out.find(L"rejected") != std::wstring::npos ||
                    out.find(L"non-fast-forward") != std::wstring::npos ||
                    out.find(L"remote contains work") != std::wstring::npos;
    if (rejected &&
        MessageBoxW(g_bar.hwnd,
                    L"В удалённом репозитории уже есть коммиты, которых нет локально "
                    L"(обычно README).\n\n"
                    L"Слить истории (git pull --allow-unrelated-histories) и повторить push?",
                    L"GitBar — пуш", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        ShowTip(L"git pull --allow-unrelated-histories…");
        std::wstring merge = PullOrigin(dir, true);
        LogGit(L"pull before push", TrimForTip(merge, 400));
        if (merge.find(L"CONFLICT") != std::wstring::npos ||
            merge.find(L"Automatic merge failed") != std::wstring::npos) {
            out = merge;   // the conflict is what the user needs to see
        } else {
            std::wstring target = PullTarget(dir);
            out = target.empty()
                      ? RunGit({ L"-C", dir, L"push", L"-u", L"origin", L"HEAD" })
                      : RunGit({ L"-C", dir, L"push", L"-u", L"origin", L"HEAD:" + target });
        }
    }
    LogGit(L"push", TrimForTip(out, 400));
    std::wstring tip = TrimForTip(out);
    if (tip.empty()) tip = L"push: готово";
    ShowTip(tip);
}

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

    MSG msg;
    ++g_modalDepth;
    MenuReposition(nullptr);   // hide the menu overlay at once, not on next tick
    for (;;) {
        if (!IsWindow(dlg)) break;
        if (!GetMessageW(&msg, nullptr, 0, 0)) break;   // WM_QUIT
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    --g_modalDepth;
    if (IsWindow(dlg)) DestroyWindow(dlg);
    DeleteObject(ctx.font);
    Reposition(true);
}

void RunPull() {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) {
        MessageBoxW(g_bar.hwnd, L"Сначала укажите папку выгрузки в настройках GitBar.",
                    L"Git pull", MB_ICONINFORMATION);
        return;
    }
    ShowTip(L"git pull…");
    std::wstring out = PullOrigin(dir, false);
    MessageBoxW(g_bar.hwnd, out.empty() ? L"Уже актуально." : out.c_str(),
                L"Git pull", MB_ICONINFORMATION);
    Reposition(false);
}

void RunFetch() {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) {
        MessageBoxW(g_bar.hwnd, L"Сначала укажите папку выгрузки в настройках GitBar.",
                    L"Git fetch", MB_ICONINFORMATION);
        return;
    }
    ShowTip(L"git fetch…");
    std::wstring out = TrimWs(RunGit({ L"-C", dir, L"fetch", L"--all", L"--prune" }));
    MessageBoxW(g_bar.hwnd, out.empty() ? L"Обновлено (без изменений)." : out.c_str(),
                L"Git fetch", MB_ICONINFORMATION);
    Reposition(false);
}

void DoAction(int id);

// Compact mode hides the twelve cells; the same actions come from this popup.
// TPM_RETURNCMD makes TrackPopupMenu return the selection to this loop instead
// of posting WM_COMMAND, so the bar's own DoAction runs the command.
// The popup is owner-drawn to match the designer's own submenus (cream face,
// brown items, rust shortcuts, pale-blue rounded hover); TrackPopupMenu still
// provides the modal dismiss / keyboard behaviour.
struct ActionItem { int id; const wchar_t* text; const wchar_t* hint; bool sepBefore; };
const ActionItem kActionItems[] = {
    { kWinIdDump,     L"Выгрузить исходники в файлы",  L"команда 45", true },
    { kWinIdDumpExt,  L"Выгрузить расширение в файлы", L"команда 205", false },
    { kWinIdInit,     L"Создать репозиторий в папке выгрузки", L"git init", false },
    { kWinIdClone,    L"Клонировать репозиторий…",     L"git clone", false },
    { kWinIdCommit,   L"Коммит изменений…",            L"git commit", false },
    { kWinIdPush,     L"Пуш в удалённый репозиторий",  L"git push", false },
    { kWinIdPull,     L"Забрать изменения",            L"git pull", true },
    { kWinIdFetch,    L"Получить изменения",           L"git fetch", false },
    { kWinIdBranches, L"Ветки…",                       L"git branch", true },
    { kWinIdStash,    L"Отложенные изменения…",        L"git stash", false },
    { kWinIdTags,     L"Теги…",                        L"git tag", false },
    { kWinIdStatus,   L"Рабочая копия…",               L"git status", false },
    { kWinIdLog,      L"История коммитов",             L"git log", false },
    { kWinIdSettings, L"Настройки…",                   L"", true },
};

HFONT SubFont() {
    static HFONT f = CreateDlgFont();
    return f;
}

// Shared column widths for the whole popup: the gold hint column sits on one
// common right-aligned x, the way the shortcut column does in a live 1C
// submenu. Computed once before TrackPopupMenu; measure and draw read it.
struct ActionMetrics { int textW = 0; int hintW = 0; bool hasHint = false; };
ActionMetrics g_actionMetrics;

void ActionMenuComputeMetrics() {
    g_actionMetrics = {};
    HDC dc = GetDC(nullptr);
    HFONT old = (HFONT)SelectObject(dc, SubFont());
    for (const ActionItem& it : kActionItems) {
        SIZE sz{};
        GetTextExtentPoint32W(dc, it.text, (int)wcslen(it.text), &sz);
        g_actionMetrics.textW = std::max(g_actionMetrics.textW, (int)sz.cx);
        if (it.hint[0]) {
            GetTextExtentPoint32W(dc, it.hint, (int)wcslen(it.hint), &sz);
            g_actionMetrics.hintW = std::max(g_actionMetrics.hintW, (int)sz.cx);
            g_actionMetrics.hasHint = true;
        }
    }
    SelectObject(dc, old);
    ReleaseDC(nullptr, dc);
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

void ActionMenuMeasure(LPMEASUREITEMSTRUCT m) {
    if (!m->itemData) { m->itemWidth = 0; m->itemHeight = kSubSepH; return; }
    // One common width for every row so the hint column lines up.
    m->itemWidth = kSubTextX + g_actionMetrics.textW +
                   (g_actionMetrics.hasHint ? 24 + g_actionMetrics.hintW + 16 : 24);
    m->itemHeight = kSubItemH;
}

void ActionMenuDraw(LPDRAWITEMSTRUCT d) {
    HDC dc = d->hDC;
    RECT rc = d->rcItem;
    FillRect(dc, &rc, UiMenuBrush());
    // The darker icon-gutter strip; painted for separators too, so the band
    // runs unbroken from the top of the popup to its bottom.
    RECT gut{ rc.left, rc.top, rc.left + kSubGutter, rc.bottom };
    FillRect(dc, &gut, UiGutterBrush());
    if (!d->itemData) {
        // The line starts at the gutter strip, not on it.
        RECT line{ rc.left + kSubGutter, (rc.top + rc.bottom) / 2, rc.right - 8,
                   (rc.top + rc.bottom) / 2 + 1 };
        HBRUSH sb = CreateSolidBrush(kSubSep);
        FillRect(dc, &line, sb);
        DeleteObject(sb);
        return;
    }
    const ActionItem* it = (const ActionItem*)d->itemData;
    bool en = (d->itemState & ODS_DISABLED) == 0;
    bool sel = en && (d->itemState & ODS_SELECTED) != 0;
    if (sel) DrawSubHover(dc, rc);
    const unsigned char* px = IconFor(it->id);
    if (px) DrawIcon(dc, px, rc.left + (kSubGutter - icons::kSize) / 2,
                     rc.top + (kSubItemH - icons::kSize) / 2);
    SetBkMode(dc, TRANSPARENT);
    COLORREF tx = !en  ? Blend(kMenuText, kMenuBg, 115)
                : sel  ? kMenuHoverText
                       : kMenuText;
    SetTextColor(dc, tx);
    HFONT old = (HFONT)SelectObject(dc, SubFont());
    RECT tr{ rc.left + kSubTextX, rc.top, rc.right - 8, rc.bottom };
    DrawTextW(dc, it->text, -1, &tr, DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
    // The platform underlines the mnemonic (the first character) while its
    // submenu is open.
    int len = (int)wcslen(it->text);
    if (en && len > 0) {
        SIZE full{}, first{};
        GetTextExtentPoint32W(dc, it->text, len, &full);
        GetTextExtentPoint32W(dc, it->text, 1, &first);
        int uy = rc.top + (kSubItemH - full.cy) / 2 + full.cy - 1;
        HPEN up = CreatePen(PS_SOLID, 1, tx);
        HGDIOBJ op = SelectObject(dc, up);
        MoveToEx(dc, rc.left + kSubTextX, uy, nullptr);
        LineTo(dc, rc.left + kSubTextX + first.cx, uy);
        SelectObject(dc, op);
        DeleteObject(up);
    }
    // The right column: gold git command, as the shortcut column in the
    // platform's own submenus.
    if (it->hint[0]) {
        SetTextColor(dc, en ? kSubShortcut : Blend(kSubShortcut, kMenuBg, 115));
        RECT hr{ rc.right - 16 - g_actionMetrics.hintW, rc.top, rc.right - 16, rc.bottom };
        DrawTextW(dc, it->hint, -1, &hr,
                  DT_RIGHT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
    }
    SelectObject(dc, old);
}

void ShowActionMenu(HWND owner) {
    ActionMenuComputeMetrics();
    HMENU menu = CreatePopupMenu();
    if (!menu) return;
    for (const ActionItem& it : kActionItems) {
        if (it.sepBefore) AppendMenuW(menu, MF_OWNERDRAW | MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_OWNERDRAW, (UINT_PTR)it.id, (LPCWSTR)&it);
    }
    MENUINFO mi{ sizeof(mi) };
    mi.fMask = MIM_BACKGROUND;
    mi.hbrBack = UiMenuBrush();
    SetMenuInfo(menu, &mi);
    POINT pt{ 0, kBarH };
    ClientToScreen(owner, &pt);
    // The owner must be foreground, otherwise the menu does not dismiss on an
    // outside click; the trailing WM_NULL is the documented follow-up. On 8.3
    // the bar is a child window, so foreground the frame instead.
    HWND top = GetAncestor(owner, GA_ROOT);
    SetForegroundWindow(top ? top : owner);
    g_bar.menuOpen = true;
    int cmd = (int)TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_LEFTALIGN | TPM_TOPALIGN,
        pt.x, pt.y, 0, owner, nullptr);
    g_bar.menuOpen = false;
    PostMessageW(owner, WM_NULL, 0, 0);
    DestroyMenu(menu);
    if (cmd) DoAction(cmd);
}

void DoAction(int id) {
    switch (id) {
    case kWinIdDump: {
        ShowTip(L"выгрузка конфигурации в файлы…");
        V8iGitBarDump();
        break;
    }
    case kWinIdDumpExt: {
        ShowTip(L"выгрузка расширения: активным должно быть окно «Расширения конфигурации»");
        V8iGitBarDumpExtension();
        break;
    }
    case kWinIdInit: RunInit(); break;
    case kWinIdClone: RunClone(); break;
    case kWinIdCommit: RunCommit(); break;
    case kWinIdPush: RunPush(); break;
    case kWinIdPull: RunPull(); break;
    case kWinIdFetch: RunFetch(); break;
    case kWinIdBranches: ShowList(g_bar.hwnd, 1); break;
    case kWinIdStash: ShowList(g_bar.hwnd, 2); break;
    case kWinIdTags: ShowList(g_bar.hwnd, 3); break;
    case kWinIdStatus: ShowList(g_bar.hwnd, 0); break;
    case kWinIdSettings: ShowSettings(g_bar.hwnd); break;
    case kWinIdLog: ShowGitLog(g_bar.hwnd); break;
    case kWinIdMenu: ShowActionMenu(g_bar.hwnd); break;
    }
}

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

LRESULT CALLBACK BarWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_PAINT:
        Paint(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;  // WM_PAINT fills everything

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

    // Right-click anywhere on the strip opens the action list too: clone has no
    // cell of its own and lives only in that menu. WM_CONTEXTMENU is handled
    // for the keyboard menu key; the mouse path is WM_RBUTTONUP because the
    // designer's frame swallows the DefWindowProc translation on 8.3.
    case WM_RBUTTONUP:
    case WM_CONTEXTMENU:
        ShowActionMenu(hwnd);
        return 0;

    // Deferred command from the native menu transmit trap (mainmenu.cpp):
    // the settings dialog opens on a normal message, not inside
    // transmitCommand where the platform is tearing its menu down.
    case WM_APP + 0x2F14:
        ShowSettings(hwnd);
        return 0;

    // Native GitBar menu action (mainmenu.cpp table, num = kWinId + 10):
    // the same actions the overlay bar ran through DoAction, deferred the
    // same way — modal dialogs must not open inside transmitCommand.
    case WM_APP + 0x2F15:
        DoAction((int)wp);
        return 0;

    case WM_MOUSEMOVE: {
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        if (g_bar.dragging && (wp & MK_LBUTTON)) {
            HWND frame = GetParent(hwnd);
            if (frame) {
                RECT cr{};
                GetClientRect(frame, &cr);
                int w = cr.right - cr.left;
                int x = pt.x - g_bar.pressPt.x;
                int maxX = w - BarW(); if (maxX < 0) maxX = 0;
                if (x < 0) x = 0;
                if (x > maxX) x = maxX;
                int y = pt.y - g_bar.pressPt.y;
                if (y < 0) y = 0;
                SetWindowPos(hwnd, HWND_TOP, x, y, 0, 0,
                             SWP_NOSIZE | SWP_NOACTIVATE);
            }
            return 0;
        }
        int id = IdFromPoint(pt);
        if (id != g_bar.hover) {
            g_bar.hover = id;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        // Ask for WM_MOUSELEAVE so the highlight clears when the mouse leaves.
        TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, hwnd, 0 };
        TrackMouseEvent(&tme);
        return 0;
    }

    case WM_MOUSELEAVE:
        if (g_bar.hover) {
            g_bar.hover = 0;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;

    case WM_LBUTTONDOWN: {
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        g_bar.pressPt = pt;
        g_bar.pressed = true;
        g_bar.dragging = false;
        SetCapture(hwnd);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_LBUTTONUP: {
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        int moved = abs(pt.x - g_bar.pressPt.x) + abs(pt.y - g_bar.pressPt.y);
        bool wasDragging = g_bar.dragging;
        g_bar.pressed = false;
        g_bar.dragging = false;
        ReleaseCapture();
        InvalidateRect(hwnd, nullptr, FALSE);
        if (!wasDragging && moved < 5) {
            int id = IdFromPoint(pt);
            if (id) DoAction(id);
        }
        return 0;
    }

    case WM_TIMER:
        if (wp == 1) Reposition(false);
        else if (wp == 2) {
            KillTimer(hwnd, 2);
            HideStatusTip();
        }
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, 1);
        KillTimer(hwnd, 2);
        if (g_bar.statusTip) {
            DestroyWindow(g_bar.statusTip);
            g_bar.statusTip = nullptr;
        }
        if (g_bar.tooltip) {
            DestroyWindow(g_bar.tooltip);
            g_bar.tooltip = nullptr;
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

DWORD WINAPI BarThread(LPVOID) {
    HINSTANCE hInst = GetModuleHandleW(nullptr);

    // UI Automation (main-menu overlay) and the shell dialogs need COM on this
    // thread; STA matches the UIA client model.
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_BAR_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSW wc{};
    wc.lpfnWndProc = BarWndProc;
    wc.hInstance = hInst;
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"V8iGitBar";
    RegisterClassW(&wc);

    WNDCLASSW mc{};
    mc.lpfnWndProc = MenuWndProc;
    mc.hInstance = hInst;
    mc.hbrBackground = nullptr;
    mc.lpszClassName = L"V8iGitMenu";
    mc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassW(&mc);

    HWND frame = FindFrame();
    if (!frame) return 0;
    {
        wchar_t fcls[64] = {};
        GetClassNameW(frame, fcls, 64);
        // 8.3 designer: V8TopLevelFrame (GDI child windows work there).
        // 8.5 designer: V8Window0.* (DWM-composed client) -- use a top-level
        // owned window, otherwise the bar is never painted on screen.
        g_topLevelDwm = (wcsstr(fcls, L"V8Window0") != nullptr);
    }
    if (g_topLevelDwm) {
        g_bar.hwnd = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED,
                                     L"V8iGitBar", L"GitBar",
                                     WS_POPUP | WS_VISIBLE,
                                     0, kDockY, kBarW, kBarH, frame, nullptr, hInst, nullptr);
        if (g_bar.hwnd) {
            SetLayeredWindowAttributes(g_bar.hwnd, 0, 255, LWA_ALPHA);
        }
    } else {
        g_bar.hwnd = CreateWindowExW(0, L"V8iGitBar", L"GitBar",
                                     WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                     0, kDockY, kBarW, kBarH, frame, nullptr, hInst, nullptr);
    }

    // Tooltips: one tool per cell, hit by rect.
    g_bar.tooltip = CreateWindowExW(0, TOOLTIPS_CLASSW, nullptr,
                                    WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                    CW_USEDEFAULT, CW_USEDEFAULT, 0, 0,
                                    g_bar.hwnd, nullptr, hInst, nullptr);
    if (g_bar.tooltip) {
        SendMessageW(g_bar.tooltip, TTM_SETMAXTIPWIDTH, 0, 360);
        for (int i = 0; i < kCells; ++i) {
            TOOLINFOW ti{ sizeof(ti), TTF_SUBCLASS };
            ti.hwnd = g_bar.hwnd;
            ti.uId = (UINT_PTR)(i + 1);
            int x = CellX(i + 1);
            ti.rect = { x, 1, x + kCell, kBarH - 1 };
            ti.lpszText = (LPWSTR)kCellTexts[i];
            SendMessageW(g_bar.tooltip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
        }
        // Overflow cell: the same popup menu as the compact chevron.
        TOOLINFOW mi{ sizeof(mi), TTF_SUBCLASS };
        mi.hwnd = g_bar.hwnd;
        mi.uId = (UINT_PTR)(kCells + 1);
        int mx = MenuCellX();
        mi.rect = { mx, 1, mx + kCell, kBarH - 1 };
        mi.lpszText = (LPWSTR)kMenuTip;
        SendMessageW(g_bar.tooltip, TTM_ADDTOOLW, 0, (LPARAM)&mi);
    }
    // Action feedback lives in its own tracking tool (see ShowTip): a subclass
    // tool spanning the whole bar would mask the per-cell tools.
    g_bar.statusTip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
                                      WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                      CW_USEDEFAULT, CW_USEDEFAULT, 0, 0,
                                      g_bar.hwnd, nullptr, hInst, nullptr);
    if (g_bar.statusTip) {
        TOOLINFOW ti{ sizeof(ti), TTF_TRACK };
        ti.hwnd = g_bar.hwnd;
        ti.uId = kStatusTipId;
        ti.lpszText = (LPWSTR)L"";
        SendMessageW(g_bar.statusTip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
        SendMessageW(g_bar.statusTip, TTM_SETMAXTIPWIDTH, 0, 480);
    }

    GetClientRect(frame, &g_bar.lastFrame);
    SetTimer(g_bar.hwnd, 1, 500, nullptr);
    Reposition(true);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    MenuShutdown();
    CoUninitialize();
    g_bar.hwnd = nullptr;
    g_bar.tooltip = nullptr;
    g_bar.statusTip = nullptr;
    return 0;
}

}  // namespace

namespace gitbar {

void ModalEnter() {
    ++g_modalDepth;
    MenuReposition(nullptr);   // hide the menu overlay at once, not on next tick
}

void ModalLeave(bool forceDock) {
    --g_modalDepth;   // the dialog itself is already gone; free the bar again
    Reposition(forceDock);
}

void BarReposition(bool forceDock) {
    Reposition(forceDock);
}

void RunCommitAction() {
    RunCommit();
}

}  // namespace gitbar

std::string GitBarCommandToJson(const std::wstring& args) {
    std::wstring a = args;
    while (!a.empty() && a.front() == L' ') a.erase(a.begin());

    if (a == L"hide") {
        if (g_bar.hwnd) {
            PostMessageW(g_bar.hwnd, WM_CLOSE, 0, 0);
            if (g_bar.thread) {
                WaitForSingleObject(g_bar.thread, 3000);
                CloseHandle(g_bar.thread);
            }
            g_bar.thread = nullptr;
            g_bar.threadId = 0;
        }
        return "{\"status\":\"ok\",\"visible\":false}";
    }

    if (g_bar.hwnd) {
        return "{\"status\":\"ok\",\"visible\":true,\"note\":\"already shown\"}";
    }

    g_bar.thread = CreateThread(nullptr, 0, BarThread, nullptr, 0, &g_bar.threadId);
    if (!g_bar.thread) {
        return "{\"status\":\"error\",\"message\":\"cannot create toolbar thread\"}";
    }
    for (int i = 0; i < 50 && !g_bar.hwnd; ++i) Sleep(10);
    char buf[128];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "{\"status\":\"ok\",\"visible\":%s,\"thread\":\"0x%llX\"}",
                g_bar.hwnd ? "true" : "false", (unsigned long long)g_bar.threadId);
    return buf;
}

// Called from the extension-dump worker thread (v8i_export.cpp) with the
// "wrong active window" hint. The tip control belongs to the bar thread, which
// is pumping messages after DoAction returned, so the cross-thread SendMessage
// inside ShowTip is safe.
void GitBarTipFromWorker(const wchar_t* text) { ShowTip(text ? text : L""); }

// --- нативный пункт меню (src/payload/mainmenu.cpp) -------------------------

// Путь к gitbar.ini — для ключа [git] nativemenu в mainmenu.cpp.
const wchar_t* V8iGitBarIniPath() {
    return GitIniPath();
}

// Вызывается mainmenu.cpp, когда платформа реально нарисовала нативный пункт:
// реплика в ряду меню становится лишней.
void V8iGitBarSetNativeMenu() {
    InterlockedExchange(&g_nativeMenu, 1);
    if (g_menu.hwnd) ShowWindow(g_menu.hwnd, SW_HIDE);
}

// Команды нашей группы из transmit-перехвата (UI-поток). Диалог настроек
// открывается отложенно — обычным сообщением бару, не внутри transmitCommand,
// где платформа разбирает своё меню. «Скрыть» — WM_CLOSE напрямую (без
// ожидания потока панели: UI-поток в transmit не должен блокироваться).
void V8iGitBarMenuAction(unsigned num) {
    if (num == 2) {
        if (!g_bar.hwnd || !IsWindowVisible(g_bar.hwnd)) GitBarCommandToJson(L"");
        if (g_bar.hwnd) PostMessageW(g_bar.hwnd, WM_APP + 0x2F14, 0, 0);
    } else if (num == 3) {
        if (g_bar.hwnd && IsWindowVisible(g_bar.hwnd))
            PostMessageW(g_bar.hwnd, WM_CLOSE, 0, 0);
        else
            GitBarCommandToJson(L"");
    } else if (num >= 11 && num <= 24) {
        // Действия нативного меню (mainmenu.cpp, номер = kWinId + 10):
        // исполняются в цикле бара (DoAction) отложенным сообщением —
        // модальные диалоги нельзя открывать внутри transmitCommand.
        if (!g_bar.hwnd) GitBarCommandToJson(L"");
        if (g_bar.hwnd) PostMessageW(g_bar.hwnd, WM_APP + 0x2F15, num - 10, 0);
    }
}

}  // namespace v8i
