#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
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
#include "gitbar/git_settings.h"
#include "gitbar/git_menu.h"

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
// A132: an action the native menu asked for while the panel was not on screen.
// The UI thread inside transmitCommand cannot wait for the bar (the old show
// joined a previous thread for up to 5 s and polled the window for 0.5 s), so
// the request rides this slot: the bar thread delivers it once its window is
// up. Values: 2 = settings dialog, 11..24 = list actions (kWinId + 10).
volatile LONG g_nativePending = 0;

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

// Every glyph is a picture from the qtv8reader metadata icon set (the open
// MIT metadata-icons set recoloured in a 1C-like palette), selected for each
// GitBar action by tools/select_icons.py and baked to premultiplied BGRA by
// tools/gen_icons.py: 1C's own resource pictures must not be redistributed.
const unsigned char* IconFor(int id) {
    switch (id) {
    case kWinIdDump: return icons::kIconDump;
    case kWinIdDumpExt: return icons::kIconDumpExt;
    case kWinIdInit: return icons::kIconInit;
    case kWinIdClone: return icons::kIconClone;
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
void Reposition(bool forceDock) {
    if (!g_bar.hwnd) { MenuReposition(nullptr); return; }   // thread is winding down
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
    // The menu overlay of the designer hides itself while a modal dialog of
    // the panel is up: the overlay is a separate top-level window and would
    // otherwise float above the dialog.
    ++g_modalDepth;
    MenuReposition(nullptr);
    PumpModalLoop(dlg, true);
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

// git add -A + git commit -F <utf8 file>. The add's result is returned when it
// did not finish cleanly: staging what a stopped `add` managed to collect and
// then committing it would publish a half-updated dump (A76).
GitResult DoCommit(const std::wstring& dir, const std::wstring& msg) {
    const GitResult add = RunGitEx({ L"-C", dir, L"add", L"-A" });
    if (!add.Finished() || add.exitCode != 0) return add;
    std::wstring file = TempMsgPath();
    if (WriteUtf8File(file, msg)) {
        return RunGitEx({ L"-C", dir, L"commit", L"-F", file });
    }
    return RunGitEx({ L"-C", dir, L"commit", L"-m", msg });
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
// A stopped pull keeps its flags, so the caller can say "timeout" instead of
// showing an empty answer as "уже актуально" (A76).
GitResult PullOrigin(const std::wstring& dir, bool allowUnrelated) {
    const std::wstring target = PullTarget(dir);

    if (!allowUnrelated) {
        GitResult r = RunGitEx({ L"-C", dir, L"pull", L"--no-edit" });
        if (!r.Finished()) return r;
        std::wstring out = TrimWs(r.out);
        const bool noUpstream = out.find(L"no tracking information") != std::wstring::npos ||
                                out.find(L"no configured push destination") != std::wstring::npos;
        if (!noUpstream) { r.out = out; return r; }
        if (target.empty()) { r.out = out; return r; }
        r = RunGitEx({ L"-C", dir, L"pull", L"--no-edit", L"origin", target });
        if (!r.Finished()) return r;
        out = TrimWs(r.out);
        if (out.find(L"unrelated histories") == std::wstring::npos) { r.out = out; return r; }
    }
    if (target.empty()) {
        GitResult r;
        r.error = L"не удалось определить ветку origin";
        return r;
    }
    GitResult r = RunGitEx({ L"-C", dir, L"pull", L"--no-edit",
                             L"--allow-unrelated-histories", L"origin", target });
    if (r.Finished()) r.out = TrimWs(r.out);
    return r;
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
    const GitResult clone = RunGitEx({ L"clone", remote, dir }, 600000);
    LogGit(L"clone", TrimForTip(clone.out, 400));
    if (!clone.Finished()) { ShowTip(GitFailureText(clone, 600000)); return; }
    if (!HasDotGit(dir)) {
        std::wstring tip = TrimForTip(clone.out, 200);
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

// git init + the configured origin. Shared by the "Init" cell and by the
// repository gate, which offers init when the dump folder has no repository at
// all (A58).
void InitRepo(const std::wstring& dir) {
    ShowTip(L"git init…");
    const GitResult init = RunGitEx({ L"-C", dir, L"init" });
    LogGit(L"init", TrimForTip(init.out, 400));
    if (!init.Finished()) { ShowTip(GitFailureText(init, kGitTimeoutMs)); return; }

    // An 'origin' makes the push button usable right after init; a stale one
    // is corrected instead of failing with "remote origin already exists".
    std::wstring remote = GitIniGet(L"remote");
    if (!remote.empty()) {
        const GitResult add = RunGitEx({ L"-C", dir, L"remote", L"add", L"origin", remote });
        if (add.out.find(L"already exists") != std::wstring::npos) {
            RunGitEx({ L"-C", dir, L"remote", L"set-url", L"origin", remote });
        }
        LogGit(L"remote origin", remote);
    }

    std::wstring tip = TrimForTip(init.out);
    if (tip.empty()) tip = L"git init: готово";
    ShowTip(tip);
}

void RunInit() {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) { ShowTip(L"нет папки выгрузки (Настройки)"); return; }
    DWORD attr = GetFileAttributesW(dir.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        ShowTip(L"папка выгрузки не найдена: " + dir);
        return;
    }
    InitRepo(dir);
}

// A58: nothing that writes may touch the dump folder before git is asked whether
// the folder owns its repository. `git -C dir add -A`/commit/push walk up to the
// enclosing repository, so "E:\work\proj\dump" inside somebody else's working
// copy used to commit and push that project's files without a word.
bool EnsureDumpRepo(HWND owner, const std::wstring& dir, const wchar_t* title) {
    RepoRootCheck kind = RepoRootCheck::NoRepo;
    std::wstring why;
    if (DumpRepoRootOk(dir, &kind, &why)) return true;
    if (kind == RepoRootCheck::NoRepo) {
        std::wstring msg = why + L"\n\nСоздать git-репозиторий в этой папке?";
        if (MessageBoxW(owner, msg.c_str(), title,
                        MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2) != IDYES) {
            ShowTip(L"нужен git-репозиторий в папке выгрузки");
            return false;
        }
        InitRepo(dir);
        if (DumpRepoRootOk(dir, &kind, &why)) return true;
    }
    MessageBoxW(owner, why.c_str(), title, MB_ICONWARNING);
    return false;
}

void RunCommit() {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) { ShowTip(L"нет папки выгрузки (Настройки)"); return; }
    if (!EnsureDumpRepo(g_bar.hwnd, dir, L"GitBar — коммит")) return;
    std::wstring msg;
    if (!AskCommitMessage(&msg)) return;

    ShowTip(L"git add/commit…");
    const GitResult r = DoCommit(dir, msg);
    LogGit(L"commit", TrimForTip(r.out, 400));
    if (!r.Finished()) { ShowTip(GitFailureText(r, kGitTimeoutMs)); return; }
    std::wstring tip = TrimForTip(r.out);
    if (tip.empty()) tip = L"коммит: готово";
    ShowTip(tip);
}

void RunPush() {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) { ShowTip(L"нет папки выгрузки (Настройки)"); return; }
    if (!EnsureDumpRepo(g_bar.hwnd, dir, L"GitBar — пуш")) return;

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
                const GitResult c = DoCommit(dir, msg);
                LogGit(L"commit before push", TrimForTip(c.out, 400));
                if (!c.Finished()) {
                    // Pushing here would publish the partially staged tree the
                    // stopped commit left behind: stop the whole operation.
                    ShowTip(GitFailureText(c, kGitTimeoutMs));
                    return;
                }
            }
        }
    }

    ShowTip(L"git push…");
    GitResult push = RunGitEx({ L"-C", dir, L"push" });
    if (!push.Finished()) { ShowTip(GitFailureText(push, kGitTimeoutMs)); return; }
    std::wstring out = push.out;
    if (out.find(L"no upstream") != std::wstring::npos ||
        out.find(L"no configured push destination") != std::wstring::npos) {
        // First push: land on the branch the remote already has (main/master),
        // otherwise a README's branch and the dump would become two heads.
        std::wstring target = PullTarget(dir);
        push = target.empty()
                   ? RunGitEx({ L"-C", dir, L"push", L"-u", L"origin", L"HEAD" })
                   : RunGitEx({ L"-C", dir, L"push", L"-u", L"origin", L"HEAD:" + target });
        if (!push.Finished()) { ShowTip(GitFailureText(push, kGitTimeoutMs)); return; }
        out = push.out;
    }
    // The merge above records origin/main as the upstream of the local master.
    // push.default=simple refuses such a pair because the branch names differ,
    // so the upstream target has to be spelled out.
    if (out.find(L"upstream branch of your current branch does not match") !=
        std::wstring::npos) {
        std::wstring target = PullTarget(dir);
        if (!target.empty()) {
            push = RunGitEx({ L"-C", dir, L"push", L"origin", L"HEAD:" + target });
            if (!push.Finished()) { ShowTip(GitFailureText(push, kGitTimeoutMs)); return; }
            out = push.out;
        }
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
        const GitResult merge = PullOrigin(dir, true);
        LogGit(L"pull before push", TrimForTip(merge.out, 400));
        if (!merge.Finished()) {
            out = GitFailureText(merge, kGitTimeoutMs);
        } else if (merge.out.find(L"CONFLICT") != std::wstring::npos ||
                   merge.out.find(L"Automatic merge failed") != std::wstring::npos) {
            out = merge.out;   // the conflict is what the user needs to see
        } else {
            std::wstring target = PullTarget(dir);
            push = target.empty()
                       ? RunGitEx({ L"-C", dir, L"push", L"-u", L"origin", L"HEAD" })
                       : RunGitEx({ L"-C", dir, L"push", L"-u", L"origin", L"HEAD:" + target });
            if (!push.Finished()) { ShowTip(GitFailureText(push, kGitTimeoutMs)); return; }
            out = push.out;
        }
    }
    LogGit(L"push", TrimForTip(out, 400));
    std::wstring tip = TrimForTip(out);
    if (tip.empty()) tip = L"push: готово";
    ShowTip(tip);
}

void RunPull() {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) {
        MessageBoxW(g_bar.hwnd, L"Сначала укажите папку выгрузки в настройках GitBar.",
                    L"Git pull", MB_ICONINFORMATION);
        return;
    }
    if (!EnsureDumpRepo(g_bar.hwnd, dir, L"Git pull")) return;
    ShowTip(L"git pull…");
    const GitResult r = PullOrigin(dir, false);
    // An empty answer from a finished pull means there was nothing to pull; from
    // a stopped one it means the deadline hit (A76).
    const std::wstring text = r.Finished()
                                  ? (r.out.empty() ? std::wstring(L"Уже актуально.") : r.out)
                                  : GitFailureText(r, kGitTimeoutMs);
    MessageBoxW(g_bar.hwnd, text.c_str(), L"Git pull", MB_ICONINFORMATION);
    Reposition(false);
}

void RunFetch() {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) {
        MessageBoxW(g_bar.hwnd, L"Сначала укажите папку выгрузки в настройках GitBar.",
                    L"Git fetch", MB_ICONINFORMATION);
        return;
    }
    if (!EnsureDumpRepo(g_bar.hwnd, dir, L"Git fetch")) return;
    ShowTip(L"git fetch…");
    const GitResult r = RunGitEx({ L"-C", dir, L"fetch", L"--all", L"--prune" });
    const std::wstring out = r.Finished() ? TrimWs(r.out) : GitFailureText(r, kGitTimeoutMs);
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

}  // namespace

namespace gitbar {

// >0 while one of our modal dialogs pumps its own message loop; the menu
// overlay must hide then, it would float over the dialog otherwise.
int g_modalDepth = 0;

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

}  // namespace gitbar

namespace {

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
        // The window is gone from this point: a command that arrives while the
        // thread is still winding down must not be told "already shown" (A55).
        if (g_bar.hwnd == hwnd) g_bar.hwnd = nullptr;
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

    // A132: deliver the action the native menu parked here while the window
    // did not exist yet (it could not wait on the UI thread).
    const LONG pending = InterlockedExchange(&g_nativePending, 0);
    if (g_bar.hwnd) {
        if (pending == 2)
            PostMessageW(g_bar.hwnd, WM_APP + 0x2F14, 0, 0);
        else if (pending >= 11 && pending <= 24)
            PostMessageW(g_bar.hwnd, WM_APP + 0x2F15, (WPARAM)(pending - 10), 0);
    }

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

// A destroyed window leaves g_bar.hwnd cleared by WM_DESTROY, but the thread may
// still be unwinding (a dialog of the panel was open when the close arrived).
// Without this wait the next show would start a second bar thread next to the
// first and leak the handle (A55).
static bool BarThreadJoined(DWORD waitMs) {
    if (!g_bar.thread) {
        g_bar.hwnd = nullptr;
        return true;
    }
    if (WaitForSingleObject(g_bar.thread, waitMs) != WAIT_OBJECT_0) return false;
    CloseHandle(g_bar.thread);
    g_bar.thread = nullptr;
    g_bar.threadId = 0;
    g_bar.hwnd = nullptr;   // the thread clears it too; do not trust the race
    return true;
}

// g_bar.hwnd is only a cache of "the bar exists": after `gitbar hide` the handle
// stays non-null for as long as the thread lives. Everything that asks whether a
// panel is on screen must check the window, not the field (A55).
static bool BarWindowAlive() {
    return g_bar.hwnd != nullptr && IsWindow(g_bar.hwnd) != FALSE;
}

std::string GitBarCommandToJson(const std::wstring& args) {
    std::wstring a = args;
    while (!a.empty() && a.front() == L' ') a.erase(a.begin());

    if (a == L"hide") {
        const bool shown = BarWindowAlive();
        if (shown) PostMessageW(g_bar.hwnd, WM_CLOSE, 0, 0);
        // A bar thread that is inside a dialog gets the WM_CLOSE there; the
        // window's WM_DESTROY posts WM_QUIT and the nested loop re-posts it, so
        // the thread ends instead of losing the quit (A55).
        if (!BarThreadJoined(5000)) {
            return "{\"status\":\"error\",\"visible\":false,"
                   "\"message\":\"toolbar thread did not stop in 5 s\"}";
        }
        if (!shown) return "{\"status\":\"ok\",\"visible\":false,\"note\":\"not shown\"}";
        return "{\"status\":\"ok\",\"visible\":false}";
    }

    if (BarWindowAlive()) {
        return "{\"status\":\"ok\",\"visible\":true,\"note\":\"already shown\"}";
    }
    if (!BarThreadJoined(5000)) {
        return "{\"status\":\"error\",\"message\":\"previous toolbar thread is still running\"}";
    }

    g_bar.thread = CreateThread(nullptr, 0, BarThread, nullptr, 0, &g_bar.threadId);
    if (!g_bar.thread) {
        return "{\"status\":\"error\",\"message\":\"cannot create toolbar thread\"}";
    }
    for (int i = 0; i < 50 && !g_bar.hwnd; ++i) Sleep(10);
    char buf[128];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "{\"status\":\"ok\",\"visible\":%s,\"thread\":\"0x%llX\"}",
                BarWindowAlive() ? "true" : "false", (unsigned long long)g_bar.threadId);
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

// A132: показ панели без единого ожидания. CreateThread возвращается сразу,
// окно бар строит сам; прежний поток, который ещё не завершился, не трогаем —
// дождаться его здесь значило бы заморозить transmit-путь ровно так же, как
// это делал GitBarCommandToJson (до 5 с join + до 0.5 с опроса окна). Застрявший
// поток окно уже не перестроит, поэтому запаркованный запрос при отмене показа
// снимается — иначе он сработал бы на какой-то дальнейший показ.
static void GitBarShowFromUiThread() {
    if (BarWindowAlive()) return;
    if (g_bar.thread) {
        InterlockedExchange(&g_nativePending, 0);
        return;
    }
    g_bar.thread = CreateThread(nullptr, 0, BarThread, nullptr, 0, &g_bar.threadId);
    if (!g_bar.thread) InterlockedExchange(&g_nativePending, 0);
}

// Команды нашей группы из transmit-перехвата (UI-поток). Ничего здесь не
// ждёт: диалог настроек и действия исполняются отложенным сообщением бару
// (внутри transmitCommand платформа разбирает своё меню, модальные диалоги
// там нельзя), а показ панели не блокирует UI-поток (A132) — когда окна нет,
// запрос уезжает в g_nativePending, и поток бара доставит его сам.
void V8iGitBarMenuAction(unsigned num) {
    if (num == 3) {
        // «Скрыть» — WM_CLOSE напрямую: окно получает его в своём же цикле,
        // поток завершается через WM_QUIT, который вернёт вложенный цикл.
        if (BarWindowAlive() && IsWindowVisible(g_bar.hwnd))
            PostMessageW(g_bar.hwnd, WM_CLOSE, 0, 0);
        return;
    }
    if (BarWindowAlive() && IsWindowVisible(g_bar.hwnd)) {
        if (num == 2)
            PostMessageW(g_bar.hwnd, WM_APP + 0x2F14, 0, 0);
        else if (num >= 11 && num <= 24)
            PostMessageW(g_bar.hwnd, WM_APP + 0x2F15, (WPARAM)(num - 10), 0);
        return;
    }
    // Панели на экране нет: запоминаем, что именно попросили, и показываем
    // панель без ожиданий — поток бара откроет диалог/список, как только
    // построит окно.
    if (num == 2 || (num >= 11 && num <= 24)) {
        InterlockedExchange(&g_nativePending, (LONG)num);
        GitBarShowFromUiThread();
    }
}

}  // namespace v8i
