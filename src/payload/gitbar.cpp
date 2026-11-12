#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <uiautomation.h>
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "v8inject/diag.h"
#include "icons.h"

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

namespace {

const wchar_t* kIniPath() {
    static wchar_t path[MAX_PATH] = {};
    if (!path[0]) {
        ExpandEnvironmentStringsW(L"%APPDATA%\\v8inject\\gitbar.ini", path, MAX_PATH);
    }
    return path;
}

std::wstring IniGet(const wchar_t* key) {
    wchar_t buf[1024] = {};
    GetPrivateProfileStringW(L"git", key, L"", buf, 1024, kIniPath());
    return buf;
}

// Writes one key of the gitbar ini. Returns false when the file could not be
// written -- on a machine that never ran v8inject the %APPDATA%\v8inject
// folder does not exist, and WritePrivateProfileString then fails silently,
// so the settings look saved and are not.
bool IniSet(const wchar_t* key, const wchar_t* value) {
    wchar_t dir[MAX_PATH] = {};
    if (ExpandEnvironmentStringsW(L"%APPDATA%\\v8inject", dir, MAX_PATH) > 0)
        CreateDirectoryW(dir, nullptr);          // ERROR_ALREADY_EXISTS is fine
    if (!WritePrivateProfileStringW(L"git", key, value, kIniPath())) {
        LogLine("gitbar: cannot write ini key %ls (win32 %lu)", key, GetLastError());
        return false;
    }
    return true;
}

// Client width below which the full strip would cover the designer's own
// toolbar buttons; the bar then collapses to a single menu button instead.
// 0 disables the compact mode. Read on every reposition, so a hand-edited
// ini takes effect without restarting 1C.
int CompactThreshold() {
    wchar_t buf[32] = {};
    GetPrivateProfileStringW(L"git", L"compactwidth", L"900", buf, 32, kIniPath());
    int v = (int)wcstol(buf, nullptr, 10);
    if (v < 0) v = 0;
    return v > 10000 ? 10000 : v;
}

std::wstring GitExe() {
    std::wstring p = IniGet(L"gitpath");
    if (p.empty()) p = L"git.exe";  // fall back to PATH
    return p;
}

std::wstring Utf8ToWideOf(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}

// Trim + squeeze for tooltips: git output is multi-line and CRLF-terminated.
std::wstring TrimForTip(const std::wstring& s, size_t maxLen = 160) {
    std::wstring out;
    bool space = false;
    for (wchar_t c : s) {
        if (c == L'\r' || c == L'\n' || c == L'\t' || c == L' ') {
            space = !out.empty();
            continue;
        }
        if (space) { out += L' '; space = false; }
        out += c;
        if (out.size() >= maxLen) { out += L"…"; break; }
    }
    return out;
}

std::wstring TrimWs(const std::wstring& s) {
    size_t b = s.find_first_not_of(L" \t\r\n");
    if (b == std::wstring::npos) return L"";
    size_t e = s.find_last_not_of(L" \t\r\n");
    return s.substr(b, e - b + 1);
}

// LogLine takes a narrow printf format and vfprintf converts %ls with the "C"
// locale: any Cyrillic character in the text makes the conversion fail and the
// whole argument prints empty. Convert to UTF-8 and pass it as %s instead.
std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n, nullptr, nullptr);
    return out;
}

void LogGit(const wchar_t* what, const std::wstring& text) {
    std::string u = WideToUtf8(text);
    LogLine("gitbar: %s: %s", WideToUtf8(what).c_str(), u.c_str());
}

// Runs "<gitpath> <args>" and returns stdout + stderr. Only ever runs from the
// toolbar's own thread. A git that waits for console input (credential prompt)
// is killed at the deadline instead of hanging the panel forever.
std::wstring RunGit(const std::vector<std::wstring>& args, DWORD timeoutMs = 120000) {
    std::wstring cmdline = L"\"" + GitExe() + L"\"";
    for (const std::wstring& a : args) {
        cmdline += L" \"";
        cmdline += a;
        cmdline += L"\"";
    }

    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE outRd = nullptr, outWr = nullptr;
    if (!CreatePipe(&outRd, &outWr, &sa, 0)) return L"<pipe failed>";
    SetHandleInformation(outRd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{ sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = outWr;
    si.hStdError = outWr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::wstring cmd = cmdline;  // CreateProcessW may write into it
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(outRd);
        CloseHandle(outWr);
        wchar_t b[128];
        _snwprintf_s(b, _countof(b), _TRUNCATE, L"<cannot start git (win32 %lu)>", GetLastError());
        return b;
    }
    CloseHandle(outWr);

    std::string out;
    char buf[4096];
    DWORD start = GetTickCount();
    bool exited = false;
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(outRd, nullptr, 0, nullptr, &avail, nullptr)) break;  // closed
        if (avail) {
            DWORD rd = 0;
            // Read exactly what the pipe holds. A byte-mode pipe blocks until
            // the whole requested count arrives, so asking for the full buffer
            // while only a few dozen bytes are buffered would hang here until
            // the writer closes -- and the timeout below would never be
            // reached.
            DWORD want = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
            if (!ReadFile(outRd, buf, want, &rd, nullptr) || rd == 0) break;
            out.append(buf, rd);
            continue;
        }
        if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) { exited = true; break; }
        if (GetTickCount() - start > timeoutMs) {
            TerminateProcess(pi.hProcess, 1);
            out.append("\n<timeout>");
            break;
        }
    }
    if (exited) {  // drain whatever is still buffered in the pipe
        DWORD avail = 0;
        while (PeekNamedPipe(outRd, nullptr, 0, nullptr, &avail, nullptr) && avail) {
            DWORD rd = 0;
            DWORD want = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
            if (!ReadFile(outRd, buf, want, &rd, nullptr) || rd == 0) break;
            out.append(buf, rd);
        }
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(outRd);
    return Utf8ToWideOf(out);
}

std::wstring NowStamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t b[64];
    _snwprintf_s(b, _countof(b), _TRUNCATE, L"%04d-%02d-%02d %02d:%02d:%02d",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}

// git reads the commit message from a file: argv quoting of a Cyrillic
// multi-line message is a lottery, a UTF-8 file without BOM is not.
std::wstring TempMsgPath() {
    wchar_t dir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, dir);
    return std::wstring(dir) + L"v8i_commitmsg.txt";
}

bool WriteUtf8File(const std::wstring& path, const std::wstring& text) {
    int n = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(),
                                nullptr, 0, nullptr, nullptr);
    if (n <= 0) return false;
    std::string u((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), &u[0], n, nullptr, nullptr);

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    bool ok = WriteFile(h, u.data(), (DWORD)u.size(), &wr, nullptr) && wr == u.size();
    CloseHandle(h);
    return ok;
}

HWND FindFrame() {
    struct Ctx { HWND h; DWORD pid; } ctx = { nullptr, GetCurrentProcessId() };
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        Ctx* c = (Ctx*)lp;
        DWORD pid = 0;
        GetWindowThreadProcessId(h, &pid);
        if (pid != c->pid) return TRUE;
        wchar_t cls[64] = {};
        GetClassNameW(h, cls, 64);
        if (wcscmp(cls, L"V8iGitBar") == 0) return TRUE;
        wchar_t title[64] = {};
        GetWindowTextW(h, title, 64);
        if (title[0] && IsWindowVisible(h)) { c->h = h; return FALSE; }
        return TRUE;
    }, (LPARAM)&ctx);
    return ctx.h;
}

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

// ---------------------------------------------------------------------------
// Shared 1C-style window theme: the classic cream platform-dialog skin measured
// from a live «Выгрузить файлы конфигурации» dialog — cream face, beige buttons
// with a 1px #B3AC86 frame, white fields, rust field captions and a light-blue
// list selection. Used by the bar, settings, prompt, list and history windows.
// ---------------------------------------------------------------------------

const COLORREF kDlgBg      = RGB(252, 250, 235);   // FCFAEB dialog face
const COLORREF kDlgBorder  = RGB(179, 172, 134);   // B3AC86 group / button frame
const COLORREF kDlgFieldBg = RGB(255, 255, 255);
const COLORREF kDlgFieldBorder = RGB(141, 141, 141);  // 8D8D8D edit frame
const COLORREF kDlgBtnFace = RGB(215, 211, 189);   // D7D3BD button face
const COLORREF kDlgHover   = RGB(252, 250, 196);   // FCFAC4 pale-yellow hover
const COLORREF kDlgPress   = RGB(205, 199, 171);
const COLORREF kDlgText    = RGB(51, 51, 51);      // 333333
const COLORREF kDlgLabel   = RGB(158, 82, 42);     // 9E522A rust field caption
const COLORREF kDlgSel     = RGB(158, 216, 235);   // 9ED8EB light-blue selection
const COLORREF kDlgSelIdle = RGB(212, 208, 200);
const COLORREF kDlgCaption = RGB(204, 204, 204);   // CCCCCC classic caption band
const int kCapH = 22;                              // caption height, as in 1C dialogs

// Main-menu row and dropdown-submenu palette, sampled from the live designer's
// «Администрирование» dropdown.
const COLORREF kMenuBg         = RGB(248, 247, 238);  // F8F7EE menu face
const COLORREF kMenuText       = RGB(65, 48, 3);      // 413003 dark-brown item
const COLORREF kMenuHoverBorder = RGB(158, 182, 233); // 9EB6E9
const COLORREF kMenuHoverText  = RGB(61, 78, 143);    // 3D4E8F
const COLORREF kSubShortcut    = RGB(179, 128, 0);    // B38000 shortcut column
const COLORREF kSubSep         = RGB(217, 213, 194);  // D9D5C2 separator line
const COLORREF kSubGutterBg    = RGB(233, 229, 206);  // E9E5CE icon column strip
const int kSubItemH = 22;
const int kSubSepH = 7;
const int kSubGutter = 28;   // icon column, as in 1C submenus
const int kSubTextX = kSubGutter + 6;   // labels start 6 px past the strip

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
    SelectObject(dc, border);
    SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, rc.left, rc.top, rc.right, rc.bottom);
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
            SelectObject(dc, pen);
            SelectObject(dc, GetStockObject(NULL_BRUSH));
            Rectangle(dc, cell.left, cell.top, cell.right, cell.bottom);
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

// One-field modal prompt (commit message). WS_VISIBLE is not decoration: a
// top-level window created without it is never shown, and the modal loop below
// would then wait on an invisible dialog.
// A button notifies its parent with a SENT WM_COMMAND, not a posted one: a bare
// GetMessage pump never sees it, and the DefDlgProc of a hand-made #32770 just
// drops it. Every dialog here therefore owns a real window proc that reads its
// fields and closes itself synchronously; the pump only watches IsWindow().
struct PromptCtx {
    std::wstring* out = nullptr;
    HWND ed = nullptr;
    HFONT font = nullptr;
    bool accepted = false;
    bool hoverX = false;
    bool trackedLeave = false;
};

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
    for (;;) {
        if (!IsWindow(dlg)) break;
        if (!GetMessageW(&msg, nullptr, 0, 0)) break;   // WM_QUIT: the bar is going away
        if (IsDialogMessageW(dlg, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (IsWindow(dlg)) DestroyWindow(dlg);
    if (ctx.font) DeleteObject(ctx.font);
    Reposition(true);
    return ctx.accepted;
}

// Commit message: the ini value is only a default — it is asked every time.
bool AskCommitMessage(std::wstring* msg) {
    std::wstring def = IniGet(L"commitmsg");
    if (def.empty()) def = L"chore: 1c dump " + NowStamp();
    if (!PromptText(g_bar.hwnd, L"GitBar — комментарий к коммиту",
                    L"Комментарий (git commit -m):", def, msg)) {
        ShowTip(L"коммит отменён");
        return false;
    }
    if (msg->empty()) *msg = def;
    IniSet(L"commitmsg", msg->c_str());
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
    std::wstring def = IniGet(L"remote");
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
                                 IniGet(L"dumpdir"), &pick);
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

    IniSet(L"dumpdir", dir.c_str());
    IniSet(L"remote", remote.c_str());
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
    std::wstring dir = IniGet(L"dumpdir");
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
    std::wstring remote = IniGet(L"remote");
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
    std::wstring dir = IniGet(L"dumpdir");
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
    std::wstring dir = IniGet(L"dumpdir");
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
    if (!c->fields[0].empty()) ok = IniSet(L"gitpath", c->fields[0].c_str()) && ok;
    if (!c->fields[1].empty()) ok = IniSet(L"dumpdir", c->fields[1].c_str()) && ok;
    ok = IniSet(L"commitmsg", c->fields[2].c_str()) && ok;   // empty = auto "chore: 1c dump <stamp>"
    ok = IniSet(L"remote", c->fields[3].c_str()) && ok;
    LogGit(L"settings saved to", kIniPath());
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
    ctx.fields[1] = IniGet(L"dumpdir");
    ctx.fields[2] = IniGet(L"commitmsg");
    ctx.fields[3] = IniGet(L"remote");

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

// ---------------------------------------------------------------------------
// Git history viewer in the configurator: the lane graph, ref badges and diff
// pane borrowed from v8GitView, dressed in the classic 1C skin — cream chrome,
// white rows, rust captions, light-blue selection and a light diff pane.
// ---------------------------------------------------------------------------

namespace {

struct GraphEdge { int fromLane; int toLane; int color; };
struct RefBadge { std::wstring label; COLORREF color; };

struct LogRow {
    std::wstring oid;
    std::wstring hash;
    std::wstring author;
    std::wstring date;
    std::wstring subject;
    std::vector<RefBadge> badges;
    int lane = 0;
    int color = 0;
    bool incoming = false;
    std::vector<GraphEdge> edges;
};

// One line of "git show": file headers, hunks and changed lines are kept apart
// so the pane can draw gutters, colours and the sign column without re-parsing
// the patch on every paint.
struct DiffLine {
    enum Kind { Context, Add, Del, Hunk, FileHead, Meta, Stat, Note };
    Kind kind = Context;
    int oldNo = 0;
    int newNo = 0;
    std::wstring text;     // prefix character already stripped for +, -, ' '
    // Changed word ranges: paired -/+ lines emphasise only the fragments that
    // differ, the way GitExtensions colours the edited words.
    std::vector<std::pair<int, int>> hl;
};

struct LogCtx {
    HWND hwnd = nullptr;
    std::vector<LogRow> rows;
    int maxLanes = 1;
    int top = 0;           // first visible row index
    int sel = -1;          // selected row
    int visible = 1;
    std::wstring dir;
    std::vector<DiffLine> diff;
    int diffTop = 0;       // first visible diff line
    int diffLines = 0;     // total diff lines (for the scroll hint)
    HFONT mono = nullptr;
    HFONT ui = nullptr;
    HFONT uiSemi = nullptr;    // bold for subjects / file headers
    HFONT title = nullptr;
    HFONT badge = nullptr;
    RECT rcClose{};
    bool hoverClose = false;
    int hover = -1;            // row under the cursor
    int drag = 0;              // 0 none, 1 list scrollbar, 2 patch scrollbar
    int dragY = 0;
    int dragTop = 0;
    RECT rcListSb{};
    RECT rcPatchSb{};
};

const int kLogRowH = 28;      // commit row height
const int kDiffRowH = 16;     // patch rows stay compact
const int kLogListTop = 42;   // first commit row, below title + column headers
const int kLaneStep = 16;
const int kGraphPadL = 10;
const int kGraphPadR = 8;
const int kSbW = 10;          // thin overlay scrollbar width
// Light palette in the shared 1C skin (kDlg* above): cream chrome, white rows,
// rust column captions, light-blue selection and a white diff field.
const COLORREF kLogBg = kDlgBg;                     // FCFAEB window chrome
const COLORREF kLogPanel = RGB(245, 243, 229);      // F5F3E5 header band
const COLORREF kLogBase = kDlgFieldBg;              // white list rows
const COLORREF kLogAlt = RGB(248, 246, 236);        // subtle cream alternation
const COLORREF kLogSel = kDlgSel;                   // 9ED8EB light-blue selection
const COLORREF kLogBorder = kDlgBorder;             // B3AC86 frames
const COLORREF kLogText = kDlgText;                 // 333333
const COLORREF kLogGray = RGB(128, 121, 98);        // warm dim text
const COLORREF kLogAddBg = RGB(232, 244, 232);
const COLORREF kLogAddTx = RGB(45, 110, 58);
const COLORREF kLogAddHl = RGB(172, 222, 180);
const COLORREF kLogDelBg = RGB(250, 235, 236);
const COLORREF kLogDelTx = RGB(155, 48, 56);
const COLORREF kLogDelHl = RGB(238, 180, 184);
const COLORREF kLogHunkBg = RGB(240, 238, 226);
const COLORREF kLogHunkTx = kLogGray;
const COLORREF kLogHeadBg = kDlgBtnFace;            // D7D3BD "diff --git" band
const COLORREF kLogPatchBg = kDlgFieldBg;           // white code pane
const COLORREF kLogLineNo = RGB(158, 152, 126);
const COLORREF kLogGutter = RGB(244, 242, 230);

COLORREF Blend(COLORREF fg, COLORREF bg, int alpha) {
    int r = (GetRValue(fg) * alpha + GetRValue(bg) * (255 - alpha)) / 255;
    int g = (GetGValue(fg) * alpha + GetGValue(bg) * (255 - alpha)) / 255;
    int b = (GetBValue(fg) * alpha + GetBValue(bg) * (255 - alpha)) / 255;
    return RGB(r, g, b);
}

// Scale the HSV value down, keep the hue: badge labels and other accents that
// would glow on a dark face become darker inks on cream / white rows.
COLORREF Darker(COLORREF c, int pct) {
    int r = GetRValue(c) * pct / 100, g = GetGValue(c) * pct / 100,
        b = GetBValue(c) * pct / 100;
    return RGB(r, g, b);
}

// Lane palette tuned for the light face: saturated mid-tones stay readable on
// white rows, the cream chrome and the light-blue selection.
const COLORREF kLaneColors[] = {
    RGB(0x2E, 0x6F, 0xD2), RGB(0xD3, 0x74, 0x0F), RGB(0x39, 0x8B, 0x3B), RGB(0xC6, 0x39, 0x40),
    RGB(0x92, 0x4F, 0x8C), RGB(0x1F, 0x84, 0x8C), RGB(0xB0, 0x7D, 0x0B), RGB(0xC2, 0x53, 0x6F),
    RGB(0x7D, 0x54, 0x33), RGB(0x60, 0x60, 0x60), RGB(0x2B, 0x5F, 0x9E), RGB(0x1F, 0x87, 0x55),
    RGB(0x4E, 0x5A, 0x72), RGB(0x9C, 0x78, 0x00), RGB(0x59, 0x3E, 0x9B), RGB(0x0F, 0x7E, 0xA5),
};
const int kLaneCount = (int)(sizeof(kLaneColors) / sizeof(kLaneColors[0]));
COLORREF LaneColor(int lane) { return kLaneColors[((lane % kLaneCount) + kLaneCount) % kLaneCount]; }

COLORREF RefColor(const std::wstring& ref) {
    if (ref.rfind(L"refs/remotes/", 0) == 0) return RGB(0xCC, 0x78, 0x32);
    if (ref.rfind(L"refs/tags/", 0) == 0) return RGB(0x98, 0x76, 0xAA);
    if (ref.rfind(L"refs/heads/", 0) == 0) return RGB(0x3D, 0x7F, 0x3D);
    return RGB(0x4B, 0x6E, 0xAF);
}

// " (HEAD -> refs/heads/main, refs/tags/v1)" -> badges. HEAD symrefs only
// duplicate the real branch badge, so they are skipped (as in v8GitView).
void ParseBadges(const std::wstring& refs, std::vector<RefBadge>& out) {
    std::wstring s = TrimWs(refs);
    if (s.size() >= 2 && s.front() == L'(' && s.back() == L')')
        s = s.substr(1, s.size() - 2);
    size_t p = 0;
    while (p < s.size()) {
        size_t e = s.find(L", ", p);
        if (e == std::wstring::npos) e = s.size();
        std::wstring ref = TrimWs(s.substr(p, e - p));
        p = e + 2;
        if (ref.empty() || ref == L"HEAD") continue;
        // git prints the checked-out branch once, as "HEAD -> refs/heads/x",
        // and tags with a "tag: " prefix in full decorate mode.
        if (ref.rfind(L"HEAD -> ", 0) == 0) ref = ref.substr(8);
        if (ref.rfind(L"tag: ", 0) == 0) ref = ref.substr(5);
        if (ref.rfind(L"refs/remotes/", 0) == 0 && ref.size() >= 5 &&
            ref.compare(ref.size() - 5, 5, L"/HEAD") == 0) continue;
        std::wstring label = ref;
        if (ref.rfind(L"refs/heads/", 0) == 0) label = ref.substr(11);
        else if (ref.rfind(L"refs/remotes/", 0) == 0) label = ref.substr(13);
        else if (ref.rfind(L"refs/tags/", 0) == 0) label = ref.substr(10);
        out.push_back({ label, RefColor(ref) });
    }
}

// Lane layout over the parent list, ported from v8GitView GraphLayout: each
// lane waits for one commit; the first parent keeps the commit's column,
// extra parents open new lanes on the right.
struct GraphLayout {
    struct Wait { std::wstring oid; int color; };
    std::vector<Wait> lanes;
    int nextColor = 0;

    int Find(const std::wstring& oid) const {
        for (size_t i = 0; i < lanes.size(); ++i)
            if (lanes[i].oid == oid) return (int)i;
        return -1;
    }

    void Next(LogRow& r, const std::vector<std::wstring>& parents) {
        int commitLane = Find(r.oid);
        r.incoming = commitLane >= 0;
        if (commitLane < 0) {
            lanes.push_back({ r.oid, nextColor++ % kLaneCount });
            commitLane = (int)lanes.size() - 1;
        }
        std::vector<Wait> top = lanes;
        int commitColor = top[commitLane].color;
        r.lane = commitLane;
        r.color = commitColor;
        lanes.erase(lanes.begin() + commitLane);
        for (size_t i = 0; i < parents.size(); ++i) {
            int target = Find(parents[i]);
            if (target >= 0) {
                r.edges.push_back({ commitLane, target, lanes[target].color });
                continue;
            }
            int insertAt, color;
            if (i == 0) {
                insertAt = commitLane < (int)lanes.size() ? commitLane : (int)lanes.size();
                color = commitColor;
            } else {
                insertAt = (int)lanes.size();
                color = nextColor++ % kLaneCount;
            }
            lanes.insert(lanes.begin() + insertAt, { parents[i], color });
            r.edges.push_back({ commitLane, insertAt, color });
        }
        for (size_t k = 0; k < top.size(); ++k) {
            if ((int)k == commitLane) continue;
            int to = Find(top[k].oid);
            if (to >= 0) r.edges.push_back({ (int)k, to, top[k].color });
        }
    }
};

int LogListBottom(const RECT& rc) {
    int h = rc.bottom - kLogListTop;
    return kLogListTop + (h > 0 ? h * 48 / 100 : 0);
}

int LogDetailTop(const RECT& rc) { return LogListBottom(rc) + 24; }
int LogPatchTop(const RECT& rc) { return LogDetailTop(rc) + 52; }

bool LoadLog(const std::wstring& dir, std::vector<LogRow>& rows, int* maxLanes) {
    // 0x1F (unit separator) between fields: subjects may contain anything.
    // Full decorate gives refs/heads|remotes|tags prefixes for badge colours;
    // %H/%P feed the parent-based lane layout instead of git's ASCII graph.
    std::wstring out = RunGit({ L"-C", dir, L"log", L"--decorate=full",
                                L"-n", L"300", L"--date=short",
                                L"--pretty=format:%x1f%H%x1f%h%x1f%an <%ae>%x1f%ad%x1f%d%x1f%s%x1f%P" });
    if (out.empty()) return false;
    GraphLayout layout;
    *maxLanes = 1;
    size_t p = 0;
    while (p < out.size()) {
        size_t e = out.find_first_of(L"\r\n", p);
        if (e == std::wstring::npos) e = out.size();
        std::wstring line = out.substr(p, e - p);
        p = e;
        while (p < out.size() && (out[p] == L'\r' || out[p] == L'\n')) ++p;
        if (line.empty() || line[0] != L'\x1f') continue;
        std::vector<std::wstring> f;
        size_t q = 1;
        while (true) {
            size_t d = line.find(L'\x1f', q);
            if (d == std::wstring::npos) { f.push_back(line.substr(q)); break; }
            f.push_back(line.substr(q, d - q));
            q = d + 1;
        }
        if (f.size() < 7) continue;
        LogRow r;
        r.oid = TrimWs(f[0]);
        r.hash = TrimWs(f[1]);
        r.author = f[2];
        r.date = f[3];
        r.subject = f[5];
        ParseBadges(f[4], r.badges);
        std::vector<std::wstring> parents;
        size_t a = 0;
        while (a < f[6].size()) {
            size_t b = f[6].find(L' ', a);
            if (b == std::wstring::npos) b = f[6].size();
            if (b > a) parents.push_back(f[6].substr(a, b - a));
            a = b + 1;
        }
        layout.Next(r, parents);
        *maxLanes = std::max(*maxLanes, r.lane + 1);
        for (const GraphEdge& ed : r.edges)
            *maxLanes = std::max(*maxLanes, std::max(ed.fromLane, ed.toLane) + 1);
        rows.push_back(std::move(r));
    }
    return !rows.empty();
}

HFONT LogFont(int points, const wchar_t* face, int weight, DWORD pitch) {
    HDC dc = GetDC(nullptr);
    int h = -MulDiv(points, GetDeviceCaps(dc, LOGPIXELSY), 72);
    ReleaseDC(nullptr, dc);
    // Tahoma 8 pt matches the platform dialog font; Consolas 9 pt keeps
    // hashes and code readable.
    return CreateFontW(h, 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       pitch, face);
}

// "@@ -a,b +c,d @@" -- the counts are optional, so four format variants cover
// every hunk git prints.
void ParseHunkHeader(const std::wstring& line, int* oldNo, int* newNo) {
    int a = 0, b = 0, c = 0, d = 0;
    *oldNo = 0;
    *newNo = 0;
    if (swscanf_s(line.c_str(), L"@@ -%d,%d +%d,%d @@", &a, &b, &c, &d) == 4 ||
        swscanf_s(line.c_str(), L"@@ -%d,%d +%d @@", &a, &b, &c) == 3 ||
        swscanf_s(line.c_str(), L"@@ -%d +%d,%d @@", &a, &c, &d) == 3 ||
        swscanf_s(line.c_str(), L"@@ -%d +%d @@", &a, &c) == 2) {
        *oldNo = a - 1;   // the first line of the hunk increments these
        *newNo = c - 1;
    }
}

// Word-level diff of one deleted/added line pair. Tokens are runs of letters,
// digits and non-ASCII (Cyrillic paths and messages stay whole), single other
// characters and whitespace runs. The LCS keeps identical fragments plain and
// marks the rest, so a one-character edit lights up one character and not the
// whole line.
struct WordTok {
    int start;
    int end;
};

bool IsWordChar(wchar_t c) {
    return (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'Z') ||
           (c >= L'a' && c <= L'z') || c == L'_' || c >= 0x80;
}

void TokenizeWords(const std::wstring& s, std::vector<WordTok>& t) {
    t.clear();
    for (size_t i = 0; i < s.size();) {
        size_t j = i;
        if (IsWordChar(s[i])) {
            while (j < s.size() && IsWordChar(s[j])) ++j;
        } else if (s[i] == L' ' || s[i] == L'\t') {
            while (j < s.size() && (s[j] == L' ' || s[j] == L'\t')) ++j;
        } else {
            ++j;
        }
        t.push_back({ (int)i, (int)j });
        i = j;
    }
}

bool SameTok(const std::wstring& a, const WordTok& x, const std::wstring& b, const WordTok& y) {
    int la = x.end - x.start, lb = y.end - y.start;
    return la == lb && a.compare((size_t)x.start, (size_t)la, b, (size_t)y.start,
                                 (size_t)lb) == 0;
}

void MarkUnmatched(const std::vector<WordTok>& t, const std::vector<char>& matched,
                   std::vector<std::pair<int, int>>& out) {
    int start = -1;
    for (size_t i = 0; i < t.size(); ++i) {
        if (!matched[i]) {
            if (start < 0) start = t[i].start;
        } else if (start >= 0) {
            out.push_back({ start, t[i - 1].end });
            start = -1;
        }
    }
    if (start >= 0) out.push_back({ start, t.back().end });
}

void PairHighlight(DiffLine& del, DiffLine& add) {
    std::vector<WordTok> a, b;
    TokenizeWords(del.text, a);
    TokenizeWords(add.text, b);
    if (a.empty() || b.empty()) return;
    size_t n = a.size(), m = b.size();
    if (n * m > 400000) return;   // pathological line: keep the plain line tint
    std::vector<int> dp((n + 1) * (m + 1), 0);
    for (size_t i = 1; i <= n; ++i)
        for (size_t j = 1; j <= m; ++j)
            dp[i * (m + 1) + j] = SameTok(del.text, a[i - 1], add.text, b[j - 1])
                ? dp[(i - 1) * (m + 1) + (j - 1)] + 1
                : std::max(dp[(i - 1) * (m + 1) + j], dp[i * (m + 1) + (j - 1)]);
    std::vector<char> ma(n, 0), mb(m, 0);
    size_t i = n, j = m;
    while (i > 0 && j > 0) {
        if (SameTok(del.text, a[i - 1], add.text, b[j - 1]) &&
            dp[i * (m + 1) + j] == dp[(i - 1) * (m + 1) + (j - 1)] + 1) {
            ma[i - 1] = mb[j - 1] = 1;
            --i;
            --j;
        } else if (dp[(i - 1) * (m + 1) + j] >= dp[i * (m + 1) + (j - 1)]) {
            --i;
        } else {
            --j;
        }
    }
    MarkUnmatched(a, ma, del.hl);
    MarkUnmatched(b, mb, add.hl);
}

void ParseDiff(const std::wstring& patch, std::vector<DiffLine>& out) {
    int oldNo = 0, newNo = 0;
    bool inHunk = false;
    size_t pos = 0;
    while (pos < patch.size()) {
        size_t e = patch.find_first_of(L"\r\n", pos);
        if (e == std::wstring::npos) e = patch.size();
        std::wstring line = patch.substr(pos, e - pos);
        pos = e;
        while (pos < patch.size() && (patch[pos] == L'\r' || patch[pos] == L'\n')) ++pos;

        DiffLine dl;
        if (line.rfind(L"diff --git ", 0) == 0) {
            inHunk = false;
            std::wstring path = line.substr(11);
            size_t b = path.rfind(L" b/");
            if (b != std::wstring::npos) path = path.substr(b + 3);
            dl.kind = DiffLine::FileHead;
            dl.text = path;
            out.push_back(dl);
            continue;
        }
        if (line.rfind(L"@@", 0) == 0) {
            inHunk = true;
            ParseHunkHeader(line, &oldNo, &newNo);
            dl.kind = DiffLine::Hunk;
            dl.text = line;
            out.push_back(dl);
            continue;
        }
        if (inHunk) {
            if (line.empty()) { inHunk = false; continue; }
            wchar_t ch = line[0];
            if (ch == L'+') {
                dl.kind = DiffLine::Add;
                dl.newNo = ++newNo;
                dl.text = line.substr(1);
            } else if (ch == L'-') {
                dl.kind = DiffLine::Del;
                dl.oldNo = ++oldNo;
                dl.text = line.substr(1);
            } else if (ch == L' ') {
                dl.kind = DiffLine::Context;
                dl.oldNo = ++oldNo;
                dl.newNo = ++newNo;
                dl.text = line.substr(1);
            } else if (ch == L'\\') {
                dl.kind = DiffLine::Note;
                dl.text = line;
            } else {
                dl.kind = DiffLine::Context;
                dl.text = line;
            }
            out.push_back(dl);
            continue;
        }

        // Outside a hunk: index/---/+++/mode lines belong to the file header,
        // the --stat block and its "N files changed" summary are stat lines.
        if (line.empty()) continue;
        if (line.rfind(L"index ", 0) == 0 || line.rfind(L"--- ", 0) == 0 ||
            line.rfind(L"+++ ", 0) == 0 || line.rfind(L"new file mode", 0) == 0 ||
            line.rfind(L"deleted file mode", 0) == 0 ||
            line.rfind(L"old mode", 0) == 0 || line.rfind(L"new mode", 0) == 0 ||
            line.rfind(L"similarity index", 0) == 0 ||
            line.rfind(L"rename from", 0) == 0 || line.rfind(L"rename to", 0) == 0 ||
            line.rfind(L"Binary files", 0) == 0) {
            dl.kind = DiffLine::Meta;
        } else {
            dl.kind = DiffLine::Stat;
        }
        dl.text = line;
        out.push_back(dl);
    }

    // git prints each hunk's removals before its additions; pair them line by
    // line so PairHighlight can mark the changed words.
    for (size_t i = 0; i < out.size();) {
        if (out[i].kind != DiffLine::Del) { ++i; continue; }
        size_t d0 = i;
        while (i < out.size() && out[i].kind == DiffLine::Del) ++i;
        size_t a0 = i;
        while (i < out.size() && out[i].kind == DiffLine::Add) ++i;
        size_t pairs = std::min(i - a0, a0 - d0);
        for (size_t k = 0; k < pairs; ++k) PairHighlight(out[d0 + k], out[a0 + k]);
    }
}

// Commit node: a filled dot with a soft halo on the row face.
static void DrawNode(HDC dc, int cx, int cy, COLORREF color, COLORREF bg) {
    HPEN np = (HPEN)SelectObject(dc, GetStockObject(NULL_PEN));
    HBRUSH hb = CreateSolidBrush(Blend(color, bg, 70));
    HBRUSH ob = (HBRUSH)SelectObject(dc, hb);
    Ellipse(dc, cx - 7, cy - 7, cx + 8, cy + 8);
    SelectObject(dc, ob);
    DeleteObject(hb);
    HBRUSH db = CreateSolidBrush(color);
    ob = (HBRUSH)SelectObject(dc, db);
    Ellipse(dc, cx - 4, cy - 4, cx + 5, cy + 5);
    SelectObject(dc, ob);
    SelectObject(dc, np);
    DeleteObject(db);
}

// Rounded branch/tag pills: tinted fill, stronger border, darker bold label.
// Advances x past the drawn badges; overflow collapses into a "+N" pill.
static void DrawBadges(HDC dc, HFONT font, const std::vector<RefBadge>& badges,
                       int& x, int y, int rowH, int rightLimit, COLORREF bg) {
    if (badges.empty() || x >= rightLimit) return;
    HFONT of = (HFONT)SelectObject(dc, font);
    int top = y + (rowH - 18) / 2;
    size_t drawn = 0;
    for (size_t i = 0; i < badges.size(); ++i) {
        const RefBadge& b = badges[i];
        SIZE sz{};
        GetTextExtentPoint32W(dc, b.label.c_str(), (int)b.label.size(), &sz);
        int w = sz.cx + 12;
        int reserve = (i + 1 == badges.size()) ? 0 : 34;
        if (x + w + reserve > rightLimit) break;
        HBRUSH fb = CreateSolidBrush(Blend(b.color, bg, 45));
        HPEN bp = CreatePen(PS_SOLID, 1, Blend(b.color, bg, 150));
        HBRUSH ob = (HBRUSH)SelectObject(dc, fb);
        HPEN op = (HPEN)SelectObject(dc, bp);
        RoundRect(dc, x, top, x + w + 1, top + 19, 8, 8);
        SelectObject(dc, ob);
        SelectObject(dc, op);
        DeleteObject(fb);
        DeleteObject(bp);
        SetTextColor(dc, Darker(b.color, 76));
        RECT br{ x, top, x + w, top + 18 };
        DrawTextW(dc, b.label.c_str(), (int)b.label.size(), &br,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        x += w + 4;
        ++drawn;
    }
    if (drawn < badges.size()) {
        wchar_t lab[16] = {};
        _snwprintf_s(lab, _TRUNCATE, L"+%d", (int)(badges.size() - drawn));
        SIZE sz{};
        GetTextExtentPoint32W(dc, lab, (int)wcslen(lab), &sz);
        int w = sz.cx + 12;
        if (x + w <= rightLimit) {
            HBRUSH fb = CreateSolidBrush(kDlgBtnFace);
            HPEN bp = CreatePen(PS_SOLID, 1, kLogBorder);
            HBRUSH ob = (HBRUSH)SelectObject(dc, fb);
            HPEN op = (HPEN)SelectObject(dc, bp);
            RoundRect(dc, x, top, x + w + 1, top + 19, 8, 8);
            SelectObject(dc, ob);
            SelectObject(dc, op);
            DeleteObject(fb);
            DeleteObject(bp);
            SetTextColor(dc, kLogGray);
            RECT br{ x, top, x + w, top + 18 };
            DrawTextW(dc, lab, -1, &br,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            x += w + 4;
        }
    }
    SelectObject(dc, of);
}

static int PatchRowsFit(const RECT& rc) {
    int r = (rc.bottom - 6 - LogPatchTop(rc)) / kDiffRowH;
    return r < 1 ? 1 : r;
}

// Thin overlay scrollbar: track height, thumb height (0 = everything fits) and
// thumb top. Shared by paint and the drag / click handlers so they agree.
static void SbGeom(int trackTop, int trackBottom, int total, int fit, int top,
                   int* thumbH, int* thumbY) {
    int trackH = trackBottom - trackTop;
    *thumbH = 0;
    *thumbY = trackTop;
    if (total <= fit || trackH <= 0) return;
    int th = trackH * fit / total;
    if (th < 24) th = 24;
    if (th > trackH) th = trackH;
    int maxTop = total - fit;
    int range = trackH - th;
    *thumbH = th;
    *thumbY = trackTop + (maxTop > 0 && range > 0 ? range * top / maxTop : 0);
}

static void DrawScrollbar(HDC dc, const RECT& track, int thumbH, int thumbY, bool active) {
    if (thumbH <= 0) return;
    HBRUSH tb = CreateSolidBrush(kLogBg);
    FillRect(dc, &track, tb);
    DeleteObject(tb);
    RECT th{ track.left + 1, thumbY, track.right - 1, thumbY + thumbH };
    HBRUSH hb = CreateSolidBrush(active ? kDlgFieldBorder : kLogBorder);
    FillRect(dc, &th, hb);
    DeleteObject(hb);
}

void LogPaint(LogCtx* c) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(c->hwnd, &ps);
    RECT rc{};
    GetClientRect(c->hwnd, &rc);
    HBRUSH bg = CreateSolidBrush(kLogBg);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);
    DrawCaption(dc, c->hwnd, c->title, c->hoverClose);
    // The body keeps its own coordinate space below the painted caption.
    SetWindowOrgEx(dc, 0, -kCapH, nullptr);
    rc.bottom -= kCapH;
    SetBkMode(dc, TRANSPARENT);

    const int contentRight = rc.right - kSbW - 4;
    const int kDateW = 110;
    const int kAuthorW = 176;
    int graphW = kGraphPadL + c->maxLanes * kLaneStep + kGraphPadR;
    if (graphW > 240) graphW = 240;
    const int listLeft = 4;
    const int subjLeft = listLeft + graphW;
    const int dateLeft = contentRight - kDateW;
    const int authorLeft = dateLeft - kAuthorW;
    const int subjRight = authorLeft;
    auto LaneX = [&](int lane) { return listLeft + kGraphPadL + lane * kLaneStep; };
    auto RowBg = [&](int idx) -> COLORREF {
        if (idx == c->sel) return kLogSel;
        COLORREF base = (idx & 1) ? kLogAlt : kLogBase;
        return idx == c->hover ? Blend(kDlgHover, base, 140) : base;
    };

    // Header band: repo path on the cream face under the caption.
    RECT hdr{ 0, 0, rc.right, 24 };
    HBRUSH hbr = CreateSolidBrush(kLogPanel);
    FillRect(dc, &hdr, hbr);
    DeleteObject(hbr);
    SelectObject(dc, c->title);
    SetTextColor(dc, kLogText);
    RECT dr{ 12, 0, rc.right - 12, 24 };
    DrawTextW(dc, c->dir.c_str(), -1, &dr,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

    HPEN border = CreatePen(PS_SOLID, 1, kLogBorder);
    HPEN obp = (HPEN)SelectObject(dc, border);
    MoveToEx(dc, 0, 24, nullptr);
    LineTo(dc, rc.right, 24);
    MoveToEx(dc, 0, kLogListTop - 1, nullptr);
    LineTo(dc, rc.right, kLogListTop - 1);
    SelectObject(dc, obp);
    DeleteObject(border);

    // Column headers: commit | author | date, rust labels like the field
    // captions on a live platform dialog.
    RECT hband{ 0, 24, rc.right, kLogListTop - 1 };
    HBRUSH hbb = CreateSolidBrush(kLogPanel);
    FillRect(dc, &hband, hbb);
    DeleteObject(hbb);
    SelectObject(dc, c->ui);
    SetTextColor(dc, kDlgLabel);
    RECT hG{ 8, 24, subjLeft, kLogListTop - 1 };
    DrawTextW(dc, L"Коммит", -1, &hG, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    RECT hA{ authorLeft + 4, 24, dateLeft, kLogListTop - 1 };
    DrawTextW(dc, L"Автор", -1, &hA, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    RECT hD{ dateLeft, 24, contentRight, kLogListTop - 1 };
    DrawTextW(dc, L"Дата", -1, &hD, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

    int listTop = kLogListTop;
    int listBottom = LogListBottom(rc);
    c->visible = (listBottom - listTop) / kLogRowH;
    if (c->visible < 1) c->visible = 1;

    // The commit list: white rows with a subtle cream alternation, light-blue
    // selection, pale-yellow hover.
    RECT listArea{ listLeft, listTop, contentRight, listBottom };
    HBRUSH lbr = CreateSolidBrush(kLogBase);
    FillRect(dc, &listArea, lbr);
    DeleteObject(lbr);

    // One round-cap pen per lane colour; lane changes are cubic elbows.
    HPEN lanePens[kLaneCount];
    for (int k = 0; k < kLaneCount; ++k) {
        LOGBRUSH lb{ BS_SOLID, kLaneColors[k], 0 };
        lanePens[k] = ExtCreatePen(PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_ROUND | PS_JOIN_ROUND,
                                   2, &lb, 0, nullptr);
    }

    // Pass 1: row backgrounds so graph and text sit on top.
    for (int i = 0; i < c->visible; ++i) {
        int idx = c->top + i;
        if (idx >= (int)c->rows.size()) break;
        int yTop = listTop + i * kLogRowH;
        RECT row{ listLeft, yTop, contentRight, yTop + kLogRowH };
        HBRUSH rb = CreateSolidBrush(RowBg(idx));
        FillRect(dc, &row, rb);
        DeleteObject(rb);
    }

    // Pass 2: the graph. Incoming lane from the row above, passing lanes as
    // cubic curves across the row, own edges leaving the dot downwards.
    IntersectClipRect(dc, listLeft, listTop, subjLeft - 2, listBottom);
    for (int i = 0; i < c->visible; ++i) {
        int idx = c->top + i;
        if (idx >= (int)c->rows.size()) break;
        int yTop = listTop + i * kLogRowH;
        int yBot = yTop + kLogRowH;
        int mid = (yTop + yBot) / 2;
        const LogRow& r = c->rows[idx];
        if (r.incoming) {
            HPEN op = (HPEN)SelectObject(dc, lanePens[r.color % kLaneCount]);
            MoveToEx(dc, LaneX(r.lane), yTop, nullptr);
            LineTo(dc, LaneX(r.lane), mid);
            SelectObject(dc, op);
        }
        for (const GraphEdge& e : r.edges) {
            if (e.fromLane == r.lane) continue;
            int x0 = LaneX(e.fromLane), x1 = LaneX(e.toLane);
            HPEN op = (HPEN)SelectObject(dc, lanePens[e.color % kLaneCount]);
            POINT pts[4] = { { x0, yTop }, { x0, mid }, { x1, mid }, { x1, yBot } };
            PolyBezier(dc, pts, 4);
            SelectObject(dc, op);
        }
        for (const GraphEdge& e : r.edges) {
            if (e.fromLane != r.lane) continue;
            int x0 = LaneX(r.lane), x1 = LaneX(e.toLane);
            int ym = (mid + yBot) / 2;
            HPEN op = (HPEN)SelectObject(dc, lanePens[e.color % kLaneCount]);
            POINT pts[4] = { { x0, mid }, { x0, ym }, { x1, ym }, { x1, yBot } };
            PolyBezier(dc, pts, 4);
            SelectObject(dc, op);
        }
        DrawNode(dc, LaneX(r.lane), mid, LaneColor(r.color), RowBg(idx));
    }
    SelectClipRgn(dc, nullptr);

    // Pass 3: dim mono hash, badges, subject, author and date.
    for (int i = 0; i < c->visible; ++i) {
        int idx = c->top + i;
        if (idx >= (int)c->rows.size()) break;
        int yTop = listTop + i * kLogRowH;
        int yBot = yTop + kLogRowH;
        const LogRow& r = c->rows[idx];
        COLORREF rbg = RowBg(idx);
        bool sel = idx == c->sel;
        int x = subjLeft;

        SelectObject(dc, c->mono);
        SetTextColor(dc, Blend(kLogText, rbg, sel ? 190 : 135));
        SIZE hs{};
        GetTextExtentPoint32W(dc, r.hash.c_str(), (int)r.hash.size(), &hs);
        int hashW = hs.cx + 12;
        RECT hr{ x, yTop, x + hashW, yBot };
        DrawTextW(dc, r.hash.c_str(), (int)r.hash.size(), &hr,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        x += hashW;

        int subjMin = subjRight - x;
        if (subjMin > 180) subjMin = 180;
        if (subjMin < 60) subjMin = 60;
        DrawBadges(dc, c->badge, r.badges, x, yTop, kLogRowH, subjRight - subjMin, rbg);

        SelectObject(dc, c->ui);
        SetTextColor(dc, kDlgText);
        RECT sr{ x, yTop, subjRight, yBot };
        DrawTextW(dc, r.subject.c_str(), (int)r.subject.size(), &sr,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

        std::wstring aname = r.author;
        size_t lt = aname.find(L" <");
        if (lt != std::wstring::npos) aname = aname.substr(0, lt);
        RECT ar{ authorLeft + 4, yTop, dateLeft - 4, yBot };
        DrawTextW(dc, aname.c_str(), (int)aname.size(), &ar,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        RECT dtr{ dateLeft, yTop, contentRight, yBot };
        DrawTextW(dc, r.date.c_str(), (int)r.date.size(), &dtr,
                  DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    }
    for (int k = 0; k < kLaneCount; ++k)
        if (lanePens[k]) DeleteObject(lanePens[k]);

    // Separator + status line between the list and the details card.
    SelectObject(dc, c->ui);
    HPEN sep = CreatePen(PS_SOLID, 1, kLogBorder);
    HPEN osep = (HPEN)SelectObject(dc, sep);
    MoveToEx(dc, 4, listBottom + 1, nullptr);
    LineTo(dc, rc.right - 4, listBottom + 1);
    SelectObject(dc, osep);
    DeleteObject(sep);

    SetTextColor(dc, kLogGray);
    wchar_t st[160] = {};
    int shown = c->visible;
    if (shown > (int)c->rows.size() - c->top) shown = (int)c->rows.size() - c->top;
    _snwprintf_s(st, _TRUNCATE, L"%d коммитов · %d линий · %d–%d",
                 (int)c->rows.size(), c->maxLanes, c->top + 1, c->top + shown);
    RECT sr{ 8, listBottom + 3, rc.right - 360, listBottom + 22 };
    DrawTextW(dc, st, -1, &sr, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
    {
        wchar_t hint[128] = {};
        if (c->diffLines > 0)
            _snwprintf_s(hint, _TRUNCATE, L"изменений: %d  ·  ↑↓ / колесо · Enter — закрыть",
                         c->diffLines);
        else
            _snwprintf_s(hint, _TRUNCATE, L"↑↓ / колесо — прокрутка · Enter — закрыть");
        RECT hr{ rc.right - 350, listBottom + 3, rc.right - 8, listBottom + 22 };
        DrawTextW(dc, hint, -1, &hr, DT_RIGHT | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
    }

    // Details panel: white field card with subject, badges, author, date, hash.
    int detTop = LogDetailTop(rc);
    {
        RECT card{ 8, detTop, rc.right - 8, detTop + 44 };
        HBRUSH cb = CreateSolidBrush(kLogBase);
        FillRect(dc, &card, cb);
        DeleteObject(cb);
        HPEN cp = CreatePen(PS_SOLID, 1, kDlgFieldBorder);
        HPEN ocp = (HPEN)SelectObject(dc, cp);
        HBRUSH ob2 = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
        Rectangle(dc, card.left, card.top, card.right, card.bottom);
        SelectObject(dc, ob2);
        SelectObject(dc, ocp);
        DeleteObject(cp);
        if (c->sel >= 0 && c->sel < (int)c->rows.size()) {
            const LogRow& r = c->rows[c->sel];
            SelectObject(dc, c->badge);
            int bw = 0;
            for (const RefBadge& b : r.badges) {
                SIZE sz{};
                GetTextExtentPoint32W(dc, b.label.c_str(), (int)b.label.size(), &sz);
                bw += sz.cx + 16;
            }
            int bx = card.right - 12 - bw;
            int subjAvail = bx - 10 - (card.left + 12);
            if (subjAvail < 40) subjAvail = 40;
            SelectObject(dc, c->uiSemi);
            SetTextColor(dc, kLogText);
            RECT sjr{ card.left + 12, card.top + 4, card.left + 12 + subjAvail, card.top + 20 };
            DrawTextW(dc, r.subject.c_str(), (int)r.subject.size(), &sjr,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
            DrawBadges(dc, c->badge, r.badges, bx, card.top + 4, 20, card.right - 12, kLogBase);
            std::wstring aname = r.author;
            size_t lt = aname.find(L" <");
            if (lt != std::wstring::npos) aname = aname.substr(0, lt);
            SelectObject(dc, c->ui);
            SetTextColor(dc, kLogText);
            RECT ar{ card.left + 12, card.top + 24, card.left + 232, card.top + 40 };
            DrawTextW(dc, aname.c_str(), (int)aname.size(), &ar,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
            SIZE nw{};
            GetTextExtentPoint32W(dc, aname.c_str(), (int)aname.size(), &nw);
            int dx = card.left + 12 + (nw.cx < 220 ? nw.cx : 220) + 10;
            SetTextColor(dc, kLogGray);
            RECT dtr{ dx, card.top + 24, dx + 120, card.top + 40 };
            DrawTextW(dc, r.date.c_str(), (int)r.date.size(), &dtr,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(dc, c->mono);
            SetTextColor(dc, Blend(kLogText, kLogBase, 135));
            RECT hr{ card.right - 100, card.top + 24, card.right - 12, card.top + 40 };
            DrawTextW(dc, r.hash.c_str(), (int)r.hash.size(), &hr,
                      DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(dc, c->ui);
        }
    }

    // Patch pane: white code field, light two-column gutter, coloured sign,
    // green/red row tints and word-level chips; hunk / file headers get bands.
    int patchTop = LogPatchTop(rc);
    int patchBottom = rc.bottom - 6;
    if (patchBottom > patchTop && !c->diff.empty()) {
        int rowsFit = PatchRowsFit(rc);
        int maxTop = c->diffLines - rowsFit;
        if (maxTop < 0) maxTop = 0;
        if (c->diffTop > maxTop) c->diffTop = maxTop;
        if (c->diffTop < 0) c->diffTop = 0;

        const int kNoW = 40;
        const int kSignW = 14;
        int paneLeft = 6;
        int paneRight = rc.right - kSbW - 4;
        int gutterRight = paneLeft + kNoW * 2;
        int codeLeft = gutterRight + kSignW + 6;

        RECT pane{ paneLeft, patchTop, paneRight, patchBottom };
        HBRUSH pb = CreateSolidBrush(kLogPatchBg);
        FillRect(dc, &pane, pb);
        DeleteObject(pb);
        RECT gut{ paneLeft, patchTop, gutterRight, patchBottom };
        HBRUSH gb = CreateSolidBrush(kLogGutter);
        FillRect(dc, &gut, gb);
        DeleteObject(gb);

        for (int i = c->diffTop; i < c->diffTop + rowsFit && i < (int)c->diff.size(); ++i) {
            const DiffLine& d = c->diff[i];
            int y = patchTop + (i - c->diffTop) * kDiffRowH;
            RECT lr{ paneLeft, y, paneRight, y + kDiffRowH };
            bool codeRow = (d.kind == DiffLine::Add || d.kind == DiffLine::Del ||
                            d.kind == DiffLine::Context);
            COLORREF fg = kLogText;
            COLORREF bgc = kLogPatchBg;
            COLORREF sign = kLogGray;
            switch (d.kind) {
            case DiffLine::Add:      bgc = kLogAddBg;  sign = kLogAddTx; break;
            case DiffLine::Del:      bgc = kLogDelBg;  sign = kLogDelTx; break;
            case DiffLine::Hunk:     bgc = kLogHunkBg; fg = kLogHunkTx;  break;
            case DiffLine::FileHead: bgc = kLogHeadBg; break;
            case DiffLine::Meta:
                fg = kLogGray;
                if (d.text.rfind(L"--- ", 0) == 0) fg = kLogDelTx;
                else if (d.text.rfind(L"+++ ", 0) == 0) fg = kLogAddTx;
                break;
            case DiffLine::Stat:
            case DiffLine::Note:     fg = kLogGray; break;
            default: break;
            }
            if (bgc != kLogPatchBg) {
                HBRUSH b = CreateSolidBrush(bgc);
                FillRect(dc, &lr, b);
                DeleteObject(b);
            }
            if (d.kind == DiffLine::FileHead) {
                HPEN fp = CreatePen(PS_SOLID, 1, kLogBorder);
                HPEN ofp = (HPEN)SelectObject(dc, fp);
                MoveToEx(dc, paneLeft, y, nullptr);
                LineTo(dc, paneRight, y);
                SelectObject(dc, ofp);
                DeleteObject(fp);
            }

            if (codeRow) {
                SelectObject(dc, c->mono);
                SetTextColor(dc, kLogLineNo);
                wchar_t nb[16] = {};
                if (d.oldNo) {
                    _snwprintf_s(nb, _TRUNCATE, L"%d", d.oldNo);
                    RECT nr{ paneLeft, y, paneLeft + kNoW - 6, y + kDiffRowH };
                    DrawTextW(dc, nb, -1, &nr, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                }
                if (d.newNo) {
                    _snwprintf_s(nb, _TRUNCATE, L"%d", d.newNo);
                    RECT nr{ paneLeft + kNoW, y, gutterRight - 6, y + kDiffRowH };
                    DrawTextW(dc, nb, -1, &nr, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                }
                if (d.kind == DiffLine::Add || d.kind == DiffLine::Del) {
                    SetTextColor(dc, sign);
                    RECT signr{ gutterRight, y, gutterRight + kSignW, y + kDiffRowH };
                    DrawTextW(dc, d.kind == DiffLine::Add ? L"+" : L"-", 1, &signr,
                              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                }
                if (!d.hl.empty() && (d.kind == DiffLine::Add || d.kind == DiffLine::Del)) {
                    HBRUSH hb = CreateSolidBrush(d.kind == DiffLine::Add ? kLogAddHl : kLogDelHl);
                    HPEN np = (HPEN)SelectObject(dc, GetStockObject(NULL_PEN));
                    HBRUSH ob = (HBRUSH)SelectObject(dc, hb);
                    int limit = paneRight - 6;
                    for (const std::pair<int, int>& h : d.hl) {
                        SIZE sz{};
                        int x1 = codeLeft;
                        if (h.first > 0) {
                            GetTextExtentPoint32W(dc, d.text.c_str(), h.first, &sz);
                            x1 += sz.cx;
                        }
                        int x2 = codeLeft;
                        GetTextExtentPoint32W(dc, d.text.c_str(), h.second, &sz);
                        x2 += sz.cx;
                        if (x1 >= limit) break;
                        if (x2 > limit) x2 = limit;
                        Rectangle(dc, x1, y + 2, x2, y + kDiffRowH - 2);
                    }
                    SelectObject(dc, ob);
                    SelectObject(dc, np);
                    DeleteObject(hb);
                }
            }

            SetTextColor(dc, fg);
            if (d.kind == DiffLine::FileHead) SelectObject(dc, c->uiSemi);
            else SelectObject(dc, c->mono);
            int textLeft = codeRow ? codeLeft : paneLeft + 8;
            RECT tr{ textLeft, y, paneRight - 6, y + kDiffRowH };
            DrawTextW(dc, d.text.c_str(), (int)d.text.size(), &tr,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
        }
        HPEN gp = CreatePen(PS_SOLID, 1, kLogBorder);
        HPEN ogp = (HPEN)SelectObject(dc, gp);
        MoveToEx(dc, gutterRight, patchTop, nullptr);
        LineTo(dc, gutterRight, patchBottom);
        MoveToEx(dc, paneLeft, patchTop - 1, nullptr);
        LineTo(dc, paneRight, patchTop - 1);
        SelectObject(dc, ogp);
        DeleteObject(gp);
    }

    // Thin overlay scrollbars for the list and the patch.
    {
        int sbL = rc.right - kSbW - 2;
        RECT ltrack{ sbL, listTop, rc.right - 2, listBottom };
        c->rcListSb = ltrack;
        int th = 0, ty = 0;
        SbGeom(listTop, listBottom, (int)c->rows.size(), c->visible, c->top, &th, &ty);
        DrawScrollbar(dc, ltrack, th, ty, c->drag == 1);
        if (!c->diff.empty()) {
            RECT ptrack{ sbL, patchTop, rc.right - 2, patchBottom };
            c->rcPatchSb = ptrack;
            int pth = 0, pty = 0;
            SbGeom(patchTop, patchBottom, c->diffLines, PatchRowsFit(rc), c->diffTop, &pth, &pty);
            DrawScrollbar(dc, ptrack, pth, pty, c->drag == 2);
        } else {
            SetRectEmpty(&c->rcPatchSb);
        }
    }

    SetWindowOrgEx(dc, 0, 0, nullptr);
    HPEN frame = CreatePen(PS_SOLID, 1, kLogBorder);
    HPEN ofr = (HPEN)SelectObject(dc, frame);
    HBRUSH obb = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
    RECT full{};
    GetClientRect(c->hwnd, &full);
    Rectangle(dc, 0, 0, full.right - 1, full.bottom - 1);
    SelectObject(dc, obb);
    SelectObject(dc, ofr);
    DeleteObject(frame);
    EndPaint(c->hwnd, &ps);
}

void LogScrollTo(LogCtx* c, int top) {
    int maxTop = (int)c->rows.size() - c->visible;
    if (maxTop < 0) maxTop = 0;
    if (top < 0) top = 0;
    if (top > maxTop) top = maxTop;
    if (top != c->top) { c->top = top; InvalidateRect(c->hwnd, nullptr, FALSE); }
}

void LogSelect(LogCtx* c, int idx) {
    if (idx < 0) idx = 0;
    if (idx > (int)c->rows.size() - 1) idx = (int)c->rows.size() - 1;
    c->sel = idx;
    if (c->sel < c->top) LogScrollTo(c, c->sel);
    if (c->sel >= c->top + c->visible) LogScrollTo(c, c->sel - c->visible + 1);
    const LogRow& r = c->rows[c->sel];
    c->diff.clear();
    c->diffTop = 0;
    c->diffLines = 0;
    if (!r.hash.empty()) {
        // Patch for the diff pane: stat first (one line per file), then the
        // unified diff itself. ParseDiff turns it into rows with line numbers.
        std::wstring patch = RunGit({ L"-c", L"core.quotepath=false",
                                      L"-C", c->dir, L"show", L"--format=",
                                      L"--stat", L"--patch", L"--no-color", r.hash });
        ParseDiff(patch, c->diff);
        c->diffLines = (int)c->diff.size();
    }
    InvalidateRect(c->hwnd, nullptr, FALSE);
}

LRESULT CALLBACK LogWndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    LogCtx* c = (LogCtx*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (msg) {
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lp;
        if (mmi) {
            mmi->ptMinTrackSize.x = 640;
            mmi->ptMinTrackSize.y = 460 + kCapH;
        }
        return 0;
    }
    case WM_PAINT:
        if (c) LogPaint(c);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_SIZE:
        if (c) {
            RECT rc{};
            GetClientRect(h, &rc);
            SetRect(&c->rcClose, rc.right - 26, 3, rc.right - 4, 21);
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    case WM_MOUSEWHEEL: {
        if (!c) break;
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        ScreenToClient(h, &pt);
        pt.y -= kCapH;
        RECT rc{};
        GetClientRect(h, &rc);
        rc.bottom -= kCapH;
        int delta = GET_WHEEL_DELTA_WPARAM(wp) / WHEEL_DELTA * 3;
        if (pt.y > LogPatchTop(rc)) {
            // cursor over the patch pane — scroll the diff
            int rowsFit = PatchRowsFit(rc);
            if (rowsFit < 1) rowsFit = 1;
            int maxTop = c->diffLines - rowsFit;
            if (maxTop < 0) maxTop = 0;
            c->diffTop -= delta;
            if (c->diffTop > maxTop) c->diffTop = maxTop;
            if (c->diffTop < 0) c->diffTop = 0;
            InvalidateRect(h, nullptr, FALSE);
        } else {
            LogScrollTo(c, c->top - delta);
        }
        return 0;
    }
    case WM_MOUSEMOVE: {
        if (!c) break;
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        bool hv = PtInRect(&c->rcClose, pt) != 0;
        if (hv != c->hoverClose) { c->hoverClose = hv; InvalidateRect(h, nullptr, FALSE); }
        pt.y -= kCapH;
        RECT rc{};
        GetClientRect(h, &rc);
        rc.bottom -= kCapH;
        if (c->drag) {
            if (c->drag == 1) {
                int trackH = LogListBottom(rc) - kLogListTop;
                int total = (int)c->rows.size();
                int th = 0;
                if (total > c->visible) {
                    th = trackH * c->visible / total;
                    if (th < 24) th = 24;
                    if (th > trackH) th = trackH;
                }
                int maxTop = total - c->visible;
                if (maxTop < 0) maxTop = 0;
                int range = trackH - th;
                if (range < 1) range = 1;
                LogScrollTo(c, c->dragTop + (pt.y - c->dragY) * maxTop / range);
            } else {
                int patchTop = LogPatchTop(rc);
                int trackH = rc.bottom - 6 - patchTop;
                int fit = PatchRowsFit(rc);
                int th = 0;
                if (c->diffLines > fit) {
                    th = trackH * fit / c->diffLines;
                    if (th < 24) th = 24;
                    if (th > trackH) th = trackH;
                }
                int maxTop = c->diffLines - fit;
                if (maxTop < 0) maxTop = 0;
                int range = trackH - th;
                if (range < 1) range = 1;
                int nt = c->dragTop + (pt.y - c->dragY) * maxTop / range;
                if (nt < 0) nt = 0;
                if (nt > maxTop) nt = maxTop;
                if (nt != c->diffTop) { c->diffTop = nt; InvalidateRect(h, nullptr, FALSE); }
            }
            return 0;
        }
        int nh = -1;
        if (pt.y >= kLogListTop && pt.y < LogListBottom(rc) && pt.x < rc.right - kSbW - 2) {
            int idx = c->top + (pt.y - kLogListTop) / kLogRowH;
            if (idx >= 0 && idx < (int)c->rows.size()) nh = idx;
        }
        if (nh != c->hover) { c->hover = nh; InvalidateRect(h, nullptr, FALSE); }
        TRACKMOUSEEVENT tme{ sizeof(tme), TME_LEAVE, h, 0 };
        TrackMouseEvent(&tme);
        return 0;
    }
    case WM_MOUSELEAVE:
        if (c && (c->hover != -1 || c->hoverClose)) {
            c->hover = -1;
            c->hoverClose = false;
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    case WM_LBUTTONDOWN: {
        if (!c) break;
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        if (PtInRect(&c->rcClose, pt)) { DestroyWindow(h); return 0; }
        pt.y -= kCapH;
        RECT rc{};
        GetClientRect(h, &rc);
        rc.bottom -= kCapH;
        if (PtInRect(&c->rcListSb, pt)) {
            int th = 0, ty = 0;
            SbGeom(kLogListTop, LogListBottom(rc), (int)c->rows.size(), c->visible,
                   c->top, &th, &ty);
            if (th > 0 && pt.y >= ty && pt.y < ty + th) {
                c->drag = 1; c->dragY = pt.y; c->dragTop = c->top;
                SetCapture(h);
            } else {
                LogScrollTo(c, c->top + (pt.y < ty ? -c->visible : c->visible));
            }
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }
        if (PtInRect(&c->rcPatchSb, pt)) {
            int patchTop = LogPatchTop(rc);
            int fit = PatchRowsFit(rc);
            int th = 0, ty = 0;
            SbGeom(patchTop, rc.bottom - 6, c->diffLines, fit, c->diffTop, &th, &ty);
            if (th > 0 && pt.y >= ty && pt.y < ty + th) {
                c->drag = 2; c->dragY = pt.y; c->dragTop = c->diffTop;
                SetCapture(h);
            } else {
                int nt = c->diffTop + (pt.y < ty ? -fit : fit);
                int maxTop = c->diffLines - fit;
                if (maxTop < 0) maxTop = 0;
                if (nt < 0) nt = 0;
                if (nt > maxTop) nt = maxTop;
                c->diffTop = nt;
            }
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }
        if (pt.y >= kLogListTop && pt.y < LogListBottom(rc)) {
            int idx = c->top + (pt.y - kLogListTop) / kLogRowH;
            if (idx >= 0 && idx < (int)c->rows.size()) LogSelect(c, idx);
        }
        return 0;
    }
    case WM_LBUTTONUP:
        if (c && c->drag) {
            c->drag = 0;
            ReleaseCapture();
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    case WM_NCHITTEST:
        return CapHitTest(h, wp, lp);
    case WM_KEYDOWN:
        if (!c) break;
        if (wp == VK_ESCAPE || wp == VK_RETURN) { DestroyWindow(h); return 0; }
        if (wp == VK_DOWN) LogSelect(c, c->sel + 1);
        if (wp == VK_UP) LogSelect(c, c->sel - 1);
        if (wp == VK_NEXT) LogScrollTo(c, c->top + c->visible);
        if (wp == VK_PRIOR) LogScrollTo(c, c->top - c->visible);
        if (wp == VK_HOME) LogSelect(c, 0);
        if (wp == VK_END) LogSelect(c, (int)c->rows.size() - 1);
        return 0;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

}  // namespace

void ShowGitLog(HWND owner) {
    std::wstring dir = IniGet(L"dumpdir");
    if (dir.empty()) {
        MessageBoxW(owner, L"Сначала укажите папку выгрузки в настройках GitBar.",
                    L"История Git", MB_ICONINFORMATION);
        return;
    }
    if (GetFileAttributesW((dir + L"\\.git").c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(owner, (L"В папке выгрузки нет git-репозитория:\n" + dir).c_str(),
                    L"История Git", MB_ICONINFORMATION);
        return;
    }
    static bool cls = false;
    if (!cls) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = LogWndProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = L"V8iGitLog";
        if (!RegisterClassW(&wc)) return;
        cls = true;
    }
    LogCtx* c = new LogCtx();
    c->dir = dir;
    if (!LoadLog(dir, c->rows, &c->maxLanes)) {
        delete c;
        MessageBoxW(owner, L"Не удалось прочитать историю (git log вернул пусто).",
                    L"История Git", MB_ICONINFORMATION);
        return;
    }
    c->mono = LogFont(9, L"Consolas", FW_NORMAL, FIXED_PITCH | FF_MODERN);
    c->ui = LogFont(8, L"Tahoma", FW_NORMAL, DEFAULT_PITCH | FF_SWISS);
    c->uiSemi = LogFont(8, L"Tahoma", FW_BOLD, DEFAULT_PITCH | FF_SWISS);
    c->title = LogFont(8, L"Tahoma", FW_BOLD, DEFAULT_PITCH | FF_SWISS);
    c->badge = LogFont(8, L"Tahoma", FW_BOLD, DEFAULT_PITCH | FF_SWISS);

    HWND h = CreateWindowExW(WS_EX_DLGMODALFRAME, L"V8iGitLog",
                             L"История Git — v8inject",
                             WS_POPUP | WS_THICKFRAME | WS_VISIBLE,
                             CW_USEDEFAULT, CW_USEDEFAULT, 960, 700 + kCapH, owner, nullptr,
                             GetModuleHandleW(nullptr), nullptr);
    if (!h) { delete c; return; }
    CenterOnOwner(h, owner);
    SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)c);
    c->hwnd = h;
    RECT rc{};
    GetClientRect(h, &rc);
    SetRect(&c->rcClose, rc.right - 26, 3, rc.right - 4, 21);
    rc.bottom -= kCapH;
    c->visible = (LogListBottom(rc) - kLogListTop) / kLogRowH;
    if (c->visible < 1) c->visible = 1;
    SetForegroundWindow(h);
    LogSelect(c, 0);

    MSG msg;
    ++g_modalDepth;
    MenuReposition(nullptr);   // hide the menu overlay at once, not on next tick
    while (IsWindow(h) && GetMessageW(&msg, nullptr, 0, 0)) {
        if (msg.hwnd == h || IsChild(h, msg.hwnd)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        } else {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    --g_modalDepth;
    if (IsWindow(h)) DestroyWindow(h);
    if (c->mono) DeleteObject(c->mono);
    if (c->ui) DeleteObject(c->ui);
    if (c->uiSemi) DeleteObject(c->uiSemi);
    if (c->title) DeleteObject(c->title);
    if (c->badge) DeleteObject(c->badge);
    delete c;
    Reposition(false);
}

void RunPull() {
    std::wstring dir = IniGet(L"dumpdir");
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
    std::wstring dir = IniGet(L"dumpdir");
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

// ---------------------------------------------------------------------------
// Generic list window: working copy, branches, stashes, tags.
// ---------------------------------------------------------------------------

struct ListDlg {
    HWND h = nullptr;
    HWND list = nullptr;
    HWND closeBtn = nullptr;
    RECT listFrame{};             // 1px 1C frame painted around the list
    HFONT font = nullptr;
    std::wstring dir;
    int kind = 0;                 // 0=status 1=branches 2=stash 3=tags
    std::vector<std::wstring> items;
    int btnIds[5] = {};
    int btnCount = 0;
    bool hoverX = false;
    bool trackedLeave = false;
};

static void ListDlgLayout(ListDlg* d) {
    if (!d || !d->h) return;
    RECT rc{};
    GetClientRect(d->h, &rc);
    const int pad = 8, bh = 26;
    int by = rc.bottom - pad - bh;
    SetRect(&d->listFrame, pad, kCapH + pad, rc.right - pad, by - pad);
    MoveWindow(d->list, pad + 1, kCapH + pad + 1, rc.right - 2 * pad - 2,
               by - 2 * pad - 2 - kCapH, TRUE);
    int bx = pad;
    for (int i = 0; i < d->btnCount; ++i) {
        MoveWindow(GetDlgItem(d->h, d->btnIds[i]), bx, by, 110, bh, TRUE);
        bx += 116;
    }
    if (d->closeBtn)
        MoveWindow(d->closeBtn, rc.right - pad - 110, by, 110, bh, TRUE);
}

static void SplitLines(const std::wstring& s, std::vector<std::wstring>& out) {
    out.clear();
    size_t p = 0;
    while (p < s.size()) {
        size_t e = s.find_first_of(L"\r\n", p);
        if (e == std::wstring::npos) e = s.size();
        std::wstring line = s.substr(p, e - p);
        p = e;
        while (p < s.size() && (s[p] == L'\r' || s[p] == L'\n')) ++p;
        if (!line.empty()) out.push_back(line);
    }
}

static void ListDlgFill(ListDlg* d) {
    std::wstring out;
    switch (d->kind) {
    // core.quotepath=false: without it git escapes non-ASCII names as
    // "\320\241.txt", and that escaped text is what would be handed back to
    // "git add" -- the command would not find the file.
    case 0: out = RunGit({ L"-C", d->dir, L"-c", L"core.quotepath=false",
                           L"status", L"--porcelain" }); break;
    case 1: out = RunGit({ L"-C", d->dir, L"branch", L"-a" }); break;
    case 2: out = RunGit({ L"-C", d->dir, L"stash", L"list" }); break;
    default: out = RunGit({ L"-C", d->dir, L"tag", L"-n1" }); break;
    }
    SplitLines(out, d->items);
    SendMessageW(d->list, LB_RESETCONTENT, 0, 0);
    for (const std::wstring& line : d->items)
        SendMessageW(d->list, LB_ADDSTRING, 0, (LPARAM)line.c_str());
    if (!d->items.empty()) SendMessageW(d->list, LB_SETCURSEL, 0, 0);
}

// Selected item with the porcelain status prefix stripped (for file paths).
static std::wstring ListDlgSel(ListDlg* d) {
    int sel = (int)SendMessageW(d->list, LB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= (int)d->items.size()) return L"";
    std::wstring line = d->items[sel];
    if (d->kind == 0) {
        // " M path", "?? path", "R  old -> new"
        size_t sp = line.find(L' ');
        if (sp != std::wstring::npos) {
            std::wstring path = TrimWs(line.substr(sp + 1));
            size_t arrow = path.find(L" -> ");
            if (arrow != std::wstring::npos) path = path.substr(arrow + 4);
            return path;
        }
        return L"";
    }
    if (d->kind == 1) {
        std::wstring b = TrimWs(line);
        if (b.rfind(L"* ", 0) == 0) b = TrimWs(b.substr(2));
        return b;
    }
    if (d->kind == 2) {
        // "stash@{0}: WIP on main: ..."
        size_t colon = line.find(L':');
        return colon == std::wstring::npos ? line : TrimWs(line.substr(0, colon));
    }
    // tag: "v1.0  message"
    size_t sp = line.find(L' ');
    return sp == std::wstring::npos ? line : line.substr(0, sp);
}

// Asks before an action that cannot be undone: throwing away the edits in a
// file, deleting a branch, a stash or a tag. A mis-click on "Отменить" in the
// working-copy list used to discard the user's changes without a word.
bool ConfirmDestructive(HWND h, const wchar_t* what, const std::wstring& sel) {
    std::wstring msg = std::wstring(what) + L"\n\n" + sel +
                        L"\n\nДействие необратимо. Продолжить?";
    return MessageBoxW(h, msg.c_str(), L"Git",
                        MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) == IDYES;
}

static void ListDlgAct(ListDlg* d, int btn) {
    std::wstring sel = ListDlgSel(d);
    std::wstring out;
    if (sel.empty()) return;
    switch (d->kind) {
    case 0:  // working copy
        if (btn == 0) out = RunGit({ L"-C", d->dir, L"add", L"--", sel });
        else if (btn == 1) out = RunGit({ L"-C", d->dir, L"reset", L"HEAD", L"--", sel });
        else if (btn == 2) {
            if (!ConfirmDestructive(d->h, L"Отменить изменения в файле (правки будут потеряны):", sel))
                return;
            out = RunGit({ L"-C", d->dir, L"checkout", L"--", sel });
        }
        break;
    case 1:  // branches
        if (btn == 0) out = RunGit({ L"-C", d->dir, L"checkout", sel });
        else if (btn == 1) {
            if (!ConfirmDestructive(d->h, L"Удалить ветку:", sel)) return;
            out = RunGit({ L"-C", d->dir, L"branch", L"-d", sel });
        }
        break;
    case 2:  // stashes
        if (btn == 0) out = RunGit({ L"-C", d->dir, L"stash", L"pop", sel });
        else if (btn == 1) {
            if (!ConfirmDestructive(d->h, L"Удалить отложенные изменения:", sel)) return;
            out = RunGit({ L"-C", d->dir, L"stash", L"drop", sel });
        }
        break;
    default:  // tags
        if (btn == 0) {
            if (!ConfirmDestructive(d->h, L"Удалить тег:", sel)) return;
            out = RunGit({ L"-C", d->dir, L"tag", L"-d", sel });
        }
        else if (btn == 1) out = RunGit({ L"-C", d->dir, L"push", L"origin", sel });
        break;
    }
    out = TrimWs(out);
    if (!out.empty() && out.find(L"fatal") != std::wstring::npos)
        MessageBoxW(d->h, out.c_str(), L"Git", MB_ICONWARNING);
    ListDlgFill(d);
    Reposition(false);
}

static void ListDlgDrawItem(const DRAWITEMSTRUCT* dis, HFONT font) {
    bool sel = (dis->itemState & ODS_SELECTED) != 0;
    bool focus = GetFocus() == dis->hwndItem;
    COLORREF face = sel ? (focus ? kDlgSel : kDlgSelIdle) : kDlgFieldBg;
    HBRUSH b = CreateSolidBrush(face);
    FillRect(dis->hDC, &dis->rcItem, b);
    DeleteObject(b);
    if (dis->itemID == (UINT)-1) return;   // just the empty tail of the list

    wchar_t text[1024] = {};
    SendMessageW(dis->hwndItem, LB_GETTEXT, dis->itemID, (LPARAM)text);
    RECT row = dis->rcItem;
    row.left += 4;
    HGDIOBJ oldFont = SelectObject(dis->hDC, font);
    int oldMode = SetBkMode(dis->hDC, TRANSPARENT);
    SetTextColor(dis->hDC, kDlgText);
    DrawTextW(dis->hDC, text, -1, &row,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    SetBkMode(dis->hDC, oldMode);
    SelectObject(dis->hDC, oldFont);
}

static LRESULT CALLBACK ListDlgProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    ListDlg* d = (ListDlg*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (msg) {
    case WM_COMMAND: {
        if (!d) break;
        int id = LOWORD(wp);
        if (id == 900) { DestroyWindow(h); return 0; }
        if (id >= 901 && id <= 905) {
            int idx = id - 901;
            if (d->kind == 0) {
                if (idx == 3) { RunCommit(); ListDlgFill(d); }
                else if (idx == 4) {
                    std::wstring out = RunGit({ L"-C", d->dir, L"commit", L"--amend", L"--no-edit" });
                    MessageBoxW(h, TrimWs(out).c_str(), L"Amend", MB_ICONINFORMATION);
                    ListDlgFill(d);
                } else ListDlgAct(d, idx);
            } else {
                ListDlgAct(d, idx);
            }
        }
        return 0;
    }
    case WM_CTLCOLORLISTBOX:
        SetBkColor((HDC)wp, kDlgFieldBg);
        return (LRESULT)UiFieldBrush();
    case WM_PAINT: {
        if (!d) break;
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        DrawCaption(dc, h, d->font, d->hoverX);
        UiFrame(dc, d->listFrame, kDlgBorder);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_NCHITTEST:
        return CapHitTest(h, wp, lp);
    case WM_MOUSEMOVE: {
        if (!d) break;
        if (!d->trackedLeave) {
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, h, 0 };
            TrackMouseEvent(&tme);
            d->trackedLeave = true;
        }
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        RECT rc;
        GetClientRect(h, &rc);
        RECT capRect = CapCloseRect(rc);
        bool hv = PtInRect(&capRect, pt) != 0;
        if (hv != d->hoverX) { d->hoverX = hv; InvalidateRect(h, nullptr, FALSE); }
        return 0;
    }
    case WM_MOUSELEAVE:
        if (d) {
            d->trackedLeave = false;
            if (d->hoverX) { d->hoverX = false; InvalidateRect(h, nullptr, FALSE); }
        }
        return 0;
    case WM_LBUTTONDOWN: {
        if (!d) break;
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        RECT rc;
        GetClientRect(h, &rc);
        RECT capRect = CapCloseRect(rc);
        if (PtInRect(&capRect, pt)) { DestroyWindow(h); return 0; }
        break;
    }
    case WM_DRAWITEM: {
        if (!d) break;
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lp;
        if (dis->CtlType == ODT_BUTTON && UiDrawOwnerButton(dis, d->font))
            return TRUE;
        if (dis->CtlType == ODT_LISTBOX) {
            ListDlgDrawItem(dis, d->font);
            return TRUE;
        }
        break;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mm = (MINMAXINFO*)lp;
        mm->ptMinTrackSize.x = 740;
        mm->ptMinTrackSize.y = 220 + kCapH;
        return 0;
    }
    case WM_SIZE: {
        if (!d) break;
        ListDlgLayout(d);
        InvalidateRect(h, nullptr, FALSE);
        return 0;
    }
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

void ShowList(int kind) {
    std::wstring dir = IniGet(L"dumpdir");
    if (dir.empty()) {
        MessageBoxW(g_bar.hwnd, L"Сначала укажите папку выгрузки в настройках GitBar.",
                    L"Git", MB_ICONINFORMATION);
        return;
    }
    if (GetFileAttributesW((dir + L"\\.git").c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(g_bar.hwnd, (L"В папке выгрузки нет git-репозитория:\n" + dir).c_str(),
                    L"Git", MB_ICONINFORMATION);
        return;
    }
    static bool cls = false;
    if (!cls) {
        WNDCLASSW wc{};
        wc.lpfnWndProc = ListDlgProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = UiBgBrush();
        wc.lpszClassName = L"V8iGitList";
        if (!RegisterClassW(&wc)) return;
        cls = true;
    }
    const wchar_t* title = kind == 0 ? L"Рабочая копия — v8inject"
                         : kind == 1 ? L"Ветки — v8inject"
                         : kind == 2 ? L"Stash — v8inject"
                                     : L"Теги — v8inject";
    ListDlg* d = new ListDlg();
    d->dir = dir;
    d->kind = kind;
    d->font = CreateDlgFont();
    HWND h = CreateWindowExW(WS_EX_DLGMODALFRAME, L"V8iGitList", title,
                             WS_POPUP | WS_THICKFRAME | WS_VISIBLE,
                             CW_USEDEFAULT, CW_USEDEFAULT, 760, 480 + kCapH,
                             g_bar.hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!h) { DeleteObject(d->font); delete d; return; }
    CenterOnOwner(h, g_bar.hwnd);
    d->h = h;
    SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)d);
    d->list = CreateWindowExW(0, L"LISTBOX", L"",
                              WS_CHILD | WS_VISIBLE | WS_VSCROLL |
                              LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS,
                              0, 0, 0, 0, h, nullptr, GetModuleHandleW(nullptr), nullptr);
    SendMessageW(d->list, WM_SETFONT, (WPARAM)d->font, TRUE);
    {
        HDC dc = GetDC(h);
        int rowH = MulDiv(17, GetDeviceCaps(dc, LOGPIXELSY), 96);
        ReleaseDC(h, dc);
        SendMessageW(d->list, LB_SETITEMHEIGHT, 0, rowH);
    }

    struct { const wchar_t* text; } defs[5] = {};
    if (kind == 0) {
        defs[0] = { L"Индексировать" }; defs[1] = { L"Снять" };
        defs[2] = { L"Отменить" }; defs[3] = { L"Коммит" }; defs[4] = { L"Amend" };
        d->btnCount = 5;
    } else if (kind == 1) {
        defs[0] = { L"Переключить" }; defs[1] = { L"Удалить" };
        d->btnCount = 2;
    } else if (kind == 2) {
        defs[0] = { L"Применить" }; defs[1] = { L"Удалить" };
        d->btnCount = 2;
    } else {
        defs[0] = { L"Удалить" }; defs[1] = { L"Отправить" };
        d->btnCount = 2;
    }
    for (int i = 0; i < d->btnCount; ++i) {
        d->btnIds[i] = 901 + i;
        HWND btn = CreateWindowExW(0, L"BUTTON", defs[i].text,
                                   WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                                   0, 0, 110, 26, h, (HMENU)(INT_PTR)(901 + i),
                                   GetModuleHandleW(nullptr), nullptr);
        ThemedButton(btn, d->font);
    }
    d->closeBtn = CreateWindowExW(0, L"BUTTON", L"Закрыть",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                                  0, 0, 110, 26, h, (HMENU)(INT_PTR)900,
                                  GetModuleHandleW(nullptr), nullptr);
    ThemedButton(d->closeBtn, d->font);
    ListDlgLayout(d);
    ListDlgFill(d);
    SetForegroundWindow(h);
    SetFocus(d->list);

    MSG msg;
    ++g_modalDepth;
    MenuReposition(nullptr);   // hide the menu overlay at once, not on next tick
    while (IsWindow(h) && GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    --g_modalDepth;
    if (IsWindow(h)) DestroyWindow(h);
    if (d->font) DeleteObject(d->font);
    delete d;
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
    case kWinIdBranches: ShowList(1); break;
    case kWinIdStash: ShowList(2); break;
    case kWinIdTags: ShowList(3); break;
    case kWinIdStatus: ShowList(0); break;
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
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

// Called from the bar's 500ms reposition tick. Re-queries UIA only when the
// frame moved/resized or every few seconds; otherwise just keeps the overlay
// raised above the frame's own painting.
void MenuReposition(HWND frame) {
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
    RECT fr{}; GetWindowRect(frame, &fr);
    bool frameChanged = (fr.left != g_menu.lastFrame.left || fr.top != g_menu.lastFrame.top ||
                         fr.right != g_menu.lastFrame.right || fr.bottom != g_menu.lastFrame.bottom);
    g_menu.lastFrame = fr;
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

}  // namespace v8i
