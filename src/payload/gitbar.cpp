#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>

#include "v8inject/diag.h"
#include "icons.h"

#include <cstring>

extern "C" void V8iGitBarDump();  // v8i_export.cpp

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

void IniSet(const wchar_t* key, const wchar_t* value) {
    WritePrivateProfileStringW(L"git", key, value, kIniPath());
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
            if (!ReadFile(outRd, buf, sizeof(buf), &rd, nullptr) || rd == 0) break;
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
            if (!ReadFile(outRd, buf, sizeof(buf), &rd, nullptr) || rd == 0) break;
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
const int kCells = 6;
const int kBarW = 2 + kCells * kCell + 2;
const int kBarH = 24;
const int kDockY = 28;      // toolbar row, just under the menu
const int kWinIdDump = 1, kWinIdInit = 2, kWinIdCommit = 3,
          kWinIdPush = 4, kWinIdSettings = 5, kWinIdLog = 6;

struct GitBar {
    HWND hwnd = nullptr;
    HWND tooltip = nullptr;
    int hover = 0;          // cell index under the cursor (1..kCells), 0 = none
    bool pressed = false;
    bool dragging = false;
    POINT pressPt{};
    RECT lastFrame{};
    DWORD threadId = 0;
    HANDLE thread = nullptr;
};

GitBar g_bar;
// True on 8.5+: the designer paints its client through DWM, so a child window
// never shows; the bar is a top-level owned window there instead.
bool g_topLevelDwm = false;

int CellX(int id) { return 2 + (id - 1) * kCell; }

int IdFromPoint(POINT pt) {
    if (pt.y < 0 || pt.y >= kBarH) return 0;
    for (int id = 1; id <= kCells; ++id) {
        int x = CellX(id);
        if (pt.x >= x && pt.x < x + kCell) return id;
    }
    return 0;
}

// The five glyphs are 1C's own toolbar pictures, baked to premultiplied BGRA
// by tools/gen_icons.py: hand-drawn GDI shapes never matched the platform's
// look, and these do because they come from the same resource bundles.
const unsigned char* IconFor(int id) {
    switch (id) {
    case kWinIdDump: return icons::kIconDump;
    case kWinIdInit: return icons::kIconInit;
    case kWinIdCommit: return icons::kIconCommit;
    case kWinIdPush: return icons::kIconPush;
    case kWinIdSettings: return icons::kIconSettings;
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

void Paint(HWND hwnd) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);
    RECT rc{};
    GetClientRect(hwnd, &rc);

    // Panel background and a 1C-ish border, so the strip reads as a toolbar.
    HBRUSH bg = CreateSolidBrush(RGB(238, 234, 222));
    FillRect(dc, &rc, bg);
    DeleteObject(bg);
    HPEN border = CreatePen(PS_SOLID, 1, RGB(176, 166, 142));
    SelectObject(dc, border);
    SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, rc.left, rc.top, rc.right, rc.bottom);
    DeleteObject(border);

    for (int id = 1; id <= kCells; ++id) {
        int x = CellX(id);
        RECT cell{ x, 1, x + kCell, kBarH - 1 };
        if (id == g_bar.hover) {
            HBRUSH hl = CreateSolidBrush(g_bar.pressed ? RGB(226, 216, 178)
                                                       : RGB(250, 244, 214));
            FillRect(dc, &cell, hl);
            DeleteObject(hl);
            HPEN pen = CreatePen(PS_SOLID, 1, RGB(198, 184, 148));
            SelectObject(dc, pen);
            SelectObject(dc, GetStockObject(NULL_BRUSH));
            Rectangle(dc, cell.left, cell.top, cell.right, cell.bottom);
            DeleteObject(pen);
        }
        if (id == kWinIdLog) {
            // Hand-drawn "log" glyph (three text lines with a leading dot):
            // there is no suitable picture among the baked 1C icons.
            int gx = x + 4, gy = 5;
            HPEN pen = CreatePen(PS_SOLID, 1, RGB(96, 96, 96));
            HPEN op = (HPEN)SelectObject(dc, pen);
            for (int k = 0; k < 3; ++k) {
                int yy = gy + k * 5;
                MoveToEx(dc, gx, yy, nullptr);
                LineTo(dc, gx + 3, yy);
                MoveToEx(dc, gx + 5, yy, nullptr);
                LineTo(dc, gx + 15, yy);
            }
            SelectObject(dc, op);
            DeleteObject(pen);
        } else {
            DrawIcon(dc, IconFor(id), x + (kCell - icons::kSize) / 2,
                     (kBarH - icons::kSize) / 2);
        }
    }
    EndPaint(hwnd, &ps);
}

// Docks the bar at the right end of the toolbar row unless the user dragged
// it; keeps it raised above the frame's own toolbar children, which 1C
// re-creates and would otherwise paint over us.
void Reposition(bool forceDock) {
    HWND frame = GetParent(g_bar.hwnd);
    if (!frame) { frame = FindFrame(); if (frame) SetParent(g_bar.hwnd, frame); }
    if (!frame) return;

    RECT cr{};
    GetClientRect(frame, &cr);
    int w = cr.right - cr.left;
    int h = cr.bottom - cr.top;

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
        tl.x = origin.x + (w - kBarW - 4);
        tl.y = origin.y + kDockY;
        if (!IsWindowVisible(frame)) { ShowWindow(g_bar.hwnd, SW_HIDE); hiddenMinimized = true; }
        else if (!IsWindowVisible(g_bar.hwnd)) { ShowWindow(g_bar.hwnd, SW_SHOWNOACTIVATE); }
    } else {
        ScreenToClient(frame, &tl);
        bool frameChanged = (cr.right != g_bar.lastFrame.right ||
                             cr.bottom != g_bar.lastFrame.bottom);
        g_bar.lastFrame = cr;
        if (forceDock || frameChanged) {
            tl.x = w - kBarW - 4;
            tl.y = kDockY;
        }
        if (tl.x < 0) tl.x = 0;
        if (tl.y < 0) tl.y = 0;
        if (tl.x > w - kBarW) tl.x = w - kBarW;
        if (tl.y > h - kBarH) tl.y = h - kBarH;
    }
    if (hiddenMinimized) return;
    SetWindowPos(g_bar.hwnd, HWND_TOP, tl.x, tl.y, 0, 0,
                 SWP_NOSIZE | SWP_NOACTIVATE | (g_topLevelDwm ? 0 : SWP_SHOWWINDOW));
}

void ShowTip(const std::wstring& text) {
    if (!g_bar.tooltip || !g_bar.hwnd) return;
    TOOLINFOW ti{ sizeof(ti), TTF_IDISHWND };
    ti.hwnd = g_bar.hwnd;
    ti.uId = (UINT_PTR)g_bar.hwnd;
    ti.lpszText = (LPWSTR)text.c_str();
    SendMessageW(g_bar.tooltip, TTM_UPDATETIPTEXTW, 0, (LPARAM)&ti);
    SendMessageW(g_bar.tooltip, TTM_POPUP, 0, 0);
    LogGit(L"tip", text);
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
    bool accepted = false;
};

LRESULT CALLBACK PromptDlgProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    PromptCtx* c = (PromptCtx*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (msg) {
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
                               WS_CAPTION | WS_SYSMENU | WS_OVERLAPPED | WS_VISIBLE,
                               CW_USEDEFAULT, CW_USEDEFAULT, 470, 160, owner, nullptr,
                               GetModuleHandleW(nullptr), nullptr);
    if (!dlg) return false;

    PromptCtx ctx;
    ctx.out = out;
    SetWindowLongPtrW(dlg, GWLP_WNDPROC, (LONG_PTR)PromptDlgProc);
    SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)&ctx);

    CreateWindowExW(0, L"STATIC", label, WS_CHILD | WS_VISIBLE | SS_LEFT,
                    12, 12, 430, 18, dlg, nullptr, GetModuleHandleW(nullptr), nullptr);
    HWND ed = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                              12, 34, 430, 24, dlg, (HMENU)1001,
                              GetModuleHandleW(nullptr), nullptr);
    ctx.ed = ed;
    SetWindowTextW(ed, initial.c_str());
    SendMessageW(ed, EM_SETSEL, 0, -1);
    CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                    252, 72, 90, 26, dlg, (HMENU)(INT_PTR)IDOK, GetModuleHandleW(nullptr), nullptr);
    CreateWindowExW(0, L"BUTTON", L"Отмена", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    352, 72, 90, 26, dlg, (HMENU)(INT_PTR)IDCANCEL,
                    GetModuleHandleW(nullptr), nullptr);

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
        out = RunGit({ L"-C", dir, L"push", L"-u", L"origin", L"HEAD" });
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

const COLORREF kDlgBg      = RGB(245, 242, 221);   // 1C window cream (measured
                                                   // from a live designer: #F5F2DD)
const COLORREF kDlgBorder  = RGB(176, 166, 142);
const COLORREF kDlgFieldBg = RGB(255, 255, 255);
const COLORREF kDlgHover   = RGB(250, 244, 214);
const COLORREF kDlgPress   = RGB(226, 216, 178);
const COLORREF kDlgText    = RGB(0, 0, 0);

const wchar_t* kFieldLabels[4] = { L"git.exe", L"папка выгрузки",
                                   L"комментарий к коммиту", L"remote origin (не обяз.)" };
const wchar_t* kFieldIni[4]    = { L"gitpath", L"dumpdir", L"commitmsg", L"remote" };

struct SettingsCtx {
    std::wstring fields[4];
    size_t caret[4] = {};
    int    active = 0;
    RECT   fieldRects[4];
    RECT   okRect, cancelRect;
    int    hoverBtn = -1;   // 0 = OK, 1 = Отмена, -1 = none
    int    pressBtn = -1;
    HFONT  font = nullptr;
    bool   trackedLeave = false;
};

HFONT CreateDlgFont() {
    HDC dc = GetDC(nullptr);
    int h = -MulDiv(8, GetDeviceCaps(dc, LOGPIXELSY), 72);
    ReleaseDC(nullptr, dc);
    return CreateFontW(h, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Tahoma");
}

void SettingsLayout(HWND h, SettingsCtx* c) {
    RECT rc;
    GetClientRect(h, &rc);
    const int fx = 150, fw = rc.right - fx - 14, fh = 22;
    for (int i = 0; i < 4; ++i)
        SetRect(&c->fieldRects[i], fx, 20 + i * 34, fx + fw, 20 + i * 34 + fh);
    SetRect(&c->okRect,     fx, 166, fx + 84, 190);
    SetRect(&c->cancelRect, fx + 94, 166, fx + 178, 190);
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
    return -1;
}

void SettingsSave(HWND h, SettingsCtx* c) {
    if (!c->fields[0].empty()) IniSet(L"gitpath", c->fields[0].c_str());
    if (!c->fields[1].empty()) IniSet(L"dumpdir", c->fields[1].c_str());
    IniSet(L"commitmsg", c->fields[2].c_str());   // empty = auto "chore: 1c dump <stamp>"
    IniSet(L"remote", c->fields[3].c_str());
    LogGit(L"settings saved to", kIniPath());
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
        // fields + labels
        for (int i = 0; i < 4; ++i) {
            RECT& fr = c->fieldRects[i];
            HBRUSH fb = CreateSolidBrush(kDlgFieldBg);
            FillRect(dc, &fr, fb);
            DeleteObject(fb);
            HPEN fp = CreatePen(PS_SOLID, 1, kDlgBorder);
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
            DrawTextW(dc, kFieldLabels[i], -1, &lr,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
        // buttons
        for (int b = 0; b < 2; ++b) {
            RECT& br = b ? c->cancelRect : c->okRect;
            HBRUSH bf = CreateSolidBrush(c->pressBtn == b ? kDlgPress
                                       : c->hoverBtn == b ? kDlgHover : kDlgBg);
            FillRect(dc, &br, bf);
            DeleteObject(bf);
            HPEN bp = CreatePen(PS_SOLID, 1, kDlgBorder);
            HPEN obp = (HPEN)SelectObject(dc, bp);
            HBRUSH obr = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
            Rectangle(dc, br.left, br.top, br.right, br.bottom);
            SelectObject(dc, obr);
            SelectObject(dc, obp);
            DeleteObject(bp);
            DrawTextW(dc, b ? L"Отмена" : L"OK", -1, &br,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
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
        return 0;
    }
    case WM_MOUSELEAVE:
        if (c) { c->hoverBtn = -1; c->trackedLeave = false; InvalidateRect(h, nullptr, FALSE); }
        return 0;
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
                               WS_CAPTION | WS_SYSMENU | WS_OVERLAPPED | WS_VISIBLE,
                               CW_USEDEFAULT, CW_USEDEFAULT, 460, 232, owner, nullptr,
                               GetModuleHandleW(nullptr), nullptr);
    if (!dlg) { DeleteObject(ctx.font); return; }
    SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)&ctx);
    SettingsLayout(dlg, &ctx);

    SetForegroundWindow(dlg);
    SetFocus(dlg);

    MSG msg;
    for (;;) {
        if (!IsWindow(dlg)) break;
        if (!GetMessageW(&msg, nullptr, 0, 0)) break;   // WM_QUIT
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (IsWindow(dlg)) DestroyWindow(dlg);
    DeleteObject(ctx.font);
    Reposition(true);
}

// ---------------------------------------------------------------------------
// Git history viewer: a 1C-style window in the configurator listing recent
// commits with git's own graph column (git log --graph --decorate).
// ---------------------------------------------------------------------------

namespace {

struct LogRow {
    std::wstring graph;    // "│ * " prefix produced by --graph
    std::wstring hash;
    std::wstring author;
    std::wstring date;
    std::wstring refs;
    std::wstring subject;
};

struct LogCtx {
    HWND hwnd = nullptr;
    std::vector<LogRow> rows;
    int top = 0;           // first visible row index
    int sel = -1;          // selected row
    int visible = 1;
    std::wstring dir;
    std::wstring detail;   // expanded commit text for the selected row
    std::wstring diff;     // patch of the selected commit (git show --patch)
    int diffTop = 0;       // first visible diff line
    int diffLines = 0;     // total diff lines (for the scroll hint)
    HFONT mono = nullptr;
    HFONT ui = nullptr;
    RECT rcClose{};
    bool hoverClose = false;
};

const int kLogRowH = 17;
const COLORREF kLogBg = RGB(245, 242, 221);
const COLORREF kLogSel = RGB(49, 106, 197);
const COLORREF kLogBorder = RGB(176, 166, 142);
const COLORREF kLogGray = RGB(112, 104, 88);
const COLORREF kLogRefs = RGB(30, 90, 160);

std::wstring TrimWs(const std::wstring& s) {
    size_t b = s.find_first_not_of(L" \t\r\n");
    if (b == std::wstring::npos) return L"";
    size_t e = s.find_last_not_of(L" \t\r\n");
    return s.substr(b, e - b + 1);
}

bool LoadLog(const std::wstring& dir, std::vector<LogRow>& rows) {
    // 0x1F (unit separator) between fields: subjects may contain anything.
    std::wstring out = RunGit({ L"-C", dir, L"log", L"--graph", L"--decorate",
                                L"-n", L"300", L"--date=short",
                                L"--pretty=format:%x1f%h%x1f%an <%ae>%x1f%ad%x1f%d%x1f%s" });
    if (out.empty()) return false;
    size_t p = 0;
    while (p < out.size()) {
        size_t e = out.find_first_of(L"\r\n", p);
        if (e == std::wstring::npos) e = out.size();
        std::wstring line = out.substr(p, e - p);
        p = e;
        while (p < out.size() && (out[p] == L'\r' || out[p] == L'\n')) ++p;
        if (line.empty()) continue;
        size_t star = line.find(L'*');
        if (star == std::wstring::npos) {
            rows.push_back({ line, L"", L"", L"", L"", L"" });   // merge graph line
            continue;
        }
        std::wstring graph = line.substr(0, star + 1);
        std::wstring rest = line.substr(star + 1);
        // git prints the graph marker, then our separator: "* \x1fhash..." --
        // drop the leading separator or every field shifts by one.
        while (!rest.empty() && (rest[0] == L' ' || rest[0] == L'\t' || rest[0] == L'\x1f'))
            rest.erase(0, 1);
        std::vector<std::wstring> f;
        size_t q = 0;
        while (true) {
            size_t d = rest.find(L'\x1f', q);
            if (d == std::wstring::npos) { f.push_back(rest.substr(q)); break; }
            f.push_back(rest.substr(q, d - q));
            q = d + 1;
        }
        if (f.size() < 5) continue;
        rows.push_back({ graph, TrimWs(f[0]), f[1], f[2], TrimWs(f[3]), f[4] });
    }
    return !rows.empty();
}

HFONT LogFont(int points, const wchar_t* face) {
    HDC dc = GetDC(nullptr);
    int h = -MulDiv(points, GetDeviceCaps(dc, LOGPIXELSY), 72);
    ReleaseDC(nullptr, dc);
    return CreateFontW(h, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                       FIXED_PITCH | FF_MODERN, face);
}

// Gantt-style graph column: a diamond on the commit's date and a "today" line.
static int DaysFromYmd(const std::wstring& s) {
    int y = 0, m = 0, d = 0;
    if (swscanf_s(s.c_str(), L"%d-%d-%d", &y, &m, &d) != 3) return 0;
    return y * 366 + m * 31 + d;  // coarse linear day number, fine for a week span
}

static void DrawDiamond(HDC dc, int cx, int cy, int r, COLORREF color) {
    HPEN pen = CreatePen(PS_SOLID, 1, color);
    HBRUSH br = CreateSolidBrush(color);
    HPEN op = (HPEN)SelectObject(dc, pen);
    HBRUSH ob = (HBRUSH)SelectObject(dc, br);
    POINT pts[4] = { { cx, cy - r }, { cx + r, cy }, { cx, cy + r }, { cx - r, cy } };
    Polygon(dc, pts, 4);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(br);
    DeleteObject(pen);
}

void LogPaint(LogCtx* c) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(c->hwnd, &ps);
    RECT rc{};
    GetClientRect(c->hwnd, &rc);
    HBRUSH bg = CreateSolidBrush(kLogBg);
    FillRect(dc, &rc, bg);
    DeleteObject(bg);
    SetBkMode(dc, TRANSPARENT);

    HPEN border = CreatePen(PS_SOLID, 1, kLogBorder);
    HPEN obp = (HPEN)SelectObject(dc, border);
    HBRUSH obb = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, 0, 0, rc.right - 1, rc.bottom - 1);
    SelectObject(dc, obb);
    SelectObject(dc, obp);
    DeleteObject(border);

    HGDIOBJ oldFont = SelectObject(dc, c->ui);
    SetTextColor(dc, RGB(0, 0, 0));
    RECT head{ 8, 4, rc.right - 34, 20 };
    DrawTextW(dc, (L"История: " + c->dir).c_str(), -1, &head,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

    // column headers: graph | commit | subject | date | author
    {
        const int kGraphW = 170;
        const int kHashW = 78;
        const int kDateW = 84;
        const int kAuthorW = 210;
        int right = rc.right - 4;
        SetTextColor(dc, kLogGray);
        RECT hG{ 4, 20, 4 + kGraphW, 34 };
        DrawTextW(dc, L"Граф", -1, &hG, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        RECT hH{ 4 + kGraphW, 20, 4 + kGraphW + kHashW, 34 };
        DrawTextW(dc, L"Коммит", -1, &hH, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        RECT hSubj{ 4 + kGraphW + kHashW, 20, right - kDateW - kAuthorW, 34 };
        DrawTextW(dc, L"Комментарий", -1, &hSubj,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        RECT hDate{ right - kDateW - kAuthorW, 20, right - kAuthorW, 34 };
        DrawTextW(dc, L"Дата", -1, &hDate,
                  DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        RECT hAuth{ right - kAuthorW, 20, right, 34 };
        DrawTextW(dc, L"Автор", -1, &hAuth,
                  DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        HPEN hl = CreatePen(PS_SOLID, 1, kLogBorder);
        HPEN ohl = (HPEN)SelectObject(dc, hl);
        MoveToEx(dc, 4, 34, nullptr);
        LineTo(dc, right, 34);
        SelectObject(dc, ohl);
        DeleteObject(hl);
    }

    // close box [X]
    HBRUSH cb = CreateSolidBrush(c->hoverClose ? RGB(226, 216, 178) : kLogBg);
    FillRect(dc, &c->rcClose, cb);
    DeleteObject(cb);
    HPEN cp = CreatePen(PS_SOLID, 1, kLogBorder);
    SelectObject(dc, cp);
    SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, c->rcClose.left, c->rcClose.top, c->rcClose.right, c->rcClose.bottom);
    DeleteObject(cp);
    DrawTextW(dc, L"X", -1, &c->rcClose, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    // rows — top half; details + patch below
    int listTop = 36;
    int listBottom = 36 + (rc.bottom - 36) * 45 / 100;
    c->visible = (listBottom - listTop) / kLogRowH;
    if (c->visible < 1) c->visible = 1;
    // Gantt scale for the graph column (diamond on each commit date)
    int minDays = 0;
    for (size_t ri = 0; ri < c->rows.size(); ++ri) {
        const LogRow& r2 = c->rows[ri];
        if (r2.date.empty()) continue;
        int dd = DaysFromYmd(r2.date);
        if (dd && (!minDays || dd < minDays)) minDays = dd;
    }
    SYSTEMTIME stNow{};
    GetLocalTime(&stNow);
    int todayDays = stNow.wYear * 366 + stNow.wMonth * 31 + stNow.wDay;
    int maxDays = (todayDays > minDays) ? todayDays : minDays + 5;
    int span = maxDays - minDays;
    if (span < 1) span = 1;
    const int kGraphW = 170;
    // "today" line, clamped to the column
    {
        int tx = 4 + (todayDays - minDays) * (kGraphW - 10) / span;
        if (tx < 4) tx = 4;
        if (tx > 4 + kGraphW - 2) tx = 4 + kGraphW - 2;
        HPEN lp = CreatePen(PS_DOT, 1, RGB(190, 60, 60));
        HPEN olp = (HPEN)SelectObject(dc, lp);
        SetBkMode(dc, TRANSPARENT);
        MoveToEx(dc, tx, listTop, nullptr);
        LineTo(dc, tx, listBottom);
        SelectObject(dc, olp);
        DeleteObject(lp);
    }

    HGDIOBJ oldMono = SelectObject(dc, c->mono);
    for (int i = 0; i < c->visible; ++i) {
        int idx = c->top + i;
        if (idx >= (int)c->rows.size()) break;
        RECT row{ 4, listTop + i * kLogRowH, rc.right - 4, listTop + (i + 1) * kLogRowH - 1 };
        const LogRow& r = c->rows[idx];
        bool selected = (idx == c->sel);
        if (selected) {
            HBRUSH sb = CreateSolidBrush(kLogSel);
            FillRect(dc, &row, sb);
            DeleteObject(sb);
            SetTextColor(dc, RGB(255, 255, 255));
        } else {
            SetTextColor(dc, RGB(0, 0, 0));
        }
        // columns: graph | commit | subject | date | author
        const int kHashW2 = 78;
        const int kDateW2 = 84;
        const int kAuthorW2 = 210;
        int right = row.right - 2;
        // diamond on the commit date (Gantt)
        if (!r.date.empty()) {
            int dd = DaysFromYmd(r.date);
            if (dd) {
                int dx = 8 + (dd - minDays) * (kGraphW - 16) / span;
                if (dx >= 4 && dx <= 4 + kGraphW) {
                    DrawDiamond(dc, dx, (row.top + row.bottom) / 2,
                                selected ? 3 : 4, selected ? RGB(255, 255, 255)
                                                           : RGB(49, 106, 197));
                }
            }
        }
        SetTextColor(dc, selected ? RGB(255, 255, 255) : kLogGray);
        if (!r.hash.empty()) {
            RECT hr{ 4 + kGraphW, row.top, 4 + kGraphW + kHashW2, row.bottom };
            DrawTextW(dc, r.hash.c_str(), (int)r.hash.size(), &hr,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
        int subjRight = right - kDateW2 - kAuthorW2;
        RECT sr{ 4 + kGraphW + kHashW2, row.top, subjRight, row.bottom };
        SetTextColor(dc, selected ? RGB(255, 255, 255) : RGB(0, 0, 0));
        DrawTextW(dc, r.subject.c_str(), (int)r.subject.size(), &sr,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        RECT dr{ subjRight, row.top, subjRight + kDateW2, row.bottom };
        SetTextColor(dc, selected ? RGB(240, 240, 240) : kLogGray);
        DrawTextW(dc, r.date.c_str(), (int)r.date.size(), &dr,
                  DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        RECT ar{ subjRight + kDateW2, row.top, right, row.bottom };
        SetTextColor(dc, selected ? RGB(240, 240, 240) : kLogGray);
        DrawTextW(dc, r.author.c_str(), (int)r.author.size(), &ar,
                  DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
    }
    SelectObject(dc, oldMono);

    // separator, status line, commit details and the patch pane
    SelectObject(dc, oldFont);
    HPEN sep = CreatePen(PS_SOLID, 1, kLogBorder);
    HPEN osep = (HPEN)SelectObject(dc, sep);
    MoveToEx(dc, 4, listBottom + 2, nullptr);
    LineTo(dc, rc.right - 4, listBottom + 2);
    SelectObject(dc, osep);
    DeleteObject(sep);

    SetTextColor(dc, kLogGray);
    wchar_t st[160] = {};
    int shown = c->visible;
    if (shown > (int)c->rows.size() - c->top) shown = (int)c->rows.size() - c->top;
    _snwprintf_s(st, _TRUNCATE, L"коммитов: %d  ▸ %d…%d   (↑↓ — коммиты, колесо в диффе — прокрутка, Enter — закрыть)",
                 (int)c->rows.size(), c->top + 1, c->top + shown);
    RECT sr{ 8, listBottom + 4, rc.right - 8, listBottom + 20 };
    DrawTextW(dc, st, -1, &sr, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);

    int detTop = listBottom + 22;
    int detBottom = detTop + 34;
    if (!c->detail.empty()) {
        RECT det{ 8, detTop, rc.right - 8, detBottom };
        SetTextColor(dc, RGB(0, 0, 0));
        DrawTextW(dc, c->detail.c_str(), -1, &det,
                  DT_LEFT | DT_TOP | DT_NOPREFIX | DT_END_ELLIPSIS | DT_WORDBREAK);
    }

    // patch pane: one line per diff row, coloured by its first character
    int patchTop = detBottom + 4;
    int patchBottom = rc.bottom - 6;
    if (patchBottom > patchTop && !c->diff.empty()) {
        int rowsFit = (patchBottom - patchTop) / kLogRowH;
        if (rowsFit < 1) rowsFit = 1;
        int maxTop = c->diffLines - rowsFit;
        if (maxTop < 0) maxTop = 0;
        if (c->diffTop > maxTop) c->diffTop = maxTop;
        if (c->diffTop < 0) c->diffTop = 0;

        HGDIOBJ oldMono2 = SelectObject(dc, c->mono);
        size_t pos = 0;
        int lineIdx = 0;
        while (pos <= c->diff.size()) {
            size_t e = c->diff.find_first_of(L"\r\n", pos);
            if (e == std::wstring::npos) e = c->diff.size();
            std::wstring line = c->diff.substr(pos, e - pos);
            pos = e;
            while (pos < c->diff.size() && (c->diff[pos] == L'\r' || c->diff[pos] == L'\n')) ++pos;
            if (lineIdx >= c->diffTop && lineIdx < c->diffTop + rowsFit) {
                int y = patchTop + (lineIdx - c->diffTop) * kLogRowH;
                RECT lr{ 6, y, rc.right - 6, y + kLogRowH - 1 };
                wchar_t first = line.empty() ? L' ' : line[0];
                if (first == L'+' && !(line.size() > 2 && line[1] == L'+')) {
                    HBRUSH gb = CreateSolidBrush(RGB(228, 245, 228));
                    FillRect(dc, &lr, gb);
                    DeleteObject(gb);
                    SetTextColor(dc, RGB(20, 110, 20));
                } else if (first == L'-' && !(line.size() > 2 && line[1] == L'-')) {
                    HBRUSH rb = CreateSolidBrush(RGB(252, 232, 232));
                    FillRect(dc, &lr, rb);
                    DeleteObject(rb);
                    SetTextColor(dc, RGB(160, 30, 30));
                } else if (line.rfind(L"@@", 0) == 0) {
                    SetTextColor(dc, RGB(40, 80, 160));
                } else if (line.rfind(L"diff --git", 0) == 0 ||
                           line.rfind(L"index ", 0) == 0 ||
                           line.rfind(L"--- ", 0) == 0 ||
                           line.rfind(L"+++ ", 0) == 0) {
                    SetTextColor(dc, kLogGray);
                } else {
                    SetTextColor(dc, RGB(0, 0, 0));
                }
                DrawTextW(dc, line.c_str(), (int)line.size(), &lr,
                          DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
            }
            ++lineIdx;
            if (pos >= c->diff.size()) break;
        }
        SelectObject(dc, oldMono2);

        wchar_t dh[64] = {};
        _snwprintf_s(dh, _TRUNCATE, L"дифф: %d строк ▸ %d", c->diffLines, c->diffTop + 1);
        RECT dhr{ rc.right - 200, listBottom + 4, rc.right - 8, listBottom + 20 };
        SetTextColor(dc, kLogGray);
        DrawTextW(dc, dh, -1, &dhr, DT_RIGHT | DT_SINGLELINE | DT_NOPREFIX);
    }
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
    c->detail.clear();
    c->diff.clear();
    c->diffTop = 0;
    c->diffLines = 0;
    if (!r.hash.empty()) {
        std::wstring body = RunGit({ L"-C", c->dir, L"show", L"-s",
                                     L"--format=%an <%ae>, %ad%n%B", r.hash });
        c->detail = TrimWs(body);
        if (c->detail.empty()) c->detail = r.author + L", " + r.date;

        // Patch for the diff pane: stat first (one line per file), then the
        // unified diff itself. Colour comes from the line prefix in LogPaint.
        std::wstring patch = RunGit({ L"-C", c->dir, L"show", L"--format=",
                                      L"--stat", L"--patch", L"--no-color", r.hash });
        c->diff = patch;
        for (wchar_t ch : patch)
            if (ch == L'\n') ++c->diffLines;
        if (c->diffLines == 0 && !patch.empty()) c->diffLines = 1;
    }
    InvalidateRect(c->hwnd, nullptr, FALSE);
}

LRESULT CALLBACK LogWndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    LogCtx* c = (LogCtx*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (msg) {
    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lp;
        if (mmi) {
            mmi->ptMinTrackSize.x = 620;
            mmi->ptMinTrackSize.y = 420;
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
            SetRect(&c->rcClose, rc.right - 26, 2, rc.right - 2, 22);
            InvalidateRect(h, nullptr, FALSE);
        }
        return 0;
    case WM_MOUSEWHEEL: {
        if (!c) break;
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        ScreenToClient(h, &pt);
        RECT rc{};
        GetClientRect(h, &rc);
        int listBottom = 24 + (rc.bottom - 24) * 45 / 100;
        int delta = GET_WHEEL_DELTA_WPARAM(wp) / WHEEL_DELTA * 3;
        if (pt.y > listBottom + 22) {
            // cursor over the patch pane — scroll the diff
            int rowsFit = (rc.bottom - 6 - (listBottom + 60)) / kLogRowH;
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
        return 0;
    }
    case WM_LBUTTONDOWN: {
        if (!c) break;
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        if (PtInRect(&c->rcClose, pt)) { DestroyWindow(h); return 0; }
        if (pt.y >= 36) {
            int idx = c->top + (pt.y - 36) / kLogRowH;
            if (idx >= 0 && idx < (int)c->rows.size()) LogSelect(c, idx);
        }
        return 0;
    }
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
    if (!LoadLog(dir, c->rows)) {
        delete c;
        MessageBoxW(owner, L"Не удалось прочитать историю (git log вернул пусто).",
                    L"История Git", MB_ICONINFORMATION);
        return;
    }
    c->mono = LogFont(8, L"Consolas");
    c->ui = LogFont(8, L"Tahoma");

    HWND h = CreateWindowExW(WS_EX_DLGMODALFRAME, L"V8iGitLog",
                             L"История Git — v8inject",
                             WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MAXIMIZEBOX |
                             WS_OVERLAPPED | WS_VISIBLE,
                             CW_USEDEFAULT, CW_USEDEFAULT, 940, 660, owner, nullptr,
                             GetModuleHandleW(nullptr), nullptr);
    if (!h) { delete c; return; }
    SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)c);
    c->hwnd = h;
    RECT rc{};
    GetClientRect(h, &rc);
    SetRect(&c->rcClose, rc.right - 26, 2, rc.right - 2, 22);
    c->visible = (rc.bottom - 60 - 24) / kLogRowH;
    if (c->visible < 1) c->visible = 1;
    SetForegroundWindow(h);
    LogSelect(c, 0);

    MSG msg;
    while (IsWindow(h) && GetMessageW(&msg, nullptr, 0, 0)) {
        if (msg.hwnd == h || IsChild(h, msg.hwnd)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        } else {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    if (IsWindow(h)) DestroyWindow(h);
    if (c->mono) DeleteObject(c->mono);
    if (c->ui) DeleteObject(c->ui);
    delete c;
}

void DoAction(int id) {
    switch (id) {
    case kWinIdDump: {
        ShowTip(L"выгрузка конфигурации в файлы…");
        V8iGitBarDump();
        break;
    }
    case kWinIdInit: RunInit(); break;
    case kWinIdCommit: RunCommit(); break;
    case kWinIdPush: RunPush(); break;
    case kWinIdSettings: ShowSettings(g_bar.hwnd); break;
    case kWinIdLog: ShowGitLog(g_bar.hwnd); break;
    }
}

LRESULT CALLBACK BarWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_PAINT:
        Paint(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;  // WM_PAINT fills everything

    case WM_MOUSEMOVE: {
        POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
        if (g_bar.dragging && (wp & MK_LBUTTON)) {
            HWND frame = GetParent(hwnd);
            if (frame) {
                RECT cr{};
                GetClientRect(frame, &cr);
                int w = cr.right - cr.left;
                int x = pt.x - g_bar.pressPt.x;
                if (x < 0) x = 0;
                if (x > w - kBarW) x = w - kBarW;
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
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

DWORD WINAPI BarThread(LPVOID) {
    HINSTANCE hInst = GetModuleHandleW(nullptr);

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_BAR_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSW wc{};
    wc.lpfnWndProc = BarWndProc;
    wc.hInstance = hInst;
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"V8iGitBar";
    RegisterClassW(&wc);

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
    const wchar_t* texts[kCells] = {
        L"Выгрузить исходники: конфигурация в файлы (команда 45)",
        L"git init в папке выгрузки (+ origin из настроек)",
        L"Коммит изменений (спросит комментарий)",
        L"Пуш в удалённый репозиторий",
        L"Настройки: git.exe, папка выгрузки, комментарий, remote",
        L"История коммитов (git log --graph)",
    };
    for (int i = 0; i < kCells; ++i) {
        TOOLINFOW ti{ sizeof(ti), TTF_SUBCLASS };
        ti.hwnd = g_bar.hwnd;
        ti.uId = (UINT_PTR)(i + 1);
        int x = CellX(i + 1);
        ti.rect = { x, 1, x + kCell, kBarH - 1 };
        ti.lpszText = (LPWSTR)texts[i];
        SendMessageW(g_bar.tooltip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
    }
    {  // status tool: the whole bar, shown programmatically by ShowTip()
        TOOLINFOW ti{ sizeof(ti), TTF_SUBCLASS };
        ti.hwnd = g_bar.hwnd;
        ti.uId = 100;
        ti.rect = { 0, 0, kBarW, kBarH };
        ti.lpszText = (LPWSTR)L"";
        SendMessageW(g_bar.tooltip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
    }

    GetClientRect(frame, &g_bar.lastFrame);
    SetTimer(g_bar.hwnd, 1, 500, nullptr);
    Reposition(true);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    g_bar.hwnd = nullptr;
    g_bar.tooltip = nullptr;
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

}  // namespace v8i
