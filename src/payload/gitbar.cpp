#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>

#include "v8inject/diag.h"

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
const int kCells = 5;
const int kBarW = 2 + kCells * kCell + 2;
const int kBarH = 24;
const int kDockY = 28;      // toolbar row, just under the menu
const int kWinIdDump = 1, kWinIdInit = 2, kWinIdCommit = 3,
          kWinIdPush = 4, kWinIdSettings = 5;

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

int CellX(int id) { return 2 + (id - 1) * kCell; }

int IdFromPoint(POINT pt) {
    if (pt.y < 0 || pt.y >= kBarH) return 0;
    for (int id = 1; id <= kCells; ++id) {
        int x = CellX(id);
        if (pt.x >= x && pt.x < x + kCell) return id;
    }
    return 0;
}

// 16x16 glyphs, drawn with visible 1-2px strokes.
void DrawGlyph(HDC dc, int id, int ox, int oy) {
    HBRUSH blue = CreateSolidBrush(RGB(0, 96, 160));
    HBRUSH green = CreateSolidBrush(RGB(0, 140, 60));
    HPEN dark = CreatePen(PS_SOLID, 1, RGB(40, 50, 60));
    HPEN thick = CreatePen(PS_SOLID, 2, RGB(40, 50, 60));
    HPEN bluePen = CreatePen(PS_SOLID, 2, RGB(0, 96, 160));
    HPEN greenPen = CreatePen(PS_SOLID, 2, RGB(0, 140, 60));
    HPEN oldPen = (HPEN)SelectObject(dc, dark);
    HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));

    switch (id) {
    case kWinIdDump: {  // diskette: "выгрузить в файлы"
        SelectObject(dc, blue);
        POINT body[] = { {ox+2,oy+2},{ox+10,oy+2},{ox+14,oy+6},{ox+14,oy+14},{ox+2,oy+14} };
        Polygon(dc, body, 5);
        SelectObject(dc, GetStockObject(WHITE_BRUSH));
        Rectangle(dc, ox + 4, oy + 3, ox + 10, oy + 8);   // label
        Rectangle(dc, ox + 9, oy + 10, ox + 13, oy + 14); // shutter
        break;
    }
    case kWinIdInit: {  // plus in a ring: create a repository
        SelectObject(dc, thick);
        Ellipse(dc, ox + 1, oy + 1, ox + 15, oy + 15);
        SelectObject(dc, greenPen);
        MoveToEx(dc, ox + 8, oy + 4, nullptr); LineTo(dc, ox + 8, oy + 12);
        MoveToEx(dc, ox + 4, oy + 8, nullptr); LineTo(dc, ox + 12, oy + 8);
        break;
    }
    case kWinIdCommit: {  // green check
        SelectObject(dc, greenPen);
        POINT mark[] = { {ox+2,oy+8},{ox+6,oy+12},{ox+14,oy+3} };
        Polyline(dc, mark, 3);
        break;
    }
    case kWinIdPush: {  // blue up arrow over a base bar
        SelectObject(dc, blue);
        POINT head[] = { {ox+3,oy+8},{ox+8,oy+2},{ox+13,oy+8} };
        Polygon(dc, head, 3);
        SelectObject(dc, bluePen);
        MoveToEx(dc, ox + 8, oy + 14, nullptr); LineTo(dc, ox + 8, oy + 8);
        SelectObject(dc, blue);
        Rectangle(dc, ox + 2, oy + 14, ox + 14, oy + 15);
        break;
    }
    case kWinIdSettings: {  // sliders: settings reads clearer than a 16px gear
        SelectObject(dc, thick);
        MoveToEx(dc, ox + 1, oy + 3, nullptr); LineTo(dc, ox + 15, oy + 3);
        MoveToEx(dc, ox + 1, oy + 8, nullptr); LineTo(dc, ox + 15, oy + 8);
        MoveToEx(dc, ox + 1, oy + 13, nullptr); LineTo(dc, ox + 15, oy + 13);
        SelectObject(dc, blue);
        Rectangle(dc, ox + 3, oy + 1, ox + 7, oy + 5);    // knob, row 1
        Rectangle(dc, ox + 9, oy + 6, ox + 13, oy + 10);  // knob, row 2
        Rectangle(dc, ox + 5, oy + 11, ox + 9, oy + 15);  // knob, row 3
        break;
    }
    }

    SelectObject(dc, oldPen);
    SelectObject(dc, oldBrush);
    DeleteObject(blue);
    DeleteObject(green);
    DeleteObject(dark);
    DeleteObject(thick);
    DeleteObject(bluePen);
    DeleteObject(greenPen);
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
        DrawGlyph(dc, id, x + (kCell - 16) / 2, (kBarH - 16) / 2);
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
    SetWindowPos(g_bar.hwnd, HWND_TOP, tl.x, tl.y, 0, 0,
                 SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
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
bool PromptText(HWND owner, const wchar_t* title, const wchar_t* label,
                const std::wstring& initial, std::wstring* out) {
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"#32770", title,
                               WS_CAPTION | WS_SYSMENU | WS_OVERLAPPED | WS_VISIBLE,
                               CW_USEDEFAULT, CW_USEDEFAULT, 470, 160, owner, nullptr,
                               GetModuleHandleW(nullptr), nullptr);
    if (!dlg) return false;

    CreateWindowExW(0, L"STATIC", label, WS_CHILD | WS_VISIBLE | SS_LEFT,
                    12, 12, 430, 18, dlg, nullptr, GetModuleHandleW(nullptr), nullptr);
    HWND ed = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                              WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                              12, 34, 430, 24, dlg, (HMENU)1001,
                              GetModuleHandleW(nullptr), nullptr);
    SetWindowTextW(ed, initial.c_str());
    SendMessageW(ed, EM_SETSEL, 0, -1);
    CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                    252, 72, 90, 26, dlg, (HMENU)(INT_PTR)IDOK, GetModuleHandleW(nullptr), nullptr);
    CreateWindowExW(0, L"BUTTON", L"Отмена", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    352, 72, 90, 26, dlg, (HMENU)(INT_PTR)IDCANCEL,
                    GetModuleHandleW(nullptr), nullptr);

    SetForegroundWindow(dlg);
    SetFocus(ed);

    bool accepted = false;
    MSG msg;
    for (;;) {
        if (!GetMessageW(&msg, nullptr, 0, 0)) break;   // WM_QUIT: the bar is going away
        if (!IsWindow(dlg)) break;                      // dialog already destroyed
        bool ours = (msg.hwnd == dlg) || IsChild(dlg, msg.hwnd);
        if (ours) {
            if ((msg.message == WM_COMMAND && LOWORD(msg.wParam) == IDOK) ||
                (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN)) {
                wchar_t b[1024] = {};
                GetWindowTextW(ed, b, 1024);
                *out = b;
                accepted = true;
                DestroyWindow(dlg);
                break;
            }
            if ((msg.message == WM_COMMAND && LOWORD(msg.wParam) == IDCANCEL) ||
                msg.message == WM_CLOSE) {
                DestroyWindow(dlg);
                break;
            }
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (IsWindow(dlg)) DestroyWindow(dlg);
    Reposition(true);
    return accepted;
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

// Modal settings dialog: git.exe, dump dir, default commit message, remote.
void ShowSettings(HWND owner) {
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"#32770", L"GitBar — настройки",
                               WS_CAPTION | WS_SYSMENU | WS_OVERLAPPED | WS_VISIBLE,
                               CW_USEDEFAULT, CW_USEDEFAULT, 460, 226, owner, nullptr,
                               GetModuleHandleW(nullptr), nullptr);
    if (!dlg) return;

    auto Lbl = [&](int y, const wchar_t* t) {
        CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT,
                        12, y, 140, 18, dlg, nullptr, GetModuleHandleW(nullptr), nullptr);
    };
    auto Edt = [&](int y) {
        return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                               158, y, 284, 22, dlg, nullptr, GetModuleHandleW(nullptr), nullptr);
    };

    HWND ed1 = Edt(14);
    HWND ed2 = Edt(44);
    HWND ed3 = Edt(74);
    HWND ed4 = Edt(104);
    Lbl(15, L"git.exe");
    Lbl(45, L"папка выгрузки");
    Lbl(75, L"комментарий к коммиту");
    Lbl(105, L"remote origin (не обяз.)");
    CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                    158, 150, 90, 26, dlg, (HMENU)(INT_PTR)IDOK, GetModuleHandleW(nullptr), nullptr);
    CreateWindowExW(0, L"BUTTON", L"Отмена", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    258, 150, 90, 26, dlg, (HMENU)(INT_PTR)IDCANCEL,
                    GetModuleHandleW(nullptr), nullptr);

    std::wstring git = GitExe();
    if (git == L"git.exe" && GetFileAttributesW(L"C:\\Program Files\\Git\\cmd\\git.exe")
                                 != INVALID_FILE_ATTRIBUTES) {
        git = L"C:\\Program Files\\Git\\cmd\\git.exe";
    }
    SetWindowTextW(ed1, git.c_str());
    SetWindowTextW(ed2, IniGet(L"dumpdir").c_str());
    SetWindowTextW(ed3, IniGet(L"commitmsg").c_str());
    SetWindowTextW(ed4, IniGet(L"remote").c_str());

    SetForegroundWindow(dlg);
    SetFocus(ed1);

    MSG msg;
    for (;;) {
        if (!GetMessageW(&msg, nullptr, 0, 0)) break;   // WM_QUIT
        if (!IsWindow(dlg)) break;
        bool ours = (msg.hwnd == dlg) || IsChild(dlg, msg.hwnd);
        if (ours) {
            if (msg.message == WM_COMMAND && LOWORD(msg.wParam) == IDOK) {
                wchar_t b1[1024] = {}, b2[1024] = {}, b3[1024] = {}, b4[1024] = {};
                GetWindowTextW(ed1, b1, 1024);
                GetWindowTextW(ed2, b2, 1024);
                GetWindowTextW(ed3, b3, 1024);
                GetWindowTextW(ed4, b4, 1024);
                if (b1[0]) IniSet(L"gitpath", b1);
                if (b2[0]) IniSet(L"dumpdir", b2);
                IniSet(L"commitmsg", b3);   // empty = auto "chore: 1c dump <stamp>"
                IniSet(L"remote", b4);
                DestroyWindow(dlg);
                break;
            }
            if ((msg.message == WM_COMMAND && LOWORD(msg.wParam) == IDCANCEL) ||
                msg.message == WM_CLOSE) {
                DestroyWindow(dlg);
                break;
            }
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (IsWindow(dlg)) DestroyWindow(dlg);
    Reposition(true);
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
    g_bar.hwnd = CreateWindowExW(0, L"V8iGitBar", L"GitBar",
                                 WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                 0, kDockY, kBarW, kBarH, frame, nullptr, hInst, nullptr);

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
