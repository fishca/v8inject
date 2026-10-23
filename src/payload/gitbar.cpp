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
// strip draws its four 16px glyphs itself and hit-tests clicks.
//
//   gitbar            -- show the toolbar (creates the window + thread)
//   gitbar hide       -- destroy it
// Config: %APPDATA%\v8inject\gitbar.ini
//   [git] gitpath=<full path to git.exe>
//        dumpdir=<folder the user dumps the config into>

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

// Runs "<gitpath> <args>" and returns stdout + stderr. Only ever runs from
// the toolbar's own thread.
std::wstring RunGit(const std::vector<std::wstring>& args) {
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
    DWORD rd = 0;
    while (ReadFile(outRd, buf, sizeof(buf), &rd, nullptr) && rd > 0) {
        out.append(buf, rd);
    }
    WaitForSingleObject(pi.hProcess, 60000);
    CloseHandle(pi.hProcess);
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

const int kBarW = 100;
const int kBarH = 24;
const int kCell = 24;       // per-button cell width
const int kDockY = 28;      // toolbar row, just under the menu
const int kWinIdDump = 1, kWinIdCommit = 2, kWinIdPush = 3, kWinIdSettings = 4;

struct GitBar {
    HWND hwnd = nullptr;
    HWND tooltip = nullptr;
    int hover = 0;          // cell index under the cursor (1..4), 0 = none
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
    for (int id = 1; id <= 4; ++id) {
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
    case kWinIdCommit: {  // green check
        SelectObject(dc, thick);
        SelectObject(dc, green);
        POINT mark[] = { {ox+2,oy+8},{ox+6,oy+12},{ox+14,oy+3} };
        Polyline(dc, mark, 3);
        break;
    }
    case kWinIdPush: {  // blue up arrow over a base bar
        SelectObject(dc, blue);
        POINT head[] = { {ox+3,oy+8},{ox+8,oy+2},{ox+13,oy+8} };
        Polygon(dc, head, 3);
        SelectObject(dc, thick);
        MoveToEx(dc, ox + 8, oy + 14, nullptr); LineTo(dc, ox + 8, oy + 8);
        SelectObject(dc, blue);
        Rectangle(dc, ox + 2, oy + 14, ox + 14, oy + 15);
        break;
    }
    case kWinIdSettings: {  // gear: ring + teeth
        SelectObject(dc, blue);
        static const RECT teeth[] = { {6,1,10,4}, {6,12,10,15}, {1,6,4,10}, {12,6,15,10} };
        for (const RECT& r : teeth) {
            Rectangle(dc, ox + r.left, oy + r.top, ox + r.right, oy + r.bottom);
        }
        Ellipse(dc, ox + 3, oy + 3, ox + 13, oy + 13);
        SelectObject(dc, GetStockObject(WHITE_BRUSH));
        Ellipse(dc, ox + 6, oy + 6, ox + 10, oy + 10);
        break;
    }
    }

    SelectObject(dc, oldPen);
    SelectObject(dc, oldBrush);
    DeleteObject(blue);
    DeleteObject(green);
    DeleteObject(dark);
    DeleteObject(thick);
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

    for (int id = 1; id <= 4; ++id) {
        int x = CellX(id);
        RECT cell{ x, 1, x + kCell, kBarH - 1 };
        if (id == g_bar.hover || (g_bar.pressed && id == g_bar.hover)) {
            HBRUSH hl = CreateSolidBrush(id == g_bar.hover && g_bar.pressed
                                             ? RGB(226, 216, 178)
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
    LogLine("gitbar: %ls", text.c_str());
}

void RunCommit() {
    std::wstring dir = IniGet(L"dumpdir");
    if (dir.empty()) { ShowTip(L"нет папки выгрузки (Настройки)"); return; }
    ShowTip(L"git add/commit...");
    std::wstring msg = L"chore: 1c dump " + NowStamp();
    RunGit({ L"-C", dir, L"add", L"-A" });
    std::wstring out = RunGit({ L"-C", dir, L"commit", L"-m", msg });
    ShowTip(out.size() > 160 ? out.substr(0, 160) : out);
}

void RunPush() {
    std::wstring dir = IniGet(L"dumpdir");
    if (dir.empty()) { ShowTip(L"нет папки выгрузки (Настройки)"); return; }
    ShowTip(L"git push...");
    std::wstring out = RunGit({ L"-C", dir, L"push" });
    ShowTip(out.size() > 160 ? out.substr(0, 160) : out);
}

// Modal settings dialog: two edit fields (git.exe path, dump dir).
void ShowSettings(HWND owner) {
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"#32770", L"GitBar — настройки",
                               WS_CAPTION | WS_SYSMENU | WS_OVERLAPPED,
                               CW_USEDEFAULT, CW_USEDEFAULT, 430, 150, owner, nullptr,
                               GetModuleHandleW(nullptr), nullptr);
    if (!dlg) return;

    auto Lbl = [&](int y, const wchar_t* t) {
        CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT,
                        12, y, 130, 18, dlg, nullptr, GetModuleHandleW(nullptr), nullptr);
    };
    auto Edt = [&](int y) {
        return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                               150, y, 260, 22, dlg, nullptr, GetModuleHandleW(nullptr), nullptr);
    };

    HWND ed1 = Edt(14);
    HWND ed2 = Edt(44);
    Lbl(15, L"git.exe");
    Lbl(45, L"папка выгрузки");
    CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                    150, 84, 80, 26, dlg, (HMENU)(INT_PTR)IDOK, GetModuleHandleW(nullptr), nullptr);
    CreateWindowExW(0, L"BUTTON", L"Отмена", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    250, 84, 90, 26, dlg, (HMENU)(INT_PTR)IDCANCEL, GetModuleHandleW(nullptr), nullptr);

    SetWindowTextW(ed1, GitExe().c_str());
    SetWindowTextW(ed2, IniGet(L"dumpdir").c_str());

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (msg.hwnd == dlg) {
            if (msg.message == WM_COMMAND && LOWORD(msg.wParam) == IDOK) {
                wchar_t b1[1024] = {}, b2[1024] = {};
                GetWindowTextW(ed1, b1, 1024);
                GetWindowTextW(ed2, b2, 1024);
                if (b1[0]) IniSet(L"gitpath", b1);
                if (b2[0]) IniSet(L"dumpdir", b2);
                DestroyWindow(dlg);
                continue;
            }
            if (msg.message == WM_COMMAND && LOWORD(msg.wParam) == IDCANCEL) {
                DestroyWindow(dlg);
                continue;
            }
            if (msg.message == WM_CLOSE) { DestroyWindow(dlg); continue; }
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    Reposition(true);
}

void DoAction(int id) {
    switch (id) {
    case kWinIdDump: {
        ShowTip(L"выгрузка конфигурации в файлы…");
        V8iGitBarDump();
        break;
    }
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
    const wchar_t* texts[] = {
        L"Выгрузить конфигурацию в файлы (1С сделает выгрузку сама)",
        L"Коммит изменений",
        L"Пуш в удалённый репозиторий",
        L"Настройки: git.exe и папка выгрузки",
    };
    for (int i = 0; i < 4; ++i) {
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