#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>

#include "v8inject/diag.h"

// Git toolbar ("GitBar") for the running 1C configurator.
//
// The designer's menu bar is a custom-painted control with no Win32 menu, so
// the only reliable way to place git controls inside the configurator window
// is a real Win32 window created INSIDE the 1C process by the payload. This
// version embeds the toolbar AS A CHILD of the configurator frame and docks
// it into the right end of the toolbar row, matching the 1C look: a slim
// flat strip, 16px classic-style icons (diskette / check / push / gear),
// tooltips, draggable along the toolbar row. The result comes as close to a
// native 1C panel as a foreign window can.
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

// Finds the configurator frame (the designer's top-level window). The bar is
// a CHILD of it, so this parent must be the frame and not our own window.
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
// Embedded 1C-style toolbar: child of the frame, docked at the right end of
// the toolbar row, 24px high, 16px classic icons, draggable.
// ---------------------------------------------------------------------------

const int kBarW = 100;      // 4 x 24px buttons + 4px padding
const int kBarH = 24;
const int kBtn = 24;
const int kDockY = 28;      // toolbar row, just under the menu
const int kWinIdDump = 1, kWinIdCommit = 2, kWinIdPush = 3, kWinIdSettings = 4;

struct GitBar {
    HWND hwnd = nullptr;
    HWND tooltip = nullptr;
    bool dragging = false;
    int dragDx = 0;          // x offset from the drag start
    RECT lastFrame{};        // cached frame client rect
    DWORD threadId = 0;
    HANDLE thread = nullptr;
};

GitBar g_bar;

int BtnX(int id) {
    static const int order[] = { kWinIdDump, kWinIdCommit, kWinIdPush, kWinIdSettings };
    for (int i = 0; i < 4; ++i)
        if (order[i] == id) return 2 + i * kBtn;
    return 0;
}

// 1C-classic 16x16 glyphs, drawn with GDI.
void DrawIcon(HDC dc, int id, bool hot) {
    HPEN penDark = CreatePen(PS_SOLID, 1, RGB(70, 80, 90));
    HPEN penThick = CreatePen(PS_SOLID, 2, RGB(70, 80, 90));
    HBRUSH fillGrey = CreateSolidBrush(RGB(225, 226, 230));
    HBRUSH fillBlue = CreateSolidBrush(RGB(0, 96, 160));
    HBRUSH fillGreen = CreateSolidBrush(RGB(0, 140, 60));
    HPEN oldPen = (HPEN)SelectObject(dc, penDark);
    HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
    (void)hot;

    switch (id) {
    case kWinIdDump: {  // diskette = "выгрузить в файлы"
        SelectObject(dc, fillGrey);
        POINT body[] = { {1,2},{10,2},{14,6},{14,14},{1,14} };
        Polygon(dc, body, 5);
        SelectObject(dc, GetStockObject(NULL_BRUSH));
        POINT cut[] = { {10,2},{14,6},{14,14},{1,14},{1,2} };
        Polygon(dc, cut, 5);
        // label (top-left, blue) and shutter square
        SelectObject(dc, fillBlue);
        Rectangle(dc, 2, 3, 9, 9);
        SelectObject(dc, fillGrey);
        Rectangle(dc, 9, 10, 13, 13);
        break;
    }
    case kWinIdCommit: {  // green check
        SelectObject(dc, penThick);
        SelectObject(dc, fillGreen);
        POINT mark[] = { {2,8},{6,12},{14,3} };
        Polyline(dc, mark, 3);
        break;
    }
    case kWinIdPush: {  // up arrow on a base bar
        SelectObject(dc, fillBlue);
        POINT head[] = { {3,7},{8,1},{13,7} };
        Polygon(dc, head, 3);
        SelectObject(dc, penDark);
        MoveToEx(dc, 8, 14, nullptr); LineTo(dc, 8, 8);
        SelectObject(dc, fillBlue);
        Rectangle(dc, 1, 14, 15, 15);
        break;
    }
    case kWinIdSettings: {  // gear: ring + 4 teeth
        SelectObject(dc, fillGrey);
        // teeth drawn with explicit rects below
        SelectObject(dc, penDark);
        static const RECT teeth[] = { {6,0,10,3}, {6,13,10,16}, {0,6,3,10}, {13,6,16,10} };
        for (const RECT& r : teeth) {
            SelectObject(dc, fillGrey);
            Rectangle(dc, r.left, r.top, r.right, r.bottom);
        }
        SelectObject(dc, fillGrey);
        Ellipse(dc, 3, 3, 13, 13);
        SelectObject(dc, GetStockObject(WHITE_BRUSH));
        Ellipse(dc, 6, 6, 10, 10);
        break;
    }
    }

    SelectObject(dc, oldPen);
    SelectObject(dc, oldBrush);
    DeleteObject(penDark);
    DeleteObject(penThick);
    DeleteObject(fillGrey);
    DeleteObject(fillBlue);
    DeleteObject(fillGreen);
}

// Docks the bar at the right end of the toolbar row unless the user dragged
// it somewhere else; re-arms to the dock when the frame changes size.
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

    bool frameChanged = (cr.left != g_bar.lastFrame.left || cr.right != g_bar.lastFrame.right ||
                         cr.bottom != g_bar.lastFrame.bottom);
    g_bar.lastFrame = cr;
    if (forceDock || frameChanged || !g_bar.dragging) {
        if (forceDock || frameChanged) {
            // dock to the right end of the toolbar row
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

LRESULT CALLBACK BarWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case kWinIdDump:
            ShowTip(L"выгрузить: внутренняя точка выгрузки — реверс в работе");
            return 0;
        case kWinIdCommit: RunCommit(); return 0;
        case kWinIdPush:   RunPush(); return 0;
        case kWinIdSettings: ShowSettings(hwnd); return 0;
        }
        return 0;

    case WM_DRAWITEM: {
        auto* di = (DRAWITEMSTRUCT*)lp;
        HDC dc = di->hDC;
        SetBkMode(dc, TRANSPARENT);
        RECT rc = di->rcItem;
        bool hot = (di->itemState & ODS_HOTLIGHT) != 0;
        bool down = (di->itemState & ODS_SELECTED) != 0;

        // 1C-style: flat, gentle highlight box on hover, subtle press.
        HBRUSH bg = CreateSolidBrush(hot ? RGB(255, 250, 220) : RGB(246, 244, 238));
        FillRect(dc, &rc, bg);
        DeleteObject(bg);
        if (hot || down) {
            HPEN pen = CreatePen(PS_SOLID, 1,
                                 down ? RGB(200, 170, 60) : RGB(180, 190, 205));
            SelectObject(dc, pen);
            HBRUSH br = CreateSolidBrush(down ? RGB(238, 232, 200) : RGB(255, 252, 235));
            RECT in = rc;
            InflateRect(&in, -1, -1);
            FillRect(dc, &in, br);
            FrameRect(dc, &rc, br);
            DeleteObject(br);
            SelectObject(dc, GetStockObject(NULL_BRUSH));
            Rectangle(dc, rc.left, rc.top, rc.right, rc.bottom);
            DeleteObject(pen);
        }

        int cx = rc.left + (rc.right - rc.left - 16) / 2;
        int cy = rc.top + (rc.bottom - rc.top - 16) / 2;
        SaveDC(dc);
        SetViewportOrgEx(dc, cx, cy, nullptr);
        DrawIcon(dc, (int)di->itemID, hot);
        RestoreDC(dc, -1);
        return TRUE;
    }

    case WM_LBUTTONDOWN: {
        SetCapture(hwnd);
        g_bar.dragging = true;
        return 0;
    }
    case WM_MOUSEMOVE: {
        if (g_bar.dragging && (wp & MK_LBUTTON)) {
            HWND frame = GetParent(hwnd);
            if (frame) {
                POINT pt{ (short)LOWORD(lp), (short)HIWORD(lp) };
                RECT cr{};
                GetClientRect(frame, &cr);
                int w = cr.right - cr.left;
                int x = pt.x - g_bar.dragDx;
                if (x < 0) x = 0;
                if (x > w - kBarW) x = w - kBarW;
                SetWindowPos(hwnd, HWND_TOP, x, pt.y, 0, 0,
                             SWP_NOSIZE | SWP_NOACTIVATE);
            }
        }
        return 0;
    }
    case WM_LBUTTONUP:
        g_bar.dragging = false;
        ReleaseCapture();
        return 0;

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
    wc.hbrBackground = CreateSolidBrush(RGB(246, 244, 238));
    wc.lpszClassName = L"V8iGitBar";
    RegisterClassW(&wc);

    HWND frame = FindFrame();
    g_bar.hwnd = CreateWindowExW(0, L"V8iGitBar", L"GitBar",
                                 WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
                                 0, kDockY, kBarW, kBarH, frame, nullptr, hInst, nullptr);

    auto Btn = [&](int id) {
        return CreateWindowExW(0, L"BUTTON", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                               BtnX(id), 0, kBtn, kBarH,
                               g_bar.hwnd, (HMENU)(INT_PTR)id, hInst, nullptr);
    };
    Btn(kWinIdDump);
    Btn(kWinIdCommit);
    Btn(kWinIdPush);
    Btn(kWinIdSettings);

    // Tooltips with the action names + a status tool on the bar itself.
    g_bar.tooltip = CreateWindowExW(0, TOOLTIPS_CLASSW, nullptr,
                                    WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                    CW_USEDEFAULT, CW_USEDEFAULT, 0, 0,
                                    g_bar.hwnd, nullptr, hInst, nullptr);
    struct Tip { int id; const wchar_t* text; };
    const Tip tips[] = {
        { kWinIdDump, L"Выгрузить конфигурацию в файлы (реверс в работе)" },
        { kWinIdCommit, L"Коммит изменений" },
        { kWinIdPush, L"Пуш в удалённый репозиторий" },
        { kWinIdSettings, L"Настройки: git.exe и папка выгрузки" },
    };
    for (const Tip& t : tips) {
        TOOLINFOW ti{ sizeof(ti), TTF_IDISHWND | TTF_SUBCLASS };
        ti.hwnd = g_bar.hwnd;
        ti.uId = (UINT_PTR)GetDlgItem(g_bar.hwnd, t.id);
        ti.lpszText = (LPWSTR)t.text;
        SendMessageW(g_bar.tooltip, TTM_ADDTOOLW, 0, (LPARAM)&ti);
    }
    {  // status tool: the whole bar, shown programmatically by ShowTip()
        TOOLINFOW ti{ sizeof(ti), TTF_IDISHWND };
        ti.hwnd = g_bar.hwnd;
        ti.uId = (UINT_PTR)g_bar.hwnd;
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
    // Give the window a moment to appear before reporting.
    for (int i = 0; i < 50 && !g_bar.hwnd; ++i) Sleep(10);
    char buf[128];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "{\"status\":\"ok\",\"visible\":%s,\"thread\":\"0x%llX\"}",
                g_bar.hwnd ? "true" : "false", (unsigned long long)g_bar.threadId);
    return buf;
}

}  // namespace v8i