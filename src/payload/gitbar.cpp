#include <windows.h>
#include <string>
#include <vector>

// Git toolbar ("GitBar") for the running 1C configurator.
//
// The designer's menu bar is a custom-painted control with no Win32 menu, so
// the only reliable way to place git controls on the user's screen next to
// the configurator is a real Win32 window created INSIDE the 1C process by
// the payload. It floats (topmost, tool window) over the configurator frame
// and follows it. Buttons run git.exe directly; "Выгрузить" (dump to files)
// is a stub until the configurator's internal dump entry point is located by
// reverse engineering (the function is NOT exported and a batch designer
// cannot dump while the interactive configurator holds the infobase
// exclusively).
//
//   gitbar            -- show the toolbar (creates the window + thread)
//   gitbar hide       -- destroy it
// Config: %APPDATA%\v8inject\gitbar.ini
//   [git] gitpath=<full path to git.exe>
//        dumpdir=<folder the user dumps the config into>

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

// Runs "<gitpath> <args>" and returns the first `limit` characters of stdout +
// stderr. Non-blocking for the caller's sake: this only ever runs from the
// toolbar's own thread.
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

// Finds the configurator frame (the designer's top-level window) to follow
// it. Must skip our own toolbar window: it is also a titled top-level window
// of this process, and following itself would pin the bar to its own corner.
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

const int kBtnW = 74, kBtnH = 26;
const int kBarW = 430, kBarH = 66;
const int kWinIdDump = 1, kWinIdCommit = 2, kWinIdPush = 3, kWinIdSettings = 4;

struct GitBar {
    HWND hwnd = nullptr;
    HWND status = nullptr;
    DWORD threadId = 0;
    HANDLE thread = nullptr;
};

GitBar g_bar;

void Reposition() {
    HWND frame = FindFrame();
    if (!frame) return;
    RECT fr{};
    GetWindowRect(frame, &fr);
    int x = fr.left + (fr.right - fr.left) - kBarW - 12;
    int y = fr.top + 8;
    SetWindowPos(g_bar.hwnd, HWND_TOPMOST, x, y, kBarW, kBarH,
                 SWP_SHOWWINDOW | SWP_NOACTIVATE);
}

void SetStatus(const std::wstring& s) {
    if (g_bar.status) SetWindowTextW(g_bar.status, s.c_str());
}

void RunCommit() {
    std::wstring dir = IniGet(L"dumpdir");
    if (dir.empty()) { SetStatus(L"нет папки выгрузки (Настройки)"); return; }
    SetStatus(L"git add/commit...");
    std::wstring msg = L"chore: 1c dump " + NowStamp();
    RunGit({ L"-C", dir, L"add", L"-A" });
    std::wstring out = RunGit({ L"-C", dir, L"commit", L"-m", msg });
    SetStatus(out.size() > 120 ? out.substr(0, 120) : out);
}

void RunPush() {
    std::wstring dir = IniGet(L"dumpdir");
    if (dir.empty()) { SetStatus(L"нет папки выгрузки (Настройки)"); return; }
    SetStatus(L"git push...");
    std::wstring out = RunGit({ L"-C", dir, L"push" });
    SetStatus(out.size() > 120 ? out.substr(0, 120) : out);
}

// Modal settings dialog: two edit fields (git.exe path, dump dir).
void ShowSettings(HWND owner) {
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"#32770", L"GitBar — настройки",
                               WS_CAPTION | WS_SYSMENU | WS_OVERLAPPED,
                               CW_USEDEFAULT, CW_USEDEFAULT, 420, 150, owner, nullptr,
                               GetModuleHandleW(nullptr), nullptr);
    if (!dlg) return;
    HDC dc = GetDC(dlg);
    int dpi = dc ? GetDeviceCaps(dc, LOGPIXELSY) : 96;
    if (dc) ReleaseDC(dlg, dc);
    int s = dpi > 96 ? 2 : 1;  // rough scale for high-dpi

    auto Lbl = [&](int y, const wchar_t* t) {
        CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT,
                        12, y, 120, 18, dlg, nullptr, GetModuleHandleW(nullptr), nullptr);
    };
    auto Edt = [&](int y) {
        return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                               140, y, 260, 20, dlg, nullptr, GetModuleHandleW(nullptr), nullptr);
    };

    HWND ed1 = Edt(12 * s);
    HWND ed2 = Edt(40 * s);
    Lbl(13 * s, L"git.exe");
    Lbl(41 * s, L"папка выгрузки");
    CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                    140, 74 * s, 80, 24, dlg, (HMENU)(INT_PTR)IDOK, GetModuleHandleW(nullptr), nullptr);
    CreateWindowExW(0, L"BUTTON", L"Отмена", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    240, 74 * s, 90, 24, dlg, (HMENU)(INT_PTR)IDCANCEL, GetModuleHandleW(nullptr), nullptr);

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
    Reposition();
}

LRESULT CALLBACK BarWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case kWinIdDump:
            SetStatus(L"выгрузить: ищем внутреннюю точку выгрузки (реверс в работе)");
            return 0;
        case kWinIdCommit: RunCommit(); return 0;
        case kWinIdPush:   RunPush(); return 0;
        case kWinIdSettings: ShowSettings(hwnd); return 0;
        }
        return 0;
    case WM_TIMER:
        if (wp == 1) Reposition();
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

DWORD WINAPI BarThread(LPVOID) {
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = BarWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"V8iGitBar";
    RegisterClassW(&wc);

    DWORD ex = WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE;
    g_bar.hwnd = CreateWindowExW(ex, L"V8iGitBar", L"GitBar",
                                 WS_POPUP | WS_BORDER | WS_VISIBLE,
                                 0, 0, kBarW, kBarH, nullptr, nullptr, hInst, nullptr);

    HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    auto Btn = [&](int id, const wchar_t* text, int x) {
        HWND b = CreateWindowExW(0, L"BUTTON", text,
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                 x, 6, kBtnW, kBtnH, g_bar.hwnd, (HMENU)(INT_PTR)id,
                                 hInst, nullptr);
        SendMessageW(b, WM_SETFONT, (WPARAM)font, TRUE);
        return b;
    };
    Btn(kWinIdDump, L"Выгрузить", 4);
    Btn(kWinIdCommit, L"Коммит", 82);
    Btn(kWinIdPush, L"Пуш", 160);
    Btn(kWinIdSettings, L"Настройки", 238);

    g_bar.status = CreateWindowExW(0, L"STATIC", L"",
                                   WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS,
                                   4, 38, kBarW - 8, 22, g_bar.hwnd, nullptr, hInst, nullptr);
    SendMessageW(g_bar.status, WM_SETFONT, (WPARAM)font, TRUE);

    SetTimer(g_bar.hwnd, 1, 500, nullptr);
    Reposition();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    g_bar.hwnd = nullptr;
    g_bar.status = nullptr;
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