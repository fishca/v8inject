// v8inject-agent — tray agent that injects the payload into 1C when the user
// starts the configurator, in the spirit of the Snegopat starter.
//
// Behaviour:
//   - sits in the notification area (tray icon, right-click menu)
//   - polls processes every 2 s; when a process matching the configured names
//     (default: 1cv8.exe, 1cv8c.exe, 1cv8s.exe) appears, injects the payload
//     of matching bitness (x64/x86 subfolder next to the agent) and, if
//     enabled, shows the GitBar
//   - settings live in %APPDATA%\v8inject\agent.ini ([agent] section)
//   - optional autostart with Windows via HKCU Run
//
// The agent is a normal EXE of its own process, so standard dialogs and
// controls are fine here (unlike the payload in a foreign process).

#include "v8inject/client.h"
#include "v8inject/procs.h"

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <unordered_set>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")

namespace {

constexpr wchar_t kClassName[] = L"V8iAgentWnd";
constexpr wchar_t kIniPath[] = L"v8inject\\agent.ini";
constexpr UINT_PTR kTimerPoll = 1;
constexpr UINT_PTR kTimerId = 2;

enum MenuId {
    kMInjectAll = 1,
    kMGitbarShow,
    kMState,
    kMAutostart,
    kMSettings,
    kMExit,
};

HWND g_hwnd = nullptr;
HINSTANCE g_hinst = nullptr;
NOTIFYICONDATAW g_nid{};
std::unordered_set<DWORD> g_injected;
std::unordered_set<DWORD> g_failed;
std::wstring g_names;        // comma-separated process names
bool g_autoGitBar = true;

std::wstring AppDataDir() {
    wchar_t buf[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, buf) == S_OK)
        return buf;
    return L"C:";
}

std::wstring IniPath() { return AppDataDir() + L"\\" + kIniPath; }

std::wstring ExeDir() {
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    wchar_t* slash = wcsrchr(buf, L'\\');
    if (slash) *slash = 0;
    return buf;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}

void Log(const std::wstring& line) {
    // Append a line to %APPDATA%\v8inject\agent.log next to the ini.
    std::wstring dir = AppDataDir() + L"\\v8inject";
    CreateDirectoryW(dir.c_str(), nullptr);
    HANDLE h = CreateFileW((dir + L"\\agent.log").c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t head[64] = {};
    _snwprintf_s(head, _TRUNCATE, L"%02u:%02u:%02u ", st.wHour, st.wMinute, st.wSecond);
    std::wstring text = head + line + L"\r\n";
    SetFilePointer(h, 0, nullptr, FILE_END);
    DWORD wr = 0;
    WriteFile(h, text.c_str(), (DWORD)(text.size() * 2), &wr, nullptr);
    CloseHandle(h);
}

void LoadConfig() {
    wchar_t buf[512] = {};
    GetPrivateProfileStringW(L"agent", L"names", L"1cv8.exe,1cv8c.exe,1cv8s.exe",
                             buf, 512, IniPath().c_str());
    g_names = buf;
    g_autoGitBar = GetPrivateProfileIntW(L"agent", L"autogitbar", 1, IniPath().c_str()) != 0;
}

void SaveConfig() {
    WritePrivateProfileStringW(L"agent", L"names", g_names.c_str(), IniPath().c_str());
    WritePrivateProfileStringW(L"agent", L"autogitbar",
                               g_autoGitBar ? L"1" : L"0", IniPath().c_str());
}

bool AutostartEnabled() {
    wchar_t val[512] = {};
    DWORD n = GetPrivateProfileStringW(
        L"agent", L"autostart", L"", val, 512,
        (AppDataDir() + L"\\" + kIniPath).c_str());
    return n > 0 && val[0] == L'1';
}

void SetAutostart(bool on) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return;
    if (on) {
        wchar_t exe[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        RegSetValueExW(key, L"v8inject-agent", 0, REG_SZ,
                       (const BYTE*)exe, (DWORD)(wcslen(exe) + 1) * 2);
    } else {
        RegDeleteValueW(key, L"v8inject-agent");
    }
    RegCloseKey(key);
    WritePrivateProfileStringW(L"agent", L"autostart",
                               on ? L"1" : L"0",
                               (AppDataDir() + L"\\" + kIniPath).c_str());
}

// Payloads live in <agent dir>\x64\... and \x86\... (agent may itself sit in
// one of those folders).
std::wstring PayloadFor(bool is64) {
    std::wstring dir = ExeDir();
    size_t pos = dir.find_last_of(L'\\');
    std::wstring leaf = pos == std::wstring::npos ? dir : dir.substr(pos + 1);
    if (_wcsicmp(leaf.c_str(), L"x64") == 0 || _wcsicmp(leaf.c_str(), L"x86") == 0)
        dir = dir.substr(0, pos);
    return dir + (is64 ? L"\\x64\\v8i_payload.dll" : L"\\x86\\v8i_payload.dll");
}

bool MatchesNames(const std::wstring& name) {
    std::wstring n = name, start = g_names;
    for (auto& c : n) c = (wchar_t)towlower(c);
    for (auto& c : start) c = (wchar_t)towlower(c);
    size_t p = 0;
    while (p <= start.size()) {
        size_t comma = start.find(L',', p);
        std::wstring part = start.substr(p, comma == std::wstring::npos
                                             ? std::wstring::npos : comma - p);
        // trim
        size_t b = part.find_first_not_of(L" \t");
        size_t e = part.find_last_not_of(L" \t");
        if (b != std::wstring::npos) {
            part = part.substr(b, e - b + 1);
            if (part == n) return true;
        }
        if (comma == std::wstring::npos) break;
        p = comma + 1;
    }
    return false;
}

void InjectOne(DWORD pid, bool is64) {
    std::wstring dll = PayloadFor(is64);
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log(L"payload not found: " + dll);
        g_failed.insert(pid);
        return;
    }
    v8i::Client c;
    std::wstring logDir = ExeDir();
    if (!c.Open(pid, dll, logDir, 10000)) {
        Log(L"inject pid=" + std::to_wstring(pid) + L" [" + (is64 ? L"x64" : L"x86") +
            L"] failed: " + c.LastError() + L" (stage " + std::to_wstring(c.LastStage()) +
            L", win32=" + std::to_wstring(c.LastWin32Error()) + L")");
        g_failed.insert(pid);
        return;
    }
    Log(L"injected pid=" + std::to_wstring(pid) + L" [" + (is64 ? L"x64" : L"x86") + L"]");
    g_injected.insert(pid);
    if (g_autoGitBar) {
        std::string resp;
        bool ok = c.Call(L"gitbar", resp, 8000);
        Log(L"gitbar pid=" + std::to_wstring(pid) + (ok ? L" ok" : L" no reply"));
        if (ok && resp.find("visible") == std::string::npos)
            Log(L"gitbar strange reply: " + Utf8ToWide(resp.substr(0, 120)));
    }
    c.Close(3000);
}

// The Client dtor does NOT ask the payload to unload, so the GitBar window
// (and hooks) survive the session close -- exactly like one-shot CLI runs.

void Poll() {
    auto procs = v8i::ListProcesses();
    for (const auto& p : procs) {
        if (p.session0) continue;
        if (!MatchesNames(p.name)) continue;
        if (g_injected.count(p.pid) || g_failed.count(p.pid)) continue;
        InjectOne(p.pid, p.is64);
    }
}

INT_PTR CALLBACK SettingsDlgProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_INITDIALOG:
        SetDlgItemTextW(h, 101, g_names.c_str());
        CheckDlgButton(h, 102, g_autoGitBar ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(h, 103, AutostartEnabled() ? BST_CHECKED : BST_UNCHECKED);
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            wchar_t buf[512] = {};
            GetDlgItemTextW(h, 101, buf, 512);
            g_names = buf;
            g_autoGitBar = IsDlgButtonChecked(h, 102) == BST_CHECKED;
            bool as = IsDlgButtonChecked(h, 103) == BST_CHECKED;
            SetAutostart(as);
            SaveConfig();
            EndDialog(h, IDOK);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(h, IDCANCEL); return TRUE; }
        break;
    }
    return FALSE;
}

void ShowTrayMenu() {
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, kMInjectAll, L"Внедрить в запущенные 1С");
    AppendMenuW(m, MF_STRING, kMGitbarShow, L"GitBar: показать");
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING | (AutostartEnabled() ? MF_CHECKED : 0), kMAutostart,
                L"Автозапуск с Windows");
    AppendMenuW(m, MF_STRING, kMSettings, L"Настройки…");
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, kMExit, L"Выход");
    POINT pt{};
    GetCursorPos(&pt);
    SetForegroundWindow(g_hwnd);
    int cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, g_hwnd, nullptr);
    DestroyMenu(m);
    switch (cmd) {
    case kMExit:
        PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
        break;
    case kMInjectAll: {
        auto procs = v8i::ListProcesses();
        int done = 0;
        for (const auto& p : procs) {
            if (p.session0 || !MatchesNames(p.name)) continue;
            if (g_injected.count(p.pid) || g_failed.count(p.pid)) continue;
            InjectOne(p.pid, p.is64);
            ++done;
        }
        if (done == 0) Log(L"manual inject: nothing new");
        break;
    }
    case kMGitbarShow: {
        auto procs = v8i::ListProcesses();
        for (const auto& p : procs) {
            if (p.session0 || !MatchesNames(p.name)) continue;
            // A fresh CLI-style session just to send the command; the window
            // survives, the handle is released.
            v8i::Client c;
            if (c.Open(p.pid, PayloadFor(p.is64), ExeDir(), 8000)) {
                std::string r;
                c.Call(L"gitbar", r, 8000);
                c.Close(3000);
            }
        }
        break;
    }
    case kMAutostart:
        SetAutostart(!AutostartEnabled());
        break;
    case kMSettings:
        DialogBoxW(g_hinst, MAKEINTRESOURCEW(200), g_hwnd, SettingsDlgProc);
        break;
    }
}

LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        SetTimer(h, kTimerId, 2000, nullptr);
        return 0;
    case WM_TIMER:
        if (wp == kTimerId) Poll();
        return 0;
    case WM_APP + 1:                       // tray callback
        if (LOWORD(lp) == WM_RBUTTONUP || LOWORD(lp) == WM_LBUTTONUP)
            ShowTrayMenu();
        return 0;
    case WM_CLOSE:
        KillTimer(h, kTimerId);
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

// A simple 16x16 icon so the tray has a face: cream bar with an up arrow.
HICON MakeTrayIcon() {
    constexpr int S = 16;
    uint32_t px[S * S];
    auto put = [&](int x, int y, uint8_t r, uint8_t g, uint8_t b) {
        if (x < 0 || y < 0 || x >= S || y >= S) return;
        px[y * S + x] = 0xFF000000u | (b << 16) | (g << 8) | r;
    };
    for (int y = 0; y < S; ++y)
        for (int x = 0; x < S; ++x) {
            px[y * S + x] = 0xFF000000u | (0xDE << 16) | (0xEA << 8) | 0xEE;  // bgr
        }
    for (int i = 0; i < S; ++i) {  // border
        put(i, 0, 176, 166, 142); put(i, S - 1, 176, 166, 142);
        put(0, i, 176, 166, 142); put(S - 1, i, 176, 166, 142);
    }
    // up arrow
    for (int dy = 1; dy <= 9; ++dy) {
        int x = 8 - (dy - 1) / 2;
        int len = 1 + (dy - 1) / 2 * 2;
        for (int k = 0; k < len; ++k) put(x + k, 14 - dy, 60, 110, 200);
    }
    // base
    for (int x = 3; x <= 12; ++x) put(x, 14, 60, 110, 200);
    put(8, 13, 255, 255, 255);
    BITMAPV5HEADER bmi{};
    bmi.bV5Size = sizeof(bmi);
    bmi.bV5Width = S; bmi.bV5Height = -S;
    bmi.bV5Planes = 1; bmi.bV5BitCount = 32;
    bmi.bV5Compression = BI_RGB;
    void* bits = nullptr;
    HDC dc = GetDC(nullptr);
    HBITMAP bmp = CreateDIBSection(dc, (BITMAPINFO*)&bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (bmp && bits) memcpy(bits, px, sizeof(px));
    HICON icon = nullptr;
    if (bmp) {
        ICONINFO ii{};
        ii.fIcon = TRUE;
        ii.hbmColor = bmp;
        ii.hbmMask = CreateBitmap(S, S, 1, 1, nullptr);
        icon = CreateIconIndirect(&ii);
        if (ii.hbmMask) DeleteObject(ii.hbmMask);
        DeleteObject(bmp);
    }
    ReleaseDC(nullptr, dc);
    return icon;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int) {
    g_hinst = hInst;
    CreateMutexW(nullptr, TRUE, L"V8iAgentMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    LoadConfig();

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = kClassName;
    RegisterClassW(&wc);
    g_hwnd = CreateWindowExW(0, kClassName, L"v8inject-agent", WS_OVERLAPPED,
                             CW_USEDEFAULT, CW_USEDEFAULT, 1, 1, nullptr, nullptr,
                             hInst, nullptr);
    if (!g_hwnd) return 1;

    g_nid = {};
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_APP + 1;
    g_nid.hIcon = MakeTrayIcon();
    wcscpy_s(g_nid.szTip, L"v8inject — автовнедрение в 1С");
    Shell_NotifyIconW(NIM_ADD, &g_nid);

    Log(L"agent started: " + ExeDir());
    Poll();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
    return 0;
}