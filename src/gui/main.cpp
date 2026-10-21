// v8inject GUI: pick a process, inject the payload, run commands.
//
// Plain Win32 + common controls. No frameworks: the whole point of this tool is
// to load into other people's processes, so it stays small and dependency-free.

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellscalingapi.h>

#include "v8inject/client.h"
#include "v8inject/diag.h"
#include "v8inject/injector.h"
#include "v8inject/procs.h"

#include <string>
#include <vector>

namespace {

constexpr int kIdList    = 1001;
constexpr int kIdRefresh = 1002;
constexpr int kIdDllEdit = 1003;
constexpr int kIdBrowse  = 1004;
constexpr int kIdInject  = 1005;
constexpr int kIdDetach  = 1006;
constexpr int kIdCommand = 1007;
constexpr int kIdSend    = 1008;
constexpr int kIdLog     = 1009;
constexpr int kIdStatus  = 1010;
constexpr int kIdFilter  = 1011;

HWND g_hwnd = nullptr;
HWND g_list = nullptr;
HWND g_dllEdit = nullptr;
HWND g_cmdEdit = nullptr;
HWND g_log = nullptr;
HWND g_status = nullptr;
HWND g_filter = nullptr;

std::vector<v8i::ProcessEntry> g_procs;
v8i::Client g_client;
uint32_t g_targetPid = 0;
std::wstring g_targetName;

std::wstring ExeDir() {
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    wchar_t* slash = wcsrchr(self, L'\\');
    if (slash) *slash = 0;
    return self;
}

bool HasParent(const std::wstring& path, const wchar_t* parent) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return false;
    std::wstring leaf = path.substr(pos + 1);
    return _wcsicmp(leaf.c_str(), parent) == 0;
}

std::wstring DefaultPayloadFor(bool targetIs64) {
    // Payloads are laid out as <root>\x64\... and <root>\x86\..., with the GUI
    // and CLI either in the root or inside one of those folders.
    std::wstring dir = ExeDir();
    size_t pos = dir.find_last_of(L'\\');
    std::wstring leaf = pos == std::wstring::npos ? dir : dir.substr(pos + 1);
    if (_wcsicmp(leaf.c_str(), L"x64") == 0 || _wcsicmp(leaf.c_str(), L"x86") == 0) {
        dir = dir.substr(0, pos);
    }
    return dir + (targetIs64 ? L"\\x64\\v8i_payload.dll" : L"\\x86\\v8i_payload.dll");
}

// Payload replies are UTF-8; the window is wide. Converting byte-by-byte
// (wstring(begin, end)) produces mojibake for every non-ASCII name.
std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}

void Log(const std::wstring& line) {
    std::wstring text = line + L"\r\n";
    int len = GetWindowTextLengthW(g_log);
    SendMessageW(g_log, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_log, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
}

void SetStatus(const std::wstring& text) {
    SetWindowTextW(g_status, text.c_str());
}

bool MatchesFilter(const v8i::ProcessEntry& e, const std::wstring& filter) {
    if (filter.empty()) return true;
    std::wstring name = e.name;
    std::wstring f = filter;
    for (auto& c : name) c = (wchar_t)towlower(c);
    for (auto& c : f) c = (wchar_t)towlower(c);
    return name.find(f) != std::wstring::npos;
}

void FillList() {
    std::wstring filter;
    wchar_t fbuf[128] = {};
    GetWindowTextW(g_filter, fbuf, 128);
    filter = fbuf;

    SendMessageW(g_list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_list);

    int row = 0;
    for (const auto& p : g_procs) {
        if (!MatchesFilter(p, filter)) continue;
        wchar_t pidBuf[16];
        _snwprintf_s(pidBuf, _countof(pidBuf), _TRUNCATE, L"%lu", p.pid);

        LVITEMW it{};
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = row;
        it.iSubItem = 0;
        it.pszText = pidBuf;
        it.lParam = (LPARAM)p.pid;
        int idx = ListView_InsertItem(g_list, &it);

        ListView_SetItemText(g_list, idx, 1, (LPWSTR)p.name.c_str());
        ListView_SetItemText(g_list, idx, 2, (LPWSTR)(p.is64 ? L"x64" : L"x86"));
        ListView_SetItemText(g_list, idx, 3, (LPWSTR)p.path.c_str());
        ++row;
    }
    SendMessageW(g_list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_list, nullptr, TRUE);

    wchar_t status[128];
    _snwprintf_s(status, _countof(status), _TRUNCATE, L"Процессов: %d (показано %d)",
                 (int)g_procs.size(), row);
    SetStatus(status);
}

void RefreshProcesses() {
    g_procs = v8i::ListProcesses();
    FillList();
}

uint32_t SelectedPid() {
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    if (sel < 0) return 0;
    LVITEMW it{};
    it.mask = LVIF_PARAM;
    it.iItem = sel;
    if (!ListView_GetItem(g_list, &it)) return 0;
    return (uint32_t)it.lParam;
}

std::wstring SelectedName() {
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    if (sel < 0) return std::wstring();
    wchar_t buf[256] = {};
    ListView_GetItemText(g_list, sel, 1, buf, 256);
    return buf;
}

bool SelectedIs64() {
    uint32_t pid = SelectedPid();
    for (const auto& p : g_procs)
        if (p.pid == pid) return p.is64;
    return false;
}

void BrowseDll() {
    wchar_t file[MAX_PATH] = {};
    GetWindowTextW(g_dllEdit, file, MAX_PATH);
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"Payload DLL\0*.dll\0All files\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn)) SetWindowTextW(g_dllEdit, file);
}

void DoInject() {
    uint32_t pid = SelectedPid();
    if (!pid) {
        MessageBoxW(g_hwnd, L"Выберите процесс в списке.", L"v8inject", MB_ICONINFORMATION);
        return;
    }

    wchar_t dllBuf[MAX_PATH] = {};
    GetWindowTextW(g_dllEdit, dllBuf, MAX_PATH);
    std::wstring dll = dllBuf;
    bool targetIs64 = SelectedIs64();
    if (dll.empty()) {
        dll = DefaultPayloadFor(targetIs64);
        SetWindowTextW(g_dllEdit, dll.c_str());
    }

    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(g_hwnd, L"Файл DLL не найден по указанному пути.", L"v8inject",
                    MB_ICONERROR);
        return;
    }

    bool dllIs64 = v8i::IsPe64(dll);
    if (dllIs64 != targetIs64) {
        wchar_t msg[512];
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                     L"Разрядность не совпадает.\n\nПроцесс: %s\nDLL: %s\n\n"
                     L"Windows не загрузит DLL другой разрядности в процесс.",
                     targetIs64 ? L"x64" : L"x86", dllIs64 ? L"x64" : L"x86");
        MessageBoxW(g_hwnd, msg, L"v8inject", MB_ICONERROR);
        return;
    }

    g_targetPid = pid;
    g_targetName = SelectedName();

    wchar_t msg[512];
    _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"[%lu] %s — подключаюсь...",
                 g_targetPid, g_targetName.c_str());
    Log(msg);
    SetStatus(L"Подключение...");

    if (!g_client.Open(pid, dll, ExeDir(), 15000)) {
        Log(std::wstring(L"ОШИБКА: ") + g_client.LastError());
        wchar_t diag[512];
        _snwprintf_s(diag, _countof(diag), _TRUNCATE,
                     L"stage=%d win32=%lu\nlog: %s",
                     g_client.LastStage(), g_client.LastWin32Error(),
                     v8i::GetLogPath());
        Log(diag);
        SetStatus(L"Ошибка подключения");
        MessageBoxW(g_hwnd, diag, L"Не удалось подключиться", MB_ICONERROR);
        return;
    }

    std::string resp;
    if (g_client.Call(L"version", resp, 10000)) {
        Log(L"Подключено: " + Utf8ToWide(resp));
        SetStatus(L"Подключено к " + g_targetName);
        EnableWindow(GetDlgItem(g_hwnd, kIdSend), TRUE);
        EnableWindow(GetDlgItem(g_hwnd, kIdDetach), TRUE);
    } else {
        Log(L"Подключение прошло, но payload не ответил на version");
        SetStatus(L"Нет ответа от payload");
    }
}

void DoDetach() {
    if (!g_client.IsOpen()) return;
    Log(L"Отключаюсь...");
    g_client.Close();
    Log(L"Сессия закрыта");
    SetStatus(L"Не подключено");
    EnableWindow(GetDlgItem(g_hwnd, kIdSend), FALSE);
    EnableWindow(GetDlgItem(g_hwnd, kIdDetach), FALSE);
    g_targetPid = 0;
}

void DoSend() {
    if (!g_client.IsOpen()) {
        MessageBoxW(g_hwnd, L"Сначала подключитесь к процессу.", L"v8inject",
                    MB_ICONINFORMATION);
        return;
    }
    wchar_t cmd[512] = {};
    GetWindowTextW(g_cmdEdit, cmd, 512);
    if (!cmd[0]) return;

    Log(std::wstring(L"> ") + cmd);
    std::string resp;
    if (g_client.Call(cmd, resp, 20000)) {
        Log(Utf8ToWide(resp));
    } else {
        Log(L"(нет ответа)");
    }
}

void CreateControls(HWND hwnd) {
    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);

    CreateWindowExW(0, L"STATIC", L"Процесс:", WS_CHILD | WS_VISIBLE,
                    12, 12, 80, 20, hwnd, nullptr, hInst, nullptr);

    g_filter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                               96, 9, 220, 24, hwnd, (HMENU)kIdFilter, hInst, nullptr);
    SendMessageW(g_filter, EM_SETCUEBANNER, TRUE, (LPARAM)L"фильтр по имени");

    CreateWindowExW(0, L"BUTTON", L"Обновить", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    324, 9, 90, 26, hwnd, (HMENU)kIdRefresh, hInst, nullptr);

    g_list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                             WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL |
                                 LVS_SHOWSELALWAYS,
                             12, 44, 760, 240, hwnd, (HMENU)kIdList, hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

    struct Col { const wchar_t* text; int width; };
    const Col cols[] = {
        {L"PID", 70}, {L"Имя", 200}, {L"Разр.", 60}, {L"Путь", 420}
    };
    for (int i = 0; i < 4; ++i) {
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        c.pszText = (LPWSTR)cols[i].text;
        c.cx = cols[i].width;
        c.iSubItem = i;
        ListView_InsertColumn(g_list, i, &c);
    }

    CreateWindowExW(0, L"STATIC", L"Payload DLL:", WS_CHILD | WS_VISIBLE,
                    12, 294, 80, 20, hwnd, nullptr, hInst, nullptr);
    g_dllEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                96, 291, 560, 24, hwnd, (HMENU)kIdDllEdit, hInst, nullptr);

    CreateWindowExW(0, L"BUTTON", L"...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    662, 291, 32, 26, hwnd, (HMENU)kIdBrowse, hInst, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Инжектировать", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                    12, 324, 150, 30, hwnd, (HMENU)kIdInject, hInst, nullptr);

    HWND detach = CreateWindowExW(0, L"BUTTON", L"Отключиться",
                                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                  170, 324, 120, 30, hwnd, (HMENU)kIdDetach, hInst, nullptr);
    EnableWindow(detach, FALSE);

    g_cmdEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                12, 364, 560, 26, hwnd, (HMENU)kIdCommand, hInst, nullptr);
    SendMessageW(g_cmdEdit, EM_SETCUEBANNER, TRUE,
                 (LPARAM)L"objects | pe | peek <addr> [len] | scan <addr>");

    HWND send = CreateWindowExW(0, L"BUTTON", L"Отправить", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                580, 364, 100, 26, hwnd, (HMENU)kIdSend, hInst, nullptr);
    EnableWindow(send, FALSE);

    g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL |
                                ES_READONLY | WS_VSCROLL,
                            12, 398, 760, 220, hwnd, (HMENU)kIdLog, hInst, nullptr);
    SendMessageW(g_log, EM_SETLIMITTEXT, 0, 0);

    g_status = CreateWindowExW(0, L"STATIC", L"Не подключено",
                               WS_CHILD | WS_VISIBLE | SS_LEFT,
                               12, 626, 500, 20, hwnd, (HMENU)kIdStatus, hInst, nullptr);

    // The GUI runs in UTF-8; the payload replies in UTF-8 too.
    SetConsoleOutputCP(CP_UTF8);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        g_hwnd = hwnd;
        CreateControls(hwnd);
        RefreshProcesses();
        return 0;

    case WM_SIZE:
        if (g_list) {
            RECT rc;
            GetClientRect(hwnd, &rc);
            int w = rc.right - rc.left;
            int h = rc.bottom - rc.top;
            SetWindowPos(g_list, nullptr, 12, 44, w - 24, 240, SWP_NOZORDER);
            SetWindowPos(g_dllEdit, nullptr, 96, 291, w - 24 - 96 - 44, 24, SWP_NOZORDER);
            SetWindowPos(GetDlgItem(hwnd, kIdBrowse), nullptr, w - 24 - 40, 291, 32, 26,
                         SWP_NOZORDER);
            SetWindowPos(g_log, nullptr, 12, 398, w - 24, h - 398 - 34, SWP_NOZORDER);
            SetWindowPos(g_status, nullptr, 12, h - 26, w - 24, 20, SWP_NOZORDER);
        }
        return 0;

    case WM_GETMINMAXINFO: {
        auto* mmi = (MINMAXINFO*)lp;
        mmi->ptMinTrackSize.x = 620;
        mmi->ptMinTrackSize.y = 560;
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case kIdRefresh: RefreshProcesses(); return 0;
        case kIdBrowse:  BrowseDll();        return 0;
        case kIdInject:  DoInject();         return 0;
        case kIdDetach:  DoDetach();         return 0;
        case kIdSend:    DoSend();           return 0;
        case kIdFilter:
            if (HIWORD(wp) == EN_CHANGE) FillList();
            return 0;
        }
        return 0;

    case WM_NOTIFY: {
        auto* nm = (LPNMHDR)lp;
        if (nm->idFrom == kIdList && nm->code == LVN_ITEMCHANGED) {
            auto* nv = (LPNMITEMACTIVATE)lp;
            if (nv->iItem >= 0) {
                uint32_t pid = SelectedPid();
                wchar_t dll[MAX_PATH] = {};
                GetWindowTextW(g_dllEdit, dll, MAX_PATH);
                if (!dll[0]) {
                    std::wstring def = DefaultPayloadFor(SelectedIs64());
                    SetWindowTextW(g_dllEdit, def.c_str());
                }
                wchar_t buf[320];
                _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"Выбран: [%lu] %s (%s)",
                             pid, SelectedName().c_str(),
                             SelectedIs64() ? L"x64" : L"x86");
                SetStatus(buf);
            }
        }
        if (nm->idFrom == kIdList && nm->code == NM_DBLCLK) DoInject();
        return 0;
    }

    case WM_DESTROY:
        g_client.Close();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    // Log next to the executable, same convention as the CLI.
    v8i::SetLogDirectory(ExeDir().c_str());

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"V8InjectGuiWnd";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"v8inject — инжектор DLL",
                                WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, 800, 700,
                                nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
