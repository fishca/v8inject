// v8inject GUI: pick a process, inject the payload, run commands.
//
// Plain Win32 + common controls. No frameworks: the whole point of this tool is
// to load into other people's processes, so it stays small and dependency-free.

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellscalingapi.h>

#include "v8inject/client.h"
#include "v8inject/diag.h"
#include "v8inject/injector.h"
#include "v8inject/procs.h"

#include <algorithm>
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
constexpr int kIdGitbarShow    = 1012;
constexpr int kIdGitbarHide    = 1013;
constexpr int kIdGitbarSettings = 1014;

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

// ---------------------------------------------------------------------------
// 1C-style theme: the same palette as the in-process GitBar dialogs (measured
// from a live designer) — cream form, 1px #B0A68E frames, white fields, flat
// beige buttons and the blue list selection. Native message boxes stay native.
// ---------------------------------------------------------------------------

const COLORREF kUiBg       = RGB(245, 242, 221);
const COLORREF kUiBorder   = RGB(176, 166, 142);
const COLORREF kUiFieldBg  = RGB(255, 255, 255);
const COLORREF kUiHover    = RGB(252, 246, 199);
const COLORREF kUiPress    = RGB(226, 216, 178);
const COLORREF kUiText     = RGB(0, 0, 0);
const COLORREF kUiDisabled = RGB(150, 146, 136);
const COLORREF kUiSel      = RGB(49, 106, 197);
const COLORREF kUiSelIdle  = RGB(212, 208, 200);
const COLORREF kUiHeader   = RGB(238, 234, 222);

HFONT CreateUiFont(int weight) {
    HDC dc = GetDC(nullptr);
    int h = -MulDiv(8, GetDeviceCaps(dc, LOGPIXELSY), 72);
    ReleaseDC(nullptr, dc);
    return CreateFontW(h, 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Tahoma");
}

HFONT UiFont() {
    static HFONT f = CreateUiFont(FW_NORMAL);
    return f;
}

HFONT UiFontBold() {
    static HFONT f = CreateUiFont(FW_BOLD);
    return f;
}

HBRUSH UiBgBrush() {
    static HBRUSH b = CreateSolidBrush(kUiBg);
    return b;
}

HBRUSH UiFieldBrush() {
    static HBRUSH b = CreateSolidBrush(kUiFieldBg);
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

// Ownerdraw buttons would otherwise stay flat grey: this subclass tracks the
// mouse so the button can draw the beige hover of the 1C toolbar.
LRESULT CALLBACK UiButtonProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    WNDPROC old = (WNDPROC)GetPropW(h, L"v8i.oldBtnProc");
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

HWND CreateUiButton(HWND parent, int id, const wchar_t* text,
                    int x, int y, int w, int h) {
    HWND btn = CreateWindowExW(0, L"BUTTON", text,
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                               x, y, w, h, parent, (HMENU)(INT_PTR)id,
                               (HINSTANCE)GetWindowLongPtrW(parent, GWLP_HINSTANCE),
                               nullptr);
    if (!btn) return nullptr;
    SendMessageW(btn, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    WNDPROC old = (WNDPROC)SetWindowLongPtrW(btn, GWLP_WNDPROC, (LONG_PTR)UiButtonProc);
    SetPropW(btn, L"v8i.oldBtnProc", (HANDLE)old);
    return btn;
}

bool UiDrawOwnerButton(const DRAWITEMSTRUCT* dis) {
    if (!dis || dis->CtlType != ODT_BUTTON) return false;
    wchar_t text[256] = {};
    GetWindowTextW(dis->hwndItem, text, 256);
    bool press = (dis->itemState & ODS_SELECTED) != 0;
    bool disabled = (dis->itemState & ODS_DISABLED) != 0;
    bool hover = !disabled && GetWindowLongPtrW(dis->hwndItem, GWLP_USERDATA) != 0;

    COLORREF face = press ? kUiPress : hover ? kUiHover : kUiBg;
    HBRUSH b = CreateSolidBrush(face);
    FillRect(dis->hDC, &dis->rcItem, b);
    DeleteObject(b);
    UiFrame(dis->hDC, dis->rcItem, kUiBorder);

    HGDIOBJ oldFont = SelectObject(dis->hDC, UiFont());
    int oldMode = SetBkMode(dis->hDC, TRANSPARENT);
    COLORREF oldColor = SetTextColor(dis->hDC, disabled ? kUiDisabled : kUiText);
    RECT tr = dis->rcItem;
    DrawTextW(dis->hDC, text, -1, &tr,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SetTextColor(dis->hDC, oldColor);
    SetBkMode(dis->hDC, oldMode);
    SelectObject(dis->hDC, oldFont);

    if ((dis->itemState & ODS_FOCUS) && !disabled) {
        RECT fr = dis->rcItem;
        InflateRect(&fr, -3, -3);
        DrawFocusRect(dis->hDC, &fr);
    }
    return true;
}

// Edits and lists sit 1px inside a frame drawn by the parent, so the frame has
// to be repainted when the focus moves (the border turns blue).
struct UiField {
    HWND hwnd = nullptr;
    RECT cell{};
};
std::vector<UiField> g_fields;

LRESULT CALLBACK UiFieldProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    WNDPROC old = (WNDPROC)GetPropW(h, L"v8i.oldFieldProc");
    if (msg == WM_SETFOCUS || msg == WM_KILLFOCUS) {
        InvalidateRect(h, nullptr, FALSE);   // list selection follows the focus
        if (HWND parent = GetParent(h)) InvalidateRect(parent, nullptr, FALSE);
    }
    return CallWindowProcW(old, h, msg, wp, lp);
}

void TrackFieldIn(std::vector<UiField>& fields, HWND h, int x, int y, int w, int h2) {
    WNDPROC old = (WNDPROC)SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)UiFieldProc);
    SetPropW(h, L"v8i.oldFieldProc", (HANDLE)old);
    fields.push_back({ h, { x, y, x + w, y + h2 } });
}

void TrackField(HWND h, int x, int y, int w, int h2) {
    TrackFieldIn(g_fields, h, x, y, w, h2);
}

void PlaceFieldIn(std::vector<UiField>& fields, HWND h, int x, int y, int w, int h2) {
    SetWindowPos(h, nullptr, x + 1, y + 1, w - 2, h2 - 2, SWP_NOZORDER);
    for (auto& f : fields) {
        if (f.hwnd == h) { f.cell = { x, y, x + w, y + h2 }; break; }
    }
}

void PlaceField(HWND h, int x, int y, int w, int h2) {
    PlaceFieldIn(g_fields, h, x, y, w, h2);
}

void PaintFieldFramesIn(HDC dc, const std::vector<UiField>& fields) {
    HWND focus = GetFocus();
    for (const auto& f : fields) {
        if (!IsWindowVisible(f.hwnd)) continue;
        UiFrame(dc, f.cell, f.hwnd == focus ? kUiSel : kUiBorder);
    }
}

void PaintFieldFrames(HDC dc) {
    PaintFieldFramesIn(dc, g_fields);
}

// Report-mode ListView, painted by hand: the default selection colour and the
// themed header are the two things that break the 1C look.
LRESULT UiListCustomDraw(LPNMLVCUSTOMDRAW cd) {
    switch (cd->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT:
        return CDRF_NOTIFYSUBITEMDRAW;
    case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
        int row = (int)cd->nmcd.dwItemSpec;
        bool sel = (ListView_GetItemState(g_list, row, LVIS_SELECTED) & LVIS_SELECTED) != 0;
        bool focus = GetFocus() == g_list;
        COLORREF bg = sel ? (focus ? kUiSel : kUiSelIdle) : kUiFieldBg;
        COLORREF fg = (sel && focus) ? RGB(255, 255, 255) : kUiText;

        RECT rc{};
        if (!ListView_GetSubItemRect(g_list, row, cd->iSubItem, LVIR_BOUNDS, &rc))
            return CDRF_DODEFAULT;
        HBRUSH b = CreateSolidBrush(bg);
        FillRect(cd->nmcd.hdc, &rc, b);
        DeleteObject(b);

        wchar_t text[512] = {};
        ListView_GetItemText(g_list, row, cd->iSubItem, text, 512);
        rc.left += 4;
        rc.right -= 2;
        HGDIOBJ oldFont = SelectObject(cd->nmcd.hdc, UiFont());
        int oldMode = SetBkMode(cd->nmcd.hdc, TRANSPARENT);
        COLORREF oldColor = SetTextColor(cd->nmcd.hdc, fg);
        DrawTextW(cd->nmcd.hdc, text, -1, &rc,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        SetTextColor(cd->nmcd.hdc, oldColor);
        SetBkMode(cd->nmcd.hdc, oldMode);
        SelectObject(cd->nmcd.hdc, oldFont);
        return CDRF_SKIPDEFAULT;
    }
    }
    return CDRF_DODEFAULT;
}

LRESULT UiHeaderCustomDraw(LPNMCUSTOMDRAW cd) {
    if (cd->dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
    if (cd->dwDrawStage != CDDS_ITEMPREPAINT) return CDRF_DODEFAULT;

    RECT rc = cd->rc;
    HBRUSH bg = CreateSolidBrush(kUiHeader);
    FillRect(cd->hdc, &rc, bg);
    DeleteObject(bg);
    HBRUSH line = CreateSolidBrush(kUiBorder);
    RECT bottom{ rc.left, rc.bottom - 1, rc.right, rc.bottom };
    RECT right{ rc.right - 1, rc.top, rc.right, rc.bottom };
    FillRect(cd->hdc, &bottom, line);
    FillRect(cd->hdc, &right, line);
    DeleteObject(line);

    wchar_t text[128] = {};
    HDITEMW hi{};
    hi.mask = HDI_TEXT | HDI_FORMAT;
    hi.pszText = text;
    hi.cchTextMax = 128;
    Header_GetItem((HWND)cd->hdr.hwndFrom, (int)cd->dwItemSpec, &hi);

    RECT tr = rc;
    tr.left += 4;
    tr.right -= 4;
    UINT fmt = DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS;
    if (hi.fmt & HDF_CENTER) fmt = (fmt & ~DT_LEFT) | DT_CENTER;
    if (hi.fmt & HDF_RIGHT) fmt = (fmt & ~DT_LEFT) | DT_RIGHT;

    HGDIOBJ oldFont = SelectObject(cd->hdc, UiFontBold());
    int oldMode = SetBkMode(cd->hdc, TRANSPARENT);
    COLORREF oldColor = SetTextColor(cd->hdc, kUiText);
    DrawTextW(cd->hdc, text, -1, &tr, fmt);
    SetTextColor(cd->hdc, oldColor);
    SetBkMode(cd->hdc, oldMode);
    SelectObject(cd->hdc, oldFont);
    return CDRF_SKIPDEFAULT;
}

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

// The picker is for 1C:Предприятие only — any other process in the list just
// clutters it. All three image names are legitimate 1C processes (thick client
// / configurator, thin client, server).
bool Is1C(const v8i::ProcessEntry& e) {
    if (e.name.empty()) return false;
    return _wcsicmp(e.name.c_str(), L"1cv8.exe") == 0 ||
           _wcsicmp(e.name.c_str(), L"1cv8c.exe") == 0 ||
           _wcsicmp(e.name.c_str(), L"1cv8s.exe") == 0;
}

void FillList() {
    std::wstring filter;
    wchar_t fbuf[128] = {};
    GetWindowTextW(g_filter, fbuf, 128);
    filter = fbuf;

    SendMessageW(g_list, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_list);

    int row = 0;
    int total = 0;
    for (const auto& p : g_procs) {
        if (p.session0) continue;          // services: not injectable targets
        if (!Is1C(p)) continue;            // the picker shows 1C processes only
        ++total;
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

    if (total == 0) {
        SetStatus(L"1С не запущена — процессы 1cv8.exe / 1cv8c.exe / 1cv8s.exe не найдены");
    } else {
        wchar_t status[128];
        _snwprintf_s(status, _countof(status), _TRUNCATE, L"1С: %d (показано %d)", total, row);
        SetStatus(status);
    }
}

void RefreshProcesses() {
    // Sorting here keeps the list stable across refreshes; the filter box is
    // left alone so typing is never interrupted.
    g_procs = v8i::ListProcesses();
    std::sort(g_procs.begin(), g_procs.end(),
              [](const v8i::ProcessEntry& a, const v8i::ProcessEntry& b) {
                  int c = _wcsicmp(a.name.c_str(), b.name.c_str());
                  return c != 0 ? c < 0 : a.pid < b.pid;
              });
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

    Log(L"------------------------------");

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

// ---------------------------------------------------------------------------
// GitBar: one-click show/hide of the in-process git toolbar, plus a settings
// dialog that writes the same %APPDATA%\v8inject\gitbar.ini the payload reads.
// ---------------------------------------------------------------------------

const wchar_t* GitBarIniPath() {
    static wchar_t path[MAX_PATH] = {};
    if (!path[0]) {
        ExpandEnvironmentStringsW(L"%APPDATA%\\v8inject\\gitbar.ini", path, MAX_PATH);
    }
    return path;
}

std::wstring GitBarIniGet(const wchar_t* key) {
    wchar_t buf[1024] = {};
    GetPrivateProfileStringW(L"git", key, L"", buf, 1024, GitBarIniPath());
    return buf;
}

void GitBarIniSet(const wchar_t* key, const wchar_t* value) {
    WritePrivateProfileStringW(L"git", key, value, GitBarIniPath());
}

// Connects to the selected process if not connected yet (same path as
// DoInject, minus the messages). Returns true when a session is live.
bool EnsureConnected() {
    if (g_client.IsOpen()) return true;
    uint32_t pid = SelectedPid();
    if (!pid) return false;

    wchar_t dllBuf[MAX_PATH] = {};
    GetWindowTextW(g_dllEdit, dllBuf, MAX_PATH);
    std::wstring dll = dllBuf;
    bool targetIs64 = SelectedIs64();
    if (dll.empty()) {
        dll = DefaultPayloadFor(targetIs64);
        SetWindowTextW(g_dllEdit, dll.c_str());
    }
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) return false;

    g_targetPid = pid;
    g_targetName = SelectedName();

    wchar_t msg[512];
    _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"[%lu] %s — подключаюсь...",
                 g_targetPid, g_targetName.c_str());
    Log(msg);
    SetStatus(L"Подключение...");

    if (!g_client.Open(pid, dll, ExeDir(), 15000)) {
        Log(std::wstring(L"ОШИБКА: ") + g_client.LastError());
        SetStatus(L"Ошибка подключения");
        return false;
    }
    std::string resp;
    if (g_client.Call(L"version", resp, 10000)) {
        Log(L"Подключено: " + Utf8ToWide(resp));
        SetStatus(L"Подключено к " + g_targetName);
        EnableWindow(GetDlgItem(g_hwnd, kIdSend), TRUE);
        EnableWindow(GetDlgItem(g_hwnd, kIdDetach), TRUE);
        return true;
    }
    Log(L"Подключение прошло, но payload не ответил на version");
    SetStatus(L"Нет ответа от payload");
    return false;
}

void DoGitbarShow() {
    if (!EnsureConnected()) {
        MessageBoxW(g_hwnd, L"Нет подключения к процессу (выберите 1cv8.exe).",
                    L"GitBar", MB_ICONINFORMATION);
        return;
    }
    Log(L"> gitbar");
    std::string resp;
    if (g_client.Call(L"gitbar", resp, 20000)) {
        Log(Utf8ToWide(resp));
        SetStatus(L"GitBar: панель показана (payload остаётся в процессе)");
    } else {
        Log(L"(нет ответа)");
        SetStatus(L"GitBar: нет ответа");
    }
}

void DoGitbarHide() {
    if (!g_client.IsOpen()) {
        MessageBoxW(g_hwnd, L"Сначала подключитесь к процессу.", L"GitBar",
                    MB_ICONINFORMATION);
        return;
    }
    Log(L"> gitbar hide");
    std::string resp;
    if (g_client.Call(L"gitbar hide", resp, 20000)) {
        Log(Utf8ToWide(resp));
        SetStatus(L"GitBar: панель скрыта");
    } else {
        Log(L"(нет ответа)");
    }
}

// Buttons notify their parent with a SENT WM_COMMAND, which a GetMessage pump
// never sees — the settings dialog therefore saves from its own window proc and
// the pump only waits for it to disappear.
struct GitBarSettingsCtx {
    HWND ed[4] = {};
    std::vector<UiField> fields;
    bool saved = false;
};

LRESULT CALLBACK GitBarSettingsProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    GitBarSettingsCtx* c = (GitBarSettingsCtx*)GetWindowLongPtrW(h, GWLP_USERDATA);
    switch (msg) {
    case WM_CTLCOLORDLG:
        return (LRESULT)UiBgBrush();

    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, kUiText);
        SetBkMode(dc, TRANSPARENT);
        return (LRESULT)UiBgBrush();
    }

    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, kUiText);
        SetBkColor(dc, kUiFieldBg);
        return (LRESULT)UiFieldBrush();
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        if (c) PaintFieldFramesIn(dc, c->fields);
        EndPaint(h, &ps);
        return 0;
    }

    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lp;
        if (dis->CtlType == ODT_BUTTON && UiDrawOwnerButton(dis)) return TRUE;
        break;
    }

    case DM_GETDEFID:
        return MAKELRESULT(IDOK, DC_HASDEFID);

    case WM_COMMAND:
        if (c && LOWORD(wp) == IDOK) {
            wchar_t b[4][1024] = {};
            for (int i = 0; i < 4; ++i) GetWindowTextW(c->ed[i], b[i], 1024);
            if (b[0][0]) GitBarIniSet(L"gitpath", b[0]);
            if (b[1][0]) GitBarIniSet(L"dumpdir", b[1]);
            GitBarIniSet(L"commitmsg", b[2]);
            GitBarIniSet(L"remote", b[3]);
            c->saved = true;
            DestroyWindow(h);
            return 0;
        }
        if (c && LOWORD(wp) == IDCANCEL) { DestroyWindow(h); return 0; }
        if (c && LOWORD(wp) == 2001 && HIWORD(wp) == BN_CLICKED) {
            // Standard shell folder picker for the dumpdir edit.
            wchar_t buf[MAX_PATH] = {};
            BROWSEINFOW bi = {};
            bi.hwndOwner = h;
            bi.lpszTitle = L"Папка выгрузки конфигурации";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                if (SHGetPathFromIDListW(pidl, buf)) SetWindowTextW(c->ed[1], buf);
                CoTaskMemFree(pidl);
            }
            return 0;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    }
    return DefDlgProcW(h, msg, wp, lp);
}

void DoGitbarSettings() {
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"#32770", L"GitBar — настройки",
                               WS_CAPTION | WS_SYSMENU | WS_OVERLAPPED | WS_VISIBLE |
                                   WS_CLIPCHILDREN,
                               CW_USEDEFAULT, CW_USEDEFAULT, 460, 226, g_hwnd, nullptr,
                               GetModuleHandleW(nullptr), nullptr);
    if (!dlg) return;

    GitBarSettingsCtx ctx;
    SetWindowLongPtrW(dlg, GWLP_WNDPROC, (LONG_PTR)GitBarSettingsProc);
    SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)&ctx);

    auto Lbl = [&](int y, const wchar_t* t) {
        HWND s = CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT,
                                 12, y, 140, 18, dlg, nullptr,
                                 GetModuleHandleW(nullptr), nullptr);
        SendMessageW(s, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    };
    auto Edt = [&](int cellY, int cellW) {
        HWND e = CreateWindowExW(0, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                 159, cellY + 1, cellW - 2, 22, dlg, nullptr,
                                 GetModuleHandleW(nullptr), nullptr);
        SendMessageW(e, WM_SETFONT, (WPARAM)UiFont(), TRUE);
        TrackFieldIn(ctx.fields, e, 158, cellY, cellW, 24);
        return e;
    };

    ctx.ed[0] = Edt(13, 286);
    // dumpdir gets a folder-picker button in the same row: narrower edit,
    // standard shell browse dialog on the "..." click (see WM_COMMAND 2001).
    ctx.ed[1] = Edt(43, 252);
    ctx.ed[2] = Edt(73, 286);
    ctx.ed[3] = Edt(103, 286);
    Lbl(15, L"git.exe");
    Lbl(45, L"папка выгрузки");
    Lbl(75, L"комментарий к коммиту");
    Lbl(105, L"remote origin (не обяз.)");
    CreateUiButton(dlg, 2001, L"...", 414, 44, 28, 22);
    CreateUiButton(dlg, IDOK, L"OK", 158, 150, 90, 26);
    CreateUiButton(dlg, IDCANCEL, L"Отмена", 258, 150, 90, 26);

    // Prefill: current values, or a sensible git default.
    std::wstring git = GitBarIniGet(L"gitpath");
    if (git.empty() && GetFileAttributesW(L"C:\\Program Files\\Git\\cmd\\git.exe")
                           != INVALID_FILE_ATTRIBUTES) {
        git = L"C:\\Program Files\\Git\\cmd\\git.exe";
    }
    SetWindowTextW(ctx.ed[0], git.c_str());
    SetWindowTextW(ctx.ed[1], GitBarIniGet(L"dumpdir").c_str());
    SetWindowTextW(ctx.ed[2], GitBarIniGet(L"commitmsg").c_str());
    SetWindowTextW(ctx.ed[3], GitBarIniGet(L"remote").c_str());

    SetForegroundWindow(dlg);
    SetFocus(ctx.ed[0]);

    MSG msg;
    for (;;) {
        if (!IsWindow(dlg)) break;
        if (!GetMessageW(&msg, nullptr, 0, 0)) break;
        if (IsDialogMessageW(dlg, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (IsWindow(dlg)) DestroyWindow(dlg);
    if (ctx.saved) Log(L"Настройки GitBar сохранены в " + std::wstring(GitBarIniPath()));
}

void CreateControls(HWND hwnd) {
    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);

    auto Lbl = [&](int y, int w, const wchar_t* t) {
        HWND s = CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT,
                                 12, y, w, 20, hwnd, nullptr, hInst, nullptr);
        SendMessageW(s, WM_SETFONT, (WPARAM)UiFont(), TRUE);
        return s;
    };

    Lbl(12, 80, L"Процесс:");

    g_filter = CreateWindowExW(0, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                               97, 10, 218, 22, hwnd, (HMENU)kIdFilter, hInst, nullptr);
    SendMessageW(g_filter, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    SendMessageW(g_filter, EM_SETCUEBANNER, TRUE, (LPARAM)L"фильтр по имени");
    TrackField(g_filter, 96, 9, 220, 24);

    CreateUiButton(hwnd, kIdRefresh, L"Обновить", 324, 9, 90, 26);

    g_list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
                                 LVS_SHOWSELALWAYS,
                             13, 45, 758, 238, hwnd, (HMENU)kIdList, hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    SendMessageW(g_list, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    ListView_SetBkColor(g_list, kUiFieldBg);
    ListView_SetTextBkColor(g_list, kUiFieldBg);
    ListView_SetTextColor(g_list, kUiText);
    // A 1px image list is only there to keep the rows at 1C-ish 18px.
    HIMAGELIST rowH = ImageList_Create(1, 18, ILC_COLOR32, 1, 1);
    if (rowH) ListView_SetImageList(g_list, rowH, LVSIL_SMALL);

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
    SendMessageW(ListView_GetHeader(g_list), WM_SETFONT, (WPARAM)UiFontBold(), TRUE);
    TrackField(g_list, 12, 44, 760, 240);

    Lbl(294, 80, L"Payload DLL:");
    g_dllEdit = CreateWindowExW(0, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                97, 292, 558, 22, hwnd, (HMENU)kIdDllEdit, hInst, nullptr);
    SendMessageW(g_dllEdit, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    TrackField(g_dllEdit, 96, 291, 560, 24);

    CreateUiButton(hwnd, kIdBrowse, L"...", 662, 291, 32, 26);

    CreateUiButton(hwnd, kIdInject, L"Инжектировать", 12, 324, 150, 30);

    HWND detach = CreateUiButton(hwnd, kIdDetach, L"Отключиться", 170, 324, 120, 30);
    EnableWindow(detach, FALSE);

    CreateUiButton(hwnd, kIdGitbarShow, L"GitBar: показать", 298, 324, 130, 30);
    CreateUiButton(hwnd, kIdGitbarHide, L"скрыть", 434, 324, 70, 30);
    CreateUiButton(hwnd, kIdGitbarSettings, L"Настройки", 510, 324, 100, 30);

    g_cmdEdit = CreateWindowExW(0, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                13, 365, 558, 24, hwnd, (HMENU)kIdCommand, hInst, nullptr);
    SendMessageW(g_cmdEdit, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    SendMessageW(g_cmdEdit, EM_SETCUEBANNER, TRUE,
                 (LPARAM)L"objects | pe | peek <addr> [len] | scan <addr>");
    TrackField(g_cmdEdit, 12, 364, 560, 26);

    HWND send = CreateUiButton(hwnd, kIdSend, L"Отправить", 580, 364, 100, 26);
    EnableWindow(send, FALSE);

    g_log = CreateWindowExW(0, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL |
                                ES_READONLY | WS_VSCROLL,
                            13, 399, 758, 218, hwnd, (HMENU)kIdLog, hInst, nullptr);
    SendMessageW(g_log, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    SendMessageW(g_log, EM_SETLIMITTEXT, 0, 0);
    TrackField(g_log, 12, 398, 760, 220);

    g_status = CreateWindowExW(0, L"STATIC", L"Не подключено",
                               WS_CHILD | WS_VISIBLE | SS_LEFT,
                               12, 626, 500, 20, hwnd, (HMENU)kIdStatus, hInst, nullptr);
    SendMessageW(g_status, WM_SETFONT, (WPARAM)UiFont(), TRUE);

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
            PlaceField(g_list, 12, 44, w - 24, 240);
            PlaceField(g_dllEdit, 96, 291, w - 24 - 96 - 44, 24);
            SetWindowPos(GetDlgItem(hwnd, kIdBrowse), nullptr, w - 24 - 40, 291, 32, 26,
                         SWP_NOZORDER);
            PlaceField(g_cmdEdit, 12, 364, w - 24 - 112, 26);
            SetWindowPos(GetDlgItem(hwnd, kIdSend), nullptr, w - 24 - 100, 364, 100, 26,
                         SWP_NOZORDER);
            PlaceField(g_log, 12, 398, w - 24, h - 398 - 34);
            SetWindowPos(g_status, nullptr, 12, h - 26, w - 24, 20, SWP_NOZORDER);
            InvalidateRect(hwnd, nullptr, TRUE);
        }
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        // The 1C form separates its status line with a single border.
        HPEN pen = CreatePen(PS_SOLID, 1, kUiBorder);
        HGDIOBJ op = SelectObject(dc, pen);
        MoveToEx(dc, 12, rc.bottom - 32, nullptr);
        LineTo(dc, rc.right - 12, rc.bottom - 32);
        SelectObject(dc, op);
        DeleteObject(pen);
        PaintFieldFrames(dc);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, kUiText);
        if ((HWND)lp == g_log) {
            SetBkColor(dc, kUiFieldBg);
            return (LRESULT)UiFieldBrush();
        }
        SetBkMode(dc, TRANSPARENT);
        return (LRESULT)UiBgBrush();
    }

    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, kUiText);
        SetBkColor(dc, kUiFieldBg);
        return (LRESULT)UiFieldBrush();
    }

    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lp;
        if (dis->CtlType == ODT_BUTTON && UiDrawOwnerButton(dis)) return TRUE;
        break;
    }

    case WM_GETMINMAXINFO: {
        auto* mmi = (MINMAXINFO*)lp;
        // The button row (12..610) plus the 1C-like side margins.
        mmi->ptMinTrackSize.x = 640;
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
        case kIdGitbarShow:    DoGitbarShow();    return 0;
        case kIdGitbarHide:    DoGitbarHide();    return 0;
        case kIdGitbarSettings: DoGitbarSettings(); return 0;
        case kIdFilter:
            if (HIWORD(wp) == EN_CHANGE) FillList();
            return 0;
        }
        return 0;

    case WM_NOTIFY: {
        auto* nm = (LPNMHDR)lp;
        if (nm->idFrom == kIdList && nm->code == NM_CUSTOMDRAW) {
            if (nm->hwndFrom == g_list) return UiListCustomDraw((LPNMLVCUSTOMDRAW)lp);
            if (nm->hwndFrom == ListView_GetHeader(g_list))
                return UiHeaderCustomDraw((LPNMCUSTOMDRAW)lp);
        }
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
    wc.hbrBackground = UiBgBrush();
    wc.lpszClassName = L"V8InjectGuiWnd";
    RegisterClassExW(&wc);

    // WS_CLIPCHILDREN: the form repaints its own cream background often (focus
    // frames), and overpainting the fields on every focus change would flicker.
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"v8inject — инжектор DLL",
                                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                                CW_USEDEFAULT, CW_USEDEFAULT, 800, 700,
                                nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}
