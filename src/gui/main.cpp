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
#include "v8inject/text.h"
#include "v8inject/diag.h"
#include "v8inject/injector.h"
#include "v8inject/procs.h"

#include "host/gui_settings.h"
#include "host/ui_job.h"
#include "host/ui_layout.h"
#include "host/ui_loop.h"

#include <algorithm>
#include <functional>
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
uint32_t g_sessionPid = 0;   // the process the open session belongs to
std::wstring g_targetName;

// The DPI of the monitor the window is on. Every coordinate of the form is
// written in 96-DPI units and scaled with it; the window is per-monitor DPI
// aware, so Windows does not scale anything for it (A81).
int g_dpi = 96;

// Labels and buttons at a fixed place, in 96-DPI units: positioned once and
// repositioned after the window moved to a monitor with another DPI.
std::vector<v8i::UiAnchor> g_anchors;

void Anchor(HWND h, int x, int y, int w, int h2) {
    if (!h) return;
    g_anchors.push_back({ h, x, y, w, h2 });
    const v8i::UiAnchor& a = g_anchors.back();
    SetWindowPos(h, nullptr, v8i::DpiScale(a.x, g_dpi), v8i::DpiScale(a.y, g_dpi),
                 v8i::DpiScale(a.w, g_dpi), v8i::DpiScale(a.h, g_dpi),
                 SWP_NOZORDER | SWP_NOACTIVATE);
}

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

// The window is per-monitor DPI aware, so Windows does not scale it for us and
// the font has to be built for the DPI of the monitor the window is on: the
// 96-DPI 8pt font stays 8pt in points, while every box of the layout keeps its
// 96-DPI pixel size and clips the text at 150-200% (A81). `g_dpi` itself and
// the anchors that use it are declared above.
HFONT g_font = nullptr;
HFONT g_fontBold = nullptr;

HFONT CreateUiFont(int dpi, int weight) {
    return CreateFontW(-MulDiv(8, dpi, 72), 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Tahoma");
}

HFONT UiFont() { return g_font ? g_font : (g_font = CreateUiFont(g_dpi, FW_NORMAL)); }
HFONT UiFontBold() {
    return g_fontBold ? g_fontBold : (g_fontBold = CreateUiFont(g_dpi, FW_BOLD));
}

// Applies the fonts of the current DPI to every control of the thread: the main
// window's children and, while the settings dialog is open, its own controls.
// The old fonts are deleted afterwards, when nothing selects them anymore.
struct FontPair {
    HFONT normal = nullptr;
    HFONT bold = nullptr;
};

BOOL CALLBACK RefontChild(HWND child, LPARAM lp) {
    SendMessageW(child, WM_SETFONT, (WPARAM)((const FontPair*)lp)->normal, TRUE);
    return TRUE;
}

BOOL CALLBACK RefontTopWindow(HWND top, LPARAM lp) {
    const FontPair* fp = (const FontPair*)lp;
    EnumChildWindows(top, RefontChild, (LPARAM)fp);
    (void)top;
    return TRUE;
}

void ResetUiFonts(int dpi) {
    FontPair fp;
    fp.normal = CreateUiFont(dpi, FW_NORMAL);
    fp.bold = CreateUiFont(dpi, FW_BOLD);
    if (!fp.normal || !fp.bold) {
        if (fp.normal) DeleteObject(fp.normal);
        if (fp.bold) DeleteObject(fp.bold);
        return;
    }
    const HFONT oldNormal = g_font;
    const HFONT oldBold = g_fontBold;
    g_font = fp.normal;
    g_fontBold = fp.bold;
    g_dpi = dpi;
    EnumThreadWindows(GetCurrentThreadId(), RefontTopWindow, (LPARAM)&fp);
    if (g_list) SendMessageW(ListView_GetHeader(g_list), WM_SETFONT, (WPARAM)fp.bold, TRUE);
    if (oldNormal) DeleteObject(oldNormal);
    if (oldBold) DeleteObject(oldBold);
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
                    int x, int y, int w, int h, int dpi) {
    HWND btn = CreateWindowExW(0, L"BUTTON", text,
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                               v8i::DpiScale(x, dpi), v8i::DpiScale(y, dpi),
                               v8i::DpiScale(w, dpi), v8i::DpiScale(h, dpi),
                               parent, (HMENU)(INT_PTR)id,
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
// to be repainted when the focus moves (the border turns blue). The frame and
// the control are stored in 96-DPI units (`base`) and scaled to the monitor of
// the window: the window is per-monitor DPI aware, so nothing scales the form
// for it (A81).
struct UiField {
    HWND hwnd = nullptr;
    RECT cell{};   // the frame, physical pixels
    RECT base{};   // the frame, 96-DPI units
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

void PlaceFieldIn(std::vector<UiField>& fields, HWND h, int x, int y, int w, int h2,
                  int dpi);

void TrackFieldIn(std::vector<UiField>& fields, HWND h, int x, int y, int w, int h2) {
    WNDPROC old = (WNDPROC)SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)UiFieldProc);
    SetPropW(h, L"v8i.oldFieldProc", (HANDLE)old);
    UiField f;
    f.hwnd = h;
    f.base = { x, y, x + w, y + h2 };
    f.cell = f.base;
    fields.push_back(f);
}

void TrackField(HWND h, int x, int y, int w, int h2) {
    TrackFieldIn(g_fields, h, x, y, w, h2);
}

// Places one field for the given DPI: the frame is scaled from its base rect
// and the control sits 1 (scaled) pixel inside it.
void PlaceFieldIn(std::vector<UiField>& fields, HWND h, int x, int y, int w, int h2,
                  int dpi) {
    const RECT base{ x, y, x + w, y + h2 };
    for (auto& f : fields) {
        if (f.hwnd != h) continue;
        f.base = base;
        f.cell = v8i::ScaleRect(base, dpi);
        const int inset = v8i::DpiScale(1, dpi);
        SetWindowPos(h, nullptr, f.cell.left + inset, f.cell.top + inset,
                     (f.cell.right - f.cell.left) - 2 * inset,
                     (f.cell.bottom - f.cell.top) - 2 * inset,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        break;
    }
}

void PlaceField(HWND h, int x, int y, int w, int h2) {
    PlaceFieldIn(g_fields, h, x, y, w, h2, g_dpi);
}

// After the DPI changed: every field goes back to its base rect, now scaled
// with the new DPI.
void RelayoutFieldsIn(std::vector<UiField>& fields, int dpi) {
    for (auto& f : fields) {
        PlaceFieldIn(fields, f.hwnd, f.base.left, f.base.top, f.base.right - f.base.left,
                     f.base.bottom - f.base.top, dpi);
    }
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

// Payload replies are UTF-8; the window is wide. The conversion lives in
// v8i_common (see v8inject/text.h).
using v8i::Utf8ToWide;

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

// ---------------------------------------------------------------------------
// A80: every call that talks to the target - open, version, a command - runs
// on a worker thread. Each of them has a 10-20 s timeout, and on the UI thread
// the window stopped painting, Windows marked it "Не отвечает" and offered to
// kill it.
// ---------------------------------------------------------------------------

constexpr UINT kMsgJobDone = WM_APP + 10;

enum class JobKind { None, Inject, Detach, Send, GitbarShow, GitbarHide };

struct JobOutcome {
    bool openOk = false;       // a session is live after the job
    bool fresh = false;        // this job opened it
    bool versionOk = false;    // the fresh session answered `version`
    bool callOk = false;       // the last payload call answered
    bool noConnection = false; // the job needed a session and there was none
    std::string version;
    std::string reply;
    std::wstring error;
    int stage = 0;
    DWORD win32 = 0;
};

v8i::UiJob g_job;
JobKind g_jobKind = JobKind::None;
JobOutcome g_jobOutcome;

// The buttons that start a job, plus the inputs, are off while it runs: a
// second injection or a command typed over the first one would fight for the
// same client.
void SetJobButtonsEnabled(bool enabled) {
    static const int kIds[] = { kIdRefresh, kIdInject, kIdDetach, kIdSend, kIdBrowse,
                                kIdGitbarShow, kIdGitbarHide, kIdGitbarSettings };
    for (int id : kIds) {
        HWND h = GetDlgItem(g_hwnd, id);
        if (!h) continue;
        BOOL on = enabled ? TRUE : FALSE;
        if (enabled && (id == kIdDetach || id == kIdSend)) on = g_client.IsOpen() ? TRUE : FALSE;
        EnableWindow(h, on);
    }
    HWND fields[] = { g_list, g_dllEdit, g_cmdEdit, g_filter };
    for (HWND h : fields) EnableWindow(h, enabled ? TRUE : FALSE);
}

// Runs on the worker thread. Opens the session when it is not open yet and
// then sends `command` (nullptr for none). With `reconnect` a session of
// another process is closed first: the user picked a different 1C. The UI
// thread reads nothing of the client while the job runs: its controls are
// disabled for the duration.
JobOutcome RunJobCalls(uint32_t pid, const std::wstring& dll, const wchar_t* command,
                       bool reconnect = false) {
    JobOutcome r;
    if (reconnect && g_client.IsOpen()) {
        if (!g_client.Close()) {
            // The payload did not leave; going on would open over a live
            // session. Say why instead.
            r.error = g_client.LastError();
            return r;
        }
    }
    if (!g_client.IsOpen()) {
        if (!pid) {
            r.noConnection = true;
            return r;
        }
        if (!g_client.Open(pid, dll, ExeDir(), 15000)) {
            r.error = g_client.LastError();
            r.stage = g_client.LastStage();
            r.win32 = g_client.LastWin32Error();
            return r;
        }
        r.fresh = true;
        r.versionOk = g_client.Call(L"version", r.version, 10000);
    }
    r.openOk = true;
    if (command) {
        // A157: cmd/cmd85/xref legitimately hold the 1C UI thread (cmd 45
        // keeps it inside its own modal dump dialog; the payload marshal
        // answers after its own ~30 s timeout). The flat 20 s here reported
        // "(нет ответа)" while the dialog was actually working in 1C -- the
        // CLI runs these same commands with 120 s for exactly this reason.
        const bool slow = wcsncmp(command, L"cmd ", 4) == 0 ||
                          wcsncmp(command, L"cmd85", 5) == 0 ||
                          wcsncmp(command, L"xref ", 5) == 0;
        r.callOk = g_client.Call(command, r.reply, slow ? 120000 : 20000);
        if (!r.callOk && r.error.empty()) r.error = g_client.LastError();
    }
    return r;
}

bool StartJob(JobKind kind, std::function<JobOutcome()> work) {
    if (g_job.Busy()) return false;
    g_jobKind = kind;
    g_jobOutcome = JobOutcome{};
    SetJobButtonsEnabled(false);
    if (!g_job.Start(g_hwnd, kMsgJobDone, [work]() { g_jobOutcome = work(); })) {
        g_jobKind = JobKind::None;
        SetJobButtonsEnabled(true);
        return false;
    }
    return true;
}

// Applies the outcome of the finished job, on the UI thread.
void OnJobDone() {
    const JobKind kind = g_jobKind;
    g_jobKind = JobKind::None;
    const JobOutcome r = g_jobOutcome;   // the join in Finish() made it visible
    if (!g_client.IsOpen()) g_sessionPid = 0;
    SetJobButtonsEnabled(true);

    switch (kind) {
    case JobKind::Inject:
        if (!r.openOk) {
            Log(std::wstring(L"ОШИБКА: ") + r.error);
            wchar_t diag[512];
            _snwprintf_s(diag, _countof(diag), _TRUNCATE, L"stage=%d win32=%lu\nlog: %s",
                         r.stage, r.win32, v8i::GetLogPath());
            Log(diag);
            SetStatus(L"Ошибка подключения");
            MessageBoxW(g_hwnd, diag, L"Не удалось подключиться", MB_ICONERROR);
        } else if (!r.fresh) {
            Log(L"Уже подключено: " + g_targetName);
            SetStatus(L"Подключено к " + g_targetName);
        } else if (r.versionOk) {
            g_sessionPid = g_targetPid;
            Log(L"Подключено: " + Utf8ToWide(r.version));
            SetStatus(L"Подключено к " + g_targetName);
        } else {
            g_sessionPid = g_targetPid;
            Log(L"Подключение прошло, но payload не ответил на version");
            SetStatus(L"Нет ответа от payload");
        }
        break;

    case JobKind::Detach:
        // A45: a command that is still running inside the target keeps the
        // payload alive until it returns; say so instead of reporting a clean
        // detach.
        if (r.callOk) {
            Log(L"Сессия закрыта");
        } else {
            Log(std::wstring(L"Сессия закрыта не полностью: ") + r.error);
        }
        SetStatus(L"Не подключено");
        g_targetPid = 0;
        break;

    case JobKind::Send:
        if (r.callOk) {
            Log(Utf8ToWide(r.reply));
        } else {
            Log(r.error.empty() ? std::wstring(L"(нет ответа)")
                                : (L"(нет ответа) " + r.error));
        }
        SetStatus(g_client.IsOpen() ? std::wstring(L"Подключено к ") + g_targetName
                                    : std::wstring(L"Не подключено"));
        break;

    case JobKind::GitbarShow:
    case JobKind::GitbarHide: {
        const bool show = kind == JobKind::GitbarShow;
        if (r.fresh && r.openOk) g_sessionPid = g_targetPid;
        if (r.noConnection) {
            MessageBoxW(g_hwnd,
                        show ? L"Нет подключения к процессу (выберите 1cv8.exe)."
                             : L"Сначала подключитесь к процессу.",
                        L"GitBar", MB_ICONINFORMATION);
        } else if (r.callOk) {
            Log(Utf8ToWide(r.reply));
            SetStatus(show ? L"GitBar: панель показана (payload остаётся в процессе)"
                           : L"GitBar: панель скрыта");
        } else {
            Log(L"(нет ответа)");
            SetStatus(L"GitBar: нет ответа");
        }
        break;
    }

    case JobKind::None:
        break;
    }
}

// The UI-side half of "connect to the selected process": picks the pid and the
// payload of that bitness. The blocking part runs on the job thread (A80).
bool PrepareTarget(uint32_t* pidOut, std::wstring* dllOut) {
    const uint32_t pid = SelectedPid();
    if (!pid) return false;

    wchar_t dllBuf[MAX_PATH] = {};
    GetWindowTextW(g_dllEdit, dllBuf, MAX_PATH);
    std::wstring dll = dllBuf;
    if (dll.empty()) {
        dll = DefaultPayloadFor(SelectedIs64());
        SetWindowTextW(g_dllEdit, dll.c_str());
    }
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) return false;

    g_targetPid = pid;
    g_targetName = SelectedName();

    wchar_t msg[512];
    _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"[%lu] %s — подключаюсь...",
                 g_targetPid, g_targetName.c_str());
    Log(msg);
    if (pidOut) *pidOut = pid;
    if (dllOut) *dllOut = dll;
    return true;
}

void DoInject() {
    if (g_job.Busy()) return;

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

    Log(L"------------------------------");
    g_targetPid = pid;
    g_targetName = SelectedName();

    wchar_t msg[512];
    _snwprintf_s(msg, _countof(msg), _TRUNCATE, L"[%lu] %s — подключаюсь...",
                 g_targetPid, g_targetName.c_str());
    Log(msg);
    SetStatus(L"Подключение...");

    // A session with another process is closed by the worker: injecting into
    // the second 1C must not keep talking to the first one.
    const bool reconnect = g_client.IsOpen() && g_sessionPid != pid;
    if (!StartJob(JobKind::Inject, [pid, dll, reconnect]() {
            return RunJobCalls(pid, dll, nullptr, reconnect);
        }))
        Log(L"Занято: предыдущая операция ещё выполняется");
}

void DoDetach() {
    if (g_job.Busy()) return;
    if (!g_client.IsOpen()) return;
    Log(L"Отключаюсь...");
    SetStatus(L"Отключаюсь...");
    if (!StartJob(JobKind::Detach, [] {
            JobOutcome r;
            r.callOk = g_client.Close();
            r.error = g_client.LastError();
            return r;
        }))
        Log(L"Занято: предыдущая операция ещё выполняется");
}

void DoSend() {
    if (g_job.Busy()) return;
    if (!g_client.IsOpen()) {
        MessageBoxW(g_hwnd, L"Сначала подключитесь к процессу.", L"v8inject",
                    MB_ICONINFORMATION);
        return;
    }
    wchar_t cmd[512] = {};
    GetWindowTextW(g_cmdEdit, cmd, 512);
    if (!cmd[0]) return;

    Log(std::wstring(L"> ") + cmd);
    SetStatus(L"Команда выполняется...");
    const std::wstring command = cmd;
    if (!StartJob(JobKind::Send,
                  [command]() { return RunJobCalls(0, std::wstring(), command.c_str()); }))
        Log(L"Занято: предыдущая операция ещё выполняется");
}

// ---------------------------------------------------------------------------
// GitBar: one-click show/hide of the in-process git toolbar, plus a settings
// dialog that writes the same %APPDATA%\v8inject\gitbar.ini the payload reads.
// ---------------------------------------------------------------------------

void DoGitbarShow() {
    if (g_job.Busy()) return;
    uint32_t pid = 0;
    std::wstring dll;
    if (!g_client.IsOpen() && !PrepareTarget(&pid, &dll)) {
        MessageBoxW(g_hwnd, L"Нет подключения к процессу (выберите 1cv8.exe).",
                    L"GitBar", MB_ICONINFORMATION);
        return;
    }
    Log(L"> gitbar");
    SetStatus(L"GitBar: показываю...");
    if (!StartJob(JobKind::GitbarShow,
                  [pid, dll]() { return RunJobCalls(pid, dll, L"gitbar"); }))
        Log(L"Занято: предыдущая операция ещё выполняется");
}

void DoGitbarHide() {
    if (g_job.Busy()) return;
    if (!g_client.IsOpen()) {
        MessageBoxW(g_hwnd, L"Сначала подключитесь к процессу.", L"GitBar",
                    MB_ICONINFORMATION);
        return;
    }
    Log(L"> gitbar hide");
    SetStatus(L"GitBar: скрываю...");
    if (!StartJob(JobKind::GitbarHide,
                  [] { return RunJobCalls(0, std::wstring(), L"gitbar hide"); }))
        Log(L"Занято: предыдущая операция ещё выполняется");
}

// Buttons notify their parent with a SENT WM_COMMAND, which a GetMessage pump
// never sees — the settings dialog therefore saves from its own window proc and
// the pump only waits for it to disappear.
struct GitBarSettingsCtx {
    HWND ed[4] = {};
    std::vector<UiField> fields;
    std::vector<v8i::UiAnchor> anchors;
    std::wstring iniPath;
    bool saved = false;
    std::wstring saveError;
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
            v8i::GitBarSettings s;
            s.gitPath = b[0];
            s.dumpDir = b[1];
            s.commitMessage = b[2];
            s.remote = b[3];
            // A64: through v8i::IniSet, which creates the folder of the file
            // and writes UTF-16 with a marker; "saved" is reported only when
            // every write succeeded.
            c->saved = v8i::SaveGitBarSettings(c->iniPath.c_str(), s, &c->saveError);
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
    case WM_DPICHANGED: {
        if (!c) break;
        const int dpi = (int)HIWORD(wp);
        const RECT* suggested = (const RECT*)lp;
        SetWindowPos(h, nullptr, suggested->left, suggested->top,
                     suggested->right - suggested->left,
                     suggested->bottom - suggested->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        if (dpi >= 48) {
            // The fonts of the thread are rebuilt by the handler of the main
            // window for the same change; the places follow here (A81).
            v8i::ApplyAnchors(c->anchors, dpi);
            RelayoutFieldsIn(c->fields, dpi);
        }
        InvalidateRect(h, nullptr, TRUE);
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    }
    return DefDlgProcW(h, msg, wp, lp);
}

void DoGitbarSettings() {
    const int dpi = g_dpi;
    const auto S = [dpi](int v) { return v8i::DpiScale(v, dpi); };

    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"#32770", L"GitBar — настройки",
                               WS_CAPTION | WS_SYSMENU | WS_OVERLAPPED | WS_VISIBLE |
                                   WS_CLIPCHILDREN,
                               CW_USEDEFAULT, CW_USEDEFAULT, S(460), S(226), g_hwnd, nullptr,
                               GetModuleHandleW(nullptr), nullptr);
    if (!dlg) return;

    GitBarSettingsCtx ctx;
    ctx.iniPath = v8i::GitBarIniPath();
    SetWindowLongPtrW(dlg, GWLP_WNDPROC, (LONG_PTR)GitBarSettingsProc);
    SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)&ctx);

    auto Lbl = [&](int y, const wchar_t* t) {
        HWND s = CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT,
                                 S(12), S(y), S(140), S(18), dlg, nullptr,
                                 GetModuleHandleW(nullptr), nullptr);
        SendMessageW(s, WM_SETFONT, (WPARAM)UiFont(), TRUE);
        ctx.anchors.push_back({ s, 12, y, 140, 18 });
    };
    auto Edt = [&](int cellY, int cellW) {
        HWND e = CreateWindowExW(0, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                 0, 0, 0, 0, dlg, nullptr, GetModuleHandleW(nullptr), nullptr);
        SendMessageW(e, WM_SETFONT, (WPARAM)UiFont(), TRUE);
        TrackFieldIn(ctx.fields, e, 158, cellY, cellW, 24);
        PlaceFieldIn(ctx.fields, e, 158, cellY, cellW, 24, dpi);
        return e;
    };
    auto Btn = [&](int id, const wchar_t* text, int x, int y, int w, int h2) {
        HWND b = CreateUiButton(dlg, id, text, x, y, w, h2, dpi);
        ctx.anchors.push_back({ b, x, y, w, h2 });
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
    Btn(2001, L"...", 414, 44, 28, 22);
    Btn(IDOK, L"OK", 158, 150, 90, 26);
    Btn(IDCANCEL, L"Отмена", 258, 150, 90, 26);

    // Prefill: current values, or a sensible git default.
    v8i::GitBarSettings s = v8i::LoadGitBarSettings(ctx.iniPath.c_str());
    if (s.gitPath.empty() && GetFileAttributesW(L"C:\\Program Files\\Git\\cmd\\git.exe")
                                 != INVALID_FILE_ATTRIBUTES) {
        s.gitPath = L"C:\\Program Files\\Git\\cmd\\git.exe";
    }
    SetWindowTextW(ctx.ed[0], s.gitPath.c_str());
    SetWindowTextW(ctx.ed[1], s.dumpDir.c_str());
    SetWindowTextW(ctx.ed[2], s.commitMessage.c_str());
    SetWindowTextW(ctx.ed[3], s.remote.c_str());

    SetForegroundWindow(dlg);
    SetFocus(ctx.ed[0]);

    // A61: the owner is disabled for the duration of the dialog, and a WM_QUIT
    // that arrives meanwhile goes back to the loop of the main window instead
    // of being eaten here.
    v8i::PumpOwnedModalLoop(dlg, g_hwnd);
    if (IsWindow(dlg)) DestroyWindow(dlg);

    if (ctx.saved) {
        Log(L"Настройки GitBar сохранены в " + ctx.iniPath);
    } else if (!ctx.saveError.empty()) {
        Log(L"Настройки GitBar НЕ сохранены: " + ctx.saveError);
    }
}

// The list columns are fixed widths in 96-DPI units: they follow the DPI of the
// monitor, and the row image list keeps the rows at 18 units.
struct ListCol { const wchar_t* text; int width; };
const ListCol kListCols[] = {
    { L"PID", 70 }, { L"Имя", 200 }, { L"Разр.", 60 }, { L"Путь", 420 }
};

void LayoutListColumns(int dpi) {
    if (!g_list) return;
    for (int i = 0; i < _countof(kListCols); ++i)
        ListView_SetColumnWidth(g_list, i, v8i::DpiScale(kListCols[i].width, dpi));
}

void RecreateRowImageList(int dpi) {
    if (!g_list) return;
    // A 1px image list is only there to keep the rows at 1C-ish 18px.
    HIMAGELIST rowH = ImageList_Create(1, v8i::DpiScale(18, dpi), ILC_COLOR32, 1, 1);
    if (!rowH) return;
    HIMAGELIST old = ListView_SetImageList(g_list, rowH, LVSIL_SMALL);
    if (old) ImageList_Destroy(old);
}

void CreateControls(HWND hwnd) {
    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);
    const auto S = [](int v) { return v8i::DpiScale(v, g_dpi); };

    auto Lbl = [&](int y, int w, const wchar_t* t) {
        HWND s = CreateWindowExW(0, L"STATIC", t, WS_CHILD | WS_VISIBLE | SS_LEFT,
                                 S(12), S(y), S(w), S(20), hwnd, nullptr, hInst, nullptr);
        SendMessageW(s, WM_SETFONT, (WPARAM)UiFont(), TRUE);
        Anchor(s, 12, y, w, 20);
        return s;
    };

    Lbl(12, 80, L"Процесс:");

    g_filter = CreateWindowExW(0, L"EDIT", L"",
                               WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                               0, 0, 0, 0, hwnd, (HMENU)(UINT_PTR)kIdFilter, hInst, nullptr);
    SendMessageW(g_filter, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    SendMessageW(g_filter, EM_SETCUEBANNER, TRUE, (LPARAM)L"фильтр по имени");
    TrackField(g_filter, 96, 9, 220, 24);
    PlaceField(g_filter, 96, 9, 220, 24);

    Anchor(CreateUiButton(hwnd, kIdRefresh, L"Обновить", 324, 9, 90, 26, g_dpi),
           324, 9, 90, 26);

    g_list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
                                 LVS_SHOWSELALWAYS,
                             0, 0, 0, 0, hwnd, (HMENU)(UINT_PTR)kIdList, hInst, nullptr);
    ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    SendMessageW(g_list, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    ListView_SetBkColor(g_list, kUiFieldBg);
    ListView_SetTextBkColor(g_list, kUiFieldBg);
    ListView_SetTextColor(g_list, kUiText);

    for (int i = 0; i < _countof(kListCols); ++i) {
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        c.pszText = (LPWSTR)kListCols[i].text;
        c.cx = v8i::DpiScale(kListCols[i].width, g_dpi);
        c.iSubItem = i;
        ListView_InsertColumn(g_list, i, &c);
    }
    SendMessageW(ListView_GetHeader(g_list), WM_SETFONT, (WPARAM)UiFontBold(), TRUE);
    TrackField(g_list, 12, 44, 760, 240);
    PlaceField(g_list, 12, 44, 760, 240);

    Lbl(294, 80, L"Payload DLL:");
    g_dllEdit = CreateWindowExW(0, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                0, 0, 0, 0, hwnd, (HMENU)(UINT_PTR)kIdDllEdit, hInst, nullptr);
    SendMessageW(g_dllEdit, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    TrackField(g_dllEdit, 96, 291, 560, 24);
    PlaceField(g_dllEdit, 96, 291, 560, 24);

    // The browse and send buttons follow the right edge, so LayoutMain places
    // them; the rest of the row is fixed.
    CreateUiButton(hwnd, kIdBrowse, L"...", 662, 291, 32, 26, g_dpi);

    Anchor(CreateUiButton(hwnd, kIdInject, L"Инжектировать", 12, 324, 150, 30, g_dpi),
           12, 324, 150, 30);

    HWND detach = CreateUiButton(hwnd, kIdDetach, L"Отключиться", 170, 324, 120, 30, g_dpi);
    EnableWindow(detach, FALSE);
    Anchor(detach, 170, 324, 120, 30);

    Anchor(CreateUiButton(hwnd, kIdGitbarShow, L"GitBar: показать", 298, 324, 130, 30, g_dpi),
           298, 324, 130, 30);
    Anchor(CreateUiButton(hwnd, kIdGitbarHide, L"скрыть", 434, 324, 70, 30, g_dpi),
           434, 324, 70, 30);
    Anchor(CreateUiButton(hwnd, kIdGitbarSettings, L"Настройки", 510, 324, 100, 30, g_dpi),
           510, 324, 100, 30);

    g_cmdEdit = CreateWindowExW(0, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                0, 0, 0, 0, hwnd, (HMENU)(UINT_PTR)kIdCommand, hInst, nullptr);
    SendMessageW(g_cmdEdit, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    SendMessageW(g_cmdEdit, EM_SETCUEBANNER, TRUE,
                 (LPARAM)L"objects | pe | peek <addr> [len] | scan <addr>");
    TrackField(g_cmdEdit, 12, 364, 560, 26);
    PlaceField(g_cmdEdit, 12, 364, 560, 26);

    HWND send = CreateUiButton(hwnd, kIdSend, L"Отправить", 580, 364, 100, 26, g_dpi);
    EnableWindow(send, FALSE);

    g_log = CreateWindowExW(0, L"EDIT", L"",
                            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL |
                                ES_READONLY | WS_VSCROLL,
                            0, 0, 0, 0, hwnd, (HMENU)(UINT_PTR)kIdLog, hInst, nullptr);
    SendMessageW(g_log, WM_SETFONT, (WPARAM)UiFont(), TRUE);
    SendMessageW(g_log, EM_SETLIMITTEXT, 0, 0);
    TrackField(g_log, 12, 398, 760, 220);
    PlaceField(g_log, 12, 398, 760, 220);

    g_status = CreateWindowExW(0, L"STATIC", L"Не подключено",
                               WS_CHILD | WS_VISIBLE | SS_LEFT,
                               0, 0, 0, 0, hwnd, (HMENU)(UINT_PTR)kIdStatus, hInst, nullptr);
    SendMessageW(g_status, WM_SETFONT, (WPARAM)UiFont(), TRUE);

    RecreateRowImageList(g_dpi);

    // The GUI runs in UTF-8; the payload replies in UTF-8 too.
    SetConsoleOutputCP(CP_UTF8);
}

// Places everything that depends on the size of the window - and, after a DPI
// change, everything else - for the DPI of the current monitor (A81).
void LayoutMain() {
    if (!g_list) return;
    const int dpi = g_dpi;
    const auto S = [dpi](int v) { return v8i::DpiScale(v, dpi); };

    RECT rc;
    GetClientRect(g_hwnd, &rc);
    const int pw = rc.right - rc.left;
    const int ph = rc.bottom - rc.top;
    // The layout is written for 96-DPI pixels, so the client size is converted
    // back to them before the fixed boxes are computed.
    const int w = MulDiv(pw, 96, dpi);
    const int h = MulDiv(ph, 96, dpi);

    v8i::ApplyAnchors(g_anchors, dpi);
    PlaceField(g_list, 12, 44, w - 24, 240);
    PlaceField(g_dllEdit, 96, 291, w - 24 - 96 - 44, 24);
    SetWindowPos(GetDlgItem(g_hwnd, kIdBrowse), nullptr, S(w - 24 - 40), S(291), S(32),
                 S(26), SWP_NOZORDER | SWP_NOACTIVATE);
    PlaceField(g_cmdEdit, 12, 364, w - 24 - 112, 26);
    SetWindowPos(GetDlgItem(g_hwnd, kIdSend), nullptr, S(w - 24 - 100), S(364), S(100),
                 S(26), SWP_NOZORDER | SWP_NOACTIVATE);
    PlaceField(g_log, 12, 398, w - 24, h - 398 - 34);
    SetWindowPos(g_status, nullptr, S(12), ph - S(26), pw - S(24), S(20),
                 SWP_NOZORDER | SWP_NOACTIVATE);
    InvalidateRect(g_hwnd, nullptr, TRUE);
}
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        g_hwnd = hwnd;
        // The DPI of the monitor the window opened on: the fonts and every
        // coordinate of the layout are built from it (A81).
        g_dpi = v8i::WindowDpi(hwnd);
        // The form opens at 800x700 units. Created at 800x700 physical pixels
        // it would be smaller than the minimum size at 150%.
        SetWindowPos(hwnd, nullptr, 0, 0, v8i::DpiScale(800, g_dpi),
                     v8i::DpiScale(700, g_dpi), SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        ResetUiFonts(g_dpi);
        CreateControls(hwnd);
        LayoutListColumns(g_dpi);
        LayoutMain();
        RefreshProcesses();
        return 0;

    case WM_SIZE:
        LayoutMain();
        return 0;

    case WM_DPICHANGED: {
        // Moved to a monitor with another DPI. Windows hands over a suggested
        // rectangle; the layout, the fonts and the list follow (A81).
        const int dpi = (int)HIWORD(wp);
        const RECT* suggested = (const RECT*)lp;
        if (dpi >= 48) g_dpi = dpi;
        SetWindowPos(hwnd, nullptr, suggested->left, suggested->top,
                     suggested->right - suggested->left,
                     suggested->bottom - suggested->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        ResetUiFonts(g_dpi);
        LayoutListColumns(g_dpi);
        RecreateRowImageList(g_dpi);
        RelayoutFieldsIn(g_fields, g_dpi);
        LayoutMain();
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);
        // The 1C form separates its status line with a single border.
        HPEN pen = CreatePen(PS_SOLID, 1, kUiBorder);
        HGDIOBJ op = SelectObject(dc, pen);
        const int x = v8i::DpiScale(12, g_dpi);
        MoveToEx(dc, x, rc.bottom - v8i::DpiScale(32, g_dpi), nullptr);
        LineTo(dc, rc.right - x, rc.bottom - v8i::DpiScale(32, g_dpi));
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
        // The button row (12..610) plus the 1C-like side margins, in 96-DPI
        // units like the rest of the layout.
        mmi->ptMinTrackSize.x = v8i::DpiScale(640, g_dpi);
        mmi->ptMinTrackSize.y = v8i::DpiScale(560, g_dpi);
        return 0;
    }

    case kMsgJobDone:
        if (g_job.Finish(wp, kMsgJobDone)) OnJobDone();
        return 0;

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
        // The job may be holding the client and the target process: wait for it
        // before the client goes away (A80).
        g_job.Stop();
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
