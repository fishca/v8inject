#include "git_lists.h"

#include "git_service.h"
#include "git_ui.h"

#include <windows.h>
#include <string>
#include <vector>

namespace v8i {
namespace gitbar {

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

// Porcelain v1 lines are "XY PATH": both status columns are always present (the
// second one is the unstaged column), then exactly one space, then the path.
// Cutting at the first space instead took " M path" -- a file changed but not
// staged, the normal state of a dump -- apart at index 0 and handed "M path" to
// git add/reset/checkout, which answered "pathspec did not match any files"
// (A54). The path is not trimmed: leading/trailing spaces can belong to a name.
std::wstring PorcelainPath(const std::wstring& line) {
    if (line.size() < 4 || line[2] != L' ') return L"";
    std::wstring path = line.substr(3);
    const size_t arrow = path.find(L" -> ");   // "R  old -> new": git takes the new one
    if (arrow != std::wstring::npos) path = path.substr(arrow + 4);
    return path;
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
    // An empty list is ambiguous: a clean working copy and a git that failed to
    // run look exactly the same. Say which one it is. The row is display-only —
    // d->items stays the source the selection and the buttons read.
    if (d->items.empty()) {
        const wchar_t* hint = d->kind == 0 ? L"Изменений нет: рабочая копия совпадает с HEAD"
                             : d->kind == 1 ? L"Веток не найдено"
                             : d->kind == 2 ? L"Отложенных изменений нет"
                                            : L"Тегов нет";
        SendMessageW(d->list, LB_ADDSTRING, 0, (LPARAM)hint);
    } else {
        SendMessageW(d->list, LB_SETCURSEL, 0, 0);
    }
}

// Selected item with the porcelain status prefix stripped (for file paths).
static std::wstring ListDlgSel(ListDlg* d) {
    int sel = (int)SendMessageW(d->list, LB_GETCURSEL, 0, 0);
    if (sel < 0 || sel >= (int)d->items.size()) return L"";
    std::wstring line = d->items[sel];
    if (d->kind == 0) return PorcelainPath(line);
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

// One writing command of the list. A stopped git (deadline or output cap) says so
// in words; before, it looked like a silent success because only the text was
// inspected (A76).
static void ListDlgReport(HWND h, const GitResult& r) {
    if (!r.started) return;   // nothing ran (a branch that only asks a question)
    if (!r.Finished()) {
        MessageBoxW(h, GitFailureText(r, kGitTimeoutMs).c_str(), L"Git", MB_ICONWARNING);
        return;
    }
    const std::wstring out = TrimWs(r.out);
    if (!out.empty() && out.find(L"fatal") != std::wstring::npos)
        MessageBoxW(h, out.c_str(), L"Git", MB_ICONWARNING);
}

static void ListDlgAct(ListDlg* d, int btn) {
    std::wstring sel = ListDlgSel(d);
    if (sel.empty()) return;
    GitResult r;
    switch (d->kind) {
    case 0:  // working copy
        if (btn == 0) r = RunGitEx({ L"-C", d->dir, L"add", L"--", sel });
        else if (btn == 1) r = RunGitEx({ L"-C", d->dir, L"reset", L"HEAD", L"--", sel });
        else if (btn == 2) {
            if (!ConfirmDestructive(d->h, L"Отменить изменения в файле (правки будут потеряны):", sel))
                return;
            r = RunGitEx({ L"-C", d->dir, L"checkout", L"--", sel });
        }
        break;
    case 1:  // branches
        if (btn == 0) {
            // A134: `branch -a` lists remotes/origin/... too; checking one out
            // "succeeds" (exit code 0) into a detached HEAD and the panel said
            // nothing -- the next commit landed outside any branch and looked
            // lost. A remote ref is refused with the local way to get there.
            if (sel.rfind(L"remotes/", 0) == 0) {
                MessageBoxW(d->h,
                            (L"«" + sel + L"» — ветка удалённого репозитория, переключиться на неё напрямую нельзя (detached HEAD).\n"
                             L"Создайте локальную ветку от неё: git checkout -b <имя> " + sel).c_str(),
                            L"Git", MB_ICONINFORMATION);
                return;
            }
            r = RunGitEx({ L"-C", d->dir, L"checkout", sel });
            // A134: the checkout's own words (Switched to branch / Already on)
            // belong to the user -- silence read as "did nothing".
            const std::wstring said = TrimWs(r.out);
            if (r.Finished() && !said.empty())
                MessageBoxW(d->h, said.c_str(), L"Git", MB_ICONINFORMATION);
        }
        else if (btn == 1) {
            if (!ConfirmDestructive(d->h, L"Удалить ветку:", sel)) return;
            r = RunGitEx({ L"-C", d->dir, L"branch", L"-d", sel });
        }
        break;
    case 2:  // stashes
        if (btn == 0) r = RunGitEx({ L"-C", d->dir, L"stash", L"pop", sel });
        else if (btn == 1) {
            if (!ConfirmDestructive(d->h, L"Удалить отложенные изменения:", sel)) return;
            r = RunGitEx({ L"-C", d->dir, L"stash", L"drop", sel });
        }
        break;
    default:  // tags
        if (btn == 0) {
            if (!ConfirmDestructive(d->h, L"Удалить тег:", sel)) return;
            r = RunGitEx({ L"-C", d->dir, L"tag", L"-d", sel });
        }
        else if (btn == 1) r = RunGitEx({ L"-C", d->dir, L"push", L"origin", sel });
        break;
    }
    ListDlgReport(d->h, r);
    ListDlgFill(d);
    BarReposition(false);
}

static void ListDlgDrawItem(const DRAWITEMSTRUCT* dis, HFONT font) {
    bool sel = (dis->itemState & ODS_SELECTED) != 0;
    bool focus = GetFocus() == dis->hwndItem;
    COLORREF face = sel ? (focus ? kDlgSel : kDlgSelIdle) : kDlgFieldBg;
    HBRUSH b = CreateSolidBrush(face);
    FillRect(dis->hDC, &dis->rcItem, b);
    DeleteObject(b);
    if (dis->itemID == (UINT)-1) return;   // just the empty tail of the list

    // A131: the listbox contract gives no terminator guarantee when the buffer
    // is smaller than the item -- ask for the length and draw from a buffer
    // that certainly holds it. Paths of a deep dump, stash subjects and
    // annotated tags go past 1023 characters; DrawTextW(-1) then walked off
    // the stack buffer.
    const int textLen = (int)SendMessageW(dis->hwndItem, LB_GETTEXTLEN, dis->itemID, 0);
    if (textLen < 0) return;
    std::wstring text((size_t)textLen + 1, L'\0');
    SendMessageW(dis->hwndItem, LB_GETTEXT, dis->itemID, (LPARAM)&text[0]);
    text.resize((size_t)textLen);
    RECT row = dis->rcItem;
    row.left += 4;
    HGDIOBJ oldFont = SelectObject(dis->hDC, font);
    int oldMode = SetBkMode(dis->hDC, TRANSPARENT);
    SetTextColor(dis->hDC, kDlgText);
    DrawTextW(dis->hDC, text.c_str(), -1, &row,
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
                if (idx == 3) { RunCommitAction(); ListDlgFill(d); }
                else if (idx == 4) {
                    const GitResult r = RunGitEx({ L"-C", d->dir, L"commit", L"--amend", L"--no-edit" });
                    const std::wstring out = r.Finished() ? TrimWs(r.out)
                                                          : GitFailureText(r, kGitTimeoutMs);
                    MessageBoxW(h, out.c_str(), L"Amend", MB_ICONINFORMATION);
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

void ShowList(HWND owner, int kind) {
    std::wstring dir = GitIniGet(L"dumpdir");
    if (dir.empty()) {
        MessageBoxW(owner, L"Сначала укажите папку выгрузки в настройках GitBar.",
                    L"Git", MB_ICONINFORMATION);
        return;
    }
    if (GetFileAttributesW((dir + L"\\.git").c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(owner, (L"В папке выгрузки нет git-репозитория:\n" + dir).c_str(),
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
    // The title names the repository the list belongs to. It used to be a
    // hardcoded "— v8inject" (the author's own project), which is wrong on
    // every other machine and says nothing about which folder is being read.
    const wchar_t* caption = kind == 0 ? L"Рабочая копия"
                            : kind == 1 ? L"Ветки"
                            : kind == 2 ? L"Stash"
                                        : L"Теги";
    const size_t slash = dir.find_last_of(L"\\/");
    const std::wstring leaf = slash == std::wstring::npos ? dir : dir.substr(slash + 1);
    const std::wstring title = std::wstring(caption) + L" — " + leaf;
    ListDlg* d = new ListDlg();
    d->dir = dir;
    d->kind = kind;
    d->font = CreateDlgFont();
    HWND h = CreateWindowExW(WS_EX_DLGMODALFRAME, L"V8iGitList", title.c_str(),
                             WS_POPUP | WS_THICKFRAME | WS_VISIBLE,
                             CW_USEDEFAULT, CW_USEDEFAULT, 760, 480 + kCapH,
                             owner, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!h) { DeleteObject(d->font); delete d; return; }
    CenterOnOwner(h, owner);
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

    ModalEnter();
    PumpModalLoop(h, false);
    if (IsWindow(h)) DestroyWindow(h);
    if (d->font) DeleteObject(d->font);
    delete d;
    ModalLeave(false);
}

}  // namespace gitbar
}  // namespace v8i
