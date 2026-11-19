#pragma once

#include <windows.h>
#include <string>

namespace v8i {
namespace gitbar {

// Shared 1C-style window theme: the classic cream platform-dialog skin measured
// from a live «Выгрузить файлы конфигурации» dialog — cream face, beige buttons
// with a 1px #B3AC86 frame, white fields, rust field captions and a light-blue
// list selection. Used by the bar, settings, prompt, list and history windows.
constexpr COLORREF kDlgBg      = RGB(252, 250, 235);   // FCFAEB dialog face
constexpr COLORREF kDlgBorder  = RGB(179, 172, 134);   // B3AC86 group / button frame
constexpr COLORREF kDlgFieldBg = RGB(255, 255, 255);
constexpr COLORREF kDlgFieldBorder = RGB(141, 141, 141);  // 8D8D8D edit frame
constexpr COLORREF kDlgBtnFace = RGB(215, 211, 189);   // D7D3BD button face
constexpr COLORREF kDlgHover   = RGB(252, 250, 196);   // FCFAC4 pale-yellow hover
constexpr COLORREF kDlgPress   = RGB(205, 199, 171);
constexpr COLORREF kDlgText    = RGB(51, 51, 51);      // 333333
constexpr COLORREF kDlgLabel   = RGB(158, 82, 42);     // 9E522A rust field caption
constexpr COLORREF kDlgSel     = RGB(158, 216, 235);   // 9ED8EB light-blue selection
constexpr COLORREF kDlgSelIdle = RGB(212, 208, 200);
constexpr COLORREF kDlgCaption = RGB(204, 204, 204);   // CCCCCC classic caption band
constexpr int kCapH = 22;                              // caption height, as in 1C dialogs

// Main-menu row and dropdown-submenu palette, sampled from the live designer's
// «Администрирование» dropdown.
constexpr COLORREF kMenuBg         = RGB(248, 247, 238);  // F8F7EE menu face
constexpr COLORREF kMenuText       = RGB(65, 48, 3);      // 413003 dark-brown item
constexpr COLORREF kMenuHoverBorder = RGB(158, 182, 233); // 9EB6E9
constexpr COLORREF kMenuHoverText  = RGB(61, 78, 143);    // 3D4E8F
constexpr COLORREF kSubShortcut    = RGB(179, 128, 0);    // B38000 shortcut column
constexpr COLORREF kSubSep         = RGB(217, 213, 194);  // D9D5C2 separator line
constexpr COLORREF kSubGutterBg    = RGB(233, 229, 206);  // E9E5CE icon column strip
constexpr int kSubItemH = 22;
constexpr int kSubSepH = 7;
constexpr int kSubGutter = 28;   // icon column, as in 1C submenus
constexpr int kSubTextX = kSubGutter + 6;   // labels start 6 px past the strip

RECT CapCloseRect(const RECT& rc);

// The platform draws its dialog captions itself; our windows are plain Win32,
// so the gray band with the title and the X is painted in the client area.
void DrawCaption(HDC dc, HWND h, HFONT font, bool hoverX);

// WS_POPUP ignores CW_USEDEFAULT, so place the dialog over its owner frame.
void CenterOnOwner(HWND h, HWND owner);

// Dragging by the painted caption; the X stays a client hit so the window proc
// can close on WM_LBUTTONDOWN. Sizing borders keep their default hit codes.
LRESULT CapHitTest(HWND h, WPARAM wp, LPARAM lp);

HFONT CreateDlgFont();
HBRUSH UiBgBrush();
HBRUSH UiMenuBrush();
HBRUSH UiGutterBrush();
HBRUSH UiFieldBrush();
void UiFrame(HDC dc, const RECT& rc, COLORREF color);
void UiDrawButton(HDC dc, const RECT& rc, const wchar_t* text, HFONT font,
                  bool hover, bool press);

// Mix `fg` over `bg`: alpha 255 keeps fg, 0 returns bg. Used for disabled
// menu text and for accents that must sit on the cream face.
COLORREF Blend(COLORREF fg, COLORREF bg, int alpha);

// Pale-blue rounded hover with a vertical gradient, as in 1C submenus. Shared
// by the action popup and the main-menu overlay replicas.
void DrawSubHover(HDC dc, const RECT& rc);

// The bar's owner-drawn action popup (defined in gitbar.cpp). The main-menu
// overlay opens the same list and routes its WM_MEASUREITEM / WM_DRAWITEM
// through the same handlers.
void ShowActionMenu(HWND owner);
void ActionMenuMeasure(LPMEASUREITEMSTRUCT m);
void ActionMenuDraw(LPDRAWITEMSTRUCT d);

// >0 while one of the panel's modal dialogs pumps its own message loop; the
// main-menu overlay hides then, it would float over the dialog otherwise.
// Defined in gitbar.cpp.
extern int g_modalDepth;

// Ownerdraw buttons would otherwise stay flat grey: the subclass only tracks
// hover (the press state arrives as ODS_SELECTED) and redraws on change.
void ThemedButton(HWND btn, HFONT font);
bool UiDrawOwnerButton(const DRAWITEMSTRUCT* dis, HFONT font);

// One-field modal prompt (commit message): state and window proc. The dialog
// itself (PromptText) lives in gitbar.cpp, next to the bar's modal state.
struct PromptCtx {
    std::wstring* out = nullptr;
    HWND ed = nullptr;
    HFONT font = nullptr;
    bool accepted = false;
    bool hoverX = false;
    bool trackedLeave = false;
};

LRESULT CALLBACK PromptDlgProc(HWND h, UINT msg, WPARAM wp, LPARAM lp);

// Modal windows of the panel. The main-menu overlay is a separate top-level
// window and would otherwise float above a dialog, so it hides while one is up;
// the bar is repositioned once the dialog closes. Implemented in gitbar.cpp.
void ModalEnter();
void ModalLeave(bool forceDock);

// Pumps this thread's messages until `dlg` is gone or WM_QUIT arrives. The quit
// is re-posted, so the bar's own loop still sees it and the thread ends: the
// hand-rolled loops used to `break` on WM_QUIT and swallow it, which left the
// bar thread alive with a dead window -- `gitbar hide` during a dialog made the
// panel impossible to show again and kept the "GitBar" menu overlay alive
// (A55). Returns the re-posted quit code, 0 when the dialog simply closed.
int PumpModalLoop(HWND dlg, bool dialogKeys = false);

// Brings the bar back above the configurator frame after an action redraws a
// dialog (the list windows call it after every git operation).
void BarReposition(bool forceDock);

// Bar action reused by dialogs: the working-copy list's "Commit" button.
void RunCommitAction();

}  // namespace gitbar
}  // namespace v8i
