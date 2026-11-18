#pragma once

#include <windows.h>

namespace v8i {
namespace gitbar {

// Main-menu overlay: the «GitBar» replica painted into the designer's menu row
// (git_menu.cpp). Driven by the bar's 500 ms reposition tick; a null or hidden
// frame hides the overlay.
void MenuReposition(HWND frame);
void MenuShutdown();
LRESULT CALLBACK MenuWndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp);

}  // namespace gitbar

// Called from mainmenu.cpp once the platform really painted the native item:
// the row replica becomes redundant.
void V8iGitBarSetNativeMenu();

}  // namespace v8i