#pragma once
// DPI scaling of the GUI layout.
//
// The GUI is per-monitor DPI aware (v2), so Windows does not scale it: the
// layout is written in 96-DPI units and every coordinate is multiplied by the
// DPI of the window's monitor. Without that the boxes kept their 96-DPI size
// while the font grew, and the text was clipped at 150-200% (A81).

#include <windows.h>
#include <vector>

namespace v8i {

// `px` 96-DPI units to physical pixels. A missing/zero DPI means 96.
int DpiScale(int px, int dpi);

// Physical rect of a rect given in 96-DPI units.
RECT ScaleRect(const RECT& base, int dpi);

// The DPI of the window's monitor. Falls back to the system DPI and then to 96
// (GetDpiForWindow needs Windows 10 1607; the tool runs on what it finds).
int WindowDpi(HWND hwnd);

// A control at a fixed place of the form: x/y/w/h are 96-DPI units.
struct UiAnchor {
    HWND hwnd = nullptr;
    int x = 0, y = 0, w = 0, h = 0;
};

// Moves every control to its scaled place. Used on WM_SIZE-like relayouts, and
// once again after WM_DPICHANGED.
void ApplyAnchors(const std::vector<UiAnchor>& anchors, int dpi);

}  // namespace v8i
