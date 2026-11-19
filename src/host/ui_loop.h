#pragma once
// The modal message loop of the GUI: one window on top, the owner switched off.
//
// The settings dialog of the GUI ran its own `GetMessageW` loop for every
// window of the thread and swallowed the WM_QUIT of the main window's
// WM_DESTROY: the main loop then blocked forever on a queue that had no
// windows left, and the process stayed as a zombie without a window (A61).

#include <windows.h>

namespace v8i {

// Pumps this thread's messages until `dialog` is gone. `owner` is disabled
// while the dialog is up, so the buttons of the main window cannot start an
// injection behind the dialog. A WM_QUIT that arrives meanwhile is re-posted
// for the outer loop instead of being eaten. Returns the re-posted quit code,
// 0 when the dialog simply closed.
int PumpOwnedModalLoop(HWND dialog, HWND owner, bool dialogKeys = true);

}  // namespace v8i
