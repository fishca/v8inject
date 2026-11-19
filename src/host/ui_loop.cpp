#include "ui_loop.h"

namespace v8i {

int PumpOwnedModalLoop(HWND dialog, HWND owner, bool dialogKeys) {
    bool ownerDisabled = false;
    if (owner && IsWindow(owner) && IsWindowEnabled(owner)) {
        EnableWindow(owner, FALSE);
        ownerDisabled = true;
    }

    int result = 0;
    MSG msg{};
    for (;;) {
        if (!IsWindow(dialog)) break;
        const BOOL got = GetMessageW(&msg, nullptr, 0, 0);
        if (got == 0) {
            // WM_QUIT belongs to the loop of the main window. Re-post it: the
            // old loop broke out and left that loop without a window and
            // without a quit (A61).
            result = (int)msg.wParam;
            PostQuitMessage(result);
            break;
        }
        if (got == (BOOL)-1) break;   // the queue is broken; nothing left to pump
        // IsDialogMessageW gives Tab, the default button and Esc for free; it
        // dispatches itself, so a consumed message must not be dispatched again.
        if (dialogKeys && IsDialogMessageW(dialog, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (ownerDisabled && IsWindow(owner)) EnableWindow(owner, TRUE);
    return result;
}

}  // namespace v8i
