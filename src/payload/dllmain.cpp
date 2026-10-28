#include <windows.h>

// Exported by the payload (C linkage, v8i_export.cpp): arms the WH_CBT hook
// that catches the creation of the 1C main window. Called from DllMain so the
// hook exists before the window appears — the session (v8i_probe) starts much
// later and would miss it.
extern "C" void V8iArmEarly();

// The payload is started on a remote thread created by the host. Windows ends
// that thread as soon as it returns, and with it the whole process (for the
// thread we own) -- so DllMain spawns a worker and the exported v8i_probe
// blocks forever. Everything that matters happens on the worker.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // No logging here: during 1C start-up the process is barely alive, and
        // anything heavier than SetWindowsHookEx risks a fault inside the
        // loader lock (a callback exception there terminates 1C, 0xC000041D).
        V8iArmEarly();
    }
    return TRUE;
}
