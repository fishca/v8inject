#include <windows.h>

// The payload is started on a remote thread created by the host. Windows ends
// that thread as soon as it returns, and with it the whole process (for the
// thread we own) -- so DllMain spawns a worker and the exported v8i_probe
// blocks forever. Everything that matters happens on the worker.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}
