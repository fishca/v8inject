#include <windows.h>

// Exported by the payload (C linkage): arms the startup window watcher and
// the win32u window-creation hook right after injection, before 1C creates
// its main window.
extern "C" void V8iArmStartup();

// The payload is started on a remote thread created by the host. Windows ends
// that thread as soon as it returns, and with it the whole process (for the
// thread we own) -- so DllMain spawns a worker and the exported v8i_probe
// blocks forever. Everything that matters happens on the worker.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // Probe: proves DllMain ran even if the arming path fails.
        {
            wchar_t p[MAX_PATH];
            if (GetTempPathW(MAX_PATH, p)) {
                lstrcatW(p, L"v8i_dllmain.txt");
                HANDLE h = CreateFileW(p, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h != INVALID_HANDLE_VALUE) {
                    DWORD wr = 0;
                    WriteFile(h, "dllmain ok\n", 11, &wr, nullptr);
                    CloseHandle(h);
                }
            }
        }
        V8iArmStartup();
    }
    return TRUE;
}
