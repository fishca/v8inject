#include <windows.h>
#include <wchar.h>

// Exported by the payload (C linkage, v8i_export.cpp): arms the WH_CBT hook
// that catches the creation of the 1C main window. Called from DllMain so the
// hook exists before the window appears — the session (v8i_probe) starts much
// later and would miss it.
extern "C" void V8iArmEarly();

// AppInit_DLLs loads this payload into every process of the user, so the hook
// is armed only inside the Configurator — elsewhere it must do nothing.
static bool IsTargetProcess() {
    wchar_t path[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
    const wchar_t* leaf = wcsrchr(path, L'\\');
    leaf = leaf ? leaf + 1 : path;
    return _wcsicmp(leaf, L"1cv8.exe") == 0 ||
           _wcsicmp(leaf, L"1cv8c.exe") == 0;
}

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
        if (IsTargetProcess()) V8iArmEarly();
    }
    return TRUE;
}
