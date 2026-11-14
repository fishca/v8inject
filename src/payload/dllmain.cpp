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
//
// The loader-lock contract (plan_roadmap Ф1.5, 2026-11-14). DllMain runs with
// the loader lock held, so only this may happen here:
//   - IsTargetProcess(): GetModuleFileNameW + a string compare -- no load, no
//     allocation beyond the local buffer;
//   - V8iArmEarly(): GetModuleHandleExW (the module is already loaded) +
//     SetWindowsHookExW (the hook module is our own, already mapped) +
//     CreateThread -- a thread created here starts running only after the
//     loader lock is released, so all heavier work (the inline hook on
//     CreateWindowExW with its thread suspension, the 8.5 subscribe chain,
//     logging) happens on workers, never under the lock. That split is why
//     V8iInstallCreateWindowThread exists (v8i_export.cpp); keep new early
//     work in the same shape: arm in DllMain, execute in a worker.
// Anything else -- LoadLibrary of another module, CRT startup beyond the
// basics, file IO, synchronization with other threads -- risks a loader-lock
// deadlock, and a fault here kills 1C outright (0xC000041D).
//
// AppInit_DLLs is a hypothetical delivery path this file stays compatible
// with (the hook is armed only in the Configurator, elsewhere the payload
// does nothing); the project does not configure it.
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
