#pragma once
// The autostart entry of the tray agent: HKCU\...\Run, value "v8inject-agent".
//
// The key root and the key path are parameters so the unit tests can work on a
// scratch key instead of the real Run key (A82).

#include <windows.h>
#include <string>

namespace v8i {

constexpr wchar_t kRunKeyPath[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunValueName[] = L"v8inject-agent";

// The command line written into the Run value. Windows parses that value the
// way it parses a command line, so an unquoted "C:\Program Files\..." started
// "C:\Program.exe" and the agent never came up after a reboot (A82).
std::wstring AutostartCommandLine(const std::wstring& exePath);

// Sets (on=true) or removes (on=false) the value. Returns false with `error`
// filled when the key or the value could not be written: the old code ignored
// the result of RegSetValueExW and reported success anyway (A82).
bool AutostartSet(HKEY root, const wchar_t* subKey, const wchar_t* valueName,
                  const std::wstring& exePath, bool on, std::wstring* error);

// The command line that is actually in the registry; empty when the value is
// missing. The agent's checkbox used to read its own ini flag, which was
// written even when the registry write had failed (A82).
std::wstring AutostartValue(HKEY root, const wchar_t* subKey,
                            const wchar_t* valueName);

bool AutostartActive(HKEY root, const wchar_t* subKey, const wchar_t* valueName);

}  // namespace v8i
