#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace v8i {
namespace gitbar {

// gitbar.ini: [git] section, shared with the settings dialog.
const wchar_t* GitIniPath();
std::wstring GitIniGet(const wchar_t* key, const wchar_t* fallback = L"");
bool GitIniSet(const wchar_t* key, const wchar_t* value);

// Client width below which the full strip collapses to a menu button.
int CompactThreshold();

std::wstring GitExe();
std::wstring TrimForTip(const std::wstring& s, size_t maxLen = 160);
std::wstring TrimWs(const std::wstring& s);

// Log helpers: git output is UTF-8 and often Cyrillic.
void LogGit(const wchar_t* what, const std::wstring& text);

// Runs "<gitpath> <args>" and returns stdout + stderr. Only ever runs from the
// toolbar's own thread; a git that waits for console input is killed.
std::wstring RunGit(const std::vector<std::wstring>& args, DWORD timeoutMs = 120000);

std::wstring NowStamp();
std::wstring TempMsgPath();
bool WriteUtf8File(const std::wstring& path, const std::wstring& text);

// Main Configurator frame of this process.
HWND FindFrame();

}  // namespace gitbar
}  // namespace v8i
