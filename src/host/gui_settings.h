#pragma once
// The GitBar settings the GUI's dialog edits: the [git] section of
// %APPDATA%\v8inject\gitbar.ini, which the payload's panel reads.
//
// The path is a parameter so the tests can use a scratch folder. The GUI used
// to call WritePrivateProfileStringW directly: on a profile where the panel had
// never been shown the folder did not exist, every write failed with
// ERROR_PATH_NOT_FOUND, the values were lost and the dialog still logged
// "saved" (A64).

#include <string>

namespace v8i {

struct GitBarSettings {
    std::wstring gitPath;        // git.exe
    std::wstring dumpDir;        // folder the configuration is dumped into
    std::wstring commitMessage;  // default commit message
    std::wstring remote;         // optional remote origin
};

// %APPDATA%\v8inject\gitbar.ini, expanded; empty when %APPDATA% is unknown.
std::wstring GitBarIniPath();

// Missing values come back empty.
GitBarSettings LoadGitBarSettings(const wchar_t* iniPath);

// Writes the four values through v8i::IniSet (which creates the folder of the
// file and writes UTF-16 with a byte order mark). Returns false with `error`
// filled when any value could not be written -- the caller must not report
// "saved" then (A64).
bool SaveGitBarSettings(const wchar_t* iniPath, const GitBarSettings& s,
                        std::wstring* error);

}  // namespace v8i
