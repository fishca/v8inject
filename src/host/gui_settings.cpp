#include "gui_settings.h"

#include "v8inject/ini.h"

#include <windows.h>

namespace v8i {

namespace {

constexpr wchar_t kSection[] = L"git";

}  // namespace

std::wstring GitBarIniPath() {
    wchar_t path[MAX_PATH] = {};
    if (!ExpandEnvironmentStringsW(L"%APPDATA%\\v8inject\\gitbar.ini", path, MAX_PATH))
        return std::wstring();
    return path;
}

GitBarSettings LoadGitBarSettings(const wchar_t* iniPath) {
    GitBarSettings s;
    s.gitPath = IniGet(iniPath, kSection, L"gitpath");
    s.dumpDir = IniGet(iniPath, kSection, L"dumpdir");
    s.commitMessage = IniGet(iniPath, kSection, L"commitmsg");
    s.remote = IniGet(iniPath, kSection, L"remote");
    return s;
}

bool SaveGitBarSettings(const wchar_t* iniPath, const GitBarSettings& s,
                        std::wstring* error) {
    if (error) error->clear();
    if (!iniPath || !*iniPath) {
        if (error) *error = L"пустой путь к gitbar.ini";
        return false;
    }

    struct Key {
        const wchar_t* name;
        const std::wstring* value;
    };
    const Key keys[] = {
        { L"gitpath", &s.gitPath },
        { L"dumpdir", &s.dumpDir },
        { L"commitmsg", &s.commitMessage },
        { L"remote", &s.remote },
    };
    for (const Key& k : keys) {
        if (!IniSet(iniPath, kSection, k.name, k.value->c_str())) {
            if (error) {
                *error = std::wstring(L"не удалось записать ") + k.name +
                         L" в " + iniPath + L" (код " +
                         std::to_wstring(GetLastError()) + L")";
            }
            return false;
        }
    }
    return true;
}

}  // namespace v8i
