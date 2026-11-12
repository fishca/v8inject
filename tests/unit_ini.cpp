// The ini files of the project.
//
// The settings live in %APPDATA%\v8inject, and the folder did not exist on a
// fresh machine: the write failed silently and the settings were lost. The
// test pins the round trip and the folder creation.

#include "test_runner.h"

#include "v8inject/ini.h"

#include <windows.h>

using namespace v8i;

namespace {

// A path inside the temp folder: the file is removed again afterwards.
std::wstring TempIni(const wchar_t* name) {
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring p(tmp);
    if (!p.empty() && p.back() != L'\\') p += L'\\';
    p += name;
    return p;
}

void Remove(const std::wstring& path) {
    DeleteFileW(path.c_str());
}

}  // namespace

V8I_TEST(Ini_RoundTrip) {
    const std::wstring path = TempIni(L"v8i_test_ini_roundtrip.ini");
    Remove(path);

    CHECK(IniSet(path.c_str(), L"git", L"dumpdir", L"E:\\dump\\config"));
    CHECK(IniGet(path.c_str(), L"git", L"dumpdir") == L"E:\\dump\\config");

    // A second key in the same section and another section.
    CHECK(IniSet(path.c_str(), L"git", L"remote", L"git@example.com:user/repo.git"));
    CHECK(IniSet(path.c_str(), L"agent", L"names", L"1cv8.exe"));

    CHECK(IniGet(path.c_str(), L"git", L"remote") == L"git@example.com:user/repo.git");
    CHECK(IniGet(path.c_str(), L"agent", L"names") == L"1cv8.exe");

    // A missing key reads as an empty string, or as the fallback.
    CHECK(IniGet(path.c_str(), L"git", L"nosuchkey").empty());
    CHECK(IniGet(path.c_str(), L"git", L"nosuchkey", L"default") == L"default");
    CHECK(IniGet(path.c_str(), L"nosuchsection", L"dumpdir").empty());

    Remove(path);
}

V8I_TEST(Ini_ValueIsOverwritten) {
    const std::wstring path = TempIni(L"v8i_test_ini_overwrite.ini");
    Remove(path);

    CHECK(IniSet(path.c_str(), L"git", L"commitmsg", L"first"));
    CHECK(IniSet(path.c_str(), L"git", L"commitmsg", L"second"));
    CHECK(IniGet(path.c_str(), L"git", L"commitmsg") == L"second");

    Remove(path);
}

V8I_TEST(Ini_FolderIsCreatedBeforeTheFirstWrite) {
    // The path points into a folder that does not exist yet: the write has to
    // create it, or the settings are lost without a word.
    const std::wstring folder = TempIni(L"v8i_test_ini_folder");
    const std::wstring path = folder + L"\\settings.ini";

    DeleteFileW(path.c_str());
    RemoveDirectoryW(folder.c_str());

    CHECK(IniSet(path.c_str(), L"git", L"dumpdir", L"E:\\dump"));
    CHECK(IniGet(path.c_str(), L"git", L"dumpdir") == L"E:\\dump");

    DeleteFileW(path.c_str());
    RemoveDirectoryW(folder.c_str());
}

V8I_TEST(Ini_CyrillicSurvivesTheRoundTrip) {
    const std::wstring path = TempIni(L"v8i_test_ini_cyrillic.ini");
    Remove(path);

    CHECK(IniSet(path.c_str(), L"git", L"commitmsg", L"выгрузка конфигурации"));
    CHECK(IniGet(path.c_str(), L"git", L"commitmsg") == L"выгрузка конфигурации");

    Remove(path);
}

V8I_TEST(Ini_MissingFileReadsEmpty) {
    const std::wstring path = TempIni(L"v8i_test_ini_absent.ini");
    Remove(path);
    CHECK(IniGet(path.c_str(), L"git", L"dumpdir").empty());
}
