// The ini files of the project.
//
// The settings live in %APPDATA%\v8inject, and the folder did not exist on a
// fresh machine: the write failed silently and the settings were lost. The
// test pins the round trip and the folder creation.

#include "test_runner.h"

#include "v8inject/ini.h"

#include <windows.h>
#include <cstring>

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

    // The file has to be Unicode: the Win32 ini functions write the system
    // code page into a file without a byte order mark, and a Russian setting
    // is mangled on a machine with a different code page.
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    unsigned char head[2] = {};
    DWORD read = 0;
    const bool readOk = ReadFile(f, head, sizeof(head), &read, nullptr) != FALSE;
    CloseHandle(f);
    CHECK(readOk);
    CHECK_EQ((int)read, 2);
    CHECK_EQ((int)head[0], 0xFF);      // the byte order mark
    CHECK_EQ((int)head[1], 0xFE);

    Remove(path);
}

V8I_TEST(Ini_AnsiFileIsConvertedToUnicode) {
    // A file left over from an older version (written in the system code
    // page) must not stay ANSI: the next write would mangle it again.
    const std::wstring path = TempIni(L"v8i_test_ini_ansi.ini");
    Remove(path);

    {
        HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        REQUIRE(f != INVALID_HANDLE_VALUE);
        const char* ansi = "[git]\r\ncommitmsg=old\r\n";
        DWORD written = 0;
        WriteFile(f, ansi, (DWORD)strlen(ansi), &written, nullptr);
        CloseHandle(f);
    }

    CHECK(IniSet(path.c_str(), L"git", L"dumpdir", L"E:\\dump"));
    CHECK(IniGet(path.c_str(), L"git", L"commitmsg") == L"old");
    CHECK(IniGet(path.c_str(), L"git", L"dumpdir") == L"E:\\dump");

    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    unsigned char head[2] = {};
    DWORD read = 0;
    ReadFile(f, head, sizeof(head), &read, nullptr);
    CloseHandle(f);
    CHECK_EQ((int)head[0], 0xFF);
    CHECK_EQ((int)head[1], 0xFE);

    Remove(path);
}

V8I_TEST(Ini_MissingFileReadsEmpty) {
    const std::wstring path = TempIni(L"v8i_test_ini_absent.ini");
    Remove(path);
    CHECK(IniGet(path.c_str(), L"git", L"dumpdir").empty());
}
