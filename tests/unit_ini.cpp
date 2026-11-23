// The ini files of the project.
//
// The settings live in %APPDATA%\v8inject, and the folder did not exist on a
// fresh machine: the write failed silently and the settings were lost. The
// test pins the round trip and the folder creation.

#include "test_runner.h"

#include "v8inject/ini.h"

#include <windows.h>
#include <cstring>
#include <vector>

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

// --- IniGetManual: reading without the Win32 profile APIs (A53) ------------
//
// The payload's native menu reads [git] nativemenu through IniGetManual. The
// emergency switch was dead: IniSet writes UTF-16 with a BOM, and the old raw
// byte search for "nativemenu" stopped at the NUL right after the mark.

namespace {

void WriteBytes(const std::wstring& path, const void* data, size_t len) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(f, data, (DWORD)len, &written, nullptr);
    CloseHandle(f);
}

// The bytes IniSet produces: UTF-16LE with a byte order mark.
std::vector<char> Utf16(const wchar_t* text) {
    std::vector<char> b;
    b.push_back('\xFF');
    b.push_back('\xFE');
    const size_t n = wcslen(text) * sizeof(wchar_t);
    const char* p = (const char*)text;
    b.insert(b.end(), p, p + n);
    return b;
}

}  // namespace

V8I_TEST(IniManual_ReadsAUtf16FileWrittenByIniSet) {
    const std::wstring path = TempIni(L"v8i_test_ini_manual_utf16.ini");
    Remove(path);
    Remove(path);

    REQUIRE(IniSet(path.c_str(), L"git", L"nativemenu", L"0"));
    bool found = false;
    CHECK_EQ(IniGetManual(path.c_str(), L"git", L"nativemenu", L"1", &found), L"0");
    CHECK(found);

    // The same file read as raw bytes would not contain a single byte of the
    // key name: it is UTF-16, not ASCII.
    CHECK(IniGetManual(path.c_str(), L"git", L"nosuchkey", L"1", &found) == L"1");
    CHECK(!found);
    Remove(path);
}

V8I_TEST(IniManual_ReadsUtf8AnsiAndUtf16BigEndian) {
    const std::wstring path = TempIni(L"v8i_test_ini_manual_encodings.ini");
    Remove(path);

    // UTF-8 with a mark.
    {
        const char text[] = "\xEF\xBB\xBF[git]\r\nnativemenu=0\r\n";
        WriteBytes(path, text, sizeof(text) - 1);
        bool found = false;
        CHECK_EQ(IniGetManual(path.c_str(), L"git", L"nativemenu", L"1", &found), L"0");
        CHECK(found);
    }
    // ANSI, no mark at all (a file from an older build).
    {
        const char text[] = "[git]\r\nnativemenu = 0\r\n";
        WriteBytes(path, text, sizeof(text) - 1);
        CHECK_EQ(IniGetManual(path.c_str(), L"git", L"nativemenu", L"1"), L"0");
    }
    // UTF-16 big endian: 0xFE 0xFF, then the text with swapped bytes.
    {
        const wchar_t text[] = L"[git]\nnativemenu=0\n";
        std::vector<char> b;
        b.push_back('\xFE');
        b.push_back('\xFF');
        for (const wchar_t* p = text; *p; ++p) {
            b.push_back((char)(*p >> 8));
            b.push_back((char)(*p & 0xFF));
        }
        WriteBytes(path, b.data(), b.size());
        CHECK_EQ(IniGetManual(path.c_str(), L"git", L"nativemenu", L"1"), L"0");
    }
    Remove(path);
}

// A145: GetPrivateProfileStringW strips one pair of surrounding quotes, and a
// hand-written nativemenu="0" must work like nativemenu=0.
V8I_TEST(IniManual_StripsOnePairOfQuotes) {
    const std::wstring path = TempIni(L"v8i_test_ini_manual_quotes.ini");
    Remove(path);

    const char text[] =
        "[git]\r\n"
        "nativemenu=\"0\"\r\n"
        "double=\"\"0\"\"\r\n"
        "plain=1\r\n"
        "empty=\"\"\r\n";
    WriteBytes(path, text, sizeof(text) - 1);

    bool found = false;
    CHECK_EQ(IniGetManual(path.c_str(), L"git", L"nativemenu", L"1", &found), L"0");
    CHECK(found);
    // Exactly one pair: the inner quotes are part of the value.
    CHECK_EQ(IniGetManual(path.c_str(), L"git", L"double", L"x"), L"\"0\"");
    CHECK_EQ(IniGetManual(path.c_str(), L"git", L"plain", L"x"), L"1");
    CHECK_EQ(IniGetManual(path.c_str(), L"git", L"empty", L"x"), L"");
    Remove(path);
}

V8I_TEST(IniManual_SectionCommentsAndCaseAreHandled) {
    const std::wstring path = TempIni(L"v8i_test_ini_manual_sections.ini");
    Remove(path);
    const std::wstring text =
        L"; a comment line\r\n"
        L"# another one\r\n"
        L"global=1\r\n"
        L"[agent]\r\n"
        L"nativemenu=1\r\n"
        L"[git]\r\n"
        L"  nativemenu = 0 \r\n"
        L"dumpdir=E:\\dump\r\n";
    const std::vector<char> b = Utf16(text.c_str());
    WriteBytes(path, b.data(), b.size());

    bool found = false;
    // The value of the [git] section, trimmed; the [agent] one must not win.
    CHECK_EQ(IniGetManual(path.c_str(), L"git", L"nativemenu", L"1", &found), L"0");
    CHECK(found);
    CHECK_EQ(IniGetManual(path.c_str(), L"agent", L"nativemenu", L"1"), L"1");
    CHECK_EQ(IniGetManual(path.c_str(), L"GIT", L"NATIVEMENU", L"1"), L"0");   // names are case-insensitive
    CHECK_EQ(IniGetManual(path.c_str(), L"git", L"dumpdir", L""), L"E:\\dump");
    // A key before any section belongs to no section: the [git] read misses it.
    CHECK_EQ(IniGetManual(path.c_str(), L"git", L"global", L"absent"), L"absent");
    Remove(path);
}

V8I_TEST(IniManual_MissingFileAndBadArgumentsUseTheFallback) {
    bool found = true;
    CHECK_EQ(IniGetManual(TempIni(L"v8i_test_ini_manual_absent.ini").c_str(), L"git",
                          L"nativemenu", L"1", &found), L"1");
    CHECK(!found);
    CHECK_EQ(IniGetManual(nullptr, L"git", L"nativemenu", L"on"), L"on");
    CHECK_EQ(IniGetManual(TempIni(L"x.ini").c_str(), L"git", nullptr, L"on"), L"on");
}
