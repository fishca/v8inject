// The command-line plumbing of the CLI.
//
// Two defects lived here and both were invisible to every test that existed:
// `--pid` in front of the positional arguments shifted them (A95), and the
// interactive session read stdin as OEM bytes with fgets into char[4096], so an
// overlong line came back as two commands and a Cyrillic filter was decoded
// wrongly (A94). The rules are plain functions now, so they are checked without
// a console and without a live 1C.

#include "test_runner.h"

#include "cli/argv_tools.h"
#include "cli/console_input.h"
#include "cli/watch_state.h"

#include "v8inject/text.h"

#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>

using namespace v8i;
using namespace v8i::test;

namespace {

// Arguments as wmain sees them: a mutable argv array.
struct Argv {
    explicit Argv(std::vector<std::wstring> words) : args(std::move(words)) {
        for (std::wstring& a : args) pointers.push_back(&a[0]);
    }
    PidOption Strip() { return StripPidOption((int)pointers.size(), pointers.data()); }
    std::vector<std::wstring> args;
    std::vector<wchar_t*> pointers;
};

std::wstring Join(const std::vector<std::wstring>& v) {
    std::wstring out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += L'|';
        out += v[i];
    }
    return out;
}

// A file that plays the role of stdin: a pipe would block on a write larger
// than its buffer unless a thread drained it, and the reader under test is the
// only reader here. A file handle is not a console, so LineReader takes the
// byte path -- exactly the path a redirected `attach` takes.
class InputFile {
public:
    InputFile() {
        wchar_t dir[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, dir);
        wchar_t path[MAX_PATH] = {};
        GetTempFileNameW(dir, L"v8i", 0, path);
        path_ = path;
    }
    ~InputFile() {
        if (handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr) CloseHandle(handle_);
        if (!path_.empty()) _wremove(path_.c_str());
    }

    void Write(const std::string& bytes) {
        HANDLE h = CreateFileW(path_.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return;
        DWORD written = 0;
        WriteFile(h, bytes.data(), (DWORD)bytes.size(), &written, nullptr);
        CloseHandle(h);
    }

    HANDLE Open() {
        handle_ = CreateFileW(path_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        return handle_;
    }

private:
    std::wstring path_;
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

}  // namespace

// ---------------------------------------------------------------------------
// A95: --pid is an option of the CLI, not the <exe> argument
// ---------------------------------------------------------------------------

V8I_TEST(Cli_StripPidOptionKeepsThePositionalArguments) {
    // The case from the audit: the old parser saw --pid at the place of the
    // image name, `peek` then took 1234 for the address and ignored 0x1000.
    {
        Argv a({L"v8inject", L"peek", L"--pid", L"1234", L"0x1000"});
        const PidOption o = a.Strip();
        CHECK_EQ(Join(o.args), std::wstring(L"v8inject|peek|0x1000"));
        CHECK_EQ(o.pidText, std::wstring(L"1234"));
        CHECK(o.pid == 1234UL);
    }

    // A trailing --pid works too: the option is found wherever it is.
    {
        Argv a({L"v8inject", L"peek", L"1cv8.exe", L"0x1000", L"--pid", L"4321"});
        const PidOption o = a.Strip();
        CHECK_EQ(Join(o.args), std::wstring(L"v8inject|peek|1cv8.exe|0x1000"));
        CHECK(o.pid == 4321UL);
    }

    // Without the option nothing changes and no target is forced.
    {
        Argv a({L"v8inject", L"peek", L"1cv8.exe", L"0x1000"});
        const PidOption o = a.Strip();
        CHECK(o.args.size() == 4);
        CHECK(o.pid == 0UL);
        CHECK(o.pidText.empty());
    }

    // A dangling --pid is removed instead of becoming a positional argument.
    {
        Argv a({L"v8inject", L"peek", L"--pid"});
        const PidOption o = a.Strip();
        CHECK_EQ(Join(o.args), std::wstring(L"v8inject|peek"));
        CHECK(o.pid == 0UL);
    }

    // A value that is not a number at all is still consumed: leaving it in
    // argv is what shifted the arguments. The command then falls back to the
    // image name. (A token that starts with digits -- "1cv8.exe" -- parses as
    // 1: that is wtoi's semantics, and the pid check reports it.)
    {
        Argv a({L"v8inject", L"peek", L"--pid", L"nosuchpid", L"0x1000"});
        const PidOption o = a.Strip();
        CHECK_EQ(Join(o.args), std::wstring(L"v8inject|peek|0x1000"));
        CHECK(o.pid == 0UL);
    }
}

// ---------------------------------------------------------------------------
// A94: a line is read whole and refused when it does not fit
// ---------------------------------------------------------------------------

V8I_TEST(Cli_LineReaderReadsAFileLineByLine) {
    InputFile input;
    input.Write("one\r\ntwo\nthree");
    const HANDLE h = input.Open();
    REQUIRE(h != INVALID_HANDLE_VALUE);

    LineReader reader(h);

    ConsoleLine line = reader.Next(4095);
    CHECK(!line.eof);
    CHECK(!line.tooLong);
    CHECK_EQ(line.utf8, std::string("one"));      // the CR of CRLF is dropped
    CHECK_EQ(line.chars, (size_t)3);

    line = reader.Next(4095);
    CHECK_EQ(line.utf8, std::string("two"));

    // A last line without a terminator is still a command.
    line = reader.Next(4095);
    CHECK_EQ(line.utf8, std::string("three"));

    line = reader.Next(4095);
    CHECK(line.eof);
}

V8I_TEST(Cli_LineReaderRefusesAnOverlongLineWithoutSplittingIt) {
    // 5000 characters, then a normal command. fgets into char[4096] returned
    // the first 4095 bytes as one command and the remaining 905 as the next
    // one: the tail of a command was executed as a command of its own.
    InputFile input;
    input.Write(std::string(5000, 'A') + "\nversion\n");
    const HANDLE h = input.Open();
    REQUIRE(h != INVALID_HANDLE_VALUE);

    LineReader reader(h);
    ConsoleLine line = reader.Next(4095);
    CHECK(!line.eof);
    CHECK(line.tooLong);
    CHECK_EQ(line.chars, (size_t)5000);
    CHECK(line.utf8.empty());                     // nothing is sent

    // The next command starts at the next line, not in the middle of this one.
    line = reader.Next(4095);
    CHECK(!line.eof);
    CHECK(!line.tooLong);
    CHECK_EQ(line.utf8, std::string("version"));
}

V8I_TEST(Cli_LineReaderCountsCharactersNotBytes) {
    // 3000 Cyrillic letters: 6000 bytes of UTF-8, 3000 characters. A byte-based
    // limit would have refused a command that fits the request block.
    const std::wstring word(3000, L'Ж');
    const std::string utf8 = WideToUtf8(word);
    CHECK(utf8.size() > 4095);                    // the block is smaller in bytes

    InputFile input;
    input.Write(utf8 + "\n");
    const HANDLE h = input.Open();
    REQUIRE(h != INVALID_HANDLE_VALUE);

    LineReader reader(h);
    const ConsoleLine line = reader.Next(4095);
    CHECK(!line.tooLong);
    CHECK_EQ(line.chars, (size_t)3000);
    CHECK_EQ(line.utf8, utf8);
}

// A156: the header of a trace record between "hook" and "args" is wider than
// the old fixed 60-character window -- with real-world values ("tid":12345,
// "tick":9876543210, a 16-hex "ret") it takes 66 characters, so `watch`
// discarded every record on the first check and never fired. The parser skips
// the header structurally now, bounded by the next record.
namespace {

// A record as hook.cpp actually serializes it: wide tid/tick, full 16-hex ret.
const char kWideRecord[] =
    "{\"seq\":41,\"hook\":1,\"tid\":12345,\"tick\":9876543210,"
    "\"ret\":\"0x00007FF600001234\",\"args\":[\"0x000000AABBCCDD11\",\"0x2\",\"0x3\",\"0x4\"],"
    "\"stack\":[\"0x00007FF600002000\"]}";

}  // namespace

V8I_TEST(Cli_TraceRecordParserSurvivesTheRealRecordHeader) {
    const std::string resp = kWideRecord;
    v8i::TraceRecordHead rec;
    size_t next = 0;
    // `pos` points at `"seq":` itself, the way RunWatch finds it in the reply.
    const size_t start = resp.find("\"seq\":");
    REQUIRE(start != std::string::npos);
    REQUIRE(v8i::ParseTraceRecordHead(resp, start, rec, &next));
    CHECK_EQ(rec.seq, (unsigned long long)41);
    CHECK_EQ(rec.hook, (unsigned long long)1);
    CHECK(rec.arg0 == "0x000000AABBCCDD11");
    // `next` points at the closing quote of args[0]; from there the reply
    // holds no further record.
    CHECK(resp[next] == '"');
    CHECK(resp.find("\"seq\":", next) == std::string::npos);
}

V8I_TEST(Cli_TraceRecordParserKeepsTwoRecordsApart) {
    const std::string second =
        ",{\"seq\":42,\"hook\":1,\"tid\":6,\"tick\":7,"
        "\"ret\":\"0x0000000000000001\",\"args\":[\"0x2\",\"0x0\",\"0x0\",\"0x0\"],\"stack\":[]}";
    const std::string resp = std::string(kWideRecord) + second;

    v8i::TraceRecordHead rec;
    size_t next = 0;
    const size_t firstStart = resp.find("\"seq\":");
    REQUIRE(firstStart != std::string::npos);
    REQUIRE(v8i::ParseTraceRecordHead(resp, firstStart, rec, &next));
    CHECK_EQ(rec.seq, (unsigned long long)41);

    const size_t secondStart = resp.find("\"seq\":", next);
    REQUIRE(secondStart != std::string::npos);
    REQUIRE(v8i::ParseTraceRecordHead(resp, secondStart, rec, &next));
    CHECK_EQ(rec.seq, (unsigned long long)42);
    CHECK_EQ(rec.hook, (unsigned long long)1);
    CHECK(rec.arg0 == "0x2");
}

V8I_TEST(Cli_TraceRecordParserRefusesMalformedRecords) {
    v8i::TraceRecordHead rec;
    size_t next = 0;

    CHECK(!v8i::ParseTraceRecordHead("\"seqx\":1", 0, rec, &next));
    CHECK(!v8i::ParseTraceRecordHead("\"seq\":", 0, rec, &next));
    CHECK(!v8i::ParseTraceRecordHead("\"seq\":41", 0, rec, &next));
    CHECK(!v8i::ParseTraceRecordHead("\"seq\":41,\"hook\":", 0, rec, &next));
    // A record without "args" before the next one starts: refused, not
    // misread into the following record.
    CHECK(!v8i::ParseTraceRecordHead(
        "\"seq\":41,\"hook\":1,\"tid\":5,\"next\":{\"seq\":42,\"args\":[\"0x1\"]}", 0, rec,
        &next));
}
