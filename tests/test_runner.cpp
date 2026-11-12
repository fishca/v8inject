#include "test_runner.h"

#include <cstdarg>
#include <cstdio>
#include <vector>

namespace v8i {
namespace test {

namespace {

struct Entry {
    const char* name;
    TestFn fn;
};

std::vector<Entry>& Registry() {
    static std::vector<Entry> registry;
    return registry;
}

int g_failedChecks = 0;
int g_totalChecks = 0;
FILE* g_log = nullptr;

// Writes a line to the console and to the transcript file.
void Out(const std::string& line) {
    std::printf("%s", line.c_str());
    if (g_log) { std::fputs(line.c_str(), g_log); std::fflush(g_log); }
}

}  // namespace

void SetLogFile(FILE* log) { g_log = log; }

int Register(const char* name, TestFn fn) {
    Registry().push_back(Entry{ name, fn });
    return 0;
}

void Fail(const char* file, int line, const std::string& what) {
    ++g_failedChecks;
    char b[1024];
    _snprintf_s(b, sizeof(b), _TRUNCATE, "    FAIL %s:%d: %s\n", file, line, what.c_str());
    Out(b);
}

bool CheckTrue(bool ok, const char* file, int line, const std::string& what) {
    ++g_totalChecks;
    if (!ok) Fail(file, line, what);
    return ok;
}

std::string Text(int v) {
    char b[32];
    _snprintf_s(b, sizeof(b), _TRUNCATE, "%d", v);
    return b;
}

std::string Text(unsigned int v) {
    char b[32];
    _snprintf_s(b, sizeof(b), _TRUNCATE, "%u", v);
    return b;
}

std::string Text(long long v) {
    char b[32];
    _snprintf_s(b, sizeof(b), _TRUNCATE, "%lld", v);
    return b;
}

std::string Text(unsigned long long v) {
    char b[32];
    _snprintf_s(b, sizeof(b), _TRUNCATE, "%llu", v);
    return b;
}

std::string Text(const std::string& v) {
    return "\"" + v + "\"";
}

std::string Text(const std::wstring& v) {
    if (v.size() > 64) return "\"<long>\"";
    std::string out = "\"";
    for (wchar_t c : v) {
        if (c < 0x20 || c > 0x7E) { out += "?"; continue; }
        out += (char)c;
    }
    return out + "\"";
}

int RunAll() {
    int failedTests = 0;
    const std::vector<Entry>& registry = Registry();

    char b[128];
    _snprintf_s(b, sizeof(b), _TRUNCATE, "running %zu tests\n", registry.size());
    Out(b);

    for (const Entry& e : registry) {
        const int before = g_failedChecks;
        _snprintf_s(b, sizeof(b), _TRUNCATE, "[ RUN  ] %s\n", e.name);
        Out(b);
        e.fn();
        if (g_failedChecks != before) {
            ++failedTests;
            _snprintf_s(b, sizeof(b), _TRUNCATE, "[ FAIL ] %s\n", e.name);
        } else {
            _snprintf_s(b, sizeof(b), _TRUNCATE, "[  OK  ] %s\n", e.name);
        }
        Out(b);
    }

    _snprintf_s(b, sizeof(b), _TRUNCATE,
                 "\n%zu tests, %d checks, %d failed check(s), %d failed test(s)\n",
                 registry.size(), g_totalChecks, g_failedChecks, failedTests);
    Out(b);
    return failedTests;
}

}  // namespace test
}  // namespace v8i
