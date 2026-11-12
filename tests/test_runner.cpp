#include "test_runner.h"

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

}  // namespace

int Register(const char* name, TestFn fn) {
    Registry().push_back(Entry{ name, fn });
    return 0;
}

void Fail(const char* file, int line, const std::string& what) {
    ++g_failedChecks;
    std::printf("    FAIL %s:%d: %s\n", file, line, what.c_str());
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
    std::printf("running %zu tests\n", registry.size());

    for (const Entry& e : registry) {
        const int before = g_failedChecks;
        std::printf("[ RUN  ] %s\n", e.name);
        e.fn();
        if (g_failedChecks != before) {
            ++failedTests;
            std::printf("[ FAIL ] %s\n", e.name);
        } else {
            std::printf("[  OK  ] %s\n", e.name);
        }
    }

    std::printf("\n%zu tests, %d checks, %d failed check(s), %d failed test(s)\n",
                registry.size(), g_totalChecks, g_failedChecks, failedTests);
    return failedTests;
}

}  // namespace test
}  // namespace v8i
