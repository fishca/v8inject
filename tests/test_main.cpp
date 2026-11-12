#include "test_runner.h"

#include <windows.h>
#include <cstdio>
#include <string>

// The unit tests have no framework around them: the runner prints the result
// and returns the number of failed tests as the exit code.
//
// The transcript also goes next to the binary: when the tests fail on a CI
// runner, the log of the artifact says which test failed and why - the CI
// output alone shows only the exit code. The name differs from the payload's
// own log (the payload writes next to its module and would pick the same file
// name otherwise).
int main() {
    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    size_t n = wcslen(self);
    while (n > 0 && self[n - 1] != L'\\' && self[n - 1] != L'/') --n;
    self[n] = 0;
    const std::wstring logPath = std::wstring(self) + L"v8i_tests_transcript.log";

    FILE* log = nullptr;
    if (_wfopen_s(&log, logPath.c_str(), L"w") != 0 || !log) log = nullptr;
    v8i::test::SetLogFile(log);

    const int failed = v8i::test::RunAll();

    if (log) {
        std::fprintf(log, "\nv8i_tests: %d failed test(s)\n", failed);
        fclose(log);
    }
    return failed == 0 ? 0 : 1;
}
