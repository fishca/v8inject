#include "test_runner.h"

#include <windows.h>
#include <cstdio>
#include <string>

// A child mode of the test binary itself: it writes to stdout forever, as fast
// as the pipe takes it. GitBar_RunProcessChecksTheDeadlineBeforeThePipe uses it --
// cmd.exe cannot produce output fast enough to keep the pipe from ever going
// empty, and an empty pipe is exactly what the old deadline check waited for
// (docs/AUDIT.md A76).
static int Flood() {
    std::string block(64 * 1024, 'x');
    block.back() = '\n';
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    for (;;) {
        DWORD written = 0;
        if (!WriteFile(out, block.data(), (DWORD)block.size(), &written, nullptr)) return 1;
    }
}

// A child mode of the test binary itself: a window that belongs to ANOTHER
// process. MenuCmdRefusesAWindowOfAnotherProcess uses it -- the payload has to
// refuse to post a menu command into a window it does not own (A93).
static int WindowChild() {
    const wchar_t kClass[] = L"V8iTestForeignWindow";
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = kClass;
    if (!RegisterClassExW(&wc)) return 2;
    HWND h = CreateWindowExW(0, kClass, L"v8i foreign window", WS_OVERLAPPEDWINDOW,
                             0, 0, 200, 120, nullptr, nullptr, wc.hInstance, nullptr);
    if (!h) return 3;
    std::printf("%llX\n", (unsigned long long)(uintptr_t)h);
    std::fflush(stdout);

    // The parent holds the write end of this stdin pipe: EOF there means "go
    // away", so the helper cannot outlive the test even if it fails.
    char c = 0;
    DWORD got = 0;
    ReadFile(GetStdHandle(STD_INPUT_HANDLE), &c, 1, &got, nullptr);
    return 0;
}

// The unit tests have no framework around them: the runner prints the result
// and returns the number of failed tests as the exit code.
//
// The transcript also goes next to the binary: when the tests fail on a CI
// runner, the log of the artifact says which test failed and why - the CI
// output alone shows only the exit code. The name differs from the payload's
// own log (the payload writes next to its module and would pick the same file
// name otherwise).
int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--flood") return Flood();
    if (argc > 1 && std::string(argv[1]) == "--window-child") return WindowChild();

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
