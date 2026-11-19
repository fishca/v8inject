// The log of the payload.
//
// The payload logs from several threads from the very first millisecond, while
// the folder for the log arrives later (it travels in the shared block). A63:
// the log used to initialise its critical section lazily and to write the path
// buffer without a lock, so two threads could re-initialise the section under
// each other's feet. This test hammers exactly that window: threads log while
// the path is switched.

#include "test_runner.h"

#include "v8inject/diag.h"

#include <windows.h>

#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace v8i;

namespace {

std::wstring TempDir(const wchar_t* leaf) {
    wchar_t tmp[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tmp)) return L".\\";
    std::wstring dir = tmp;
    dir += L"v8inject_diag_";
    dir += leaf;
    dir += L"\\";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

// Counts the lines of this thread's test in one log file.
int CountLines(const std::wstring& path, const char* needle) {
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) return 0;
    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, needle)) ++count;
    }
    fclose(f);
    return count;
}

}  // namespace

V8I_TEST(Diag_ConcurrentInitAndPathSwitch) {
    const std::wstring dirA = TempDir(L"a");
    const std::wstring dirB = TempDir(L"b");
    REQUIRE(!dirA.empty() && !dirB.empty());

    // A fresh start: whichever path the previous test left behind, this test
    // owns both files from here on.
    DeleteFileW((dirA + L"v8inject.log").c_str());
    DeleteFileW((dirB + L"v8inject.log").c_str());
    SetLogDirectory(dirA.c_str());

    constexpr int kThreads = 8;
    constexpr int kLines = 50;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([t] {
            for (int i = 0; i < kLines; ++i) {
                LogLine("thread %d line %d", t, i);
            }
        });
    }
    // Switch the folder while the writers are running: the old code raced
    // between "check the flag" and "initialise the section" here, and read a
    // half-written path there.
    for (int i = 0; i < 40; ++i) {
        SetLogDirectory((i % 2) ? dirB.c_str() : dirA.c_str());
    }
    for (std::thread& th : threads) th.join();
    SetLogDirectory(dirA.c_str());
    LogLine("done");

    // Both files are valid logs; between them every line is present exactly
    // once. A lost line means a torn path or a corrupted section.
    int total = CountLines(dirA + L"v8inject.log", "thread ") +
                CountLines(dirB + L"v8inject.log", "thread ");
    CHECK_EQ(total, kThreads * kLines);

    // GetLogPath reports the folder the payload is about to write to.
    const wchar_t* now = GetLogPath();
    REQUIRE(now != nullptr);
    CHECK(std::wstring(now).find(L"v8inject.log") != std::wstring::npos);

    // Logging into a missing folder must not lose the line silently: the
    // fallback chain (temp dir, then next to the module) still writes it.
    SetLogDirectory(L"Q:\\no\\such\\folder");
    LogLine("fallback check");
    SetLogDirectory(dirA.c_str());
}
