// The bitness of a process (src/host/procs.cpp, A57/A18).
//
// IsWow64Process2 answers two different questions: `processMachine` is the
// machine of the process image, `nativeMachine` is the machine of the host OS.
// The host's machine is not the answer -- on 64-bit Windows every 32-bit
// process has nativeMachine = AMD64. The decision is tested on the pure helper,
// then on the running processes themselves, where the old code answered "64"
// for a 32-bit target.

#include "test_runner.h"

#include "v8inject/procs.h"

#include <string>

using namespace v8i;
using namespace v8i::test;

V8I_TEST(Procs_TheHostMachineDoesNotDecideTheProcessBitness) {
    // A WOW64 process: a 32-bit image on a 64-bit host -- the case the old
    // code called 64-bit.
    CHECK(!IsMachine64(IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64));
    CHECK(!IsMachine64(IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_ARM64));

    // A native 64-bit process reports IMAGE_FILE_MACHINE_UNKNOWN as the process
    // machine, so the host machine is all there is to go on.
    CHECK(IsMachine64(IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_AMD64));
    CHECK(IsMachine64(IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_ARM64));

    // A native 32-bit process on a 32-bit host.
    CHECK(!IsMachine64(IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_I386));

    // An x64 process emulated on an ARM64 host is a 64-bit process.
    CHECK(IsMachine64(IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64));

    // 32-bit ARM on an ARM64 host is not.
    CHECK(!IsMachine64(IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_ARM64));
}

V8I_TEST(Procs_TheRunningProcessHasTheBitnessOfThisBuild) {
    // On an x86 build this is the test that fails on the old code, which said
    // "64-bit" because the host is 64-bit.
    CHECK_EQ(IsProcess64(GetCurrentProcessId()), sizeof(void*) == 8);
    // A pid that cannot exist reports 32-bit (nothing to open, nothing to say).
    CHECK(!IsProcess64(0xFFFFFFF0u));
}

#if defined(_M_X64) || defined(_M_ARM64)

// A live 32-bit process. SysWOW64\cmd.exe is started with /k so it stays up
// for the check: a process that had already exited would also answer "not
// 64-bit", and the test would pass without testing anything.
V8I_TEST(Procs_AWow64ProcessIsNot64Bit) {
    wchar_t wow[MAX_PATH] = {};
    const UINT n = GetSystemWow64DirectoryW(wow, MAX_PATH);
    REQUIRE(n > 0);
    std::wstring path(wow, n);
    path += L"\\cmd.exe";

    std::wstring cmd = L"\"" + path + L"\" /k";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    REQUIRE(CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi));
    // Alive, so the verdict below is about a real process and not about a
    // handle that could not be opened.
    CHECK(WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT);
    CHECK(!IsProcess64(pi.dwProcessId));

    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

#endif  // _M_X64 || _M_ARM64
