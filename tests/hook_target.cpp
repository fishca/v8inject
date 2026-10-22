// Disposable target process for the hook tests.
//
// It prints the address of a function with known arguments and then calls it
// forever, so the test can install a hook from outside, read the recorded
// arguments, and confirm the function still runs after the hook is removed.

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static volatile LONG g_calls = 0;

extern "C" __declspec(noinline) unsigned TargetTick(unsigned a, unsigned b,
                                                    unsigned c, unsigned d) {
    InterlockedIncrement(&g_calls);
    return a + b + c + d;
}

int main(int argc, char** argv) {
    // --delay <ms> keeps the function idle after start-up, which is what lets a
    // diagnostic session inspect the generated stub and trampoline before the
    // first hooked call happens.
    int delayMs = 0;
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--delay") == 0) delayMs = atoi(argv[i + 1]);
    }

    // The address has to be known to the test, and taking it also guarantees the
    // function is not folded away. %p alone prints bare hex on MSVC, so the 0x
    // prefix is written out: the CLI parses addresses with it.
    printf("pid=%lu tick=0x%p\n", (unsigned long)GetCurrentProcessId(), (void*)&TargetTick);
    fflush(stdout);

    if (delayMs > 0) Sleep((DWORD)delayMs);

    for (;;) {
        TargetTick(0x1111, 0x2222, 0x3333, 0x4444);
        Sleep(20);
    }
}
