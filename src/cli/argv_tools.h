#pragma once
// Command-line plumbing of the CLI that a test can reach without a console.
//
// The rules live here rather than in main.cpp because both were defects that
// only a test can keep fixed: an option in front of the positional arguments
// shifted them (A95), and the interactive mode decoded console bytes as UTF-8
// and split an overlong line into two commands (A94).

#include <string>
#include <vector>

namespace v8i {

// `--pid <n>` is an option of the CLI, not a positional argument of the
// payload. Stripping it before anything counts positions is what keeps
// `peek --pid 1234 0x1000` from taking the pid for the address.
struct PidOption {
    std::vector<std::wstring> args;   // argv without every "--pid <n>"
    std::wstring pidText;             // the last value given, empty if none
    unsigned long pid = 0;            // its numeric form, 0 if absent/invalid
};

PidOption StripPidOption(int argc, wchar_t** argv);

}  // namespace v8i
