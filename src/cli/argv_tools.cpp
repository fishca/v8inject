#include "cli/argv_tools.h"

#include <cstdlib>

namespace v8i {

PidOption StripPidOption(int argc, wchar_t** argv) {
    PidOption out;
    out.args.reserve((size_t)argc);
    for (int i = 0; i < argc; ++i) {
        const std::wstring a = argv[i];
        if (a == L"--pid") {
            // The value belongs to the option even when it does not look like a
            // number: leaving it in argv would make it the first positional
            // argument, which is exactly the defect.
            if (i + 1 < argc) {
                out.pidText = argv[++i];
                out.pid = (unsigned long)_wtoi(out.pidText.c_str());
            }
            continue;
        }
        out.args.push_back(a);
    }
    return out;
}

}  // namespace v8i
