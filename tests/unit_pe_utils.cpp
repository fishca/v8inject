// Module enumeration and the readability probe.
//
// EnumModules walks the PEB loader list by hand (the Win32 API does not
// offer it for foreign processes), so a mistake there means the payload
// cannot find core85.dll at all. IsReadable is the guard that keeps the PE
// parser away from unmapped memory.

#include "test_runner.h"

#include "v8inject/pe_utils.h"

using namespace v8i;

V8I_TEST(Modules_EnumerationFindsTheRunningBinary) {
    const std::vector<ModuleRange> mods = EnumModules();
    CHECK(!mods.empty());

    wchar_t self[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    const std::wstring selfPath(self);

    bool found = false;
    for (const ModuleRange& m : mods) {
        CHECK(m.base != 0);
        CHECK(m.size > 0);
        if (m.path == selfPath) found = true;
    }
    CHECK(found);
}

V8I_TEST(Modules_FindByName) {
    ModuleRange k32;
    CHECK(FindModule(L"kernel32.dll", k32));
    CHECK(k32.base != 0);
    CHECK(k32.size > 0);

    // The lookup is case-insensitive.
    ModuleRange k32Upper;
    CHECK(FindModule(L"KERNEL32.DLL", k32Upper));
    CHECK(k32Upper.base == k32.base);

    ModuleRange missing;
    CHECK(!FindModule(L"no-such-module-anywhere.dll", missing));
    CHECK(missing.base == 0);

    CHECK(!FindModule(nullptr, missing));
}

V8I_TEST(Memory_ReadabilityProbe) {
    int local = 0;
    CHECK(IsReadable(&local, sizeof(local)));

    // A stack buffer of a decent size: the probe has to walk the pages.
    char buffer[4096] = {};
    CHECK(IsReadable(buffer, sizeof(buffer)));

    // Nothing is mapped at the null page or at 0x10.
    CHECK(!IsReadable(nullptr, 1));
    CHECK(!IsReadable((const void*)0x10, 4));

    // A zero length is not readable by definition.
    CHECK(!IsReadable(&local, 0));
}
