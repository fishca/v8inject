// The names of COM types and of the calling conventions.
//
// These strings end up in the JSON report, and the platform spells them in a
// way the reader expects: a wrong name here is a wrong report.

#include "test_runner.h"

#include "v8inject/typeinfo_utils.h"

using namespace v8i;

V8I_TEST(TypeInfo_VariantTypeNames) {
    CHECK_EQ(std::wstring(VtName(VT_BSTR)), std::wstring(L"VT_BSTR"));
    CHECK_EQ(std::wstring(VtName(VT_I4)), std::wstring(L"VT_I4"));
    CHECK_EQ(std::wstring(VtName(VT_I2)), std::wstring(L"VT_I2"));
    CHECK_EQ(std::wstring(VtName(VT_DISPATCH)), std::wstring(L"VT_DISPATCH"));
    CHECK_EQ(std::wstring(VtName(VT_UNKNOWN)), std::wstring(L"VT_UNKNOWN"));
    CHECK_EQ(std::wstring(VtName(VT_HRESULT)), std::wstring(L"VT_HRESULT"));

    // An unknown type gets a visible placeholder, not an empty string.
    CHECK_EQ(std::wstring(VtName(0x7FFF)), std::wstring(L"VT_?"));
}

V8I_TEST(TypeInfo_InvokeKindNames) {
    CHECK_EQ(std::wstring(InvokeKindName(INVOKE_FUNC)), std::wstring(L"METHOD"));
    CHECK_EQ(std::wstring(InvokeKindName(INVOKE_PROPERTYGET)), std::wstring(L"PROPERTYGET"));
    CHECK_EQ(std::wstring(InvokeKindName(INVOKE_PROPERTYPUT)), std::wstring(L"PROPERTYPUT"));
    CHECK_EQ(std::wstring(InvokeKindName(INVOKE_PROPERTYPUTREF)), std::wstring(L"PROPERTYPUTREF"));
    CHECK_EQ(std::wstring(InvokeKindName(0xFF)), std::wstring(L"INVOKE_?"));
}

V8I_TEST(TypeInfo_FuncKindNames) {
    CHECK_EQ(std::wstring(FuncKindName(FUNC_VIRTUAL)), std::wstring(L"VIRTUAL"));
    CHECK_EQ(std::wstring(FuncKindName(FUNC_PUREVIRTUAL)), std::wstring(L"PUREVIRTUAL"));
    CHECK_EQ(std::wstring(FuncKindName(FUNC_NONVIRTUAL)), std::wstring(L"NONVIRTUAL"));
    CHECK_EQ(std::wstring(FuncKindName(FUNC_STATIC)), std::wstring(L"STATIC"));
    CHECK_EQ(std::wstring(FuncKindName(FUNC_DISPATCH)), std::wstring(L"DISPATCH"));
    CHECK_EQ(std::wstring(FuncKindName(0xFF)), std::wstring(L"FUNC_?"));
}

V8I_TEST(TypeInfo_GuidFormatting) {
    GUID g{};
    g.Data1 = 0x3573FFE0;
    g.Data2 = 0x2FFF;
    g.Data3 = 0x11D5;
    g.Data4[0] = 0xBF; g.Data4[1] = 0x5E; g.Data4[2] = 0x00; g.Data4[3] = 0x50;
    g.Data4[4] = 0xBA; g.Data4[5] = 0xE2; g.Data4[6] = 0xBC; g.Data4[7] = 0x79;

    const std::wstring s = GuidToString(g);
    CHECK_EQ(s, std::wstring(L"{3573FFE0-2FFF-11D5-BF5E-0050BAE2BC79}"));

    // The zero GUID has the same shape.
    const std::wstring z = GuidToString(GUID{});
    CHECK_EQ(z.size(), (size_t)38);
    CHECK_EQ(z.substr(0, 1), std::wstring(L"{"));
    CHECK_EQ(z.substr(37, 1), std::wstring(L"}"));
}
