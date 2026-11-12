// The JSON report of a type library.
//
// The report is assembled by hand, so the test checks two things: that the
// fields are there and that the result is a well-formed JSON document.

#include "json_check.h"
#include "test_runner.h"

#include "v8inject/report.h"

using namespace v8i;
using namespace v8i::test;

namespace {

TypeInfoReport SampleReport() {
    TypeInfoReport r;
    r.moduleName   = L"core83.dll";
    r.moduleBase   = 0x00400000ull;
    r.guid         = L"{3573FFE0-2FFF-11D5-BF5E-0050BAE2BC79}";
    r.typekind     = 0x18;
    r.cbSizeInstance = 24;
    r.cbSizeVft    = 8;
    r.cFuncs       = 2;
    r.cVars        = 1;
    r.cImplTypes   = 3;
    r.memidCtor    = 1610612736;
    r.memidDtor    = 1610612737;

    FuncInfo f;
    f.index      = 0;
    f.memid      = 0x60000001;
    f.name       = L"ОткрытьФорму";
    f.typeName   = L"METHOD";
    f.funcKind   = L"VIRTUAL";
    f.oVft       = 3;
    f.cParams    = 2;
    f.cParamsOpt = 1;
    f.callconv   = 1;
    f.retVt      = 8;             // VT_BSTR
    f.paramVt.push_back(3);       // VT_I4
    f.paramVt.push_back(8);       // VT_BSTR
    r.funcs.push_back(f);

    FuncInfo g = f;
    g.index = 1;
    g.name  = L"Значение";
    g.typeName = L"PROPERTYGET";
    g.cParams = 0;
    g.paramVt.clear();
    r.funcs.push_back(g);

    return r;
}

}  // namespace

V8I_TEST(Report_IsWellFormedJson) {
    const TypeInfoReport r = SampleReport();

    std::string err;
    const std::string compact = ToJson(r, false);
    CHECK(JsonValid(compact, &err));
    if (!JsonValid(compact, &err)) CHECK(err.empty());   // prints the reason

    const std::string pretty = ToJson(r, true);
    CHECK(JsonValid(pretty, &err));

    // The compact form has no line breaks, the pretty one does.
    CHECK(compact.find('\n') == std::string::npos);
    CHECK(pretty.find('\n') != std::string::npos);
}

V8I_TEST(Report_ContainsTheFields) {
    const std::string json = ToJson(SampleReport(), false);

    CHECK(json.find("\"module\": \"core83.dll\"") != std::string::npos);
    CHECK(json.find("\"moduleBase\": \"0x400000\"") != std::string::npos);
    CHECK(json.find("\"typekind\": 24") != std::string::npos);
    CHECK(json.find("\"cFuncs\": 2") != std::string::npos);
    CHECK(json.find("\"name\": \"ОткрытьФорму\"") != std::string::npos);
    CHECK(json.find("\"kind\": \"METHOD\"") != std::string::npos);
    CHECK(json.find("\"funcKind\": \"VIRTUAL\"") != std::string::npos);
    CHECK(json.find("\"params\": [3, 8]") != std::string::npos);
}

V8I_TEST(Report_EscapesSpecialCharacters) {
    TypeInfoReport r = SampleReport();
    r.moduleName = L"папка\\with\"quotes";
    FuncInfo f = r.funcs[0];
    f.name = L"line\nbreak\ttab";
    r.funcs[0] = f;

    const std::string json = ToJson(r, false);
    std::string err;
    CHECK(JsonValid(json, &err));

    // The raw quote and the raw backslash must not survive unescaped.
    CHECK(json.find("with\"quotes") == std::string::npos);
    CHECK(json.find("with\\\"quotes") != std::string::npos);
    CHECK(json.find("line\nbreak") == std::string::npos);
    CHECK(json.find("line\\nbreak") != std::string::npos);
}

V8I_TEST(Report_EmptyReportIsStillJson) {
    TypeInfoReport r;
    r.moduleName = L"empty.dll";
    const std::string json = ToJson(r, false);
    std::string err;
    CHECK(JsonValid(json, &err));
    CHECK(json.find("\"funcs\": []") != std::string::npos);
}
