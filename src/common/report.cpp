#include "v8inject/report.h"
#include "v8inject/typeinfo_utils.h"
#include "v8inject/text.h"
#include <sstream>

namespace v8i {

namespace {

std::string U8(const std::wstring& w) {
    return WideToUtf8(w);
}

// JSON-escapes a wide string: it is converted to UTF-8 first, then the
// narrow escaper handles the special characters.
std::string JStr(const std::wstring& w) {
    return JsonEscape(U8(w));
}

}  // namespace

std::string ToJson(const TypeInfoReport& r, bool pretty) {
    const char* nl = pretty ? "\n" : "";
    const char* sp = pretty ? "  " : "";
    std::ostringstream o;

    o << "{" << nl;
    o << sp << "\"module\": \"" << JStr(r.moduleName) << "\"," << nl;
    o << sp << "\"moduleBase\": \"0x" << std::hex << r.moduleBase << std::dec << "\"," << nl;
    o << sp << "\"guid\": \"" << U8(r.guid) << "\"," << nl;
    o << sp << "\"typekind\": " << r.typekind << "," << nl;
    o << sp << "\"cbSizeInstance\": " << r.cbSizeInstance << "," << nl;
    o << sp << "\"cbSizeVft\": " << r.cbSizeVft << "," << nl;
    o << sp << "\"cFuncs\": " << r.cFuncs << "," << nl;
    o << sp << "\"cVars\": " << r.cVars << "," << nl;
    o << sp << "\"cImplTypes\": " << r.cImplTypes << "," << nl;
    o << sp << "\"memidCtor\": " << r.memidCtor << "," << nl;
    o << sp << "\"memidDtor\": " << r.memidDtor << "," << nl;
    o << sp << "\"funcs\": [" << nl;

    for (size_t i = 0; i < r.funcs.size(); ++i) {
        const FuncInfo& f = r.funcs[i];
        o << sp << sp << "{" << nl;
        o << sp << sp << sp << "\"index\": " << f.index << "," << nl;
        o << sp << sp << sp << "\"memid\": " << f.memid << "," << nl;
        o << sp << sp << sp << "\"name\": \"" << JStr(f.name) << "\"," << nl;
        o << sp << sp << sp << "\"kind\": \"" << U8(f.typeName) << "\"," << nl;
        o << sp << sp << sp << "\"funcKind\": \"" << U8(f.funcKind) << "\"," << nl;
        o << sp << sp << sp << "\"oVft\": " << f.oVft << "," << nl;
        o << sp << sp << sp << "\"cParams\": " << f.cParams << "," << nl;
        o << sp << sp << sp << "\"cParamsOpt\": " << f.cParamsOpt << "," << nl;
        o << sp << sp << sp << "\"callconv\": " << f.callconv << "," << nl;
        o << sp << sp << sp << "\"retVt\": " << f.retVt << "," << nl;

        o << sp << sp << sp << "\"params\": [";
        for (size_t k = 0; k < f.paramVt.size(); ++k) {
            if (k) o << ", ";
            o << f.paramVt[k];
        }
        o << "]" << nl;
        o << sp << sp << "}" << (i + 1 < r.funcs.size() ? "," : "") << nl;
    }

    o << sp << "]" << nl;
    o << "}" << nl;
    return o.str();
}

}  // namespace v8i
