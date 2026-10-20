#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace v8i {

struct FuncInfo {
    uint32_t     index      = 0;
    int32_t      memid      = 0;
    std::wstring name;
    std::wstring typeName;   // METHOD / PROPERTYGET / PROPERTYPUT / PROPERTYPUTREF
    std::wstring funcKind;   // VIRTUAL / STATIC / DISPATCH / NONVIRTUAL
    uint16_t     oVft       = 0;
    uint16_t     cParams    = 0;
    uint16_t     cParamsOpt = 0;
    uint32_t     callconv   = 0;
    uint32_t     retVt      = 0;
    std::vector<uint32_t> paramVt;
};

struct TypeInfoReport {
    std::wstring moduleName;
    uintptr_t    moduleBase     = 0;
    std::wstring guid;
    uint32_t     typekind       = 0;
    uint32_t     cbSizeInstance = 0;
    uint16_t     cbSizeVft      = 0;
    uint16_t     cFuncs         = 0;
    uint16_t     cVars          = 0;
    uint16_t     cImplTypes     = 0;
    int32_t      memidCtor      = 0;
    int32_t      memidDtor      = 0;
    std::vector<FuncInfo> funcs;
};

std::string ToJson(const TypeInfoReport& r, bool pretty = true);

}  // namespace v8i
