#include "v8inject/typeinfo_utils.h"
#include <comdef.h>
#include <cstdio>

namespace v8i {

HRESULT GetTypeInfoFromUnknown(IUnknown* unk, ITypeInfo** ti) {
    if (!unk || !ti) return E_POINTER;
    *ti = nullptr;

    ITypeInfo* direct = nullptr;
    if (SUCCEEDED(unk->QueryInterface(IID_ITypeInfo, (void**)&direct)) && direct) {
        *ti = direct;
        return S_OK;
    }

    IDispatch* disp = nullptr;
    HRESULT hr = unk->QueryInterface(IID_IDispatch, (void**)&disp);
    if (FAILED(hr) || !disp) return SUCCEEDED(hr) ? E_NOINTERFACE : hr;

    hr = disp->GetTypeInfo(0, GetUserDefaultLCID(), ti);
    disp->Release();
    return hr;
}

static void NamesOfMemid(ITypeInfo* ti, MEMBERID id,
                         std::wstring& method, std::vector<std::wstring>& params) {
    const UINT maxNames = 32;
    BSTR  tmp[maxNames] = {};
    UINT  count = 0;
    if (SUCCEEDED(ti->GetNames(id, tmp, maxNames, &count))) {
        for (UINT i = 0; i < count && i < maxNames; ++i) {
            if (!tmp[i]) continue;
            std::wstring s(tmp[i], SysStringLen(tmp[i]));
            SysFreeString(tmp[i]);
            tmp[i] = nullptr;
            if (i == 0) method = std::move(s);
            else        params.push_back(std::move(s));
        }
    }
    for (UINT i = 0; i < maxNames; ++i)
        if (tmp[i]) SysFreeString(tmp[i]);
}

HRESULT ScanTypeInfo(ITypeInfo* ti, TypeInfoReport& out) {
    if (!ti) return E_POINTER;

    TYPEATTR* ta = nullptr;
    HRESULT hr = ti->GetTypeAttr(&ta);
    if (FAILED(hr) || !ta) return FAILED(hr) ? hr : E_FAIL;

    out.guid           = GuidToString(ta->guid);
    out.typekind       = ta->typekind;
    out.cbSizeInstance = ta->cbSizeInstance;
    out.cbSizeVft      = ta->cbSizeVft;
    out.cFuncs         = ta->cFuncs;
    out.cVars          = ta->cVars;
    out.cImplTypes     = ta->cImplTypes;
    out.memidCtor      = ta->memidConstructor;
    out.memidDtor      = ta->memidDestructor;

    out.funcs.reserve(ta->cFuncs);

    for (WORD i = 0; i < ta->cFuncs; ++i) {
        FUNCDESC* fd = nullptr;
        if (FAILED(ti->GetFuncDesc(i, &fd)) || !fd) continue;

        FuncInfo fi;
        fi.index      = i;
        fi.memid      = fd->memid;
        fi.oVft       = fd->oVft;
        fi.cParams    = fd->cParams;
        fi.cParamsOpt = fd->cParamsOpt;
        fi.callconv   = fd->callconv;
        fi.funcKind   = FuncKindName(fd->funckind);
        fi.typeName   = InvokeKindName(fd->invkind);
        fi.retVt      = (uint32_t)fd->elemdescFunc.tdesc.vt;

        std::wstring method;
        std::vector<std::wstring> pnames;
        NamesOfMemid(ti, fd->memid, method, pnames);
        fi.name = method.empty() ? L"<noname>" : method;

        if (fd->lprgelemdescParam) {
            for (short p = 0; p < fd->cParams; ++p)
                fi.paramVt.push_back((uint32_t)fd->lprgelemdescParam[p].tdesc.vt);
        }

        out.funcs.push_back(std::move(fi));
        ti->ReleaseFuncDesc(fd);
    }

    ti->ReleaseTypeAttr(ta);
    return S_OK;
}

const wchar_t* VtName(uint32_t vt) {
    switch (vt) {
    case VT_EMPTY:   return L"VT_EMPTY";
    case VT_NULL:    return L"VT_NULL";
    case VT_I2:      return L"VT_I2";
    case VT_I4:      return L"VT_I4";
    case VT_R4:      return L"VT_R4";
    case VT_R8:      return L"VT_R8";
    case VT_CY:      return L"VT_CY";
    case VT_DATE:    return L"VT_DATE";
    case VT_BSTR:    return L"VT_BSTR";
    case VT_DISPATCH:return L"VT_DISPATCH";
    case VT_ERROR:   return L"VT_ERROR";
    case VT_BOOL:    return L"VT_BOOL";
    case VT_VARIANT: return L"VT_VARIANT";
    case VT_UNKNOWN: return L"VT_UNKNOWN";
    case VT_DECIMAL: return L"VT_DECIMAL";
    case VT_I1:      return L"VT_I1";
    case VT_UI1:     return L"VT_UI1";
    case VT_UI2:     return L"VT_UI2";
    case VT_UI4:     return L"VT_UI4";
    case VT_I8:      return L"VT_I8";
    case VT_UI8:     return L"VT_UI8";
    case VT_INT:     return L"VT_INT";
    case VT_UINT:    return L"VT_UINT";
    case VT_VOID:    return L"VT_VOID";
    case VT_HRESULT: return L"VT_HRESULT";
    case VT_PTR:     return L"VT_PTR";
    case VT_LPSTR:   return L"VT_LPSTR";
    case VT_LPWSTR:  return L"VT_LPWSTR";
    default:         return L"VT_?";
    }
}

const wchar_t* InvokeKindName(uint32_t invkind) {
    switch (invkind) {
    case INVOKE_FUNC:           return L"METHOD";
    case INVOKE_PROPERTYGET:    return L"PROPERTYGET";
    case INVOKE_PROPERTYPUT:    return L"PROPERTYPUT";
    case INVOKE_PROPERTYPUTREF: return L"PROPERTYPUTREF";
    default:                    return L"INVOKE_?";
    }
}

const wchar_t* FuncKindName(uint32_t funckind) {
    switch (funckind) {
    case FUNC_VIRTUAL:     return L"VIRTUAL";
    case FUNC_PUREVIRTUAL: return L"PUREVIRTUAL";
    case FUNC_NONVIRTUAL:  return L"NONVIRTUAL";
    case FUNC_STATIC:      return L"STATIC";
    case FUNC_DISPATCH:    return L"DISPATCH";
    default:               return L"FUNC_?";
    }
}

std::wstring GuidToString(const GUID& g) {
    wchar_t buf[64] = {};
    _snwprintf_s(buf, _TRUNCATE,
                 L"{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
                 g.Data1, g.Data2, g.Data3,
                 g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
                 g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    return buf;
}

}  // namespace v8i
