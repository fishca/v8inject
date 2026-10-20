#pragma once
#include "v8inject/report.h"
#include <windows.h>
#include <oaidl.h>

namespace v8i {

// Extracts ITypeInfo from any IUnknown (falls back to IDispatch::GetTypeInfo).
// On success the caller owns *ti and must Release() it.
HRESULT GetTypeInfoFromUnknown(IUnknown* unk, ITypeInfo** ti);

// Walks the type library and fills the report. Does not take ownership of ti.
HRESULT ScanTypeInfo(ITypeInfo* ti, TypeInfoReport& out);

const wchar_t* VtName(uint32_t vt);
const wchar_t* InvokeKindName(uint32_t invkind);
const wchar_t* FuncKindName(uint32_t funckind);
std::wstring GuidToString(const GUID& g);

}  // namespace v8i
