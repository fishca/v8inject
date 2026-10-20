#pragma once
#include <windows.h>
#include <string>

namespace v8i {

DWORD FindProcessByName(const wchar_t* exeName);
bool  IsProcess64(DWORD pid);
bool  InjectLibrary(DWORD pid, const std::wstring& dllPath);

}  // namespace v8i
