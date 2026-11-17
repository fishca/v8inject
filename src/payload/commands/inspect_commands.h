#pragma once

#include <string>

namespace v8i {
namespace commands {

// Read-only inspection commands. They never execute code in the target and
// never follow pointers beyond classifying them; every reply is JSON.
std::string StrToJson(const std::wstring& args);
std::string PeekToJson(const std::wstring& args);
std::string PeToJson(const std::wstring& args);
std::string FindToJson(const std::wstring& args);
std::string DisasmToJson(const std::wstring& args);
std::string ImportsToJson(const std::wstring& args);
std::string ExportsToJson(const std::wstring& args);
std::string ModsToJson(const std::wstring& args);
std::string XrefToJson(const std::wstring& args);
std::string MemMapToJson(const std::wstring& args);
std::string HeapObjectsToJson(const std::wstring& args);
std::string FindValueToJson(const std::wstring& args);
std::string ByHwndToJson(const std::wstring& args);
std::string AroundToJson(const std::wstring& args);
std::string ObjectsToJson(const std::wstring& args);

}  // namespace commands
}  // namespace v8i
