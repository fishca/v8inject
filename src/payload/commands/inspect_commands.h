#pragma once

#include <cstddef>
#include <string>

namespace v8i {
namespace commands {

// How many exports of a module go into the reply of `pe`. A large platform
// module has hundreds if not thousands of them and the whole table does not fit
// the block's response buffer, so the reply names the first ones and says that
// it stopped (`"exportsTruncated":true`, docs/AUDIT.md A46).
constexpr size_t kPeMaxExports = 200;

// Caps of the scanner commands (docs/AUDIT.md A83). A count comes from the
// command line, and the old local parser cast "-1" to size_t: one typo turned
// `heapobjects --count -1`/`find --max -1` into an unbounded collection over
// the whole address space - megabytes of hits and a timeout instead of a reply.
// Every count is parsed with v8i::ParseNumber and checked against these caps.
constexpr size_t kMaxCount = 8192;          // disasm/xref/find/findvalue rows
constexpr size_t kMaxHeapObjects = 200000;  // heapobjects --count
constexpr size_t kMaxMemMapRows = 4096;     // memmap --count
constexpr size_t kMaxByHwndHits = 256;      // byhwnd --count
constexpr size_t kMaxHwndOffset = 0x1000;   // byhwnd --offset

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
