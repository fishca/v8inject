#pragma once
#include <string>

namespace v8i {

// gitbar [hide] -- shows/hides the floating Git toolbar (created inside the
// 1C process, follows the configurator frame). Buttons run git.exe; see
// gitbar.cpp for the config file location.
std::string GitBarCommandToJson(const std::wstring& args);

}  // namespace v8i