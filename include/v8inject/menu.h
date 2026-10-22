#pragma once
#include <string>

namespace v8i {

// menu [filter] -- windows of this process and their menu items, as JSON.
// Enumerates menus in-process because the designer's menu bar is a custom MFC
// control that GetMenu() cannot see from another process.
std::string MenuCommandToJson(const std::wstring& args);

// menucmd <hwnd> <menu-id> -- posts WM_COMMAND to that window.
std::string MenuCmdToJson(const std::wstring& args);

}  // namespace v8i