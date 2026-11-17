#pragma once

#include <windows.h>

namespace v8i {
namespace gitbar {

// Git history viewer in the configurator: the lane graph, ref badges and diff
// pane borrowed from v8GitView, dressed in the classic 1C skin. The dialog is
// modal on top of the configurator frame; it reuses the panel's theme helpers
// (git_ui.h) and reads history through the git service (git_service.h).
void ShowGitLog(HWND owner);

}  // namespace gitbar
}  // namespace v8i
