#pragma once

#include <windows.h>

namespace v8i {
namespace gitbar {

// GitBar settings dialog in the 1C classic look: git path, dump folder,
// default commit message and remote. Modal on top of `owner`.
void ShowSettings(HWND owner);

}  // namespace gitbar
}  // namespace v8i
