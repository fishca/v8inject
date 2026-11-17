#pragma once

#include <windows.h>

namespace v8i {
namespace gitbar {

// Generic list window: working copy, branches, stashes, tags. Modal on top of
// the configurator frame; actions run git on the button click and refill the
// list. `kind`: 0 working copy, 1 branches, 2 stashes, 3 tags.
void ShowList(HWND owner, int kind);

}  // namespace gitbar
}  // namespace v8i
