#pragma once

#include <windows.h>
#include <string>

namespace v8i {
namespace gitbar {

// Path of one `git status --porcelain` (v1) line: two fixed status columns, one
// space, then the path; a rename carries "old -> new" and the new path is the
// one git accepts. This is what the working-copy list hands to `git add/reset/
// checkout --`, so the status letters must never end up in the path (A54).
std::wstring PorcelainPath(const std::wstring& line);

// Generic list window: working copy, branches, stashes, tags. Modal on top of
// the configurator frame; actions run git on the button click and refill the
// list. `kind`: 0 working copy, 1 branches, 2 stashes, 3 tags.
void ShowList(HWND owner, int kind);

}  // namespace gitbar
}  // namespace v8i
