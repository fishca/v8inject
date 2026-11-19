#pragma once
// Patching vtable slots of the 1C command receiver, transactionally.
//
// The native menu replaces three slots of the receiver's vtable with its own
// traps. Two defects this closes (docs/AUDIT.md A79):
//  * a patch that failed half-way left the slots already written trapped, so a
//    later attempt stored our trap into `orig` and the trap then called itself
//    (unbounded recursion);
//  * nothing refused to write a slot that already held our trap.
//
// A transaction is only kept when every slot was written: on the first failure
// the slots written before it are restored in reverse order.
//
// Header-only and pod: the payload uses it on the receiver vtable and the unit
// tests drive it on a plain array, so the rollback is tested without 1C.

#include <windows.h>

#include "v8inject/pe_utils.h"   // IsReadable: the slot must be ours before we touch it

namespace v8i {

struct SlotPatch {
    int slot;
    void* hook;
    uintptr_t orig;   // previous value, filled by PatchSlotsTransaction
};

// Writes one vtable slot. Fails when the slot pointer is not writable, when the
// slot is out of range, or when it already holds the hook (writing it again
// would make the hook call itself).
inline bool PatchSlot(uintptr_t* vt, int slot, void* hook, uintptr_t* origOut) {
    if (!vt || slot < 0 || slot > 0x1000 || !hook) return false;
    uintptr_t* slotPtr = vt + slot;
    if (!IsReadable(slotPtr, sizeof(void*))) return false;
    void* orig = (void*)*slotPtr;
    if (orig == hook) return false;   // already ours: a second write is recursion
    DWORD old = 0;
    if (!VirtualProtect(slotPtr, sizeof(void*), PAGE_EXECUTE_READWRITE, &old))
        return false;
    *slotPtr = (uintptr_t)hook;
    FlushInstructionCache(GetCurrentProcess(), slotPtr, sizeof(void*));
    VirtualProtect(slotPtr, sizeof(void*), old, &old);
    if (origOut) *origOut = (uintptr_t)orig;
    return true;
}

// Restores a slot previously written by PatchSlot.
inline bool RestoreSlot(uintptr_t* vt, int slot, uintptr_t orig) {
    if (!vt || slot < 0 || slot > 0x1000 || !orig) return false;
    uintptr_t* slotPtr = vt + slot;
    DWORD old = 0;
    if (!VirtualProtect(slotPtr, sizeof(void*), PAGE_EXECUTE_READWRITE, &old))
        return false;
    *slotPtr = orig;
    FlushInstructionCache(GetCurrentProcess(), slotPtr, sizeof(void*));
    VirtualProtect(slotPtr, sizeof(void*), old, &old);
    return true;
}

// Patches every slot, or none: a failure restores what was already written.
inline bool PatchSlotsTransaction(uintptr_t* vt, SlotPatch* patches, int count) {
    if (!vt || !patches || count <= 0) return false;
    for (int i = 0; i < count; ++i) {
        if (PatchSlot(vt, patches[i].slot, patches[i].hook, &patches[i].orig))
            continue;
        // Roll back in reverse order: the slots written before this one.
        for (int j = i - 1; j >= 0; --j) {
            if (!RestoreSlot(vt, patches[j].slot, patches[j].orig))
                return false;   // a slot we could not free: report the failure
        }
        return false;
    }
    return true;
}

}  // namespace v8i
