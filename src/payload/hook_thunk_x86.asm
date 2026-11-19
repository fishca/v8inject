; x86 detour thunk.
;
; Entry state (set up by the per-hook stub):
;   [esp]   = pointer to HookCtx, whose first field is the trampoline address
;   [esp+4] = the caller's return address
;   [esp+8] = the first stack argument, then the rest
;
; x86 passes arguments on the stack, so the "captured arguments" here are the
; first four stack slots rather than registers. pushad/popad keeps every
; register the caller could care about, including the non-volatile ones that a
; hand-written 1C call sequence might rely on.
;
; A59: the registers pushad/popad covers are also the argument registers of the
; other calling conventions -- ecx/edx for __fastcall, ecx for the `this`
; pointer of __thiscall. The old tail loaded the trampoline into ecx/edx AFTER
; popad, which the trampoline's first instruction then handed to the hooked
; function as `this` (garbage) or as its first two arguments. The trampoline
; address is therefore left where the stub put the context, and the jump into
; it is a `ret`: it consumes that slot and enters the trampoline with the stack
; exactly as the caller's `call` left it, without touching a single register.
;
; A92: the stack handed to the C++ reporter has to satisfy the x86 convention
; the reporter was compiled for: on entry to a function esp+4 is 16-aligned.
; The pushes below leave esp at 12 (mod 16) before the call, so the callee sees
; the alignment it expects after the call pushes its return address.

.386
.model flat
option casemap:none

EXTERN _V8iHookEnter:PROC

.code

_V8iThunkX86 PROC
    pushad
    mov  ebp, esp

    ; [ebp+32] is the HookCtx the stub pushed; above the pushad block it
    ; survives popad. Read the trampoline through it now, while it is still the
    ; context, and leave the trampoline in that slot: the `ret` at the end then
    ; enters it with the stack pointer where the function's entry expects it.
    ; eax/ebx may be clobbered here: popad restores them from the stack below.
    mov  eax, dword ptr [ebp+32]    ; ctx
    mov  ebx, dword ptr [eax]       ; ctx->trampoline
    mov  dword ptr [ebp+32], ebx    ; the ctx slot becomes the jump target

    and  esp, -16
    sub  esp, 4                 ; 12 (mod 16) before the call: see A92 above
    push dword ptr [ebp+52]     ; a3
    push dword ptr [ebp+48]     ; a2
    push dword ptr [ebp+44]     ; a1
    push dword ptr [ebp+40]     ; a0
    push dword ptr [ebp+8]      ; entry ebp (the one pushad saved at [new+8])
    push dword ptr [ebp+36]     ; caller's return address
    push eax                    ; hook context (eax still holds it)
    call _V8iHookEnter
    add  esp, 28                ; cdecl: the caller cleans up (7 args)

    mov  esp, ebp
    popad                       ; restores every general register
    ret                         ; enters the trampoline, esp -> caller's return
_V8iThunkX86 ENDP

; The linker builds x86 images with /SAFESEH, and an object without an .sxdata
; entry makes that fatal (LNK2026 -> LNK1281). This thunk never registers itself
; as an exception handler, but listing it tells the linker the code is accounted
; for, which is what SAFESEH actually checks.
.safeseh _V8iThunkX86

END
