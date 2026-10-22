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

.386
.model flat
option casemap:none

EXTERN _V8iHookEnter:PROC

.code

_V8iThunkX86 PROC
    pushad
    mov  ebp, esp
    and  esp, -16
    sub  esp, 8                 ; re-align so the compiled callee sees a 16-aligned stack
    push dword ptr [ebp+52]     ; a3
    push dword ptr [ebp+48]     ; a2
    push dword ptr [ebp+44]     ; a1
    push dword ptr [ebp+40]     ; a0
    push dword ptr [ebp+36]     ; caller's return address
    push dword ptr [ebp+32]     ; hook context
    call _V8iHookEnter
    add  esp, 24                ; cdecl: the caller cleans up

    ; The trampoline must be read AFTER popad: popad restores every general
    ; register from the stack, so a trampoline pointer loaded into edx or ecx
    ; before it would be overwritten (this used to jump to whatever the caller's
    ; edx happened to be -- usually 0).
    mov  esp, ebp
    popad
    add  esp, 4                 ; drop the context the stub pushed
    mov  ecx, dword ptr [esp-4] ; the context again
    mov  edx, dword ptr [ecx]   ; ctx->trampoline
    jmp  edx
_V8iThunkX86 ENDP

END
