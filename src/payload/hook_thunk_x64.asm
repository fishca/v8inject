; x64 register-capturing detour thunk.
;
; Entry state (set up by the per-hook stub):
;   rax      = pointer to HookCtx, whose first field is the trampoline address
;   [rsp]    = the caller's rax, pushed by the stub
;   [rsp+8]  = the caller's return address
;   rcx rdx r8 r9 = the original arguments (integer registers only)
;
; The thunk reports the call, then restores every register it touched and jumps
; into the trampoline, which runs the bytes the hook overwrote and re-enters the
; function. It never returns, so it needs no unwind data: an exception raised by
; the hooked function unwinds through the original frames, not through here.
;
; SSE argument registers (xmm0-xmm3) are deliberately not captured: the trace is
; a diagnostic, and saving 64 bytes of vector state per call would slow down the
; hooked function for no benefit yet.

option casemap:none

EXTERN V8iHookEnter:PROC

.code

V8iThunkX64 PROC
    sub  rsp, 68h               ; shadow space + spills, keeps rsp 16-byte aligned
    mov  [rsp+30h], rcx
    mov  [rsp+38h], rdx
    mov  [rsp+40h], r8
    mov  [rsp+48h], r9
    mov  [rsp+50h], rax         ; hook context survives the call here

    mov  rcx, [rsp+50h]         ; arg 1: context
    mov  rdx, [rsp+70h]         ; arg 2: the caller's return address
    mov  r8,  [rsp+30h]         ; arg 3: a0 (original rcx)
    mov  r9,  [rsp+38h]         ; arg 4: a1 (original rdx)
    mov  rax, [rsp+40h]
    mov  [rsp+20h], rax         ; arg 5: a2
    mov  rax, [rsp+48h]
    mov  [rsp+28h], rax         ; arg 6: a3
    call V8iHookEnter

    mov  r10, [rsp+50h]
    mov  r11, [r10]             ; ctx->trampoline

    mov  rcx, [rsp+30h]
    mov  rdx, [rsp+38h]
    mov  r8,  [rsp+40h]
    mov  r9,  [rsp+48h]
    add  rsp, 68h
    mov  rax, [rsp]             ; restore the caller's rax
    add  rsp, 8
    jmp  r11
V8iThunkX64 ENDP

END
