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
    ; The stub pushed the caller's rax (push rax), so on entry rsp is 16-aligned
    ; (a function entered via call would have rsp%16 = 8). Adjust by a multiple
    ; of 16 so the outgoing `call V8iHookEnter` is 16-aligned again: 88h = 8 mod
    ; 16 would misalign the callee's stack and crash CRT routines that use
    ; aligned SSE stores (movdqa) such as ucrtbase printf machinery.
    sub  rsp, 90h               ; shadow space + arg slots + spills (16-aligned)
    ; spills of the ORIGINAL registers (0x20..0x37 hold our 5th..7th args at
    ; call time, so the originals live above them)
    mov  [rsp+58h], rbp
    mov  [rsp+60h], rcx
    mov  [rsp+68h], rdx
    mov  [rsp+70h], r8
    mov  [rsp+78h], r9
    mov  [rsp+80h], rax         ; hook context survives the call here

    mov  rcx, [rsp+80h]         ; arg 1: context
    mov  rdx, [rsp+98h]         ; arg 2: the caller's return address (entry [rsp+8])
    mov  r8,  [rsp+58h]         ; arg 3: entry rbp (caller chain)
    mov  r9,  [rsp+60h]         ; arg 4: a0 (original rcx)
    mov  rax, [rsp+68h]
    mov  [rsp+20h], rax         ; arg 5: a1 (original rdx)
    mov  rax, [rsp+70h]
    mov  [rsp+28h], rax         ; arg 6: a2 (original r8)
    mov  rax, [rsp+78h]
    mov  [rsp+30h], rax         ; arg 7: a3 (original r9)
    call V8iHookEnter

    mov  r10, [rsp+80h]
    mov  r11, [r10]             ; ctx->trampoline

    mov  rcx, [rsp+60h]
    mov  rdx, [rsp+68h]
    mov  r8,  [rsp+70h]
    mov  r9,  [rsp+78h]
    add  rsp, 90h
    mov  rax, [rsp]             ; restore the caller's rax (the stub's push)
    add  rsp, 8
    jmp  r11
V8iThunkX64 ENDP

END
