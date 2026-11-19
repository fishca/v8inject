; x64 register-capturing detour thunk.
;
; Entry state (set up by the per-hook stub):
;   rax      = pointer to HookCtx, whose first field is the trampoline address
;   [rsp]    = the caller's rax, pushed by the stub
;   [rsp+8]  = the caller's return address
;   rcx rdx r8 r9 = the original arguments (integer registers)
;   xmm0-xmm3     = the original float/double arguments
;
; The thunk reports the call, then restores every register it touched and jumps
; into the trampoline, which runs the bytes the hook overwrote and re-enters the
; function. It never returns, so it needs no unwind data: an exception raised by
; the hooked function unwinds through the original frames, not through here.
;
; A59: the reporter (V8iHookEnter) is ordinary C++, so for it every SSE register
; is volatile. A hooked function with a float or double argument would get its
; xmm0-xmm3 back from the reporter holding whatever the CRT left there, and the
; trampoline would then replay a prologue that reads them. The six registers the
; Windows x64 ABI uses for arguments are therefore saved on entry and restored
; after the call. (xmm6-15 are callee-saved and the reporter preserves them.)

option casemap:none

EXTERN V8iHookEnter:PROC

.code

V8iThunkX64 PROC
    ; The stub pushed the caller's rax (push rax), so on entry rsp is 16-aligned
    ; (a function entered via call would have rsp%16 = 8). Adjust by a multiple
    ; of 16 so the outgoing `call V8iHookEnter` is 16-aligned again: any
    ; non-multiple would misalign the callee's stack and crash CRT routines that
    ; use aligned SSE stores (movdqa), such as ucrtbase printf machinery.
    ;
    ; Frame layout (rsp-relative, after the sub):
    ;   0x00..0x1F  shadow space of the outgoing call
    ;   0x20..0x37  arguments 5..7 of the report (see the moves below)
    ;   0x58..0x87  the caller's rbp/rcx/rdx/r8/r9/rax
    ;   0x90..0xEF  the caller's xmm0..xmm5
    ;   0x100       the caller's rax, pushed by the stub
    ;   0x108       the caller's return address
    sub  rsp, 100h              ; 16-aligned frame, 256 bytes
    mov  [rsp+58h], rbp
    mov  [rsp+60h], rcx
    mov  [rsp+68h], rdx
    mov  [rsp+70h], r8
    mov  [rsp+78h], r9
    mov  [rsp+80h], rax         ; hook context survives the call here

    ; A59: preserve the vector argument registers across the C++ reporter.
    ; movups, not movaps: the offsets are 16-aligned here, but the thunk must
    ; not depend on an alignment it cannot check.
    movups [rsp+090h], xmm0
    movups [rsp+0A0h], xmm1
    movups [rsp+0B0h], xmm2
    movups [rsp+0C0h], xmm3
    movups [rsp+0D0h], xmm4
    movups [rsp+0E0h], xmm5

    mov  rcx, [rsp+80h]         ; arg 1: context
    mov  rdx, [rsp+108h]        ; arg 2: the caller's return address
    mov  r8,  [rsp+58h]         ; arg 3: entry rbp (caller chain)
    mov  r9,  [rsp+60h]         ; arg 4: a0 (original rcx)
    mov  rax, [rsp+68h]
    mov  [rsp+20h], rax         ; arg 5: a1 (original rdx)
    mov  rax, [rsp+70h]
    mov  [rsp+28h], rax         ; arg 6: a2 (original r8)
    mov  rax, [rsp+78h]
    mov  [rsp+30h], rax         ; arg 7: a3 (original r9)
    call V8iHookEnter

    movups xmm0, [rsp+090h]
    movups xmm1, [rsp+0A0h]
    movups xmm2, [rsp+0B0h]
    movups xmm3, [rsp+0C0h]
    movups xmm4, [rsp+0D0h]
    movups xmm5, [rsp+0E0h]

    mov  r10, [rsp+80h]
    mov  r11, [r10]             ; ctx->trampoline

    mov  rcx, [rsp+60h]
    mov  rdx, [rsp+68h]
    mov  r8,  [rsp+70h]
    mov  r9,  [rsp+78h]
    add  rsp, 100h
    mov  rax, [rsp]             ; restore the caller's rax (the stub's push)
    add  rsp, 8
    jmp  r11
V8iThunkX64 ENDP

END
