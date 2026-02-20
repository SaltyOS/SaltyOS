; SPDX-License-Identifier: GPL-2.0-only
;
; SaltyOS Bootloader - Stage 3 Entry Point (x86_64)
;
; This is the 32-bit protected mode entry point for Stage 3.
; Stage 2 jumps here after setting up protected mode.
;
; Entry state:
;   - 32-bit protected mode
;   - EDI = Stage2Info physical address
;   - A20 enabled
;   - Interrupts disabled
;   - ESP = protected mode stack (0x9FFF0)
;

[BITS 32]

; ============================================================================
; Constants
; ============================================================================

STAGE2_INFO_ADDR    equ 0x1000          ; Fixed Stage2Info address (matches Stage 2)
STAGE3_STACK_SIZE   equ 0x10000         ; 64 KB stack

; ============================================================================
; Entry Point
; ============================================================================

section .text.entry
global _start
_start:
    ; EDI contains Stage2Info pointer (from Stage 2)
    ; Save it before clearing BSS (which clobbers EDI)
    mov     esi, edi                ; Save in ESI

    ; Clear BSS
    extern __bss_start
    extern __bss_end

    cld                             ; Ensure forward direction for rep stosb
    mov     edi, __bss_start
    mov     ecx, __bss_end
    sub     ecx, edi
    xor     al, al
    rep     stosb

    ; Restore Stage2Info pointer
    ; If ESI is 0 (wasn't passed), use fixed address
    test    esi, esi
    jnz     .have_info
    mov     esi, STAGE2_INFO_ADDR
.have_info:

    ; Set up our own stack
    extern __stack_top
    mov     esp, __stack_top

    ; Call C entry point
    ; In 32-bit cdecl, first argument goes on stack
    push    esi                     ; Stage2Info *info
    extern  stage3_entry
    call    stage3_entry
    add     esp, 4

    ; Should never return
    cli
.halt:
    hlt
    jmp     .halt
