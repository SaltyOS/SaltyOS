; SaltyOS Stage 3 Entry Stub
; SPDX-License-Identifier: GPL-2.0-only
;
; This stub ensures we have a known entry point at offset 0 of stage3.bin
; Stage 2 jumps here at 0x10000

[bits 64]

section .text.entry

global _start
extern stage3_main

_start:
    ; We're already in long mode with a valid stack from Stage 2
    ; Clear direction flag
    cld
    
    ; Call the C entry point
    call stage3_main
    
    ; If stage3_main returns (shouldn't happen), halt
    cli
.halt:
    hlt
    jmp .halt
