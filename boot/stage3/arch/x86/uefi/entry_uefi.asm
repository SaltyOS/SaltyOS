; SPDX-License-Identifier: GPL-2.0-only
;
; SaltyOS Bootloader - Stage 3 Entry Point for UEFI (64-bit)
;
; When coming from UEFI:
; - We're already in 64-bit long mode
; - Paging is enabled with identity mapping
; - Interrupts are disabled
; - RCX = pointer to Stage2Info (MS ABI calling convention)
;
; This entry point:
; - Sets up a proper stack
; - Clears BSS
; - Calls stage3_entry_64()
;

bits 64

section .text.entry

global _start_uefi
global stage3_entry_64_asm
extern stage3_entry_64
extern __bss_start
extern __bss_end

; Stack for Stage 3 (64KB below 1.5MB - avoids kernel preload at 2MB)
STACK_TOP   equ 0x180000
STACK_SIZE  equ 0x10000

; ABI Bridge: Stage 2 UEFI calls us with MS x64 ABI (arg1 in RCX).
; Stage 3 C code is compiled with System V AMD64 ABI (arg1 in RDI).
; We save RCX -> R12 across BSS clearing, then pass via RDI before
; calling stage3_entry_64().
;
; Input:
;   RCX = Stage2Info pointer (MS x64 ABI)
;
_start_uefi:
stage3_entry_64_asm:
    ; Disable interrupts (should already be disabled)
    cli

    ; Save Stage2Info pointer
    mov r12, rcx

    ; Set up stack
    mov rsp, STACK_TOP
    xor rbp, rbp

    ; Clear BSS
    lea rdi, [rel __bss_start]
    lea rcx, [rel __bss_end]
    sub rcx, rdi
    shr rcx, 3          ; Convert to qwords
    xor rax, rax
    rep stosq

    ; Call C entry point
    ; Use System V AMD64 ABI: first argument in RDI
    mov rdi, r12        ; Stage2Info pointer
    call stage3_entry_64

    ; Should never return, but halt if it does
.hang:
    cli
    hlt
    jmp .hang
