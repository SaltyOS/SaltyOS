; SPDX-License-Identifier: GPL-2.0-only
;
; SaltyOS Bootloader - Mode Switch (32-bit → 64-bit)
;
; This module transitions from 32-bit protected mode to 64-bit long mode
; and jumps directly to the kernel entry point.
;
; A single function enter_long_mode_and_jump_asm performs the entire
; transition atomically, avoiding the deadlock that occurred when
; switch_to_long_mode and jump_to_kernel_64 were separate functions.
;

[BITS 32]

; ============================================================================
; Constants
; ============================================================================

; CR0 bits
CR0_PE              equ (1 << 0)        ; Protected Mode Enable
CR0_PG              equ (1 << 31)       ; Paging Enable

; CR4 bits
CR4_PAE             equ (1 << 5)        ; Physical Address Extension

; EFER MSR
EFER_MSR            equ 0xC0000080
EFER_LME            equ (1 << 8)        ; Long Mode Enable

; GDT selectors
SEL_CODE64          equ 0x08
SEL_DATA64          equ 0x10

; ============================================================================
; enter_long_mode_and_jump_asm
; ============================================================================
;
; Combined function: enable long mode and jump to kernel in one step.
;
; cdecl calling convention (32-bit):
;   [esp+4]  = pml4       (uint32_t) - Physical address of PML4 table
;   [esp+8]  = entry_lo   (uint32_t) - Kernel entry point (low 32 bits)
;   [esp+12] = entry_hi   (uint32_t) - Kernel entry point (high 32 bits)
;   [esp+16] = bootinfo_lo(uint32_t) - BootInfo pointer (low 32 bits)
;   [esp+20] = bootinfo_hi(uint32_t) - BootInfo pointer (high 32 bits)
;   [esp+24] = stack_lo   (uint32_t) - Kernel stack top (low 32 bits)
;   [esp+28] = stack_hi   (uint32_t) - Kernel stack top (high 32 bits)
;
; This function does NOT return.

section .text
global enter_long_mode_and_jump_asm
enter_long_mode_and_jump_asm:
    ; Save parameters to data section (stack won't survive mode switch)
    mov     eax, [esp+4]
    mov     [saved_pml4], eax

    mov     eax, [esp+8]
    mov     [kernel_entry], eax
    mov     eax, [esp+12]
    mov     [kernel_entry+4], eax

    mov     eax, [esp+16]
    mov     [bootinfo_ptr], eax
    mov     eax, [esp+20]
    mov     [bootinfo_ptr+4], eax

    mov     eax, [esp+24]
    mov     [kernel_stack], eax
    mov     eax, [esp+28]
    mov     [kernel_stack+4], eax

    ; Disable interrupts
    cli

    ; Enable PAE (Physical Address Extension)
    mov     eax, cr4
    or      eax, CR4_PAE
    mov     cr4, eax

    ; Load PML4 address into CR3
    mov     eax, [saved_pml4]
    mov     cr3, eax

    ; Enable Long Mode via EFER MSR
    mov     ecx, EFER_MSR
    rdmsr
    or      eax, EFER_LME
    wrmsr

    ; Enable Paging (and thus activate Long Mode)
    mov     eax, cr0
    or      eax, CR0_PG
    mov     cr0, eax

    ; Load 64-bit GDT
    lgdt    [gdt64_ptr]

    ; Far jump to 64-bit code segment
    jmp     SEL_CODE64:kernel_trampoline_64

; ============================================================================
; 64-bit Kernel Trampoline
; ============================================================================

[BITS 64]

kernel_trampoline_64:
    ; Set up 64-bit data segments
    mov     ax, SEL_DATA64
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    ; Load kernel stack
    mov     rsp, [rel kernel_stack]

    ; Clear registers
    xor     rax, rax
    xor     rbx, rbx
    xor     rcx, rcx
    xor     rdx, rdx
    xor     rsi, rsi
    xor     rbp, rbp
    xor     r8, r8
    xor     r9, r9
    xor     r10, r10
    xor     r11, r11
    xor     r12, r12
    xor     r13, r13
    xor     r14, r14
    xor     r15, r15

    ; First argument: BootInfo pointer in RDI (System V AMD64 ABI)
    mov     rdi, [rel bootinfo_ptr]

    ; Jump to kernel entry point
    mov     rax, [rel kernel_entry]
    jmp     rax

; ============================================================================
; Data
; ============================================================================

section .data

; Saved parameters for mode switch
saved_pml4:     dd 0
kernel_entry:   dq 0
bootinfo_ptr:   dq 0
kernel_stack:   dq 0

; 64-bit GDT
align 16
gdt64_start:
    ; Null descriptor (0x00)
    dq 0

    ; 64-bit code segment (0x08)
    dw 0x0000               ; Limit low (ignored in long mode)
    dw 0x0000               ; Base low
    db 0x00                 ; Base middle
    db 0x9A                 ; Access: Present, Ring 0, Code, Exec, Readable
    db 0xAF                 ; Flags: Long mode, Limit high
    db 0x00                 ; Base high

    ; 64-bit data segment (0x10)
    dw 0x0000               ; Limit low (ignored in long mode)
    dw 0x0000               ; Base low
    db 0x00                 ; Base middle
    db 0x92                 ; Access: Present, Ring 0, Data, Writable
    db 0x00                 ; Flags
    db 0x00                 ; Base high
gdt64_end:

; GDT pointer - 32-bit lgdt reads 6 bytes (2 limit + 4 base),
; 64-bit lgdt reads 10 bytes (2 limit + 8 base).
; Using dd+dd ensures correct layout for both modes.
gdt64_ptr:
    dw gdt64_end - gdt64_start - 1  ; Limit (2 bytes)
    dd gdt64_start                  ; Base low 32 bits (4 bytes)
    dd 0                            ; Base high 32 bits (4 bytes)
