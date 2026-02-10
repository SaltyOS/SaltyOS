//! AP (Application Processor) Trampoline
//!
//! Real-mode startup code placed at physical 0x8000. The BSP copies this
//! code there, then sends INIT+SIPI to each AP. The AP wakes in 16-bit
//! real mode, transitions through 32-bit protected mode, then to 64-bit
//! long mode, and finally calls ap_entry(cpu_id) in Rust.
//!
//! Communication area (set by BSP before SIPI):
//!   0x8FF0: PML4 physical address (u64)
//!   0x8FF8: per-CPU kernel stack top (u64)
//!   0x8FE8: cpu_id (u32)
//!   0x8FE0: ap_entry function pointer (u64)
//!
//! SPDX-License-Identifier: GPL-2.0-only

.section .text
.code16

.global ap_trampoline_start
.global ap_trampoline_end

ap_trampoline_start:
    // ===== 16-bit Real Mode =====
    cli
    cld

    // Set up real-mode segments
    // SIPI starts with CS = vector << 8 = 0x0800, IP = 0x0000
    // Set DS = ES = SS = 0 so we can use flat physical addresses
    xor  %ax, %ax
    mov  %ax, %ds
    mov  %ax, %es
    mov  %ax, %ss

    // Debug: write magic value 0xCAFE to 0x8F00 to prove we executed
    mov  $0xCAFE, %ax
    mov  %ax, 0x8F00

    // Load temporary GDT for 32-bit transition
    // DS=0, so effective address = 0 + operand = physical address
    lgdt (_ap_gdt32_ptr - ap_trampoline_start + 0x8000)

    // Enable Protected Mode (CR0.PE = 1)
    mov  %cr0, %eax
    or   $1, %eax
    mov  %eax, %cr0

    // Far jump to 32-bit code (flush prefetch queue)
    .byte 0x66, 0xEA                   // ljmp (32-bit operand prefix)
    .long _ap_pm32 - ap_trampoline_start + 0x8000  // offset
    .word 0x08                          // code32 selector

.code32
_ap_pm32:
    // ===== 32-bit Protected Mode =====
    mov  $0x10, %ax
    mov  %ax, %ds
    mov  %ax, %es
    mov  %ax, %ss

    // Enable PAE (CR4.PAE bit 5)
    mov  %cr4, %eax
    or   $(1 << 5), %eax
    mov  %eax, %cr4

    // Load PML4 into CR3 (set by BSP at 0x8FF0)
    mov  0x8FF0, %eax
    mov  %eax, %cr3

    // Enable Long Mode via IA32_EFER MSR (bit 8 = LME, bit 11 = NXE)
    mov  $0xC0000080, %ecx
    rdmsr
    or   $(1 << 8), %eax
    or   $(1 << 11), %eax
    wrmsr

    // Enable Paging (CR0.PG bit 31) + Write Protect (CR0.WP bit 16)
    mov  %cr0, %eax
    or   $(1 << 31), %eax
    or   $(1 << 16), %eax
    mov  %eax, %cr0

    // Load 64-bit GDT
    lgdt (_ap_gdt64_ptr - ap_trampoline_start + 0x8000)

    // Far jump to 64-bit code
    .byte 0xEA                          // ljmp
    .long _ap_lm64 - ap_trampoline_start + 0x8000  // offset
    .word 0x08                          // code64 selector

.code64
_ap_lm64:
    // ===== 64-bit Long Mode =====
    mov  $0x10, %ax
    mov  %ax, %ds
    mov  %ax, %es
    mov  %ax, %ss
    xor  %ax, %ax
    mov  %ax, %fs
    mov  %ax, %gs

    // Load per-CPU kernel stack (set by BSP at 0x8FF8)
    mov  0x8FF8, %rsp

    // Clear RFLAGS
    push $0
    popfq

    // Load cpu_id into RDI (first argument)
    xor  %rdi, %rdi
    mov  0x8FE8, %edi

    // Load ap_entry function pointer (set by BSP at 0x8FE0)
    mov  0x8FE0, %rax

    // Call ap_entry(cpu_id)
    call *%rax

    // Should never return
_ap_halt:
    hlt
    jmp  _ap_halt

// ===== Temporary 32-bit GDT (used only for real → protected transition) =====
.align 16
_ap_gdt32:
    // Null descriptor
    .quad 0
    // Code32: base=0, limit=4G, 32-bit, executable, readable
    .word 0xFFFF       // limit low
    .word 0x0000       // base low
    .byte 0x00         // base mid
    .byte 0x9A         // access: P=1 DPL=0 S=1 E=1 R=1
    .byte 0xCF         // flags: G=1 D=1, limit high=0xF
    .byte 0x00         // base high
    // Data32: base=0, limit=4G, 32-bit, writable
    .word 0xFFFF       // limit low
    .word 0x0000       // base low
    .byte 0x00         // base mid
    .byte 0x92         // access: P=1 DPL=0 S=1 W=1
    .byte 0xCF         // flags: G=1 D=1, limit high=0xF
    .byte 0x00         // base high
_ap_gdt32_end:

.align 4
_ap_gdt32_ptr:
    .word _ap_gdt32_end - _ap_gdt32 - 1
    .long _ap_gdt32 - ap_trampoline_start + 0x8000

// ===== 64-bit GDT (used for protected → long mode transition) =====
.align 16
_ap_gdt64:
    // Null descriptor
    .quad 0
    // Code64: long mode code segment
    .word 0xFFFF       // limit low
    .word 0x0000       // base low
    .byte 0x00         // base mid
    .byte 0x9A         // access: P=1 DPL=0 S=1 E=1 R=1
    .byte 0xAF         // flags: G=1 L=1 (long mode), limit high=0xF
    .byte 0x00         // base high
    // Data64: writable data segment
    .word 0xFFFF       // limit low
    .word 0x0000       // base low
    .byte 0x00         // base mid
    .byte 0x92         // access: P=1 DPL=0 S=1 W=1
    .byte 0xCF         // flags: G=1 D=1, limit high=0xF
    .byte 0x00         // base high
_ap_gdt64_end:

.align 4
_ap_gdt64_ptr:
    .word _ap_gdt64_end - _ap_gdt64 - 1
    .long _ap_gdt64 - ap_trampoline_start + 0x8000

ap_trampoline_end:
    nop
