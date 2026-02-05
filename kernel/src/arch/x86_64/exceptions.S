//! Exception and IRQ entry stubs for x86_64
//!
//! Provides assembly entry points for all 32 CPU exception vectors (0-31)
//! and IRQ handlers that need swapgs for ring-3 transitions.
//!
//! Each exception stub pushes a uniform frame (error code + vector number + CR2 + GPRs)
//! then calls exception_handler_rust in idt.rs.
//!
//! SPDX-License-Identifier: GPL-2.0-only

.section .text

// ---------------------------------------------------------------------------
// Exception Macros
// ---------------------------------------------------------------------------

// Stub for exceptions that do NOT push an error code.
// We push a dummy 0 so the stack layout is uniform.
.macro exception_stub_no_error vector
.global exception_stub_\vector
.type exception_stub_\vector, @function
exception_stub_\vector:
    push $0                     // dummy error code
    push $\vector               // vector number
    jmp exception_common
.size exception_stub_\vector, . - exception_stub_\vector
.endm

// Stub for exceptions where the CPU already pushed an error code.
.macro exception_stub_with_error vector
.global exception_stub_\vector
.type exception_stub_\vector, @function
exception_stub_\vector:
    // error code already on stack from CPU
    push $\vector               // vector number
    jmp exception_common
.size exception_stub_\vector, . - exception_stub_\vector
.endm

// ---------------------------------------------------------------------------
// Generate stubs for all 32 exception vectors
// ---------------------------------------------------------------------------

// Error-code vectors: 8, 10, 11, 12, 13, 14, 17, 21, 30
// All others: no error code

exception_stub_no_error    0    // #DE  Divide Error
exception_stub_no_error    1    // #DB  Debug
exception_stub_no_error    2    // NMI
exception_stub_no_error    3    // #BP  Breakpoint
exception_stub_no_error    4    // #OF  Overflow
exception_stub_no_error    5    // #BR  Bound Range Exceeded
exception_stub_no_error    6    // #UD  Invalid Opcode
exception_stub_no_error    7    // #NM  Device Not Available
exception_stub_with_error  8    // #DF  Double Fault
exception_stub_no_error    9    // Coprocessor Segment Overrun (legacy)
exception_stub_with_error  10   // #TS  Invalid TSS
exception_stub_with_error  11   // #NP  Segment Not Present
exception_stub_with_error  12   // #SS  Stack-Segment Fault
exception_stub_with_error  13   // #GP  General Protection Fault
exception_stub_with_error  14   // #PF  Page Fault
exception_stub_no_error    15   // (reserved)
exception_stub_no_error    16   // #MF  x87 Floating-Point
exception_stub_with_error  17   // #AC  Alignment Check
exception_stub_no_error    18   // #MC  Machine Check
exception_stub_no_error    19   // #XM  SIMD Floating-Point
exception_stub_no_error    20   // #VE  Virtualization
exception_stub_with_error  21   // #CP  Control Protection
exception_stub_no_error    22   // (reserved)
exception_stub_no_error    23   // (reserved)
exception_stub_no_error    24   // (reserved)
exception_stub_no_error    25   // (reserved)
exception_stub_no_error    26   // (reserved)
exception_stub_no_error    27   // (reserved)
exception_stub_no_error    28   // #HV  Hypervisor Injection
exception_stub_with_error  30   // #SX  Security Exception
exception_stub_no_error    29   // #VC  VMM Communication
exception_stub_no_error    31   // (reserved)

// ---------------------------------------------------------------------------
// Common handler: save full register state, call Rust handler
// ---------------------------------------------------------------------------

// Stack on entry here (from stub):
//   [RSP+24] CS    (CPU-pushed interrupt frame)
//   [RSP+16] RIP   (CPU-pushed)
//   [RSP+8]  error_code (real or dummy 0)
//   [RSP+0]  vector number

exception_common:
    // Check if exception came from user mode (CS RPL != 0)
    testb $3, 24(%rsp)
    jz 1f
    swapgs
1:

    // Read CR2 before it gets clobbered (only meaningful for #PF but harmless)
    mov %cr2, %rax
    push %rax                   // cr2

    // Save all general-purpose registers
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15

    // Pass pointer to ExceptionFrame as first argument
    mov %rsp, %rdi
    // Align stack to 16 bytes for System V ABI.
    // We pushed 15 GPRs + cr2 + vector + error_code = 18 qwords = 144 bytes.
    // CPU pushed 5 qwords = 40 bytes. Total = 184 bytes.
    // 184 mod 16 = 8, so we need to subtract 8 to align.
    sub $8, %rsp
    call exception_handler_rust
    add $8, %rsp

    // Restore general-purpose registers
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax

    // Skip cr2, vector, error_code (3 * 8 = 24 bytes)
    add $24, %rsp

    // Check if returning to user mode (CS RPL != 0)
    // After skipping cr2+vector+error_code, stack is: RIP, CS, RFLAGS, RSP, SS
    // CS is at RSP+8
    testb $3, 8(%rsp)
    jz 2f
    swapgs
2:
    iretq

// ---------------------------------------------------------------------------
// IRQ stubs: save caller-saved registers, call handler, swapgs as needed
// ---------------------------------------------------------------------------
// On IRQ entry, the CPU pushes: SS, RSP, RFLAGS, CS, RIP
// No error code, no vector. CS is at RSP+8.

.macro irq_stub name
.global irq_stub_\name
.type irq_stub_\name, @function
irq_stub_\name:
    // Check if from user mode
    testb $3, 8(%rsp)
    jz 1f
    swapgs
1:
    // Save caller-saved registers
    push %rax
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %r8
    push %r9
    push %r10
    push %r11

    // Align stack: 9 pushes = 72 bytes + 5 CPU pushes = 40 bytes = 112 bytes
    // 112 mod 16 = 0, already aligned

    call irq_handler_\name

    // Restore caller-saved registers
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rax

    // Check if returning to user mode
    testb $3, 8(%rsp)
    jz 2f
    swapgs
2:
    iretq
.size irq_stub_\name, . - irq_stub_\name
.endm

irq_stub timer
irq_stub ipi_vspace_teardown
irq_stub ipi_reschedule
