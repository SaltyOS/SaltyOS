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

    // Preserve user RAX while capturing CR2.
    // Previous code did `mov %cr2, %rax` then pushed %rax twice, which
    // restored user RAX as CR2 on iret (register corruption after #PF).
    push %rax                   // temp: original user RAX
    mov %cr2, %rax
    xchg %rax, (%rsp)           // stack top = CR2, RAX = original user RAX

    // Save all general-purpose registers
    push %rax                   // original user RAX
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

    // Align stack to 16 bytes for System V ABI.
    // We pushed 15 GPRs + cr2 + vector + error_code = 18 qwords = 144 bytes.
    // CPU pushed 5 qwords = 40 bytes. Total = 184 bytes.
    // 184 mod 16 = 8, so we need to subtract 8 to align.
    sub $8, %rsp

    // SCHED_IPC_LOCK for user-mode exceptions only (kernel-mode exceptions skip
    // to avoid deadlock if exception occurs while lock is held).
    // CS is at RSP + 8 (alignment) + 120 (15 GPRs) + 8 (cr2) + 8 (vec) + 8 (err) + 8 (RIP) = RSP + 160
    testb $3, 160(%rsp)
    jz .Lno_exc_lock
    call sched_ipc_lock
.Lno_exc_lock:

    // Pass pointer to ExceptionFrame (above alignment padding)
    lea 8(%rsp), %rdi
    call exception_handler_rust

    testb $3, 160(%rsp)
    jz .Lno_exc_lock_ret
    call sched_ipc_unlock
.Lno_exc_lock_ret:

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

// IRQ stub WITH SCHED_IPC_LOCK
.macro irq_stub_sched_ipc name
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
    // 9 pushes + 5 CPU pushes = 112 bytes, 16-byte aligned
    call sched_ipc_lock
    call irq_handler_\name
    call sched_ipc_unlock
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

// IRQ stub WITHOUT BKL (for VSpaceTeardown: per-CPU + atomics only)
.macro irq_stub_nobkl name
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

irq_stub_nobkl timer
irq_stub_nobkl ipi_vspace_teardown
irq_stub_nobkl ipi_reschedule
irq_stub_nobkl ipi_tlb_shootdown
irq_stub_nobkl ipi_tlb_shootdown_all

// ---------------------------------------------------------------------------
// Generic IRQ stubs for external hardware interrupts (vectors 33-47)
// Each calls irq_handler_generic with the vector number in RDI
// ---------------------------------------------------------------------------

.macro irq_stub_generic vector
.global irq_stub_generic_\vector
.type irq_stub_generic_\vector, @function
irq_stub_generic_\vector:
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
    // 9 pushes + 5 CPU pushes = 112 bytes, 16-byte aligned
    call sched_ipc_lock
    // Pass vector number as argument
    mov $\vector, %edi
    call irq_handler_generic
    call sched_ipc_unlock
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
.size irq_stub_generic_\vector, . - irq_stub_generic_\vector
.endm

// Generate stubs for vectors 33-39, 42-47 (skip 40-41 = IPI handlers)
irq_stub_generic 33
irq_stub_generic 34
irq_stub_generic 35
irq_stub_generic 36
irq_stub_generic 37
irq_stub_generic 38
irq_stub_generic 39
irq_stub_generic 42
irq_stub_generic 43
irq_stub_generic 44
irq_stub_generic 45
irq_stub_generic 46
irq_stub_generic 47
