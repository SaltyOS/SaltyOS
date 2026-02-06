//! Syscall entry point for x86_64
//!
//! Syscall instruction ABI:
//! - rax = syscall number
//! - rcx = return rip (clobbered by syscall)
//! - r11 = return rflags (clobbered by syscall)
//! - Arguments: rdi, rsi, rdx, r10, r8, r9
//!
//! PerCpuData layout (from GS base):
//! - Offset 0: cpu_id (u32)
//! - Offset 4: padding
//! - Offset 8: kernel_stack (u64)
//! - Offset 16: saved_rsp (u64) — scratch only, NOT used for return
//!
//! CRITICAL: The user RSP is saved on the per-thread kernel stack, NOT in
//! per-CPU data. This ensures it survives context switches when another
//! thread's syscall overwrites %gs:16.
//!
//! SPDX-License-Identifier: GPL-2.0-only

.section .text
.global syscall_entry
.type syscall_entry, @function

syscall_entry:
    # Swap GS to access per-CPU data (GS points to PerCpuData)
    swapgs

    # Save user stack pointer to per-CPU scratch area (offset 16)
    mov %rsp, %gs:16

    # Load kernel stack from per-CPU data (offset 8)
    mov %gs:8, %rsp

    # --------------------------------------------------------------------------
    # Context Preservation
    # --------------------------------------------------------------------------
    # Push user RSP first (from per-CPU scratch) — popped LAST on return.
    # This ensures each thread's user RSP is saved per-thread on its own
    # kernel stack, surviving context switches.
    pushq %gs:16

    # Push all general-purpose registers
    push %r15
    push %r14
    push %r13
    push %r12
    push %r11  # Saved RFLAGS (from syscall)
    push %r10  # User Argument 3
    push %r9
    push %r8
    push %rbp
    push %rdi
    push %rsi
    push %rdx
    push %rcx  # Saved RIP (from syscall)
    push %rbx
    push %rax  # Original Syscall Number

    # 16 pushes (user_rsp + 15 GPRs) = 128 bytes = 16-byte aligned!

    # --------------------------------------------------------------------------
    # ABI Translation (User Syscall ABI -> System V ABI)
    # --------------------------------------------------------------------------
    # Mapping:
    # r9  (Rust Arg5) <--- r8  (User Arg4)
    # r8  (Rust Arg4) <--- r10 (User Arg3)
    # rcx (Rust Arg3) <--- rdx (User Arg2)
    # rdx (Rust Arg2) <--- rsi (User Arg1)
    # rsi (Rust Arg1) <--- rdi (User Arg0)
    # rdi (Rust Arg0) <--- rax (Syscall Num)

    mov %r8,  %r9
    mov %r10, %r8
    mov %rdx, %rcx
    mov %rsi, %rdx
    mov %rdi, %rsi
    mov %rax, %rdi

    # --------------------------------------------------------------------------
    # Handler Call
    # --------------------------------------------------------------------------
    # Stack is already 16-byte aligned (128 bytes pushed), no padding needed.

    call syscall_handle_rust

    # --------------------------------------------------------------------------
    # Return Value Handling
    # --------------------------------------------------------------------------
    # Rust returns struct { u64 error; u64 value; } in RAX:RDX (System V ABI).
    # Overwrite saved RAX and saved RDX on stack so pops restore results.
    # Stack layout: [0]=rax [8]=rbx [16]=rcx(rip) [24]=rdx ...
    mov %rax, 0(%rsp)   # error  → will be popped into %rax
    mov %rdx, 24(%rsp)  # value  → will be popped into %rdx

    # --------------------------------------------------------------------------
    # Context Restoration
    # --------------------------------------------------------------------------
    pop %rax   # Error code (from handler)
    pop %rbx   # Restored (original value)
    pop %rcx   # Restores RIP (needed for sysretq)
    pop %rdx   # Return value (from handler)
    pop %rsi
    pop %rdi
    pop %rbp
    pop %r8
    pop %r9
    pop %r10
    pop %r11   # Restores RFLAGS (needed for sysretq)
    pop %r12
    pop %r13
    pop %r14
    pop %r15

    # Restore user RSP from kernel stack (per-thread, NOT from %gs:16!)
    pop %rsp

    # Return to userspace
    # sysretq loads RIP from RCX and RFLAGS from R11
    swapgs
    sysretq

.size syscall_entry, . - syscall_entry
