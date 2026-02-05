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
//! - Offset 16: saved_rsp (u64)
//!
//! SPDX-License-Identifier: GPL-2.0-only

.section .text
.global syscall_entry
.type syscall_entry, @function

syscall_entry:
    # Swap GS to access per-CPU data (GS points to PerCpuData)
    swapgs

    # Save user stack pointer to per-CPU data (offset 16)
    mov %rsp, %gs:16

    # Load kernel stack from per-CPU data (offset 8)
    mov %gs:8, %rsp

    # --------------------------------------------------------------------------
    # Context Preservation
    # --------------------------------------------------------------------------
    # Push all general-purpose registers to create a PtRegs-like structure.
    # Order matters for the final pop sequence.
    
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

    # --------------------------------------------------------------------------
    # ABI Translation (User Syscall ABI -> System V ABI)
    # --------------------------------------------------------------------------
    # We must move registers because the Syscall ABI differs from the C/Rust ABI.
    # Specifically, User passes Arg3 in R10, but Rust expects Arg3 in RCX.
    # Rust also expects the First Arg in RDI, but current RDI holds User Arg0.
    
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
    # Align stack to 16 bytes.
    # Currently pushed 15 registers (15 * 8 = 120 bytes).
    # 120 is not 16-byte aligned. Subtract 8 bytes to align.
    sub $8, %rsp

    call syscall_handle_rust

    # Remove alignment padding
    add $8, %rsp

    # --------------------------------------------------------------------------
    # Return Value Handling
    # --------------------------------------------------------------------------
    # Rust returns struct { u64 error; u64 value; } in RAX:RDX (System V ABI).
    # Overwrite saved RAX/RBX on stack so pops restore the result to user.
    # Stack: [saved_rax] [saved_rbx] [saved_rcx=user_rip] ...
    mov %rax, 0(%rsp)  # error  → will be popped into %rax
    mov %rdx, 8(%rsp)  # value  → will be popped into %rbx

    # --------------------------------------------------------------------------
    # Context Restoration
    # --------------------------------------------------------------------------
    pop %rax   # Error code (from handler)
    pop %rbx   # Return value (from handler)
    pop %rcx   # Restores RIP (needed for sysretq)
    pop %rdx
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

    # Restore user stack pointer from per-CPU data
    mov %gs:16, %rsp

    # Return to userspace
    # sysretq loads RIP from RCX and RFLAGS from R11
    swapgs
    sysretq

.size syscall_entry, . - syscall_entry