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

    # No lock acquired here — each Rust handler acquires the lock(s) it needs.

    # --------------------------------------------------------------------------
    # IPC Fastpath Dispatch
    # --------------------------------------------------------------------------
    # At this point, all GPRs still hold their original user-space values
    # (push copies to stack but does not modify the register).
    #
    # Check for Call (2) or ReplyRecv (3) — the client-server hot path.
    # Fastpath functions use System V ABI:
    #   RDI=cap_ptr  RSI=msg_info  RDX=mr0  RCX=mr1  R8=mr2  R9=mr3
    # Only R10→RCX needs remapping.
    cmp $2, %rax
    je .Lfastpath_call
    cmp $3, %rax
    je .Lfastpath_reply_recv

.Lslowpath:
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
    # 7th argument (User R9) on stack for syscall_handle_rust.
    # User R9 was saved at RSP+64 (9th push from top). After sub $16,
    # it shifts to RSP+80. We use r10 as scratch (already remapped to r8).
    sub  $16, %rsp
    mov  80(%rsp), %r10
    mov  %r10, (%rsp)

    call syscall_handle_rust

    add  $16, %rsp

    # --------------------------------------------------------------------------
    # Return Value Handling
    # --------------------------------------------------------------------------
    # Rust returns struct { u64 error; u64 value; } in RAX:RDX (System V ABI).
    # Overwrite saved RAX and saved RDX on stack so pops restore results.
    # Stack layout: [0]=rax [8]=rbx [16]=rcx(rip) [24]=rdx ...
    mov %rax, 0(%rsp)   # error  → will be popped into %rax
    mov %rdx, 24(%rsp)  # value  → will be popped into %rdx

.Lreturn:
    # No lock to release — Rust handlers release their own locks.

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

    # --------------------------------------------------------------------------
    # Fastpath: Call (syscall 2)
    # --------------------------------------------------------------------------
    # Register state: RDI=cap_ptr RSI=msg_info RDX=mr0 R10=mr1 R8=mr2 R9=mr3
    # Remap R10 → RCX for System V, then call fastpath_call_rust.
    # Returns FastpathResult { status: u64, value: u64 } in RAX:RDX.
    # If status == 0, fall through to slowpath (all regs still on stack).
.Lfastpath_call:
    mov %r10, %rcx
    call fastpath_call_rust
    test %rax, %rax
    jz .Lfastpath_call_bail
    # Fastpath succeeded: write return values to stack slots
    movq $0, 0(%rsp)           # saved RAX = 0 (no error)
    mov %rdx, 24(%rsp)         # saved RDX = return value
    jmp .Lreturn

.Lfastpath_call_bail:
    # Restore original register values from stack for slowpath.
    # The fastpath Rust function follows C ABI and preserves callee-saved
    # regs (rbx, rbp, r12-r15), but may have clobbered caller-saved regs
    # (rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11).
    # Reload from stack: [0]=rax [8]=rbx [16]=rcx [24]=rdx [32]=rsi
    # [40]=rdi [48]=rbp [56]=r8 [64]=r9 [72]=r10 [80]=r11
    mov 0(%rsp), %rax
    mov 24(%rsp), %rdx
    mov 32(%rsp), %rsi
    mov 40(%rsp), %rdi
    mov 56(%rsp), %r8
    mov 64(%rsp), %r9
    mov 72(%rsp), %r10
    jmp .Lslowpath

    # --------------------------------------------------------------------------
    # Fastpath: ReplyRecv (syscall 3)
    # --------------------------------------------------------------------------
.Lfastpath_reply_recv:
    mov %r10, %rcx
    call fastpath_reply_recv_rust
    test %rax, %rax
    jz .Lfastpath_reply_recv_bail
    # Fastpath succeeded
    movq $0, 0(%rsp)           # saved RAX = 0 (no error)
    mov %rdx, 24(%rsp)         # saved RDX = badge
    jmp .Lreturn

.Lfastpath_reply_recv_bail:
    # Restore clobbered registers for slowpath
    mov 0(%rsp), %rax
    mov 24(%rsp), %rdx
    mov 32(%rsp), %rsi
    mov 40(%rsp), %rdi
    mov 56(%rsp), %r8
    mov 64(%rsp), %r9
    mov 72(%rsp), %r10
    jmp .Lslowpath

.size syscall_entry, . - syscall_entry
