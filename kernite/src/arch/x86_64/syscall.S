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
//! - Offset 24: invoke_seq (u64) — per-CPU monotonic invoke counter
//! - Offset 32: stack_canary (u64) — per-CPU canary for stack overflow detection
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
    .cfi_startproc
    .cfi_def_cfa %rsp, 0
    .cfi_undefined %rip

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
    call sched_runtime_enter_kernel
    # Restore the user-visible caller-saved registers the fastpath dispatch
    # still needs in-register. The hook only consumed the saved stack image.
    mov 0(%rsp), %rax
    mov 24(%rsp), %rdx
    mov 32(%rsp), %rsi
    mov 40(%rsp), %rdi
    mov 56(%rsp), %r8
    mov 64(%rsp), %r9
    mov 72(%rsp), %r10

    # No lock acquired here — each Rust handler acquires the lock(s) it needs.

    # --------------------------------------------------------------------------
    # IPC Fastpath Dispatch
    # --------------------------------------------------------------------------
    # Hand the syscall to `kernite_try_sys_invoke_fastpath` (Rust). On
    # success it stamps `(error, value)` into a stack-allocated
    # `SyscallResult` and returns 1; otherwise it returns 0 and we
    # fall through to the slowpath. The helper sees the same User
    # ABI tuple the slowpath does, after we marshal it through System V.
    #
    # Register state at this label (User ABI, restored by the entry
    # hook above): rax=syscall, rdi=arg0, rsi=arg1, rdx=arg2,
    # r10=arg3, r8=arg4, r9=arg5.
    #
    # System V layout for the fastpath helper:
    #   rdi  arg0 = rax (syscall)
    #   rsi  arg1 = rdi (cap_ptr)
    #   rdx  arg2 = rsi (label)
    #   rcx  arg3 = rdx (arg0)
    #   r8   arg4 = r10 (arg1)
    #   r9   arg5 = r8  (arg2)
    #   [rsp+0]  arg6 = r9  (arg3)
    #   [rsp+8]  arg7 = &out
    # The 16 bytes above the helper-arg slots host the
    # `SyscallResult` out-buffer.

    sub $32, %rsp
    # Save user_r9 (arg3) BEFORE we clobber r9 in the System V remap.
    mov %r9, 0(%rsp)

    mov %r8,  %r9                # r9  = user_r8  (arg2)
    mov %r10, %r8                # r8  = user_r10 (arg1)
    mov %rdx, %rcx               # rcx = user_rdx (arg0)
    mov %rsi, %rdx               # rdx = user_rsi (label)
    mov %rdi, %rsi               # rsi = user_rdi (cap_ptr)
    mov %rax, %rdi               # rdi = syscall

    lea 16(%rsp), %r10           # r10 = &out (SyscallResult slot)
    mov %r10, 8(%rsp)            # arg7 = out pointer

    call kernite_try_sys_invoke_fastpath

    test %rax, %rax
    jz .Lfastpath_miss

    # Handled — stamp the return frame's saved rax/rdx slots and jump
    # to the shared return path. The saved-state image lives at
    # [rsp+32 .. rsp+32+128] after our 32-byte allocation, so the
    # original `[rsp+0]` (saved rax) is now at `[rsp+32]` and the
    # original `[rsp+24]` (saved rdx) is now at `[rsp+56]`.
    mov 16(%rsp), %rax           # error  = SyscallResult.error
    mov 24(%rsp), %rdx           # value  = SyscallResult.value
    mov %rax, 32(%rsp)           # saved-rax slot
    mov %rdx, 56(%rsp)           # saved-rdx slot
    add $32, %rsp                # undo fastpath frame
    jmp .Lreturn

.Lfastpath_miss:
    add $32, %rsp                # undo fastpath frame
    # The helper clobbered every System V volatile register; refresh
    # the User ABI snapshot from the saved-state image (the same
    # restore the entry hook performs at line 66) so the slowpath
    # sees pristine input.
    mov 0(%rsp), %rax
    mov 24(%rsp), %rdx
    mov 32(%rsp), %rsi
    mov 40(%rsp), %rdi
    mov 56(%rsp), %r8
    mov 64(%rsp), %r9
    mov 72(%rsp), %r10
    # Fall through.

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
    # Layout: [rsp+0] = arg7, [rsp+8] = stack canary
    sub  $16, %rsp
    mov  80(%rsp), %r10
    mov  %r10, (%rsp)
    mov  %gs:32, %r10
    mov  %r10, 8(%rsp)

    call syscall_handle_rust

    # Verify stack canary before returning to userspace
    mov  8(%rsp), %r10
    cmp  %r10, %gs:32
    jne  .Lstack_corrupt

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
    # Handlers restore the caller's IRQ state before returning here. Keep the
    # unpacked return frame non-preemptible until sysretq installs user RFLAGS.
    cli

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

    # Charge the final kernel window as system time and flip to user mode as
    # late as we can while preserving the restored user register image.
    push %r11
    push %r10
    push %r9
    push %r8
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %rax
    call sched_runtime_exit_to_user
    pop %rax
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi
    pop %r8
    pop %r9
    pop %r10
    pop %r11

    # Restore user RSP from kernel stack (per-thread, NOT from %gs:16!)
    pop %rsp

    # Return to userspace
    # sysretq loads RIP from RCX and RFLAGS from R11
    swapgs
    sysretq

    # --------------------------------------------------------------------------
    # Stack Canary Corruption Handler
    # --------------------------------------------------------------------------
.Lstack_corrupt:
    lea  stack_canary_msg(%rip), %rdi
    call kernel_panic
    .cfi_endproc
.size syscall_entry, . - syscall_entry

.section .rodata
stack_canary_msg:
    .asciz "[PANIC] Kernel stack canary corrupted — buffer overflow detected"
.section .text

.size syscall_entry, . - syscall_entry
