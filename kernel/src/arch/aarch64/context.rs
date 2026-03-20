//! AArch64 context switch and usermode trampoline
//!
//! Saves/restores callee-saved registers (x19-x28, x29/FP, x30/LR) on the
//! kernel stack, switches SP between threads, and provides the initial entry
//! trampoline for newly created threads that transitions to EL0.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::sched::thread::ThreadContext;
use core::arch::global_asm;

// ---------------------------------------------------------------------------
// Assembly context switch
// ---------------------------------------------------------------------------

global_asm!(
    r#"
.section .text
.global aarch64_context_switch
.type aarch64_context_switch, @function
aarch64_context_switch:
    // x0 = pointer to old thread's saved SP location (*mut u64)
    // x1 = new thread's saved SP value (u64)

    // Save callee-saved registers on current stack (96 bytes)
    stp     x19, x20, [sp, #-96]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]

    // Save current SP to old thread's save location
    mov     x2, sp
    str     x2, [x0]

    // Switch to new thread's stack
    mov     sp, x1

    // Restore callee-saved registers from new stack
    ldp     x29, x30, [sp, #80]
    ldp     x27, x28, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #96

    // Return to new thread (x30/LR has the return address)
    ret
.size aarch64_context_switch, . - aarch64_context_switch
"#,
);

unsafe extern "C" {
    fn aarch64_context_switch(old_sp: *mut u64, new_sp: u64);
}

/// Perform a context switch between two threads.
///
/// Saves callee-saved registers and SP into `old_context.sp`, restores from
/// `new_context.sp`, and returns to the new thread's saved LR.
///
/// # Safety
/// Both pointers must point to valid, initialized `ThreadContext` structures.
/// The new context's `sp` field must point to a valid kernel stack with
/// previously saved callee-saved registers (or a trampoline frame).
pub unsafe fn context_switch(
    old_context: *mut ThreadContext,
    new_context: *const ThreadContext,
) {
    // SAFETY: old_context and new_context are valid ThreadContext pointers
    // as guaranteed by the caller (scheduler). We extract the SP field
    // addresses for the assembly routine which saves/restores callee-saved
    // registers on the kernel stack.
    unsafe {
        let old_sp_ptr = &raw mut (*old_context).sp;
        let new_sp = (*new_context).sp;
        aarch64_context_switch(old_sp_ptr, new_sp);
    }
}

/// Trampoline to enter usermode for newly created threads.
///
/// When `context_switch` restores a new thread for the first time, it
/// "returns" to this function (LR was set to this address during thread
/// setup). The trampoline reads the thread's saved state from the TCB,
/// loads TTBR0_EL1 from the thread's VSpace, zeroes all general-purpose
/// registers to prevent kernel address leaks, and executes `eret` to
/// enter EL0.
///
/// Convention for initial thread setup (must be set by init.rs / thread_configure):
///   - `context.sp`       = kernel stack pointer (with trampoline frame)
///   - `context.elr_el1`  = user entry point (ELR_EL1 for eret)
///   - `context.spsr_el1` = user PSTATE (SPSR_EL1 for eret)
///   - `context.x[19]`    = user stack pointer (SP_EL0)
///
/// `context.sp` is consumed by `context_switch` for the kernel SP.
/// The `elr_el1`, `spsr_el1`, and `x[19]` fields are untouched by
/// `context_switch` (which only saves/restores callee-saved regs on
/// the stack and the SP field).
///
/// # Safety
/// Must only be called as the initial entry point for a newly scheduled
/// thread. The scheduler must have set this thread as current and its TCB
/// must have valid context and vspace_root fields.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn usermode_trampoline() -> ! {
    // SAFETY: Called as initial entry for a newly scheduled thread.
    // The scheduler has already set this as the current thread and the
    // TCB fields are fully initialized by thread_configure / init_task.
    unsafe {
        let scheduler = crate::sched::scheduler::scheduler();
        let tcb = &*scheduler.current();

        let entry = tcb.context.elr_el1;
        let user_sp = tcb.context.x[19];  // User SP_EL0 (stored in x19 slot)
        let spsr = tcb.context.spsr_el1;

        // Load user page table if a VSpace is configured
        if !tcb.vspace_root.is_null() {
            let vspace = &*tcb.vspace_root;
            let ttbr0 = vspace.root();
            // SAFETY: Writing TTBR0_EL1 switches the EL0 page table.
            // ISB ensures the TLB sees the new translation before eret.
            core::arch::asm!(
                "msr TTBR0_EL1, {ttbr0}",
                "isb",
                ttbr0 = in(reg) ttbr0,
                options(nomem, nostack),
            );
        }

        // SAFETY: Setting ELR_EL1, SPSR_EL1, and SP_EL0 configures the
        // processor state that eret will restore. All three values come
        // from the TCB which was initialized by the kernel.
        core::arch::asm!(
            "msr ELR_EL1, {entry}",
            "msr SPSR_EL1, {spsr}",
            "msr SP_EL0, {sp}",
            entry = in(reg) entry,
            spsr = in(reg) spsr,
            sp = in(reg) user_sp,
            options(nomem, nostack),
        );

        // SAFETY: Zeroing all GPRs prevents leaking kernel addresses to
        // userspace. The eret instruction atomically restores PSTATE from
        // SPSR_EL1 and jumps to ELR_EL1 at EL0. This sequence does not
        // return.
        core::arch::asm!(
            "mov x0, xzr",
            "mov x1, xzr",
            "mov x2, xzr",
            "mov x3, xzr",
            "mov x4, xzr",
            "mov x5, xzr",
            "mov x6, xzr",
            "mov x7, xzr",
            "mov x8, xzr",
            "mov x9, xzr",
            "mov x10, xzr",
            "mov x11, xzr",
            "mov x12, xzr",
            "mov x13, xzr",
            "mov x14, xzr",
            "mov x15, xzr",
            "mov x16, xzr",
            "mov x17, xzr",
            "mov x18, xzr",
            "mov x19, xzr",
            "mov x20, xzr",
            "mov x21, xzr",
            "mov x22, xzr",
            "mov x23, xzr",
            "mov x24, xzr",
            "mov x25, xzr",
            "mov x26, xzr",
            "mov x27, xzr",
            "mov x28, xzr",
            "mov x29, xzr",
            "mov x30, xzr",
            "eret",
            options(noreturn, nomem, nostack),
        );
    }
}
