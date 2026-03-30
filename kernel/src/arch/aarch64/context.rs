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

#[inline(always)]
unsafe fn write_user_return_state(return_elr: u64, return_spsr: u64, user_sp: u64) {
    unsafe {
        core::arch::asm!(
            "msr ELR_EL1, {return_elr}",
            "msr SPSR_EL1, {return_spsr}",
            "msr SP_EL0, {sp}",
            return_elr = in(reg) return_elr,
            return_spsr = in(reg) return_spsr,
            sp = in(reg) user_sp,
            options(nomem, nostack),
        );
    }
}

/// Size of the callee-saved register frame used by `aarch64_context_switch`.
pub const SWITCH_FRAME_SIZE: u64 = 96;
const SWITCH_FRAME_LR_OFFSET: u64 = 88;

#[inline]
unsafe fn init_switch_frame(frame_base: u64, resume_pc: u64) {
    let frame = frame_base as *mut u8;
    // SAFETY: Caller guarantees `[frame_base, frame_base + SWITCH_FRAME_SIZE)`
    // is writable kernel stack memory for this thread.
    unsafe {
        core::ptr::write_bytes(frame, 0, SWITCH_FRAME_SIZE as usize);
        *((frame_base + SWITCH_FRAME_LR_OFFSET) as *mut u64) = resume_pc;
    }
}

/// Initialize a kernel thread so the first context switch resumes at `entry`.
///
/// `kernel_stack_top` must point one byte past a writable kernel stack.
pub unsafe fn init_kernel_thread_context(
    context: &mut ThreadContext,
    kernel_stack_top: u64,
    entry: u64,
) {
    let frame_base = kernel_stack_top - SWITCH_FRAME_SIZE;
    // SAFETY: Caller provides a valid writable kernel stack for the new thread.
    unsafe {
        init_switch_frame(frame_base, entry);
    }
    *context = ThreadContext::empty();
    context.sp = frame_base;
    context.return_elr = entry;
}

/// Initialize a fresh user thread for first dispatch through the trampoline.
///
/// `kernel_stack_top` becomes the EL1 stack after the switch frame is popped.
pub unsafe fn init_user_thread_context(
    context: &mut ThreadContext,
    kernel_stack_top: u64,
    user_entry: u64,
    user_sp: u64,
    spsr: u64,
) {
    let frame_base = kernel_stack_top - SWITCH_FRAME_SIZE;
    // SAFETY: Caller provides a valid writable kernel stack for the new thread.
    unsafe {
        init_switch_frame(frame_base, usermode_trampoline as *const () as usize as u64);
    }
    *context = ThreadContext::empty();
    context.sp = frame_base;
    context.return_elr = user_entry;
    context.return_spsr = spsr;
    context.user_sp = user_sp;
}

/// Return the kernel PC that `context_switch` will `ret` to for this context.
pub unsafe fn resume_pc(context: &ThreadContext) -> u64 {
    // SAFETY: `context.sp` always points at the saved switch frame for an
    // inactive/ready thread.
    unsafe { *((context.sp + SWITCH_FRAME_LR_OFFSET) as *const u64) }
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
/// loads the active host TTBR0 from the thread's VSpace, zeroes all general-purpose
/// registers to prevent kernel address leaks, and executes `eret` to
/// enter EL0.
///
/// Convention for initial thread setup (must be set by init.rs / thread_configure):
///   - `context.sp`       = kernel stack pointer (with trampoline frame)
///   - `context.return_elr`  = user entry point (restored into host ELR for `eret`)
///   - `context.return_spsr` = user PSTATE (restored into host SPSR for `eret`)
///   - `context.user_sp` = user stack pointer (restored into SP_EL0)
///
/// `context.sp` is consumed by `context_switch` for the kernel SP.
/// The `return_elr`, `return_spsr`, and `user_sp` fields are untouched by
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

        let return_elr = tcb.context.return_elr;
        let user_sp = tcb.context.user_sp;
        let return_spsr = tcb.context.return_spsr;

        // Load user page table if a VSpace is configured.
        // On AArch64, the active host TTBR0 must include the ASID in bits [63:48].
        // prepare_switch_target_full() already called switch_to() which set
        // the correct TTBR0 with ASID, but the trampoline must also set it
        // so that threads created after boot (e.g. fork children) get the
        // correct mapping.  Using root() alone would overwrite the ASID to 0,
        // causing stale TLB hits from ASID 0 (init task) that map the
        // child's virtual addresses to wrong physical pages.
        if !tcb.vspace_root.is_null() {
            let vspace = &*tcb.vspace_root;
            let ttbr0 = vspace.host_ttbr0();
            // SAFETY: The scheduler has already selected this thread's VSpace.
            // Reuse the common helper so first-entry trampolines get the same
            // TLB semantics as normal AArch64 VSpace switches.
            crate::arch::paging::write_cr3(ttbr0);
        }

        // SAFETY: Setting the active host ELR/SPSR pair plus SP_EL0
        // configures the processor state that eret will restore. All three
        // values come from the TCB which was initialized by the kernel.
        write_user_return_state(return_elr, return_spsr, user_sp);

        // SAFETY: Zeroing all GPRs prevents leaking kernel addresses to
        // userspace. The eret instruction atomically restores PSTATE from
        // the active host SPSR and jumps to the active host ELR at EL0.
        // This sequence does not
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
