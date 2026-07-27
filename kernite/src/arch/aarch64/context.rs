//! AArch64 context switch and usermode trampoline
//!
//! Saves/restores callee-saved registers (x19-x28, x29/FP, x30/LR) on the
//! kernel stack, switches SP between threads, and provides the initial entry
//! trampoline for newly created threads that transitions to EL0.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::sched::thread::{Tcb, ThreadContext};
use core::ffi::c_void;

unsafe extern "C" {
    fn aarch64_context_switch(old_sp: *mut u64, new_sp: u64, old_tcb: *mut c_void);
    fn aarch64_write_user_return_state(return_elr: u64, return_spsr: u64, user_sp: u64);
    fn aarch64_enter_user(abi_tp: u64) -> !;
}

#[inline(always)]
unsafe fn write_user_return_state(return_elr: u64, return_spsr: u64, user_sp: u64) {
    unsafe {
        aarch64_write_user_return_state(return_elr, return_spsr, user_sp);
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
    old_tcb: *mut Tcb,
) {
    // SAFETY: old_context and new_context are valid ThreadContext pointers
    // as guaranteed by the caller (scheduler). We extract the SP field
    // addresses for the assembly routine which saves/restores callee-saved
    // registers on the kernel stack.
    unsafe {
        let old_sp_ptr = &raw mut (*old_context).sp;
        let new_sp = (*new_context).sp;
        aarch64_context_switch(old_sp_ptr, new_sp, old_tcb.cast());
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
        let abi_tp = tcb.abi_tp_base;

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
        crate::sched::scheduler::sched_runtime_exit_to_user();
        aarch64_enter_user(abi_tp);
    }
}
