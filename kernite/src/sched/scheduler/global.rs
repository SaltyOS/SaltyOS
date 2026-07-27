// SPDX-License-Identifier: GPL-2.0-only

use super::Scheduler;
use core::sync::atomic::{AtomicUsize, Ordering};

static mut SCHEDULER: Scheduler = Scheduler::new();

/// Per-CPU atomic tracking of the currently running TCB pointer.
///
/// Updated via `set_current()` and `schedule_unlocked()` with Release ordering.
/// Read by `current_on_cpu()` with Acquire ordering. Used by cross-CPU
/// `TCB_STOP` to spin-wait until the target CPU has context-switched away.
pub(super) static CURRENT_ON_CPU: [AtomicUsize; crate::arch::MAX_CPUS] = {
    const INIT: AtomicUsize = AtomicUsize::new(0);
    [INIT; crate::arch::MAX_CPUS]
};

static DEBUG_REPLY_WAKE_TCB: AtomicUsize = AtomicUsize::new(0);
static DEBUG_REPLY_WAKE_STAGES: AtomicUsize = AtomicUsize::new(0);

/// Read the current thread pointer for a given CPU (lock-free).
///
/// Returns the raw TCB pointer as `usize`. The caller can compare this
/// against a known TCB address to determine if that thread is still
/// executing on the target CPU.
pub fn current_on_cpu(cpu: usize) -> usize {
    CURRENT_ON_CPU[cpu].load(Ordering::Acquire)
}

pub(crate) fn debug_mark_reply_wake_tcb(tcb: *mut crate::sched::thread::Tcb) {
    DEBUG_REPLY_WAKE_TCB.store(tcb as usize, Ordering::Release);
    DEBUG_REPLY_WAKE_STAGES.store(0, Ordering::Release);
}

pub(crate) fn debug_is_reply_wake_tcb(tcb: *mut crate::sched::thread::Tcb) -> bool {
    !tcb.is_null() && DEBUG_REPLY_WAKE_TCB.load(Ordering::Acquire) == tcb as usize
}

pub(crate) fn debug_reply_wake_once(tcb: *mut crate::sched::thread::Tcb, stage: usize) -> bool {
    if !debug_is_reply_wake_tcb(tcb) {
        return false;
    }
    let bit = 1usize << stage;
    DEBUG_REPLY_WAKE_STAGES.fetch_or(bit, Ordering::AcqRel) & bit == 0
}

pub(crate) fn debug_clear_reply_wake_tcb(tcb: *mut crate::sched::thread::Tcb) {
    if debug_is_reply_wake_tcb(tcb) {
        DEBUG_REPLY_WAKE_TCB.store(0, Ordering::Release);
        DEBUG_REPLY_WAKE_STAGES.store(0, Ordering::Release);
    }
}

/// Global scheduler instance.
pub fn scheduler() -> &'static mut Scheduler {
    // SAFETY: Single-threaded kernel access, interrupts disabled during scheduler operations
    unsafe { &mut *(&raw mut SCHEDULER) }
}

#[unsafe(no_mangle)]
pub extern "C" fn sched_runtime_enter_kernel() {
    unsafe {
        scheduler().runtime_enter_kernel_local();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sched_runtime_exit_to_user() {
    unsafe {
        scheduler().runtime_exit_to_user_local();
    }
}
