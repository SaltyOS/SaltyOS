//! AArch64 FPU/NEON eager state management
//!
//! The kernel is compiled without NEON/FP support (`-mgeneral-regs-only`,
//! soft-float ABI), so FPU state only needs to be saved/restored when
//! switching between userspace threads. This module performs that
//! save+restore unconditionally on every context switch — CPACR_EL1.FPEN
//! is held at 0b11 (no trap on EL0/EL1 access) and the EC=0x07 FP/SIMD
//! trap is treated as a fatal regression.
//!
//! NEON/FP state per thread:
//! - 32 x 128-bit V registers (V0-V31) = 512 bytes
//! - FPCR (4 bytes) + FPSR (4 bytes)
//! - Total: 520 bytes (padded to 528 in XSaveArea for alignment)
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::sched::thread::Tcb;

unsafe extern "C" {
    fn aarch64_fpu_enable();
    fn aarch64_fpsimd_save_state(area: *mut u8);
    fn aarch64_fpsimd_restore_state(area: *const u8);
}

/// Configure CPACR_EL1.FPEN = 0b11 (no FP/SIMD trap on EL0 or EL1).
///
/// The kernel is soft-float, so allowing EL1 access does not risk
/// silent state corruption — the only EL1 NEON access is the dedicated
/// save/restore assembly invoked from `switch` / `flush_current` /
/// `reload_current`.
#[inline]
fn enable_fpu() {
    // SAFETY: Configures CPACR_EL1.FPEN and serializes the change with ISB.
    unsafe {
        aarch64_fpu_enable();
    }
}

/// Save the current NEON/FP register state into the TCB's XSaveArea.
///
/// Saves all 32 V registers (V0-V31), FPCR, and FPSR. FPU access must be
/// enabled (FPEN=0b11) before calling.
///
/// # Safety
/// `tcb` must be a valid pointer to a Tcb with a writable fpu_state field.
unsafe fn save(tcb: *mut Tcb) {
    // SAFETY: tcb is guaranteed valid by caller. data is the start of the
    // 528-byte save area consumed by the assembly helper.
    let area = unsafe { core::ptr::addr_of_mut!((*tcb).fpu_state.data).cast::<u8>() };
    // SAFETY: FPU must be enabled by caller; area points at writable storage.
    unsafe {
        aarch64_fpsimd_save_state(area);
    }
}

/// Restore NEON/FP register state from the TCB's XSaveArea.
///
/// Loads all 32 V registers (V0-V31), FPCR, and FPSR. FPU access must be
/// enabled (FPEN=0b11) before calling.
fn restore(tcb: &Tcb) {
    let area = tcb.fpu_state.data.as_ptr();
    // SAFETY: area points at a valid save area, including the zeroed default
    // state used before a thread first touches FP/SIMD.
    unsafe {
        aarch64_fpsimd_restore_state(area);
    }
}

/// Configure FPU for eager mode on the current CPU.
///
/// Sets FPEN=0b11 so the lifetime of the kernel allows FP/SIMD access at
/// either EL without trapping. Called once per CPU during boot.
pub fn init() {
    enable_fpu();
}

/// Initialize a freshly created or recycled TCB's FPU save area.
///
/// On aarch64 the zero-initialized save area corresponds to the
/// architectural reset state (FPCR=0, FPSR=0, all V registers zero),
/// so no explicit FP init is needed before the first restore.
pub fn init_thread(tcb: &mut Tcb) {
    tcb.fpu_state = crate::sched::thread::XSaveArea::zeroed();
}

/// Save outgoing thread's FPU/NEON state and restore incoming thread's,
/// in the single context-switch step the scheduler invokes.
///
/// # Safety
/// `old_tcb` and `new_tcb` must be valid Tcb pointers. Must be called
/// with IRQs disabled — the scheduler's `switch_common` holds this
/// invariant.
pub unsafe fn switch(old_tcb: *mut Tcb, new_tcb: *mut Tcb) {
    crate::kernel::bug::kassert!(!old_tcb.is_null());
    crate::kernel::bug::kassert!(!new_tcb.is_null());
    // SAFETY: caller asserts both pointers are valid Tcbs and IRQs are off.
    unsafe {
        save(old_tcb);
        restore(&*new_tcb);
    }
}

/// Flush the live FP/SIMD registers into `tcb`'s save area when `tcb` is
/// the currently running thread on this CPU; otherwise no-op.
///
/// # Safety
/// `tcb` must be a valid Tcb pointer.
pub unsafe fn flush_current(tcb: *mut Tcb) {
    let current = crate::sched::scheduler::scheduler().current();
    if current == tcb {
        // SAFETY: tcb is current on this CPU and its save area is exclusively
        // owned by us until we yield.
        unsafe {
            save(tcb);
        }
    }
}

/// Restore the FP/SIMD registers from `tcb`'s save area when `tcb` is the
/// currently running thread on this CPU; otherwise no-op.
///
/// Used after callers mutate `tcb.fpu_state` directly (e.g. TCB_COPY_FPU
/// into self, fault-handler register rewrites) to keep the live
/// registers in sync.
///
/// # Safety
/// `tcb` must be a valid Tcb pointer.
pub unsafe fn reload_current(tcb: *mut Tcb) {
    let current = crate::sched::scheduler::scheduler().current();
    if current == tcb {
        // SAFETY: tcb is current on this CPU; its save area is stable for the
        // duration of this syscall.
        unsafe {
            restore(&*tcb);
        }
    }
}
