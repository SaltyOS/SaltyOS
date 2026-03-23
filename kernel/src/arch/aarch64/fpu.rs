//! AArch64 FPU/NEON lazy state management
//!
//! Implements lazy FPU switching using CPACR_EL1.FPEN trapping.
//! The kernel is compiled without NEON/FP support, so FPU state only
//! needs to be saved/restored when switching between userspace threads.
//!
//! Strategy:
//! - CPACR_EL1.FPEN = 0b01 after every context switch (trap EL0, allow EL1)
//! - First NEON/FP instruction in usermode triggers ESR EC=0x07 exception
//! - Exception handler saves previous owner's state, restores current
//!   thread's state, and sets FPEN = 0b11
//!
//! NEON/FP state per thread:
//! - 32 x 128-bit Q registers (V0-V31) = 512 bytes
//! - FPCR (4 bytes) + FPSR (4 bytes)
//! - Total: 520 bytes (padded to 528 in XSaveArea for alignment)
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::sched::thread::Tcb;

/// Per-CPU FPU owner tracking.
///
/// Each element holds a pointer to the TCB that currently owns the
/// hardware FP register state on that CPU. Null means no owner.
static mut FPU_OWNER: [*mut Tcb; super::MAX_CPUS] = [core::ptr::null_mut(); super::MAX_CPUS];

// ---------------------------------------------------------------------------
// CPACR_EL1 FPEN control
// ---------------------------------------------------------------------------

/// Trap EL0 FPU/NEON access while keeping EL1 available.
///
/// Sets CPACR_EL1.FPEN (bits 21:20) to 0b01, causing FP/NEON
/// instructions from EL0 to trap while still permitting EL1 code to use
/// compiler-emitted AdvSIMD instructions in routines like `memset`.
#[inline]
fn disable_fpu() {
    let mut cpacr: u64;
    // SAFETY: Reading CPACR_EL1 is safe from EL1.
    unsafe {
        core::arch::asm!("mrs {}, CPACR_EL1", out(reg) cpacr, options(nomem, nostack));
    }
    cpacr &= !(3u64 << 20);
    cpacr |= 1u64 << 20;
    // SAFETY: Writing CPACR_EL1 to trap EL0 FP access while leaving EL1
    // available is safe.
    // ISB ensures the change takes effect before the next instruction.
    unsafe {
        core::arch::asm!("msr CPACR_EL1, {}", in(reg) cpacr, options(nomem, nostack));
        core::arch::asm!("isb", options(nomem, nostack));
    }
}

/// Enable FPU/NEON access.
///
/// Sets CPACR_EL1.FPEN (bits 21:20) to 0b11, permitting FP/NEON
/// instructions from both EL0 and EL1.
#[inline]
fn enable_fpu() {
    let mut cpacr: u64;
    // SAFETY: Reading CPACR_EL1 is safe from EL1.
    unsafe {
        core::arch::asm!("mrs {}, CPACR_EL1", out(reg) cpacr, options(nomem, nostack));
    }
    cpacr |= 3u64 << 20;
    // SAFETY: Writing CPACR_EL1 to allow FP access is safe.
    // ISB ensures the change takes effect before the next instruction.
    unsafe {
        core::arch::asm!("msr CPACR_EL1, {}", in(reg) cpacr, options(nomem, nostack));
        core::arch::asm!("isb", options(nomem, nostack));
    }
}

// ---------------------------------------------------------------------------
// Save / restore NEON state
// ---------------------------------------------------------------------------

/// Save the current NEON/FP register state into the TCB's XSaveArea.
///
/// Saves all 32 Q registers (V0-V31), FPCR, and FPSR. FPU access
/// must be enabled (FPEN=0b11) before calling.
///
/// # Safety
/// `tcb` must be a valid pointer to a Tcb with a writable fpu_state field.
unsafe fn save(tcb: *mut Tcb) {
    // SAFETY: tcb is guaranteed valid by caller. We use addr_of_mut! to
    // get a raw pointer to the fpu_state field without creating a mutable
    // reference (avoiding aliasing concerns with the static FPU_OWNER).
    let area = unsafe { core::ptr::addr_of_mut!((*tcb).fpu_state).cast::<u8>() };
    // SAFETY: area points to the TCB's 528-byte XSaveArea which is large
    // enough for 32 Q registers (512 bytes) + FPCR (4) + FPSR (4).
    // FPU must be enabled (caller responsibility).
    unsafe {
        core::arch::asm!(
            "stp q0,  q1,  [{area}]",
            "stp q2,  q3,  [{area}, #32]",
            "stp q4,  q5,  [{area}, #64]",
            "stp q6,  q7,  [{area}, #96]",
            "stp q8,  q9,  [{area}, #128]",
            "stp q10, q11, [{area}, #160]",
            "stp q12, q13, [{area}, #192]",
            "stp q14, q15, [{area}, #224]",
            "stp q16, q17, [{area}, #256]",
            "stp q18, q19, [{area}, #288]",
            "stp q20, q21, [{area}, #320]",
            "stp q22, q23, [{area}, #352]",
            "stp q24, q25, [{area}, #384]",
            "stp q26, q27, [{area}, #416]",
            "stp q28, q29, [{area}, #448]",
            "stp q30, q31, [{area}, #480]",
            "mrs {tmp}, FPCR",
            "str {tmp:w}, [{area}, #512]",
            "mrs {tmp}, FPSR",
            "str {tmp:w}, [{area}, #516]",
            area = in(reg) area,
            tmp = out(reg) _,
        );
    }
}

/// Restore NEON/FP register state from the TCB's XSaveArea.
///
/// Loads all 32 Q registers (V0-V31), FPCR, and FPSR. FPU access
/// must be enabled (FPEN=0b11) before calling.
fn restore(tcb: &Tcb) {
    let area = tcb.fpu_state.data.as_ptr();
    // SAFETY: area points to the TCB's 528-byte XSaveArea containing
    // previously saved NEON state (or zeroes for first use after init).
    // FPU must be enabled (caller responsibility).
    unsafe {
        core::arch::asm!(
            "ldp q0,  q1,  [{area}]",
            "ldp q2,  q3,  [{area}, #32]",
            "ldp q4,  q5,  [{area}, #64]",
            "ldp q6,  q7,  [{area}, #96]",
            "ldp q8,  q9,  [{area}, #128]",
            "ldp q10, q11, [{area}, #160]",
            "ldp q12, q13, [{area}, #192]",
            "ldp q14, q15, [{area}, #224]",
            "ldp q16, q17, [{area}, #256]",
            "ldp q18, q19, [{area}, #288]",
            "ldp q20, q21, [{area}, #320]",
            "ldp q22, q23, [{area}, #352]",
            "ldp q24, q25, [{area}, #384]",
            "ldp q26, q27, [{area}, #416]",
            "ldp q28, q29, [{area}, #448]",
            "ldp q30, q31, [{area}, #480]",
            "ldr {tmp:w}, [{area}, #512]",
            "msr FPCR, {tmp}",
            "ldr {tmp:w}, [{area}, #516]",
            "msr FPSR, {tmp}",
            area = in(reg) area,
            tmp = out(reg) _,
        );
    }
}

// ---------------------------------------------------------------------------
// Public interface (matches x86_64 fpu module API)
// ---------------------------------------------------------------------------

/// Initialize FPU lazy switching on the current CPU.
///
/// Traps EL0 FPU access so the first NEON/FP instruction from EL0
/// triggers a trap (EC=0x07) for lazy context switching.
pub fn init() {
    disable_fpu();
}

/// Disable FPU access, arming the lazy-switch trap.
///
/// Called on every context switch (analogous to x86_64 `set_ts()`).
/// The next EL0 FP/NEON instruction will generate an EC=0x07 trap.
pub fn set_ts() {
    disable_fpu();
}

/// Save outgoing thread's FPU state during context switch.
///
/// If the given TCB is the current CPU's FPU owner, saves the live
/// hardware state into the TCB's XSaveArea and releases ownership.
/// This ensures the buffer is up-to-date before the thread can be
/// migrated to another CPU.
///
/// # Safety
/// `tcb_ptr` must be a valid pointer to a Tcb.
pub unsafe fn save_on_switch(tcb_ptr: *mut u8) {
    let cpu = super::current_cpu();
    // SAFETY: Accessing FPU_OWNER with interrupts disabled (context
    // switch always runs with IRQs masked). cpu is bounded by MAX_CPUS.
    let owner = unsafe { core::ptr::addr_of!(FPU_OWNER).read_volatile()[cpu] };
    if owner as *mut u8 == tcb_ptr {
        // SAFETY: Must enable FPU to access NEON registers for save.
        enable_fpu();
        // SAFETY: Caller guarantees tcb_ptr is a valid Tcb pointer.
        // save() requires a *mut Tcb to write into the fpu_state field.
        unsafe { save(tcb_ptr as *mut Tcb); }
        // SAFETY: Clearing owner after save; single-CPU access with IRQs off.
        unsafe {
            let owners = core::ptr::addr_of_mut!(FPU_OWNER);
            (*owners)[cpu] = core::ptr::null_mut();
        }
    }
}

/// If the given TCB is the current CPU's FPU owner, flush its state
/// from hardware into the TCB's XSaveArea.
///
/// Used by TCB_COPY_FPU to ensure the source TCB's state is up-to-date
/// before copying.
///
/// # Safety
/// `tcb_ptr` must be a valid pointer to a Tcb.
pub unsafe fn flush_if_owner(tcb_ptr: *mut u8) {
    let cpu = super::current_cpu();
    // SAFETY: Accessing FPU_OWNER with IRQs off (syscall context).
    let owner = unsafe { core::ptr::addr_of!(FPU_OWNER).read_volatile()[cpu] };
    if owner as *mut u8 == tcb_ptr {
        // SAFETY: Must enable FPU to access NEON registers for save.
        enable_fpu();
        // SAFETY: Caller guarantees tcb_ptr is a valid Tcb pointer.
        unsafe { save(tcb_ptr as *mut Tcb); }
        // SAFETY: Clearing owner and re-disabling FPU.
        unsafe {
            let owners = core::ptr::addr_of_mut!(FPU_OWNER);
            (*owners)[cpu] = core::ptr::null_mut();
        }
        disable_fpu();
    }
}

/// Clear FPU ownership if the given TCB is the current CPU's FPU owner.
///
/// Called during TCB cleanup to prevent stale pointer dereference.
/// The dying thread's FPU state is discarded (no need to save).
pub fn disown_if_current(tcb_ptr: *mut u8) {
    let cpu = super::current_cpu();
    // SAFETY: Accessing FPU_OWNER with IRQs off (cleanup context).
    let owner = unsafe { core::ptr::addr_of!(FPU_OWNER).read_volatile()[cpu] };
    if owner as *mut u8 == tcb_ptr {
        // SAFETY: Clearing owner; single-CPU access with IRQs off.
        unsafe {
            let owners = core::ptr::addr_of_mut!(FPU_OWNER);
            (*owners)[cpu] = core::ptr::null_mut();
        }
        disable_fpu();
    }
}

/// Handle FPU/NEON access trap (ESR EC=0x07).
///
/// Called from the exception handler when a usermode thread executes a
/// NEON/FP instruction while CPACR_EL1.FPEN=0b01. Saves the previous
/// owner's state, restores the current thread's state (or initializes
/// default state on first use), and enables FPU access.
pub fn handle_trap() {
    // Enable FPU before accessing any NEON registers (for save/restore)
    enable_fpu();

    let cpu = super::current_cpu();
    let current = crate::sched::scheduler::scheduler().current();

    // SAFETY: Accessing FPU_OWNER with IRQs off (exception context
    // inherits the interrupted thread's IRQ state, and EL0->EL1
    // transition does not unmask IRQs).
    let owner = unsafe { core::ptr::addr_of!(FPU_OWNER).read_volatile()[cpu] };

    // Save old owner's state if switching between threads
    if !owner.is_null() && owner != current {
        // SAFETY: owner is a valid TCB pointer set by a previous
        // handle_trap call on this CPU. FPU is enabled above.
        unsafe { save(owner); }
    }

    // Restore current thread's state or initialize on first use
    if !current.is_null() {
        // SAFETY: current is the running thread's TCB, guaranteed
        // valid by the scheduler.
        let tcb = unsafe { &*current };
        if tcb.fpu_initialized {
            restore(tcb);
        } else {
            // First FPU use — zero all Q registers and control regs.
            // Hardware reset state is already zero after enable_fpu,
            // but explicitly mark the thread as initialized.
            // SAFETY: current is valid and we have exclusive access
            // during exception handling.
            unsafe {
                (*current).fpu_initialized = true;
            }
        }
    }

    // Update per-CPU ownership
    // SAFETY: Single-CPU access with IRQs off.
    unsafe {
        let owners = core::ptr::addr_of_mut!(FPU_OWNER);
        (*owners)[cpu] = current;
    }
    // FPU stays enabled — FPEN=0b11 allows the faulting instruction
    // to re-execute successfully on eret.
}
