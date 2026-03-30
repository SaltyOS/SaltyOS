//! AArch64 FPU/NEON lazy state management
//!
//! Implements lazy FPU switching using CPACR_EL1.
//! The kernel is compiled without NEON/FP support, so FPU state only
//! needs to be saved/restored when switching between userspace threads.
//!
//! The kernel target spec (`aarch64-saltyos.json`) disables NEON via
//! `-neon` and uses a soft-float ABI, while C code uses `-mgeneral-regs-only`,
//! preventing the compiler from emitting AdvSIMD/FP instructions in
//! kernel code. This ensures the lazy switching strategy is correct:
//! Rust code never touches Q registers directly, and the save/restore
//! path lives in dedicated assembly helpers.
//!
//! Strategy:
//! - EL1 host: CPACR_EL1.FPEN = 0b01 after every context switch (trap EL0, allow EL1)
//! - First NEON/FP instruction in usermode triggers ESR EC=0x07 exception
//! - Exception handler saves previous owner's state, restores current
//!   thread's state, and re-enables FP access
//!
//! NEON/FP state per thread:
//! - 32 x 128-bit Q registers (V0-V31) = 512 bytes
//! - FPCR (4 bytes) + FPSR (4 bytes)
//! - Total: 520 bytes (padded to 528 in XSaveArea for alignment)
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::sched::thread::Tcb;

unsafe extern "C" {
    fn aarch64_fpsimd_save_state(area: *mut u8);
    fn aarch64_fpsimd_restore_state(area: *const u8);
}

/// Per-CPU FPU owner tracking.
///
/// Each element holds a pointer to the TCB that currently owns the
/// hardware FP register state on that CPU. Null means no owner.
static mut FPU_OWNER: [*mut Tcb; super::MAX_CPUS] = [core::ptr::null_mut(); super::MAX_CPUS];

// ---------------------------------------------------------------------------
// Host FP trap control
// ---------------------------------------------------------------------------

/// Trap user FPU/NEON access while keeping EL1 able to toggle FP access.
///
/// Sets CPACR_EL1.FPEN (bits 21:20) to 0b01.
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
    unsafe {
        core::arch::asm!("msr CPACR_EL1, {}", in(reg) cpacr, options(nomem, nostack));
        core::arch::asm!("isb", options(nomem, nostack));
    }
}

/// Enable FPU/NEON access by setting CPACR_EL1.FPEN (bits 21:20) to 0b11.
#[inline]
fn enable_fpu() {
    let mut cpacr: u64;
    // SAFETY: Reading CPACR_EL1 is safe from EL1.
    unsafe {
        core::arch::asm!("mrs {}, CPACR_EL1", out(reg) cpacr, options(nomem, nostack));
    }
    cpacr |= 3u64 << 20;
    // SAFETY: Writing CPACR_EL1 to allow FP access is safe.
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
    // SAFETY: tcb is guaranteed valid by caller. data is the start of the
    // 528-byte save area consumed by the assembly helper.
    let area = unsafe { core::ptr::addr_of_mut!((*tcb).fpu_state.data).cast::<u8>() };
    // SAFETY: FPU must be enabled by caller; area points at writable storage.
    unsafe { aarch64_fpsimd_save_state(area); }
}

/// Restore NEON/FP register state from the TCB's XSaveArea.
///
/// Loads all 32 Q registers (V0-V31), FPCR, and FPSR. FPU access
/// must be enabled (FPEN=0b11) before calling.
fn restore(tcb: &Tcb) {
    let area = tcb.fpu_state.data.as_ptr();
    // SAFETY: area points at a valid save area, including the zeroed default
    // state used before a thread first touches FP/SIMD.
    unsafe { aarch64_fpsimd_restore_state(area); }
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
/// `tcb_ptr` must be a valid pointer to a Tcb. Must be called with
/// IRQs disabled from the context switch path.
///
/// The read-then-null of `FPU_OWNER[cpu]` is not a race because:
/// 1. IRQ disable prevents preemption on this CPU, so no other code
///    on this CPU can interleave with the read→save→null sequence.
/// 2. Other CPUs only access their own `FPU_OWNER[their_cpu]` index,
///    never ours.
/// 3. The outgoing thread cannot be scheduled on another CPU until
///    `switch_to()` completes and releases the scheduler lock.
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
/// NEON/FP instruction while host FP access trapping is armed. Saves the previous
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
        restore(tcb);
        if !tcb.fpu_initialized {
            // SAFETY: current is valid and we have exclusive access during
            // exception handling.
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
