//! FPU/SSE eager state management
//!
//! The kernel itself is soft-float and never uses XMM registers, so FPU
//! state only needs to be saved/restored when switching between userspace
//! threads. This module performs that save+restore unconditionally on
//! every context switch — CR0.TS is held at 0 throughout and the
//! `#NM` (Device Not Available) trap is treated as a fatal regression.
//!
//! Strategy:
//! - `bsp_init` / `ap_init` configure CR0/CR4/XCR0 once per CPU and clear
//!   CR0.TS for the lifetime of the kernel.
//! - `init_thread` zero-initializes a TCB's save area; XRSTOR with an
//!   all-zero header (XSTATE_BV=0) reproduces the architectural init
//!   state per Intel SDM Vol.1 §13.8, so no fninit/ldmxcsr is required.
//! - `switch` xsaves the outgoing thread and xrstors the incoming thread
//!   in one IRQ-disabled step. The new thread runs immediately with no
//!   trap round-trip.
//! - `flush_current` / `reload_current` keep the live registers in sync
//!   when callers mutate the current thread's save area in place
//!   (TCB_COPY_FPU into self, fault-handler `tcb.fpu_state` rewrites).
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::sched::thread::{Tcb, XSaveArea};

unsafe extern "C" {
    fn x86_fpu_read_cr0() -> u64;
    fn x86_fpu_write_cr0(value: u64);
    fn x86_fpu_read_cr4() -> u64;
    fn x86_fpu_write_cr4(value: u64);
    fn x86_fpu_xsetbv0(value: u64);
    fn x86_fpu_fninit();
    fn x86_fpu_xsave(area: *mut u8);
    fn x86_fpu_xrstor(area: *const u8);
    fn x86_fpu_fxsave(area: *mut u8);
    fn x86_fpu_fxrstor(area: *const u8);
}

/// Initialize FPU hardware on the BSP (Boot Strap Processor).
///
/// Configures CR0, CR4, and XCR0 for SSE/XSAVE support. Called during
/// early kernel init after CPUID detection.
pub fn init_bsp() {
    // SAFETY: Single-threaded boot context, modifying control registers
    unsafe {
        configure_fpu_hardware();
    }
    crate::kernel::printk::kdebug!(arch, |_g| {
        _g.puts("[FPU] BSP FPU hardware configured\n");
    });
}

/// Initialize FPU hardware on an AP (Application Processor).
///
/// Same configuration as BSP — each CPU needs its own CR0/CR4 setup.
pub fn init_ap() {
    // SAFETY: AP init context, interrupts disabled
    unsafe {
        configure_fpu_hardware();
    }
}

/// Common FPU hardware configuration for both BSP and APs.
///
/// # Safety
/// Must be called during CPU init with interrupts disabled.
unsafe fn configure_fpu_hardware() {
    unsafe {
        // CR0 configuration (eager FPU):
        //   Clear EM (bit 2) — don't emulate FPU
        //   Set MP (bit 1) — monitor coprocessor (Intel-recommended for 80486+)
        //   Set NE (bit 5) — native FPU error reporting (use #MF, not IRQ 13)
        //   Clear TS (bit 3) and never set it — eager FPU saves/restores on
        //     every context switch, so #NM-driven lazy switching is not used.
        let mut cr0 = x86_fpu_read_cr0();
        cr0 &= !((1 << 2) | (1 << 3)); // clear EM, TS
        cr0 |= (1 << 1) | (1 << 5); // set MP, NE
        x86_fpu_write_cr0(cr0);

        // CR4 configuration:
        //   Set OSFXSR (bit 9) — enable FXSAVE/FXRSTOR
        //   Set OSXMMEXCPT (bit 10) — enable #XM exceptions for SIMD errors
        //   Set OSXSAVE (bit 18) — enable XSAVE/XRSTOR (if CPU supports it)
        let mut cr4 = x86_fpu_read_cr4();
        cr4 |= (1 << 9) | (1 << 10);
        if super::cpuid::has_xsave() {
            cr4 |= 1 << 18;
        }
        // SMEP: prevent kernel from executing user-mode pages (CR4 bit 20)
        if super::cpuid::has_smep() {
            cr4 |= 1 << 20;
        }
        // SMAP: prevent kernel from accessing user-mode pages unless EFLAGS.AC=1 (CR4 bit 21)
        if super::cpuid::has_smap() {
            cr4 |= 1 << 21;
            super::uaccess::enable_smap_runtime();
        }
        x86_fpu_write_cr4(cr4);

        // XCR0 configuration (if XSAVE available):
        //   Enable x87 (bit 0) + SSE (bit 1) state components
        if super::cpuid::has_xsave() {
            let xcr0: u64 = 0x3; // x87 + SSE
            x86_fpu_xsetbv0(xcr0);
        }

        // Initialize x87 FPU to known state
        x86_fpu_fninit();

        // Verify our static XSAVE buffer is large enough for the configured XCR0.
        // Currently XCR0=0x3 (x87+SSE) needs ≤576B and our buffer is 832B, but if
        // someone adds AVX-512 bits to XCR0 in the future, this catches the overflow
        // before it silently corrupts adjacent TCB fields.
        let needed = super::cpuid::xsave_area_size();
        if needed > 832 {
            crate::kernel::printk::kerror!(|_g| {
                _g.puts("*** FATAL: XSAVE area size (");
                _g.dec(needed as u64);
                _g.puts(") exceeds TCB buffer (832) ***\n");
            });
            loop {
                super::halt();
            }
        }
    }
}

/// Save FPU state to XSAVE area using XSAVE instruction.
///
/// # Safety
/// Area must be 64-byte aligned. Only call when XSAVE is supported.
unsafe fn xsave(area: &mut XSaveArea) {
    // SAFETY: XSAVE saves x87+SSE state (components 0x3) to 64-byte aligned area.
    // The assembly helper works regardless of soft-float target.
    unsafe {
        x86_fpu_xsave(area.data.as_mut_ptr());
    }
}

/// Restore FPU state from XSAVE area using XRSTOR instruction.
///
/// # Safety
/// Area must be 64-byte aligned and contain valid XSAVE state.
unsafe fn xrstor(area: &XSaveArea) {
    // SAFETY: XRSTOR restores x87+SSE state (components 0x3) from 64-byte aligned area.
    unsafe {
        x86_fpu_xrstor(area.data.as_ptr());
    }
}

/// Save FPU state using FXSAVE (fallback when XSAVE unavailable).
///
/// # Safety
/// Area must be 16-byte aligned (we use 64-byte aligned, which satisfies this).
unsafe fn fxsave(area: &mut XSaveArea) {
    unsafe {
        x86_fpu_fxsave(area.data.as_mut_ptr());
    }
}

/// Restore FPU state using FXRSTOR (fallback when XSAVE unavailable).
///
/// # Safety
/// Area must contain valid FXSAVE state.
unsafe fn fxrstor(area: &XSaveArea) {
    unsafe {
        x86_fpu_fxrstor(area.data.as_ptr());
    }
}

/// Initialize a freshly created or recycled TCB's FPU save area.
///
/// A zero-initialized XSAVE area encodes the processor-supplied init
/// state for every state component (Intel SDM Vol.1 §13.8: when XRSTOR
/// observes XSTATE_BV bit `i` cleared, component `i` is reset to its
/// init state — x87 control word 0x37F, MXCSR 0x1F80, tag word 0xFFFF,
/// all data registers zero). No fninit / ldmxcsr is needed before the
/// first switch-in.
pub fn init_thread(tcb: &mut Tcb) {
    tcb.fpu_state = XSaveArea::zeroed();
}

/// Save outgoing thread's FPU state and restore incoming thread's, in
/// the single context-switch step the scheduler invokes.
///
/// # Safety
/// `old_tcb` and `new_tcb` must be valid Tcb pointers. Must be called
/// with local IRQs disabled — the scheduler's `switch_common` holds
/// this invariant.
pub unsafe fn switch(old_tcb: *mut Tcb, new_tcb: *mut Tcb) {
    crate::kernel::bug::kassert!(!old_tcb.is_null());
    crate::kernel::bug::kassert!(!new_tcb.is_null());
    // SAFETY: caller asserts both pointers are valid Tcbs and IRQs are off,
    // so no other code on this CPU observes the half-saved state.
    unsafe {
        if super::cpuid::has_xsave() {
            xsave(&mut (*old_tcb).fpu_state);
            xrstor(&(*new_tcb).fpu_state);
        } else {
            fxsave(&mut (*old_tcb).fpu_state);
            fxrstor(&(*new_tcb).fpu_state);
        }
    }
}

/// Flush the live FPU registers into `tcb`'s save area when `tcb` is the
/// currently running thread on this CPU; otherwise no-op.
///
/// In eager mode the FPU is always implicitly owned by the currently
/// running thread, so this collapses to a self-check against the
/// scheduler. Used by TCB_COPY_FPU to capture the live state of the
/// parent / interrupted thread before reading it.
///
/// # Safety
/// `tcb` must be a valid Tcb pointer.
pub unsafe fn flush_current(tcb: *mut Tcb) {
    let current = crate::sched::scheduler::scheduler().current();
    if current == tcb {
        // SAFETY: tcb is current on this CPU, so its save area is exclusively
        // owned by us until we yield.
        unsafe {
            if super::cpuid::has_xsave() {
                xsave(&mut (*tcb).fpu_state);
            } else {
                fxsave(&mut (*tcb).fpu_state);
            }
        }
    }
}

/// Restore the FPU registers from `tcb`'s save area when `tcb` is the
/// currently running thread on this CPU; otherwise no-op.
///
/// Used after callers mutate `tcb.fpu_state` directly (e.g. TCB_COPY_FPU
/// into self, fault-handler register rewrites) to keep the live
/// registers in sync — without this, the next switch-out would xsave
/// the stale register contents back over the freshly written buffer.
///
/// # Safety
/// `tcb` must be a valid Tcb pointer.
pub unsafe fn reload_current(tcb: *mut Tcb) {
    let current = crate::sched::scheduler::scheduler().current();
    if current == tcb {
        // SAFETY: tcb is current on this CPU; its save area is stable for the
        // duration of this syscall.
        unsafe {
            if super::cpuid::has_xsave() {
                xrstor(&(*tcb).fpu_state);
            } else {
                fxrstor(&(*tcb).fpu_state);
            }
        }
    }
}
