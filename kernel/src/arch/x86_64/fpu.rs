//! FPU/SSE Lazy State Management
//!
//! Implements lazy FPU switching using CR0.TS + #NM (Device Not Available).
//! The kernel itself is soft-float and never uses XMM registers, so FPU state
//! only needs to be saved/restored when switching between userspace threads.
//!
//! Strategy:
//! - CR0.TS is set on every context switch
//! - First FPU instruction in usermode triggers #NM exception
//! - #NM handler saves old owner's state (XSAVE) and restores new owner's (XRSTOR)
//! - CR0.TS is cleared after restore, allowing subsequent FPU instructions
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::sched::thread::{Tcb, XSaveArea};
use super::cpu;

/// Initialize FPU hardware on the BSP (Boot Strap Processor).
///
/// Configures CR0, CR4, and XCR0 for SSE/XSAVE support.
/// Called during early kernel init after CPUID detection.
pub fn init_bsp() {
    // SAFETY: Single-threaded boot context, modifying control registers
    unsafe {
        configure_fpu_hardware();
    }
    crate::serial_puts("[FPU] BSP FPU hardware configured\n");
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
        // CR0 configuration:
        //   Clear EM (bit 2) — don't emulate FPU
        //   Set MP (bit 1) — monitor coprocessor (WAIT/FWAIT trigger #NM when TS=1)
        //   Set NE (bit 5) — native FPU error reporting (use #MF, not IRQ 13)
        //   TS (bit 3) is NOT set here — it's set on context switch (scheduler.rs)
        let mut cr0: u64;
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nostack));
        cr0 &= !(1 << 2); // clear EM
        cr0 |= (1 << 1) | (1 << 5); // set MP, NE (TS is set on context switch, not here)
        core::arch::asm!("mov cr0, {}", in(reg) cr0, options(nostack));

        // CR4 configuration:
        //   Set OSFXSR (bit 9) — enable FXSAVE/FXRSTOR
        //   Set OSXMMEXCPT (bit 10) — enable #XM exceptions for SIMD errors
        //   Set OSXSAVE (bit 18) — enable XSAVE/XRSTOR (if CPU supports it)
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack));
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
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack));

        // XCR0 configuration (if XSAVE available):
        //   Enable x87 (bit 0) + SSE (bit 1) state components
        if super::cpuid::has_xsave() {
            let xcr0: u64 = 0x3; // x87 + SSE
            core::arch::asm!(
                "xsetbv",
                in("ecx") 0u32,
                in("eax") xcr0 as u32,
                in("edx") 0u32,
                options(nostack),
            );
        }

        // Initialize x87 FPU to known state
        core::arch::asm!("fninit", options(nostack));

        // Verify our static XSAVE buffer is large enough for the configured XCR0.
        // Currently XCR0=0x3 (x87+SSE) needs ≤576B and our buffer is 832B, but if
        // someone adds AVX-512 bits to XCR0 in the future, this catches the overflow
        // before it silently corrupts adjacent TCB fields.
        let needed = super::cpuid::xsave_area_size();
        if needed > 832 {
            let s = crate::SerialGuard::acquire();
            s.puts("*** FATAL: XSAVE area size (");
            s.dec(needed as u64);
            s.puts(") exceeds TCB buffer (832) ***\n");
            drop(s);
            loop { super::halt(); }
        }
    }
}

/// Handle #NM (Device Not Available) exception — lazy FPU switching.
///
/// Called from the IDT exception handler when a usermode thread executes
/// an FPU/SSE instruction with CR0.TS set.
///
/// # Safety
/// Must be called from exception context with the faulting thread as current.
pub unsafe fn handle_nm() {
    unsafe {
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();
        if current.is_null() {
            return;
        }

        // Clear TS BEFORE any FPU/SSE operations to prevent recursive #NM.
        // Instructions like xsave/fxsave/xrstor/fxrstor/ldmxcsr all trigger
        // #NM when CR0.TS=1, which would cause a kernel-mode #NM panic.
        clear_ts();

        let old_owner = cpu::get_fpu_owner() as *mut Tcb;

        // 1. Save old owner's FPU state (if different thread)
        if !old_owner.is_null() && old_owner != current {
            if super::cpuid::has_xsave() {
                xsave(&mut (*old_owner).fpu_state);
            } else {
                fxsave(&mut (*old_owner).fpu_state);
            }
        }

        // 2. Restore current thread's FPU state (or initialize defaults)
        if (*current).fpu_initialized {
            if super::cpuid::has_xsave() {
                xrstor(&(*current).fpu_state);
            } else {
                fxrstor(&(*current).fpu_state);
            }
        } else {
            // First FPU use by this thread — initialize to clean defaults
            core::arch::asm!("fninit", options(nostack));
            // Set MXCSR to default: all SIMD exceptions masked
            let mxcsr: u32 = 0x1F80;
            core::arch::asm!(
                "ldmxcsr [{}]",
                in(reg) &mxcsr,
                options(nostack),
            );
            (*current).fpu_initialized = true;
        }

        // 3. Update ownership (TS already cleared at entry)
        cpu::set_fpu_owner(current as *mut u8);
    }
}

/// Save FPU state to XSAVE area using XSAVE instruction.
///
/// # Safety
/// Area must be 64-byte aligned. Only call when XSAVE is supported.
unsafe fn xsave(area: &mut XSaveArea) {
    // SAFETY: XSAVE saves x87+SSE state (components 0x3) to 64-byte aligned area.
    // The asm! block uses explicit register arguments; this instruction works
    // regardless of soft-float target since it's inline asm.
    unsafe {
        core::arch::asm!(
            "xsave [{}]",
            in(reg) area.data.as_mut_ptr(),
            in("eax") 0x3u32,
            in("edx") 0u32,
            options(nostack),
        );
    }
}

/// Restore FPU state from XSAVE area using XRSTOR instruction.
///
/// # Safety
/// Area must be 64-byte aligned and contain valid XSAVE state.
unsafe fn xrstor(area: &XSaveArea) {
    // SAFETY: XRSTOR restores x87+SSE state (components 0x3) from 64-byte aligned area.
    unsafe {
        core::arch::asm!(
            "xrstor [{}]",
            in(reg) area.data.as_ptr(),
            in("eax") 0x3u32,
            in("edx") 0u32,
            options(nostack),
        );
    }
}

/// Save FPU state using FXSAVE (fallback when XSAVE unavailable).
///
/// # Safety
/// Area must be 16-byte aligned (we use 64-byte aligned, which satisfies this).
unsafe fn fxsave(area: &mut XSaveArea) {
    unsafe {
        core::arch::asm!(
            "fxsave [{}]",
            in(reg) area.data.as_mut_ptr(),
            options(nostack),
        );
    }
}

/// Restore FPU state using FXRSTOR (fallback when XSAVE unavailable).
///
/// # Safety
/// Area must contain valid FXSAVE state.
unsafe fn fxrstor(area: &XSaveArea) {
    unsafe {
        core::arch::asm!(
            "fxrstor [{}]",
            in(reg) area.data.as_ptr(),
            options(nostack),
        );
    }
}

/// Save current FPU state of the hardware into the given area.
///
/// Public wrapper for use by TCB_COPY_FPU syscall when the source
/// thread is the current FPU owner and its state needs flushing.
///
/// # Safety
/// Caller must ensure area is valid and 64-byte aligned.
pub unsafe fn xsave_current(area: &mut XSaveArea) {
    unsafe {
        if super::cpuid::has_xsave() {
            xsave(area);
        } else {
            fxsave(area);
        }
    }
}

/// Set CR0.TS (Task Switched) bit.
///
/// Next FPU/SSE instruction will trigger #NM for lazy switching.
/// Called on context switch.
#[inline]
pub fn set_ts() {
    // SAFETY: Setting TS is safe — it only causes #NM on next FPU use
    unsafe {
        core::arch::asm!(
            "mov rax, cr0",
            "or rax, 8",
            "mov cr0, rax",
            out("rax") _,
            options(nostack),
        );
    }
}

/// Clear CR0.TS bit.
///
/// Allows FPU/SSE instructions without triggering #NM.
/// Called after restoring FPU state for the current thread.
#[inline]
fn clear_ts() {
    // SAFETY: clts is a privileged instruction that clears TS — safe in kernel
    unsafe {
        core::arch::asm!("clts", options(nostack));
    }
}

/// If the given TCB is the current CPU's FPU owner, flush its FPU state
/// from hardware registers into the TCB's XSaveArea.
///
/// Used by TCB_COPY_FPU to ensure the source TCB's state is up-to-date
/// before copying to the destination.
///
/// # Safety
/// `tcb_ptr` must be a valid pointer to a Tcb.
pub unsafe fn flush_if_owner(tcb_ptr: *mut u8) {
    if cpu::get_fpu_owner() == tcb_ptr {
        // SAFETY: Caller guarantees tcb_ptr is valid Tcb.
        // Clear TS before XSAVE — if the caller reached here via a path that
        // set CR0.TS (e.g. fork on the same CPU after context switch), XSAVE
        // would trigger a kernel #NM.
        unsafe {
            clear_ts();
            let tcb = &mut *(tcb_ptr as *mut Tcb);
            xsave_current(&mut tcb.fpu_state);
        }
    }
}

/// Save outgoing thread's FPU state to its TCB buffer during context switch.
///
/// If the given TCB is the current CPU's FPU owner, saves the live hardware
/// state into the TCB's XSaveArea and releases ownership. This ensures the
/// buffer is up-to-date before the thread migrates to another CPU.
///
/// # Safety
/// `tcb_ptr` must be a valid pointer to a Tcb.
pub unsafe fn save_on_switch(tcb_ptr: *mut u8) {
    if cpu::get_fpu_owner() == tcb_ptr {
        // SAFETY: Caller guarantees tcb_ptr is valid Tcb.
        // Clear TS before XSAVE to prevent kernel #NM.
        unsafe {
            clear_ts();
            let tcb = &mut *(tcb_ptr as *mut Tcb);
            xsave_current(&mut tcb.fpu_state);
            cpu::set_fpu_owner(core::ptr::null_mut());
        }
    }
}

/// Clear FPU ownership if the given TCB is the current CPU's FPU owner.
///
/// Called during TCB cleanup to prevent stale pointer dereference.
/// If the dying thread's FPU state is in hardware, we discard it
/// (no need to save — the thread is being destroyed).
pub fn disown_if_current(tcb_ptr: *mut u8) {
    if cpu::get_fpu_owner() == tcb_ptr {
        // SAFETY: We're clearing the owner and setting TS so next FPU use
        // triggers #NM for whoever runs next.
        unsafe {
            cpu::set_fpu_owner(core::ptr::null_mut());
        }
        set_ts();
    }
}
