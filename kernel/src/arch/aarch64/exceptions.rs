// SPDX-License-Identifier: GPL-2.0-only
//! AArch64 exception vector table and dispatch handlers.
//!
//! Provides the VBAR_EL1 vector table (via `global_asm!`) and Rust-side
//! handlers for synchronous exceptions (SVC, data/instruction aborts) and
//! IRQs from both EL1 and EL0.

use core::arch::global_asm;

// ---------------------------------------------------------------------------
// Exception frame
// ---------------------------------------------------------------------------

/// Saved register state pushed onto the kernel stack by the exception entry
/// macro.  Layout must match the `SAVE_REGS` / `RESTORE_REGS` assembly below.
///
/// Total size: 34 saved values (x0-x30 + SP_EL0 + ELR_EL1 + SPSR_EL1) =
/// 272 bytes, padded to 288 for 16-byte stack alignment.
#[repr(C)]
pub struct ExceptionFrame {
    /// General-purpose registers x0-x30.
    pub regs: [u64; 31],
    /// Saved user stack pointer (SP_EL0).
    pub sp_el0: u64,
    /// Exception return address (ELR_EL1).
    pub elr_el1: u64,
    /// Saved processor state (SPSR_EL1).
    pub spsr_el1: u64,
    /// Padding to 288 bytes (16-byte aligned).
    pub _pad: [u64; 2],
}

// ---------------------------------------------------------------------------
// ESR_EL1 exception class constants
// ---------------------------------------------------------------------------

/// SVC instruction execution in AArch64 state.
const EC_SVC_AARCH64: u64 = 0x15;
/// Instruction abort from a lower Exception Level.
const EC_IABT_LOWER: u64 = 0x20;
/// Instruction abort from the current Exception Level.
const EC_IABT_CURRENT: u64 = 0x21;
/// Data abort from a lower Exception Level.
const EC_DABT_LOWER: u64 = 0x24;
/// Data abort from the current Exception Level.
const EC_DABT_CURRENT: u64 = 0x25;
/// Access to SVE, Advanced SIMD, or floating-point (trapped).
const EC_FP_TRAP: u64 = 0x07;

/// Spurious interrupt ID (no pending interrupt).
const INTID_SPURIOUS: u32 = 1023;
/// Physical timer PPI interrupt ID.
const INTID_PHYS_TIMER: u32 = 30;
/// Maximum SGI interrupt ID (inclusive).
const INTID_SGI_MAX: u32 = 15;

// ---------------------------------------------------------------------------
// Vector table + save/restore macros (assembly)
// ---------------------------------------------------------------------------

global_asm!(
    r#"
// ---- Register save macro ----
// Pushes x0-x30, SP_EL0, ELR_EL1, SPSR_EL1 onto the kernel stack.
// Frame size: 288 bytes (272 payload + 16 padding for alignment).
.macro SAVE_REGS
    sub     sp, sp, #288
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]
    mrs     x0, SP_EL0
    str     x0, [sp, #248]
    mrs     x0, ELR_EL1
    str     x0, [sp, #256]
    mrs     x0, SPSR_EL1
    str     x0, [sp, #264]
.endm

// ---- Register restore macro ----
// Pops the saved state and returns via ERET.
.macro RESTORE_REGS
    ldr     x0, [sp, #264]
    msr     SPSR_EL1, x0
    ldr     x0, [sp, #256]
    msr     ELR_EL1, x0
    ldr     x0, [sp, #248]
    msr     SP_EL0, x0
    ldp     x28, x29, [sp, #224]
    ldr     x30, [sp, #240]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #288
    eret
.endm

// ---- Vector table ----
// Must be 2048-byte aligned (VBAR_EL1 requirement).
// 16 entries, each 128 bytes (32 instructions max).

    .section .text
    .balign 2048
    .global exception_vectors
exception_vectors:

    // ---- Group 0: Current EL with SP0 (not used) ----
    .balign 128
    b       .                   // Sync
    .balign 128
    b       .                   // IRQ
    .balign 128
    b       .                   // FIQ
    .balign 128
    b       .                   // SError

    // ---- Group 1: Current EL with SPx (kernel exceptions) ----
    .balign 128
    b       el1_sync            // Sync
    .balign 128
    b       el1_irq             // IRQ
    .balign 128
    b       .                   // FIQ (unused)
    .balign 128
    b       .                   // SError (TODO: handle)

    // ---- Group 2: Lower EL using AArch64 (user exceptions) ----
    .balign 128
    b       el0_sync            // Sync (SVC, data abort, etc.)
    .balign 128
    b       el0_irq             // IRQ
    .balign 128
    b       .                   // FIQ (unused)
    .balign 128
    b       .                   // SError (TODO: handle)

    // ---- Group 3: Lower EL using AArch32 (not supported) ----
    .balign 128
    b       .
    .balign 128
    b       .
    .balign 128
    b       .
    .balign 128
    b       .

// ---- Handler stubs ----

el1_sync:
    SAVE_REGS
    mov     x0, sp
    bl      el1_sync_handler
    RESTORE_REGS

el1_irq:
    SAVE_REGS
    mov     x0, sp
    bl      el1_irq_handler
    RESTORE_REGS

el0_sync:
    SAVE_REGS
    mov     x0, sp
    bl      el0_sync_handler
    RESTORE_REGS

el0_irq:
    SAVE_REGS
    mov     x0, sp
    bl      el0_irq_handler
    RESTORE_REGS
"#,
);

// ---------------------------------------------------------------------------
// Rust exception handlers
// ---------------------------------------------------------------------------

/// Handle synchronous exceptions taken from EL1 (kernel context).
///
/// Reads ESR_EL1 to determine the exception class and dispatches accordingly.
#[unsafe(no_mangle)]
extern "C" fn el1_sync_handler(frame: *const ExceptionFrame) {
    let esr: u64;
    // SAFETY: Reading ESR_EL1 is always safe from EL1.
    unsafe {
        core::arch::asm!("mrs {}, ESR_EL1", out(reg) esr, options(nomem, nostack));
    }
    let ec = (esr >> 26) & 0x3F;

    match ec {
        EC_DABT_CURRENT => {
            // Data abort from EL1 (kernel page fault).
            let far: u64;
            // SAFETY: Reading FAR_EL1 is always safe from EL1.
            unsafe {
                core::arch::asm!("mrs {}, FAR_EL1", out(reg) far, options(nomem, nostack));
            }
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };
            panic!(
                "EL1 data abort: FAR={:#018x} ESR={:#010x} ELR={:#018x}",
                far, esr, elr,
            );
        }
        EC_IABT_CURRENT => {
            // Instruction abort from EL1.
            let far: u64;
            // SAFETY: Reading FAR_EL1 is always safe from EL1.
            unsafe {
                core::arch::asm!("mrs {}, FAR_EL1", out(reg) far, options(nomem, nostack));
            }
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };
            panic!(
                "EL1 instruction abort: FAR={:#018x} ESR={:#010x} ELR={:#018x}",
                far, esr, elr,
            );
        }
        _ => {
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };
            panic!(
                "Unexpected EL1 sync exception: EC={:#04x} ESR={:#010x} ELR={:#018x}",
                ec, esr, elr,
            );
        }
    }
}

/// Handle IRQs taken from EL1 (kernel context).
///
/// Acknowledges the interrupt via the GIC, dispatches based on INTID,
/// and sends EOI.
#[unsafe(no_mangle)]
extern "C" fn el1_irq_handler(_frame: *const ExceptionFrame) {
    let intid = super::gic::acknowledge_irq();

    match intid {
        INTID_PHYS_TIMER => {
            // Physical timer PPI — re-arm before EOI to clear ISTATUS,
            // then EOI before timer_tick (which may context-switch).
            super::timer::rearm();
            super::gic::eoi(intid);
            crate::sched::timer_tick();
        }
        0..=INTID_SGI_MAX => {
            // Software Generated Interrupt (IPI).
            super::gic::eoi(intid);
            // TODO: dispatch IPI based on intid (reschedule, TLB shootdown, etc.)
        }
        INTID_SPURIOUS => {
            // Spurious interrupt — no EOI needed.
        }
        _ => {
            // SPI or other interrupt — EOI and log.
            super::gic::eoi(intid);
        }
    }
}

/// Handle synchronous exceptions taken from EL0 (user context).
///
/// Dispatches SVC (syscall), data aborts (user page fault), instruction
/// aborts, and FP/NEON traps.
#[unsafe(no_mangle)]
extern "C" fn el0_sync_handler(frame: *mut ExceptionFrame) {
    let esr: u64;
    // SAFETY: Reading ESR_EL1 is always safe from EL1.
    unsafe {
        core::arch::asm!("mrs {}, ESR_EL1", out(reg) esr, options(nomem, nostack));
    }
    let ec = (esr >> 26) & 0x3F;

    match ec {
        EC_SVC_AARCH64 => {
            // SVC from AArch64 — system call.
            // AArch64 SVC convention:
            //   x8  = syscall number
            //   x0  = cap_ptr
            //   x1-x5 = arg0-arg4
            // SAFETY: frame was set up by SAVE_REGS and is a valid pointer
            // to a fully-initialized ExceptionFrame on the kernel stack.
            // syscall_handle_rust is unsafe because it performs privileged
            // kernel operations based on the syscall number.
            unsafe {
                let f = &*frame;
                let result = crate::syscall::syscall_handle_rust(
                    f.regs[8],  // syscall number (x8)
                    f.regs[0],  // cap_ptr (x0)
                    f.regs[1],  // arg0 (x1)
                    f.regs[2],  // arg1 (x2)
                    f.regs[3],  // arg2 (x3)
                    f.regs[4],  // arg3 (x4)
                    f.regs[5],  // arg4 (x5)
                );
                // Write return values back into the saved frame so RESTORE_REGS
                // delivers them to userspace.
                (*frame).regs[0] = result.error; // x0 = error code
                (*frame).regs[1] = result.value; // x1 = return value
            }
        }
        EC_DABT_LOWER => {
            // Data abort from EL0 (user page fault).
            let far: u64;
            // SAFETY: Reading FAR_EL1 is always safe from EL1.
            unsafe {
                core::arch::asm!("mrs {}, FAR_EL1", out(reg) far, options(nomem, nostack));
            }
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };
            // TODO: dispatch to VSpace fault handler for COW / demand paging
            crate::serial_puts("[EXCEPTION] EL0 data abort: FAR=");
            {
                let s = crate::SerialGuard::acquire();
                s.hex(far);
                s.puts(" ESR=");
                s.hex(esr);
                s.puts(" ELR=");
                s.hex(elr);
                s.puts("\n");
            }
        }
        EC_IABT_LOWER => {
            // Instruction abort from EL0.
            let far: u64;
            // SAFETY: Reading FAR_EL1 is always safe from EL1.
            unsafe {
                core::arch::asm!("mrs {}, FAR_EL1", out(reg) far, options(nomem, nostack));
            }
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };
            // TODO: deliver SIGSEGV or kill faulting thread
            crate::serial_puts("[EXCEPTION] EL0 instruction abort: FAR=");
            {
                let s = crate::SerialGuard::acquire();
                s.hex(far);
                s.puts(" ESR=");
                s.hex(esr);
                s.puts(" ELR=");
                s.hex(elr);
                s.puts("\n");
            }
        }
        EC_FP_TRAP => {
            // FPU/NEON access trap — lazy context switching.
            super::fpu::handle_trap();
        }
        _ => {
            // SAFETY: frame was set up by SAVE_REGS and is valid.
            let elr = unsafe { (*frame).elr_el1 };
            crate::serial_puts("[EXCEPTION] Unknown EL0 sync: EC=");
            {
                let s = crate::SerialGuard::acquire();
                s.hex(ec);
                s.puts(" ESR=");
                s.hex(esr);
                s.puts(" ELR=");
                s.hex(elr);
                s.puts("\n");
            }
        }
    }
}

/// Handle IRQs taken from EL0 (user context).
///
/// Delegates to the EL1 IRQ handler — the GIC interrupt handling is identical
/// regardless of which exception level was interrupted.
#[unsafe(no_mangle)]
extern "C" fn el0_irq_handler(frame: *const ExceptionFrame) {
    el1_irq_handler(frame);
}

// ---------------------------------------------------------------------------
// VBAR installation
// ---------------------------------------------------------------------------

/// Install the exception vector table by writing its address to VBAR_EL1.
///
/// Must be called during early boot after the vector table is accessible
/// (identity-mapped or in the direct physical map).
pub fn init() {
    unsafe extern "C" {
        static exception_vectors: u8;
    }
    // SAFETY: exception_vectors is defined in the global_asm! block above
    // and is guaranteed to be 2048-byte aligned.
    let vbar = core::ptr::addr_of!(exception_vectors) as u64;
    // SAFETY: Writing VBAR_EL1 is safe during single-threaded boot from EL1.
    // The ISB ensures the new vector table address is visible before any
    // subsequent exception can be taken.
    unsafe {
        core::arch::asm!(
            "msr VBAR_EL1, {}",
            "isb",
            in(reg) vbar,
            options(nomem, nostack),
        );
    }
}
