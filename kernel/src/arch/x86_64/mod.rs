//! x86_64 architecture support
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod apic;
mod boot;
mod context;
mod cpu;
mod gdt;
mod idt;
mod pit;
pub mod paging;

pub use cpu::{current_cpu, MAX_CPUS};

// Re-export architecture-specific implementations for generic arch interface
pub use context::{context_switch, init_thread_context};

/// Initialize x86_64 architecture
pub fn init() {
    // Initialize per-CPU data for BSP
    cpu::init_bsp();

    // Initialize GDT
    gdt::init();

    // Initialize APIC and timer
    apic::init();

    // Initialize PIT (for calibration and fallback)
    pit::init();

    // Initialize IDT (now includes APIC timer handler)
    idt::init();

    // Initialize paging (kernel page tables already set up by bootloader)
    paging::init();
}

/// Halt CPU until next interrupt
#[inline(always)]
pub fn halt() {
    // SAFETY: hlt is always safe, just waits for interrupt
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

/// Disable interrupts
#[inline(always)]
pub fn cli() {
    // SAFETY: Disabling interrupts is safe in kernel context
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
}

/// Enable interrupts
#[inline(always)]
pub fn sti() {
    // SAFETY: Enabling interrupts is safe when IDT is set up
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }
}

/// Output byte to port
#[inline(always)]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Caller ensures port access is valid
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack)
        );
    }
}

/// Input byte from port
#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: Caller ensures port access is valid
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nomem, nostack)
        );
    }
    value
}
