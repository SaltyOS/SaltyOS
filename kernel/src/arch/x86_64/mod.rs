//! x86_64 architecture support
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod apic;
mod boot;
mod context;
mod cpu;
mod gdt;
mod idt;
pub mod paging;
mod pit;

pub use apic::{send_ipi, IpiKind};
pub use cpu::{current_cpu, MAX_CPUS};

// Re-export architecture-specific implementations for generic arch interface
pub use context::context_switch;

/// Initialize x86_64 architecture
///
/// Critical initialization order:
/// 1. CPU data (BSP)
/// 2. GDT (required for IDT)
/// 3. IDT (must be ready BEFORE any interrupts fire)
/// 4. Memory management (frame allocator, needed by paging)
/// 5. APIC (timer is masked, won't fire yet)
/// 6. PIT (used for APIC timer calibration)
/// 7. Paging (kernel page tables + direct mapping)
///
/// Timer is started later via start_timer() after scheduler is ready.
pub fn init(boot_info: Option<&crate::BootInfo>) {
    // Debug: Print init entry
    unsafe {
        for byte in b"\n[ARCH] init() called\n" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
    }

    // Initialize per-CPU data for BSP
    cpu::init_bsp();

    // Initialize GDT (required before IDT)
    gdt::init();

    // Debug: Before IDT init
    unsafe {
        for byte in b"[ARCH] About to call idt::init()\n" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
    }

    // Initialize IDT BEFORE APIC timer starts
    // This prevents triple fault when timer fires
    idt::init();

    // Debug: After IDT init
    unsafe {
        for byte in b"[ARCH] idt::init() returned successfully\n" {
            while (inb(0x3F8 + 5) & 0x20) == 0 {}
            outb(0x3F8, *byte);
        }
    }

    // Initialize memory management (frame allocator needed by paging::init())
    if let Some(info) = boot_info {
        crate::mm::init(info);
    }

    // Initialize paging (kernel page tables already set up by bootloader)
    paging::init();

    // Initialize PIT (for calibration and fallback)
    pit::init();

    // Initialize APIC (timer is masked, won't fire yet)
    apic::init();
}

/// Start the APIC timer
///
/// Called after scheduler is initialized to begin timer ticks.
/// The timer is configured but masked during init() to prevent
/// interrupts before the scheduler is ready.
pub fn start_timer() {
    apic::start_timer();
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
