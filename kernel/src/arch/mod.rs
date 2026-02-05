//! Architecture-specific code
//!
//! SPDX-License-Identifier: GPL-2.0-only

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

// Re-export architecture-specific items
#[cfg(target_arch = "x86_64")]
pub use x86_64::{current_cpu, MAX_CPUS};

// Re-export context switch interface
#[cfg(target_arch = "x86_64")]
pub use x86_64::context_switch;

// Re-export IPI types and functions
#[cfg(target_arch = "x86_64")]
pub use x86_64::{send_ipi, IpiKind};

/// Initialize architecture-specific subsystems
pub fn init(boot_info: Option<&crate::ParsedBootInfo>) {
    #[cfg(target_arch = "x86_64")]
    x86_64::init(boot_info);
}

/// Halt the CPU until next interrupt
pub fn halt() {
    #[cfg(target_arch = "x86_64")]
    x86_64::halt();
}

/// Enable interrupts
pub fn sti() {
    #[cfg(target_arch = "x86_64")]
    x86_64::sti();
}

/// Disable interrupts
pub fn cli() {
    #[cfg(target_arch = "x86_64")]
    x86_64::cli();
}

/// Start timer interrupts
///
/// Called after scheduler is initialized to begin timer ticks.
/// This is separate from init() because the timer must not start
/// until the idle thread is ready to handle interrupts.
pub fn start_timer() {
    #[cfg(target_arch = "x86_64")]
    x86_64::start_timer();
}

/// Output byte to I/O port
///
/// # Safety
/// Caller must ensure the port access is valid.
#[inline(always)]
pub unsafe fn outb(port: u16, value: u8) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Caller ensures port access is valid
    unsafe {
        x86_64::outb(port, value);
    }
}

/// Input byte from I/O port
///
/// # Safety
/// Caller must ensure the port access is valid.
#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Caller ensures port access is valid
    unsafe {
        return x86_64::inb(port);
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}
