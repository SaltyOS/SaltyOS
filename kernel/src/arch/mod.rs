//! Architecture-specific code
//!
//! SPDX-License-Identifier: GPL-2.0-only

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

// Re-export paging module through a common path so shared code can use
// `crate::arch::paging::*` instead of `crate::arch::x86_64::paging::*`
#[cfg(target_arch = "x86_64")]
pub use x86_64::paging;

#[cfg(target_arch = "aarch64")]
pub use aarch64::paging;

// Re-export architecture-specific items
#[cfg(target_arch = "x86_64")]
pub use x86_64::{current_cpu, next_invoke_seq, current_invoke_seq, set_kernel_stack, set_tss_rsp0, read_fs_base, write_fs_base, generate_stack_canary, set_per_cpu_canary, MAX_CPUS};

#[cfg(target_arch = "aarch64")]
pub use aarch64::{current_cpu, next_invoke_seq, current_invoke_seq, set_kernel_stack, set_tss_rsp0, read_fs_base, write_fs_base, generate_stack_canary, set_per_cpu_canary, MAX_CPUS};

// Re-export context switch interface
#[cfg(target_arch = "x86_64")]
pub use x86_64::{context_switch, usermode_trampoline};

#[cfg(target_arch = "aarch64")]
pub use aarch64::{context_switch, usermode_trampoline};

// Re-export IPI types and functions
#[cfg(target_arch = "x86_64")]
pub use x86_64::{get_ticks, now_ns, send_ipi, set_tlb_shootdown_addr, IpiKind};

#[cfg(target_arch = "aarch64")]
pub use aarch64::{get_ticks, now_ns, send_ipi, set_tlb_shootdown_addr, IpiKind};

// Re-export IOAPIC dynamic IRQ routing
#[cfg(target_arch = "x86_64")]
pub use x86_64::{ioapic_unmask, ioapic_unmask_level, ioapic_mask};

#[cfg(target_arch = "aarch64")]
pub use aarch64::{ioapic_unmask, ioapic_unmask_level, ioapic_mask};

// Re-export FPU sub-module (lazy switching, context switch hooks)
#[cfg(target_arch = "x86_64")]
pub use x86_64::fpu;

#[cfg(target_arch = "aarch64")]
pub use aarch64::fpu;

// Re-export CPUID feature detection sub-module
#[cfg(target_arch = "x86_64")]
pub use x86_64::cpuid;

#[cfg(target_arch = "aarch64")]
pub use aarch64::cpuid;

// Re-export SMAP sub-module (stac/clac, UserAccessGuard)
#[cfg(target_arch = "x86_64")]
pub use x86_64::smap;

#[cfg(target_arch = "aarch64")]
pub use aarch64::smap;

/// Initialize architecture-specific subsystems
pub fn init(boot_info: Option<&crate::ParsedBootInfo>) {
    #[cfg(target_arch = "x86_64")]
    x86_64::init(boot_info);
    #[cfg(target_arch = "aarch64")]
    aarch64::init(boot_info);
}

/// Initialize SMP (start Application Processors)
pub fn init_smp(boot_info: Option<&crate::ParsedBootInfo>) {
    #[cfg(target_arch = "x86_64")]
    x86_64::init_smp(boot_info);
    #[cfg(target_arch = "aarch64")]
    aarch64::init_smp(boot_info);
}

/// Remove bootloader identity mapping after all APs have booted.
pub fn clear_boot_identity_map() {
    #[cfg(target_arch = "x86_64")]
    x86_64::paging::clear_boot_identity_map();
    #[cfg(target_arch = "aarch64")]
    aarch64::clear_boot_identity_map();
}

/// Halt the CPU until next interrupt
pub fn halt() {
    #[cfg(target_arch = "x86_64")]
    x86_64::halt();
    #[cfg(target_arch = "aarch64")]
    aarch64::halt();
}

/// Enable interrupts
pub fn sti() {
    #[cfg(target_arch = "x86_64")]
    x86_64::sti();
    #[cfg(target_arch = "aarch64")]
    aarch64::sti();
}

/// Disable interrupts
pub fn cli() {
    #[cfg(target_arch = "x86_64")]
    x86_64::cli();
    #[cfg(target_arch = "aarch64")]
    aarch64::cli();
}

/// Start timer interrupts
///
/// Called after scheduler is initialized to begin timer ticks.
/// This is separate from init() because the timer must not start
/// until the idle thread is ready to handle interrupts.
pub fn start_timer() {
    #[cfg(target_arch = "x86_64")]
    x86_64::start_timer();
    #[cfg(target_arch = "aarch64")]
    aarch64::start_timer();
}

/// Perform system shutdown (power off). Does not return.
pub fn shutdown() -> ! {
    #[cfg(target_arch = "x86_64")]
    x86_64::shutdown();
    #[cfg(target_arch = "aarch64")]
    aarch64::shutdown();
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    loop {
        halt();
    }
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
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Caller ensures port access is valid (panics on aarch64)
    unsafe {
        aarch64::outb(port, value);
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
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Returns 0 on aarch64 (no I/O ports)
    unsafe {
        return aarch64::inb(port);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    0
}
