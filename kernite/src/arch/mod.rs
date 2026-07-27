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
#[allow(unused_imports)]
pub use x86_64::current_invoke_seq;
#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    MAX_CPUS, current_cpu, diagnostic_current_cpu, generate_stack_canary, get_kernel_stack,
    irqs_disabled, next_invoke_seq, per_cpu_ready, read_fs_base, restore_irq, save_irq_disable,
    set_kernel_stack, set_per_cpu_canary, set_tss_rsp0, write_abi_tp_base, write_fs_base,
};

#[cfg(target_arch = "aarch64")]
#[allow(unused_imports)]
pub use aarch64::current_invoke_seq;
#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    MAX_CPUS, current_cpu, diagnostic_current_cpu, generate_stack_canary, get_kernel_stack,
    irqs_disabled, next_invoke_seq, per_cpu_ready, read_fs_base, restore_irq, save_irq_disable,
    set_kernel_stack, set_per_cpu_canary, set_tss_rsp0, write_abi_tp_base, write_fs_base,
};

// Re-export context switch interface
#[cfg(target_arch = "x86_64")]
pub use x86_64::{context_switch, usermode_trampoline};

#[cfg(target_arch = "aarch64")]
pub use aarch64::context_switch;

// Re-export IPI types and functions
#[cfg(target_arch = "x86_64")]
pub use x86_64::{IpiKind, now_ns, send_ipi, set_tlb_shootdown_addr};

#[cfg(target_arch = "aarch64")]
pub use aarch64::{IpiKind, now_ns, send_ipi, set_tlb_shootdown_addr};

// Re-export IOAPIC dynamic IRQ routing
#[cfg(target_arch = "x86_64")]
pub use x86_64::{ioapic_mask, ioapic_unmask_level};

#[cfg(target_arch = "aarch64")]
pub use aarch64::{ioapic_mask, ioapic_unmask_level};

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

// Re-export user memory access control (SMAP on x86_64, PAN on aarch64)
#[cfg(target_arch = "x86_64")]
pub use x86_64::uaccess;

#[cfg(target_arch = "aarch64")]
pub use aarch64::uaccess;

// Re-export architecture RNG instruction probes through a common path.
#[cfg(target_arch = "x86_64")]
pub use x86_64::random;

#[cfg(target_arch = "aarch64")]
pub use aarch64::random;

/// Initialize architecture-specific subsystems
pub fn init(boot_info: Option<&crate::init::bootinfo::ParsedBootInfo>) {
    #[cfg(target_arch = "x86_64")]
    x86_64::init(boot_info);
    #[cfg(target_arch = "aarch64")]
    aarch64::init(boot_info);
}

/// Initialize SMP (start Application Processors)
pub fn init_smp(boot_info: Option<&crate::init::bootinfo::ParsedBootInfo>) {
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

/// Capture architecture-specific context for a generic panic path.
pub(crate) fn capture_current_panic_context() -> crate::kernel::stacktrace::ArchPanicContext {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::capture_current_panic_context()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::capture_current_panic_context()
    }
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

/// Print architecture-specific detail for a generic panic that did not enter
/// through an exception/trap frame.
pub fn dump_panic_detail() {
    #[cfg(target_arch = "x86_64")]
    x86_64::dump_panic_detail();
    #[cfg(target_arch = "aarch64")]
    aarch64::dump_panic_detail();
}

/// Disable interrupts and halt the CPU forever. Used by fail-fast paths
/// that cannot recover (core service self-fault, kernel-mode fault on
/// the boot CPU). Does not return; never wakes from interrupt because
/// interrupts are disabled before the halt loop.
pub fn system_halt() -> ! {
    cli();
    loop {
        halt();
    }
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

/// Perform system reboot (warm reset). Does not return.
pub fn reboot() -> ! {
    #[cfg(target_arch = "x86_64")]
    x86_64::reboot();
    #[cfg(target_arch = "aarch64")]
    aarch64::reboot();
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    loop {
        halt();
    }
}

pub fn publish_page_table_page(table_phys: crate::mm::PhysAddr) {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = table_phys;
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::publish_page_table_page(table_phys);
    }
}

pub fn sync_user_page_before_unmap(vaddr: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        let _ = vaddr;
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::sync_user_page_before_unmap(vaddr);
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

/// Output 16-bit word to I/O port
///
/// # Safety
/// Caller must ensure the port access is valid.
#[inline(always)]
pub unsafe fn outw(port: u16, value: u16) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        x86_64::outw(port, value);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        aarch64::outw(port, value);
    }
}

/// Input 16-bit word from I/O port
///
/// # Safety
/// Caller must ensure the port access is valid.
#[inline(always)]
pub unsafe fn inw(port: u16) -> u16 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        return x86_64::inw(port);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        return aarch64::inw(port);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    0
}

/// Output 32-bit dword to I/O port
///
/// # Safety
/// Caller must ensure the port access is valid.
#[inline(always)]
pub unsafe fn outl(port: u16, value: u32) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        x86_64::outl(port, value);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        aarch64::outl(port, value);
    }
}

/// Input 32-bit dword from I/O port
///
/// # Safety
/// Caller must ensure the port access is valid.
#[inline(always)]
pub unsafe fn inl(port: u16) -> u32 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        return x86_64::inl(port);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        return aarch64::inl(port);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    0
}
