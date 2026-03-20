//! AArch64 architecture support for SaltyOS
//!
//! SPDX-License-Identifier: GPL-2.0-only

pub mod boot;
pub mod cpu;
pub mod pl011;
pub mod paging;
pub mod pan;
pub mod gic;
pub mod timer;
pub mod psci;

/// Maximum supported CPUs
pub const MAX_CPUS: usize = 16;

// --- IRQ save/restore (DAIF manipulation) ---

/// Save interrupt state and disable interrupts (mask DAIF.I)
#[inline(always)]
pub fn save_irq_disable() -> u64 {
    let daif: u64;
    // SAFETY: Reading DAIF is always safe
    unsafe {
        core::arch::asm!("mrs {}, DAIF", out(reg) daif, options(nomem, nostack));
    }
    // SAFETY: Masking IRQ via DAIFSet is always safe
    unsafe {
        core::arch::asm!("msr DAIFSet, #0x2", options(nomem, nostack));
    }
    daif
}

/// Restore interrupt state from saved DAIF
///
/// # Safety
/// `saved` must be a value previously returned by `save_irq_disable()`.
#[inline(always)]
pub unsafe fn restore_irq(saved: u64) {
    // SAFETY: Caller guarantees saved is a valid DAIF value
    unsafe {
        core::arch::asm!("msr DAIF, {}", in(reg) saved, options(nomem, nostack));
    }
}

/// Enable interrupts (unmask DAIF.I)
#[inline(always)]
pub fn sti() {
    // SAFETY: Unmasking IRQ is safe when called from kernel context
    unsafe {
        core::arch::asm!("msr DAIFClr, #0x2", options(nomem, nostack));
    }
}

/// Disable interrupts (mask DAIF.I)
#[inline(always)]
pub fn cli() {
    // SAFETY: Masking IRQ is always safe
    unsafe {
        core::arch::asm!("msr DAIFSet, #0x2", options(nomem, nostack));
    }
}

/// Halt the CPU until next interrupt (WFI)
#[inline(always)]
pub fn halt() {
    // SAFETY: WFI is a hint instruction, always safe
    unsafe {
        core::arch::asm!("wfi", options(nomem, nostack));
    }
}

/// I/O port output (not available on aarch64 — panics)
///
/// # Safety
/// This function always panics on aarch64.
#[inline(always)]
pub unsafe fn outb(_port: u16, _value: u8) {
    panic!("outb: I/O ports not available on aarch64");
}

/// I/O port input (not available on aarch64 — returns 0)
///
/// # Safety
/// This function always returns 0 on aarch64.
#[inline(always)]
pub unsafe fn inb(_port: u16) -> u8 {
    0
}

// --- Per-CPU data ---

/// Get current CPU ID (from MPIDR_EL1)
pub fn current_cpu() -> usize {
    let mpidr: u64;
    // SAFETY: Reading MPIDR_EL1 is always safe
    unsafe {
        core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) mpidr, options(nomem, nostack));
    }
    // Aff0 field (bits 7:0) gives the CPU number on most platforms
    (mpidr & 0xFF) as usize
}

/// Next invocation sequence number (stub — returns 0 for Phase 1)
pub fn next_invoke_seq() -> u64 {
    0
}

/// Current invocation sequence number (stub — returns 0 for Phase 1)
pub fn current_invoke_seq() -> u64 {
    0
}

/// Set kernel stack for current CPU (stub for Phase 1)
pub fn set_kernel_stack(_stack_top: u64) {
    // TODO: Phase 3 — set SP_EL1 or TPIDR_EL1-based kernel stack
}

/// Set TSS RSP0 equivalent (stub for Phase 1, no TSS on aarch64)
pub fn set_tss_rsp0(_stack_top: u64) {
    // No TSS on aarch64 — exception entry uses SP_EL1
}

/// Read thread-local base (TPIDR_EL0)
pub fn read_fs_base() -> u64 {
    let val: u64;
    // SAFETY: Reading TPIDR_EL0 is always safe
    unsafe {
        core::arch::asm!("mrs {}, TPIDR_EL0", out(reg) val, options(nomem, nostack));
    }
    val
}

/// Write thread-local base (TPIDR_EL0)
pub fn write_fs_base(val: u64) {
    // SAFETY: Writing TPIDR_EL0 is safe from kernel context
    unsafe {
        core::arch::asm!("msr TPIDR_EL0, {}", in(reg) val, options(nomem, nostack));
    }
}

/// Generate a stack canary value
pub fn generate_stack_canary() -> u64 {
    // Try RNDR (ARMv8.5-RNG) first, fall back to CNTPCT_EL0
    let val: u64;
    let ok: u64;
    // SAFETY: mrs RNDR may fail with NZCV flags set
    unsafe {
        core::arch::asm!(
            "mrs {val}, S3_3_C2_C4_0",  // RNDR
            "cset {ok}, ne",
            val = out(reg) val,
            ok = out(reg) ok,
            options(nomem, nostack),
        );
    }
    if ok != 0 {
        return val;
    }
    // Fallback: CNTPCT_EL0 (not cryptographically random, but usable)
    let fallback: u64;
    // SAFETY: Reading CNTPCT is always safe
    unsafe {
        core::arch::asm!("mrs {}, CNTPCT_EL0", out(reg) fallback, options(nomem, nostack));
    }
    fallback
}

/// Set per-CPU stack canary (stub for Phase 1)
pub fn set_per_cpu_canary(_canary: u64) {
    // TODO: Phase 3 — store in TPIDR_EL1
}

/// IPI kind enumeration
#[derive(Debug, Clone, Copy)]
pub enum IpiKind {
    Reschedule,
    TlbShootdown,
    Halt,
}

/// Get timer tick count (CNTPCT_EL0)
pub fn get_ticks() -> u64 {
    let val: u64;
    // SAFETY: Reading CNTPCT_EL0 is always safe from EL1
    unsafe {
        core::arch::asm!("mrs {}, CNTPCT_EL0", out(reg) val, options(nomem, nostack));
    }
    val
}

/// Get current time in nanoseconds
pub fn now_ns() -> u64 {
    let freq: u64;
    // SAFETY: Reading CNTFRQ_EL0 is always safe
    unsafe {
        core::arch::asm!("mrs {}, CNTFRQ_EL0", out(reg) freq, options(nomem, nostack));
    }
    if freq == 0 {
        return 0;
    }
    let ticks = get_ticks();
    // Convert ticks to nanoseconds: ticks * 1_000_000_000 / freq
    // Use 128-bit math to avoid overflow
    ((ticks as u128 * 1_000_000_000u128) / freq as u128) as u64
}

/// Send IPI to another CPU (stub for Phase 1)
pub fn send_ipi(_target_cpu: usize, _kind: IpiKind) {
    // TODO: Phase 4 — GICv3 SGI
}

/// Set TLB shootdown address (stub for Phase 1)
pub fn set_tlb_shootdown_addr(_addr: usize) {
    // TODO: Phase 4 — SMP TLB shootdown
}

/// IOAPIC unmask (not applicable on aarch64)
pub fn ioapic_unmask(_irq: u32, _cpu: u8) {}
/// IOAPIC unmask level-triggered (not applicable on aarch64)
pub fn ioapic_unmask_level(_irq: u32, _cpu: u8) {}
/// IOAPIC mask (not applicable on aarch64)
pub fn ioapic_mask(_irq: u32) {}

/// Context switch between threads (stub for Phase 1)
///
/// # Safety
/// Both pointers must be valid stack pointers.
pub unsafe extern "C" fn context_switch(_old_sp: *mut u64, _new_sp: u64) {
    // TODO: Phase 3 — save/restore callee-saved x19-x28, x29, x30, SP
}

/// Trampoline to enter usermode (stub for Phase 1)
///
/// # Safety
/// All parameters must be valid addresses.
pub unsafe extern "C" fn usermode_trampoline() {
    // TODO: Phase 3 — set ELR_EL1, SPSR_EL1, SP_EL0, eret
    loop {
        // SAFETY: WFI is safe
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
    }
}

/// Initialize architecture-specific subsystems
pub fn init(boot_info: Option<&crate::ParsedBootInfo>) {
    // Initialize PL011 UART for serial output
    pl011::init();

    // Initialize GIC (stub for Phase 1)
    // gic::init();

    // Initialize paging (stub for Phase 1)
    if let Some(info) = boot_info {
        let _ = info; // TODO: Phase 2 — frame allocator + page tables
    }

    crate::serial_puts("[ARCH] AArch64 subsystems initialized\n");
}

/// Initialize SMP (stub for Phase 1)
pub fn init_smp(_boot_info: Option<&crate::ParsedBootInfo>) {
    // TODO: Phase 4 — PSCI CPU_ON
}

/// Remove bootloader identity mapping (stub for Phase 1)
pub fn clear_boot_identity_map() {
    // TODO: Phase 2 — clear TTBR0 identity map
}

/// Start timer interrupts (stub for Phase 1)
pub fn start_timer() {
    // TODO: Phase 3 — ARM Generic Timer
}

/// ACPI S5 shutdown (stub — uses PSCI SYSTEM_OFF)
pub fn shutdown() -> ! {
    // PSCI SYSTEM_OFF (SMC #0, function_id = 0x84000008)
    // SAFETY: PSCI SYSTEM_OFF does not return
    unsafe {
        core::arch::asm!(
            "mov x0, #0x84000008",
            "smc #0",
            options(noreturn, nomem, nostack),
        );
    }
}

// FPU module (stub for Phase 1)
pub mod fpu {
    pub fn init() {}
    pub fn save(_thread: &crate::sched::thread::Tcb) {}
    pub fn restore(_thread: &crate::sched::thread::Tcb) {}
    pub fn handle_trap() {}
}

// CPUID-equivalent module (stub for Phase 1)
pub mod cpuid {
    pub fn has_rdrand() -> bool { false }
    pub fn has_rdseed() -> bool { false }
}

// SMAP-equivalent module (PAN on aarch64)
pub mod smap {
    pub fn init() {}

    pub struct UserAccessGuard;
    impl UserAccessGuard {
        pub fn new() -> Self {
            // TODO: Phase 2 — clear PAN bit
            UserAccessGuard
        }
    }
    impl Drop for UserAccessGuard {
        fn drop(&mut self) {
            // TODO: Phase 2 — set PAN bit
        }
    }
}
