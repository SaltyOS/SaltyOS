//! AArch64 architecture support for SaltyOS
//!
//! SPDX-License-Identifier: GPL-2.0-only

pub mod boot;
pub mod context;
pub mod cpu;
pub mod exceptions;
pub mod fpu;
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

/// Context switch between threads.
///
/// Delegates to the `context` module which saves callee-saved registers
/// on the old thread's stack and restores from the new thread's stack.
///
/// # Safety
/// Both pointers must point to valid, initialized `ThreadContext` structures.
pub unsafe fn context_switch(
    old_context: *mut crate::sched::thread::ThreadContext,
    new_context: *const crate::sched::thread::ThreadContext,
) {
    // SAFETY: Caller guarantees both pointers are valid ThreadContext.
    unsafe { context::context_switch(old_context, new_context); }
}

/// Trampoline to enter usermode for newly created threads.
///
/// Delegates to the `context` module which reads the thread's saved
/// ELR_EL1, SP_EL0, SPSR_EL1 from the TCB, loads TTBR0, zeroes all
/// GPRs, and executes `eret` to enter EL0.
///
/// # Safety
/// Must only be used as the initial entry point for a newly scheduled thread.
pub unsafe extern "C" fn usermode_trampoline() -> ! {
    // SAFETY: Caller guarantees this is a newly scheduled thread with
    // valid TCB fields.
    unsafe { context::usermode_trampoline(); }
}

/// Initialize architecture-specific subsystems
///
/// Init order:
/// 1. PL011 UART (serial output)
/// 2. Exception vector table (VBAR_EL1)
/// 3. GICv3 (distributor + BSP redistributor + CPU interface)
/// 4. Generic Timer (configure, but do not start yet)
/// 5. Memory management (frame allocator)
/// 6. Paging (direct physical map)
/// 7. GIC MMIO remap to direct map
/// 8. Frame bitmap remap + per-frame arrays
pub fn init(boot_info: Option<&crate::ParsedBootInfo>) {
    // Initialize PL011 UART for serial output
    pl011::init();

    // Install exception vector table (must be early so any faults are caught)
    exceptions::init();

    // Initialize GICv3 (uses identity-mapped MMIO during early boot)
    gic::init();

    // Configure the generic timer (reads frequency, does not start ticking)
    timer::init();

    // Initialize memory management (frame allocator needed by paging::init())
    if let Some(info) = boot_info {
        crate::mm::init(info);
    }

    // Initialize paging (direct physical map)
    paging::init();

    // Remap GIC MMIO from identity-map to direct-map addresses
    gic::remap_to_direct_map();

    // Switch frame bitmap pointer from identity map (TTBR0) to direct
    // physical map (TTBR1). Must happen after paging::init() creates the
    // direct map and before TTBR0 identity map is cleared.
    crate::mm::remap_frame_bitmap();

    // Allocate per-frame tracking arrays now that direct map covers all RAM.
    crate::mm::init_per_frame_arrays();

    // Initialize FPU lazy switching (trap NEON/FP access from EL0)
    fpu::init();

    crate::serial_puts("[ARCH] AArch64 subsystems initialized\n");
}

/// Initialize SMP (stub for Phase 1)
pub fn init_smp(_boot_info: Option<&crate::ParsedBootInfo>) {
    // TODO: Phase 4 — PSCI CPU_ON
}

/// Remove bootloader identity mapping (L0[0] via TTBR0).
pub fn clear_boot_identity_map() {
    paging::clear_boot_identity_map();
}

/// Start periodic timer interrupts (10 ms tick via PPI 30).
pub fn start_timer() {
    timer::start();
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

// CPUID-equivalent module: reports RNDR (hardware RNG) availability
pub mod cpuid {
    /// Check if RNDR instruction is available (ARMv8.5-RNG).
    ///
    /// Reads ID_AA64ISAR0_EL1.RNDR (bits 63:60); value >= 1 means supported.
    pub fn has_rdrand() -> bool {
        let isar0: u64;
        // SAFETY: Reading ID_AA64ISAR0_EL1 is always safe from EL1.
        unsafe {
            core::arch::asm!("mrs {}, ID_AA64ISAR0_EL1", out(reg) isar0, options(nomem, nostack));
        }
        ((isar0 >> 60) & 0xF) >= 1
    }

    /// RNDR serves the same purpose as both RDRAND and RDSEED on x86.
    pub fn has_rdseed() -> bool {
        has_rdrand()
    }
}

// SMAP-equivalent module: Privileged Access Never (PAN) on aarch64
pub mod smap {
    /// Initialize PAN if supported by the processor.
    ///
    /// Checks ID_AA64MMFR1_EL1.PAN (bits 23:20) and clears SCTLR_EL1.SPAN
    /// so that PAN is automatically set on exception entry from EL0.
    pub fn init() {
        let mmfr1: u64;
        // SAFETY: Reading ID_AA64MMFR1_EL1 is always safe from EL1.
        unsafe {
            core::arch::asm!("mrs {}, ID_AA64MMFR1_EL1", out(reg) mmfr1, options(nomem, nostack));
        }
        if ((mmfr1 >> 20) & 0xF) >= 1 {
            // PAN is supported — clear SPAN so PAN is auto-set on exception entry
            let mut sctlr: u64;
            // SAFETY: Reading SCTLR_EL1 is safe from EL1.
            unsafe {
                core::arch::asm!("mrs {}, SCTLR_EL1", out(reg) sctlr, options(nomem, nostack));
            }
            sctlr &= !(1u64 << 23); // Clear SPAN (bit 23)
            // SAFETY: Writing SCTLR_EL1 to enable PAN auto-set is safe.
            // ISB ensures the change takes effect before subsequent instructions.
            unsafe {
                core::arch::asm!("msr SCTLR_EL1, {}", in(reg) sctlr, options(nomem, nostack));
                core::arch::asm!("isb", options(nomem, nostack));
            }
        }
    }

    /// RAII guard that temporarily disables PAN to allow kernel access
    /// to user memory. PAN is re-enabled when the guard is dropped.
    pub struct UserAccessGuard;

    impl UserAccessGuard {
        /// Clear PAN to allow user memory access from EL1.
        pub fn new() -> Self {
            // SAFETY: Clearing PAN temporarily allows EL1 to access
            // user-mapped pages. The guard's Drop impl will re-enable PAN.
            unsafe {
                core::arch::asm!("msr PAN, #0", options(nomem, nostack));
            }
            UserAccessGuard
        }
    }

    impl Drop for UserAccessGuard {
        fn drop(&mut self) {
            // SAFETY: Setting PAN blocks EL1 access to user-mapped pages,
            // restoring the default protection.
            unsafe {
                core::arch::asm!("msr PAN, #1", options(nomem, nostack));
            }
        }
    }
}
