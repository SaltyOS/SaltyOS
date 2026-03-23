//! AArch64 architecture support for SaltyOS
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub mod ap_boot;
pub mod boot;
pub mod context;
pub mod cpu;
pub mod exceptions;
pub mod fpu;
pub mod pl011;
pub mod paging;
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

/// Next invocation sequence number for the current CPU.
pub fn next_invoke_seq() -> u64 {
    cpu::next_invoke_seq()
}

/// Current invocation sequence number for the current CPU.
pub fn current_invoke_seq() -> u64 {
    cpu::current_invoke_seq()
}

/// Set kernel stack for current CPU (via TPIDR_EL1 per-CPU data).
pub fn set_kernel_stack(stack_top: u64) {
    cpu::set_kernel_stack(stack_top);
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
    // Try RNDR (ARMv8.5-RNG) first when advertised by the CPU. On
    // systems without FEAT_RNG, executing RNDR itself raises an
    // undefined-instruction exception instead of returning failure.
    if cpuid::has_rdrand() {
        let val: u64;
        let ok: u64;
        // SAFETY: FEAT_RNG support has been checked above, so RNDR is a
        // valid system register access here. NZCV flags report success.
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
    }
    // Fallback: CNTPCT_EL0 (not cryptographically random, but usable)
    let fallback: u64;
    // SAFETY: Reading CNTPCT is always safe
    unsafe {
        core::arch::asm!("mrs {}, CNTPCT_EL0", out(reg) fallback, options(nomem, nostack));
    }
    fallback
}

/// Set per-CPU stack canary (via TPIDR_EL1 per-CPU data).
pub fn set_per_cpu_canary(canary: u64) {
    cpu::set_per_cpu_canary(canary);
}

/// IPI kind enumeration (must match x86_64 variants)
#[derive(Debug, Clone, Copy)]
pub enum IpiKind {
    VSpaceTeardown = 0,
    Reschedule = 1,
    TlbShootdown = 8,
    TlbShootdownAll = 9,
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

// ---------------------------------------------------------------------------
// IPI via GICv3 SGI
// ---------------------------------------------------------------------------

/// SGI INTID allocation for IPI kinds.
const SGI_RESCHEDULE: u32 = 0;
const SGI_TLB_SHOOTDOWN: u32 = 1;
const SGI_TLB_SHOOTDOWN_ALL: u32 = 2;
const SGI_VSPACE_TEARDOWN: u32 = 3;

/// Send an IPI to another CPU via GICv3 Software Generated Interrupt.
pub fn send_ipi(target_cpu: usize, kind: IpiKind) {
    let intid = match kind {
        IpiKind::Reschedule => SGI_RESCHEDULE,
        IpiKind::TlbShootdown => SGI_TLB_SHOOTDOWN,
        IpiKind::TlbShootdownAll => SGI_TLB_SHOOTDOWN_ALL,
        IpiKind::VSpaceTeardown => SGI_VSPACE_TEARDOWN,
    };
    gic::send_sgi(target_cpu, intid);
}

// ---------------------------------------------------------------------------
// TLB shootdown infrastructure
// ---------------------------------------------------------------------------

/// Per-CPU TLB shootdown target address.
static TLB_SHOOTDOWN_ADDR: [AtomicU64; MAX_CPUS] =
    [const { AtomicU64::new(0) }; MAX_CPUS];

/// Set the TLB shootdown address for a remote CPU.
///
/// The remote CPU's IPI handler reads this address and invalidates the
/// corresponding TLB entry.
pub fn set_tlb_shootdown_addr(cpu_id: usize, addr: u64) {
    if cpu_id < MAX_CPUS {
        TLB_SHOOTDOWN_ADDR[cpu_id].store(addr, Ordering::Release);
    }
}

/// Read and clear the TLB shootdown address for the current CPU.
pub fn take_tlb_shootdown_addr(cpu_id: usize) -> u64 {
    if cpu_id < MAX_CPUS {
        TLB_SHOOTDOWN_ADDR[cpu_id].swap(0, Ordering::AcqRel)
    } else {
        0
    }
}

/// Enable a GIC interrupt (equivalent of IOAPIC unmask on x86_64).
pub fn ioapic_unmask(irq: u32) {
    gic::enable_irq(irq);
}
/// Enable a GIC interrupt (level-triggered — same as edge on GIC).
pub fn ioapic_unmask_level(irq: u32) {
    gic::enable_irq(irq);
}
/// Disable a GIC interrupt (equivalent of IOAPIC mask on x86_64).
pub fn ioapic_mask(irq: u32) {
    gic::disable_irq(irq);
}

// ---------------------------------------------------------------------------
// PCI I/O port emulation via MMIO (QEMU virt PCI I/O window)
// ---------------------------------------------------------------------------

/// QEMU virt PCI I/O window physical address (64 KB).
const PCI_IO_PHYS_BASE: u64 = 0x3eff_0000;
/// Number of 4 KB pages in the PCI I/O window.
const PCI_IO_PAGES: u64 = 16;

/// Virtual base of the mapped PCI I/O window (set during pci_io_init).
static mut PCI_IO_VIRT_BASE: u64 = 0;

/// Map the PCI I/O window into kernel virtual memory during boot.
fn pci_io_init() {
    let mut virt = 0u64;
    for i in 0..PCI_IO_PAGES {
        // SAFETY: Boot-time single-threaded, paging::init() has run.
        let v = unsafe { paging::map_mmio_page(PCI_IO_PHYS_BASE + i * 4096) };
        if i == 0 {
            virt = v;
        }
    }
    // SAFETY: Single-threaded boot context, no concurrent access.
    unsafe { *(&raw mut PCI_IO_VIRT_BASE) = virt; }
}

/// Read 8 bits from PCI I/O port `port`.
///
/// # Safety
/// Caller must ensure `port` is within the mapped I/O window.
#[inline]
pub unsafe fn pci_io_read8(port: u16) -> u8 {
    let addr = unsafe { *(&raw const PCI_IO_VIRT_BASE) } + port as u64;
    // SAFETY: Address is within mapped PCI I/O window, volatile for device semantics.
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

/// Write 8 bits to PCI I/O port `port`.
///
/// # Safety
/// Caller must ensure `port` is within the mapped I/O window.
#[inline]
pub unsafe fn pci_io_write8(port: u16, val: u8) {
    let addr = unsafe { *(&raw const PCI_IO_VIRT_BASE) } + port as u64;
    // SAFETY: Address is within mapped PCI I/O window, volatile for device semantics.
    unsafe { core::ptr::write_volatile(addr as *mut u8, val); }
}

/// Read 16 bits from PCI I/O port `port`.
///
/// # Safety
/// Caller must ensure `port` is within the mapped I/O window.
#[inline]
pub unsafe fn pci_io_read16(port: u16) -> u16 {
    let addr = unsafe { *(&raw const PCI_IO_VIRT_BASE) } + port as u64;
    // SAFETY: Address is within mapped PCI I/O window, volatile for device semantics.
    unsafe { core::ptr::read_volatile(addr as *const u16) }
}

/// Write 16 bits to PCI I/O port `port`.
///
/// # Safety
/// Caller must ensure `port` is within the mapped I/O window.
#[inline]
pub unsafe fn pci_io_write16(port: u16, val: u16) {
    let addr = unsafe { *(&raw const PCI_IO_VIRT_BASE) } + port as u64;
    // SAFETY: Address is within mapped PCI I/O window, volatile for device semantics.
    unsafe { core::ptr::write_volatile(addr as *mut u16, val); }
}

/// Read 32 bits from PCI I/O port `port`.
///
/// # Safety
/// Caller must ensure `port` is within the mapped I/O window.
#[inline]
pub unsafe fn pci_io_read32(port: u16) -> u32 {
    let addr = unsafe { *(&raw const PCI_IO_VIRT_BASE) } + port as u64;
    // SAFETY: Address is within mapped PCI I/O window, volatile for device semantics.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write 32 bits to PCI I/O port `port`.
///
/// # Safety
/// Caller must ensure `port` is within the mapped I/O window.
#[inline]
pub unsafe fn pci_io_write32(port: u16, val: u32) {
    let addr = unsafe { *(&raw const PCI_IO_VIRT_BASE) } + port as u64;
    // SAFETY: Address is within mapped PCI I/O window, volatile for device semantics.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val); }
}

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
/// 3. Memory management (frame allocator)
/// 4. Paging (direct physical map + sparse MMIO windows)
/// 5. UART/GIC MMIO remap to higher-half kernel addresses
/// 6. GICv3 (distributor + BSP redistributor + CPU interface)
/// 7. Generic Timer (configure, but do not start yet)
/// 8. Frame bitmap remap + per-frame arrays
pub fn init(boot_info: Option<&crate::ParsedBootInfo>) {
    // Initialize PL011 UART for serial output
    pl011::init();

    // Install exception vector table (must be early so any faults are caught)
    exceptions::init();

    // Initialize BSP per-CPU data (TPIDR_EL1). Must be early so per-CPU
    // field accessors work for the rest of boot.
    cpu::init_bsp();

    // Initialize memory management (frame allocator needed by paging::init())
    if let Some(info) = boot_info {
        crate::mm::init(info);
    }

    // Initialize paging (direct physical map)
    paging::init();

    // Remap always-on MMIO from boot identity addresses to kernel mappings.
    pl011::remap_to_direct_map();
    gic::remap_to_direct_map();

    // Map QEMU virt PCI I/O window so IoPort operations can use MMIO.
    pci_io_init();

    // Initialize GICv3 after higher-half MMIO mappings exist.
    gic::init();

    // Configure the generic timer (reads frequency, does not start ticking)
    timer::init();

    // Switch frame bitmap pointer from identity map (TTBR0) to direct
    // physical map (TTBR1). Must happen after paging::init() creates the
    // direct map and before TTBR0 identity map is cleared.
    crate::mm::remap_frame_bitmap();

    // Allocate per-frame tracking arrays now that direct map covers all RAM.
    crate::mm::init_per_frame_arrays();

    // Enable PAN runtime tracking before the first EL0 transition.
    uaccess::init();

    // Initialize FPU lazy switching (trap NEON/FP access from EL0)
    fpu::init();

    crate::serial_puts("[ARCH] AArch64 subsystems initialized\n");
}

/// Initialize SMP — bring up Application Processors via PSCI CPU_ON.
///
/// For each possible AP (cpu_id 1..MAX_CPUS):
///   1. Allocates a per-CPU kernel stack
///   2. Writes the AP mailbox with system register values from the BSP
///   3. Calls PSCI CPU_ON to start the AP at the trampoline physical address
///   4. Waits for the AP to signal ready
///
/// Stops probing when PSCI returns an error (non-existent CPU).
pub fn init_smp(boot_info: Option<&crate::ParsedBootInfo>) {
    let info = match boot_info {
        Some(i) => i,
        None => {
            crate::serial_puts("[SMP] No boot info, skipping SMP init\n");
            return;
        }
    };

    // Compute AP trampoline physical address.
    // The kernel is linked at VA 0 but loaded at kernel_phys_base and
    // relocated to kernel_virt_base. Symbol addresses are in the virtual
    // address space, so we convert back to physical.
    unsafe extern "C" {
        static _ap_trampoline_start: u8;
    }
    let trampoline_virt = core::ptr::addr_of!(_ap_trampoline_start) as u64;
    let trampoline_phys = if info.kernel_virt_base != 0 {
        trampoline_virt - info.kernel_virt_base + info.kernel_phys_base
    } else {
        // Identity-mapped: virt == phys
        trampoline_virt
    };

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[SMP] Trampoline phys=");
        s.hex(trampoline_phys);
        s.puts(" virt=");
        s.hex(trampoline_virt);
        s.putc(b'\n');
    }

    // Read BSP system register values for the AP mailbox.
    let mair = paging::read_mair();
    let tcr = paging::read_tcr();
    let sctlr = paging::read_sctlr();
    let ttbr0 = paging::read_cr3();    // Identity map root
    let ttbr1 = paging::read_ttbr1();  // Kernel root
    let entry_virt = ap_boot::ap_entry as *const () as u64;

    // Map GICR MMIO pages for all potential APs before starting them.
    gic::remap_ap_gicr(MAX_CPUS);

    let mut ap_count = 0u32;

    for cpu_id in 1..MAX_CPUS {
        // Allocate per-CPU kernel stack (16 KB = 4 pages).
        const STACK_PAGES: usize = 4;
        const STACK_SIZE: u64 = STACK_PAGES as u64 * 4096;

        let stack_phys = match crate::mm::pmm_alloc_contiguous(STACK_PAGES) {
            Some(p) => p,
            None => {
                crate::serial_puts("[SMP] Failed to allocate AP kernel stack\n");
                break;
            }
        };
        let stack_top = crate::mm::phys_to_virt(stack_phys) + STACK_SIZE;

        // Clear synchronization flags for this AP.
        cpu::clear_ap_claimed(cpu_id);
        ap_boot::clear_ap_ready(cpu_id);

        // Write the AP mailbox. Only one AP is started at a time.
        // SAFETY: Single writer (BSP), single reader (the AP being started).
        // The DSB SY below ensures the writes are visible before CPU_ON.
        unsafe {
            let mb = &raw mut boot::AP_MAILBOX;
            (*mb).stack_top = stack_top;
            (*mb).mair = mair;
            (*mb).tcr = tcr;
            (*mb).sctlr = sctlr;
            (*mb).ttbr0 = ttbr0;
            (*mb).ttbr1 = ttbr1;
            (*mb).entry_virt = entry_virt;
        }

        // Clean the mailbox cache lines to Point of Coherency (PoC).
        // The AP starts with MMU off, reading from physical memory directly.
        // Without cache clean, the AP may see stale (zero) data because
        // the BSP's writes sit in the L1/L2 cache.
        // SAFETY: DC CIVAC and DSB are always safe from EL1.
        unsafe {
            let mb_addr = &raw const boot::AP_MAILBOX as u64;
            let mb_size = core::mem::size_of::<boot::ApMailbox>() as u64;
            let mut addr = mb_addr;
            while addr < mb_addr + mb_size {
                core::arch::asm!(
                    "dc civac, {0}",
                    in(reg) addr,
                    options(nostack),
                );
                addr += 64; // Cache line size
            }
            core::arch::asm!("dsb sy", "isb", options(nomem, nostack));
        }

        {
            let s = crate::SerialGuard::acquire();
            s.puts("[SMP] Starting AP cpu_id=");
            s.dec(cpu_id as u64);
            s.putc(b'\n');
        }

        // Start the AP via PSCI CPU_ON.
        // target_cpu = MPIDR affinity value; on QEMU virt, Aff0 = cpu_id.
        let result = psci::cpu_on(cpu_id as u64, trampoline_phys, cpu_id as u64);
        if result == psci::PSCI_ALREADY_ON {
            // CPU already running (shouldn't happen), skip.
            continue;
        }
        if result != psci::PSCI_SUCCESS {
            // CPU doesn't exist or PSCI error — stop probing.
            {
                let s = crate::SerialGuard::acquire();
                s.puts("[SMP] PSCI CPU_ON failed for cpu_id=");
                s.dec(cpu_id as u64);
                s.puts(" error=");
                s.puts(psci::error_name(result));
                s.putc(b'\n');
            }
            break;
        }

        // Wait for AP to signal ready (spin with timeout).
        // Approximate timeout: ~500ms (500_000 iterations of a short spin).
        let mut timeout = 500_000u32;
        while !ap_boot::is_ap_ready(cpu_id) {
            if timeout == 0 {
                let s = crate::SerialGuard::acquire();
                s.puts("[SMP] AP cpu_id=");
                s.dec(cpu_id as u64);
                s.puts(" timeout waiting for ready\n");
                break;
            }
            for _ in 0..100 {
                core::hint::spin_loop();
            }
            timeout -= 1;
        }

        if ap_boot::is_ap_ready(cpu_id) {
            ap_count += 1;
        }
    }

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[SMP] ");
        s.dec(ap_count as u64);
        s.puts(" AP(s) online\n");
    }
}

/// Remove bootloader identity mapping (L0[0] via TTBR0).
pub fn clear_boot_identity_map() {
    paging::clear_boot_identity_map();
}

/// Start periodic timer interrupts (10 ms tick via PPI 30).
pub fn start_timer() {
    timer::start();
}

/// Shut down the system via PSCI SYSTEM_OFF.
pub fn shutdown() -> ! {
    psci::system_off();
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

/// User memory access control — Privileged Access Never (PAN) on aarch64.
///
/// When FEAT_PAN is supported, the processor traps EL1 accesses to
/// user-mapped pages (Stage 1, EL0-accessible). This module detects
/// PAN support at boot, configures auto-PAN-set on exception entry
/// (SCTLR_EL1.SPAN=0), and provides an RAII guard for temporary access.
pub mod uaccess {
    use super::{AtomicBool, Ordering};

    /// True once FEAT_PAN has been detected and enabled for runtime use.
    static PAN_ACTIVE: AtomicBool = AtomicBool::new(false);

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
            PAN_ACTIVE.store(true, Ordering::Release);
        } else {
            PAN_ACTIVE.store(false, Ordering::Release);
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
            if PAN_ACTIVE.load(Ordering::Acquire) {
                unsafe {
                    // Clear PAN: MSR PAN, #0 → encoding 0xD500409F
                    core::arch::asm!(".inst 0xD500409F", options(nomem, nostack));
                }
            }
            UserAccessGuard
        }
    }

    impl Drop for UserAccessGuard {
        fn drop(&mut self) {
            // SAFETY: Setting PAN blocks EL1 access to user-mapped pages,
            // restoring the default protection.
            if PAN_ACTIVE.load(Ordering::Acquire) {
                unsafe {
                    // Set PAN: MSR PAN, #1 → encoding 0xD500419F
                    core::arch::asm!(".inst 0xD500419F", options(nomem, nostack));
                }
            }
        }
    }
}
