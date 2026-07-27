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
pub mod gic;
pub mod paging;
pub mod pl011;
pub mod psci;
pub mod random;
pub mod stacktrace;
pub mod timer;

/// Maximum supported CPUs
pub const MAX_CPUS: usize = 16;

pub(crate) use stacktrace::capture_current_panic_context;

unsafe extern "C" {
    fn aarch64_mod_save_irq_disable() -> u64;
    fn aarch64_mod_restore_irq(saved: u64);
    fn aarch64_mod_sti();
    fn aarch64_mod_cli();
    fn aarch64_mod_halt();
    fn aarch64_mod_current_el() -> u64;
    fn aarch64_mod_read_mpidr_el1() -> u64;
    fn aarch64_mod_read_tpidr_el0() -> u64;
    fn aarch64_mod_write_tpidr_el0(value: u64);
    fn aarch64_mod_read_cntpct_el0() -> u64;
    fn aarch64_mod_read_cntfrq_el0() -> u64;
    fn aarch64_mod_read_currentel_raw() -> u64;
    fn aarch64_mod_read_daif() -> u64;
    fn aarch64_mod_read_esr_el1() -> u64;
    fn aarch64_mod_read_far_el1() -> u64;
    fn aarch64_mod_read_ttbr0_el1() -> u64;
    fn aarch64_mod_read_ttbr1_el1() -> u64;
    fn aarch64_mod_read_tcr_el1() -> u64;
    fn aarch64_mod_read_sctlr_el1() -> u64;
    fn aarch64_mod_write_sctlr_el1_isb(value: u64);
    fn aarch64_mod_read_ctr_el0() -> u64;
    fn aarch64_mod_dsb_ishst_isb();
    fn aarch64_mod_dsb_ish();
    fn aarch64_mod_isb();
    fn aarch64_mod_dsb_sy_isb();
    fn aarch64_mod_dc_civac(addr: u64);
    fn aarch64_mod_ic_ivau(addr: u64);
    fn aarch64_mod_read_id_aa64isar0_el1() -> u64;
    fn aarch64_mod_read_id_aa64mmfr1_el1() -> u64;
    fn aarch64_mod_pan_clear();
    fn aarch64_mod_pan_set();
}

// --- IRQ save/restore (DAIF manipulation) ---

/// Save interrupt state and disable interrupts (mask DAIF.I)
#[inline(always)]
pub fn save_irq_disable() -> u64 {
    unsafe { aarch64_mod_save_irq_disable() }
}

/// Restore interrupt state from saved DAIF
///
/// # Safety
/// `saved` must be a value previously returned by `save_irq_disable()`.
#[inline(always)]
pub unsafe fn restore_irq(saved: u64) {
    // SAFETY: Caller guarantees saved is a valid DAIF value
    unsafe {
        aarch64_mod_restore_irq(saved);
    }
}

/// Return true when IRQs are masked in DAIF.I.
#[inline(always)]
pub fn irqs_disabled() -> bool {
    // SAFETY: Reading DAIF is side-effect free in kernel context.
    unsafe { aarch64_mod_read_daif() & (1 << 7) != 0 }
}

/// Enable interrupts (unmask DAIF.I)
#[inline(always)]
pub fn sti() {
    // SAFETY: Unmasking IRQ is safe when called from kernel context
    unsafe {
        aarch64_mod_sti();
    }
}

/// Disable interrupts (mask DAIF.I)
#[inline(always)]
pub fn cli() {
    // SAFETY: Masking IRQ is always safe
    unsafe {
        aarch64_mod_cli();
    }
}

/// Halt the CPU until next interrupt (WFI)
#[inline(always)]
pub fn halt() {
    // SAFETY: WFI is a hint instruction, always safe
    unsafe {
        aarch64_mod_halt();
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

/// I/O port output 16-bit (not available on aarch64 — panics)
///
/// # Safety
/// Always panics on aarch64.
#[inline(always)]
pub unsafe fn outw(_port: u16, _value: u16) {
    panic!("outw: I/O ports not available on aarch64");
}

/// I/O port input 16-bit (not available on aarch64 — returns 0)
///
/// # Safety
/// Always returns 0 on aarch64.
#[inline(always)]
pub unsafe fn inw(_port: u16) -> u16 {
    0
}

/// I/O port output 32-bit (not available on aarch64 — panics)
///
/// # Safety
/// Always panics on aarch64.
#[inline(always)]
pub unsafe fn outl(_port: u16, _value: u32) {
    panic!("outl: I/O ports not available on aarch64");
}

/// I/O port input 32-bit (not available on aarch64 — returns 0)
///
/// # Safety
/// Always returns 0 on aarch64.
#[inline(always)]
pub unsafe fn inl(_port: u16) -> u32 {
    0
}

// --- EL state ---

/// Return the current exception level number.
pub fn current_el() -> u64 {
    unsafe { aarch64_mod_current_el() }
}

/// Returns true if the host kernel is running at EL2.
///
/// SaltyOS now fixes the AArch64 host kernel at EL1. EL2 is reserved for a
/// future virtualization backend, so the host-side answer is always false.
pub fn is_el2() -> bool {
    false
}

// --- Per-CPU data ---

/// Get current CPU ID (from MPIDR_EL1)
pub fn current_cpu() -> usize {
    let mpidr = unsafe { aarch64_mod_read_mpidr_el1() };
    // Aff0 field (bits 7:0) gives the CPU number on most platforms
    (mpidr & 0xFF) as usize
}

#[inline(always)]
pub fn per_cpu_ready() -> bool {
    true
}

#[inline(always)]
pub fn diagnostic_current_cpu() -> usize {
    current_cpu()
}

/// Next invocation sequence number for the current CPU.
pub fn next_invoke_seq() -> u64 {
    cpu::next_invoke_seq()
}

/// Current invocation sequence number for the current CPU.
pub fn current_invoke_seq() -> u64 {
    cpu::current_invoke_seq()
}

/// Set kernel stack for current CPU (via host TPIDR-backed per-CPU data).
pub fn set_kernel_stack(stack_top: u64) {
    cpu::set_kernel_stack(stack_top);
}

/// Return the kernel stack top for the current CPU.
pub fn get_kernel_stack() -> u64 {
    cpu::get_kernel_stack()
}

/// Set TSS RSP0 equivalent (stub for Phase 1, no TSS on aarch64)
pub fn set_tss_rsp0(_stack_top: u64) {
    // No TSS on aarch64 — exception entry uses SP_EL1
}

/// Read thread-local base (TPIDR_EL0)
pub fn read_fs_base() -> u64 {
    unsafe { aarch64_mod_read_tpidr_el0() }
}

/// Write thread-local base (TPIDR_EL0).
///
/// # Safety
/// Caller must ensure `val` is a valid TLS base for the current
/// thread. Marked `unsafe` to keep the arch trait shape symmetric
/// with x86_64's `write_fs_base` (which writes an MSR and demands
/// the same caller contract).
pub unsafe fn write_fs_base(val: u64) {
    unsafe {
        aarch64_mod_write_tpidr_el0(val);
    }
}

/// Update the user ABI thread pointer.
///
/// AArch64 restores the ABI register (`x18`) from the current TCB's saved
/// thread state on return to EL0, so there is no live kernel register update
/// to perform here.
pub fn write_abi_tp_base(_val: u64) {}

/// Generate a stack canary value
pub fn generate_stack_canary() -> u64 {
    // Try RNDR (ARMv8.5-RNG) first when advertised by the CPU. On
    // systems without FEAT_RNG, executing RNDR itself raises an
    // undefined-instruction exception instead of returning failure.
    if cpuid::has_hw_rng() {
        if let Some(val) = random::rdrand64_once() {
            return val;
        }
    }
    // Fallback: CNTPCT_EL0 (not cryptographically random, but usable)
    unsafe { aarch64_mod_read_cntpct_el0() }
}

/// Set per-CPU stack canary (via host TPIDR-backed per-CPU data).
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
    unsafe { aarch64_mod_read_cntpct_el0() }
}

/// Get current time in nanoseconds
pub fn now_ns() -> u64 {
    let freq = unsafe { aarch64_mod_read_cntfrq_el0() };
    if freq == 0 {
        return 0;
    }
    let ticks = get_ticks();
    // Convert ticks to nanoseconds: ticks * 1_000_000_000 / freq
    // Use 128-bit math to avoid overflow
    ((ticks as u128 * 1_000_000_000u128) / freq as u128) as u64
}

/// Print AArch64 detail for a generic panic without an exception frame.
pub fn dump_panic_detail() {
    use crate::kernel::printk::{serial_dec_raw, serial_hex_raw, serial_putc_hw, serial_puts_raw};

    let current_el = unsafe { aarch64_mod_read_currentel_raw() };
    let daif = unsafe { aarch64_mod_read_daif() };
    let esr_el1 = unsafe { aarch64_mod_read_esr_el1() };
    let far_el1 = unsafe { aarch64_mod_read_far_el1() };
    let ttbr0_el1 = unsafe { aarch64_mod_read_ttbr0_el1() };
    let ttbr1_el1 = unsafe { aarch64_mod_read_ttbr1_el1() };
    let tcr_el1 = unsafe { aarch64_mod_read_tcr_el1() };
    let sctlr_el1 = unsafe { aarch64_mod_read_sctlr_el1() };

    serial_puts_raw("arch: aarch64 generic\n");
    serial_puts_raw("cpu: ");
    serial_dec_raw(diagnostic_current_cpu() as u64);
    serial_puts_raw(" per_cpu_ready=");
    serial_dec_raw(per_cpu_ready() as u64);
    serial_puts_raw(" ticks=");
    serial_dec_raw(get_ticks());
    serial_putc_hw(b'\n');
    serial_puts_raw("CurrentEL: ");
    serial_hex_raw(current_el);
    serial_puts_raw(" DAIF: ");
    serial_hex_raw(daif);
    serial_puts_raw(" ESR_EL1: ");
    serial_hex_raw(esr_el1);
    serial_puts_raw(" FAR_EL1: ");
    serial_hex_raw(far_el1);
    serial_putc_hw(b'\n');
    serial_puts_raw("TTBR0_EL1: ");
    serial_hex_raw(ttbr0_el1);
    serial_puts_raw(" TTBR1_EL1: ");
    serial_hex_raw(ttbr1_el1);
    serial_putc_hw(b'\n');
    serial_puts_raw("TCR_EL1: ");
    serial_hex_raw(tcr_el1);
    serial_puts_raw(" SCTLR_EL1: ");
    serial_hex_raw(sctlr_el1);
    serial_putc_hw(b'\n');
}

pub fn publish_page_table_page(table_phys: u64) {
    paging::flush_dcache_poc_page(crate::mm::phys_to_virt(table_phys));
    unsafe {
        aarch64_mod_dsb_ishst_isb();
    }
}

/// Flush a user page that was populated through the current VA alias.
///
/// Userland loaders fill pages through a scratch mapping, unmap that alias,
/// and then remap the same frame at a different VA. Under strict AArch64
/// cache models this requires explicit cache maintenance on the written alias
/// before the remap, otherwise the new mapping may observe stale data or code.
pub fn sync_user_page_before_unmap(vaddr: u64) {
    let ctr = unsafe { aarch64_mod_read_ctr_el0() };

    let dline_shift = ((ctr >> 16) & 0xF) as usize;
    let iline_shift = (ctr & 0xF) as usize;
    let dline = 4usize << dline_shift;
    let iline = 4usize << iline_shift;
    let dline = if dline == 0 { 64 } else { dline };
    let iline = if iline == 0 { 64 } else { iline };

    let page_start = vaddr & !0xFFFu64;
    let page_end = page_start + 4096;

    let mut addr = page_start;
    while addr < page_end {
        // SAFETY: The caller keeps the VA mapped until after this helper
        // returns; cleaning by VA is required to publish data written through
        // the scratch alias.
        unsafe {
            aarch64_mod_dc_civac(addr);
        }
        addr += dline as u64;
    }

    // SAFETY: Complete data cache clean before invalidating I-cache.
    unsafe {
        aarch64_mod_dsb_ish();
    }

    let mut addr = page_start;
    while addr < page_end {
        // SAFETY: Invalidating I-cache after publishing freshly written code
        // is harmless for data pages and required for executable remaps.
        unsafe {
            aarch64_mod_ic_ivau(addr);
        }
        addr += iline as u64;
    }

    // SAFETY: Ensure the invalidation is globally observed before returning
    // to the unmap/remap path.
    unsafe {
        aarch64_mod_dsb_ish();
        aarch64_mod_isb();
    }
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
///
/// # Safety
/// Caller must ensure `target_cpu` is a valid online CPU id and
/// `kind` matches a valid SGI binding. Marked `unsafe` to keep the
/// arch trait shape symmetric with x86_64's `send_ipi` (which writes
/// LAPIC ICR and demands the same caller contract).
pub unsafe fn send_ipi(target_cpu: usize, kind: IpiKind) {
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
static TLB_SHOOTDOWN_ADDR: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

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
    unsafe {
        *(&raw mut PCI_IO_VIRT_BASE) = virt;
    }
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
    unsafe {
        core::ptr::write_volatile(addr as *mut u8, val);
    }
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
    unsafe {
        core::ptr::write_volatile(addr as *mut u16, val);
    }
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
    unsafe {
        core::ptr::write_volatile(addr as *mut u32, val);
    }
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
    old_tcb: *mut crate::sched::thread::Tcb,
) {
    // SAFETY: Caller guarantees both pointers are valid ThreadContext.
    unsafe {
        context::context_switch(old_context, new_context, old_tcb);
    }
}

/// Trampoline to enter usermode for newly created threads.
///
/// Delegates to the `context` module which reads the thread's saved
/// host return ELR/SPSR pair plus SP_EL0 from the TCB, loads TTBR0, zeroes all
/// GPRs, and executes `eret` to enter EL0.
///
/// # Safety
/// Must only be used as the initial entry point for a newly scheduled thread.
pub unsafe extern "C" fn usermode_trampoline() -> ! {
    // SAFETY: Caller guarantees this is a newly scheduled thread with
    // valid TCB fields.
    unsafe {
        context::usermode_trampoline();
    }
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
pub fn init(boot_info: Option<&crate::init::bootinfo::ParsedBootInfo>) {
    // Initialize PL011 UART for serial output
    pl011::init();

    // Install exception vector table (must be early so any faults are caught)
    exceptions::init();

    // Initialize BSP per-CPU data (host TPIDR). Must be early so per-CPU
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

    // Switch frame bitmap pointer from the early identity mapping to the
    // higher-half direct map. Must happen after paging::init() creates the
    // direct map and before the low boot alias is cleared.
    crate::mm::remap_frame_bitmap();

    // Allocate per-frame tracking arrays now that direct map covers all RAM.
    crate::mm::init_per_frame_arrays();

    // Enable PAN runtime tracking before the first EL0 transition.
    uaccess::init();

    // Configure CPACR_EL1.FPEN=0b11 for eager FPU (no FP/SIMD trap)
    fpu::init();

    crate::kernel::printk::serial_puts("[ARCH] AArch64 subsystems initialized\n");
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
pub fn init_smp(boot_info: Option<&crate::init::bootinfo::ParsedBootInfo>) {
    let info = match boot_info {
        Some(i) => i,
        None => {
            crate::kernel::printk::serial_puts("[SMP] No boot info, skipping SMP init\n");
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

    crate::kernel::printk::kdebug!(arch, |_g| {
        _g.puts("[SMP] Trampoline phys=");
        _g.hex(trampoline_phys);
        _g.puts(" virt=");
        _g.hex(trampoline_virt);
        _g.putc(b'\n');
    });

    // Read BSP system register values for the AP mailbox.
    let mair = paging::read_mair();
    let tcr = paging::read_tcr();
    let sctlr = paging::read_sctlr();
    let host_ttbr0 = paging::read_cr3(); // Shared bootstrap/full root
    let compat_ttbr1 = paging::read_ttbr1(); // Kernel root template for EL1 compatibility
    let entry_virt = ap_boot::ap_entry as *const () as u64;

    // Map GICR MMIO pages for all potential APs before starting them.
    gic::remap_ap_gicr(MAX_CPUS);

    // Secondary CPUs enable the MMU and start walking the kernel root as soon
    // as paging is enabled. Clean the shared page-table tree to PoC so their
    // walkers cannot observe stale descriptors sitting dirty in the BSP cache
    // hierarchy.
    paging::clean_kernel_page_tables_to_poc();

    let mut ap_count = 0u32;

    for cpu_id in 1..MAX_CPUS {
        // Allocate per-CPU kernel stack (16 KB = 4 pages).
        const STACK_PAGES: usize = 4;
        const STACK_SIZE: u64 = STACK_PAGES as u64 * 4096;

        let stack_owner = crate::mm::frame::FrameOwner::KernelPrivate {
            subkind: crate::mm::frame::KernelMetaKind::KernelStack,
        };
        let stack_phys = match crate::mm::pmm_alloc_contiguous_owned(STACK_PAGES, &stack_owner) {
            Some(p) => p,
            None => {
                crate::kernel::printk::serial_puts("[SMP] Failed to allocate AP kernel stack\n");
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
            (*mb).host_ttbr0 = host_ttbr0;
            (*mb).compat_ttbr1 = compat_ttbr1;
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
                aarch64_mod_dc_civac(addr);
                addr += 64; // Cache line size
            }
            aarch64_mod_dsb_sy_isb();
        }

        crate::kernel::printk::kdebug!(arch, |_g| {
            _g.puts("[SMP] Starting AP cpu_id=");
            _g.dec(cpu_id as u64);
            _g.putc(b'\n');
        });

        // Start the AP via PSCI CPU_ON.
        // target_cpu = MPIDR affinity value; on QEMU virt, Aff0 = cpu_id.
        let result = psci::cpu_on(cpu_id as u64, trampoline_phys, cpu_id as u64);
        if result == psci::PSCI_ALREADY_ON {
            // CPU already running (shouldn't happen), skip.
            continue;
        }
        if result != psci::PSCI_SUCCESS {
            // CPU doesn't exist or PSCI error — stop probing.
            crate::kernel::printk::kerror!(|_g| {
                _g.puts("[SMP] PSCI CPU_ON failed for cpu_id=");
                _g.dec(cpu_id as u64);
                _g.puts(" error=");
                _g.puts(psci::error_name(result));
                _g.putc(b'\n');
            });
            break;
        }

        // Wait for AP to signal ready (spin with timeout).
        // Approximate timeout: ~500ms (500_000 iterations of a short spin).
        let mut timeout = 500_000u32;
        while !ap_boot::is_ap_ready(cpu_id) {
            if timeout == 0 {
                crate::kernel::printk::kdebug!(arch, |_g| {
                    _g.puts("[SMP] AP cpu_id=");
                    _g.dec(cpu_id as u64);
                    _g.puts(" timeout waiting for ready\n");
                });
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

    crate::kernel::printk::kinfo!(|_g| {
        _g.puts("[SMP] ");
        _g.dec(ap_count as u64);
        _g.puts(" AP(s) online\n");
    });
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

/// Warm reboot via PSCI SYSTEM_RESET.
pub fn reboot() -> ! {
    psci::system_reset();
}

// CPUID-equivalent module: reports hardware RNG availability
pub mod cpuid {
    /// Check if RNDR instruction is available (ARMv8.5 FEAT_RNG).
    ///
    /// Reads ID_AA64ISAR0_EL1.RNDR (bits 63:60); value >= 1 means supported.
    pub fn has_hw_rng() -> bool {
        let isar0 = unsafe { super::aarch64_mod_read_id_aa64isar0_el1() };
        ((isar0 >> 60) & 0xF) >= 1
    }

    /// RNDR serves the same purpose as both RDRAND and RDSEED on x86.
    pub fn has_hw_seed() -> bool {
        has_hw_rng()
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
    use core::mem::MaybeUninit;
    use core::ptr;

    /// True once FEAT_PAN has been detected and enabled for runtime use.
    static PAN_ACTIVE: AtomicBool = AtomicBool::new(false);

    /// Initialize PAN if supported by the processor.
    ///
    /// Checks ID_AA64MMFR1_EL1.PAN (bits 23:20) and clears SCTLR_EL1.SPAN
    /// so that PAN is automatically set on exception entry from EL0.
    pub fn init() {
        if super::current_el() != 1 {
            PAN_ACTIVE.store(false, Ordering::Release);
            return;
        }

        let mmfr1 = unsafe { super::aarch64_mod_read_id_aa64mmfr1_el1() };
        if ((mmfr1 >> 20) & 0xF) >= 1 {
            // PAN is supported — clear SPAN so PAN is auto-set on exception entry
            let mut sctlr = unsafe { super::aarch64_mod_read_sctlr_el1() };
            sctlr &= !(1u64 << 23); // Clear SPAN (bit 23)
            // SAFETY: Writing SCTLR_EL1 to enable PAN auto-set is safe.
            // ISB ensures the change takes effect before subsequent instructions.
            unsafe {
                super::aarch64_mod_write_sctlr_el1_isb(sctlr);
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
                    super::aarch64_mod_pan_clear();
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
                    super::aarch64_mod_pan_set();
                }
            }
        }
    }

    /// Maximum valid user-space address (lower half of 48-bit VA space).
    const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;

    #[inline]
    fn validate_user_range(addr: u64, size: usize) -> bool {
        if addr >= USER_ADDR_LIMIT {
            return false;
        }
        match addr.checked_add(size as u64) {
            Some(end) => end <= USER_ADDR_LIMIT,
            None => false,
        }
    }

    #[inline]
    fn current_vspace_root() -> Option<*mut crate::mm::VSpace> {
        let current = crate::sched::scheduler::scheduler().current();
        if current.is_null() {
            return None;
        }
        let vspace = unsafe { (*current).vspace_root };
        if vspace.is_null() {
            return None;
        }
        Some(vspace)
    }

    /// Copy raw bytes from the current thread's user address space into kernel memory.
    ///
    /// Returns `false` when the range is out of user space or any covered page is not
    /// currently mapped in the active thread's VSpace.
    pub unsafe fn copy_from_user_bytes(addr: u64, dst: *mut u8, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        if !validate_user_range(addr, len) {
            return false;
        }

        let Some(vspace) = current_vspace_root() else {
            return false;
        };

        let mut copied = 0usize;
        while copied < len {
            let cur = addr + copied as u64;
            let page_off = cur as usize & (crate::mm::PAGE_SIZE - 1);
            let chunk = core::cmp::min(crate::mm::PAGE_SIZE - page_off, len - copied);
            let phys = match unsafe { (&*vspace).resolve_page(cur) } {
                Some(phys) => phys,
                None => return false,
            };
            let src = (crate::mm::phys_to_virt(phys) as *const u8).wrapping_add(page_off);
            unsafe {
                ptr::copy_nonoverlapping(src, dst.add(copied), chunk);
            }
            copied += chunk;
        }

        true
    }

    /// Copy raw bytes from kernel memory into the current thread's user address space.
    ///
    /// Returns `false` when the range is out of user space or any covered page cannot
    /// be made writable in the active thread's VSpace.
    pub unsafe fn copy_to_user_bytes(addr: u64, src: *const u8, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        if !validate_user_range(addr, len) {
            return false;
        }

        let Some(vspace) = current_vspace_root() else {
            return false;
        };

        let mut copied = 0usize;
        while copied < len {
            let cur = addr + copied as u64;
            let page_off = cur as usize & (crate::mm::PAGE_SIZE - 1);
            let chunk = core::cmp::min(crate::mm::PAGE_SIZE - page_off, len - copied);
            let vspace_ref = unsafe { &mut *vspace };
            if !vspace_ref.ensure_writable(cur) {
                return false;
            }
            let phys = match vspace_ref.resolve_page(cur) {
                Some(phys) => phys,
                None => return false,
            };
            let dst = (crate::mm::phys_to_virt(phys) as *mut u8).wrapping_add(page_off);
            unsafe {
                ptr::copy_nonoverlapping(src.add(copied), dst, chunk);
            }
            copied += chunk;
        }

        true
    }

    /// Copy a value of type `T` from user-space address `addr`.
    ///
    /// Returns `None` if the address is not in the valid user range or is not
    /// fully readable in the current thread's VSpace.
    pub unsafe fn copy_from_user<T: Copy>(addr: u64) -> Option<T> {
        let mut value = MaybeUninit::<T>::uninit();
        if !unsafe {
            copy_from_user_bytes(
                addr,
                value.as_mut_ptr().cast::<u8>(),
                core::mem::size_of::<T>(),
            )
        } {
            return None;
        }
        Some(unsafe { value.assume_init() })
    }

    /// Write a value of type `T` to user-space address `addr`.
    ///
    /// Returns `false` if the address is not in the valid user range or is not
    /// fully writable in the current thread's VSpace.
    pub unsafe fn copy_to_user<T: Copy>(addr: u64, val: &T) -> bool {
        unsafe {
            copy_to_user_bytes(
                addr,
                (val as *const T).cast::<u8>(),
                core::mem::size_of::<T>(),
            )
        }
    }
}
