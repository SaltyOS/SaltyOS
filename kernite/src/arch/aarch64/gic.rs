// SPDX-License-Identifier: GPL-2.0-only
//! GICv3 Generic Interrupt Controller driver.
//!
//! Provides distributor (GICD), redistributor (GICR), and CPU interface (ICC)
//! initialization for the ARM GICv3 interrupt controller as found on the QEMU
//! virt platform.
//!
//! GICD/GICR registers are accessed via MMIO; ICC registers are accessed via
//! system register instructions (MSR/MRS with `S3_0_Cn_Cm_op2` encodings).

// ---------------------------------------------------------------------------
// QEMU virt GICv3 base addresses (hardcoded; ACPI/DTB parsing comes later)
// ---------------------------------------------------------------------------

/// GICD (Distributor) physical base address on QEMU virt.
const GICD_PHYS_BASE: u64 = 0x0800_0000;

/// GICR (Redistributor) physical base address on QEMU virt.
/// Each redistributor occupies 128 KB (64 KB RD_base + 64 KB SGI_base).
const GICR_PHYS_BASE: u64 = 0x080A_0000;

/// Size of one redistributor region (RD_base + SGI_base).
const GICR_STRIDE: u64 = 0x2_0000; // 128 KB

/// Map the full architected distributor window.
///
/// Linux uses a 64 KB distributor aperture, and our bringup now touches
/// GICD_IROUTER at 0x6000 in addition to the low control/config registers.
const GICD_MMIO_SIZE: u64 = 0x1_0000;

// ---------------------------------------------------------------------------
// GICD register offsets
// ---------------------------------------------------------------------------

/// Distributor Control Register.
const GICD_CTLR: u64 = 0x0000;
/// Distributor Type Register.
const GICD_TYPER: u64 = 0x0004;
/// Interrupt Group Registers (32 bits per register, 1 bit per IRQ).
const GICD_IGROUPR: u64 = 0x0080;
/// Interrupt Set-Enable Registers.
const GICD_ISENABLER: u64 = 0x0100;
/// Interrupt Clear-Enable Registers.
const GICD_ICENABLER: u64 = 0x0180;
/// Interrupt Clear-Active Registers.
const GICD_ICACTIVER: u64 = 0x0380;
/// Interrupt Priority Registers (8 bits per IRQ).
const GICD_IPRIORITYR: u64 = 0x0400;
/// Interrupt Configuration Registers.
const GICD_ICFGR: u64 = 0x0C00;
/// Interrupt Router Registers.
const GICD_IROUTER: u64 = 0x6000;

/// GICD_CTLR bit: Enable Affinity Routing (ARE) for Non-Secure state.
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
/// GICD_CTLR bit: Enable Group 1 Non-Secure interrupts.
const GICD_CTLR_ENABLE_GRP1_NS: u32 = 1 << 1;
/// GICD_CTLR bit: Disable Security state.
const GICD_CTLR_DS: u32 = 1 << 6;
/// GICD_CTLR bit: Register Write Pending.
const GICD_CTLR_RWP: u32 = 1 << 31;

/// Maximum architected interrupt ID handled by this driver.
const GIC_MAX_INTID: u32 = 1020;
/// Default Group-1 priority encoded four times in one 32-bit word.
const GIC_PRIORITY_DEFAULT: u32 = 0xA0A0_A0A0;
/// Default CPU priority mask used by Linux for normal IRQ delivery.
const ICC_PMR_DEFAULT: u8 = 0xF0;
// ---------------------------------------------------------------------------
// GICR register offsets (relative to redistributor base)
// ---------------------------------------------------------------------------

/// Redistributor Control Register (RD_base + 0x0).
const GICR_CTLR: u64 = 0x0000;
/// Redistributor Wake Register (RD_base + 0x14).
const GICR_WAKER: u64 = 0x0014;

/// SGI_base offset from RD_base.
const GICR_SGI_BASE_OFFSET: u64 = 0x1_0000; // 64 KB

/// Interrupt Group Register 0 (SGI_base + 0x80).
const GICR_IGROUPR0: u64 = GICR_SGI_BASE_OFFSET + 0x0080;
/// Interrupt Set-Enable Register 0 (SGI_base + 0x100).
const GICR_ISENABLER0: u64 = GICR_SGI_BASE_OFFSET + 0x0100;
/// Interrupt Clear-Enable Register 0 (SGI_base + 0x180).
const GICR_ICENABLER0: u64 = GICR_SGI_BASE_OFFSET + 0x0180;
/// Interrupt Clear-Active Register 0 (SGI_base + 0x380).
const GICR_ICACTIVER0: u64 = GICR_SGI_BASE_OFFSET + 0x0380;
/// Interrupt Priority Registers (SGI_base + 0x400).
const GICR_IPRIORITYR: u64 = GICR_SGI_BASE_OFFSET + 0x0400;

/// GICR_WAKER bit: Processor Sleep.
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
/// GICR_WAKER bit: Children Asleep.
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;
/// GICR_CTLR bit: Register Write Pending.
const GICR_CTLR_RWP: u32 = 1 << 3;

unsafe extern "C" {
    fn aarch64_gic_mmio_read32(addr: u64) -> u32;
    fn aarch64_gic_mmio_write32(addr: u64, val: u32);
    fn aarch64_gic_mmio_write64(addr: u64, val: u64);
    fn aarch64_gic_read_mpidr_el1() -> u64;
    fn aarch64_gic_icc_iar1_read() -> u64;
    fn aarch64_gic_icc_eoir1_write(val: u64);
    fn aarch64_gic_icc_pmr_write(val: u64);
    fn aarch64_gic_icc_pmr_read() -> u64;
    fn aarch64_gic_icc_bpr1_write(val: u64);
    fn aarch64_gic_icc_sre_read() -> u64;
    fn aarch64_gic_icc_sre_write(val: u64);
    fn aarch64_gic_icc_igrpen1_write(val: u64);
    fn aarch64_gic_icc_ctlr_read() -> u64;
    fn aarch64_gic_icc_ctlr_write(val: u64);
    fn aarch64_gic_icc_ap0r0_write(val: u64);
    fn aarch64_gic_icc_ap0r1_write(val: u64);
    fn aarch64_gic_icc_ap0r2_write(val: u64);
    fn aarch64_gic_icc_ap0r3_write(val: u64);
    fn aarch64_gic_icc_ap1r0_write(val: u64);
    fn aarch64_gic_icc_ap1r1_write(val: u64);
    fn aarch64_gic_icc_ap1r2_write(val: u64);
    fn aarch64_gic_icc_ap1r3_write(val: u64);
    fn aarch64_gic_icc_sgi1r_write(val: u64);
    fn aarch64_gic_icc_sre_el2_enable();
    fn aarch64_gic_isb();
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Volatile 32-bit MMIO read.
///
/// # Safety
/// `addr` must be a valid, mapped MMIO address.
#[inline(always)]
unsafe fn mmio_read32(addr: u64) -> u32 {
    // SAFETY: Caller guarantees `addr` is a valid MMIO location. Use a plain
    // base-register load so HVF sees a simple syndrome-bearing access form.
    unsafe { aarch64_gic_mmio_read32(addr) }
}

/// Volatile 32-bit MMIO write.
///
/// # Safety
/// `addr` must be a valid, mapped MMIO address.
#[inline(always)]
unsafe fn mmio_write32(addr: u64, val: u32) {
    // SAFETY: Caller guarantees `addr` is a valid MMIO location. Use a plain
    // base-register store to avoid writeback addressing forms in HVF MMIO exits.
    unsafe {
        aarch64_gic_mmio_write32(addr, val);
    }
}

/// Volatile 64-bit MMIO write.
///
/// # Safety
/// `addr` must be a valid, naturally aligned, mapped MMIO address.
#[inline(always)]
unsafe fn mmio_write64(addr: u64, val: u64) {
    // SAFETY: Caller guarantees `addr` is valid MMIO and 64-bit aligned. Use
    // a plain base-register store to keep the fault syndrome fully decoded.
    unsafe {
        aarch64_gic_mmio_write64(addr, val);
    }
}

#[inline(always)]
fn gicd_wait_for_rwp(gicd: u64) {
    // SAFETY: GICD MMIO is mapped and the caller is sequencing distributor
    // configuration writes that architecturally complete when RWP clears.
    unsafe {
        while mmio_read32(gicd + GICD_CTLR) & GICD_CTLR_RWP != 0 {
            core::hint::spin_loop();
        }
    }
}

#[inline(always)]
fn gicr_wait_for_rwp(gicr: u64) {
    // SAFETY: GICR MMIO is mapped and the caller is sequencing redistributor
    // configuration writes that architecturally complete when RWP clears.
    unsafe {
        while mmio_read32(gicr + GICR_CTLR) & GICR_CTLR_RWP != 0 {
            core::hint::spin_loop();
        }
    }
}

#[inline(always)]
fn implemented_irq_count(gicd: u64) -> u32 {
    // SAFETY: GICD MMIO is mapped; GICD_TYPER is a read-only architectural
    // register describing the implemented interrupt range.
    let typer = unsafe { mmio_read32(gicd + GICD_TYPER) };
    let irq_count = ((typer & 0x1f) + 1) * 32;
    irq_count.min(GIC_MAX_INTID)
}

#[inline(always)]
fn current_cpu_affinity() -> u64 {
    // SAFETY: Reading MPIDR_EL1 is always safe in privileged code.
    let mpidr = unsafe { aarch64_gic_read_mpidr_el1() };
    ((mpidr >> 32) & 0xff) << 32
        | ((mpidr >> 16) & 0xff) << 16
        | ((mpidr >> 8) & 0xff) << 8
        | (mpidr & 0xff)
}

// ---------------------------------------------------------------------------
// ICC system register helpers
// ---------------------------------------------------------------------------

/// Read ICC_IAR1_EL1 (Interrupt Acknowledge Register, Group 1).
/// Returns the INTID of the highest-priority pending interrupt.
#[inline(always)]
fn icc_iar1_read() -> u32 {
    // SAFETY: Reading ICC_IAR1_EL1 is safe from EL1 when GIC is initialized.
    let val = unsafe { aarch64_gic_icc_iar1_read() };
    val as u32
}

/// Write ICC_EOIR1_EL1 (End of Interrupt Register, Group 1).
#[inline(always)]
fn icc_eoir1_write(intid: u32) {
    let val = intid as u64;
    // SAFETY: Writing ICC_EOIR1_EL1 is safe from EL1 after acknowledging.
    unsafe {
        aarch64_gic_icc_eoir1_write(val);
    }
}

/// Write ICC_PMR_EL1 (Priority Mask Register).
#[inline(always)]
fn icc_pmr_write(priority: u8) {
    let val = priority as u64;
    // SAFETY: Writing ICC_PMR_EL1 is safe from EL1.
    unsafe {
        aarch64_gic_icc_pmr_write(val);
    }
}

/// Read ICC_PMR_EL1 (Priority Mask Register).
#[inline(always)]
fn icc_pmr_read() -> u8 {
    // SAFETY: Reading ICC_PMR_EL1 is safe from EL1.
    let val = unsafe { aarch64_gic_icc_pmr_read() };
    val as u8
}

/// Write ICC_BPR1_EL1 (Binary Point Register, Group 1).
#[inline(always)]
fn icc_bpr1_write(bpr: u8) {
    let val = bpr as u64;
    // SAFETY: Writing ICC_BPR1_EL1 is safe from EL1.
    unsafe {
        aarch64_gic_icc_bpr1_write(val);
    }
}

/// Read ICC_SRE_EL1 (System Register Enable).
#[inline(always)]
fn icc_sre_read() -> u64 {
    // SAFETY: Reading ICC_SRE_EL1 is safe from EL1.
    unsafe { aarch64_gic_icc_sre_read() }
}

/// Write ICC_SRE_EL1 (System Register Enable).
#[inline(always)]
fn icc_sre_write(val: u64) {
    // SAFETY: Writing ICC_SRE_EL1 is safe from EL1.
    unsafe {
        aarch64_gic_icc_sre_write(val);
    }
}

/// Write ICC_IGRPEN1_EL1 (Interrupt Group 1 Enable).
#[inline(always)]
fn icc_igrpen1_write(val: u64) {
    // SAFETY: Writing ICC_IGRPEN1_EL1 is safe from EL1.
    unsafe {
        aarch64_gic_icc_igrpen1_write(val);
    }
}

/// Read ICC_CTLR_EL1.
#[inline(always)]
fn icc_ctlr_read() -> u64 {
    // SAFETY: Reading ICC_CTLR_EL1 is safe from EL1.
    unsafe { aarch64_gic_icc_ctlr_read() }
}

/// Write ICC_CTLR_EL1.
#[inline(always)]
fn icc_ctlr_write(val: u64) {
    // SAFETY: Writing ICC_CTLR_EL1 is safe from EL1.
    unsafe {
        aarch64_gic_icc_ctlr_write(val);
    }
}

#[inline(always)]
fn icc_ap0r0_write(val: u64) {
    unsafe { aarch64_gic_icc_ap0r0_write(val) }
}

#[inline(always)]
fn icc_ap0r1_write(val: u64) {
    unsafe { aarch64_gic_icc_ap0r1_write(val) }
}

#[inline(always)]
fn icc_ap0r2_write(val: u64) {
    unsafe { aarch64_gic_icc_ap0r2_write(val) }
}

#[inline(always)]
fn icc_ap0r3_write(val: u64) {
    unsafe { aarch64_gic_icc_ap0r3_write(val) }
}

#[inline(always)]
fn icc_ap1r0_write(val: u64) {
    unsafe { aarch64_gic_icc_ap1r0_write(val) }
}

#[inline(always)]
fn icc_ap1r1_write(val: u64) {
    unsafe { aarch64_gic_icc_ap1r1_write(val) }
}

#[inline(always)]
fn icc_ap1r2_write(val: u64) {
    unsafe { aarch64_gic_icc_ap1r2_write(val) }
}

#[inline(always)]
fn icc_ap1r3_write(val: u64) {
    unsafe { aarch64_gic_icc_ap1r3_write(val) }
}

/// Write ICC_SGI1R_EL1 (SGI Generation Register, Group 1).
#[inline(always)]
fn icc_sgi1r_write(val: u64) {
    // SAFETY: Writing ICC_SGI1R_EL1 triggers an SGI; safe from EL1.
    unsafe {
        aarch64_gic_icc_sgi1r_write(val);
    }
}

// ---------------------------------------------------------------------------
// Address resolution helpers
// ---------------------------------------------------------------------------

fn gicd_base() -> u64 {
    crate::mm::phys_to_virt(GICD_PHYS_BASE)
}

/// Return the virtual base address of the GICR for `cpu_id`.
fn gicr_base(cpu_id: usize) -> u64 {
    crate::mm::phys_to_virt(GICR_PHYS_BASE + (cpu_id as u64) * GICR_STRIDE)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the GIC distributor (GICD), BSP redistributor (GICR), and
/// BSP CPU interface (ICC).
///
/// Must be called once during single-threaded boot.
pub fn init() {
    let gicd = gicd_base();
    let irq_count = implemented_irq_count(gicd) as u64;
    let distributor_reg_count = (irq_count + 31) / 32;
    let priority_reg_count = (irq_count + 3) / 4;
    let config_reg_count = (irq_count + 15) / 16;
    let boot_cpu_affinity = current_cpu_affinity();

    // ---- Step 1: Distributor (GICD) ----

    // Disable the distributor while configuring.
    // SAFETY: GICD MMIO is identity-mapped during early boot.
    unsafe {
        mmio_write32(gicd + GICD_CTLR, 0);
    }
    gicd_wait_for_rwp(gicd);

    // Set all SPIs (INTID 32+) to Group 1 Non-Secure.
    // Register 0 covers INTIDs 0-31 (SGIs/PPIs, handled by GICR).
    for i in 1u64..distributor_reg_count {
        // SAFETY: GICD MMIO is mapped.
        unsafe {
            mmio_write32(gicd + GICD_IGROUPR + i * 4, 0xFFFF_FFFF);
        }
    }

    // Normalize all SPIs to level-triggered configuration.
    for i in 2u64..config_reg_count {
        // SAFETY: GICD MMIO is mapped.
        unsafe {
            mmio_write32(gicd + GICD_ICFGR + i * 4, 0);
        }
    }

    // Set all SPI priorities to 0xA0 (middle priority).
    // IPRIORITYR registers start at INTID 0; skip first 32 (SGI/PPI).
    for i in 8u64..priority_reg_count {
        // SAFETY: GICD MMIO is mapped.
        unsafe {
            mmio_write32(gicd + GICD_IPRIORITYR + i * 4, GIC_PRIORITY_DEFAULT);
        }
    }

    // Disable all SPIs initially.
    for i in 1u64..distributor_reg_count {
        // SAFETY: GICD MMIO is mapped.
        unsafe {
            mmio_write32(gicd + GICD_ICACTIVER + i * 4, 0xFFFF_FFFF);
            mmio_write32(gicd + GICD_ICENABLER + i * 4, 0xFFFF_FFFF);
        }
    }
    gicd_wait_for_rwp(gicd);

    // Enable the distributor with ARE_NS and Group 1 NS.
    // SAFETY: GICD MMIO is mapped.
    unsafe {
        mmio_write32(
            gicd + GICD_CTLR,
            GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1_NS,
        );
    }
    gicd_wait_for_rwp(gicd);

    // Route all SPIs to the boot CPU now that ARE_NS is active.
    for intid in 32u64..irq_count {
        // SAFETY: GICD MMIO is mapped and IROUTER uses 64-bit aligned access.
        unsafe {
            mmio_write64(gicd + GICD_IROUTER + intid * 8, boot_cpu_affinity);
        }
    }

    // ---- Step 2: BSP Redistributor (GICR) ----
    init_redistributor(0);

    // ---- Step 3: BSP CPU Interface (ICC) ----
    init_cpu_interface();

    crate::kernel::printk::serial_puts("[GIC] GICv3 initialized (distributor + BSP)\n");
}

/// Initialize the redistributor for the given CPU.
///
/// Marks the processor as online (clears WAKER.ProcessorSleep), configures
/// all SGIs/PPIs as Group 1, and sets their priority.
fn init_redistributor(cpu_id: usize) {
    let gicr = gicr_base(cpu_id);

    // Wake the redistributor — clear ProcessorSleep bit.
    // SAFETY: GICR MMIO is mapped (identity or direct map depending on boot stage).
    unsafe {
        let waker = mmio_read32(gicr + GICR_WAKER);
        mmio_write32(gicr + GICR_WAKER, waker & !GICR_WAKER_PROCESSOR_SLEEP);
    }

    // Wait for ChildrenAsleep to clear, indicating the redistributor is awake.
    // SAFETY: Reading GICR_WAKER is safe.
    unsafe {
        while mmio_read32(gicr + GICR_WAKER) & GICR_WAKER_CHILDREN_ASLEEP != 0 {
            core::hint::spin_loop();
        }
    }

    // Set all SGIs/PPIs (INTID 0-31) to Group 1 Non-Secure.
    // SAFETY: GICR MMIO is mapped.
    unsafe {
        mmio_write32(gicr + GICR_IGROUPR0, 0xFFFF_FFFF);
        mmio_write32(gicr + GICR_ICACTIVER0, 0xFFFF_FFFF);
        mmio_write32(gicr + GICR_ICENABLER0, 0xFFFF_FFFF);
    }

    // Set all SGI/PPI priorities to 0xA0.
    for i in 0u64..8 {
        // SAFETY: GICR MMIO is mapped.
        unsafe {
            mmio_write32(gicr + GICR_IPRIORITYR + i * 4, GIC_PRIORITY_DEFAULT);
        }
    }
    gicr_wait_for_rwp(gicr);

    // Enable all SGIs (INTIDs 0-15) — needed for IPIs.
    // PPIs are enabled individually (e.g., timer PPI 30 via enable_irq).
    // SAFETY: GICR MMIO is mapped.
    unsafe {
        mmio_write32(gicr + GICR_ISENABLER0, 0x0000_FFFF);
    }
    gicr_wait_for_rwp(gicr);
}

/// Initialize the CPU interface (ICC system registers) for the current CPU.
///
/// Enables the system register interface, sets the priority mask to allow
/// all priorities, and enables Group 1 interrupts.
fn init_cpu_interface() {
    if super::current_el() == 2 {
        unsafe {
            aarch64_gic_icc_sre_el2_enable();
        }
    }

    // Enable system register access (ICC_SRE_EL1.SRE = 1).
    let sre = icc_sre_read();
    icc_sre_write(sre | 0x1);
    if (icc_sre_read() & 0x1) == 0 {
        crate::kernel::printk::serial_puts("[GIC] WARNING: ICC_SRE_EL1.SRE did not stick\n");
    }

    let pribits = (((icc_ctlr_read() >> 8) & 0x7) + 1) as u32;
    let old_pmr = icc_pmr_read();
    let probe_pmr = 1u8 << (8 - pribits.min(8));
    icc_pmr_write(probe_pmr);
    let has_group0 = icc_pmr_read() != 0;
    icc_pmr_write(old_pmr);

    // Restore a known CPU-interface state regardless of firmware handoff.
    icc_pmr_write(ICC_PMR_DEFAULT);

    // Set binary point to 0 — all priority bits used for preemption.
    icc_bpr1_write(0);

    // Use architected combined EOI+deactivate mode.
    //
    // QEMU under Apple HVF aborts if the guest writes ICC_DIR_EL1, even after
    // the interrupt has been acknowledged. Combined mode keeps the IRQ
    // lifecycle entirely on ICC_EOIR1_EL1 and avoids the hypervisor-specific
    // assert while remaining architecturally valid for GICv3.
    icc_ctlr_write(icc_ctlr_read() & !(1 << 1));

    if has_group0 {
        match pribits {
            7 | 8 => {
                icc_ap0r3_write(0);
                icc_ap0r2_write(0);
                icc_ap0r1_write(0);
                icc_ap0r0_write(0);
            }
            6 => {
                icc_ap0r1_write(0);
                icc_ap0r0_write(0);
            }
            4 | 5 => {
                icc_ap0r0_write(0);
            }
            _ => {}
        }
        // SAFETY: ISB is always safe.
        unsafe {
            aarch64_gic_isb();
        }
    }

    match pribits {
        7 | 8 => {
            icc_ap1r3_write(0);
            icc_ap1r2_write(0);
            icc_ap1r1_write(0);
            icc_ap1r0_write(0);
        }
        6 => {
            icc_ap1r1_write(0);
            icc_ap1r0_write(0);
        }
        4 | 5 => {
            icc_ap1r0_write(0);
        }
        _ => {}
    }

    // SAFETY: ISB is always safe.
    unsafe {
        aarch64_gic_isb();
    }

    // Enable Group 1 interrupts.
    icc_igrpen1_write(1);

    // Ensure all writes are visible.
    // SAFETY: ISB is always safe.
    unsafe {
        aarch64_gic_isb();
    }
}

/// Initialize an application processor's redistributor and CPU interface.
///
/// Called by each AP during SMP bringup.
pub fn init_ap(cpu_id: usize) {
    init_redistributor(cpu_id);
    init_cpu_interface();
}

/// Acknowledge the highest-priority pending interrupt.
///
/// Returns the INTID (0-1019 for real interrupts, 1020-1023 for special
/// values including spurious).
#[inline(always)]
pub fn acknowledge_irq() -> u32 {
    icc_iar1_read()
}

/// Signal End of Interrupt for the given INTID.
#[inline(always)]
pub fn eoi(intid: u32) {
    icc_eoir1_write(intid);
}

/// Enable a specific interrupt by INTID.
///
/// For SGIs/PPIs (0-31), writes to the redistributor ISENABLER0.
/// For SPIs (32-1019), writes to the distributor ISENABLER.
pub fn enable_irq(intid: u32) {
    let reg_index = (intid / 32) as u64;
    let bit = 1u32 << (intid % 32);

    if intid < 32 {
        // SGI/PPI — use the current CPU's redistributor.
        let cpu_id = super::current_cpu();
        let gicr = gicr_base(cpu_id);
        // SAFETY: GICR MMIO is mapped.
        unsafe {
            mmio_write32(gicr + GICR_ISENABLER0, bit);
        }
        gicr_wait_for_rwp(gicr);
    } else {
        // SPI — use the distributor.
        let gicd = gicd_base();
        // SAFETY: GICD MMIO is mapped.
        unsafe {
            mmio_write32(gicd + GICD_ISENABLER + reg_index * 4, bit);
        }
        gicd_wait_for_rwp(gicd);
        // SAFETY: ISB is always safe and ensures subsequent instructions see
        // the completed interrupt-enable side effects.
        unsafe {
            aarch64_gic_isb();
        }
    }
}

/// Disable a specific interrupt by INTID.
///
/// For SGIs/PPIs (0-31), writes to the redistributor ICENABLER0.
/// For SPIs (32-1019), writes to the distributor ICENABLER.
///
/// For SPIs, polls GICD_CTLR.RWP after the ICENABLER write to guarantee
/// the disable has propagated through the GIC before returning. Without
/// this, a subsequent ISENABLER write on another CPU can race with the
/// pending disable, leaving the interrupt permanently masked (IHI 0069).
pub fn disable_irq(intid: u32) {
    let reg_index = (intid / 32) as u64;
    let bit = 1u32 << (intid % 32);

    if intid < 32 {
        // SGI/PPI — use the current CPU's redistributor.
        let cpu_id = super::current_cpu();
        let gicr = gicr_base(cpu_id);
        // SAFETY: GICR MMIO is mapped.
        unsafe {
            mmio_write32(gicr + GICR_ICENABLER0, bit);
        }
        gicr_wait_for_rwp(gicr);
    } else {
        // SPI — use the distributor.
        let gicd = gicd_base();
        // SAFETY: GICD MMIO is mapped. RWP poll ensures the disable
        // completes before returning, preventing a cross-CPU race where
        // a concurrent enable_irq on another CPU is swallowed.
        unsafe {
            mmio_write32(gicd + GICD_ICENABLER + reg_index * 4, bit);
        }
        gicd_wait_for_rwp(gicd);
    }
}

/// Send a Software Generated Interrupt (SGI) to a target CPU.
///
/// Uses ICC_SGI1R_EL1 with the target affinity and INTID.
/// Only valid for INTIDs 0-15.
pub fn send_sgi(target_cpu: usize, intid: u32) {
    if intid > 15 {
        return;
    }

    // ICC_SGI1R_EL1 encoding:
    //   bits [3:0]   = TargetList (bitmask of CPUs within the affinity)
    //   bits [27:24] = INTID
    //   bits [39:32] = Aff1
    //   bits [47:40] = Aff2
    //   bits [55:48] = Aff3
    //
    // For QEMU virt with flat topology (Aff0 = cpu_id), the target list
    // bit corresponds to the CPU number within Aff0.
    let target_list = 1u64 << (target_cpu & 0xF);
    let sgi_val = target_list | ((intid as u64) << 24);
    icc_sgi1r_write(sgi_val);
}

/// Map GICR MMIO pages for application processors.
///
/// Each CPU has a 128 KB redistributor region. The BSP's GICR (CPU 0) is
/// mapped during `remap_to_direct_map()`.  This function maps the remaining
/// GICR regions for CPUs 1..`cpu_count`.
///
/// Must be called after `paging::init()` and before starting any APs.
pub fn remap_ap_gicr(cpu_count: usize) {
    for cpu_id in 1..cpu_count {
        let base = GICR_PHYS_BASE + (cpu_id as u64) * GICR_STRIDE;
        let mut offset = 0u64;
        while offset < GICR_STRIDE {
            // SAFETY: Boot context; paging::init() has run and the direct
            // map covers all physical RAM. map_mmio_page creates a 4 KB
            // mapping in the kernel page tables.
            unsafe {
                super::paging::map_mmio_page(base + offset);
            }
            offset += crate::mm::PAGE_SIZE as u64;
        }
    }
}

/// Remap GIC MMIO bases from identity-mapped physical addresses to their
/// virtual equivalents in the direct physical map.
///
/// Must be called after `paging::init()` establishes the direct map.
pub fn remap_to_direct_map() {
    let mut offset = 0;
    while offset < GICD_MMIO_SIZE {
        unsafe {
            super::paging::map_mmio_page(GICD_PHYS_BASE + offset);
        }
        offset += crate::mm::PAGE_SIZE as u64;
    }

    offset = 0;
    while offset < GICR_STRIDE {
        unsafe {
            super::paging::map_mmio_page(GICR_PHYS_BASE + offset);
        }
        offset += crate::mm::PAGE_SIZE as u64;
    }
}
