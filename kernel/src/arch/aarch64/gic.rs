// SPDX-License-Identifier: GPL-2.0-only
//! GICv3 Generic Interrupt Controller driver.
//!
//! Provides distributor (GICD), redistributor (GICR), and CPU interface (ICC)
//! initialization for the ARM GICv3 interrupt controller as found on the QEMU
//! virt platform.
//!
//! GICD/GICR registers are accessed via MMIO; ICC registers are accessed via
//! system register instructions (MSR/MRS with `S3_0_Cn_Cm_op2` encodings).

use core::ptr;

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

// ---------------------------------------------------------------------------
// GICD register offsets
// ---------------------------------------------------------------------------

/// Distributor Control Register.
const GICD_CTLR: u64 = 0x0000;
/// Interrupt Group Registers (32 bits per register, 1 bit per IRQ).
const GICD_IGROUPR: u64 = 0x0080;
/// Interrupt Set-Enable Registers.
const GICD_ISENABLER: u64 = 0x0100;
/// Interrupt Clear-Enable Registers.
const GICD_ICENABLER: u64 = 0x0180;
/// Interrupt Priority Registers (8 bits per IRQ).
const GICD_IPRIORITYR: u64 = 0x0400;

/// GICD_CTLR bit: Enable Affinity Routing (ARE) for Non-Secure state.
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
/// GICD_CTLR bit: Enable Group 1 Non-Secure interrupts.
const GICD_CTLR_ENABLE_GRP1_NS: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// GICR register offsets (relative to redistributor base)
// ---------------------------------------------------------------------------

/// Redistributor Wake Register (RD_base + 0x14).
const GICR_WAKER: u64 = 0x0014;

/// SGI_base offset from RD_base.
const GICR_SGI_BASE_OFFSET: u64 = 0x1_0000; // 64 KB

/// Interrupt Group Register 0 (SGI_base + 0x80).
const GICR_IGROUPR0: u64 = GICR_SGI_BASE_OFFSET + 0x0080;
/// Interrupt Set-Enable Register 0 (SGI_base + 0x100).
const GICR_ISENABLER0: u64 = GICR_SGI_BASE_OFFSET + 0x0100;
/// Interrupt Priority Registers (SGI_base + 0x400).
const GICR_IPRIORITYR: u64 = GICR_SGI_BASE_OFFSET + 0x0400;

/// GICR_WAKER bit: Processor Sleep.
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
/// GICR_WAKER bit: Children Asleep.
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// Virtual base address storage
// ---------------------------------------------------------------------------

/// Mapped virtual base of the GICD. Set once during `init()`.
static mut GICD_BASE: u64 = 0;

/// Mapped virtual base of the GICR for the BSP. Each AP computes its own
/// offset as `GICR_BASE_START + cpu_id * GICR_STRIDE`.
static mut GICR_BASE_START: u64 = 0;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Volatile 32-bit MMIO read.
///
/// # Safety
/// `addr` must be a valid, mapped MMIO address.
#[inline(always)]
unsafe fn mmio_read32(addr: u64) -> u32 {
    // SAFETY: Caller guarantees addr is valid MMIO.
    unsafe { ptr::read_volatile(addr as *const u32) }
}

/// Volatile 32-bit MMIO write.
///
/// # Safety
/// `addr` must be a valid, mapped MMIO address.
#[inline(always)]
unsafe fn mmio_write32(addr: u64, val: u32) {
    // SAFETY: Caller guarantees addr is valid MMIO.
    unsafe { ptr::write_volatile(addr as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// ICC system register helpers
// ---------------------------------------------------------------------------

/// Read ICC_IAR1_EL1 (Interrupt Acknowledge Register, Group 1).
/// Returns the INTID of the highest-priority pending interrupt.
#[inline(always)]
fn icc_iar1_read() -> u32 {
    let val: u64;
    // SAFETY: Reading ICC_IAR1_EL1 is safe from EL1 when GIC is initialized.
    unsafe {
        core::arch::asm!(
            "mrs {}, S3_0_C12_C12_0",
            out(reg) val,
            options(nomem, nostack),
        );
    }
    val as u32
}

/// Write ICC_EOIR1_EL1 (End of Interrupt Register, Group 1).
#[inline(always)]
fn icc_eoir1_write(intid: u32) {
    let val = intid as u64;
    // SAFETY: Writing ICC_EOIR1_EL1 is safe from EL1 after acknowledging.
    unsafe {
        core::arch::asm!(
            "msr S3_0_C12_C12_1, {}",
            in(reg) val,
            options(nomem, nostack),
        );
    }
}

/// Write ICC_PMR_EL1 (Priority Mask Register).
#[inline(always)]
fn icc_pmr_write(priority: u8) {
    let val = priority as u64;
    // SAFETY: Writing ICC_PMR_EL1 is safe from EL1.
    unsafe {
        core::arch::asm!(
            "msr S3_0_C4_C6_0, {}",
            in(reg) val,
            options(nomem, nostack),
        );
    }
}

/// Write ICC_BPR1_EL1 (Binary Point Register, Group 1).
#[inline(always)]
fn icc_bpr1_write(bpr: u8) {
    let val = bpr as u64;
    // SAFETY: Writing ICC_BPR1_EL1 is safe from EL1.
    unsafe {
        core::arch::asm!(
            "msr S3_0_C12_C12_3, {}",
            in(reg) val,
            options(nomem, nostack),
        );
    }
}

/// Read ICC_SRE_EL1 (System Register Enable).
#[inline(always)]
fn icc_sre_read() -> u64 {
    let val: u64;
    // SAFETY: Reading ICC_SRE_EL1 is safe from EL1.
    unsafe {
        core::arch::asm!(
            "mrs {}, S3_0_C12_C12_5",
            out(reg) val,
            options(nomem, nostack),
        );
    }
    val
}

/// Write ICC_SRE_EL1 (System Register Enable).
#[inline(always)]
fn icc_sre_write(val: u64) {
    // SAFETY: Writing ICC_SRE_EL1 is safe from EL1.
    unsafe {
        core::arch::asm!(
            "msr S3_0_C12_C12_5, {}",
            "isb",
            in(reg) val,
            options(nomem, nostack),
        );
    }
}

/// Write ICC_IGRPEN1_EL1 (Interrupt Group 1 Enable).
#[inline(always)]
fn icc_igrpen1_write(val: u64) {
    // SAFETY: Writing ICC_IGRPEN1_EL1 is safe from EL1.
    unsafe {
        core::arch::asm!(
            "msr S3_0_C12_C12_7, {}",
            "isb",
            in(reg) val,
            options(nomem, nostack),
        );
    }
}

/// Write ICC_SGI1R_EL1 (SGI Generation Register, Group 1).
#[inline(always)]
fn icc_sgi1r_write(val: u64) {
    // SAFETY: Writing ICC_SGI1R_EL1 triggers an SGI; safe from EL1.
    unsafe {
        core::arch::asm!(
            "msr S3_0_C12_C11_5, {}",
            "isb",
            in(reg) val,
            options(nomem, nostack),
        );
    }
}

// ---------------------------------------------------------------------------
// Address resolution helpers
// ---------------------------------------------------------------------------

/// Return the virtual base address of the GICD.
///
/// Before `paging::init()` (i.e., during early boot with identity mapping),
/// this returns the physical address directly. After the direct map is
/// established, it returns `phys_to_virt(GICD_PHYS_BASE)`.
fn gicd_base() -> u64 {
    // SAFETY: GICD_BASE is written once in init() and only read afterwards.
    let base = unsafe { ptr::read_volatile(ptr::addr_of!(GICD_BASE)) };
    if base != 0 {
        return base;
    }
    // Fallback: identity map (early boot).
    GICD_PHYS_BASE
}

/// Return the virtual base address of the GICR for `cpu_id`.
fn gicr_base(cpu_id: usize) -> u64 {
    // SAFETY: GICR_BASE_START is written once in init() and only read afterwards.
    let start = unsafe { ptr::read_volatile(ptr::addr_of!(GICR_BASE_START)) };
    let base = if start != 0 {
        start
    } else {
        GICR_PHYS_BASE
    };
    base + (cpu_id as u64) * GICR_STRIDE
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the GIC distributor (GICD), BSP redistributor (GICR), and
/// BSP CPU interface (ICC).
///
/// Must be called once during single-threaded boot.
pub fn init() {
    // Resolve virtual addresses.  During early boot (before paging::init),
    // the identity map makes phys == virt.  We store the addresses for
    // later use; after the direct map is up we will update them.
    //
    // SAFETY: Single-threaded boot context.  These statics are written
    // exactly once and only read afterwards.
    unsafe {
        ptr::write_volatile(ptr::addr_of_mut!(GICD_BASE), GICD_PHYS_BASE);
        ptr::write_volatile(ptr::addr_of_mut!(GICR_BASE_START), GICR_PHYS_BASE);
    }

    let gicd = gicd_base();

    // ---- Step 1: Distributor (GICD) ----

    // Disable the distributor while configuring.
    // SAFETY: GICD MMIO is identity-mapped during early boot.
    unsafe {
        mmio_write32(gicd + GICD_CTLR, 0);
    }

    // Wait for RWP (Register Write Pending) to clear — bit 31.
    // SAFETY: Reading GICD_CTLR is safe.
    unsafe {
        while mmio_read32(gicd + GICD_CTLR) & (1 << 31) != 0 {
            core::hint::spin_loop();
        }
    }

    // Set all SPIs (INTID 32+) to Group 1 Non-Secure.
    // Register 0 covers INTIDs 0-31 (SGIs/PPIs, handled by GICR).
    // Registers 1-31 cover INTIDs 32-1019.
    for i in 1u64..32 {
        // SAFETY: GICD MMIO is mapped.
        unsafe {
            mmio_write32(gicd + GICD_IGROUPR + i * 4, 0xFFFF_FFFF);
        }
    }

    // Set all SPI priorities to 0xA0 (middle priority).
    // IPRIORITYR registers start at INTID 0; skip first 32 (SGI/PPI).
    for i in 8u64..256 {
        // SAFETY: GICD MMIO is mapped.
        unsafe {
            mmio_write32(gicd + GICD_IPRIORITYR + i * 4, 0xA0A0_A0A0);
        }
    }

    // Disable all SPIs initially.
    for i in 1u64..32 {
        // SAFETY: GICD MMIO is mapped.
        unsafe {
            mmio_write32(gicd + GICD_ICENABLER + i * 4, 0xFFFF_FFFF);
        }
    }

    // Enable the distributor with ARE_NS and Group 1 NS.
    // SAFETY: GICD MMIO is mapped.
    unsafe {
        mmio_write32(gicd + GICD_CTLR, GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1_NS);
    }

    // ---- Step 2: BSP Redistributor (GICR) ----
    init_redistributor(0);

    // ---- Step 3: BSP CPU Interface (ICC) ----
    init_cpu_interface();

    crate::serial_puts("[GIC] GICv3 initialized (distributor + BSP)\n");
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
    }

    // Set all SGI/PPI priorities to 0xA0.
    for i in 0u64..8 {
        // SAFETY: GICR MMIO is mapped.
        unsafe {
            mmio_write32(gicr + GICR_IPRIORITYR + i * 4, 0xA0A0_A0A0);
        }
    }

    // Enable all SGIs (INTIDs 0-15) — needed for IPIs.
    // PPIs are enabled individually (e.g., timer PPI 30 via enable_irq).
    // SAFETY: GICR MMIO is mapped.
    unsafe {
        mmio_write32(gicr + GICR_ISENABLER0, 0x0000_FFFF);
    }
}

/// Initialize the CPU interface (ICC system registers) for the current CPU.
///
/// Enables the system register interface, sets the priority mask to allow
/// all priorities, and enables Group 1 interrupts.
fn init_cpu_interface() {
    // Enable system register access (ICC_SRE_EL1.SRE = 1).
    let sre = icc_sre_read();
    icc_sre_write(sre | 0x1);

    // Set priority mask to 0xFF — allow all priority levels.
    icc_pmr_write(0xFF);

    // Set binary point to 0 — all priority bits used for preemption.
    icc_bpr1_write(0);

    // Enable Group 1 interrupts.
    icc_igrpen1_write(1);

    // Ensure all writes are visible.
    // SAFETY: ISB is always safe.
    unsafe {
        core::arch::asm!("isb", options(nomem, nostack));
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
    } else {
        // SPI — use the distributor.
        let gicd = gicd_base();
        // SAFETY: GICD MMIO is mapped.
        unsafe {
            mmio_write32(gicd + GICD_ISENABLER + reg_index * 4, bit);
        }
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

/// Remap GIC MMIO bases from identity-mapped physical addresses to their
/// virtual equivalents in the direct physical map.
///
/// Must be called after `paging::init()` establishes the direct map.
pub fn remap_to_direct_map() {
    let gicd_virt = crate::mm::phys_to_virt(GICD_PHYS_BASE);
    let gicr_virt = crate::mm::phys_to_virt(GICR_PHYS_BASE);

    // SAFETY: Single-threaded context during boot; these statics are only
    // updated from identity-map addresses to direct-map addresses.
    unsafe {
        ptr::write_volatile(ptr::addr_of_mut!(GICD_BASE), gicd_virt);
        ptr::write_volatile(ptr::addr_of_mut!(GICR_BASE_START), gicr_virt);
    }
}
