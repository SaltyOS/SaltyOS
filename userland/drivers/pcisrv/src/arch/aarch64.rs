//! aarch64 PCI config space access via ECAM (Enhanced Configuration Access Mechanism).
//!
//! QEMU virt machine exposes PCIe ECAM at physical address 0x3f00_0000.
//! We map it into our virtual address space during pci_init() and then
//! perform config reads/writes via volatile memory-mapped accesses.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use besalt::consts::*;
use besalt::invoke;

/// ECAM device untyped cap slot (received via CopyCap from init slot 15).
const CAP_ECAM_DEVUT: u64 = 64;

/// Self VSpace cap slot.
const CAP_SELF_VSPACE: u64 = 1;

/// Fixed virtual address for the ECAM mapping.
/// Keep this outside the low-ASLR executable region.
const ECAM_VADDR: u64 = 0x0000_0000_4000_0000;

/// Base virtual address of the mapped ECAM region (set during pci_init).
static mut ECAM_BASE: u64 = 0;
static mut ECAM_READY: bool = false;

/// Map the ECAM region into our address space.
///
/// Must be called once before any pci_read32/pci_write32 calls.
pub fn pci_init() {
    // Map 1 MiB (256 pages x 4 KiB) covering bus 0 config space.
    // Bus 0 has 32 devices x 8 functions x 4 KiB = 1 MiB.
    let num_pages = 256u64;
    let flags = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER | VSPACE_FLAG_CACHE_DISABLE;

    let (err, mapped) = invoke::vspace_map_device_range(
        CAP_SELF_VSPACE,
        CAP_ECAM_DEVUT,
        0,
        ECAM_VADDR,
        num_pages,
        flags,
    );

    if err != 0 || mapped != num_pages {
        besalt::uerror!(|_lb| {
            _lb.str(b"[pcisrv] ECAM map failed err=");
            _lb.hex(err as u64);
            _lb.str(b" mapped=");
            _lb.hex(mapped);
            _lb.str(b"\n");
        });
        unsafe {
            *(&raw mut ECAM_BASE) = 0;
            *(&raw mut ECAM_READY) = false;
        }
        return;
    }

    // SAFETY: Single-threaded init path; no other access to ECAM_BASE yet.
    unsafe {
        *(&raw mut ECAM_BASE) = ECAM_VADDR;
        *(&raw mut ECAM_READY) = true;
    }
}

/// Read 32 bits from PCIe config space via ECAM.
pub fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    unsafe {
        if !*(&raw const ECAM_READY) {
            return 0xFFFF_FFFF;
        }
    }

    let off = ((bus as usize) << 20)
        | ((dev as usize) << 15)
        | ((func as usize) << 12)
        | ((offset as usize) & 0xFFC);
    // SAFETY: ECAM region is mapped during pci_init() and remains valid for
    // the lifetime of this process. The computed offset stays within the
    // mapped 1 MiB region for bus 0 accesses.
    unsafe {
        let base = *(&raw const ECAM_BASE) as usize;
        core::ptr::read_volatile((base + off) as *const u32)
    }
}

/// Write 32 bits to PCIe config space via ECAM.
pub fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    unsafe {
        if !*(&raw const ECAM_READY) {
            return;
        }
    }

    let off = ((bus as usize) << 20)
        | ((dev as usize) << 15)
        | ((func as usize) << 12)
        | ((offset as usize) & 0xFFC);
    // SAFETY: ECAM region is mapped during pci_init() and remains valid for
    // the lifetime of this process. The computed offset stays within the
    // mapped 1 MiB region for bus 0 accesses.
    unsafe {
        let base = *(&raw const ECAM_BASE) as usize;
        core::ptr::write_volatile((base + off) as *mut u32, value);
    }
}

/// QEMU virt PCI INTx → GIC SPI mapping.
///
/// QEMU virt maps PCI INTx (A-D) to GIC SPIs 3-6 (INTID 35-38).
/// Swizzle formula: `spi = 3 + (dev_slot + (pin - 1)) % 4`
/// where pin is 1-based (1=INTA, 2=INTB, ...) from PCI config offset 0x3D.
/// Returns GIC INTID (SPI + 32) or 0xFF if no interrupt.
pub fn resolve_pci_irq(dev: u8, func: u8, _irq_line: u8) -> u8 {
    // Read interrupt pin from PCI config (offset 0x3D, 1-based: 1=INTA..4=INTD)
    let pin_reg = pci_read32(0, dev, func, 0x3C);
    let pin = ((pin_reg >> 8) & 0xFF) as u8;
    if pin == 0 || pin > 4 {
        return 0xFF; // No interrupt
    }
    // QEMU virt swizzle: SPI = 3 + (dev_slot + pin - 1) % 4
    let spi = 3 + ((dev as u32 + pin as u32 - 1) % 4) as u8;
    // GIC INTID = SPI + 32
    spi + 32
}
