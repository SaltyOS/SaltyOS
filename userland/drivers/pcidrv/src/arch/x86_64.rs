//! x86_64 PCI config space access via I/O port mechanism 1 (ports 0xCF8/0xCFC).
//! SPDX-License-Identifier: GPL-2.0-only

use trona::invoke;

/// PCI config space IoPort cap. Delivered via `CopyCap=15:64` in
/// pcidrv.service from init's CAP_PCI_IOPORT slot (15); init also pushes
/// `ROLE_PCI_IOPORT` into the startup cap_table via `init_slot_to_role`
/// so the substrate `trona::caps::pci_ioport()` getter returns the slot
/// without any local hardcoding.

/// No-op on x86_64 -- I/O port caps are ready at startup.
pub fn pci_init() {}

/// Read 32 bits from PCI config space using mechanism 1 (IO ports 0xCF8/0xCFC).
pub fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    invoke::ioport_out32(trona::caps::pci_ioport(), 0, addr);
    invoke::ioport_in32(trona::caps::pci_ioport(), 4)
}

/// On x86_64, PCI IRQ line from config space is the actual ISA IRQ number.
pub fn resolve_pci_irq(_dev: u8, _func: u8, irq_line: u8) -> u8 {
    irq_line
}

/// Write 32 bits to PCI config space using mechanism 1 (IO ports 0xCF8/0xCFC).
pub fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    let addr: u32 = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    invoke::ioport_out32(trona::caps::pci_ioport(), 0, addr);
    invoke::ioport_out32(trona::caps::pci_ioport(), 4, value);
}
