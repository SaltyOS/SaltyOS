//! x86_64 PCI config space access via I/O port mechanism 1 (ports 0xCF8/0xCFC).
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::invoke;

/// PCI config space IoPort cap. Mirrors init's `CAP_PCI_IOPORT` slot (15)
/// into pcidrv's bootstrap layout; init also pushes `ROLE_PCI_IOPORT`
/// into the startup cap table via `init_slot_to_role` so the substrate
/// `trona_runtime::client::caps::pci_ioport()` getter returns the slot without any local
/// hardcoding.

/// Mechanism 1 ports — absolute I/O addresses inside the cap's range
/// `[0xCF8, 0xD00)`.
const PCI_CONFIG_ADDRESS: u64 = 0xCF8;
const PCI_CONFIG_DATA: u64 = 0xCFC;

/// No-op on x86_64 -- I/O port caps are ready at startup.
pub fn pci_init() {}

#[cold]
fn log_ioport_err(op: &[u8], port: u64, err: i32) {
    trona_runtime::uerror!(|_lb| {
        _lb.str(b"[pcidrv] ioport ");
        _lb.bytes(op);
        _lb.str(b" port=");
        _lb.hex(port);
        _lb.str(b" err=");
        _lb.dec(err as u64);
        _lb.putc(b'\n');
    });
}

/// Read 32 bits from PCI config space using mechanism 1.
///
/// Returns `0xFFFF_FFFF` on syscall error — matches the "missing
/// device" sentinel PCI hardware itself returns when no device responds
/// at the queried address, so existing vendor-id checks treat error and
/// missing-device uniformly. The error itself is surfaced via
/// [`log_ioport_err`].
pub fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    let cap = trona_runtime::client::caps::pci_ioport().cap_ref();
    if let Err(err) = invoke::ioport_out32(cap, PCI_CONFIG_ADDRESS, addr) {
        log_ioport_err(b"write", PCI_CONFIG_ADDRESS, err);
        return 0xFFFF_FFFF;
    }
    invoke::ioport_in32(cap, PCI_CONFIG_DATA).unwrap_or_else(|err| {
        log_ioport_err(b"read", PCI_CONFIG_DATA, err);
        0xFFFF_FFFF
    })
}

/// On x86_64, PCI IRQ line from config space is the actual ISA IRQ number.
pub fn resolve_pci_irq(_dev: u8, _func: u8, irq_line: u8) -> u8 {
    irq_line
}

/// Write 32 bits to PCI config space using mechanism 1.
pub fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    let addr: u32 = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    let cap = trona_runtime::client::caps::pci_ioport().cap_ref();
    if let Err(err) = invoke::ioport_out32(cap, PCI_CONFIG_ADDRESS, addr) {
        log_ioport_err(b"write", PCI_CONFIG_ADDRESS, err);
        return;
    }
    if let Err(err) = invoke::ioport_out32(cap, PCI_CONFIG_DATA, value) {
        log_ioport_err(b"write", PCI_CONFIG_DATA, err);
    }
}
