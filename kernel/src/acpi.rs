//! Shared ACPI table parsing infrastructure.
//!
//! Provides architecture-generic ACPI table walking (RSDP → XSDT/RSDT →
//! find table by signature) and MCFG parsing for PCIe ECAM discovery.
//!
//! Architecture-specific ACPI tables (MADT LAPIC/IOAPIC for x86, GIC for
//! aarch64, FADT for x86 shutdown) remain in their respective arch modules.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::mm::PHYS_MAP_OFFSET;

// ---------------------------------------------------------------------------
// ACPI structures
// ---------------------------------------------------------------------------

/// RSDP (Root System Description Pointer) v1
#[repr(C, packed)]
pub struct Rsdp {
    pub signature: [u8; 8], // "RSD PTR "
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,
}

/// RSDP v2 (XSDP) extends RSDP with 64-bit XSDT pointer
#[repr(C, packed)]
pub struct Rsdp2 {
    pub rsdp: Rsdp,
    pub length: u32,
    pub xsdt_address: u64,
    pub extended_checksum: u8,
    pub reserved: [u8; 3],
}

/// ACPI SDT header (common to all description tables)
#[repr(C, packed)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Validate an ACPI table checksum.
///
/// All bytes in the structure must sum to zero (mod 256).
///
/// # Safety
/// `ptr` must point to at least `len` readable bytes.
pub unsafe fn validate_checksum(ptr: *const u8, len: usize) -> bool {
    let mut sum: u8 = 0;
    for i in 0..len {
        // SAFETY: Caller guarantees `ptr..ptr+len` is valid.
        sum = sum.wrapping_add(unsafe { *ptr.add(i) });
    }
    sum == 0
}

/// Convert a physical address to a virtual pointer using the direct mapping.
pub fn phys_to_ptr<T>(phys: u64) -> *const T {
    (phys + PHYS_MAP_OFFSET) as *const T
}

/// PSCI conduit advertised by firmware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PsciConduit {
    Smc,
    Hvc,
}

// ---------------------------------------------------------------------------
// Generic table walker
// ---------------------------------------------------------------------------

/// Find an ACPI table by its 4-byte signature.
///
/// Walks RSDP → XSDT (if revision >= 2) or RSDT → scans entries for a
/// matching signature. Returns the physical address of the table.
///
/// # Safety
/// `rsdp_phys` must be a valid physical address of an ACPI RSDP structure,
/// reachable via the kernel direct physical map.
pub unsafe fn find_table(rsdp_phys: u64, signature: &[u8; 4]) -> Option<u64> {
    if rsdp_phys == 0 {
        return None;
    }

    let rsdp_ptr: *const Rsdp = phys_to_ptr(rsdp_phys);
    // SAFETY: rsdp_phys was validated by caller.
    let rsdp = unsafe { &*rsdp_ptr };

    if &rsdp.signature != b"RSD PTR " {
        return None;
    }

    // SAFETY: RSDP v1 is always 20 bytes.
    if !unsafe { validate_checksum(rsdp_ptr as *const u8, 20) } {
        return None;
    }

    if rsdp.revision >= 2 {
        // SAFETY: revision >= 2 guarantees Rsdp2 layout is valid.
        let rsdp2 = unsafe { &*(rsdp_ptr as *const Rsdp2) };
        unsafe { find_table_in_xsdt(rsdp2.xsdt_address, signature) }
    } else {
        unsafe { find_table_in_rsdt(rsdp.rsdt_address as u64, signature) }
    }
}

/// Search XSDT (64-bit entry pointers) for a table with the given signature.
///
/// # Safety
/// `xsdt_phys` must be a valid physical address of an XSDT reachable via
/// the kernel direct physical map.
unsafe fn find_table_in_xsdt(xsdt_phys: u64, signature: &[u8; 4]) -> Option<u64> {
    let xsdt_ptr: *const SdtHeader = phys_to_ptr(xsdt_phys);
    // SAFETY: Caller guarantees xsdt_phys is valid.
    let xsdt = unsafe { &*xsdt_ptr };

    let header_size = core::mem::size_of::<SdtHeader>();
    if (xsdt.length as usize) < header_size {
        return None;
    }
    let entry_count = (xsdt.length as usize - header_size) / 8;

    // SAFETY: entries follow immediately after the SDT header.
    let entries_ptr = unsafe { (xsdt_ptr as *const u8).add(header_size) as *const u64 };

    for i in 0..entry_count {
        // SAFETY: i < entry_count, within the XSDT.
        let table_phys = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) };
        let table_hdr: *const SdtHeader = phys_to_ptr(table_phys);
        // SAFETY: table_hdr points to a valid SDT via the direct map.
        let sig = unsafe { (*table_hdr).signature };

        if &sig == signature {
            return Some(table_phys);
        }
    }

    None
}

/// Search RSDT (32-bit entry pointers) for a table with the given signature.
///
/// # Safety
/// `rsdt_phys` must be a valid physical address of an RSDT reachable via
/// the kernel direct physical map.
unsafe fn find_table_in_rsdt(rsdt_phys: u64, signature: &[u8; 4]) -> Option<u64> {
    let rsdt_ptr: *const SdtHeader = phys_to_ptr(rsdt_phys);
    // SAFETY: Caller guarantees rsdt_phys is valid.
    let rsdt = unsafe { &*rsdt_ptr };

    let header_size = core::mem::size_of::<SdtHeader>();
    if (rsdt.length as usize) < header_size {
        return None;
    }
    let entry_count = (rsdt.length as usize - header_size) / 4;

    // SAFETY: entries follow immediately after the SDT header.
    let entries_ptr = unsafe { (rsdt_ptr as *const u8).add(header_size) as *const u32 };

    for i in 0..entry_count {
        // SAFETY: i < entry_count, within the RSDT.
        let table_phys = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) } as u64;
        let table_hdr: *const SdtHeader = phys_to_ptr(table_phys);
        // SAFETY: table_hdr points to a valid SDT via the direct map.
        let sig = unsafe { (*table_hdr).signature };

        if &sig == signature {
            return Some(table_phys);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// FADT — ARM boot architecture flags
// ---------------------------------------------------------------------------

const FADT_FLAGS_OFFSET: usize = 112;
const FADT_ARM_BOOT_FLAGS_OFFSET: usize = 132;
const FADT_MINOR_REVISION_OFFSET: usize = 134;

const ACPI_FADT_HW_REDUCED: u32 = 1 << 20;
const ACPI_FADT_PSCI_COMPLIANT: u16 = 1 << 0;
const ACPI_FADT_PSCI_USE_HVC: u16 = 1 << 1;

/// Parse the FADT ARM boot architecture flags to discover the PSCI conduit.
///
/// Returns `Some(PsciConduit)` only when firmware explicitly advertises PSCI
/// support via `ARM_BOOT_ARCH`. Otherwise returns `None`.
///
/// # Safety
/// `rsdp_phys` must be a valid physical address of an ACPI RSDP structure,
/// reachable via the kernel direct physical map.
pub unsafe fn parse_psci_conduit(rsdp_phys: u64) -> Option<PsciConduit> {
    let fadt_phys = unsafe { find_table(rsdp_phys, b"FACP") }?;
    let fadt_ptr = phys_to_ptr::<u8>(fadt_phys);
    let hdr = unsafe { &*(fadt_ptr as *const SdtHeader) };
    let length = hdr.length as usize;

    if length <= FADT_MINOR_REVISION_OFFSET {
        return None;
    }

    let major_revision = hdr.revision;
    let minor_revision = unsafe { *fadt_ptr.add(FADT_MINOR_REVISION_OFFSET) };
    let arm_boot_flags =
        unsafe { core::ptr::read_unaligned(fadt_ptr.add(FADT_ARM_BOOT_FLAGS_OFFSET) as *const u16) };

    // arm64 ACPI requires HW-reduced mode. If firmware does not advertise it,
    // do not trust PSCI flags from this FADT.
    if length >= FADT_FLAGS_OFFSET + 4 {
        let flags =
            unsafe { core::ptr::read_unaligned(fadt_ptr.add(FADT_FLAGS_OFFSET) as *const u32) };
        if (flags & ACPI_FADT_HW_REDUCED) == 0 {
            return None;
        }
    }

    // ACPI 5.1 introduced ARM boot flags. Some firmware reports 5.0 but still
    // fills in `arm_boot_flags`; accept that case only when the flags are
    // actually present and non-zero.
    if major_revision < 5 || (major_revision == 5 && minor_revision < 1) {
        if arm_boot_flags == 0 {
            return None;
        }
    }

    if (arm_boot_flags & ACPI_FADT_PSCI_COMPLIANT) == 0 {
        return None;
    }

    if (arm_boot_flags & ACPI_FADT_PSCI_USE_HVC) != 0 {
        Some(PsciConduit::Hvc)
    } else {
        Some(PsciConduit::Smc)
    }
}

// ---------------------------------------------------------------------------
// MCFG — PCIe ECAM discovery
// ---------------------------------------------------------------------------

/// PCIe ECAM information discovered from ACPI MCFG table.
pub struct EcamInfo {
    /// ECAM base physical address.
    pub phys_addr: u64,
    /// Size as power of 2 (e.g., 28 = 256 MiB for 256 buses).
    pub size_bits: u8,
    /// First PCI bus number covered.
    pub start_bus: u8,
    /// Last PCI bus number covered.
    pub end_bus: u8,
}

/// MCFG configuration space allocation entry.
#[repr(C, packed)]
struct McfgEntry {
    base_address: u64,
    segment_group: u16,
    start_bus: u8,
    end_bus: u8,
    reserved: [u8; 4],
}

/// Parse the ACPI MCFG table to discover the PCIe ECAM base address.
///
/// Returns ECAM info for PCI segment group 0 (the primary host bridge).
///
/// # Safety
/// `rsdp_phys` must be a valid physical address of an ACPI RSDP structure,
/// reachable via the kernel direct physical map. Must be called after the
/// direct physical map has been established.
pub unsafe fn parse_mcfg(rsdp_phys: u64) -> Option<EcamInfo> {
    let mcfg_phys = unsafe { find_table(rsdp_phys, b"MCFG") };

    let mcfg_phys = match mcfg_phys {
        Some(addr) => addr,
        None => {
            crate::serial_puts("[ACPI] MCFG table not found\n");
            return None;
        }
    };

    let mcfg_hdr: *const SdtHeader = phys_to_ptr(mcfg_phys);
    // SAFETY: mcfg_phys is a valid ACPI table address.
    let total_length = unsafe { (*mcfg_hdr).length } as usize;

    let header_size = core::mem::size_of::<SdtHeader>();
    // MCFG has 8 reserved bytes between the SDT header and entries.
    let entries_offset = header_size + 8;
    let entry_size = core::mem::size_of::<McfgEntry>();

    if total_length < entries_offset + entry_size {
        crate::serial_puts("[ACPI] MCFG table too short\n");
        return None;
    }

    let entry_count = (total_length - entries_offset) / entry_size;
    // SAFETY: entries start at mcfg_phys + entries_offset.
    let entries_ptr = unsafe {
        (mcfg_hdr as *const u8).add(entries_offset) as *const McfgEntry
    };

    for i in 0..entry_count {
        // SAFETY: i < entry_count, within the MCFG table bounds.
        let entry = unsafe { &*entries_ptr.add(i) };
        let seg = entry.segment_group;
        let base = entry.base_address;
        let start = entry.start_bus;
        let end = entry.end_bus;

        if seg == 0 {
            // Each bus occupies 1 MiB of ECAM space (32 dev × 8 func × 4 KiB).
            let num_buses = (end as u64) - (start as u64) + 1;
            let size_bytes = num_buses << 20; // num_buses * 1 MiB
            let size_bits = ceil_log2(size_bytes);

            {
                let s = crate::SerialGuard::acquire();
                s.puts("[ACPI] MCFG: ECAM at ");
                s.hex(base);
                s.puts(" bus ");
                s.dec(start as u64);
                s.puts("..");
                s.dec(end as u64);
                s.puts(" size=2^");
                s.dec(size_bits as u64);
                s.putc(b'\n');
            }

            return Some(EcamInfo {
                phys_addr: base,
                size_bits,
                start_bus: start,
                end_bus: end,
            });
        }
    }

    crate::serial_puts("[ACPI] MCFG: no segment group 0 entry\n");
    None
}

/// Compute ceil(log2(val)), returning the smallest n such that 2^n >= val.
fn ceil_log2(val: u64) -> u8 {
    if val <= 1 {
        return 0;
    }
    // 64 - leading_zeros gives floor(log2) + 1 for non-powers,
    // or exact log2 for powers of two.
    let bits = 64 - (val - 1).leading_zeros();
    bits as u8
}
