//! ACPI MADT Parser for SMP CPU Discovery
//!
//! Parses the RSDP → XSDT/RSDT → MADT chain to discover Application Processors.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::cpu::MAX_CPUS;
use crate::mm::PHYS_MAP_OFFSET;

/// CPU descriptor discovered from ACPI MADT
#[derive(Clone, Copy)]
pub struct CpuDescriptor {
    /// Local APIC ID
    pub apic_id: u8,
    /// True if this is the Bootstrap Processor
    pub is_bsp: bool,
    /// True if this CPU is enabled (or online-capable)
    pub enabled: bool,
}

impl CpuDescriptor {
    const fn empty() -> Self {
        Self {
            apic_id: 0,
            is_bsp: false,
            enabled: false,
        }
    }
}

/// I/O APIC descriptor discovered from ACPI MADT
#[derive(Clone, Copy)]
pub struct IoApicDescriptor {
    pub id: u8,
    pub base_addr: u32,
    pub gsi_base: u32,
}

/// Result of MADT parsing
pub struct MadtInfo {
    pub cpus: [CpuDescriptor; MAX_CPUS],
    pub cpu_count: usize,
    pub io_apic_addr: u32,
    pub io_apic_gsi_base: u32,
}

/// RSDP (Root System Description Pointer) v1
#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],  // "RSD PTR "
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

/// RSDP v2 (XSDP) extends RSDP with 64-bit XSDT pointer
#[repr(C, packed)]
struct Rsdp2 {
    rsdp: Rsdp,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

/// ACPI SDT header (common to all tables)
#[repr(C, packed)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// MADT (Multiple APIC Description Table) header
#[repr(C, packed)]
struct MadtHeader {
    header: SdtHeader,
    local_apic_addr: u32,
    flags: u32,
}

/// MADT entry header
#[repr(C, packed)]
struct MadtEntryHeader {
    entry_type: u8,
    length: u8,
}

/// MADT Type 0: Processor Local APIC
#[repr(C, packed)]
struct MadtLocalApic {
    header: MadtEntryHeader,
    processor_id: u8,
    apic_id: u8,
    flags: u32,
}

/// MADT Type 1: I/O APIC
#[repr(C, packed)]
struct MadtIoApic {
    header: MadtEntryHeader,
    id: u8,
    reserved: u8,
    address: u32,
    gsi_base: u32,
}

// MADT entry type constants
const MADT_TYPE_LOCAL_APIC: u8 = 0;
const MADT_TYPE_IO_APIC: u8 = 1;

// Local APIC flags
const LAPIC_FLAG_ENABLED: u32 = 1 << 0;
const LAPIC_FLAG_ONLINE_CAPABLE: u32 = 1 << 1;

/// Validate an ACPI table checksum
///
/// All bytes in the structure must sum to zero (mod 256).
unsafe fn validate_checksum(ptr: *const u8, len: usize) -> bool {
    let mut sum: u8 = 0;
    for i in 0..len {
        sum = sum.wrapping_add(unsafe { *ptr.add(i) });
    }
    sum == 0
}

/// Convert a physical address to a virtual pointer using the direct mapping
fn phys_to_ptr<T>(phys: u64) -> *const T {
    (phys + PHYS_MAP_OFFSET) as *const T
}

/// Scan for RSDP in standard BIOS locations
///
/// Searches:
/// 1. EBDA (Extended BIOS Data Area) - first 1KB starting at address in BDA[0x40E]
/// 2. Main BIOS area: 0xE0000 - 0xFFFFF
///
/// Returns the physical address of the RSDP, or 0 if not found.
pub unsafe fn scan_for_rsdp() -> u64 {
    unsafe {
        crate::serial_puts("[ACPI] Scanning for RSDP...\n");

        // Search EBDA (address stored at BDA 0x040E, segment value)
        let ebda_segment_ptr = phys_to_ptr::<u16>(0x040E);
        let ebda_segment = core::ptr::read_unaligned(ebda_segment_ptr);
        let ebda_base = (ebda_segment as u64) << 4;

        if ebda_base >= 0x80000 && ebda_base < 0xA0000 {
            if let Some(addr) = scan_region_for_rsdp(ebda_base, 1024) {
                let s = crate::SerialGuard::acquire();
                s.puts("[ACPI] Found RSDP in EBDA at ");
                s.hex(addr);
                s.putc(b'\n');
                return addr;
            }
        }

        // Search main BIOS area: 0xE0000 - 0xFFFFF
        if let Some(addr) = scan_region_for_rsdp(0xE0000, 0x20000) {
            let s = crate::SerialGuard::acquire();
            s.puts("[ACPI] Found RSDP in BIOS area at ");
            s.hex(addr);
            s.putc(b'\n');
            return addr;
        }

        crate::serial_puts("[ACPI] RSDP not found\n");
        0
    }
}

/// Scan a physical memory region for the RSDP signature "RSD PTR "
///
/// Scans on 16-byte boundaries as required by the ACPI spec.
unsafe fn scan_region_for_rsdp(base_phys: u64, length: usize) -> Option<u64> {
    let base_ptr: *const u8 = phys_to_ptr(base_phys);

    let mut offset = 0;
    while offset + 20 <= length {
        let ptr = unsafe { base_ptr.add(offset) };
        let sig = unsafe { core::slice::from_raw_parts(ptr, 8) };

        if sig == b"RSD PTR " {
            // Validate checksum (first 20 bytes for RSDP v1)
            if unsafe { validate_checksum(ptr, 20) } {
                return Some(base_phys + offset as u64);
            }
        }

        offset += 16; // RSDP must be on 16-byte boundary
    }

    None
}

/// Parse the ACPI MADT to discover CPUs
///
/// # Safety
/// `rsdp_phys` must be a valid physical address of the ACPI RSDP structure.
pub unsafe fn parse_madt(rsdp_phys: u64) -> Option<MadtInfo> {
    if rsdp_phys == 0 {
        crate::serial_puts("[ACPI] No RSDP address provided\n");
        return None;
    }

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[ACPI] RSDP at phys ");
        s.hex(rsdp_phys);
        s.putc(b'\n');
    }

    // Read RSDP
    let rsdp_ptr: *const Rsdp = phys_to_ptr(rsdp_phys);
    let rsdp = unsafe { &*rsdp_ptr };

    // Validate RSDP signature
    if &rsdp.signature != b"RSD PTR " {
        crate::serial_puts("[ACPI] Invalid RSDP signature\n");
        return None;
    }

    // Validate RSDP v1 checksum (first 20 bytes)
    if !unsafe { validate_checksum(rsdp_ptr as *const u8, 20) } {
        crate::serial_puts("[ACPI] RSDP checksum failed\n");
        return None;
    }

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[ACPI] RSDP valid, revision=");
        s.dec(rsdp.revision as u64);
        s.putc(b'\n');
    }

    // Find MADT via XSDT (revision >= 2) or RSDT (revision 0)
    let madt_phys = if rsdp.revision >= 2 {
        let rsdp2 = unsafe { &*(rsdp_ptr as *const Rsdp2) };
        unsafe { find_madt_in_xsdt(rsdp2.xsdt_address) }
    } else {
        unsafe { find_madt_in_rsdt(rsdp.rsdt_address as u64) }
    };

    let madt_phys = match madt_phys {
        Some(addr) => addr,
        None => {
            crate::serial_puts("[ACPI] MADT not found\n");
            return None;
        }
    };

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[ACPI] MADT at phys ");
        s.hex(madt_phys);
        s.putc(b'\n');
    }

    // Parse MADT entries
    unsafe { parse_madt_entries(madt_phys) }
}

/// Search XSDT (64-bit pointers) for the MADT table
unsafe fn find_madt_in_xsdt(xsdt_phys: u64) -> Option<u64> {
    let xsdt_ptr: *const SdtHeader = phys_to_ptr(xsdt_phys);
    let xsdt = unsafe { &*xsdt_ptr };

    let header_size = core::mem::size_of::<SdtHeader>();
    let entry_count = (xsdt.length as usize - header_size) / 8;

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[ACPI] XSDT has ");
        s.dec(entry_count as u64);
        s.puts(" entries\n");
    }

    let entries_ptr = unsafe { (xsdt_ptr as *const u8).add(header_size) as *const u64 };

    for i in 0..entry_count {
        let table_phys = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) };
        let table_hdr: *const SdtHeader = phys_to_ptr(table_phys);
        let sig = unsafe { (*table_hdr).signature };

        if &sig == b"APIC" {
            return Some(table_phys);
        }
    }

    None
}

/// Search RSDT (32-bit pointers) for the MADT table
unsafe fn find_madt_in_rsdt(rsdt_phys: u64) -> Option<u64> {
    let rsdt_ptr: *const SdtHeader = phys_to_ptr(rsdt_phys);
    let rsdt = unsafe { &*rsdt_ptr };

    let header_size = core::mem::size_of::<SdtHeader>();
    let entry_count = (rsdt.length as usize - header_size) / 4;

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[ACPI] RSDT has ");
        s.dec(entry_count as u64);
        s.puts(" entries\n");
    }

    let entries_ptr = unsafe { (rsdt_ptr as *const u8).add(header_size) as *const u32 };

    for i in 0..entry_count {
        let table_phys = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) } as u64;
        let table_hdr: *const SdtHeader = phys_to_ptr(table_phys);
        let sig = unsafe { (*table_hdr).signature };

        if &sig == b"APIC" {
            return Some(table_phys);
        }
    }

    None
}

/// Parse MADT entries to extract CPU and I/O APIC information
unsafe fn parse_madt_entries(madt_phys: u64) -> Option<MadtInfo> {
    let madt_ptr: *const MadtHeader = phys_to_ptr(madt_phys);
    let madt = unsafe { &*madt_ptr };

    let total_length = madt.header.length as usize;
    let entries_start = core::mem::size_of::<MadtHeader>();

    let base_ptr = madt_ptr as *const u8;

    let mut info = MadtInfo {
        cpus: [CpuDescriptor::empty(); MAX_CPUS],
        cpu_count: 0,
        io_apic_addr: 0,
        io_apic_gsi_base: 0,
    };

    // Read BSP's APIC ID from the LAPIC ID register to identify which CPU is BSP
    let bsp_apic_id = unsafe { read_bsp_apic_id() };

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[ACPI] BSP APIC ID: ");
        s.dec(bsp_apic_id as u64);
        s.putc(b'\n');
    }

    let mut offset = entries_start;
    while offset + 2 <= total_length {
        let entry_hdr = unsafe { &*(base_ptr.add(offset) as *const MadtEntryHeader) };
        let entry_len = entry_hdr.length as usize;

        if entry_len < 2 || offset + entry_len > total_length {
            break;
        }

        match entry_hdr.entry_type {
            MADT_TYPE_LOCAL_APIC => {
                if entry_len >= core::mem::size_of::<MadtLocalApic>() {
                    let lapic = unsafe { &*(base_ptr.add(offset) as *const MadtLocalApic) };
                    let flags = lapic.flags;
                    let enabled = (flags & LAPIC_FLAG_ENABLED) != 0
                        || (flags & LAPIC_FLAG_ONLINE_CAPABLE) != 0;

                    if enabled && info.cpu_count < MAX_CPUS {
                        let is_bsp = lapic.apic_id == bsp_apic_id;
                        info.cpus[info.cpu_count] = CpuDescriptor {
                            apic_id: lapic.apic_id,
                            is_bsp,
                            enabled: true,
                        };
                        info.cpu_count += 1;

                        {
                            let s = crate::SerialGuard::acquire();
                            s.puts("[ACPI]   CPU ");
                            s.dec(lapic.processor_id as u64);
                            s.puts(" APIC_ID=");
                            s.dec(lapic.apic_id as u64);
                            if is_bsp { s.puts(" (BSP)"); }
                            s.putc(b'\n');
                        }
                    }
                }
            }
            MADT_TYPE_IO_APIC => {
                if entry_len >= core::mem::size_of::<MadtIoApic>() {
                    let io_apic = unsafe { &*(base_ptr.add(offset) as *const MadtIoApic) };
                    info.io_apic_addr = io_apic.address;
                    info.io_apic_gsi_base = io_apic.gsi_base;

                    {
                        let s = crate::SerialGuard::acquire();
                        s.puts("[ACPI]   I/O APIC id=");
                        s.dec(io_apic.id as u64);
                        s.puts(" addr=");
                        s.hex(io_apic.address as u64);
                        s.puts(" gsi_base=");
                        s.dec(io_apic.gsi_base as u64);
                        s.putc(b'\n');
                    }
                }
            }
            _ => {
                // Skip unknown entry types
            }
        }

        offset += entry_len;
    }

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[ACPI] Found ");
        s.dec(info.cpu_count as u64);
        s.puts(" CPU(s)\n");
    }

    if info.cpu_count > 0 {
        Some(info)
    } else {
        None
    }
}

/// ACPI power management info extracted from FADT
pub struct AcpiPowerInfo {
    /// PM1a Control Block I/O port
    pub pm1a_cnt_blk: u16,
    /// PM1b Control Block I/O port (0 if not present)
    pub pm1b_cnt_blk: u16,
    /// SLP_TYPa value for S5 (deep power off)
    pub slp_typ_s5: u16,
    /// Whether the FADT was successfully parsed
    pub valid: bool,
}

static mut ACPI_POWER: AcpiPowerInfo = AcpiPowerInfo {
    pm1a_cnt_blk: 0,
    pm1b_cnt_blk: 0,
    slp_typ_s5: 0,
    valid: false,
};

/// FADT (Fixed ACPI Description Table) — partial definition
/// We only need fields up to pm1b_cnt_blk (offset 68 + 4 = 72 bytes)
#[repr(C, packed)]
struct Fadt {
    header: SdtHeader,          // 0..36
    firmware_ctrl: u32,         // 36
    dsdt: u32,                  // 40
    _reserved1: u8,             // 44
    preferred_pm_profile: u8,   // 45
    sci_int: u16,               // 46
    smi_cmd: u32,               // 48
    acpi_enable: u8,            // 52
    acpi_disable: u8,           // 53
    s4bios_req: u8,             // 54
    pstate_cnt: u8,             // 55
    pm1a_evt_blk: u32,          // 56
    pm1b_evt_blk: u32,          // 60
    pm1a_cnt_blk: u32,          // 64
    pm1b_cnt_blk: u32,          // 68
}

/// Search XSDT (64-bit pointers) for the FADT table (signature "FACP")
unsafe fn find_fadt_in_xsdt(xsdt_phys: u64) -> Option<u64> {
    let xsdt_ptr: *const SdtHeader = phys_to_ptr(xsdt_phys);
    let xsdt = unsafe { &*xsdt_ptr };

    let header_size = core::mem::size_of::<SdtHeader>();
    let entry_count = (xsdt.length as usize - header_size) / 8;
    let entries_ptr = unsafe { (xsdt_ptr as *const u8).add(header_size) as *const u64 };

    for i in 0..entry_count {
        let table_phys = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) };
        let table_hdr: *const SdtHeader = phys_to_ptr(table_phys);
        let sig = unsafe { (*table_hdr).signature };
        if &sig == b"FACP" {
            return Some(table_phys);
        }
    }
    None
}

/// Search RSDT (32-bit pointers) for the FADT table (signature "FACP")
unsafe fn find_fadt_in_rsdt(rsdt_phys: u64) -> Option<u64> {
    let rsdt_ptr: *const SdtHeader = phys_to_ptr(rsdt_phys);
    let rsdt = unsafe { &*rsdt_ptr };

    let header_size = core::mem::size_of::<SdtHeader>();
    let entry_count = (rsdt.length as usize - header_size) / 4;
    let entries_ptr = unsafe { (rsdt_ptr as *const u8).add(header_size) as *const u32 };

    for i in 0..entry_count {
        let table_phys = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) } as u64;
        let table_hdr: *const SdtHeader = phys_to_ptr(table_phys);
        let sig = unsafe { (*table_hdr).signature };
        if &sig == b"FACP" {
            return Some(table_phys);
        }
    }
    None
}

/// Parse the FADT to extract PM1a/PM1b control block ports for shutdown.
///
/// # Safety
/// `rsdp_phys` must be a valid physical address of the ACPI RSDP structure.
pub unsafe fn parse_fadt(rsdp_phys: u64) {
    if rsdp_phys == 0 {
        return;
    }

    let rsdp_ptr: *const Rsdp = phys_to_ptr(rsdp_phys);
    let rsdp = unsafe { &*rsdp_ptr };

    if &rsdp.signature != b"RSD PTR " {
        return;
    }

    let fadt_phys = if rsdp.revision >= 2 {
        let rsdp2 = unsafe { &*(rsdp_ptr as *const Rsdp2) };
        unsafe { find_fadt_in_xsdt(rsdp2.xsdt_address) }
    } else {
        unsafe { find_fadt_in_rsdt(rsdp.rsdt_address as u64) }
    };

    let fadt_phys = match fadt_phys {
        Some(addr) => addr,
        None => {
            crate::serial_puts("[ACPI] FADT not found\n");
            return;
        }
    };

    let fadt_ptr: *const Fadt = phys_to_ptr(fadt_phys);
    let fadt = unsafe { &*fadt_ptr };

    // Validate minimum length
    if (fadt.header.length as usize) < core::mem::size_of::<Fadt>() {
        crate::serial_puts("[ACPI] FADT too short\n");
        return;
    }

    let pm1a = fadt.pm1a_cnt_blk as u16;
    let pm1b = fadt.pm1b_cnt_blk as u16;

    unsafe {
        ACPI_POWER.pm1a_cnt_blk = pm1a;
        ACPI_POWER.pm1b_cnt_blk = pm1b;
        // QEMU uses SLP_TYPa=0 for S5 on i440fx/Q35
        ACPI_POWER.slp_typ_s5 = 0;
        ACPI_POWER.valid = pm1a != 0;
    }

    {
        let s = crate::SerialGuard::acquire();
        s.puts("[ACPI] FADT parsed: PM1a_CNT=");
        s.hex(pm1a as u64);
        s.puts(" PM1b_CNT=");
        s.hex(pm1b as u64);
        s.putc(b'\n');
    }
}

/// Get the parsed ACPI power management info.
pub fn get_power_info() -> &'static AcpiPowerInfo {
    // SAFETY: ACPI_POWER is only written during boot (single-threaded).
    unsafe { &*(&raw const ACPI_POWER) }
}

/// Read the BSP's Local APIC ID from the APIC ID register
unsafe fn read_bsp_apic_id() -> u8 {
    let apic_base = super::apic::LAPIC_BASE + PHYS_MAP_OFFSET;
    let id_reg = unsafe { ((apic_base + super::apic::LAPIC_ID as u64) as *const u32).read_volatile() };
    // APIC ID is in bits 24-31
    ((id_reg >> 24) & 0xFF) as u8
}
