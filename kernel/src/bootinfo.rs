//! BootInfo TLV Parser
//!
//! Parses the TLV-encoded BootInfo structure passed from the bootloader.
//! See `boot/common/bootinfo_tlv.h` for the format specification.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// BootInfo magic: "SALTYBOO" in little-endian
const BOOTINFO_MAGIC: u64 = 0x53414C5459424F4F;
const BOOTINFO_VERSION: u16 = 1;

/// Maximum memory map entries we support
const MAX_MEMMAP_ENTRIES: usize = 256;

// TLV type identifiers (matches bootinfo_tlv.h)
const TLV_END: u16 = 0;
const TLV_MEMMAP: u16 = 1;
const TLV_KERNEL_IMAGE: u16 = 2;
const TLV_INITRD: u16 = 3;
const TLV_FRAMEBUFFER: u16 = 5;
const TLV_ACPI_RSDP: u16 = 6;

/// BootInfo header flags
pub const BOOTINFO_FLAG_UEFI_BOOT: u32 = 1 << 0;
pub const BOOTINFO_FLAG_STAGE3_EL2: u32 = 1 << 4;

/// Raw BootInfo header (matches C struct exactly)
#[repr(C, packed)]
struct RawBootInfoHeader {
    magic: u64,
    version: u16,
    arch: u16,
    total_size: u32,
    flags: u32,
    reserved: u32,
}

/// Raw TLV header
#[repr(C, packed)]
struct RawTlvHeader {
    tlv_type: u16,
    reserved: u16,
    length: u32,
}

/// Raw memory map entry (matches C struct)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RawMemMapEntry {
    base: u64,
    length: u64,
    mem_type: u32,
    reserved: u32,
}

/// Raw kernel image info
#[repr(C, packed)]
struct RawKernelImage {
    phys_base: u64,
    virt_base: u64,
    size: u64,
    entry_point: u64,
}

/// Raw initrd info
#[repr(C, packed)]
struct RawInitrd {
    phys_addr: u64,
    size: u64,
}

/// Raw framebuffer info
#[repr(C, packed)]
struct RawFramebuffer {
    phys_addr: u64,
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u32,
    red_pos: u8,
    red_size: u8,
    green_pos: u8,
    green_size: u8,
    blue_pos: u8,
    blue_size: u8,
    reserved: [u8; 2],
}

/// Raw ACPI RSDP info
#[repr(C, packed)]
struct RawAcpiRsdp {
    rsdp_addr: u64,
    revision: u8,
    reserved: [u8; 7],
}

/// Memory region type (matches bootloader ABI in bootinfo_tlv.h)
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemoryKind {
    Usable = 1,
    Reserved = 2,
    AcpiReclaimable = 3,
    AcpiNvs = 4,
    BadMemory = 5,
    Bootloader = 16,
    Kernel = 17,
    Initrd = 18,
    BootInfo = 19,
}

impl MemoryKind {
    fn from_raw(val: u32) -> Self {
        match val {
            1 => MemoryKind::Usable,
            2 => MemoryKind::Reserved,
            3 => MemoryKind::AcpiReclaimable,
            4 => MemoryKind::AcpiNvs,
            5 => MemoryKind::BadMemory,
            16 => MemoryKind::Bootloader,
            17 => MemoryKind::Kernel,
            18 => MemoryKind::Initrd,
            19 => MemoryKind::BootInfo,
            _ => MemoryKind::Reserved,
        }
    }
}

/// Memory map entry (kernel-side)
#[derive(Clone, Copy)]
pub struct MemoryMapEntry {
    pub base: u64,
    pub length: u64,
    pub kind: MemoryKind,
}

/// Framebuffer information
#[derive(Clone, Copy)]
pub struct FramebufferInfo {
    pub addr: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
    pub red_pos: u8,
    pub red_size: u8,
    pub green_pos: u8,
    pub green_size: u8,
    pub blue_pos: u8,
    pub blue_size: u8,
}

/// Parsed boot information (kernel-internal representation)
pub struct ParsedBootInfo {
    pub flags: u32,
    pub memory_map: [MemoryMapEntry; MAX_MEMMAP_ENTRIES],
    pub memory_map_len: usize,
    pub kernel_phys_base: u64,
    pub kernel_virt_base: u64,
    pub kernel_size: u64,
    pub initrd_addr: u64,
    pub initrd_size: u64,
    pub rsdp_addr: u64,
    pub framebuffer: FramebufferInfo,
}

/// Static storage for parsed boot info (placed in .bss, ~3KB)
static mut PARSED_BOOT_INFO: ParsedBootInfo = ParsedBootInfo {
    flags: 0,
    memory_map: [MemoryMapEntry {
        base: 0,
        length: 0,
        kind: MemoryKind::Reserved,
    }; MAX_MEMMAP_ENTRIES],
    memory_map_len: 0,
    kernel_phys_base: 0,
    kernel_virt_base: 0,
    kernel_size: 0,
    initrd_addr: 0,
    initrd_size: 0,
    rsdp_addr: 0,
    framebuffer: FramebufferInfo {
        addr: 0,
        width: 0,
        height: 0,
        pitch: 0,
        bpp: 0,
        red_pos: 0,
        red_size: 0,
        green_pos: 0,
        green_size: 0,
        blue_pos: 0,
        blue_size: 0,
    },
};

/// Align value up to 8-byte boundary
#[inline]
const fn align_up_8(val: u32) -> u32 {
    (val + 7) & !7
}

/// Parse TLV-encoded BootInfo from raw pointer.
///
/// Returns a reference to the static `ParsedBootInfo` on success.
///
/// # Safety
/// - `ptr` must point to a valid BootInfo TLV structure written by the bootloader.
/// - Must only be called once during early kernel init (single-threaded).
pub unsafe fn parse(ptr: *const u8) -> Option<&'static ParsedBootInfo> {
    if ptr.is_null() {
        return None;
    }

    unsafe {
        // Read and validate header
        let hdr = &*(ptr as *const RawBootInfoHeader);
        if hdr.magic != BOOTINFO_MAGIC {
            return None;
        }
        if hdr.version != BOOTINFO_VERSION {
            return None;
        }

        let total_size = hdr.total_size as usize;
        let hdr_size = core::mem::size_of::<RawBootInfoHeader>();
        let tlv_hdr_size = core::mem::size_of::<RawTlvHeader>();

        if total_size < hdr_size {
            return None;
        }

        let info = &mut *(&raw mut PARSED_BOOT_INFO);
        info.flags = hdr.flags;

        // Walk TLV records
        let mut offset = hdr_size;

        while offset + tlv_hdr_size <= total_size {
            let tlv = &*(ptr.add(offset) as *const RawTlvHeader);

            if tlv.tlv_type == TLV_END {
                break;
            }

            let data_ptr = ptr.add(offset + tlv_hdr_size);
            let data_len = tlv.length as usize;

            match tlv.tlv_type {
                TLV_MEMMAP => {
                    let entry_size = core::mem::size_of::<RawMemMapEntry>();
                    let count = data_len / entry_size;
                    let count = if count > MAX_MEMMAP_ENTRIES {
                        MAX_MEMMAP_ENTRIES
                    } else {
                        count
                    };

                    for i in 0..count {
                        let raw = &*(data_ptr.add(i * entry_size) as *const RawMemMapEntry);
                        info.memory_map[i] = MemoryMapEntry {
                            base: raw.base,
                            length: raw.length,
                            kind: MemoryKind::from_raw(raw.mem_type),
                        };
                    }
                    info.memory_map_len = count;
                }
                TLV_KERNEL_IMAGE => {
                    if data_len >= core::mem::size_of::<RawKernelImage>() {
                        let ki = &*(data_ptr as *const RawKernelImage);
                        info.kernel_phys_base = ki.phys_base;
                        info.kernel_virt_base = ki.virt_base;
                        info.kernel_size = ki.size;
                    }
                }
                TLV_INITRD => {
                    if data_len >= core::mem::size_of::<RawInitrd>() {
                        let initrd = &*(data_ptr as *const RawInitrd);
                        info.initrd_addr = initrd.phys_addr;
                        info.initrd_size = initrd.size;
                    }
                }
                TLV_FRAMEBUFFER => {
                    if data_len >= core::mem::size_of::<RawFramebuffer>() {
                        let fb = &*(data_ptr as *const RawFramebuffer);
                        info.framebuffer = FramebufferInfo {
                            addr: fb.phys_addr,
                            width: fb.width,
                            height: fb.height,
                            pitch: fb.pitch,
                            bpp: fb.bpp as u8,
                            red_pos: fb.red_pos,
                            red_size: fb.red_size,
                            green_pos: fb.green_pos,
                            green_size: fb.green_size,
                            blue_pos: fb.blue_pos,
                            blue_size: fb.blue_size,
                        };
                    }
                }
                TLV_ACPI_RSDP => {
                    if data_len >= core::mem::size_of::<RawAcpiRsdp>() {
                        let acpi = &*(data_ptr as *const RawAcpiRsdp);
                        info.rsdp_addr = acpi.rsdp_addr;
                    }
                }
                _ => { /* skip unknown TLV types */ }
            }

            // Advance to next TLV (8-byte aligned)
            offset += tlv_hdr_size + align_up_8(tlv.length) as usize;
        }

        Some(&*(&raw const PARSED_BOOT_INFO))
    }
}
