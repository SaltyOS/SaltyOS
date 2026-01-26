// SaltyKernel ABI (SKA) - Bootloader→Kernel Contract
#![no_std]

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootInfo {
    /// Magic number: "SKA\0"
    pub magic: [u8; 4],

    /// Version number (MAJOR.MINOR in high/low bytes)
    pub version: u32,

    /// Boot flags
    pub flags: BootFlags,

    /// Memory map pointer (physical address)
    pub memory_map: PhysAddr,

    /// Number of memory map entries
    pub memory_map_entries: u32,

    /// Framebuffer information (if available)
    pub framebuffer: Option<FramebufferInfo>,

    /// Initrd module (if available)
    pub initrd: Option<ModuleInfo>,

    /// Command line (physical address)
    pub cmdline: PhysAddr,

    /// Command line length
    pub cmdline_len: u32,

    /// ACPI RSDP pointer (optional)
    pub rsdp: Option<PhysAddr>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryEntry {
    /// Base physical address
    pub base: PhysAddr,

    /// Length in bytes
    pub length: u64,

    /// Memory type
    pub mem_type: MemoryType,

    /// ACPI extended attributes (optional)
    pub acpi_attrs: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    /// Usable RAM
    Usable = 1,

    /// Reserved, do not use
    Reserved = 2,

    /// ACPI Reclaimable
    AcpiReclaimable = 3,

    /// ACPI NVS Memory
    AcpiNvs = 4,

    /// Unusable memory
    Unusable = 5,

    /// Disabled (BIOS-specific)
    Disabled = 6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical address of framebuffer
    pub address: PhysAddr,

    /// Width in pixels
    pub width: u32,

    /// Height in pixels
    pub height: u32,

    /// Pitch (bytes per line)
    pub pitch: u32,

    /// Pixel format
    pub format: PixelFormat,

    /// Bits per pixel
    pub bpp: u8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// RGB (8:8:8)
    Rgb,

    /// BGR (8:8:8)
    Bgr,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ModuleInfo {
    /// Physical address of module
    pub address: PhysAddr,

    /// Module size in bytes
    pub size: u64,

    /// Module name (optional)
    pub name: [u8; 64],
}

bitflags::bitflags! {
    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct BootFlags: u32 {
        /// Bootloader was UEFI
        const UEFI = 1 << 0;

        /// Bootloader was BIOS/legacy
        const BIOS = 1 << 1;

        /// Framebuffer is available
        const FRAMEBUFFER = 1 << 2;

        /// ACPI is available
        const ACPI = 1 << 3;

        /// Initrd is available
        const INITRD = 1 << 4;
    }
}

/// Physical address type
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysAddr(pub u64);

impl PhysAddr {
    /// Create a new physical address
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Get the address value
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Align down to page boundary
    #[inline]
    pub const fn align_down(&self, align: u64) -> Self {
        Self(self.0 & !(align - 1))
    }

    /// Align up to page boundary
    #[inline]
    pub const fn align_up(&self, align: u64) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    /// Check if aligned
    #[inline]
    pub const fn is_aligned(&self, align: u64) -> bool {
        self.0 % align == 0
    }
}

/// Page size constant
pub const PAGE_SIZE: u64 = 4096;

/// Magic number for BootInfo
pub const BOOTINFO_MAGIC: &[u8; 4] = b"SKA\0";

/// Current BootInfo version
pub const BOOTINFO_VERSION: u32 = 0x0001; // v0.1

impl BootInfo {
    /// Validate the boot info
    pub fn validate(&self) -> bool {
        self.magic == *BOOTINFO_MAGIC
            && self.version == BOOTINFO_VERSION
    }
}
