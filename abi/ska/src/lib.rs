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

    /// Size of this BootInfo struct in bytes (for forward compatibility)
    pub size: u32,

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

    /// Optional extra data (TLV) physical pointer
    pub extra: PhysAddr,

    /// Optional extra data length
    pub extra_len: u32,
}

// ============================================================================
// BootInfo Extras (TLV)
// ============================================================================
/// Extra entry header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExtraHeader {
    pub kind: u32,
    pub len: u32,
}

/// Extra entry kinds
pub const EXTRA_KIND_MEM_RESERVED: u32 = 1;

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

// ============================================================================
// Memory Layout Constants
// ============================================================================
/// Page size constant
pub const PAGE_SIZE: u64 = 4096;

/// Kernel physical base address (where bootloader loads kernel)
pub const KERNEL_PHYS_BASE: u64 = 0x0020_0000;

/// Kernel virtual base address (higher-half kernel)
pub const KERNEL_VIRT_BASE: u64 = 0xffff_ffff_8000_0000;

/// Direct map offset for physical memory access
pub const DIRECT_MAP_OFFSET: u64 = 0xffff_8800_0000_0000;

/// Kernel heap base virtual address
pub const KERNEL_HEAP_BASE: u64 = 0xffff_8900_0000_0000;

/// Initial kernel heap size (256 MB)
pub const KERNEL_HEAP_SIZE: usize = 256 * 1024 * 1024;

/// Maximum managed physical memory (8 GiB)
pub const MAX_MANAGED_MEMORY: u64 = 8 * 1024 * 1024 * 1024;

/// Size of kernel image (2 MB)
pub const KERNEL_SIZE: u64 = 0x0020_0000;

// User space memory layout
/// User code base address
pub const USER_CODE_BASE: u64 = 0x0000_0000_4000_0000;

/// User stack base address
pub const USER_STACK_BASE: u64 = USER_CODE_BASE + 0x0000_0000_0010_0000;

/// User stack size (4 pages = 16 KiB)
pub const USER_STACK_SIZE: u64 = 4096 * 4;

/// User stack pages count
pub const USER_STACK_PAGES: u64 = 4;

// ============================================================================
// BootInfo Constants
// ============================================================================
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
