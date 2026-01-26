//! SSABI types

#![no_std]

use core::fmt;

/// Thread ID
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ThreadId(pub u64);

impl ThreadId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Capability handle (unforgeable reference to kernel object)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CapHandle {
    pub id: u64,
}

impl CapHandle {
    pub const INVALID: Self = Self { id: 0 };

    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    pub const fn is_valid(self) -> bool {
        self.id != 0
    }

    pub const fn as_u64(self) -> u64 {
        self.id
    }
}

impl fmt::Debug for CapHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cap({:#x})", self.id)
    }
}

impl From<u64> for CapHandle {
    fn from(id: u64) -> Self {
        Self { id }
    }
}

/// Address space handle
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct AddressSpace(pub CapHandle);

impl AddressSpace {
    pub const fn new(cap: CapHandle) -> Self {
        Self(cap)
    }

    pub const fn cap(self) -> CapHandle {
        self.0
    }
}

/// IPC endpoint
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Endpoint(pub CapHandle);

impl Endpoint {
    pub const fn new(cap: CapHandle) -> Self {
        Self(cap)
    }

    pub const fn cap(self) -> CapHandle {
        self.0
    }
}

/// Physical address
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(pub u64);

impl PhysAddr {
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

impl From<u64> for PhysAddr {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

/// Virtual address
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(pub u64);

impl VirtAddr {
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Check if address is aligned to given page size
    pub const fn is_aligned_to(self, align: usize) -> bool {
        self.0 as usize % align == 0
    }

    /// Align address down to page boundary
    pub const fn align_down_to(self, align: usize) -> Self {
        Self(self.0 & !(align as u64 - 1))
    }

    /// Align address up to page boundary
    pub const fn align_up_to(self, align: usize) -> Self {
        Self((self.0 + (align as u64 - 1)) & !(align as u64 - 1))
    }

    /// Add offset to address
    pub fn checked_add(self, offset: u64) -> Option<Self> {
        self.0.checked_add(offset).map(VirtAddr)
    }
}

impl From<u64> for VirtAddr {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

/// Memory capability
#[derive(Clone, Copy)]
#[repr(C)]
pub struct MemCap {
    pub handle: CapHandle,
    pub size: usize,
    pub mem_type: MemType,
}

impl MemCap {
    pub const fn new(handle: CapHandle, size: usize, mem_type: MemType) -> Self {
        Self {
            handle,
            size,
            mem_type,
        }
    }
}

/// Memory type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MemType {
    /// Physical memory (for DMA, MMIO)
    Physical = 0,
    /// Anonymous (zero-filled) memory
    Anonymous = 1,
    /// File-backed memory (pager-controlled)
    FileBacked = 2,
    /// Shared memory (multiple mappings allowed)
    Shared = 3,
}

/// Protection flags for memory mappings
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ProtFlags(pub u8);

impl ProtFlags {
    pub const READ: u8 = 1 << 0;
    pub const WRITE: u8 = 1 << 1;
    pub const EXEC: u8 = 1 << 2;

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// Capability rights (permissions)
bitflags::bitflags! {
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct CapRights: u64 {
        const READ   = 1 << 0;
        const WRITE  = 1 << 1;
        const EXEC   = 1 << 2;
        const MAP    = 1 << 3;
        const IRQ    = 1 << 4;
        const SUBMIT = 1 << 5;
        const DUP    = 1 << 6;
        const REVOKE = 1 << 7;
    }
}

/// Capability type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CapType {
    /// IPC endpoint
    Endpoint = 0,
    /// Memory region
    Memory = 1,
    /// Address space
    AddressSpace = 2,
    /// IRQ line
    IrqLine = 3,
    /// Device (MMIO/IRQ bundle)
    Device = 4,
    /// DMA-capable buffer
    DmaBuffer = 5,
    /// Pager capability
    Pager = 6,
}

impl CapType {
    /// Convert from u8
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Endpoint),
            1 => Some(Self::Memory),
            2 => Some(Self::AddressSpace),
            3 => Some(Self::IrqLine),
            4 => Some(Self::Device),
            5 => Some(Self::DmaBuffer),
            6 => Some(Self::Pager),
            _ => None,
        }
    }

    /// Convert to u8
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}
