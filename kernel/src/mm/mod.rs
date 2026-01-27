//! SaltyOS Memory Management
//!
//! Phase 2: Physical frame allocation, virtual memory, kernel heap, and pager interface.

pub mod physical;
pub mod vm;
pub mod heap;
pub mod pager;

pub use physical::{Frame, FrameNumber, allocate_frame, deallocate_frame};
// Note: These are exported for API use but may trigger unused warnings
#[allow(dead_code)]
pub use vm::{PageFlags, map_page, unmap_page, flush_tlb};
#[allow(dead_code)]
pub use heap::{heap_alloc, heap_free};
pub use pager::handle_page_fault;

use saltyos_ska::{BootInfo, KERNEL_PHYS_BASE, KERNEL_VIRT_BASE,
                    DIRECT_MAP_OFFSET, KERNEL_HEAP_BASE, KERNEL_SIZE,
                    MAX_MANAGED_MEMORY, PAGE_SIZE};

/// Initialize memory management subsystem
///
/// # Safety
/// Must be called once during kernel initialization with a valid BootInfo pointer.
pub unsafe fn init(bootinfo: &BootInfo) {
    // 1. Physical allocator (must be first)
    physical::init(bootinfo);

    // 2. Virtual memory (sets up direct map)
    vm::init(bootinfo);

    // 3. Kernel heap (uses KERNEL_HEAP_BASE, not direct map)
    heap::init(bootinfo);

    // 4. Pager interface
    pager::init(bootinfo);
}

/// Virtual address type
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(pub u64);

impl VirtAddr {
    /// Create a new virtual address
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
    pub fn align_down(&self, align: u64) -> Self {
        Self(self.0 & !(align - 1))
    }

    /// Align up to page boundary
    #[inline]
    pub fn align_up(&self, align: u64) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    /// Check if aligned
    #[inline]
    pub const fn is_aligned(&self, align: u64) -> bool {
        self.0 % align == 0
    }
}
