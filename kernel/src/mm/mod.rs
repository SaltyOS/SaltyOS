//! Memory Management
//!
//! Physical frame allocator, virtual address spaces, slab allocator.
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod frame;
mod slab;
mod vspace;

pub use frame::FrameAllocator;
pub use vspace::VSpace;

use crate::BootInfo;

/// Page size (4KB)
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

/// Physical address type
pub type PhysAddr = u64;

/// Virtual address type
pub type VirtAddr = u64;

/// Global frame allocator
static mut FRAME_ALLOCATOR: Option<FrameAllocator> = None;

/// Initialize memory management from boot info
pub fn init(boot_info: &BootInfo) {
    // SAFETY: Single-threaded initialization
    unsafe {
        (*(&raw mut FRAME_ALLOCATOR)) = Some(FrameAllocator::new(boot_info));
    }
}

/// Allocate a physical frame
pub fn alloc_frame() -> Option<PhysAddr> {
    // SAFETY: Single-threaded access, interrupts disabled during allocation
    unsafe { (*(&raw mut FRAME_ALLOCATOR)).as_mut()?.alloc() }
}

/// Free a physical frame
pub fn free_frame(addr: PhysAddr) {
    // SAFETY: Single-threaded access, interrupts disabled during deallocation
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.free(addr);
        }
    }
}
