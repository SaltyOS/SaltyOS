//! Memory Management
//!
//! Physical frame allocator, virtual address spaces, slab allocator.
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod frame;
mod slab;
pub mod vspace;

pub use frame::FrameAllocator;
pub use vspace::{
    advance_quiescent_gen, current_vspace_tracking, kernel_vspace_root, kernel_vspace_tracking,
    process_deferred_free, restore_irq, save_irq_disable, set_current_vspace_tracking,
    set_pending_deactivate, take_pending_deactivate, DeactivateResult, VSpace, VSpaceTracking,
};

use crate::BootInfo;

/// Page size (4KB)
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

/// Direct physical mapping offset
/// Physical memory is mapped at this virtual address
pub const PHYS_MAP_OFFSET: u64 = 0xFFFF_8000_0000_0000;

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

/// Free multiple contiguous frames
pub fn free_frames(addr: PhysAddr, size_bytes: usize) {
    let num_frames = (size_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    for i in 0..num_frames {
        free_frame(addr + (i * PAGE_SIZE) as u64);
    }
}

/// Align value up to alignment boundary
#[inline]
pub const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// Align value down to alignment boundary
#[inline]
pub const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

/// Check if value is aligned to alignment boundary
#[inline]
pub const fn is_aligned(value: usize, align: usize) -> bool {
    value & (align - 1) == 0
}

/// Convert physical address to virtual address (direct mapping)
#[inline]
pub const fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    phys + PHYS_MAP_OFFSET
}

/// Convert virtual address to physical address (direct mapping)
#[inline]
pub const fn virt_to_phys(virt: VirtAddr) -> PhysAddr {
    virt - PHYS_MAP_OFFSET
}
