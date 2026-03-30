//! NodeAllocator trait — generic page-granular allocator interface.
//!
//! Used by Maple tree and radix tree. Decouples data structure code
//! from PMM, enabling host-side unit testing with a static bump allocator.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// Page-granular node allocator.
///
/// All allocations are exactly one page (4096 bytes), returned zeroed.
/// Implementations must be safe to call from interrupt-disabled contexts.
pub trait NodeAllocator {
    /// Allocate a zeroed page. Returns null on failure.
    fn alloc_node(&mut self) -> *mut u8;

    /// Free a previously allocated page.
    ///
    /// # Safety
    /// `ptr` must have been returned by `alloc_node` and not yet freed.
    unsafe fn free_node(&mut self, ptr: *mut u8);
}

/// PMM-backed NodeAllocator for kernel use.
///
/// Tags allocated pages with the specified `FrameOwner`.
/// Caller chooses the owner (e.g., `KernelPrivate { MapleNode }`
/// for VSpace Maple tree, or `MoMeta { Radix }` for MO page tree).
///
/// If `use_reserve` is true, falls back to the emergency reserve pool
/// when the main pool is exhausted. Use this only in fault handlers.
pub struct PmmNodeAllocator {
    pub owner: super::frame::FrameOwner,
    pub use_reserve: bool,
}

impl NodeAllocator for PmmNodeAllocator {
    fn alloc_node(&mut self) -> *mut u8 {
        let phys = match super::pmm_alloc(&self.owner) {
            Some(p) => p,
            None => {
                if !self.use_reserve {
                    return core::ptr::null_mut();
                }
                match super::pmm_alloc_reserve() {
                    Some(p) => p,
                    None => return core::ptr::null_mut(),
                }
            }
        };
        let virt = super::phys_to_virt(phys) as *mut u8;
        unsafe {
            core::ptr::write_bytes(virt, 0, super::PAGE_SIZE);
        }
        virt
    }

    unsafe fn free_node(&mut self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }
        let phys = super::virt_to_phys(ptr as u64);
        super::pmm_free(phys, &self.owner);
    }
}
