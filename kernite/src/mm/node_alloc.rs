//! NodeAllocator trait — generic page-granular allocator interface.
//!
//! Used by Maple tree and radix tree. Decouples data structure code
//! from PMM, enabling host-side unit testing with a static bump allocator.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::ptr::NonNull;

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

    /// Allocate a zeroed page wrapped in an owned handle.
    ///
    /// The returned [`OwnedMapleNode`] carries the exclusive right to either
    /// consume the page (by handing it to a data-structure routine that
    /// takes `OwnedMapleNode` by value) or return it to this allocator via
    /// [`free_owned_node`](Self::free_owned_node).
    fn alloc_node_owned(&mut self) -> Option<OwnedMapleNode> {
        let ptr = self.alloc_node();
        NonNull::new(ptr).map(|p| OwnedMapleNode { ptr: p })
    }

    /// Return an owned node handle to this allocator.
    fn free_owned_node(&mut self, node: OwnedMapleNode) {
        // SAFETY: `node.ptr` was produced by `alloc_node` (via
        // `alloc_node_owned`) and the owner relinquishes it here.
        unsafe { self.free_node(node.into_raw().as_ptr()) }
    }
}

/// Owned handle to a detached, zeroed allocator page.
///
/// Dropping this without routing it through either the consuming API that
/// accepted it or [`NodeAllocator::free_owned_node`] leaks the page. The
/// debug build asserts on drop to catch mistakes early; in release builds
/// the drop is silent to avoid kernel panics on logic errors.
#[must_use = "owned node must be consumed or returned to the allocator"]
pub struct OwnedMapleNode {
    ptr: NonNull<u8>,
}

impl OwnedMapleNode {
    /// Extract the raw pointer, consuming the handle.
    ///
    /// Only the allocator implementation and the data-structure routines
    /// that own node lifecycles should call this.
    pub fn into_raw(self) -> NonNull<u8> {
        let ptr = self.ptr;
        core::mem::forget(self);
        ptr
    }
}

impl Drop for OwnedMapleNode {
    fn drop(&mut self) {
        crate::kernel::bug::kassert!(
            false,
            "OwnedMapleNode dropped without consumption — node leaked"
        );
    }
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
                match super::pmm_alloc_reserve(&self.owner) {
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
