//! Slab Allocator for kernel objects
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::PAGE_SIZE;

/// Slab header at start of each slab
#[repr(C)]
struct SlabHeader {
    next: *mut SlabHeader,
    free_list: *mut FreeObject,
    used_count: usize,
    total_count: usize,
}

/// Free object in slab (uses object memory for next pointer)
#[repr(C)]
struct FreeObject {
    next: *mut FreeObject,
}

/// Slab allocator for fixed-size objects
pub struct SlabAllocator {
    /// Object size
    obj_size: usize,
    /// First slab
    slab_list: *mut SlabHeader,
}

impl SlabAllocator {
    pub const fn new(obj_size: usize) -> Self {
        Self {
            obj_size,
            slab_list: core::ptr::null_mut(),
        }
    }

    /// Allocate an object
    pub fn alloc(&mut self) -> Option<*mut u8> {
        // Find a slab with free objects
        let mut slab = self.slab_list;
        while !slab.is_null() {
            unsafe {
                if !(*slab).free_list.is_null() {
                    let obj = (*slab).free_list;
                    (*slab).free_list = (*obj).next;
                    (*slab).used_count += 1;
                    return Some(obj as *mut u8);
                }
                slab = (*slab).next;
            }
        }

        // No free objects, need to allocate new slab
        // TODO: Allocate new slab from frame allocator
        None
    }

    /// Free an object
    pub fn free(&mut self, ptr: *mut u8) {
        // Find which slab this object belongs to
        let mut slab = self.slab_list;
        while !slab.is_null() {
            unsafe {
                let slab_start = slab as usize;
                let slab_end = slab_start + PAGE_SIZE;
                let ptr_addr = ptr as usize;

                if ptr_addr >= slab_start && ptr_addr < slab_end {
                    let obj = ptr as *mut FreeObject;
                    (*obj).next = (*slab).free_list;
                    (*slab).free_list = obj;
                    (*slab).used_count -= 1;
                    return;
                }
                slab = (*slab).next;
            }
        }
    }
}
