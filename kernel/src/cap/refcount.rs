//! Reference Counting for Kernel Objects
//!
//! Inline reference counting in KernelObject for proper lifecycle management.
//! When refcount reaches zero, object-specific cleanup is performed.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::object::{KernelObject, ObjectType};
use core::sync::atomic::Ordering;

/// Release object (called by delete_capability)
///
/// Decrements reference count and destroys object if it reaches zero.
///
/// # Safety
/// obj must be a valid pointer to a KernelObject.
pub unsafe fn release_object(obj: *mut KernelObject, obj_type: ObjectType) {
    if obj.is_null() {
        return;
    }

    unsafe {
        // Decrement refcount
        let old_count = (*obj).ref_count.fetch_sub(1, Ordering::AcqRel);

        if old_count == 1 {
            // Last reference - destroy object
            destroy_object(obj, obj_type);
        }
    }
}

/// Increment object reference count
///
/// # Safety
/// obj must be a valid pointer to a KernelObject.
pub unsafe fn increment_refcount(obj: *mut KernelObject) -> u32 {
    if obj.is_null() {
        return 0;
    }
    unsafe { (*obj).ref_count.fetch_add(1, Ordering::AcqRel) + 1 }
}

/// Get current reference count
///
/// # Safety
/// obj must be a valid pointer to a KernelObject.
pub unsafe fn get_refcount(obj: *mut KernelObject) -> u32 {
    if obj.is_null() {
        return 0;
    }
    unsafe { (*obj).ref_count.load(Ordering::Acquire) }
}

/// Destroy object when refcount reaches zero
///
/// # Safety
/// obj must be a valid pointer to a KernelObject with no remaining references.
unsafe fn destroy_object(obj: *mut KernelObject, obj_type: ObjectType) {
    unsafe {
        match obj_type {
            ObjectType::Endpoint => {
                // Wake any blocked threads
                let ep = &mut *(obj as *mut crate::ipc::Endpoint);
                ep.cleanup();
            }

            ObjectType::Notification => {
                // Wake any waiting thread
                let notif = &mut *(obj as *mut crate::ipc::Notification);
                notif.cleanup();
            }

            ObjectType::Untyped => {
                // Untyped memory freed back to frame allocator
                let untyped = &mut *(obj as *mut super::untyped::UntypedMemory);
                let size_bytes = untyped.size_bytes();
                crate::mm::free_frames(untyped.phys_addr, size_bytes);
            }

            ObjectType::Frame => {
                // Frame object ownership is released independently of mappings.
                let frame = &mut *(obj as *mut super::untyped::FrameObject);
                crate::mm::release_frame_object(frame.phys_addr, frame.size_bits);
            }

            ObjectType::CNode => {
                // CNode cleanup: delete all capabilities stored in slots
                let cnode = &mut *(obj as *mut super::cnode::CNode);
                let num_slots = cnode.num_slots();

                #[cfg(debug_assertions)]
                crate::println!("[REFCOUNT] CNode destroy: cleaning up {} slots", num_slots);

                // Iterate all slots and delete any non-null capabilities.
                // delete_capability is idempotent (checks SlotState::Free) and
                // safe to call recursively (bounded by MAX_RESOLVE_DEPTH).
                for i in 0..num_slots {
                    // SAFETY: slot_ptr is within bounds (i < num_slots)
                    let cap_ref = *cnode.slot_ptr(i);
                    if cap_ref.slot != super::slot::INVALID_SLOT {
                        super::cdt::CDT::delete_capability(cap_ref.slot);
                    }
                }

                #[cfg(debug_assertions)]
                crate::println!("[REFCOUNT] CNode destroy: cleanup complete");
            }

            ObjectType::VSpace => {
                // Page table cleanup
                let vspace = &mut *(obj as *mut crate::mm::VSpace);

                #[cfg(debug_assertions)]
                crate::println!("[REFCOUNT] VSpace destroy: cleaning up page tables");

                vspace.cleanup();

                #[cfg(debug_assertions)]
                crate::println!("[REFCOUNT] VSpace destroy: cleanup complete");
            }

            ObjectType::Tcb => {
                // Thread cleanup
                let tcb = &mut *(obj as *mut crate::sched::thread::Tcb);
                tcb.cleanup();
            }

            ObjectType::IrqHandler => {
                let irq = &mut *(obj as *mut crate::ipc::IrqHandler);
                irq.cleanup();
            }

            ObjectType::IoPort => {
                // I/O port capability - no cleanup needed
            }

            ObjectType::SchedContext => {
                // Scheduling context cleanup
                let sc = &mut *(obj as *mut crate::sched::thread::SchedContext);
                sc.cleanup();
            }

            ObjectType::Null => {
                // Nothing to do
            }
        }
    }
}

/// Extension trait for cleanup operations
pub trait Cleanup {
    /// Cleanup resources when object is destroyed
    fn cleanup(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refcount_increment() {
        let obj = KernelObject::new(ObjectType::Endpoint, 4);

        assert_eq!(obj.ref_count.load(Ordering::Acquire), 1);
        unsafe {
            increment_refcount(&obj as *const _ as *mut _);
        }
        assert_eq!(obj.ref_count.load(Ordering::Acquire), 2);
    }
}
