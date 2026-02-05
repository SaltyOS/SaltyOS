//! Untyped Memory Management
//!
//! Untyped memory is the raw memory from which all kernel objects are created.
//! This module implements retyping (allocating objects) and untyping (freeing),
//! with proper parent-child tracking via CDT.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::slot::{get_cap, get_meta, CapSlot, INVALID_SLOT};
use super::{CapError, ObjectType, CDT};
use crate::mm::{self, PhysAddr, PAGE_SIZE};

/// Untyped memory region
///
/// Represents a contiguous region of physical memory that can be
/// retyped into kernel objects.
#[repr(C)]
pub struct UntypedMemory {
    /// Kernel object header (must be first for refcount access)
    pub header: super::object::KernelObject,

    /// Physical address of the region
    pub phys_addr: PhysAddr,

    /// Size as power of 2 (e.g., 20 = 1MB, 12 = 4KB)
    pub size_bits: u8,

    /// Watermark - next offset to allocate from
    pub watermark: u32,

    /// Whether this is device memory (non-cacheable)
    pub is_device: bool,
}

impl UntypedMemory {
    pub const fn new(phys_addr: PhysAddr, size_bits: u8, is_device: bool) -> Self {
        Self {
            header: super::object::KernelObject::new(ObjectType::Untyped, size_bits),
            phys_addr,
            size_bits,
            watermark: 0,
            is_device,
        }
    }

    /// Get size in bytes
    pub fn size_bytes(&self) -> usize {
        1usize << self.size_bits
    }

    /// Get available bytes
    pub fn available(&self) -> usize {
        self.size_bytes() - (self.watermark as usize)
    }

    /// Check if untyped has children
    pub fn has_children(&self) -> bool {
        // Checked via ut_next links in slot metadata
        false // Placeholder - actual check is in UntypedTracker
    }
}

/// Single frame object (for Frame capabilities)
#[repr(C)]
pub struct FrameObject {
    /// Kernel object header (must be first for refcount access)
    pub header: super::object::KernelObject,
    pub phys_addr: PhysAddr,
    pub size_bits: u8,
}

impl FrameObject {
    pub const fn new(phys_addr: PhysAddr, size_bits: u8) -> Self {
        Self {
            header: super::object::KernelObject::new(ObjectType::Frame, size_bits),
            phys_addr,
            size_bits,
        }
    }

    pub fn size_bytes(&self) -> usize {
        1usize << self.size_bits
    }
}

/// Untyped child tracker
///
/// Tracks objects allocated from untyped memory using ut_next links
/// in slot metadata. This allows O(1) iteration over untyped's children.
pub struct UntypedTracker;

impl UntypedTracker {
    /// Add child to untyped's child list
    ///
    /// Called when an object is created via retype().
    /// Uses ut_first_child/ut_next links in slot metadata to build a linked list.
    /// This is separate from the CDT child list (cdt_first_child).
    pub fn add_child(untyped_slot: CapSlot, child_slot: CapSlot) {
        unsafe {
            let slots_ptr = core::ptr::addr_of_mut!(crate::cap::slot::SLOTS[0]);

            let untyped_storage = &mut *slots_ptr.add(untyped_slot as usize);
            let child_storage = &mut *slots_ptr.add(child_slot as usize);

            // Read current head of untyped's child list
            let old_first = untyped_storage.meta.ut_first_child;

            // Insert child at head of list
            child_storage.meta.ut_next = old_first;
            child_storage.meta.ut_parent = untyped_slot;

            // Update untyped's first child pointer
            untyped_storage.meta.ut_first_child = child_slot;
        }
    }

    /// Remove child from untyped's child list
    ///
    /// Called when an object is deleted.
    pub fn remove_child(untyped_slot: CapSlot, child_slot: CapSlot) {
        unsafe {
            let slots_ptr = core::ptr::addr_of_mut!(crate::cap::slot::SLOTS[0]);

            let untyped_storage = &mut *slots_ptr.add(untyped_slot as usize);

            let mut prev = INVALID_SLOT;
            let mut current = untyped_storage.meta.ut_first_child;

            while current != INVALID_SLOT {
                let curr_storage = &*slots_ptr.add(current as usize);

                if current == child_slot {
                    // Found it - remove from list
                    let next = curr_storage.meta.ut_next;

                    if prev == INVALID_SLOT {
                        // Was first child
                        untyped_storage.meta.ut_first_child = next;
                    } else {
                        // Update prev's ut_next
                        let prev_storage = &mut *slots_ptr.add(prev as usize);
                        prev_storage.meta.ut_next = next;
                    }

                    // Clear child's ut links
                    let child_storage = &mut *slots_ptr.add(child_slot as usize);
                    child_storage.meta.ut_next = INVALID_SLOT;
                    child_storage.meta.ut_parent = INVALID_SLOT;
                    return;
                }

                prev = current;
                current = curr_storage.meta.ut_next;
            }
        }
    }

    /// Check if untyped has children
    ///
    /// Used to prevent reset/untype when objects exist.
    pub fn has_children(untyped_slot: CapSlot) -> bool {
        unsafe {
            let slots_ptr = core::ptr::addr_of!(crate::cap::slot::SLOTS[0]);
            let storage = &*slots_ptr.add(untyped_slot as usize);
            storage.meta.ut_first_child != INVALID_SLOT
        }
    }

    /// Reset untyped memory
    ///
    /// Clears watermark, allowing reuse of the untyped region.
    /// Only allowed if untyped has no children.
    pub fn reset(untyped_slot: CapSlot) -> Result<(), CapError> {
        if Self::has_children(untyped_slot) {
            return Err(CapError::HasChildren);
        }

        unsafe {
            let slots_ptr = core::ptr::addr_of!(crate::cap::slot::SLOTS[0]);
            let storage = &*slots_ptr.add(untyped_slot as usize);
            let obj_ptr = storage.cap.object as *mut UntypedMemory;
            (*obj_ptr).watermark = 0;
        }

        Ok(())
    }
}

/// Get object size in bytes for a given type
fn object_size(obj_type: ObjectType, size_bits: u8) -> usize {
    match obj_type {
        ObjectType::Endpoint => core::mem::size_of::<crate::ipc::Endpoint>(),
        ObjectType::Notification => core::mem::size_of::<crate::ipc::Notification>(),
        ObjectType::CNode => 1usize << size_bits, // CNode size is variable
        ObjectType::Tcb => core::mem::size_of::<crate::sched::thread::Tcb>(),
        ObjectType::VSpace => PAGE_SIZE, // Page table
        ObjectType::Frame => 1usize << size_bits,
        ObjectType::Untyped => 1usize << size_bits,
        ObjectType::IrqHandler => core::mem::size_of::<crate::ipc::IrqHandler>(),
        ObjectType::IoPort => core::mem::size_of::<()>(),     // Placeholder
        ObjectType::SchedContext => core::mem::size_of::<crate::sched::thread::SchedContext>(),
        ObjectType::Null => 0,
    }
}

/// Initialize kernel object in memory
unsafe fn init_object(
    obj_type: ObjectType,
    phys_addr: PhysAddr,
    size_bits: u8,
) -> Result<*mut crate::cap::object::KernelObject, CapError> {
    use crate::cap::object::KernelObject;

    let virt_addr = mm::phys_to_virt(phys_addr) as *mut u8;

    unsafe {
        match obj_type {
            ObjectType::Endpoint => {
                let ep = virt_addr as *mut crate::ipc::Endpoint;
                ep.write(crate::ipc::Endpoint::new());
                Ok(ep as *mut KernelObject)
            }

            ObjectType::Notification => {
                let notif = virt_addr as *mut crate::ipc::Notification;
                notif.write(crate::ipc::Notification::new());
                Ok(notif as *mut KernelObject)
            }

            ObjectType::CNode => {
                let obj = virt_addr as *mut KernelObject;
                obj.write(KernelObject::new(obj_type, size_bits));
                Ok(obj)
            }

            ObjectType::Frame => {
                let frame = virt_addr as *mut FrameObject;
                frame.write(FrameObject::new(phys_addr, size_bits));
                Ok(frame as *mut KernelObject)
            }

            ObjectType::Untyped => {
                let untyped = virt_addr as *mut UntypedMemory;
                untyped.write(UntypedMemory::new(phys_addr, size_bits, false));
                Ok(untyped as *mut KernelObject)
            }

            ObjectType::Tcb => {
                let tcb = virt_addr as *mut crate::sched::thread::Tcb;
                tcb.write(crate::sched::thread::Tcb::new());
                Ok(tcb as *mut KernelObject)
            }

            ObjectType::VSpace => {
                let vs = virt_addr as *mut crate::mm::VSpace;
                vs.write(crate::mm::VSpace::new(phys_addr));
                Ok(vs as *mut KernelObject)
            }

            ObjectType::SchedContext => {
                let sc = virt_addr as *mut crate::sched::thread::SchedContext;
                sc.write(crate::sched::thread::SchedContext::new());
                Ok(sc as *mut KernelObject)
            }

            ObjectType::IrqHandler => {
                let irq = virt_addr as *mut crate::ipc::IrqHandler;
                irq.write(crate::ipc::IrqHandler::new(0));
                Ok(irq as *mut KernelObject)
            }

            _ => Err(CapError::InvalidOperation),
        }
    }
}

impl UntypedMemory {
    /// Retype untyped memory into typed objects
    ///
    /// Allocates objects from the untyped region and creates capabilities.
    /// Objects become children of the untyped in both CDT and ut_next list.
    pub fn retype(
        &mut self,
        untyped_slot: CapSlot,
        new_type: ObjectType,
        size_bits: u8,
        num_objects: usize,
        dest_cnode: &mut crate::cap::cnode::CNode,
        dest_offset: usize,
    ) -> Result<(), CapError> {
        let obj_size = object_size(new_type, size_bits);
        let total_size = obj_size * num_objects;

        // Check sufficient memory
        if self.available() < total_size {
            return Err(CapError::InsufficientMemory);
        }

        // Check destination slots are empty
        for i in 0..num_objects {
            if !dest_cnode.is_slot_empty(dest_offset + i) {
                return Err(CapError::SlotOccupied);
            }
        }

        // Allocate objects
        for i in 0..num_objects {
            let obj_offset = self.watermark as usize + (i * obj_size);
            let obj_addr = self.phys_addr + obj_offset as u64;

            // Initialize object
            let object = unsafe { init_object(new_type, obj_addr, size_bits)? };

            // Allocate capability slot
            let cap_slot = crate::cap::slot::alloc_slot().ok_or(CapError::OutOfSlots)?;

            // Initialize capability
            let cap = crate::cap::slot::get_cap_mut(cap_slot);
            cap.object = object;
            cap.obj_type = new_type;
            cap.rights = crate::cap::CapRights::ALL;
            cap.depth = 0;
            cap.badge = 0;

            // CRITICAL: Insert into CDT as CHILD of untyped
            CDT::insert_child(untyped_slot, cap_slot);

            // Add to untyped's child list (for revoke tracking)
            UntypedTracker::add_child(untyped_slot, cap_slot);

            // Insert CapRef into CNode
            dest_cnode.insert_ref(
                dest_offset + i,
                crate::cap::cnode::CapRef { slot: cap_slot },
            )?;
        }

        // Update watermark
        self.watermark += total_size as u32;

        Ok(())
    }

    /// Untype (free) an object
    ///
    /// Frees an object back to the untyped pool.
    /// Only allowed if:
    /// 1. Object has no derived capabilities
    /// 2. Object's refcount is 1 (only this cap references it)
    pub fn untype(&mut self, untyped_slot: CapSlot, cap_slot: CapSlot) -> Result<(), CapError> {
        let cap = get_cap(cap_slot);
        let meta = get_meta(cap_slot);

        // SAFETY CHECK 1: Must be child of this untyped
        if meta.ut_parent != untyped_slot {
            return Err(CapError::NotAChild);
        }

        // SAFETY CHECK 2: No derived capabilities (CDT check)
        if CDT::has_children(cap_slot) {
            return Err(CapError::HasDerivedCaps);
        }

        // SAFETY CHECK 3: Refcount must be 1 (only this cap)
        let refcount = unsafe {
            (*cap.object)
                .ref_count
                .load(core::sync::atomic::Ordering::Acquire)
        };
        if refcount != 1 {
            return Err(CapError::ObjectInUse);
        }

        // Perform deletion (full lifecycle)
        CDT::revoke(cap_slot);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_untyped_size() {
        let untyped = UntypedMemory::new(0x1000, 20, false);
        assert_eq!(untyped.size_bytes(), 1 << 20);
        assert_eq!(untyped.available(), 1 << 20);
    }

    #[test]
    fn test_watermark() {
        let mut untyped = UntypedMemory::new(0x1000, 12, false);
        assert_eq!(untyped.watermark, 0);
        assert_eq!(untyped.available(), 4096);

        untyped.watermark = 2048;
        assert_eq!(untyped.available(), 2048);
    }
}
