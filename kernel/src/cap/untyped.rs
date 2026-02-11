//! Untyped Memory Management
//!
//! Untyped memory is the raw memory from which all kernel objects are created.
//! This module implements retyping (allocating objects) and untyping (freeing),
//! with proper parent-child tracking via CDT.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::slot::{free_slot, get_cap, get_meta, CapSlot, INVALID_SLOT, MAX_SLOTS};
use super::{CapError, ObjectType, CDT};
use crate::cap::cnode::{effective_cnode_bits, CapRef};
use crate::mm::{self, PhysAddr, PAGE_SIZE};
use core::mem::MaybeUninit;

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

// Frame metadata is stored out-of-line from frame payload memory.
// This prevents user mappings/writes to frame pages from corrupting
// kernel metadata (e.g., phys_addr used by VSpace_Map).
static mut FRAME_METADATA: [MaybeUninit<FrameObject>; MAX_SLOTS] =
    [const { MaybeUninit::uninit() }; MAX_SLOTS];

// VSpace metadata is also stored out-of-line. The untyped-allocated page is
// used exclusively as the PML4 root page table.
static mut VSPACE_METADATA: [MaybeUninit<crate::mm::VSpace>; MAX_SLOTS] =
    [const { MaybeUninit::uninit() }; MAX_SLOTS];

// Sub-untyped metadata is stored out-of-line to prevent child frame retypes
// from overwriting the UntypedMemory struct (which would be at offset 0 of
// the sub-untyped's physical region if stored in-band).
static mut UNTYPED_METADATA: [MaybeUninit<UntypedMemory>; MAX_SLOTS] =
    [const { MaybeUninit::uninit() }; MAX_SLOTS];

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

/// Get object size in bytes for a given type.
///
/// For CNode, uses `effective_cnode_bits()` to determine slot count,
/// returning header + trailing slots.
fn object_size(obj_type: ObjectType, size_bits: u8) -> Result<usize, CapError> {
    match obj_type {
        ObjectType::Endpoint => Ok(core::mem::size_of::<crate::ipc::Endpoint>()),
        ObjectType::Notification => Ok(core::mem::size_of::<crate::ipc::Notification>()),
        ObjectType::CNode => {
            let bits = effective_cnode_bits(size_bits)?;
            Ok(core::mem::size_of::<crate::cap::CNode>()
                + ((1usize << bits) * core::mem::size_of::<CapRef>()))
        }
        ObjectType::Tcb => Ok(core::mem::size_of::<crate::sched::thread::Tcb>()),
        ObjectType::VSpace => Ok(PAGE_SIZE), // Page table (always 4KB-aligned PML4)
        ObjectType::Frame => {
            // Minimum 4KB page; size_bits=0 defaults to PAGE_SIZE
            let bits = if size_bits < 12 { 12 } else { size_bits };
            Ok(1usize << bits)
        }
        ObjectType::Untyped => Ok(1usize << size_bits),
        ObjectType::IrqHandler => Ok(core::mem::size_of::<crate::ipc::IrqHandler>()),
        ObjectType::IoPort => Ok(core::mem::size_of::<crate::cap::IoPortRange>()),
        ObjectType::SchedContext => Ok(core::mem::size_of::<crate::sched::thread::SchedContext>()),
        ObjectType::Null => Ok(0),
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
                let bits = effective_cnode_bits(size_bits)?;
                crate::cap::CNode::init_at(virt_addr, bits);
                Ok(virt_addr as *mut KernelObject)
            }

            ObjectType::Frame => Err(CapError::InvalidOperation),

            ObjectType::Untyped => Err(CapError::InvalidOperation),

            ObjectType::Tcb => {
                let tcb = virt_addr as *mut crate::sched::thread::Tcb;
                tcb.write(crate::sched::thread::Tcb::new());
                Ok(tcb as *mut KernelObject)
            }

            ObjectType::VSpace => {
                Err(CapError::InvalidOperation)
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

            ObjectType::IoPort => {
                let ioport = virt_addr as *mut crate::cap::IoPortRange;
                ioport.write(crate::cap::IoPortRange::new(0, 0));
                Ok(ioport as *mut KernelObject)
            }

            _ => Err(CapError::InvalidOperation),
        }
    }
}

/// Initialize frame metadata in slot-indexed static storage.
unsafe fn init_frame_metadata(
    cap_slot: CapSlot,
    phys_addr: PhysAddr,
    size_bits: u8,
) -> *mut crate::cap::object::KernelObject {
    let actual_bits = if size_bits < 12 { 12 } else { size_bits };
    let frame_ptr = unsafe { FRAME_METADATA[cap_slot as usize].as_mut_ptr() };
    unsafe {
        frame_ptr.write(FrameObject::new(phys_addr, actual_bits));
    }
    frame_ptr as *mut crate::cap::object::KernelObject
}

/// Initialize VSpace metadata in slot-indexed static storage and initialize
/// the provided physical page as a PML4 root.
unsafe fn init_vspace_metadata(
    cap_slot: CapSlot,
    pml4_phys: PhysAddr,
) -> *mut crate::cap::object::KernelObject {
    let pml4_virt = mm::phys_to_virt(pml4_phys) as *mut u64;
    unsafe {
        core::ptr::write_bytes(pml4_virt, 0, PAGE_SIZE / 8);

        // Copy kernel higher-half entries so kernel remains mapped.
        let kernel_cr3 = crate::arch::x86_64::paging::read_cr3();
        let kernel_pml4 = mm::phys_to_virt(kernel_cr3) as *const u64;
        for i in 256..512 {
            pml4_virt.add(i).write(kernel_pml4.add(i).read());
        }
    }

    let vspace_ptr = unsafe { VSPACE_METADATA[cap_slot as usize].as_mut_ptr() };
    unsafe {
        vspace_ptr.write(crate::mm::VSpace::new(pml4_phys));
    }
    vspace_ptr as *mut crate::cap::object::KernelObject
}

/// Initialize sub-untyped metadata in slot-indexed static storage.
///
/// # Safety
/// Caller must ensure `cap_slot` is a valid, exclusively-owned slot index.
unsafe fn init_untyped_metadata(
    cap_slot: CapSlot,
    phys_addr: PhysAddr,
    size_bits: u8,
    is_device: bool,
) -> *mut crate::cap::object::KernelObject {
    let untyped_ptr = unsafe { UNTYPED_METADATA[cap_slot as usize].as_mut_ptr() };
    unsafe {
        untyped_ptr.write(UntypedMemory::new(phys_addr, size_bits, is_device));
    }
    untyped_ptr as *mut crate::cap::object::KernelObject
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
        // Device memory can only be retyped into Frame or Untyped (no zeroing)
        if self.is_device
            && !matches!(new_type, ObjectType::Frame | ObjectType::Untyped)
        {
            return Err(CapError::InvalidOperation);
        }

        let obj_size = object_size(new_type, size_bits)?;
        let total_size = obj_size * num_objects;

        // Validate destination range before probing slot occupancy.
        // Without this, out-of-range indices look "not empty" and are
        // misreported as SlotOccupied.
        let end = dest_offset
            .checked_add(num_objects)
            .ok_or(CapError::InvalidSlot)?;
        if end > dest_cnode.num_slots() {
            return Err(CapError::InvalidSlot);
        }

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

        // Align watermark to object size (critical for Frame/VSpace page alignment).
        // CNode only needs CapRef alignment (4 bytes), not full slot-array size,
        // since CNodes are never user-mapped.
        if obj_size > 0 {
            let align = if new_type == ObjectType::CNode {
                core::mem::align_of::<CapRef>()
            } else {
                obj_size
            };
            let aligned = (self.watermark as usize + align - 1) & !(align - 1);
            self.watermark = aligned as u32;

            // Re-check after alignment
            if self.available() < total_size {
                return Err(CapError::InsufficientMemory);
            }
        }

        // Allocate objects
        for i in 0..num_objects {
            let obj_offset = self.watermark as usize + (i * obj_size);
            let obj_addr = self.phys_addr + obj_offset as u64;

            // Allocate capability slot
            let cap_slot = crate::cap::slot::alloc_slot().ok_or(CapError::OutOfSlots)?;

            // Initialize object
            let object = unsafe {
                match new_type {
                    ObjectType::Frame => init_frame_metadata(cap_slot, obj_addr, size_bits),
                    ObjectType::VSpace => init_vspace_metadata(cap_slot, obj_addr),
                    ObjectType::Untyped => init_untyped_metadata(cap_slot, obj_addr, size_bits, self.is_device),
                    _ => match init_object(new_type, obj_addr, size_bits) {
                        Ok(obj) => obj,
                        Err(e) => {
                            free_slot(cap_slot);
                            return Err(e);
                        }
                    },
                }
            };

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
