//! CNode - Capability Node
//!
//! CNodes store capability references (slot indices), not capability values.
//! This allows multiple CNodes to reference the same capability (sharing).
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{
    alloc_slot, free_slot, get_cap, get_cap_mut, get_meta, get_meta_mut, CapRights, Capability, CDT,
    KernelObject, ObjectType, INVALID_SLOT,
};

/// Default CNode size_bits when caller passes 0 (ABI backward compat)
pub const CNODE_DEFAULT_SIZE_BITS: u8 = 10; // 1024 slots
/// Minimum allowed CNode size_bits
pub const CNODE_MIN_SIZE_BITS: u8 = 4; // 16 slots
/// Maximum allowed CNode size_bits
pub const CNODE_MAX_SIZE_BITS: u8 = 16; // 65536 slots

/// Legacy aliases (kept for any external references)
pub const CNODE_SIZE_BITS: usize = CNODE_DEFAULT_SIZE_BITS as usize;
pub const CNODE_SIZE: usize = 1 << CNODE_SIZE_BITS;

/// Capability reference - points to global slot
///
/// CNodes store CapRef values, which are indices into the global slot array.
/// This allows:
/// - Multiple CNodes to reference the same capability
/// - Moving capabilities between CNodes without copying
/// - Efficient capability transfer
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CapRef {
    pub slot: u32,
}

impl CapRef {
    pub const fn null() -> Self {
        Self { slot: INVALID_SLOT }
    }

    pub fn is_null(&self) -> bool {
        self.slot == INVALID_SLOT
    }

    /// Get the capability this reference points to
    pub fn get(&self) -> &'static Capability {
        get_cap(self.slot)
    }
}

/// Capability Node - stores capability references
///
/// CNodes are kernel objects that hold a header followed by a contiguous
/// array of CapRef entries in memory. The number of slots is determined
/// by `header.size_bits` (capacity = 1 << size_bits).
///
/// Memory layout:
///   +0:  KernelObject header (12 bytes, header.size_bits = log2(num_slots))
///   +12: CapRef[0] .. CapRef[2^size_bits - 1]
#[repr(C)]
pub struct CNode {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    // Slots [CapRef; 1 << header.size_bits] follow contiguously in memory.
    // Accessed via pointer arithmetic (slot_ptr / slot_ptr_mut).
}

/// Validate size_bits for CNode, returning effective bits or error.
///
/// - 0 → default (CNODE_DEFAULT_SIZE_BITS = 10, i.e. 1024 slots)
/// - 1..3 → InvalidArgument (too small)
/// - 4..16 → use as-is
/// - 17+ → InvalidArgument (too large)
pub fn effective_cnode_bits(size_bits: u8) -> Result<u8, CapError> {
    if size_bits == 0 {
        Ok(CNODE_DEFAULT_SIZE_BITS)
    } else if size_bits < CNODE_MIN_SIZE_BITS {
        Err(CapError::InvalidArgument)
    } else if size_bits > CNODE_MAX_SIZE_BITS {
        Err(CapError::InvalidArgument)
    } else {
        Ok(size_bits)
    }
}

impl CNode {
    /// Number of slots this CNode holds (1 << header.size_bits)
    pub fn num_slots(&self) -> usize {
        1usize << (self.header.size_bits as usize)
    }

    /// Get pointer to slot at `index` (no bounds check)
    unsafe fn slot_ptr(&self, index: usize) -> *const CapRef {
        unsafe {
            let base = (self as *const CNode).add(1) as *const CapRef;
            base.add(index)
        }
    }

    /// Get mutable pointer to slot at `index` (no bounds check)
    unsafe fn slot_ptr_mut(&mut self, index: usize) -> *mut CapRef {
        unsafe {
            let base = (self as *mut CNode).add(1) as *mut CapRef;
            base.add(index)
        }
    }

    /// Initialize a CNode in-place at the given memory address.
    ///
    /// Writes the header and zero-fills all slot entries with CapRef::null().
    /// The caller must ensure `ptr` points to at least
    /// `size_of::<CNode>() + (1 << size_bits) * size_of::<CapRef>()` bytes.
    pub unsafe fn init_at(ptr: *mut u8, size_bits: u8) {
        unsafe {
            let cnode = ptr as *mut CNode;
            // Write header
            core::ptr::write(
                &raw mut (*cnode).header,
                KernelObject::new(ObjectType::CNode, size_bits),
            );
            // Zero-fill all slots with CapRef::null() (INVALID_SLOT = 0xFFFFFFFF)
            let num_slots = 1usize << (size_bits as usize);
            let slots_base = cnode.add(1) as *mut CapRef;
            for i in 0..num_slots {
                core::ptr::write(slots_base.add(i), CapRef::null());
            }
        }
    }

    /// Check if slot is empty (holds null reference)
    pub fn is_slot_empty(&self, index: usize) -> bool {
        if index >= self.num_slots() {
            return false;
        }
        unsafe { (*self.slot_ptr(index)).is_null() }
    }

    /// Insert a capability reference into a slot
    pub fn insert_ref(&mut self, index: usize, cap_ref: CapRef) -> Result<(), CapError> {
        if index >= self.num_slots() {
            return Err(CapError::InvalidSlot);
        }
        if !self.is_slot_empty(index) {
            return Err(CapError::SlotOccupied);
        }
        unsafe {
            core::ptr::write(self.slot_ptr_mut(index), cap_ref);
        }
        Ok(())
    }

    /// Get capability reference at index
    pub fn get_ref(&self, index: usize) -> Option<CapRef> {
        if index < self.num_slots() && !self.is_slot_empty(index) {
            Some(unsafe { *self.slot_ptr(index) })
        } else {
            None
        }
    }

    /// Get capability at index
    pub fn get(&self, index: usize) -> Option<&Capability> {
        self.get_ref(index).map(|r| r.get())
    }

    /// Copy capability from source to destination
    ///
    /// Creates a new capability with potentially reduced rights.
    /// The new capability becomes a child of the source in the CDT.
    pub fn copy_slot(
        &mut self,
        dest: usize,
        src_cnode: &CNode,
        src: usize,
        new_rights: CapRights,
    ) -> Result<(), CapError> {
        // Validate indices
        if dest >= self.num_slots() || src >= src_cnode.num_slots() {
            return Err(CapError::InvalidSlot);
        }

        // Check destination is empty
        if !self.is_slot_empty(dest) {
            return Err(CapError::SlotOccupied);
        }

        // Get source capability
        let src_ref = src_cnode.get_ref(src).ok_or(CapError::SlotEmpty)?;
        let src_cap = src_ref.get();

        // Check source has Grant right
        if !src_cap.has_right(CapRights::GRANT) {
            return Err(CapError::InsufficientRights);
        }

        // Allocate new slot for destination
        let dest_slot = alloc_slot().ok_or(CapError::OutOfSlots)?;

        // Perform copy (this updates CDT and refcount)
        src_cap.copy(src_ref.slot, new_rights, dest_slot)?;

        // Insert reference into destination CNode
        unsafe {
            core::ptr::write(self.slot_ptr_mut(dest), CapRef { slot: dest_slot });
        }

        Ok(())
    }

    /// Mint badged capability
    ///
    /// Creates a badged copy of an endpoint capability.
    /// Badged capabilities cannot have Grant right.
    pub fn mint_slot(
        &mut self,
        dest: usize,
        src_cnode: &CNode,
        src: usize,
        badge: u64,
        new_rights: CapRights,
    ) -> Result<(), CapError> {
        // Validate indices
        if dest >= self.num_slots() || src >= src_cnode.num_slots() {
            return Err(CapError::InvalidSlot);
        }

        // Check destination is empty
        if !self.is_slot_empty(dest) {
            return Err(CapError::SlotOccupied);
        }

        // Get source capability
        let src_ref = src_cnode.get_ref(src).ok_or(CapError::SlotEmpty)?;
        let src_cap = src_ref.get();

        // Allocate new slot for destination
        let dest_slot = alloc_slot().ok_or(CapError::OutOfSlots)?;

        // Perform mint (this updates CDT and refcount)
        src_cap.mint(src_ref.slot, badge, new_rights, dest_slot)?;

        // Insert reference into destination CNode
        unsafe {
            core::ptr::write(self.slot_ptr_mut(dest), CapRef { slot: dest_slot });
        }

        Ok(())
    }

    /// Move capability from source to destination
    ///
    /// Transfers the capability reference without creating a new capability.
    /// The source slot becomes empty.
    pub fn move_slot(
        &mut self,
        dest: usize,
        src_cnode: &mut CNode,
        src: usize,
    ) -> Result<(), CapError> {
        // Validate indices
        if dest >= self.num_slots() || src >= src_cnode.num_slots() {
            return Err(CapError::InvalidSlot);
        }

        // Check destination is empty
        if !self.is_slot_empty(dest) {
            return Err(CapError::SlotOccupied);
        }

        // Get source reference
        let src_ref = src_cnode.get_ref(src).ok_or(CapError::SlotEmpty)?;

        // Transfer reference (no global slot changes)
        unsafe {
            core::ptr::write(self.slot_ptr_mut(dest), src_ref);
            core::ptr::write(src_cnode.slot_ptr_mut(src), CapRef::null());
        }

        Ok(())
    }

    /// Mutate capability (move + change badge)
    ///
    /// Moves a capability from source to destination and sets a new badge.
    /// The source slot becomes empty. Only works on endpoint capabilities.
    pub fn mutate_slot(
        &mut self,
        dest: usize,
        src_cnode: &mut CNode,
        src: usize,
        new_badge: u64,
    ) -> Result<(), CapError> {
        // First do the move
        self.move_slot(dest, src_cnode, src)?;

        // Then modify the badge on the moved capability
        let cap_ref = self.get_ref(dest).ok_or(CapError::SlotEmpty)?;
        let cap = get_cap_mut(cap_ref.slot);

        // Only endpoints can be badged
        if cap.obj_type != super::ObjectType::Endpoint {
            return Err(CapError::InvalidOperation);
        }

        cap.badge = new_badge;
        Ok(())
    }

    /// Save the caller's reply capability into a CNode slot
    ///
    /// Takes the reply_tcb from the current thread and creates a one-shot
    /// reply capability in the specified slot. The reply_tcb is cleared
    /// from the current thread.
    pub fn save_caller(
        &mut self,
        index: usize,
        current_tcb: *mut super::super::sched::thread::Tcb,
    ) -> Result<(), CapError> {
        if index >= self.num_slots() {
            return Err(CapError::InvalidSlot);
        }
        if !self.is_slot_empty(index) {
            return Err(CapError::SlotOccupied);
        }

        unsafe {
            let tcb = &mut *current_tcb;
            if tcb.reply_tcb.is_null() {
                return Err(CapError::SlotEmpty);
            }

            // Allocate a new global slot for the reply capability
            let slot = alloc_slot().ok_or(CapError::OutOfSlots)?;
            let cap = super::get_cap_mut(slot);

            // Create a reply capability pointing to the caller's TCB
            cap.object = tcb.reply_tcb as *mut super::KernelObject;
            // Increment refcount to balance release_object() in delete()
            super::increment_refcount(cap.object);
            cap.obj_type = super::ObjectType::Tcb;
            cap.rights = super::CapRights::REPLY;
            cap.badge = 0;
            cap.depth = 0;
            cap._reserved = 0;
            cap._pad = 0;

            // Insert reference into CNode
            core::ptr::write(self.slot_ptr_mut(index), CapRef { slot });

            // Clear the reply capability from the current thread (one-shot)
            tcb.reply_tcb = core::ptr::null_mut();
            tcb.reply_can_grant = false;
        }

        Ok(())
    }

    /// Revoke capability and all descendants
    ///
    /// Deletes the capability at the given index and recursively
    /// revokes all its descendants in the CDT.
    pub fn revoke(&mut self, index: usize) -> Result<(), CapError> {
        if index >= self.num_slots() {
            return Err(CapError::InvalidSlot);
        }

        let cap_ref = self.get_ref(index).ok_or(CapError::SlotEmpty)?;

        // Revoke handles full lifecycle including slot cleanup
        CDT::revoke(cap_ref.slot);

        // Clear CNode slot
        unsafe {
            core::ptr::write(self.slot_ptr_mut(index), CapRef::null());
        }

        Ok(())
    }

    /// Delete single capability
    ///
    /// Deletes the capability at the given index.
    /// Fails if the capability has children (use revoke instead).
    pub fn delete(&mut self, index: usize) -> Result<(), CapError> {
        if index >= self.num_slots() {
            return Err(CapError::InvalidSlot);
        }

        let cap_ref = self.get_ref(index).ok_or(CapError::SlotEmpty)?;

        // Check for children - must use revoke if children exist
        if CDT::has_children(cap_ref.slot) {
            return Err(CapError::HasChildren);
        }

        // Perform deletion (full lifecycle)
        CDT::remove(cap_ref.slot);

        // Remove from untyped's child list (if applicable)
        let meta = get_meta(cap_ref.slot);
        if meta.ut_parent != INVALID_SLOT {
            super::untyped::UntypedTracker::remove_child(meta.ut_parent, cap_ref.slot);
        }

        // Release object
        let cap = get_cap(cap_ref.slot);
        if !cap.is_null() {
            unsafe {
                super::release_object(cap.object, cap.obj_type);
            }
        }

        // Nullify capability
        super::nullify_capability(cap_ref.slot);

        // Clear ut_parent
        get_meta_mut(cap_ref.slot).ut_parent = INVALID_SLOT;

        // Free the slot
        free_slot(cap_ref.slot);

        // Clear CNode slot
        unsafe {
            core::ptr::write(self.slot_ptr_mut(index), CapRef::null());
        }

        Ok(())
    }

    /// Get information about a capability
    pub fn cap_info(&self, index: usize) -> Result<CapInfo, CapError> {
        if index >= self.num_slots() {
            return Err(CapError::InvalidSlot);
        }

        let cap_ref = self.get_ref(index).ok_or(CapError::SlotEmpty)?;
        let cap = get_cap(cap_ref.slot);
        let meta = get_meta(cap_ref.slot);

        Ok(CapInfo {
            obj_type: cap.obj_type,
            rights: cap.rights,
            badge: cap.badge,
            depth: cap.depth,
            has_children: CDT::has_children(cap_ref.slot),
            child_count: CDT::child_count(cap_ref.slot),
            ut_parent: meta.ut_parent,
        })
    }
}

/// Information about a capability
#[derive(Debug, Clone, Copy)]
pub struct CapInfo {
    pub obj_type: super::ObjectType,
    pub rights: CapRights,
    pub badge: u64,
    pub depth: u8,
    pub has_children: bool,
    pub child_count: usize,
    pub ut_parent: u32,
}

/// Capability errors
#[derive(Debug, Clone, Copy)]
pub enum CapError {
    InvalidSlot,
    SlotOccupied,
    SlotEmpty,
    InsufficientRights,
    RightsNotSubset,
    DepthExceeded,
    InvalidOperation,
    InvalidBadge,
    InsufficientMemory,
    OutOfSlots,
    NotAChild,
    HasChildren,
    HasDerivedCaps,
    ObjectInUse,
    InvalidState,
    InvalidArgument,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Size of a test CNode buffer (header + 16 slots, size_bits=4)
    const TEST_SIZE_BITS: u8 = CNODE_MIN_SIZE_BITS; // 16 slots
    const TEST_BUF_SIZE: usize =
        core::mem::size_of::<CNode>() + ((1 << TEST_SIZE_BITS) * core::mem::size_of::<CapRef>());

    fn make_test_cnode(buf: &mut [u8; TEST_BUF_SIZE]) -> &mut CNode {
        unsafe {
            CNode::init_at(buf.as_mut_ptr(), TEST_SIZE_BITS);
            &mut *(buf.as_mut_ptr() as *mut CNode)
        }
    }

    #[test]
    fn test_cnode_new() {
        let mut buf = [0u8; TEST_BUF_SIZE];
        let cnode = make_test_cnode(&mut buf);
        assert_eq!(cnode.num_slots(), 1 << TEST_SIZE_BITS);
        assert!(cnode.is_slot_empty(0));
        assert!(cnode.get(0).is_none());
    }

    #[test]
    fn test_insert_ref() {
        let mut buf = [0u8; TEST_BUF_SIZE];
        let cnode = make_test_cnode(&mut buf);
        let cap_ref = CapRef { slot: 100 };

        assert!(cnode.insert_ref(0, cap_ref).is_ok());
        assert!(!cnode.is_slot_empty(0));
        assert_eq!(cnode.get_ref(0).unwrap().slot, 100);
    }

    #[test]
    fn test_insert_occupied() {
        let mut buf = [0u8; TEST_BUF_SIZE];
        let cnode = make_test_cnode(&mut buf);
        let cap_ref = CapRef { slot: 100 };

        assert!(cnode.insert_ref(0, cap_ref).is_ok());
        assert!(cnode.insert_ref(0, cap_ref).is_err());
    }

    #[test]
    fn test_move_slot() {
        let mut buf1 = [0u8; TEST_BUF_SIZE];
        let mut buf2 = [0u8; TEST_BUF_SIZE];
        unsafe {
            CNode::init_at(buf1.as_mut_ptr(), TEST_SIZE_BITS);
            CNode::init_at(buf2.as_mut_ptr(), TEST_SIZE_BITS);
        }
        let cnode1 = unsafe { &mut *(buf1.as_mut_ptr() as *mut CNode) };
        let cnode2 = unsafe { &mut *(buf2.as_mut_ptr() as *mut CNode) };
        let cap_ref = CapRef { slot: 100 };

        // Insert into first CNode
        cnode1.insert_ref(0, cap_ref).unwrap();

        // Move to second CNode
        cnode2.move_slot(5, cnode1, 0).unwrap();

        assert!(cnode1.is_slot_empty(0));
        assert!(!cnode2.is_slot_empty(5));
    }

    #[test]
    fn test_effective_cnode_bits() {
        // 0 → default
        assert_eq!(effective_cnode_bits(0).unwrap(), CNODE_DEFAULT_SIZE_BITS);
        // 1..3 → error
        assert!(effective_cnode_bits(1).is_err());
        assert!(effective_cnode_bits(3).is_err());
        // 4..16 → as-is
        assert_eq!(effective_cnode_bits(4).unwrap(), 4);
        assert_eq!(effective_cnode_bits(10).unwrap(), 10);
        assert_eq!(effective_cnode_bits(16).unwrap(), 16);
        // 17+ → error
        assert!(effective_cnode_bits(17).is_err());
        assert!(effective_cnode_bits(255).is_err());
    }
}
