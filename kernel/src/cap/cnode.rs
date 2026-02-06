//! CNode - Capability Node
//!
//! CNodes store capability references (slot indices), not capability values.
//! This allows multiple CNodes to reference the same capability (sharing).
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{
    alloc_slot, free_slot, get_cap, get_meta, get_meta_mut, CapRights, Capability, CDT,
    KernelObject, ObjectType, INVALID_SLOT,
};

/// CNode size (number of slots as power of 2)
pub const CNODE_SIZE_BITS: usize = 8;
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
/// CNodes are kernel objects that hold an array of CapRef entries.
/// Each entry is either INVALID_SLOT (empty) or a valid slot index.
#[repr(C, align(4096))]
pub struct CNode {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    slots: [CapRef; CNODE_SIZE],
}

impl CNode {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::CNode, CNODE_SIZE_BITS as u8),
            slots: [CapRef::null(); CNODE_SIZE],
        }
    }

    /// Check if slot is empty (holds null reference)
    pub fn is_slot_empty(&self, index: usize) -> bool {
        index < CNODE_SIZE && self.slots[index].is_null()
    }

    /// Insert a capability reference into a slot
    pub fn insert_ref(&mut self, index: usize, cap_ref: CapRef) -> Result<(), CapError> {
        if index >= CNODE_SIZE {
            return Err(CapError::InvalidSlot);
        }
        if !self.is_slot_empty(index) {
            return Err(CapError::SlotOccupied);
        }
        self.slots[index] = cap_ref;
        Ok(())
    }

    /// Get capability reference at index
    pub fn get_ref(&self, index: usize) -> Option<CapRef> {
        if index < CNODE_SIZE && !self.is_slot_empty(index) {
            Some(self.slots[index])
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
        if dest >= CNODE_SIZE || src >= CNODE_SIZE {
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
        self.slots[dest] = CapRef { slot: dest_slot };

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
        if dest >= CNODE_SIZE || src >= CNODE_SIZE {
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
        self.slots[dest] = CapRef { slot: dest_slot };

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
        if dest >= CNODE_SIZE || src >= CNODE_SIZE {
            return Err(CapError::InvalidSlot);
        }

        // Check destination is empty
        if !self.is_slot_empty(dest) {
            return Err(CapError::SlotOccupied);
        }

        // Get source reference
        let src_ref = src_cnode.get_ref(src).ok_or(CapError::SlotEmpty)?;

        // Transfer reference (no global slot changes)
        self.slots[dest] = src_ref;
        src_cnode.slots[src] = CapRef::null();

        Ok(())
    }

    /// Revoke capability and all descendants
    ///
    /// Deletes the capability at the given index and recursively
    /// revokes all its descendants in the CDT.
    pub fn revoke(&mut self, index: usize) -> Result<(), CapError> {
        if index >= CNODE_SIZE {
            return Err(CapError::InvalidSlot);
        }

        let cap_ref = self.get_ref(index).ok_or(CapError::SlotEmpty)?;

        // Revoke handles full lifecycle including slot cleanup
        CDT::revoke(cap_ref.slot);

        // Clear CNode slot
        self.slots[index] = CapRef::null();

        Ok(())
    }

    /// Delete single capability
    ///
    /// Deletes the capability at the given index.
    /// Fails if the capability has children (use revoke instead).
    pub fn delete(&mut self, index: usize) -> Result<(), CapError> {
        if index >= CNODE_SIZE {
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
        self.slots[index] = CapRef::null();

        Ok(())
    }

    /// Get information about a capability
    pub fn cap_info(&self, index: usize) -> Result<CapInfo, CapError> {
        if index >= CNODE_SIZE {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cnode_new() {
        let cnode = CNode::new();
        assert!(cnode.is_slot_empty(0));
        assert!(cnode.get(0).is_none());
    }

    #[test]
    fn test_insert_ref() {
        let mut cnode = CNode::new();
        let cap_ref = CapRef { slot: 100 };

        assert!(cnode.insert_ref(0, cap_ref).is_ok());
        assert!(!cnode.is_slot_empty(0));
        assert_eq!(cnode.get_ref(0).unwrap().slot, 100);
    }

    #[test]
    fn test_insert_occupied() {
        let mut cnode = CNode::new();
        let cap_ref = CapRef { slot: 100 };

        assert!(cnode.insert_ref(0, cap_ref).is_ok());
        assert!(cnode.insert_ref(0, cap_ref).is_err());
    }

    #[test]
    fn test_move_slot() {
        let mut cnode1 = CNode::new();
        let mut cnode2 = CNode::new();
        let cap_ref = CapRef { slot: 100 };

        // Insert into first CNode
        cnode1.insert_ref(0, cap_ref).unwrap();

        // Move to second CNode
        cnode2.move_slot(5, &mut cnode1, 0).unwrap();

        assert!(cnode1.is_slot_empty(0));
        assert!(!cnode2.is_slot_empty(5));
    }
}
