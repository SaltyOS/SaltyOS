//! CNode - Capability Node
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::Capability;

/// CNode size (number of slots as power of 2)
pub const CNODE_SIZE_BITS: usize = 8;
pub const CNODE_SIZE: usize = 1 << CNODE_SIZE_BITS;

/// Capability Node - stores capabilities
#[repr(C, align(4096))]
pub struct CNode {
    slots: [Capability; CNODE_SIZE],
}

impl CNode {
    pub const fn new() -> Self {
        Self {
            slots: [Capability::null(); CNODE_SIZE],
        }
    }

    pub fn get(&self, index: usize) -> Option<&Capability> {
        if index < CNODE_SIZE {
            Some(&self.slots[index])
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Capability> {
        if index < CNODE_SIZE {
            Some(&mut self.slots[index])
        } else {
            None
        }
    }

    pub fn insert(&mut self, index: usize, cap: Capability) -> Result<(), CapError> {
        if index >= CNODE_SIZE {
            return Err(CapError::InvalidSlot);
        }
        if !self.slots[index].is_null() {
            return Err(CapError::SlotOccupied);
        }
        self.slots[index] = cap;
        Ok(())
    }

    pub fn delete(&mut self, index: usize) -> Result<(), CapError> {
        if index >= CNODE_SIZE {
            return Err(CapError::InvalidSlot);
        }
        self.slots[index] = Capability::null();
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CapError {
    InvalidSlot,
    SlotOccupied,
    SlotEmpty,
    InsufficientRights,
}
