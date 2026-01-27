//! Capability System
//!
//! Fat capabilities (32 bytes) with rights management.
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod cnode;
mod object;

pub use cnode::CNode;
pub use object::{KernelObject, ObjectType};

/// Capability rights
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Rights {
    Read = 1 << 0,
    Write = 1 << 1,
    Execute = 1 << 2,
    Grant = 1 << 3,
    Revoke = 1 << 4,
}

/// Fat capability (32 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Capability {
    /// Pointer to kernel object
    pub object: *mut KernelObject,
    /// Object type
    pub obj_type: ObjectType,
    /// Access rights
    pub rights: u16,
    /// Badge value (for IPC identification)
    pub badge: u64,
    /// Generation counter (for revocation)
    pub generation: u32,
    /// Reserved for future use
    pub reserved: u32,
}

impl Capability {
    pub const fn null() -> Self {
        Self {
            object: core::ptr::null_mut(),
            obj_type: ObjectType::Null,
            rights: 0,
            badge: 0,
            generation: 0,
            reserved: 0,
        }
    }

    pub fn is_null(&self) -> bool {
        self.object.is_null()
    }

    pub fn has_right(&self, right: Rights) -> bool {
        (self.rights & right as u16) != 0
    }
}

/// Initialize capability system
pub fn init() {
    // Initialize global capability tables
}
