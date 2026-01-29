//! Kernel Objects
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::AtomicU32;

/// Kernel object types
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectType {
    Null = 0,
    Untyped = 1,
    Endpoint = 2,
    Notification = 3,
    Tcb = 4,
    CNode = 5,
    VSpace = 6,
    Frame = 7,
    IrqHandler = 8,
    IoPort = 9,
    SchedContext = 10,
}

/// Base kernel object header with inline reference count
///
/// All kernel objects start with this header.
/// The ref_count field is used for tracking capability references.
#[repr(C)]
pub struct KernelObject {
    /// Object type
    pub obj_type: ObjectType,

    /// Size in bits (for memory objects)
    pub size_bits: u8,

    /// Reference count (number of capabilities referencing this object)
    pub ref_count: AtomicU32,

    /// Padding/reserved
    pub _reserved: u32,
}

impl KernelObject {
    pub const fn new(obj_type: ObjectType, size_bits: u8) -> Self {
        Self {
            obj_type,
            size_bits,
            ref_count: AtomicU32::new(1),
            _reserved: 0,
        }
    }
}
