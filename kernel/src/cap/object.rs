//! Kernel Objects
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// Kernel object types
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
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

/// Base kernel object header
#[repr(C)]
pub struct KernelObject {
    pub obj_type: ObjectType,
    pub size_bits: u8,
    pub generation: u32,
}

impl KernelObject {
    pub const fn new(obj_type: ObjectType, size_bits: u8) -> Self {
        Self {
            obj_type,
            size_bits,
            generation: 0,
        }
    }
}
