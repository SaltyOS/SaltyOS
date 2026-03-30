//! I/O Port Range
//!
//! Kernel object representing a range of x86 I/O ports.
//! Access is mediated through capabilities to enforce isolation.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::cap::object::{KernelObject, ObjectType};

/// I/O port range kernel object
#[repr(C)]
pub struct IoPortRange {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    /// Base I/O port number
    pub base_port: u16,
    /// Number of ports in this range
    pub num_ports: u16,
}

impl IoPortRange {
    pub const fn new(base_port: u16, num_ports: u16) -> Self {
        Self {
            header: KernelObject::new(ObjectType::IoPort, 0),
            base_port,
            num_ports,
        }
    }
}
