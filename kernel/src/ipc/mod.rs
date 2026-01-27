//! IPC Subsystem
//!
//! Synchronous endpoints and asynchronous notifications.
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod endpoint;
mod notification;

/// IPC message (register-based for fastpath)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Message {
    /// Message label/tag
    pub label: u64,
    /// Message registers
    pub regs: [u64; 4],
}

impl Message {
    pub const fn empty() -> Self {
        Self {
            label: 0,
            regs: [0; 4],
        }
    }
}

/// Initialize IPC subsystem
pub fn init() {
    // Initialize IPC structures
}
