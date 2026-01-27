//! Asynchronous Notification
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// Notification object for async signaling
#[repr(C)]
pub struct Notification {
    /// Pending notification bits
    bits: u64,
    /// Waiting thread (if any)
    waiting: *mut u8,
}

impl Notification {
    pub const fn new() -> Self {
        Self {
            bits: 0,
            waiting: core::ptr::null_mut(),
        }
    }

    /// Signal notification (set bits)
    pub fn signal(&mut self, bits: u64) {
        self.bits |= bits;
        // TODO: Wake waiting thread if any
    }

    /// Wait for notification
    pub fn wait(&mut self) -> u64 {
        // TODO: Block if no bits set
        let bits = self.bits;
        self.bits = 0;
        bits
    }

    /// Poll without blocking
    pub fn poll(&mut self) -> Option<u64> {
        if self.bits != 0 {
            let bits = self.bits;
            self.bits = 0;
            Some(bits)
        } else {
            None
        }
    }
}
