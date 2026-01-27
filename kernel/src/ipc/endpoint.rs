//! Synchronous IPC Endpoint
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::Message;

/// Endpoint state
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EndpointState {
    Idle,
    Send,
    Recv,
}

/// IPC Endpoint
#[repr(C)]
pub struct Endpoint {
    state: EndpointState,
    /// Queue of waiting threads (TCB pointers)
    queue_head: *mut u8,
    queue_tail: *mut u8,
}

impl Endpoint {
    pub const fn new() -> Self {
        Self {
            state: EndpointState::Idle,
            queue_head: core::ptr::null_mut(),
            queue_tail: core::ptr::null_mut(),
        }
    }

    /// Send message (blocks until receiver ready)
    pub fn send(&mut self, _msg: &Message, _badge: u64) {
        // TODO: Implement send
        // 1. If receiver waiting, transfer message directly
        // 2. Otherwise, queue sender and block
    }

    /// Receive message (blocks until sender ready)
    pub fn recv(&mut self) -> (Message, u64) {
        // TODO: Implement recv
        // 1. If sender waiting, receive message directly
        // 2. Otherwise, queue receiver and block
        (Message::empty(), 0)
    }

    /// Call (send + recv atomically)
    pub fn call(&mut self, msg: &Message, badge: u64) -> Message {
        self.send(msg, badge);
        self.recv().0
    }

    /// Reply and receive next
    pub fn reply_recv(&mut self, _reply: &Message) -> (Message, u64) {
        // TODO: Implement reply_recv
        (Message::empty(), 0)
    }
}
