//! Synchronous IPC Endpoint
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{Message, WaitQueue, block_current_thread};
use crate::sched::thread::{Tcb, ThreadState, BlockedReason};

use crate::sched::scheduler::scheduler as get_scheduler;

/// Endpoint state
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EndpointState {
    /// No threads waiting
    Idle,
    /// One or more senders waiting
    SendBlocked,
    /// One or more receivers waiting
    RecvBlocked,
}

/// IPC Endpoint
#[repr(C)]
pub struct Endpoint {
    state: EndpointState,
    /// Queue of waiting senders
    send_queue: WaitQueue,
    /// Queue of waiting receivers
    recv_queue: WaitQueue,
}

impl Endpoint {
    pub const fn new() -> Self {
        Self {
            state: EndpointState::Idle,
            send_queue: WaitQueue::new(),
            recv_queue: WaitQueue::new(),
        }
    }

    /// Send message (blocks until receiver ready)
    pub fn send(&mut self, msg: &Message, badge: u64) {
        unsafe {
            let current = get_scheduler().current();

            match self.state {
                EndpointState::RecvBlocked => {
                    // FASTPATH: Receiver waiting - transfer immediately
                    let receiver = self.recv_queue.pop().unwrap();
                    self.transfer_message(current, receiver, msg, badge);

                    // Wake receiver
                    (*receiver).state = ThreadState::Ready;
                    get_scheduler().enqueue(receiver);

                    // Update state
                    if self.recv_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }
                }
                EndpointState::Idle | EndpointState::SendBlocked => {
                    // SLOWPATH: No receiver - block sender
                    self.send_queue.push(current);
                    self.state = EndpointState::SendBlocked;

                    let reason = BlockedReason::SendBlocked {
                        msg: *msg,
                        badge,
                    };
                    block_current_thread(current, reason);
                }
            }
        }
    }

    /// Receive message (blocks until sender ready)
    pub fn recv(&mut self) -> (Message, u64) {
        unsafe {
            let current = get_scheduler().current();

            match self.state {
                EndpointState::SendBlocked => {
                    // FASTPATH: Sender waiting - transfer immediately
                    let sender = self.send_queue.pop().unwrap();

                    // Extract message from sender's blocked reason
                    let (msg, badge) = match (*sender).blocked_reason {
                        Some(BlockedReason::SendBlocked { msg, badge }) => (msg, badge),
                        _ => (Message::empty(), 0),
                    };

                    self.transfer_message(sender, current, &msg, badge);

                    // Wake sender
                    (*sender).state = ThreadState::Ready;
                    get_scheduler().enqueue(sender);

                    // Update state
                    if self.send_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }

                    (msg, badge)
                }
                EndpointState::Idle | EndpointState::RecvBlocked => {
                    // SLOWPATH: No sender - block receiver
                    self.recv_queue.push(current);
                    self.state = EndpointState::RecvBlocked;

                    block_current_thread(current, BlockedReason::RecvBlocked);

                    // When we wake, message is in saved_caller_*
                    let msg = (*current).saved_caller_msg;
                    let badge = (*current).saved_caller_badge;
                    (msg, badge)
                }
            }
        }
    }

    /// Call (send + recv atomically)
    pub fn call(&mut self, msg: &Message, badge: u64) -> Message {
        self.send(msg, badge);
        self.recv().0
    }

    /// Reply to saved caller and receive next message
    pub fn reply_recv(&mut self, _reply: &Message) -> (Message, u64) {
        unsafe {
            let current = get_scheduler().current();

            // Note: In full implementation, we would reply to saved caller
            // via a reply cap. For now, we skip the reply part as
            // saved_caller is not persisted across calls.

            // Clear saved caller info
            (*current).saved_caller_badge = 0;
        }

        // Now receive next request
        self.recv()
    }

    /// Transfer message from sender to receiver
    unsafe fn transfer_message(
        &self,
        _sender: *mut Tcb,
        receiver: *mut Tcb,
        msg: &Message,
        badge: u64,
    ) {
        // Copy message and badge to receiver's TCB
        (*receiver).saved_caller_msg = *msg;
        (*receiver).saved_caller_badge = badge;
    }
}
