//! Synchronous IPC Endpoint
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{block_current_thread, Message, WaitQueue};
use crate::sched::thread::{BlockedReason, Tcb, ThreadState};

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

    /// Get the current endpoint state
    pub fn state(&self) -> EndpointState {
        self.state
    }

    /// Send message (blocks until receiver ready)
    pub fn send(&mut self, msg: &Message, badge: u64) {
        unsafe {
            let current = get_scheduler().current();

            match self.state {
                EndpointState::RecvBlocked => {
                    // FASTPATH: Receiver waiting - transfer immediately
                    let receiver = self.recv_queue.pop().unwrap();

                    // Set up reply capability in receiver's TCB
                    // The receiver (server) can now reply to the sender (client)
                    (*receiver).reply_tcb = current;
                    (*receiver).reply_can_grant = false; // TODO: check sender's grant right

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

                    let reason = BlockedReason::SendBlocked { msg: *msg, badge };
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

                    // Set up reply capability in receiver's (current thread's) TCB
                    // The receiver can now reply to the sender
                    (*current).reply_tcb = sender;
                    (*current).reply_can_grant = false; // TODO: check sender's grant right

                    self.transfer_message(sender, current, &msg, badge);

                    // Wake sender (for regular send, not call - call sender stays blocked)
                    (*sender).state = ThreadState::Ready;
                    (*sender).blocked_reason = None;
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

        // After send, we need to receive a reply
        // The reply will come via the server's reply_tcb capability
        unsafe {
            let current = get_scheduler().current();

            // Wait for reply
            // The reply will be delivered to saved_caller_msg by the server
            (*current).state = ThreadState::Blocked;
            (*current).blocked_reason = Some(BlockedReason::ReplyWait { msg: *msg, badge });
            get_scheduler().reschedule();

            // When we wake up, the reply is in saved_caller_msg
            (*current).saved_caller_msg
        }
    }

    /// Reply to saved caller and receive next message
    pub fn reply_recv(&mut self, reply: &Message) -> (Message, u64) {
        unsafe {
            let current = get_scheduler().current();

            // Reply to saved caller via reply capability
            let caller = (*current).reply_tcb;

            if !caller.is_null() {
                // Transfer reply message to caller's TCB
                (*caller).saved_caller_msg = *reply;
                (*caller).saved_caller_badge = 0;

                // Clear caller's blocked reason
                (*caller).blocked_reason = None;

                // Wake the caller
                (*caller).state = ThreadState::Ready;
                get_scheduler().enqueue(caller);

                // Clear reply capability (one-shot)
                (*current).reply_tcb = core::ptr::null_mut();
                (*current).reply_can_grant = false;
            }
            // If caller is null, there's no one to reply to - just proceed to recv
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
        unsafe {
            // Copy message and badge to receiver's TCB
            (*receiver).saved_caller_msg = *msg;
            (*receiver).saved_caller_badge = badge;
        }
    }

    /// Cleanup when endpoint is destroyed
    ///
    /// Wake all blocked threads with error.
    pub fn cleanup(&mut self) {
        unsafe {
            // Wake all blocked senders
            while let Some(sender) = self.send_queue.pop() {
                (*sender).state = ThreadState::Ready;
                (*sender).blocked_reason = None;
                get_scheduler().enqueue(sender);
            }

            // Wake all blocked receivers
            while let Some(receiver) = self.recv_queue.pop() {
                (*receiver).state = ThreadState::Ready;
                (*receiver).blocked_reason = None;
                get_scheduler().enqueue(receiver);
            }

            self.state = EndpointState::Idle;
        }
    }
}
