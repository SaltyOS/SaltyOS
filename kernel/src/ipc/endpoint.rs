//! Synchronous IPC Endpoint
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{block_current_thread, Message, WaitQueue};
use crate::cap::{KernelObject, ObjectType};
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
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    state: EndpointState,
    /// Queue of waiting senders
    send_queue: WaitQueue,
    /// Queue of waiting receivers
    recv_queue: WaitQueue,
}

impl Endpoint {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::Endpoint, 0),
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
                    (*receiver).reply_can_grant = true;

                    self.transfer_message(current, receiver, msg, badge);

                    // Wake receiver
                    (*receiver).state = ThreadState::Ready;
                    (*receiver).blocked_endpoint = core::ptr::null_mut();
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
                    (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;

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
                    let (msg, badge, is_fault) = match (*sender).blocked_reason {
                        Some(BlockedReason::SendBlocked { msg, badge }) => (msg, badge, false),
                        Some(BlockedReason::FaultBlocked { msg, badge }) => (msg, badge, true),
                        _ => (Message::empty(), 0, false),
                    };

                    // Set up reply capability in receiver's (current thread's) TCB
                    // The receiver can now reply to the sender
                    (*current).reply_tcb = sender;
                    (*current).reply_can_grant = true;

                    self.transfer_message(sender, current, &msg, badge);

                    if is_fault {
                        // Fault sender: keep blocked until reply (via reply_recv)
                        // Just clear endpoint ref since it's no longer in the queue
                        (*sender).blocked_endpoint = core::ptr::null_mut();
                    } else {
                        // Regular sender: wake immediately
                        (*sender).state = ThreadState::Ready;
                        (*sender).blocked_reason = None;
                        (*sender).blocked_endpoint = core::ptr::null_mut();
                        get_scheduler().enqueue(sender);
                    }

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
                    (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;

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
    ///
    /// Copies the message and badge to the receiver's TCB.
    /// If the message has extra caps (capability transfer), those are
    /// transferred from sender's CSpace to receiver's CSpace via their
    /// IPC buffers.
    unsafe fn transfer_message(
        &self,
        sender: *mut Tcb,
        receiver: *mut Tcb,
        msg: &Message,
        badge: u64,
    ) {
        unsafe {
            // Copy message and badge to receiver's TCB
            (*receiver).saved_caller_msg = *msg;
            (*receiver).saved_caller_badge = badge;

            // Check for capability transfer via IPC buffer
            // The sender's IPC buffer caps[] array holds slot indices into
            // sender's CNode. The receiver's IPC buffer receive_cnode/index/depth
            // specify where to place received caps.
            let sender_buf = (*sender).ipc_buffer;
            let receiver_buf = (*receiver).ipc_buffer;
            if sender_buf != 0 && receiver_buf != 0 {
                let sender_ipc = sender_buf as *const super::IpcBuffer;
                let receiver_ipc = receiver_buf as *const super::IpcBuffer;

                // Read extra_caps count from receiver's IPC buffer
                // (sender signals how many caps via msg_info extra_caps field)
                let recv_cnode_ptr = (*receiver_ipc).receive_cnode;
                let recv_index = (*receiver_ipc).receive_index;

                if recv_cnode_ptr != 0 {
                    // Transfer up to 4 caps
                    for i in 0..4u64 {
                        let src_slot_idx = (*sender_ipc).caps[i as usize];
                        if src_slot_idx == 0 { break; }

                        // Look up cap in sender's CSpace
                        let sender_cspace = &*(*sender).cspace_root;
                        let src_cap = match sender_cspace.get(src_slot_idx as usize) {
                            Some(c) => c,
                            None => continue,
                        };

                        // Check Grant right
                        if !src_cap.has_right(crate::cap::CapRights::GRANT) {
                            continue;
                        }

                        // Look up receiver's CNode
                        let recv_cspace = &*(*receiver).cspace_root;
                        let recv_cnode_cap = match recv_cspace.get(recv_cnode_ptr as usize) {
                            Some(c) => c,
                            None => continue,
                        };

                        if recv_cnode_cap.obj_type != crate::cap::ObjectType::CNode {
                            continue;
                        }

                        let recv_cnode = &mut *(recv_cnode_cap.object as *mut crate::cap::CNode);
                        let dest_slot = (recv_index + i) as usize;

                        // Copy capability into receiver's CNode
                        let _ = recv_cnode.copy_slot(
                            dest_slot,
                            sender_cspace,
                            src_slot_idx as usize,
                            src_cap.rights,
                        );
                    }
                }
            }
        }
    }

    /// Deliver a fault message to this endpoint
    ///
    /// Like send(), but the faulting thread is ALWAYS blocked (even on fastpath).
    /// The receiver gets a reply capability to resume the faulting thread.
    ///
    /// Fastpath: handler waiting on recv → transfer message, set reply_tcb, wake handler
    /// Slowpath: no handler → queue faulting thread as sender
    pub fn deliver_fault(&mut self, faulting_tcb: *mut Tcb, msg: &Message) {
        unsafe {
            match self.state {
                EndpointState::RecvBlocked => {
                    // Fastpath: handler already waiting
                    let receiver = self.recv_queue.pop().unwrap();

                    // Set reply cap so handler can reply to resume faulting thread
                    (*receiver).reply_tcb = faulting_tcb;
                    (*receiver).reply_can_grant = false;

                    // Transfer fault message to handler
                    self.transfer_message(faulting_tcb, receiver, msg, 0);

                    // Wake handler
                    (*receiver).state = ThreadState::Ready;
                    (*receiver).blocked_endpoint = core::ptr::null_mut();
                    get_scheduler().enqueue(receiver);

                    if self.recv_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }
                }
                _ => {
                    // Slowpath: no handler waiting — queue faulting thread as sender
                    self.send_queue.push(faulting_tcb);
                    self.state = EndpointState::SendBlocked;
                    (*faulting_tcb).blocked_endpoint = self as *mut Endpoint as *mut u8;
                }
            }
        }
    }

    /// Remove a specific TCB from send or recv queue
    ///
    /// Used when suspending a thread that is blocked on this endpoint.
    /// Returns true if the thread was found and removed.
    pub fn remove_from_queue(&mut self, tcb: *mut Tcb) -> bool {
        if self.send_queue.remove(tcb) {
            if self.send_queue.is_empty() && self.state == EndpointState::SendBlocked {
                self.state = EndpointState::Idle;
            }
            return true;
        }
        if self.recv_queue.remove(tcb) {
            if self.recv_queue.is_empty() && self.state == EndpointState::RecvBlocked {
                self.state = EndpointState::Idle;
            }
            return true;
        }
        false
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
                (*sender).blocked_endpoint = core::ptr::null_mut();
                get_scheduler().enqueue(sender);
            }

            // Wake all blocked receivers
            while let Some(receiver) = self.recv_queue.pop() {
                (*receiver).state = ThreadState::Ready;
                (*receiver).blocked_reason = None;
                (*receiver).blocked_endpoint = core::ptr::null_mut();
                get_scheduler().enqueue(receiver);
            }

            self.state = EndpointState::Idle;
        }
    }
}
