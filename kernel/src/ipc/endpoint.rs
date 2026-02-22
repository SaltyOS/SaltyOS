//! Synchronous IPC Endpoint
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{block_current_thread, Message, WaitQueue};
use crate::cap::{KernelObject, ObjectType};
use crate::sched::thread::{BlockedReason, Tcb, ThreadState};

use crate::sched::scheduler::scheduler as get_scheduler;

/// Depth of the per-endpoint fire-and-forget queue used by `NBSend`.
///
/// Only messages without capability transfer are enqueued. Messages with
/// extra caps still require an active receiver for immediate transfer.
const NBSEND_QUEUE_DEPTH: usize = 64;

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
    /// Ring buffer for non-blocking fire-and-forget messages.
    nbsend_msgs: [Message; NBSEND_QUEUE_DEPTH],
    nbsend_badges: [u64; NBSEND_QUEUE_DEPTH],
    nbsend_head: usize,
    nbsend_tail: usize,
    nbsend_count: usize,
}

impl Endpoint {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::Endpoint, 0),
            state: EndpointState::Idle,
            send_queue: WaitQueue::new(),
            recv_queue: WaitQueue::new(),
            nbsend_msgs: [Message::empty(); NBSEND_QUEUE_DEPTH],
            nbsend_badges: [0; NBSEND_QUEUE_DEPTH],
            nbsend_head: 0,
            nbsend_tail: 0,
            nbsend_count: 0,
        }
    }

    /// Initialize an endpoint in-place without constructing a large by-value
    /// temporary (which can inflate kernel stack usage in retype paths).
    ///
    /// # Safety
    /// `ptr` must point to writable memory large enough for `Endpoint`.
    pub unsafe fn init_at(ptr: *mut Endpoint) {
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<Endpoint>());
            (*ptr).header = KernelObject::new(ObjectType::Endpoint, 0);
            (*ptr).state = EndpointState::Idle;
        }
    }

    /// Get the current endpoint state
    pub fn state(&self) -> EndpointState {
        self.state
    }

    /// Push an async `NBSend` message into the endpoint-local ring buffer.
    ///
    /// Returns `false` when the queue is full.
    fn enqueue_nbsend(&mut self, msg: &Message, badge: u64) -> bool {
        if self.nbsend_count >= NBSEND_QUEUE_DEPTH {
            return false;
        }

        let mut queued = *msg;
        // Queued async messages cannot transfer caps after sender resumes.
        queued.extra_caps = 0;
        queued.caps = [0; 4];

        self.nbsend_msgs[self.nbsend_tail] = queued;
        self.nbsend_badges[self.nbsend_tail] = badge;
        self.nbsend_tail = (self.nbsend_tail + 1) % NBSEND_QUEUE_DEPTH;
        self.nbsend_count += 1;
        true
    }

    /// Pop one queued async `NBSend` message, if present.
    fn dequeue_nbsend(&mut self) -> Option<(Message, u64)> {
        if self.nbsend_count == 0 {
            return None;
        }

        let msg = self.nbsend_msgs[self.nbsend_head];
        let badge = self.nbsend_badges[self.nbsend_head];
        self.nbsend_head = (self.nbsend_head + 1) % NBSEND_QUEUE_DEPTH;
        self.nbsend_count -= 1;
        Some((msg, badge))
    }

    /// Cache the current thread's receive-slot configuration from its IPC buffer.
    /// This must be called while the thread is current (its VSpace is active).
    pub(crate) unsafe fn cache_receive_slot(tcb: *mut Tcb) {
        unsafe {
            if tcb.is_null() {
                return;
            }
            let buf = (*tcb).ipc_buffer;
            if buf == 0 {
                (*tcb).ipc_receive_cnode = 0;
                (*tcb).ipc_receive_index = 0;
                (*tcb).ipc_receive_depth = 0;
                return;
            }

            let ipc_buf = buf as *const super::IpcBuffer;
            (*tcb).ipc_receive_cnode = (*ipc_buf).receive_cnode;
            (*tcb).ipc_receive_index = (*ipc_buf).receive_index;
            (*tcb).ipc_receive_depth = (*ipc_buf).receive_depth;
        }
    }

    /// Send message (blocks until receiver ready)
    pub fn send(&mut self, msg: &Message, badge: u64) {
        unsafe {
            let current = get_scheduler().current();

            match self.state {
                EndpointState::RecvBlocked => {
                    // FASTPATH: Receiver waiting - transfer immediately
                    let receiver = match self.recv_queue.pop() {
                        Some(r) => r,
                        None => {
                            // State inconsistency — recover by falling through to block
                            self.state = EndpointState::Idle;
                            self.send_queue.push(current);
                            self.state = EndpointState::SendBlocked;
                            (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;
                            let reason = BlockedReason::SendBlocked { msg: *msg, badge };
                            block_current_thread(current, reason);
                            return;
                        }
                    };

                    // Send/NBSend do NOT create a reply capability.
                    // Only Call sets reply_tcb (see call() method).

                    // Update endpoint state BEFORE transfer_message: cap transfer
                    // may release SCHED_IPC_LOCK, so the endpoint must be consistent.
                    if self.recv_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }

                    // If receiver was timed, remove from sleep queue
                    if matches!((*receiver).blocked_reason, Some(BlockedReason::RecvTimedBlocked)) {
                        crate::sched::sleep_queue::remove(receiver);
                        (*receiver).timer_wakeup_ns = 0;
                    }

                    // Clear receiver's blocked markers BEFORE transfer_message:
                    // transfer_message may release SCHED_IPC_LOCK for cap transfer,
                    // during which notification.signal() could see stale RecvBlocked
                    // state and double-enqueue the receiver.
                    (*receiver).blocked_reason = None;
                    (*receiver).blocked_endpoint = core::ptr::null_mut();

                    self.transfer_message(current, receiver, msg, badge);

                    // Guard: if receiver was suspended during transfer_message's
                    // SCHED_IPC_LOCK release window (cap transfer), don't resurrect.
                    if (*receiver).state != ThreadState::Inactive {
                        (*receiver).state = ThreadState::Ready;
                        get_scheduler().enqueue(receiver);
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

    /// Non-blocking send.
    ///
    /// Behavior:
    /// - If a receiver is waiting, deliver immediately (same as send fastpath).
    /// - Otherwise, enqueue in endpoint-local async queue and return.
    /// - If queue is full (or message needs cap transfer without receiver), fail.
    ///
    /// Returns `true` on success, `false` if message cannot be accepted.
    pub fn nbsend(&mut self, msg: &Message, badge: u64) -> bool {
        unsafe {
            let current = get_scheduler().current();

            match self.state {
                EndpointState::RecvBlocked => {
                    // Receiver waiting: deliver immediately so caps (if any) can transfer.
                    if let Some(receiver) = self.recv_queue.pop() {
                        if self.recv_queue.is_empty() {
                            self.state = EndpointState::Idle;
                        }

                        // If receiver was timed, remove from sleep queue
                        if matches!((*receiver).blocked_reason, Some(BlockedReason::RecvTimedBlocked)) {
                            crate::sched::sleep_queue::remove(receiver);
                            (*receiver).timer_wakeup_ns = 0;
                        }

                        // Clear blocked markers before transfer_message (see send()).
                        (*receiver).blocked_reason = None;
                        (*receiver).blocked_endpoint = core::ptr::null_mut();

                        self.transfer_message(current, receiver, msg, badge);

                        if (*receiver).state != ThreadState::Inactive {
                            (*receiver).state = ThreadState::Ready;
                            get_scheduler().enqueue(receiver);
                        }
                        true
                    } else {
                        // State inconsistency: recover and fall back to async queue.
                        self.state = EndpointState::Idle;
                        if msg.extra_caps != 0 {
                            false
                        } else {
                            self.enqueue_nbsend(msg, badge)
                        }
                    }
                }
                EndpointState::Idle | EndpointState::SendBlocked => {
                    // No active receiver: only cap-less messages are queueable.
                    if msg.extra_caps != 0 {
                        false
                    } else {
                        self.enqueue_nbsend(msg, badge)
                    }
                }
            }
        }
    }

    /// Receive message (blocks until sender ready)
    pub fn recv(&mut self) -> (Message, u64) {
        unsafe {
            let current = get_scheduler().current();
            Self::cache_receive_slot(current);

            match self.state {
                EndpointState::SendBlocked => {
                    // FASTPATH: Sender waiting - transfer immediately
                    let sender = match self.send_queue.pop() {
                        Some(s) => s,
                        None => {
                            // State inconsistency — recover by blocking receiver
                            self.state = EndpointState::Idle;
                            self.recv_queue.push(current);
                            self.state = EndpointState::RecvBlocked;
                            (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;
                            block_current_thread(current, BlockedReason::RecvBlocked);
                            let msg = (*current).saved_caller_msg;
                            let badge = (*current).saved_caller_badge;
                            return (msg, badge);
                        }
                    };

                    // Extract message from sender's blocked reason and determine
                    // whether sender should be kept blocked (fault/call) or woken
                    let (msg, badge, keep_blocked) = match (*sender).blocked_reason {
                        Some(BlockedReason::SendBlocked { msg, badge }) => (msg, badge, false),
                        Some(BlockedReason::SendTimedBlocked { msg, badge }) => {
                            // Remove timed sender from sleep queue
                            crate::sched::sleep_queue::remove(sender);
                            (*sender).timer_wakeup_ns = 0;
                            (msg, badge, false)
                        }
                        Some(BlockedReason::FaultBlocked { msg, badge }) => (msg, badge, true),
                        Some(BlockedReason::CallSendBlocked { msg, badge }) => (msg, badge, true),
                        _ => (Message::empty(), 0, false),
                    };

                    // Update endpoint state BEFORE transfer_message: cap transfer
                    // may release SCHED_IPC_LOCK, so the endpoint must be consistent.
                    if self.send_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }

                    self.transfer_message(sender, current, &msg, badge);

                    if keep_blocked {
                        // Set reply capability ONLY for Call/Fault senders.
                        // Regular Send senders are woken immediately below
                        // and must not be referenced by reply_tcb.
                        (*current).reply_tcb = sender;
                        (*current).reply_can_grant = !matches!(
                            (*sender).blocked_reason,
                            Some(BlockedReason::FaultBlocked { .. })
                        );
                        // Fault/Call sender: keep blocked until reply (via reply_recv)
                        // Clear endpoint ref since it's no longer in the queue
                        (*sender).blocked_endpoint = core::ptr::null_mut();

                        // For call senders, transition to ReplyWait so reply_recv
                        // can match it (same as fastpath call)
                        if matches!(
                            (*sender).blocked_reason,
                            Some(BlockedReason::CallSendBlocked { .. })
                        ) {
                            (*sender).blocked_reason = Some(BlockedReason::ReplyWait {
                                msg,
                                badge,
                            });
                        }
                    } else {
                        // Regular sender: wake immediately
                        (*sender).state = ThreadState::Ready;
                        (*sender).blocked_reason = None;
                        (*sender).blocked_endpoint = core::ptr::null_mut();
                        get_scheduler().enqueue(sender);
                    }

                    (msg, badge)
                }
                EndpointState::Idle | EndpointState::RecvBlocked => {
                    // Drain queued async NBSend messages before blocking.
                    if let Some((msg, badge)) = self.dequeue_nbsend() {
                        return (msg, badge);
                    }

                    // SLOWPATH: No sender - check bound notification before blocking
                    // If thread has a bound notification with pending bits, return
                    // those immediately instead of blocking on the endpoint.
                    if !(*current).bound_notification.is_null() {
                        let ntfn = &mut *((*current).bound_notification
                            as *mut super::Notification);
                        let bits = ntfn.bits.swap(0, core::sync::atomic::Ordering::SeqCst);
                        if bits != 0 {
                            // Return notification bits as badge, empty message
                            return (Message::empty(), bits);
                        }
                    }

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
    ///
    /// Unlike send() followed by recv(), this is atomic: the caller is blocked
    /// BEFORE the receiver is woken, preventing a race where the receiver
    /// replies before the caller enters the Blocked state.
    pub fn call(&mut self, msg: &Message, badge: u64) -> Message {
        unsafe {
            let current = get_scheduler().current();
            Self::cache_receive_slot(current);

            match self.state {
                EndpointState::RecvBlocked => {
                    // FASTPATH: Receiver waiting - transfer immediately
                    let receiver = match self.recv_queue.pop() {
                        Some(r) => r,
                        None => {
                            // State inconsistency — fall through to slowpath
                            self.state = EndpointState::Idle;
                            self.send_queue.push(current);
                            self.state = EndpointState::SendBlocked;
                            (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;
                            let reason = BlockedReason::CallSendBlocked { msg: *msg, badge };
                            block_current_thread(current, reason);
                            return (*current).saved_caller_msg;
                        }
                    };

                    // Block caller BEFORE waking receiver to prevent race:
                    // Without this, receiver could reply_recv() before caller
                    // sets Blocked, overwriting Ready with Blocked forever.
                    (*current).state = ThreadState::Blocked;
                    (*current).blocked_reason = Some(BlockedReason::ReplyWait {
                        msg: *msg,
                        badge,
                    });

                    // Set up reply capability so receiver can reply to us
                    (*receiver).reply_tcb = current;
                    (*receiver).reply_can_grant = true;

                    // Update endpoint state BEFORE transfer_message: cap transfer
                    // may release SCHED_IPC_LOCK, so the endpoint must be consistent.
                    if self.recv_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }

                    // If receiver was timed, remove from sleep queue
                    if matches!((*receiver).blocked_reason, Some(BlockedReason::RecvTimedBlocked)) {
                        crate::sched::sleep_queue::remove(receiver);
                        (*receiver).timer_wakeup_ns = 0;
                    }

                    // Clear blocked markers before transfer_message (see send()).
                    (*receiver).blocked_reason = None;
                    (*receiver).blocked_endpoint = core::ptr::null_mut();

                    self.transfer_message(current, receiver, msg, badge);

                    // Wake receiver (guard against suspension during cap transfer)
                    if (*receiver).state != ThreadState::Inactive {
                        (*receiver).state = ThreadState::Ready;
                        get_scheduler().enqueue(receiver);
                    }

                    // Caller sleeps until reply_recv() wakes it
                    get_scheduler().reschedule();

                    // Woken by reply - message is in saved_caller_msg
                    (*current).saved_caller_msg
                }
                EndpointState::Idle | EndpointState::SendBlocked => {
                    // SLOWPATH: No receiver - queue caller as CallSendBlocked
                    self.send_queue.push(current);
                    self.state = EndpointState::SendBlocked;
                    (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;

                    let reason = BlockedReason::CallSendBlocked { msg: *msg, badge };
                    block_current_thread(current, reason);

                    // Woken by reply_recv() - message is in saved_caller_msg
                    (*current).saved_caller_msg
                }
            }
        }
    }

    /// Reply to saved caller and receive next message
    pub fn reply_recv(&mut self, reply: &Message) -> (Message, u64) {
        unsafe {
            let current = get_scheduler().current();

            // Reply to saved caller via reply capability
            let caller = (*current).reply_tcb;

            if !caller.is_null() {
                // Transfer reply message to caller's TCB.
                // Fault replies cannot grant capabilities.
                if (*current).reply_can_grant {
                    self.transfer_message(current, caller, reply, 0);
                } else {
                    let mut no_grant_reply = *reply;
                    no_grant_reply.extra_caps = 0;
                    no_grant_reply.caps = [0; 4];
                    self.transfer_message(current, caller, &no_grant_reply, 0);
                }

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
    /// If the message has extra caps, those are copied from sender CSpace to
    /// receiver CSpace using receiver's cached receive slot configuration.
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

            // Check for capability transfer via IPC buffer.
            // Use msg.extra_caps (from sender's msg_info) to bound the loop.
            let cap_count = msg.extra_caps.min(4);
            if cap_count > 0 {
                let recv_cnode_ptr = (*receiver).ipc_receive_cnode;
                let recv_index = (*receiver).ipc_receive_index;

                if recv_cnode_ptr == 0 {
                    return;
                }

                // Release SCHED_IPC_LOCK before acquiring CAP_LOCK to maintain
                // lock ordering: CAP_LOCK → SCHED_IPC_LOCK (never the reverse).
                // Safe: receiver already dequeued, message data copied, IF=0 (no
                // timer on this CPU), only CSpace slot copying remains.
                crate::mm::SCHED_IPC_LOCK.unlock();
                crate::mm::CAP_LOCK.lock();
                for i in 0..cap_count as u64 {
                    let src_slot_idx = msg.caps[i as usize];
                    if src_slot_idx == 0 {
                        continue;
                    }

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
                crate::mm::CAP_LOCK.unlock();
                crate::mm::SCHED_IPC_LOCK.lock();
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
            // Set faulting thread state BEFORE fastpath/slowpath branch.
            // This ensures both paths have correct state — previously the
            // slowpath left blocked_reason as None, causing recv() to
            // deliver an empty message and immediately wake the faulter.
            (*faulting_tcb).state = ThreadState::Blocked;
            (*faulting_tcb).blocked_reason = Some(BlockedReason::FaultBlocked {
                msg: *msg,
                badge: (*faulting_tcb).fault_handler_badge,
            });

            match self.state {
                EndpointState::RecvBlocked => {
                    // Fastpath: handler already waiting
                    let receiver = match self.recv_queue.pop() {
                        Some(r) => r,
                        None => {
                            // State inconsistency — fall through to slowpath
                            self.state = EndpointState::Idle;
                            self.send_queue.push(faulting_tcb);
                            self.state = EndpointState::SendBlocked;
                            (*faulting_tcb).blocked_endpoint = self as *mut Endpoint as *mut u8;
                            return;
                        }
                    };

                    // Set reply cap so handler can reply to resume faulting thread
                    (*receiver).reply_tcb = faulting_tcb;
                    (*receiver).reply_can_grant = false;

                    // Update endpoint state BEFORE transfer_message: cap transfer
                    // may release SCHED_IPC_LOCK, so the endpoint must be consistent.
                    if self.recv_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }

                    // Clear blocked markers before transfer_message (see send()).
                    (*receiver).blocked_reason = None;
                    (*receiver).blocked_endpoint = core::ptr::null_mut();

                    // Transfer fault message to handler (badge identifies faulting client)
                    self.transfer_message(faulting_tcb, receiver, msg, (*faulting_tcb).fault_handler_badge);

                    // Wake handler (guard against suspension during cap transfer)
                    if (*receiver).state != ThreadState::Inactive {
                        (*receiver).state = ThreadState::Ready;
                        get_scheduler().enqueue(receiver);
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

    // ---------------------------------------------------------------
    // Fastpath helpers — direct queue access without blocking/rescheduling
    // ---------------------------------------------------------------

    /// Pop a receiver from the recv queue (fastpath).
    /// Returns None if queue is empty.
    pub(crate) fn fastpath_pop_recv(&mut self) -> Option<*mut Tcb> {
        self.recv_queue.pop()
    }

    /// Push a receiver back to front of recv queue (fastpath rollback).
    pub(crate) fn fastpath_push_recv(&mut self, tcb: *mut Tcb) {
        self.recv_queue.push_front(tcb);
    }

    /// Pop a sender from the send queue (fastpath).
    /// Returns None if queue is empty.
    pub(crate) fn fastpath_pop_send(&mut self) -> Option<*mut Tcb> {
        self.send_queue.pop()
    }

    /// Push a sender back to front of send queue (fastpath rollback).
    pub(crate) fn fastpath_push_send(&mut self, tcb: *mut Tcb) {
        self.send_queue.push_front(tcb);
    }

    /// Check if recv queue is empty (fastpath).
    pub(crate) fn fastpath_recv_queue_empty(&self) -> bool {
        self.recv_queue.is_empty()
    }

    /// Check if send queue is empty (fastpath).
    pub(crate) fn fastpath_send_queue_empty(&self) -> bool {
        self.send_queue.is_empty()
    }

    /// Set endpoint state (fastpath).
    pub(crate) fn fastpath_set_state(&mut self, state: EndpointState) {
        self.state = state;
    }

    /// Send with timeout (blocks until receiver ready or timeout expires).
    ///
    /// Returns 0 on success, `SyscallError::Cancelled` (12) on timeout.
    /// Uses dual-queue pattern: thread is in both endpoint send queue and sleep queue.
    pub fn send_timeout(&mut self, msg: &Message, badge: u64, timeout_ns: u64) -> u64 {
        unsafe {
            let current = get_scheduler().current();

            match self.state {
                EndpointState::RecvBlocked => {
                    // FASTPATH: Receiver waiting - transfer immediately
                    let receiver = match self.recv_queue.pop() {
                        Some(r) => r,
                        None => {
                            self.state = EndpointState::Idle;
                            // Fall through to slowpath below
                            return self.send_timeout_slowpath(current, msg, badge, timeout_ns);
                        }
                    };

                    if self.recv_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }

                    // If receiver was timed, remove from sleep queue
                    if matches!((*receiver).blocked_reason, Some(BlockedReason::RecvTimedBlocked)) {
                        crate::sched::sleep_queue::remove(receiver);
                        (*receiver).timer_wakeup_ns = 0;
                    }

                    (*receiver).blocked_reason = None;
                    (*receiver).blocked_endpoint = core::ptr::null_mut();

                    self.transfer_message(current, receiver, msg, badge);

                    if (*receiver).state != ThreadState::Inactive {
                        (*receiver).state = ThreadState::Ready;
                        get_scheduler().enqueue(receiver);
                    }
                    0 // success
                }
                EndpointState::Idle | EndpointState::SendBlocked => {
                    self.send_timeout_slowpath(current, msg, badge, timeout_ns)
                }
            }
        }
    }

    /// Slowpath for send_timeout: block sender in dual queue.
    unsafe fn send_timeout_slowpath(
        &mut self,
        current: *mut Tcb,
        msg: &Message,
        badge: u64,
        timeout_ns: u64,
    ) -> u64 {
        unsafe {
            self.send_queue.push(current);
            self.state = EndpointState::SendBlocked;
            (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;
            (*current).blocked_reason = Some(BlockedReason::SendTimedBlocked {
                msg: *msg,
                badge,
            });
            (*current).state = ThreadState::Blocked;
            (*current).futex_wakeup_result = 0;

            // Insert into sleep queue for timeout wakeup
            let now_ns = crate::arch::now_ns();
            let wakeup_ns = now_ns.saturating_add(timeout_ns);
            get_scheduler().block_current_futex_timed(wakeup_ns);

            // When we resume: check if we timed out
            (*current).futex_wakeup_result
        }
    }

    /// Receive with timeout (blocks until sender ready or timeout expires).
    ///
    /// Returns `(msg, badge, result)` where result is 0 on success or
    /// `SyscallError::Cancelled` (12) on timeout.
    pub fn recv_timeout(&mut self, timeout_ns: u64) -> (Message, u64, u64) {
        unsafe {
            let current = get_scheduler().current();
            Endpoint::cache_receive_slot(current);

            match self.state {
                EndpointState::SendBlocked => {
                    // FASTPATH: Sender waiting - transfer immediately
                    let sender = match self.send_queue.pop() {
                        Some(s) => s,
                        None => {
                            self.state = EndpointState::Idle;
                            return self.recv_timeout_slowpath(current, timeout_ns);
                        }
                    };

                    let (msg, badge, keep_blocked) = match (*sender).blocked_reason {
                        Some(BlockedReason::SendBlocked { msg, badge }) => (msg, badge, false),
                        Some(BlockedReason::SendTimedBlocked { msg, badge }) => {
                            // Remove timed sender from sleep queue
                            crate::sched::sleep_queue::remove(sender);
                            (*sender).timer_wakeup_ns = 0;
                            (msg, badge, false)
                        }
                        Some(BlockedReason::FaultBlocked { msg, badge }) => (msg, badge, true),
                        Some(BlockedReason::CallSendBlocked { msg, badge }) => (msg, badge, true),
                        _ => (Message::empty(), 0, false),
                    };

                    if self.send_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }

                    self.transfer_message(sender, current, &msg, badge);

                    if keep_blocked {
                        (*current).reply_tcb = sender;
                        (*current).reply_can_grant = !matches!(
                            (*sender).blocked_reason,
                            Some(BlockedReason::FaultBlocked { .. })
                        );
                        (*sender).blocked_endpoint = core::ptr::null_mut();
                        if matches!(
                            (*sender).blocked_reason,
                            Some(BlockedReason::CallSendBlocked { .. })
                        ) {
                            (*sender).blocked_reason = Some(BlockedReason::ReplyWait {
                                msg,
                                badge,
                            });
                        }
                    } else {
                        (*sender).state = ThreadState::Ready;
                        (*sender).blocked_reason = None;
                        (*sender).blocked_endpoint = core::ptr::null_mut();
                        get_scheduler().enqueue(sender);
                    }

                    (msg, badge, 0) // success
                }
                EndpointState::Idle | EndpointState::RecvBlocked => {
                    // Drain queued async NBSend messages before blocking
                    if let Some((msg, badge)) = self.dequeue_nbsend() {
                        return (msg, badge, 0);
                    }

                    // Check bound notification
                    if !(*current).bound_notification.is_null() {
                        let ntfn = &mut *((*current).bound_notification
                            as *mut super::Notification);
                        let bits = ntfn.bits.swap(0, core::sync::atomic::Ordering::SeqCst);
                        if bits != 0 {
                            return (Message::empty(), bits, 0);
                        }
                    }

                    self.recv_timeout_slowpath(current, timeout_ns)
                }
            }
        }
    }

    /// Slowpath for recv_timeout: block receiver in dual queue.
    unsafe fn recv_timeout_slowpath(
        &mut self,
        current: *mut Tcb,
        timeout_ns: u64,
    ) -> (Message, u64, u64) {
        unsafe {
            self.recv_queue.push(current);
            self.state = EndpointState::RecvBlocked;
            (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;
            (*current).blocked_reason = Some(BlockedReason::RecvTimedBlocked);
            (*current).state = ThreadState::Blocked;
            (*current).futex_wakeup_result = 0;

            // Insert into sleep queue for timeout wakeup
            let now_ns = crate::arch::now_ns();
            let wakeup_ns = now_ns.saturating_add(timeout_ns);
            get_scheduler().block_current_futex_timed(wakeup_ns);

            // When we resume: check result
            let result = (*current).futex_wakeup_result;
            if result != 0 {
                // Timed out — return empty message
                (Message::empty(), 0, result)
            } else {
                // Woken by sender — message is in saved_caller_*
                let msg = (*current).saved_caller_msg;
                let badge = (*current).saved_caller_badge;
                (msg, badge, 0)
            }
        }
    }

    /// Cleanup when endpoint is destroyed
    ///
    /// Wake all blocked threads with error.
    /// Called from destroy_object() with CAP_LOCK held and IRQs disabled.
    /// Acquires SCHED_IPC_LOCK to safely manipulate IPC queues and TCB state.
    pub fn cleanup(&mut self) {
        // Lock ordering: CAP_LOCK (held by caller) → SCHED_IPC_LOCK — correct.
        // IRQs are already disabled from the CAP_LOCK acquisition path.
        crate::mm::SCHED_IPC_LOCK.lock();

        unsafe {
            // Wake all blocked senders
            while let Some(sender) = self.send_queue.pop() {
                // Remove timed senders from sleep queue
                if matches!((*sender).blocked_reason, Some(BlockedReason::SendTimedBlocked { .. })) {
                    crate::sched::sleep_queue::remove(sender);
                    (*sender).timer_wakeup_ns = 0;
                }
                (*sender).state = ThreadState::Ready;
                (*sender).blocked_reason = None;
                (*sender).blocked_endpoint = core::ptr::null_mut();
                get_scheduler().enqueue(sender);
            }

            // Wake all blocked receivers
            while let Some(receiver) = self.recv_queue.pop() {
                // Remove timed receivers from sleep queue
                if matches!((*receiver).blocked_reason, Some(BlockedReason::RecvTimedBlocked)) {
                    crate::sched::sleep_queue::remove(receiver);
                    (*receiver).timer_wakeup_ns = 0;
                }
                (*receiver).state = ThreadState::Ready;
                (*receiver).blocked_reason = None;
                (*receiver).blocked_endpoint = core::ptr::null_mut();
                get_scheduler().enqueue(receiver);
            }

            self.state = EndpointState::Idle;
            self.nbsend_head = 0;
            self.nbsend_tail = 0;
            self.nbsend_count = 0;
        }

        crate::mm::SCHED_IPC_LOCK.unlock();
    }
}
