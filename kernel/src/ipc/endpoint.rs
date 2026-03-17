//! Synchronous IPC Endpoint
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{Message, WaitQueue};
use crate::cap::{KernelObject, ObjectType};
use crate::sched::thread::{BlockedReason, Tcb, ThreadState};

use crate::sched::scheduler::scheduler as get_scheduler;

/// Depth of the per-endpoint fire-and-forget queue used by `NBSend`.
///
/// Only messages without capability transfer are enqueued. Messages with
/// extra caps still require an active receiver for immediate transfer.
const NBSEND_QUEUE_DEPTH: usize = 64;
const POSIX_PM_EXEC_LABEL: u64 = 6;
const IPC_BUFFER_RESERVED_BYTES: usize = core::mem::size_of::<[u64; 478]>();

fn exec_payload_len(msg: &Message) -> Option<usize> {
    if msg.label != POSIX_PM_EXEC_LABEL {
        return None;
    }

    let path_len = msg.regs[0] as usize;
    if path_len > 64 {
        return None;
    }

    let path_regs = 1 + ((path_len + 7) / 8);
    let len_reg = path_regs + 1;
    if len_reg >= msg.length || len_reg >= msg.regs.len() {
        return None;
    }

    let payload_len = msg.regs[len_reg] as usize;
    if payload_len > IPC_BUFFER_RESERVED_BYTES {
        return None;
    }
    Some(payload_len)
}

unsafe fn resolve_ipc_buffer_ptr(tcb: *mut Tcb) -> Option<*mut super::IpcBuffer> {
    unsafe {
        if tcb.is_null() {
            return None;
        }

        let ipc_buffer = (*tcb).ipc_buffer;
        if ipc_buffer == 0 || (ipc_buffer & 0xFFF) != 0 || (*tcb).vspace_root.is_null() {
            return None;
        }

        let vspace = &*(*tcb).vspace_root;
        let phys = vspace.resolve_page(ipc_buffer)?;
        Some(crate::mm::phys_to_virt(phys) as *mut super::IpcBuffer)
    }
}

unsafe fn transfer_exec_payload(sender: *mut Tcb, receiver: *mut Tcb, msg: &Message) {
    unsafe {
        if msg.label != POSIX_PM_EXEC_LABEL {
            return;
        }

        let Some(receiver_buf) = resolve_ipc_buffer_ptr(receiver) else {
            return;
        };
        let dst = (*receiver_buf).reserved.as_mut_ptr() as *mut u8;
        core::ptr::write_bytes(dst, 0, IPC_BUFFER_RESERVED_BYTES);

        let Some(payload_len) = exec_payload_len(msg) else {
            return;
        };
        if payload_len == 0 {
            return;
        }

        let Some(sender_buf) = resolve_ipc_buffer_ptr(sender) else {
            return;
        };
        let src = (*sender_buf).reserved.as_ptr() as *const u8;
        core::ptr::copy(src, dst, payload_len);
    }
}

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
    /// Per-endpoint spinlock (Zircon-style per-object locking).
    ///
    /// Lock ordering: CAP_LOCK → endpoint.lock → sched.lock_cpu
    /// Context switch and reschedule MUST happen OUTSIDE ep_lock.
    lock: core::sync::atomic::AtomicU8,
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
            lock: core::sync::atomic::AtomicU8::new(0),
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

    /// Acquire per-endpoint lock.
    #[inline]
    pub fn ep_lock(&self) {
        use core::sync::atomic::Ordering;
        if self.lock.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return;
        }
        let mut backoff: u32 = 0;
        loop {
            for _ in 0..(1u32 << backoff.min(6)) {
                core::hint::spin_loop();
            }
            if self.lock.load(Ordering::Relaxed) == 0
                && self.lock.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
            {
                return;
            }
            if backoff < 6 { backoff += 1; }
        }
    }

    /// Release per-endpoint lock.
    #[inline]
    pub fn ep_unlock(&self) {
        self.lock.store(0, core::sync::atomic::Ordering::Release);
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
            self.ep_lock();
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
                            super::block_current_thread_no_switch(current, BlockedReason::SendBlocked { msg: *msg, badge });
                            self.ep_unlock();
                            get_scheduler().reschedule();
                            return;
                        }
                    };

                    if self.recv_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }

                    if matches!((*receiver).blocked_reason, Some(BlockedReason::RecvTimedBlocked)) {
                        crate::sched::sleep_queue::remove(receiver);
                        (*receiver).timer_wakeup_ns = 0;
                    }

                    (*receiver).blocked_reason = None;
                    (*receiver).blocked_endpoint = core::ptr::null_mut();

                    self.transfer_message(current, receiver, msg, badge);

                    if (*receiver).state != ThreadState::Inactive {
                        (*receiver).state = ThreadState::Ready;
                    }
                    self.ep_unlock();
                    if (*receiver).state == ThreadState::Ready {
                        get_scheduler().enqueue(receiver);
                    }
                }
                EndpointState::Idle | EndpointState::SendBlocked => {
                    // SLOWPATH: No receiver - block sender
                    self.send_queue.push(current);
                    self.state = EndpointState::SendBlocked;
                    (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;
                    super::block_current_thread_no_switch(current, BlockedReason::SendBlocked { msg: *msg, badge });
                    self.ep_unlock();
                    get_scheduler().reschedule();
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
            self.ep_lock();
            let current = get_scheduler().current();

            let result = match self.state {
                EndpointState::RecvBlocked => {
                    if let Some(receiver) = self.recv_queue.pop() {
                        if self.recv_queue.is_empty() {
                            self.state = EndpointState::Idle;
                        }

                        if matches!((*receiver).blocked_reason, Some(BlockedReason::RecvTimedBlocked)) {
                            crate::sched::sleep_queue::remove(receiver);
                            (*receiver).timer_wakeup_ns = 0;
                        }

                        (*receiver).blocked_reason = None;
                        (*receiver).blocked_endpoint = core::ptr::null_mut();

                        self.transfer_message(current, receiver, msg, badge);

                        let wake = (*receiver).state != ThreadState::Inactive;
                        if wake {
                            (*receiver).state = ThreadState::Ready;
                        }
                        self.ep_unlock();
                        if wake {
                            get_scheduler().enqueue(receiver);
                        }
                        return true;
                    } else {
                        self.state = EndpointState::Idle;
                        if msg.extra_caps != 0 {
                            false
                        } else {
                            self.enqueue_nbsend(msg, badge)
                        }
                    }
                }
                EndpointState::Idle | EndpointState::SendBlocked => {
                    if msg.extra_caps != 0 {
                        false
                    } else {
                        self.enqueue_nbsend(msg, badge)
                    }
                }
            };
            self.ep_unlock();
            result
        }
    }

    /// Receive phase (inner) — ep_lock MUST be held by caller.
    ///
    /// Returns `Some((msg, badge, wake_tcb))` on non-blocking path.
    /// `wake_tcb` is a sender to enqueue (or null if kept blocked / no sender to wake).
    /// Returns `None` if thread is now Blocked and needs reschedule after ep_unlock.
    unsafe fn recv_inner(&mut self, current: *mut Tcb) -> Option<(Message, u64, *mut Tcb)> {
        unsafe {
            match self.state {
                EndpointState::SendBlocked => {
                    let sender = match self.send_queue.pop() {
                        Some(s) => s,
                        None => {
                            // State inconsistency — block receiver
                            self.state = EndpointState::Idle;
                            self.recv_queue.push(current);
                            self.state = EndpointState::RecvBlocked;
                            (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;
                            super::block_current_thread_no_switch(current, BlockedReason::RecvBlocked);
                            return None;
                        }
                    };

                    let (msg, badge, keep_blocked) = match (*sender).blocked_reason {
                        Some(BlockedReason::SendBlocked { msg, badge }) => (msg, badge, false),
                        Some(BlockedReason::SendTimedBlocked { msg, badge }) => {
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
                        crate::sched::pip::pip_donate(sender, current);
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
                        Some((msg, badge, core::ptr::null_mut()))
                    } else {
                        (*sender).state = ThreadState::Ready;
                        (*sender).blocked_reason = None;
                        (*sender).blocked_endpoint = core::ptr::null_mut();
                        Some((msg, badge, sender))
                    }
                }
                EndpointState::Idle | EndpointState::RecvBlocked => {
                    if let Some((msg, badge)) = self.dequeue_nbsend() {
                        return Some((msg, badge, core::ptr::null_mut()));
                    }

                    if !(*current).bound_notification.is_null() {
                        let ntfn = &mut *((*current).bound_notification
                            as *mut super::Notification);
                        let bits = ntfn.bits.swap(0, core::sync::atomic::Ordering::SeqCst);
                        if bits != 0 {
                            return Some((Message::empty(), bits, core::ptr::null_mut()));
                        }
                    }

                    self.recv_queue.push(current);
                    self.state = EndpointState::RecvBlocked;
                    (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;
                    super::block_current_thread_no_switch(current, BlockedReason::RecvBlocked);
                    None
                }
            }
        }
    }

    /// Receive message (blocks until sender ready)
    pub fn recv(&mut self) -> (Message, u64) {
        unsafe {
            self.ep_lock();
            let current = get_scheduler().current();

            // Clear stale reply capability
            if !(*current).reply_tcb.is_null() {
                crate::sched::pip::pip_undonate(current, (*current).reply_tcb);
                (*current).reply_tcb = core::ptr::null_mut();
                (*current).reply_can_grant = false;
            }

            Self::cache_receive_slot(current);

            if let Some((msg, badge, wake)) = self.recv_inner(current) {
                self.ep_unlock();
                if !wake.is_null() {
                    get_scheduler().enqueue(wake);
                }
                return (msg, badge);
            }

            // Blocked — release lock, then reschedule
            self.ep_unlock();
            get_scheduler().reschedule();

            let msg = (*current).saved_caller_msg;
            let badge = (*current).saved_caller_badge;
            (msg, badge)
        }
    }

    /// Call (send + recv atomically)
    ///
    /// Unlike send() followed by recv(), this is atomic: the caller is blocked
    /// BEFORE the receiver is woken, preventing a race where the receiver
    /// replies before the caller enters the Blocked state.
    pub fn call(&mut self, msg: &Message, badge: u64) -> Message {
        unsafe {
            self.ep_lock();
            let current = get_scheduler().current();
            Self::cache_receive_slot(current);

            match self.state {
                EndpointState::RecvBlocked => {
                    let receiver = match self.recv_queue.pop() {
                        Some(r) => r,
                        None => {
                            self.state = EndpointState::Idle;
                            self.send_queue.push(current);
                            self.state = EndpointState::SendBlocked;
                            (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;
                            super::block_current_thread_no_switch(current, BlockedReason::CallSendBlocked { msg: *msg, badge });
                            self.ep_unlock();
                            get_scheduler().reschedule();
                            return (*current).saved_caller_msg;
                        }
                    };

                    // Block caller BEFORE waking receiver
                    (*current).state = ThreadState::Blocked;
                    (*current).blocked_reason = Some(BlockedReason::ReplyWait {
                        msg: *msg,
                        badge,
                    });

                    (*receiver).reply_tcb = current;
                    (*receiver).reply_can_grant = true;
                    crate::sched::pip::pip_donate(current, receiver);

                    if self.recv_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }

                    if matches!((*receiver).blocked_reason, Some(BlockedReason::RecvTimedBlocked)) {
                        crate::sched::sleep_queue::remove(receiver);
                        (*receiver).timer_wakeup_ns = 0;
                    }

                    (*receiver).blocked_reason = None;
                    (*receiver).blocked_endpoint = core::ptr::null_mut();

                    self.transfer_message(current, receiver, msg, badge);

                    let wake_receiver = (*receiver).state != ThreadState::Inactive;
                    if wake_receiver {
                        (*receiver).state = ThreadState::Ready;
                    }
                    self.ep_unlock();
                    if wake_receiver {
                        get_scheduler().enqueue(receiver);
                    }

                    // Caller blocked (ReplyWait) — reschedule with no lock held
                    get_scheduler().reschedule();
                    (*current).saved_caller_msg
                }
                EndpointState::Idle | EndpointState::SendBlocked => {
                    self.send_queue.push(current);
                    self.state = EndpointState::SendBlocked;
                    (*current).blocked_endpoint = self as *mut Endpoint as *mut u8;
                    super::block_current_thread_no_switch(current, BlockedReason::CallSendBlocked { msg: *msg, badge });
                    self.ep_unlock();
                    get_scheduler().reschedule();
                    (*current).saved_caller_msg
                }
            }
        }
    }

    /// Reply to saved caller and receive next message
    pub fn reply_recv(&mut self, reply: &Message) -> (Message, u64) {
        unsafe {
            self.ep_lock();
            let current = get_scheduler().current();

            // ---- REPLY PHASE ----
            let caller = (*current).reply_tcb;
            let mut wake_caller: *mut Tcb = core::ptr::null_mut();

            if !caller.is_null() {
                let caller_replyable = (*caller).state == ThreadState::Blocked
                    && matches!(
                        (*caller).blocked_reason,
                        Some(BlockedReason::ReplyWait { .. }) | Some(BlockedReason::FaultBlocked { .. })
                    );

                if caller_replyable {
                    crate::sched::pip::pip_undonate(current, caller);

                    if (*current).reply_can_grant {
                        self.transfer_message(current, caller, reply, 0);
                    } else {
                        let mut no_grant_reply = *reply;
                        no_grant_reply.extra_caps = 0;
                        no_grant_reply.caps = [0; 4];
                        self.transfer_message(current, caller, &no_grant_reply, 0);
                    }

                    (*caller).blocked_reason = None;
                    (*caller).state = ThreadState::Ready;
                    wake_caller = caller;
                }

                (*current).reply_tcb = core::ptr::null_mut();
                (*current).reply_can_grant = false;
            }

            // ---- RECV PHASE ----
            Self::cache_receive_slot(current);

            if let Some((msg, badge, wake_sender)) = self.recv_inner(current) {
                self.ep_unlock();
                // Wake caller and/or sender outside lock
                if !wake_caller.is_null() {
                    get_scheduler().enqueue(wake_caller);
                }
                if !wake_sender.is_null() {
                    get_scheduler().enqueue(wake_sender);
                }
                return (msg, badge);
            }

            // Blocked — release lock, wake caller, reschedule
            self.ep_unlock();
            if !wake_caller.is_null() {
                get_scheduler().enqueue(wake_caller);
            }
            get_scheduler().reschedule();

            let msg = (*current).saved_caller_msg;
            let badge = (*current).saved_caller_badge;
            (msg, badge)
        }
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
            transfer_exec_payload(sender, receiver, msg);

            // Check for capability transfer via IPC buffer.
            // Use msg.extra_caps (from sender's msg_info) to bound the loop.
            let cap_count = msg.extra_caps.min(4);
            if cap_count > 0 {
                let recv_cnode_ptr = (*receiver).ipc_receive_cnode;
                let recv_index = (*receiver).ipc_receive_index;

                if recv_cnode_ptr == 0 {
                    return;
                }

                // Release endpoint lock before acquiring CAP_LOCK to maintain
                // lock ordering: CAP_LOCK → endpoint.lock (never the reverse).
                // Safe: receiver already dequeued, message data copied, IF=0 (no
                // timer on this CPU), only CSpace slot copying remains.
                self.ep_unlock();
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
                self.ep_lock();
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
            self.ep_lock();

            if (*faulting_tcb).state == ThreadState::Inactive {
                self.ep_unlock();
                return;
            }

            (*faulting_tcb).state = ThreadState::Blocked;
            (*faulting_tcb).blocked_reason = Some(BlockedReason::FaultBlocked {
                msg: *msg,
                badge: (*faulting_tcb).fault_handler_badge,
            });

            match self.state {
                EndpointState::RecvBlocked => {
                    let receiver = match self.recv_queue.pop() {
                        Some(r) => r,
                        None => {
                            self.state = EndpointState::Idle;
                            self.send_queue.push(faulting_tcb);
                            self.state = EndpointState::SendBlocked;
                            (*faulting_tcb).blocked_endpoint = self as *mut Endpoint as *mut u8;
                            self.ep_unlock();
                            return;
                        }
                    };

                    (*receiver).reply_tcb = faulting_tcb;
                    (*receiver).reply_can_grant = false;

                    if self.recv_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }

                    (*receiver).blocked_reason = None;
                    (*receiver).blocked_endpoint = core::ptr::null_mut();

                    self.transfer_message(faulting_tcb, receiver, msg, (*faulting_tcb).fault_handler_badge);

                    let wake = (*receiver).state != ThreadState::Inactive;
                    if wake {
                        (*receiver).state = ThreadState::Ready;
                    }
                    self.ep_unlock();
                    if wake {
                        get_scheduler().enqueue(receiver);
                    }
                }
                _ => {
                    self.send_queue.push(faulting_tcb);
                    self.state = EndpointState::SendBlocked;
                    (*faulting_tcb).blocked_endpoint = self as *mut Endpoint as *mut u8;
                    self.ep_unlock();
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
            self.ep_lock();
            let current = get_scheduler().current();

            match self.state {
                EndpointState::RecvBlocked => {
                    let receiver = match self.recv_queue.pop() {
                        Some(r) => r,
                        None => {
                            self.state = EndpointState::Idle;
                            return self.send_timeout_slowpath(current, msg, badge, timeout_ns);
                        }
                    };

                    if self.recv_queue.is_empty() {
                        self.state = EndpointState::Idle;
                    }

                    if matches!((*receiver).blocked_reason, Some(BlockedReason::RecvTimedBlocked)) {
                        crate::sched::sleep_queue::remove(receiver);
                        (*receiver).timer_wakeup_ns = 0;
                    }

                    (*receiver).blocked_reason = None;
                    (*receiver).blocked_endpoint = core::ptr::null_mut();

                    self.transfer_message(current, receiver, msg, badge);

                    let wake = (*receiver).state != ThreadState::Inactive;
                    if wake {
                        (*receiver).state = ThreadState::Ready;
                    }
                    self.ep_unlock();
                    if wake {
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
    /// ep_lock MUST be held on entry; released before reschedule.
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

            self.ep_unlock();

            let now_ns = crate::arch::now_ns();
            let wakeup_ns = now_ns.saturating_add(timeout_ns);
            get_scheduler().block_current_futex_timed(wakeup_ns);

            (*current).futex_wakeup_result
        }
    }

    /// Receive with timeout (blocks until sender ready or timeout expires).
    ///
    /// Returns `(msg, badge, result)` where result is 0 on success or
    /// `SyscallError::Cancelled` (12) on timeout.
    pub fn recv_timeout(&mut self, timeout_ns: u64) -> (Message, u64, u64) {
        unsafe {
            self.ep_lock();
            let current = get_scheduler().current();

            if !(*current).reply_tcb.is_null() {
                crate::sched::pip::pip_undonate(current, (*current).reply_tcb);
                (*current).reply_tcb = core::ptr::null_mut();
                (*current).reply_can_grant = false;
            }

            Endpoint::cache_receive_slot(current);

            match self.state {
                EndpointState::SendBlocked => {
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
                        crate::sched::pip::pip_donate(sender, current);
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
                        self.ep_unlock();
                    } else {
                        (*sender).state = ThreadState::Ready;
                        (*sender).blocked_reason = None;
                        (*sender).blocked_endpoint = core::ptr::null_mut();
                        self.ep_unlock();
                        get_scheduler().enqueue(sender);
                    }

                    (msg, badge, 0)
                }
                EndpointState::Idle | EndpointState::RecvBlocked => {
                    if let Some((msg, badge)) = self.dequeue_nbsend() {
                        self.ep_unlock();
                        return (msg, badge, 0);
                    }

                    if !(*current).bound_notification.is_null() {
                        let ntfn = &mut *((*current).bound_notification
                            as *mut super::Notification);
                        let bits = ntfn.bits.swap(0, core::sync::atomic::Ordering::SeqCst);
                        if bits != 0 {
                            self.ep_unlock();
                            return (Message::empty(), bits, 0);
                        }
                    }

                    self.recv_timeout_slowpath(current, timeout_ns)
                }
            }
        }
    }

    /// Slowpath for recv_timeout: block receiver in dual queue.
    /// ep_lock MUST be held on entry; released before reschedule.
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

            self.ep_unlock();

            let now_ns = crate::arch::now_ns();
            let wakeup_ns = now_ns.saturating_add(timeout_ns);
            get_scheduler().block_current_futex_timed(wakeup_ns);

            let result = (*current).futex_wakeup_result;
            if result != 0 {
                (Message::empty(), 0, result)
            } else {
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
        // Lock ordering: CAP_LOCK (held by caller) → endpoint.lock — correct.
        // IRQs are already disabled from the CAP_LOCK acquisition path.
        self.ep_lock();

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

        self.ep_unlock();
    }
}
