//! IPC Assembly Fastpath
//!
//! Optimized paths for Call (syscall 2) and ReplyRecv (syscall 3).
//! Called from assembly before the full ABI translation + dispatch.
//! Returns status in RAX (1 = handled, 0 = fall through to slowpath)
//! and value in RDX (badge for ReplyRecv, 0 for Call).
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::cap::{CapRights, ObjectType};
use crate::ipc::{EndpointState, Endpoint, Message};
use crate::sched::thread::{BlockedReason, ThreadState};

use super::{lookup_capability, validate_endpoint_cap, msg_info, write_msg_to_ipc_buffer};

/// Fastpath result returned in RAX:RDX.
///
/// status = 1: fastpath handled the syscall, value is the return value.
/// status = 0: fall through to slowpath.
#[repr(C)]
pub struct FastpathResult {
    pub status: u64,
    pub value: u64,
}

impl FastpathResult {
    #[inline(always)]
    const fn slowpath() -> Self {
        Self { status: 0, value: 0 }
    }

    #[inline(always)]
    const fn ok(value: u64) -> Self {
        Self { status: 1, value }
    }
}

/// Fastpath for Call syscall (syscall number 2).
///
/// Conditions for fastpath (bail to slowpath if ANY fails):
/// - extra_caps == 0
/// - length <= 4
/// - Valid Endpoint cap with CALL right
/// - Receiver is waiting (RecvBlocked)
/// - Same CPU (no cross-CPU IPI needed)
/// - Valid VSpace and kernel stack on receiver
///
/// # Register mapping at call site (from assembly):
/// rdi = cap_ptr, rsi = msg_info, rdx = mr0, rcx = mr1, r8 = mr2, r9 = mr3
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fastpath_call_rust(
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> FastpathResult {
    // Bail conditions: extra_caps != 0 or length > 4
    let extra_caps = msg_info::get_extra_caps(msg_info);
    if extra_caps != 0 {
        return FastpathResult::slowpath();
    }
    let length = msg_info::get_length(msg_info);
    if length > 4 {
        return FastpathResult::slowpath();
    }

    // Look up and validate endpoint capability
    let cap = match lookup_capability(cap_ptr) {
        Ok(c) => c,
        Err(_) => return FastpathResult::slowpath(),
    };
    if cap.obj_type != ObjectType::Endpoint {
        return FastpathResult::slowpath();
    }
    if validate_endpoint_cap(cap, CapRights::CALL).is_err() {
        return FastpathResult::slowpath();
    }

    unsafe {
        let endpoint = &mut *(cap.object as *mut Endpoint);

        // Must be RecvBlocked (receiver waiting)
        if endpoint.state() != EndpointState::RecvBlocked {
            return FastpathResult::slowpath();
        }

        // Pop receiver from recv queue
        let receiver = match endpoint.fastpath_pop_recv() {
            Some(r) => r,
            None => return FastpathResult::slowpath(),
        };

        // Same-CPU check: receiver must not have cross-CPU affinity
        let this_cpu = crate::arch::current_cpu() as u32;
        let recv_affinity = (*receiver).cpu_affinity;
        if recv_affinity != 0xFFFF_FFFF && recv_affinity != this_cpu {
            // Put receiver back; bail to slowpath
            endpoint.fastpath_push_recv(receiver);
            return FastpathResult::slowpath();
        }

        // Receiver must have valid VSpace and kernel stack
        if (*receiver).vspace_root.is_null() || (*receiver).kernel_stack_top == 0 {
            endpoint.fastpath_push_recv(receiver);
            return FastpathResult::slowpath();
        }

        let sched = crate::sched::scheduler::scheduler();
        let current = sched.current();
        if current.is_null() {
            endpoint.fastpath_push_recv(receiver);
            return FastpathResult::slowpath();
        }

        // Cache caller's receive-slot config (needed if server replies with caps)
        Endpoint::cache_receive_slot(current);

        // Build message directly (no allocation, inline registers only)
        let label = msg_info::get_label(msg_info);
        let mut msg = Message::empty();
        msg.label = label;
        msg.length = length;
        if length > 0 { msg.regs[0] = mr0; }
        if length > 1 { msg.regs[1] = mr1; }
        if length > 2 { msg.regs[2] = mr2; }
        if length > 3 { msg.regs[3] = mr3; }

        // Block caller BEFORE waking receiver (same as slowpath call())
        (*current).state = ThreadState::Blocked;
        (*current).blocked_reason = Some(BlockedReason::ReplyWait {
            msg,
            badge: cap.badge,
        });

        // Set reply capability so receiver can reply to us
        (*receiver).reply_tcb = current;
        (*receiver).reply_can_grant = true;

        // Transfer message to receiver's TCB (no cap transfer on fastpath)
        (*receiver).saved_caller_msg = msg;
        (*receiver).saved_caller_badge = cap.badge;

        // Wake receiver
        (*receiver).state = ThreadState::Ready;
        (*receiver).blocked_endpoint = core::ptr::null_mut();

        // Update endpoint state
        if endpoint.fastpath_recv_queue_empty() {
            endpoint.fastpath_set_state(EndpointState::Idle);
        }

        // Direct switch: set receiver as current, switch VSpace + kernel stack
        sched.set_current(receiver);
        (*receiver).state = ThreadState::Running;

        if !(*receiver).vspace_root.is_null() {
            let vspace = &*(*receiver).vspace_root;
            vspace.switch_to();
        }

        if (*receiver).kernel_stack_top != 0 {
            crate::arch::set_kernel_stack((*receiver).kernel_stack_top);
            crate::arch::set_tss_rsp0((*receiver).kernel_stack_top);
        }

        // Context switch: caller suspends here, resumes when reply wakes it
        let old_ctx = &mut (*current).context as *mut _;
        let new_ctx = &(*receiver).context as *const _;
        crate::arch::context_switch(old_ctx, new_ctx);

        // --- Caller has been woken by reply ---
        // At this point, current thread IS the original caller again.
        // The reply message was placed in saved_caller_msg by reply_recv.
        let reply_msg = (*current).saved_caller_msg;
        let reply_badge = (*current).saved_caller_badge;
        write_msg_to_ipc_buffer(&reply_msg, reply_badge);

        FastpathResult::ok(0)
    }
}

/// Fastpath for ReplyRecv syscall (syscall number 3).
///
/// Two phases:
/// 1. Reply: write reply to caller's saved_caller_msg, wake caller
/// 2. Recv: pop sender from send queue, read message
///
/// Server stays running (no context switch).
///
/// # Register mapping at call site (from assembly):
/// rdi = cap_ptr, rsi = msg_info, rdx = mr0, rcx = mr1, r8 = mr2, r9 = mr3
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fastpath_reply_recv_rust(
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> FastpathResult {
    // Bail conditions: extra_caps != 0 or length > 4
    let extra_caps = msg_info::get_extra_caps(msg_info);
    if extra_caps != 0 {
        return FastpathResult::slowpath();
    }
    let length = msg_info::get_length(msg_info);
    if length > 4 {
        return FastpathResult::slowpath();
    }

    // Look up and validate endpoint capability (need RECV right)
    let cap = match lookup_capability(cap_ptr) {
        Ok(c) => c,
        Err(_) => return FastpathResult::slowpath(),
    };
    if cap.obj_type != ObjectType::Endpoint {
        return FastpathResult::slowpath();
    }
    if validate_endpoint_cap(cap, CapRights::RECV).is_err() {
        return FastpathResult::slowpath();
    }

    unsafe {
        let endpoint = &mut *(cap.object as *mut Endpoint);
        let sched = crate::sched::scheduler::scheduler();
        let current = sched.current();
        if current.is_null() {
            return FastpathResult::slowpath();
        }

        // ---- REPLY PHASE ----
        let caller = (*current).reply_tcb;

        if !caller.is_null() {
            // Only fastpath if caller is in ReplyWait (not FaultBlocked)
            let is_reply_wait = matches!(
                (*caller).blocked_reason,
                Some(BlockedReason::ReplyWait { .. })
            );
            if !is_reply_wait {
                return FastpathResult::slowpath();
            }

            // Build reply message inline
            let reply_label = msg_info::get_label(msg_info);
            let mut reply_msg = Message::empty();
            reply_msg.label = reply_label;
            reply_msg.length = length;
            if length > 0 { reply_msg.regs[0] = mr0; }
            if length > 1 { reply_msg.regs[1] = mr1; }
            if length > 2 { reply_msg.regs[2] = mr2; }
            if length > 3 { reply_msg.regs[3] = mr3; }

            // Write reply to caller's TCB
            (*caller).saved_caller_msg = reply_msg;
            (*caller).saved_caller_badge = 0;

            // Wake caller
            (*caller).blocked_reason = None;
            (*caller).state = ThreadState::Ready;
            sched.enqueue(caller);

            // Clear one-shot reply capability
            (*current).reply_tcb = core::ptr::null_mut();
            (*current).reply_can_grant = false;
        }
        // If caller is null, no one to reply to — proceed to recv phase

        // ---- RECV PHASE ----
        // Must have a sender waiting (SendBlocked)
        if endpoint.state() != EndpointState::SendBlocked {
            return FastpathResult::slowpath();
        }

        let sender = match endpoint.fastpath_pop_send() {
            Some(s) => s,
            None => return FastpathResult::slowpath(),
        };

        // Extract message from sender's blocked reason
        let (msg, badge, keep_blocked) = match (*sender).blocked_reason {
            Some(BlockedReason::SendBlocked { msg, badge }) => (msg, badge, false),
            Some(BlockedReason::CallSendBlocked { msg, badge }) => (msg, badge, true),
            _ => {
                // Fault or unexpected — bail to slowpath
                endpoint.fastpath_push_send(sender);
                return FastpathResult::slowpath();
            }
        };

        // Fastpath only handles short messages with no cap transfer
        if msg.extra_caps != 0 || msg.length > 4 {
            endpoint.fastpath_push_send(sender);
            return FastpathResult::slowpath();
        }

        // Set reply capability in server's TCB
        (*current).reply_tcb = sender;
        (*current).reply_can_grant = true;

        // Write received message to server's TCB and IPC buffer
        (*current).saved_caller_msg = msg;
        (*current).saved_caller_badge = badge;
        write_msg_to_ipc_buffer(&msg, badge);

        if keep_blocked {
            // Call sender: keep blocked until reply, transition to ReplyWait
            (*sender).blocked_endpoint = core::ptr::null_mut();
            (*sender).blocked_reason = Some(BlockedReason::ReplyWait { msg, badge });
        } else {
            // Regular sender: wake immediately
            (*sender).state = ThreadState::Ready;
            (*sender).blocked_reason = None;
            (*sender).blocked_endpoint = core::ptr::null_mut();
            sched.enqueue(sender);
        }

        // Update endpoint state
        if endpoint.fastpath_send_queue_empty() {
            endpoint.fastpath_set_state(EndpointState::Idle);
        }

        // No context switch — server stays running
        FastpathResult::ok(badge)
    }
}
