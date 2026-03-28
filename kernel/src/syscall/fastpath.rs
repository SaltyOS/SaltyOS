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
use crate::mm::{save_irq_disable, restore_irq, CAP_LOCK};
use crate::sched::thread::{BlockedReason, Tcb, ThreadState};

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

#[inline(always)]
fn fastpath_waiter_is_local_stable(tcb: *mut Tcb, this_cpu: usize) -> bool {
    unsafe {
        if tcb.is_null() || (*tcb).run_owner().is_some() || (*tcb).ready_queued {
            return false;
        }
        if (*tcb).queued_cpu != 0xFFFF_FFFF {
            return false;
        }

        let affinity = (*tcb).cpu_affinity;
        if affinity != 0xFFFF_FFFF {
            return affinity == this_cpu as u32;
        }

        let last_cpu = (*tcb).last_cpu;
        last_cpu == 0xFFFF_FFFF || last_cpu == this_cpu as u32
    }
}

/// Fastpath for Call syscall (syscall number 2).
///
/// Conditions for fastpath (bail to slowpath if ANY fails):
/// - extra_caps == 0
/// - length <= 4
/// - Valid Endpoint cap with CALL right
/// - Receiver is waiting (RecvBlocked)
/// - Receiver has fully switched out on its previous CPU
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

    // lookup_capability() handles both flat (depth==0) and multi-level
    // (depth!=0) CSpaces — no need to bail on cspace_depth here.

    // Locked cap lookup: copy to stack under CAP_LOCK to prevent torn reads.
    // CAP_LOCK is released BEFORE per-object lock is acquired (no ordering change).
    let irq_cap = unsafe { save_irq_disable() };
    CAP_LOCK.lock();
    let cap_result = lookup_capability(cap_ptr).map(|c| *c);
    CAP_LOCK.unlock();
    unsafe { restore_irq(irq_cap) };

    let cap = match cap_result {
        Ok(c) => c,
        Err(_) => return FastpathResult::slowpath(),
    };
    if cap.obj_type != ObjectType::Endpoint {
        return FastpathResult::slowpath();
    }
    if validate_endpoint_cap(&cap, CapRights::CALL).is_err() {
        return FastpathResult::slowpath();
    }

    let endpoint_ptr = cap.object as *mut Endpoint;
    let badge = cap.badge;
    let this_cpu = crate::arch::current_cpu() as usize;

    unsafe {
        // Per-endpoint lock for IPC queue operations (Zircon-style).
        // No per-object lock needed — context switch uses no global lock.
        let irq = save_irq_disable();
        let endpoint = &mut *endpoint_ptr;
        endpoint.ep_lock();

        if endpoint.state() != EndpointState::RecvBlocked {
            endpoint.ep_unlock();
            restore_irq(irq);
            return FastpathResult::slowpath();
        }

        let receiver = match endpoint.fastpath_pop_recv() {
            Some(r) => r,
            None => {
                endpoint.ep_unlock();
                restore_irq(irq);
                return FastpathResult::slowpath();
            }
        };

        if !fastpath_waiter_is_local_stable(receiver, this_cpu) {
            endpoint.fastpath_push_recv(receiver);
            endpoint.ep_unlock();
            restore_irq(irq);
            return FastpathResult::slowpath();
        }

        if (*receiver).vspace_root.is_null() || (*receiver).kernel_stack_top == 0 {
            endpoint.fastpath_push_recv(receiver);
            endpoint.ep_unlock();
            restore_irq(irq);
            return FastpathResult::slowpath();
        }

        let sched = crate::sched::scheduler::scheduler();
        let current = sched.current();
        if current.is_null() {
            endpoint.fastpath_push_recv(receiver);
            endpoint.ep_unlock();
            restore_irq(irq);
            return FastpathResult::slowpath();
        }

        // Cross-CPU steal is safe once the waiter is unowned: the previous CPU
        // has already saved its context and dropped run ownership, so we can
        // install it as current here without racing another core's switch-out.

        Endpoint::cache_receive_slot(current);

        let label = msg_info::get_label(msg_info);
        let mut msg = Message::empty();
        msg.label = label;
        msg.length = length;
        if length > 0 { msg.regs[0] = mr0; }
        if length > 1 { msg.regs[1] = mr1; }
        if length > 2 { msg.regs[2] = mr2; }
        if length > 3 { msg.regs[3] = mr3; }

        (*current).state = ThreadState::Blocked;
        (*current).blocked_reason = Some(BlockedReason::ReplyWait { msg, badge });

        (*receiver).reply_tcb = current;
        (*receiver).reply_can_grant = true;

        if !(*receiver).pip_donating_to.is_null() {
            (*receiver).reply_tcb = core::ptr::null_mut();
            (*receiver).reply_can_grant = false;
            (*current).state = ThreadState::Running;
            (*current).blocked_reason = None;
            endpoint.fastpath_push_recv(receiver);
            if endpoint.state() == EndpointState::Idle {
                endpoint.fastpath_set_state(EndpointState::RecvBlocked);
            }
            endpoint.ep_unlock();
            restore_irq(irq);
            return FastpathResult::slowpath();
        }
        crate::sched::pip::pip_donate(current, receiver);

        (*receiver).saved_caller_msg = msg;
        (*receiver).saved_caller_badge = badge;

        if matches!((*receiver).blocked_reason, Some(BlockedReason::RecvTimedBlocked)) {
            crate::sched::sleep_queue::remove(receiver);
            (*receiver).timer_wakeup_ns = 0;
        }

        (*receiver).state = ThreadState::Ready;
        (*receiver).blocked_reason = None;
        (*receiver).blocked_endpoint = core::ptr::null_mut();

        if endpoint.fastpath_recv_queue_empty() {
            endpoint.fastpath_set_state(EndpointState::Idle);
        }

        sched.lock();
        sched.set_current(receiver);
        (*receiver).state = ThreadState::Running;
        (*receiver).last_cpu = this_cpu as u32;
        sched.unlock();

        // Release endpoint lock before context switch (no lock held during switch)
        endpoint.ep_unlock();

        sched.do_context_switch_fastpath(current, receiver);

        // --- Caller has been woken by reply ---
        let reply_msg = (*current).saved_caller_msg;
        let reply_badge = (*current).saved_caller_badge;
        write_msg_to_ipc_buffer(&reply_msg, reply_badge);

        restore_irq(irq);

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

    // lookup_capability() handles both flat (depth==0) and multi-level
    // (depth!=0) CSpaces — no need to bail on cspace_depth here.

    // Locked cap lookup: copy to stack under CAP_LOCK to prevent torn reads.
    let irq_cap = unsafe { save_irq_disable() };
    CAP_LOCK.lock();
    let cap_result = lookup_capability(cap_ptr).map(|c| *c);
    CAP_LOCK.unlock();
    unsafe { restore_irq(irq_cap) };

    let cap = match cap_result {
        Ok(c) => c,
        Err(_) => return FastpathResult::slowpath(),
    };
    if cap.obj_type != ObjectType::Endpoint {
        return FastpathResult::slowpath();
    }
    if validate_endpoint_cap(&cap, CapRights::RECV).is_err() {
        return FastpathResult::slowpath();
    }

    let endpoint_ptr = cap.object as *mut Endpoint;
    let _badge = cap.badge;
    let this_cpu = crate::arch::current_cpu() as usize;

    unsafe {
        // Per-endpoint lock only — NO global lock needed (Zircon-style).
        let irq = save_irq_disable();
        let endpoint = &mut *endpoint_ptr;
        endpoint.ep_lock();

        let sched = crate::sched::scheduler::scheduler();
        let current = sched.current();
        if current.is_null() {
            endpoint.ep_unlock();
            restore_irq(irq);
            return FastpathResult::slowpath();
        }

        // ---- REPLY PHASE ----
        let caller = (*current).reply_tcb;
        let mut wake_caller: *mut Tcb = core::ptr::null_mut();

        if !caller.is_null() {
            if !fastpath_waiter_is_local_stable(caller, this_cpu) {
                endpoint.ep_unlock();
                restore_irq(irq);
                return FastpathResult::slowpath();
            }
            let is_reply_wait = matches!(
                (*caller).blocked_reason,
                Some(BlockedReason::ReplyWait { .. })
            );
            if !is_reply_wait {
                endpoint.ep_unlock();
                restore_irq(irq);
                return FastpathResult::slowpath();
            }

            crate::sched::pip::pip_undonate(current, caller);

            let reply_label = msg_info::get_label(msg_info);
            let mut reply_msg = Message::empty();
            reply_msg.label = reply_label;
            reply_msg.length = length;
            if length > 0 { reply_msg.regs[0] = mr0; }
            if length > 1 { reply_msg.regs[1] = mr1; }
            if length > 2 { reply_msg.regs[2] = mr2; }
            if length > 3 { reply_msg.regs[3] = mr3; }

            (*caller).saved_caller_msg = reply_msg;
            (*caller).saved_caller_badge = 0;
            (*caller).blocked_reason = None;
            (*caller).state = ThreadState::Ready;
            wake_caller = caller;

            (*current).reply_tcb = core::ptr::null_mut();
            (*current).reply_can_grant = false;
        }

        // ---- RECV PHASE ----
        if endpoint.state() != EndpointState::SendBlocked {
            endpoint.ep_unlock();
            // Wake caller outside lock if needed
            if !wake_caller.is_null() {
                sched.lock();
                sched.enqueue_unlocked(wake_caller);
                sched.unlock();
            }
            restore_irq(irq);
            return FastpathResult::slowpath();
        }

        let sender = match endpoint.fastpath_pop_send() {
            Some(s) => s,
            None => {
                endpoint.ep_unlock();
                if !wake_caller.is_null() {
                    sched.lock();
                    sched.enqueue_unlocked(wake_caller);
                    sched.unlock();
                }
                restore_irq(irq);
                return FastpathResult::slowpath();
            }
        };

        if !fastpath_waiter_is_local_stable(sender, this_cpu) {
            endpoint.fastpath_push_send(sender);
            endpoint.ep_unlock();
            if !wake_caller.is_null() {
                sched.lock();
                sched.enqueue_unlocked(wake_caller);
                sched.unlock();
            }
            restore_irq(irq);
            return FastpathResult::slowpath();
        }

        let (msg, badge, keep_blocked) = match (*sender).blocked_reason {
            Some(BlockedReason::SendBlocked { msg, badge }) => (msg, badge, false),
            Some(BlockedReason::CallSendBlocked { msg, badge }) => (msg, badge, true),
            _ => {
                endpoint.fastpath_push_send(sender);
                endpoint.ep_unlock();
                if !wake_caller.is_null() {
                    sched.lock();
                    sched.enqueue_unlocked(wake_caller);
                    sched.unlock();
                }
                restore_irq(irq);
                return FastpathResult::slowpath();
            }
        };

        if msg.extra_caps != 0 || msg.length > 4 {
            endpoint.fastpath_push_send(sender);
            endpoint.ep_unlock();
            if !wake_caller.is_null() {
                sched.lock();
                sched.enqueue_unlocked(wake_caller);
                sched.unlock();
            }
            restore_irq(irq);
            return FastpathResult::slowpath();
        }

        (*current).saved_caller_msg = msg;
        (*current).saved_caller_badge = badge;
        write_msg_to_ipc_buffer(&msg, badge);

        if keep_blocked {
            (*current).reply_tcb = sender;
            (*current).reply_can_grant = true;
            crate::sched::pip::pip_donate(sender, current);
            (*sender).blocked_endpoint = core::ptr::null_mut();
            (*sender).blocked_reason = Some(BlockedReason::ReplyWait { msg, badge });
        } else {
            (*sender).state = ThreadState::Ready;
            (*sender).blocked_reason = None;
            (*sender).blocked_endpoint = core::ptr::null_mut();
        }

        if endpoint.fastpath_send_queue_empty() {
            endpoint.fastpath_set_state(EndpointState::Idle);
        }

        endpoint.ep_unlock();

        // Wake caller and/or sender outside lock
        if !wake_caller.is_null() {
            sched.lock();
            sched.enqueue_unlocked(wake_caller);
            sched.unlock();
        }
        if !keep_blocked {
            sched.lock();
            sched.enqueue_unlocked(sender);
            sched.unlock();
        }

        restore_irq(irq);

        // No context switch — server stays running
        FastpathResult::ok(badge)
    }
}
