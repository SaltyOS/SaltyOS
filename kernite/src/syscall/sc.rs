// SPDX-License-Identifier: GPL-2.0-only
//! Scheduling-context-related syscall handlers.

use super::cspace::{resolve_sched_context_request, resolve_tcb_request};
use super::{
    CapRights, Capability, DeferredReleaseList, ObjectType, SchedContext, SyscallError,
    SyscallResult, Tcb, ThreadState, restore_irq, save_irq_disable, validate_capability,
};

pub(super) fn syscall_sc_configure(
    cap: &Capability,
    budget_ns: u64,
    period_ns: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    if budget_ns == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    if period_ns != 0 && period_ns < budget_ns {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let irq = save_irq_disable();
        let sc = &mut *(cap.object as *mut SchedContext);
        let scheduler = crate::sched::scheduler::scheduler();
        let mut releases = DeferredReleaseList::new();
        sc.sc_lock();
        sc.budget = budget_ns;
        sc.period = period_ns;
        sc.remaining = budget_ns;

        if period_ns > 0 {
            let now = crate::arch::now_ns();
            sc.deadline = now.saturating_add(period_ns);
        } else {
            sc.deadline = u64::MAX;
        }

        if !sc.bound_tcb.is_null() {
            let tcb = &mut *sc.bound_tcb;
            tcb.tcb_lock();
            tcb.recompute_sched_key();
            if tcb.state() == ThreadState::Runnable {
                scheduler.requeue_thread_with_releases_locked(tcb as *mut Tcb, &mut releases);
            }
            tcb.tcb_unlock();
        }
        sc.sc_unlock();
        scheduler.drain_release(&mut releases);
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_sc_bind(cap: &Capability, tcb_cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let tcb_req = match resolve_tcb_request(tcb_cap_ptr, CapRights::WRITE) {
        Ok(request) => request,
        Err(e) => return SyscallResult::err(e),
    };

    unsafe {
        let irq = save_irq_disable();
        let sc = &mut *(cap.object as *mut SchedContext);
        let scheduler = crate::sched::scheduler::scheduler();
        let mut releases = DeferredReleaseList::new();
        sc.sc_lock();
        let tcb = &mut *tcb_req.tcb();
        tcb.tcb_lock();

        if !sc.bound_tcb.is_null() || !tcb.sched_context.is_null() {
            tcb.tcb_unlock();
            sc.sc_unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        sc.bound_tcb = tcb as *mut Tcb;
        tcb.sched_context = sc as *mut SchedContext;
        tcb.prepare_fair_sched_context_for_enqueue();
        tcb.recompute_sched_key();

        crate::cap::increment_refcount(sc as *mut SchedContext as *mut crate::cap::KernelObject);

        if tcb.state() == ThreadState::Runnable {
            scheduler.requeue_thread_with_releases_locked(tcb as *mut Tcb, &mut releases);
        }
        tcb.tcb_unlock();
        sc.sc_unlock();
        scheduler.drain_release(&mut releases);
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_sc_unbind(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let old_sc;
    unsafe {
        let irq = save_irq_disable();
        let sc = &mut *(cap.object as *mut SchedContext);
        sc.sc_lock();

        if sc.bound_tcb.is_null() {
            sc.sc_unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let tcb = &mut *sc.bound_tcb;
        tcb.tcb_lock();

        if tcb.state() == ThreadState::Runnable
            || tcb.state() == ThreadState::Runnable
            || !core::ptr::eq(tcb.sched_context, sc as *mut SchedContext)
        {
            tcb.tcb_unlock();
            sc.sc_unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        old_sc = tcb.sched_context;
        tcb.sched_context = core::ptr::null_mut();
        sc.bound_tcb = core::ptr::null_mut();
        tcb.tcb_unlock();
        sc.sc_unlock();
        restore_irq(irq);
    }

    if !old_sc.is_null() {
        unsafe {
            crate::cap::release_object(
                old_sc as *mut crate::cap::KernelObject,
                ObjectType::SchedContext,
            );
        }
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_sc_yield_to(cap: &Capability, target_sc_cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let target_req = match resolve_sched_context_request(target_sc_cap_ptr, CapRights::WRITE) {
        Ok(request) => request,
        Err(e) => return SyscallResult::err(e),
    };

    unsafe {
        let irq = save_irq_disable();
        let current_sc = &mut *(cap.object as *mut SchedContext);
        let target_sc = &mut *target_req.sched_context();

        let current_ptr = current_sc as *mut SchedContext as usize;
        let target_ptr = target_sc as *mut SchedContext as usize;
        if current_ptr < target_ptr {
            current_sc.sc_lock();
            target_sc.sc_lock();
        } else if current_ptr > target_ptr {
            target_sc.sc_lock();
            current_sc.sc_lock();
        } else {
            current_sc.sc_lock();
        }

        target_sc.remaining = target_sc.remaining.saturating_add(current_sc.remaining);
        current_sc.remaining = 0;

        if current_ptr != target_ptr {
            target_sc.sc_unlock();
        }

        let scheduler = crate::sched::scheduler::scheduler();
        current_sc.sc_unlock();
        scheduler.yield_current();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_sc_consumed(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let irq = save_irq_disable();
        let sc = &*(cap.object as *const SchedContext);
        sc.sc_lock();
        let result = SyscallResult::ok(sc.consumed);
        sc.sc_unlock();
        restore_irq(irq);
        result
    }
}
