// SPDX-License-Identifier: GPL-2.0-only
//! EventQueue / Watch / Timer invoke handlers.

use core::sync::atomic::Ordering;

use super::support::IPC_EVENT_RECORD_BASE_WORD;
use super::{
    CapRights, Capability, ObjectType, SyscallError, SyscallResult, copy_to_current_ipc_words,
    validate_capability,
};
use crate::event::event_queue::{EqWaitOutcome, EventQueue};
use crate::event::record::EventRecord;
use crate::event::timer::Timer;
use crate::event::watch::Watch;
use crate::ipc::data_pipe::DataPipe;
use crate::ipc::message_pipe::MessagePipe;

fn lookup_event_queue(cap_ptr: u64) -> Result<*mut EventQueue, SyscallError> {
    let cap =
        super::cspace::lookup_typed_capability(cap_ptr, ObjectType::EventQueue, CapRights::READ)?;
    Ok(cap.object as *mut EventQueue)
}

/// Publish an `EventRecord` to the well-known
/// `KERNITE_IPC_RESERVED_EVENT_RECORD_BASE` slot in the caller's IPC
/// buffer. `kind` and `status` share the first u64 word so the
/// payload's byte layout is identical to the userland-visible
/// `kernite_event_record` struct (kind: u32, status: u32, cookie: u64,
/// ...) — userland casts the slice directly without unpacking.
fn write_event_record_to_ipc(record: &EventRecord) -> Result<(), SyscallError> {
    unsafe {
        copy_to_current_ipc_words(
            IPC_EVENT_RECORD_BASE_WORD,
            &[
                (record.kind as u64) | ((record.status as u64) << 32),
                record.cookie,
                record.object_id,
                record.state_set,
                record.state_seen,
                record.payload0,
                record.payload1,
                record.payload2,
            ],
        )
    }
}

pub(super) fn syscall_eq_wait(cap: &Capability, deadline: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::EventQueue, CapRights::READ) {
        return SyscallResult::err(e);
    }
    let eq = cap.object as *mut EventQueue;
    match unsafe { (*eq).wait_block(deadline) } {
        EqWaitOutcome::Record(record) => match write_event_record_to_ipc(&record) {
            Ok(()) => SyscallResult::ok(0),
            Err(err) => SyscallResult::err(err),
        },
        EqWaitOutcome::TimedOut => SyscallResult::err(SyscallError::TimedOut),
        EqWaitOutcome::Closed => SyscallResult::err(SyscallError::Cancelled),
    }
}

pub(super) fn syscall_eq_poll(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::EventQueue, CapRights::READ) {
        return SyscallResult::err(e);
    }
    let eq = cap.object as *mut EventQueue;
    match unsafe { (*eq).dequeue() } {
        Some(record) => match write_event_record_to_ipc(&record) {
            Ok(()) => SyscallResult::ok(1),
            Err(err) => SyscallResult::err(err),
        },
        None => SyscallResult::ok(0),
    }
}

pub(super) fn syscall_eq_cancel(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::EventQueue, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let eq = cap.object as *mut EventQueue;
    unsafe {
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();
        if current.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        (*eq).cancel_waiter(current);
    }
    SyscallResult::ok(0)
}

pub(super) fn syscall_watch_register(
    cap: &Capability,
    watched_cap_ptr: u64,
    eq_cap_ptr: u64,
    mask: u64,
    cookie: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Watch, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let watched_cap = match resolve_watched_object(watched_cap_ptr) {
        Some(c) => c,
        None => return SyscallResult::err(SyscallError::InvalidOperation),
    };

    let eq = match lookup_event_queue(eq_cap_ptr) {
        Ok(eq) => eq,
        Err(e) => return SyscallResult::err(e),
    };

    unsafe {
        crate::cap::increment_refcount(eq as *mut crate::cap::KernelObject);

        let watch = cap.object as *mut Watch;

        // If the Watch was previously armed against another object,
        // detach it from that object's watcher list and release its
        // bound EventQueue ref before reconfiguring. Skipping this
        // step would leak the prior list link and the prior EQ
        // refcount, and a future publish on the prior object would
        // fire into a now-unrelated EQ.
        (*watch).disarm();
        let prev_obj = (*watch).watched_object;
        if !prev_obj.is_null() {
            let prev_obj_type = (*prev_obj).obj_type;
            let prev_list_ptr = crate::event::source::watcher_list_for_obj_type(
                prev_obj_type,
                prev_obj as *mut core::ffi::c_void,
            );
            if !prev_list_ptr.is_null() {
                let _ = (*prev_list_ptr).remove(watch);
            }
            (*watch).watched_object = core::ptr::null_mut();
        }
        let prev_eq = (*watch).event_queue;
        if !prev_eq.is_null() {
            (*watch).event_queue = core::ptr::null_mut();
            crate::cap::release_object(
                prev_eq as *mut crate::cap::KernelObject,
                ObjectType::EventQueue,
            );
        }

        // The watch ABI carries a single caller-supplied tag through
        // the invoke arg — `Watch.key` (used as `EventRecord.object_id`
        // on fire) and `Watch.cookie` (used as `EventRecord.cookie`)
        // both receive that same value. Splitting the two would
        // require a wire extension; today's invoke surface (4 args
        // already consumed by `watched / eq / mask / cookie`) leaves
        // no room.
        (*watch).configure(
            watched_cap.object as *mut crate::cap::KernelObject,
            mask,
            eq,
            cookie,
            cookie,
        );

        let watcher_list_ptr = crate::event::source::watcher_list_for_obj_type(
            watched_cap.obj_type,
            watched_cap.object as *mut core::ffi::c_void,
        );
        if watcher_list_ptr.is_null() {
            crate::cap::release_object(eq as *mut crate::cap::KernelObject, ObjectType::EventQueue);
            (*watch).event_queue = core::ptr::null_mut();
            (*watch).watched_object = core::ptr::null_mut();
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        (*watcher_list_ptr).insert(watch);
        (*watch).arm();

        // Lost-wakeup-free: re-check the state word after the watch
        // is visible in the list. If the bits were already set,
        // claim the one-shot fire under the list lock so a racing
        // `WatcherList::publish` cannot also fire the same match.
        // The CAS `armed: 1 → 0` is the arbitration: whoever flips
        // first owns the fire; the loser observes 0 and skips.
        if let Some(state) = state_flags_for(
            watched_cap.obj_type,
            watched_cap.object as *mut core::ffi::c_void,
        ) {
            let now = state.load(Ordering::Acquire);
            if (now & mask) != 0 {
                let irq2 = crate::mm::save_irq_disable();
                (*watcher_list_ptr).lock.lock();
                let we_won = (*watch)
                    .armed
                    .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
                if we_won {
                    let _ = (*watcher_list_ptr).remove_locked(watch);
                }
                (*watcher_list_ptr).lock.unlock();
                crate::mm::restore_irq(irq2);

                if we_won {
                    // EQ is already pinned by the register-time
                    // `increment_refcount(eq)` above; safe to
                    // enqueue outside the list lock.
                    let mut rec = EventRecord::empty();
                    rec.kind = uapi::KERNITE_EVENT_TYPE_STATE;
                    rec.status = uapi::KERNITE_EVENT_STATUS_OK;
                    rec.cookie = cookie;
                    rec.object_id = cookie;
                    rec.state_set = now & mask;
                    let _ = (*eq).enqueue(rec);
                }
            }
        }
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_watch_disarm(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Watch, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let watch = cap.object as *mut Watch;
    unsafe {
        (*watch).disarm();
        let watched = (*watch).watched_object;
        if !watched.is_null() {
            let watched_obj_type = (*watched).obj_type;
            let watcher_list_ptr = crate::event::source::watcher_list_for_obj_type(
                watched_obj_type,
                watched as *mut core::ffi::c_void,
            );
            if !watcher_list_ptr.is_null() {
                let _ = (*watcher_list_ptr).remove(watch);
            }
        }
        let eq = (*watch).event_queue;
        if !eq.is_null() {
            (*watch).event_queue = core::ptr::null_mut();
            crate::cap::release_object(eq as *mut crate::cap::KernelObject, ObjectType::EventQueue);
        }
    }
    SyscallResult::ok(0)
}

/// Cancel a watch.
///
/// Disarms the watch, detaches it from the source object's watcher
/// list, bumps the per-watch `cancel_epoch` so any in-flight
/// `WatcherList::publish` batch drops its fire at enqueue time, and
/// purges any records already queued under this watch's cookie from
/// the bound `EventQueue`. Records that were already drained by
/// `EQ_WAIT` cannot be recalled — userland dispatchers must validate
/// the cookie's `live_gen` field. The kernel side is queue hygiene +
/// teardown determinism, not the truth source for stale-event
/// safety.
pub(super) fn syscall_watch_cancel(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Watch, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let watch = cap.object as *mut Watch;
    unsafe {
        // Disarm first so any concurrent publish that has not yet
        // taken the watcher-list lock observes 0 and skips us.
        (*watch).disarm();

        // Detach from the source object's watcher list. A publish
        // batch that already snapshotted us before this point still
        // holds a refcount-pinned pointer; the cancel_epoch bump
        // below trips the fire-time check and drops the enqueue.
        let watched = (*watch).watched_object;
        if !watched.is_null() {
            let watched_obj_type = (*watched).obj_type;
            let watcher_list_ptr = crate::event::source::watcher_list_for_obj_type(
                watched_obj_type,
                watched as *mut core::ffi::c_void,
            );
            if !watcher_list_ptr.is_null() {
                let _ = (*watcher_list_ptr).remove(watch);
            }
        }

        (*watch).cancel_epoch_inc();

        let eq = (*watch).event_queue;
        if !eq.is_null() {
            let _ = (*eq).purge_matching((*watch).cookie);
            (*watch).event_queue = core::ptr::null_mut();
            crate::cap::release_object(eq as *mut crate::cap::KernelObject, ObjectType::EventQueue);
        }
    }
    SyscallResult::ok(0)
}

fn resolve_watched_object(cap_ptr: u64) -> Option<crate::cap::Capability> {
    for ty in [
        ObjectType::EventQueue,
        ObjectType::MessagePipe,
        ObjectType::DataPipe,
        ObjectType::Timer,
        ObjectType::IrqHandler,
    ] {
        if let Ok(cap) = super::cspace::lookup_typed_capability(cap_ptr, ty, CapRights::empty()) {
            return Some(cap);
        }
    }
    None
}

// Watcher-list dispatch lives in `crate::event::source` — the
// canonical owner of the watchable-source vocabulary. Call
// `crate::event::source::watcher_list_for_obj_type` from finalizer
// / disarm paths that hold an `ObjectType`, or
// `crate::event::source::watcher_list_for` when you already have a
// classified `WatchableSource`.

unsafe fn state_flags_for(
    obj_type: ObjectType,
    obj: *mut core::ffi::c_void,
) -> Option<&'static core::sync::atomic::AtomicU64> {
    unsafe {
        match obj_type {
            ObjectType::EventQueue => Some(&(*(obj as *const EventQueue)).state_flags),
            ObjectType::Timer => Some(&(*(obj as *const Timer)).state_flags),
            ObjectType::IrqHandler => {
                Some(&(*(obj as *const crate::event::irq::IrqHandler)).state_flags)
            }
            ObjectType::MessagePipe => {
                let side = obj as *const MessagePipe;
                let core_ptr = (*side).core;
                if core_ptr.is_null() {
                    None
                } else if (*side).which_side == crate::ipc::message_pipe::SIDE_A {
                    Some(&(*core_ptr).state_a)
                } else {
                    Some(&(*core_ptr).state_b)
                }
            }
            ObjectType::DataPipe => {
                let side = obj as *const DataPipe;
                let core_ptr = (*side).core;
                if core_ptr.is_null() {
                    None
                } else if (*side).which_side == crate::ipc::data_pipe::SIDE_A {
                    Some(&(*core_ptr).state_a)
                } else {
                    Some(&(*core_ptr).state_b)
                }
            }
            _ => None,
        }
    }
}

pub(super) fn syscall_timer_set(
    cap: &Capability,
    deadline_ns: u64,
    period_ns: u64,
    eq_cap_ptr: u64,
    cookie: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Timer, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let eq = match lookup_event_queue(eq_cap_ptr) {
        Ok(eq) => eq,
        Err(e) => return SyscallResult::err(e),
    };
    unsafe {
        crate::cap::increment_refcount(eq as *mut crate::cap::KernelObject);
        let timer = cap.object as *mut Timer;
        // `set` takes ownership of the freshly-bumped EQ ref and
        // releases the previously bound EQ ref atomically inside the
        // swap, so no leak when re-arming with the same EQ.
        (*timer).set(deadline_ns, period_ns, eq, 0, cookie);
    }
    SyscallResult::ok(0)
}

pub(super) fn syscall_timer_cancel(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Timer, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    unsafe {
        let timer = cap.object as *mut Timer;
        let was_armed = (*timer).cancel();
        SyscallResult::ok(if was_armed { 1 } else { 0 })
    }
}

pub(super) fn syscall_timer_query(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Timer, CapRights::READ) {
        return SyscallResult::err(e);
    }
    unsafe {
        let timer = cap.object as *const Timer;
        let now = crate::arch::now_ns();
        match (*timer).query(now) {
            Some(remaining) => SyscallResult::ok(remaining),
            None => SyscallResult::err(SyscallError::Cancelled),
        }
    }
}

/// Bind an `EventQueue` to an `IrqHandler` so that subsequent IRQ
/// fires enqueue an `EVENT_TYPE_IRQ` record carrying `cookie` /
/// `irq_num` into the queue.
///
/// The kernel takes a refcount on the EventQueue for the duration of
/// the binding; `IRQ_UNBIND_EQ` releases it. `IRQ_BIND_EQ` against an
/// already-bound handler returns `AlreadyExists` — userland must
/// unbind first.
pub(super) fn syscall_irq_bind_eq(cap: &Capability, eq_cap_ptr: u64, cookie: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IrqHandler, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }
    let eq = match lookup_event_queue(eq_cap_ptr) {
        Ok(e) => e,
        Err(e) => return SyscallResult::err(e),
    };
    let handler = cap.object as *mut crate::event::irq::IrqHandler;
    if handler.is_null() {
        return SyscallResult::err(SyscallError::InvalidCapability);
    }
    // The bind is serialized under IRQ_LOCK inside irq.rs so it
    // cannot race dispatch_irq / signal_fire; on success it takes the
    // EventQueue reference and stores the cookie before publishing
    // `bound_eq`. An already-bound handler returns `false` without touching
    // the live binding's cookie.
    if unsafe { crate::event::irq::irq_handler_bind_eq(handler, eq, cookie) } {
        SyscallResult::ok(0)
    } else {
        SyscallResult::err(SyscallError::AlreadyExists)
    }
}

/// Detach the bound `EventQueue` from an `IrqHandler`. Releases the
/// refcount taken by `IRQ_BIND_EQ`. No-op if nothing is bound.
pub(super) fn syscall_irq_unbind_eq(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IrqHandler, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }
    let handler = cap.object as *mut crate::event::irq::IrqHandler;
    if handler.is_null() {
        return SyscallResult::err(SyscallError::InvalidCapability);
    }
    // Unbind under IRQ_LOCK → EventQueue.lock, unlinking from the
    // queue's interrupt lane before releasing the bind reference.
    unsafe { crate::event::irq::irq_handler_unbind_eq(handler) };
    SyscallResult::ok(0)
}

/// Acknowledge an IRQ — clear `STATE_SIGNALED` so the next fire
/// publishes again. Level-triggered lines also need the controller-
/// level mask cleared, which is the dispatcher's responsibility once
/// every handler in the chain has been acked.
pub(super) fn syscall_irq_ack(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IrqHandler, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let handler = cap.object as *const crate::event::irq::IrqHandler;
    if handler.is_null() {
        return SyscallResult::err(SyscallError::InvalidCapability);
    }
    // Serialized under IRQ_LOCK (inside irq.rs) so the ack cannot clear
    // STATE_SIGNALED mid-`signal_fire`, before its watcher-edge publish.
    unsafe { crate::event::irq::irq_handler_ack(handler) };
    SyscallResult::ok(0)
}
