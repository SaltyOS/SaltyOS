//! Waitpid handler + observer-owned lifecycle event queue primitives.
//!
//! Each observer process owns a packed FIFO of lifecycle event records in
//! `observer_events[0..observer_event_count)`. Those records are the
//! authoritative completion/recovery plane for child observation; parked
//! `waitpid` callers are only a fast-path wakeup optimization over that durable
//! state.
//!
//! Terminal `EXITED` records drive `Zombie -> Reaped` transition when
//! consumed. Non-terminal `STOPPED` / `CONTINUED` and recovery-only
//! `FORK_COMMITTED` records simply clear the matching slot-local event state
//! when they are consumed or discarded.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::*;

use crate::base::proc_table::{
    COMPLETION_EVENT_CONTINUED, COMPLETION_EVENT_EXITED, COMPLETION_EVENT_FORK_COMMITTED,
    COMPLETION_EVENT_NONE, COMPLETION_EVENT_STOPPED, OBSERVER_EVENT_RECORDS, ObserverEventRecord,
    ProcessState, find_by_badge, find_by_pid, monotonic_now_ns, proctab, proctab_cap,
};

const WAIT_WAKE_RETRY_INTERVAL_NS: u64 = 1_000_000;

#[inline]
fn completion_wait_deadline_ns(msg: &TronaMsg) -> u64 {
    if msg.length >= 3 { msg.regs[2] } else { 0 }
}

#[inline]
fn record_matches_wait(record: &ObserverEventRecord, target_pid: u32, options: u32) -> bool {
    if record.kind == COMPLETION_EVENT_NONE {
        return false;
    }
    if target_pid != u32::MAX && record.pid != target_pid {
        return false;
    }
    match record.kind {
        COMPLETION_EVENT_EXITED => true,
        COMPLETION_EVENT_STOPPED => (options & crate::personality::posix::WUNTRACED) != 0,
        COMPLETION_EVENT_CONTINUED => (options & crate::personality::posix::WCONTINUED) != 0,
        _ => false,
    }
}

#[inline]
fn record_is_nonterminal(record: &ObserverEventRecord) -> bool {
    matches!(
        record.kind,
        COMPLETION_EVENT_STOPPED | COMPLETION_EVENT_CONTINUED
    )
}

#[inline]
fn record_is_evictable_for(incoming_kind: u8, record: &ObserverEventRecord) -> bool {
    match incoming_kind {
        COMPLETION_EVENT_EXITED => {
            record_is_nonterminal(record) || record.kind == COMPLETION_EVENT_FORK_COMMITTED
        }
        COMPLETION_EVENT_FORK_COMMITTED => record_is_nonterminal(record),
        _ => false,
    }
}

unsafe fn find_matching_completion_record(
    parent_idx: usize,
    target_pid: u32,
    options: u32,
) -> Option<usize> {
    unsafe {
        let count = proctab(parent_idx).observer_event_count as usize;
        for record_idx in 0..count {
            let record = proctab(parent_idx).observer_events[record_idx];
            if record_matches_wait(&record, target_pid, options) {
                return Some(record_idx);
            }
        }
        None
    }
}

unsafe fn matching_completion_for_wait(parent_idx: usize) -> Option<usize> {
    unsafe {
        find_matching_completion_record(
            parent_idx,
            proctab(parent_idx).completion_wait_target_pid,
            proctab(parent_idx).completion_wait_options,
        )
    }
}

unsafe fn remove_observer_event(parent_idx: usize, record_idx: usize) -> ObserverEventRecord {
    unsafe {
        let count = proctab(parent_idx).observer_event_count as usize;
        let removed = proctab(parent_idx).observer_events[record_idx];
        for i in record_idx..count.saturating_sub(1) {
            let next = proctab(parent_idx).observer_events[i + 1];
            proctab(parent_idx).observer_events[i] = next;
        }
        if count != 0 {
            proctab(parent_idx).observer_events[count - 1] = ObserverEventRecord::zeroed();
            proctab(parent_idx).observer_event_count -= 1;
        }
        removed
    }
}

unsafe fn find_evictable_observer_event(parent_idx: usize, incoming_kind: u8) -> Option<usize> {
    unsafe {
        let count = proctab(parent_idx).observer_event_count as usize;
        for record_idx in 0..count {
            let record = proctab(parent_idx).observer_events[record_idx];
            if record_is_evictable_for(incoming_kind, &record) {
                return Some(record_idx);
            }
        }
        None
    }
}

pub(crate) unsafe fn observer_has_pending_event(
    parent_idx: usize,
    child_pid: u32,
    event_kind: u8,
) -> bool {
    unsafe {
        let count = proctab(parent_idx).observer_event_count as usize;
        for record_idx in 0..count {
            let record = proctab(parent_idx).observer_events[record_idx];
            if record.pid == child_pid && record.kind == event_kind {
                return true;
            }
        }
        false
    }
}

pub(crate) unsafe fn dismiss_observer_event_record(record: ObserverEventRecord) {
    unsafe {
        let Some(child_idx) = find_by_pid(record.pid) else {
            return;
        };

        match record.kind {
            COMPLETION_EVENT_EXITED => {
                if proctab(child_idx).state == ProcessState::Zombie {
                    proctab(child_idx).exit.completion_consumed = true;
                    proctab(child_idx).state = ProcessState::Reaped;
                    crate::lifecycle::exit::finalize_after_completion_consume(child_idx);
                }
            }
            COMPLETION_EVENT_STOPPED => {
                if proctab(child_idx).completion_event_kind == COMPLETION_EVENT_STOPPED
                    && proctab(child_idx).completion_event_status == record.status
                {
                    proctab(child_idx).completion_event_kind = COMPLETION_EVENT_NONE;
                    proctab(child_idx).completion_event_status = 0;
                    proctab(child_idx).stop_status = 0;
                }
            }
            COMPLETION_EVENT_CONTINUED => {
                if proctab(child_idx).completion_event_kind == COMPLETION_EVENT_CONTINUED {
                    proctab(child_idx).completion_event_kind = COMPLETION_EVENT_NONE;
                    proctab(child_idx).completion_event_status = 0;
                    proctab(child_idx).stop_status = 0;
                }
            }
            COMPLETION_EVENT_FORK_COMMITTED => {
                if proctab(child_idx).completion_event_kind == COMPLETION_EVENT_FORK_COMMITTED
                    && proctab(child_idx).completion_event_cookie == record.cookie
                {
                    proctab(child_idx).completion_event_kind = COMPLETION_EVENT_NONE;
                    proctab(child_idx).completion_event_status = 0;
                    proctab(child_idx).completion_event_cookie = 0;
                }
            }
            _ => {}
        }
    }
}

unsafe fn consume_observer_event(parent_idx: usize, record_idx: usize) -> ObserverEventRecord {
    unsafe {
        let record = remove_observer_event(parent_idx, record_idx);
        dismiss_observer_event_record(record);
        record
    }
}

pub(crate) unsafe fn append_observer_event(parent_idx: usize, record: ObserverEventRecord) -> bool {
    unsafe {
        if record.kind == COMPLETION_EVENT_NONE || record.pid == 0 {
            return false;
        }

        if matches!(
            record.kind,
            COMPLETION_EVENT_STOPPED | COMPLETION_EVENT_CONTINUED
        ) {
            let count = proctab(parent_idx).observer_event_count as usize;
            for record_idx in 0..count {
                let existing = proctab(parent_idx).observer_events[record_idx];
                if existing.pid == record.pid && record_is_nonterminal(&existing) {
                    proctab(parent_idx).observer_events[record_idx] = record;
                    return true;
                }
            }
        }

        while (proctab(parent_idx).observer_event_count as usize) >= OBSERVER_EVENT_RECORDS {
            let Some(evict_idx) = find_evictable_observer_event(parent_idx, record.kind) else {
                return false;
            };
            let evicted = remove_observer_event(parent_idx, evict_idx);
            dismiss_observer_event_record(evicted);
        }

        let count = proctab(parent_idx).observer_event_count as usize;
        proctab(parent_idx).observer_events[count] = record;
        proctab(parent_idx).observer_event_count += 1;
        true
    }
}

pub(crate) unsafe fn consume_fork_committed_event(parent_idx: usize, cookie: u64) -> Option<u32> {
    unsafe {
        if cookie == 0 {
            return None;
        }
        let count = proctab(parent_idx).observer_event_count as usize;
        for record_idx in 0..count {
            let record = proctab(parent_idx).observer_events[record_idx];
            if record.kind == COMPLETION_EVENT_FORK_COMMITTED && record.cookie == cookie {
                let pid = record.pid;
                let _ = consume_observer_event(parent_idx, record_idx);
                return Some(pid);
            }
        }
        None
    }
}

/// Zero the parent-owned waiter triple without touching the shared reply
/// endpoint. Deferred waits store the MessagePipe endpoint to reply on,
/// not a per-call cap that needs teardown.
#[inline]
unsafe fn zero_parent_waiter(idx: usize) {
    unsafe {
        let p = proctab(idx);
        p.completion_wait_reply = 0;
        p.completion_wait_target_pid = 0;
        p.completion_wait_options = 0;
        p.completion_wait_deadline_ns = 0;
        p.completion_wait_wake_retry_deadline_ns = 0;
    }
}

/// Drop disposition: clear a parked wait without sending a reply. The
/// stored value is the shared server MessagePipe endpoint, so there is no
/// per-call cap to delete.
pub(crate) unsafe fn clear_parent_waiter(idx: usize) {
    unsafe {
        if proctab(idx).completion_wait_reply == 0 {
            return;
        }
        zero_parent_waiter(idx);
    }
}

/// Cancel disposition: deliver `TRONA_TIMED_OUT` via reply-marked MP_WRITE.
unsafe fn complete_parent_wait_timeout(idx: usize) {
    unsafe {
        let reply_slot = proctab(idx).completion_wait_reply;
        if reply_slot == 0 {
            return;
        }
        let mut reply = TronaMsg::zeroed();
        reply.label = trona_protocol::posix::TRONA_TIMED_OUT;
        let _ =
            trona_kernel::ipc::mp_write_reply_ctx(crate::ipc_ctx(), reply_slot, &raw const reply);
        zero_parent_waiter(idx);
    }
}

#[inline]
pub(crate) unsafe fn schedule_parent_wait_wake_retry(idx: usize) {
    unsafe {
        let p = proctab(idx);
        if p.completion_wait_reply == 0 {
            p.completion_wait_wake_retry_deadline_ns = 0;
            return;
        }
        p.completion_wait_wake_retry_deadline_ns =
            monotonic_now_ns().saturating_add(WAIT_WAKE_RETRY_INTERVAL_NS);
    }
}

#[inline]
pub(crate) unsafe fn parked_wait_matches_child(parent_idx: usize, _child_idx: usize) -> bool {
    unsafe {
        if proctab(parent_idx).completion_wait_reply == 0 {
            return false;
        }
        matching_completion_for_wait(parent_idx).is_some()
    }
}

/// Best-effort wake for a parked waitpid caller.
pub(crate) unsafe fn try_wake_parent_waiter(parent_idx: usize) -> bool {
    unsafe {
        let reply_slot = proctab(parent_idx).completion_wait_reply;
        if reply_slot == 0 {
            return false;
        }

        let Some(record_idx) = matching_completion_for_wait(parent_idx) else {
            return false;
        };

        let record = proctab(parent_idx).observer_events[record_idx];
        let mut reply = TronaMsg::zeroed();
        reply.label = crate::TRONA_OK;
        reply.length = 2;
        reply.regs[0] = record.status as u64;
        reply.regs[1] = record.pid as u64;
        let err =
            trona_kernel::ipc::mp_write_reply_ctx(crate::ipc_ctx(), reply_slot, &raw const reply);
        if err != 0 {
            return false;
        }

        zero_parent_waiter(parent_idx);
        let _ = consume_observer_event(parent_idx, record_idx);
        true
    }
}

// ===========================================================================
// Deadline pump
// ===========================================================================

pub(crate) fn has_pending_wait_deadlines() -> bool {
    unsafe {
        for i in 0..proctab_cap() {
            let p = proctab(i);
            if p.completion_wait_reply != 0
                && (p.completion_wait_deadline_ns != 0
                    || p.completion_wait_wake_retry_deadline_ns != 0)
            {
                return true;
            }
        }
    }
    false
}

pub(crate) fn nearest_completion_wait_deadline_ns() -> u64 {
    let mut deadline = u64::MAX;
    unsafe {
        for i in 0..proctab_cap() {
            let p = proctab(i);
            if p.completion_wait_reply == 0 {
                continue;
            }
            if p.completion_wait_deadline_ns != 0 && p.completion_wait_deadline_ns < deadline {
                deadline = p.completion_wait_deadline_ns;
            }
            if p.completion_wait_wake_retry_deadline_ns != 0
                && p.completion_wait_wake_retry_deadline_ns < deadline
            {
                deadline = p.completion_wait_wake_retry_deadline_ns;
            }
        }
    }
    deadline
}

pub(crate) unsafe fn process_completion_wait_deadlines() {
    unsafe {
        let now_ns = monotonic_now_ns();
        for i in 0..proctab_cap() {
            let p = proctab(i);
            if p.completion_wait_reply == 0 {
                continue;
            }

            if p.completion_wait_wake_retry_deadline_ns != 0
                && now_ns >= p.completion_wait_wake_retry_deadline_ns
            {
                proctab(i).completion_wait_wake_retry_deadline_ns = 0;
                if !try_wake_parent_waiter(i) && proctab(i).completion_wait_reply != 0 {
                    // Preserve the parked waiter until we either
                    // deliver a completion or the caller's deadline
                    // expires. Clearing the saved reply endpoint here can
                    // strand the blocked `INIT_WAIT` caller forever.
                    schedule_parent_wait_wake_retry(i);
                }
                continue;
            }

            if p.completion_wait_deadline_ns != 0 && now_ns >= p.completion_wait_deadline_ns {
                complete_parent_wait_timeout(i);
            }
        }
    }
}

// ===========================================================================
// handle_wait
// ===========================================================================

pub(crate) unsafe fn handle_wait(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) -> bool {
    unsafe {
        let child_pid = msg.regs[0] as u32;
        let options = msg.regs[1] as u32;
        let deadline_ns = completion_wait_deadline_ns(msg);

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return false;
        };
        let caller_pid = proctab(caller_idx).pid;

        if proctab(caller_idx).completion_wait_reply != 0 {
            clear_parent_waiter(caller_idx);
        }

        if let Some(record_idx) = find_matching_completion_record(caller_idx, child_pid, options) {
            let record = proctab(caller_idx).observer_events[record_idx];
            reply.label = crate::TRONA_OK;
            reply.length = 2;
            reply.regs[0] = record.status as u64;
            reply.regs[1] = record.pid as u64;
            let _ = consume_observer_event(caller_idx, record_idx);
            return false;
        }

        if child_pid == u32::MAX {
            let mut has_living = false;
            for i in 0..proctab_cap() {
                let p = proctab(i);
                if p.state != ProcessState::Free && p.completion_observer_pid == caller_pid {
                    if p.state == ProcessState::Running || p.state == ProcessState::Stopped {
                        has_living = true;
                    }
                }
            }

            if !has_living {
                reply.label = crate::TRONA_NOT_FOUND;
                return false;
            }
        } else {
            let Some(ci) = find_by_pid(child_pid) else {
                reply.label = crate::TRONA_NOT_FOUND;
                return false;
            };
            if proctab(ci).completion_observer_pid != caller_pid {
                reply.label = crate::TRONA_NOT_FOUND;
                return false;
            }
            if proctab(ci).state == ProcessState::Reaped {
                reply.label = crate::TRONA_NOT_FOUND;
                return false;
            }
        }

        if (options & crate::personality::posix::WNOHANG) != 0 {
            reply.label = crate::TRONA_OK;
            reply.length = 2;
            reply.regs[0] = 0;
            reply.regs[1] = 0;
            return false;
        }

        if deadline_ns != 0 && monotonic_now_ns() >= deadline_ns {
            reply.label = trona_protocol::posix::TRONA_TIMED_OUT;
            return false;
        }

        let reply_slot = trona_runtime::client::caps::service_recv_ep();
        if reply_slot == 0 {
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return false;
        }

        proctab(caller_idx).completion_wait_reply = reply_slot;
        proctab(caller_idx).completion_wait_target_pid = child_pid;
        proctab(caller_idx).completion_wait_options = options;
        proctab(caller_idx).completion_wait_deadline_ns = deadline_ns;
        proctab(caller_idx).completion_wait_wake_retry_deadline_ns = 0;
        true
    }
}
