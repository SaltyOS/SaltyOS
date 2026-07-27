// SPDX-License-Identifier: GPL-2.0-only
//! Lease-based timer wheel for managing poll and PTY read timeouts.
//!
//! In worker-pool mode, exactly one worker owns timer processing at a time.
//! Ownership is acquired via CAS on TIMER_OWNER when the heartbeat goes stale
//! (>50ms without update). The timer owner calls `process_expired_timers()`
//! after each IPC dispatch, which pops expired entries and fires their
//! callbacks without holding the heap lock.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use trona_runtime::thread::sync::Mutex;

use crate::personality::posix::{misc, poll};

// ---------------------------------------------------------------------------
// Timer kind
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum TimerKind {
    PollDeadline,
    PtyReadTimeout,
    MountRetry,
}

// ---------------------------------------------------------------------------
// Timer entry
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub(crate) struct TimerEntry {
    pub(crate) deadline_ns: u64,
    pub(crate) kind: TimerKind,
    pub(crate) cookie: u32,
}

// ---------------------------------------------------------------------------
// Min-heap
// ---------------------------------------------------------------------------

const MAX_TIMERS: usize = 128;

static HEAP_LOCK: Mutex = Mutex::new();
static mut HEAP: [TimerEntry; MAX_TIMERS] = [TimerEntry {
    deadline_ns: 0,
    kind: TimerKind::PollDeadline,
    cookie: 0,
}; MAX_TIMERS];
static mut HEAP_LEN: usize = 0;

unsafe fn heap_swap(a: usize, b: usize) {
    unsafe {
        let tmp = HEAP[a];
        HEAP[a] = HEAP[b];
        HEAP[b] = tmp;
    }
}

unsafe fn heap_sift_up(mut idx: usize) {
    unsafe {
        while idx > 0 {
            let parent = (idx - 1) / 2;
            if HEAP[idx].deadline_ns < HEAP[parent].deadline_ns {
                heap_swap(idx, parent);
                idx = parent;
            } else {
                break;
            }
        }
    }
}

unsafe fn heap_sift_down(mut idx: usize) {
    unsafe {
        loop {
            let left = 2 * idx + 1;
            let right = 2 * idx + 2;
            let mut smallest = idx;

            if left < HEAP_LEN && HEAP[left].deadline_ns < HEAP[smallest].deadline_ns {
                smallest = left;
            }
            if right < HEAP_LEN && HEAP[right].deadline_ns < HEAP[smallest].deadline_ns {
                smallest = right;
            }

            if smallest == idx {
                break;
            }
            heap_swap(idx, smallest);
            idx = smallest;
        }
    }
}

// ---------------------------------------------------------------------------
// Timer owner lease
// ---------------------------------------------------------------------------

/// Worker index that currently owns timer processing. 0 = main thread / uncontested.
static TIMER_OWNER: AtomicU32 = AtomicU32::new(0);

/// Monotonic timestamp (ns) of the owner's last heartbeat.
static TIMER_HEARTBEAT: AtomicU64 = AtomicU64::new(0);

/// Lease expiry: if heartbeat is older than 50ms, another worker may steal ownership.
const LEASE_EXPIRY_NS: u64 = 50_000_000;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Insert a timer into the heap. Safe to call from any worker.
pub(crate) fn register_timer(deadline_ns: u64, kind: TimerKind, cookie: u32) {
    HEAP_LOCK.lock();
    unsafe {
        if HEAP_LEN < MAX_TIMERS {
            HEAP[HEAP_LEN] = TimerEntry {
                deadline_ns,
                kind,
                cookie,
            };
            HEAP_LEN += 1;
            heap_sift_up(HEAP_LEN - 1);
        }
    }
    HEAP_LOCK.unlock();
}

/// Peek the earliest deadline without removing it. Returns None if empty.
pub(crate) fn next_deadline_ns() -> Option<u64> {
    HEAP_LOCK.lock();
    let result = unsafe {
        if HEAP_LEN > 0 {
            Some(HEAP[0].deadline_ns)
        } else {
            None
        }
    };
    HEAP_LOCK.unlock();
    result
}

/// Compute relative timeout (ns) from now until the earliest deadline.
/// Returns 0 if no timers are pending (meaning: block indefinitely).
pub(crate) fn relative_timeout_ns(now_ns: u64) -> u64 {
    match next_deadline_ns() {
        Some(deadline) => {
            if deadline <= now_ns {
                1 // expired — wake immediately
            } else {
                deadline.saturating_sub(now_ns)
            }
        }
        None => 0,
    }
}

/// Pop and dispatch all expired timers. Called by the owner loop after
/// each IPC dispatch cycle. Collects expired entries under the lock,
/// then fires callbacks without holding it.
pub(crate) unsafe fn process_expired_timers(state: &mut crate::owner::VfsState) {
    let now_ns = poll::monotonic_now_ns();

    // Collect expired entries under the lock
    let mut expired: [TimerEntry; 16] = [TimerEntry {
        deadline_ns: 0,
        kind: TimerKind::PollDeadline,
        cookie: 0,
    }; 16];
    let mut count = 0usize;

    HEAP_LOCK.lock();
    unsafe {
        while HEAP_LEN > 0 && HEAP[0].deadline_ns <= now_ns && count < 16 {
            expired[count] = HEAP[0];
            count += 1;

            HEAP_LEN -= 1;
            if HEAP_LEN > 0 {
                HEAP[0] = HEAP[HEAP_LEN];
                heap_sift_down(0);
            }
        }
    }
    HEAP_LOCK.unlock();

    // Fire callbacks outside the lock
    if count == 0 {
        return;
    }

    let mut did_mount = false;

    for i in 0..count {
        match expired[i].kind {
            TimerKind::PollDeadline => unsafe {
                poll::handle_poll_timer(state, expired[i].cookie, now_ns);
            },
            TimerKind::PtyReadTimeout => unsafe {
                crate::personality::posix::tty::handle_pty_timer(state, expired[i].cookie, now_ns);
            },
            TimerKind::MountRetry => did_mount = true,
        }
    }

    if did_mount {
        unsafe {
            crate::boot::late_mount::retry_pending_mounts(state);
        }
    }
}

/// Check if this worker is the current timer owner.
pub(crate) fn am_i_timer_owner(worker_idx: u32) -> bool {
    TIMER_OWNER.load(Ordering::Acquire) == worker_idx
}

/// Try to claim timer ownership via CAS. Succeeds if the current owner's
/// heartbeat is stale (>50ms old) or if no owner is set.
pub(crate) fn try_claim_timer(worker_idx: u32) -> bool {
    let now_ns = poll::monotonic_now_ns();
    let last_hb = TIMER_HEARTBEAT.load(Ordering::Acquire);

    if now_ns.saturating_sub(last_hb) < LEASE_EXPIRY_NS {
        return false;
    }

    let current_owner = TIMER_OWNER.load(Ordering::Acquire);
    if TIMER_OWNER
        .compare_exchange(
            current_owner,
            worker_idx,
            Ordering::AcqRel,
            Ordering::Relaxed,
        )
        .is_ok()
    {
        TIMER_HEARTBEAT.store(now_ns, Ordering::Release);
        true
    } else {
        false
    }
}

/// Refresh the heartbeat timestamp. Called by the timer owner on each
/// iteration to prevent lease expiry.
pub(crate) fn refresh_heartbeat() {
    let now_ns = poll::monotonic_now_ns();
    TIMER_HEARTBEAT.store(now_ns, Ordering::Release);
}
