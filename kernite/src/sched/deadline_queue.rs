// SPDX-License-Identifier: GPL-2.0-only
//! Unified ns-precision deadline queue.
//!
//! Single sorted intrusive treap keyed on `deadline_ns`, holding every
//! deadline-driven event in the kernel:
//!
//! * `FutexTimed` — `VSPACE_FUTEX_WAIT` with timeout (owner = `Tcb`).
//! * `IpcTimeout` — blocking `MP_*` / `DP_*` ops with `timeout_ns > 0`
//!   (owner = `Tcb`).
//! * `TimerFire` — `Timer` kernel-object expiry (owner = `Timer`).
//!
//! `Tcb` carries a single embedded `DeadlineNode` because
//! `blocked_reason` is itself a single-state field — at most one
//! deadline-driven block can be active at a time. `Timer` carries its
//! own embedded node.
//!
//! The fast path of `peek_expired` is lockless: a global
//! `NEXT_DEADLINE_NS: AtomicU64` mirrors the tree's min key, so the
//! per-CPU tick handler reads one atomic to decide whether to walk
//! `check_wakeups` at all. The mirror is kept consistent under the
//! tree lock.
//!
//! UAF / cancel-race protection:
//! * Each `DeadlineNode` carries a `state: AtomicU8` (`Idle` /
//!   `Queued` / `Dispatching`) so insert / cancel / dispatch can
//!   detect each other and bail.
//! * On insert the owner takes a membership pin: thread owners bump
//!   `sched_ref`, timer owners bump the timer's `KernelObject.ref_count`.
//!   The pin is dropped only after dispatch completes (or cancel
//!   removes the node).
//! * On dispatch the node's `seq` is compared against the owner's
//!   live state-seq snapshot — a re-arm with a fresh seq invalidates
//!   the popped node before any callback runs.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::cap::ObjectType;
use crate::cap::object::KernelObject;
use crate::mm::{SpinLock, restore_irq, save_irq_disable};
use crate::sched::thread::Tcb;

/// Sentinel meaning "no node armed". Larger than any real monotonic
/// deadline so `peek_expired(now)` never spuriously fires.
pub const DEADLINE_INACTIVE: u64 = u64::MAX;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeadlineKind {
    FutexTimed = 0,
    IpcTimeout = 1,
    TimerFire = 2,
}

impl DeadlineKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::FutexTimed),
            1 => Some(Self::IpcTimeout),
            2 => Some(Self::TimerFire),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeadlineNodeState {
    Idle = 0,
    Queued = 1,
    Dispatching = 2,
}

/// Intrusive deadline-queue node embedded in `Tcb` and `Timer`.
///
/// All fields outside of `state` are mutated under `DEADLINE_LOCK`.
/// `state` uses `AtomicU8` CAS so producers / consumers can detect
/// concurrent transitions without holding the lock.
#[repr(C)]
pub struct DeadlineNode {
    pub key_ns: u64,
    pub left: *mut DeadlineNode,
    pub right: *mut DeadlineNode,
    pub parent: *mut DeadlineNode,
    /// Cached min(key, left.subtree_min, right.subtree_min) so the
    /// global `NEXT_DEADLINE_NS` hint can be refreshed from the root
    /// in O(1) after a structural mutation.
    pub subtree_min: u64,
    /// Lifecycle gate. Set to `Queued` while the node is reachable
    /// from `DEADLINE_ROOT`; transitions to `Dispatching` while the
    /// dispatch loop holds a popped reference; back to `Idle` once
    /// the callback completes (or the cancel path detaches it).
    pub state: AtomicU8,
    /// `DeadlineKind` (encoded as `u8` so the node can be `repr(C)`
    /// without enum padding surprises across FFI).
    pub kind: u8,
    /// Owner state-seq snapshot (`Tcb::wait_seq` for thread owners,
    /// `Timer::set` increments for timer owners). Compared against
    /// the live owner snapshot at dispatch to reject stale wakeups.
    pub seq: u64,
    /// Strong owner pointer — `*mut Tcb` for thread kinds, `*mut
    /// Timer` for `TimerFire`. Membership pin makes this raw pointer
    /// safe to dereference until the dispatch / cancel completes.
    pub owner_obj: *mut KernelObject,
}

impl DeadlineNode {
    pub const fn new() -> Self {
        Self {
            key_ns: DEADLINE_INACTIVE,
            left: core::ptr::null_mut(),
            right: core::ptr::null_mut(),
            parent: core::ptr::null_mut(),
            subtree_min: DEADLINE_INACTIVE,
            state: AtomicU8::new(DeadlineNodeState::Idle as u8),
            kind: DeadlineKind::FutexTimed as u8,
            seq: 0,
            owner_obj: core::ptr::null_mut(),
        }
    }
}

/// Global lock protecting tree topology (root, parent / child links,
/// subtree_min cache).
static DEADLINE_LOCK: SpinLock = SpinLock::new();

/// Tree root. `null` = empty queue.
///
/// SAFETY invariant: every read / write goes through `DEADLINE_LOCK`.
static mut DEADLINE_ROOT: *mut DeadlineNode = core::ptr::null_mut();

/// Lockless mirror of `DEADLINE_ROOT.subtree_min`. The per-CPU tick
/// path reads this with `Acquire` to decide whether `check_wakeups`
/// needs to acquire the queue lock. Refreshed under the lock after
/// every insert / remove / rotation.
pub static NEXT_DEADLINE_NS: AtomicU64 = AtomicU64::new(DEADLINE_INACTIVE);

#[inline]
fn refresh_next_deadline_locked() {
    let next = unsafe {
        let root = DEADLINE_ROOT;
        if root.is_null() {
            DEADLINE_INACTIVE
        } else {
            (*root).subtree_min
        }
    };
    NEXT_DEADLINE_NS.store(next, Ordering::Release);
}

/// `true` if any armed deadline has been crossed by `now_ns`.
/// Lockless — reads the cached min only.
#[inline]
pub fn peek_expired(now_ns: u64) -> bool {
    NEXT_DEADLINE_NS.load(Ordering::Acquire) <= now_ns
}

#[inline]
fn treap_priority(node: *mut DeadlineNode) -> u64 {
    // Same hash function as `rq.rs::fair_tree_heap_key` — lifts a raw
    // pointer to a balanced random priority for treap heap ordering.
    let mut x = node as usize as u64;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^ (x >> 33)
}

#[inline]
fn treap_precedes(a: *mut DeadlineNode, b: *mut DeadlineNode) -> bool {
    let ka = treap_priority(a);
    let kb = treap_priority(b);
    if ka != kb {
        ka < kb
    } else {
        (a as usize) < (b as usize)
    }
}

#[inline]
unsafe fn recalc_node(n: *mut DeadlineNode) {
    if n.is_null() {
        return;
    }
    unsafe {
        let mut min = (*n).key_ns;
        let l = (*n).left;
        if !l.is_null() {
            min = min.min((*l).subtree_min);
        }
        let r = (*n).right;
        if !r.is_null() {
            min = min.min((*r).subtree_min);
        }
        (*n).subtree_min = min;
    }
}

#[inline]
unsafe fn recalc_upwards(mut n: *mut DeadlineNode) {
    unsafe {
        while !n.is_null() {
            recalc_node(n);
            n = (*n).parent;
        }
    }
}

unsafe fn rotate_left(pivot: *mut DeadlineNode) {
    unsafe {
        let new_root = (*pivot).right;
        let moved = (*new_root).left;
        let parent = (*pivot).parent;

        (*pivot).right = moved;
        if !moved.is_null() {
            (*moved).parent = pivot;
        }

        (*new_root).parent = parent;
        if parent.is_null() {
            DEADLINE_ROOT = new_root;
        } else if (*parent).left == pivot {
            (*parent).left = new_root;
        } else {
            (*parent).right = new_root;
        }

        (*new_root).left = pivot;
        (*pivot).parent = new_root;

        recalc_node(pivot);
        recalc_node(new_root);
    }
}

unsafe fn rotate_right(pivot: *mut DeadlineNode) {
    unsafe {
        let new_root = (*pivot).left;
        let moved = (*new_root).right;
        let parent = (*pivot).parent;

        (*pivot).left = moved;
        if !moved.is_null() {
            (*moved).parent = pivot;
        }

        (*new_root).parent = parent;
        if parent.is_null() {
            DEADLINE_ROOT = new_root;
        } else if (*parent).left == pivot {
            (*parent).left = new_root;
        } else {
            (*parent).right = new_root;
        }

        (*new_root).right = pivot;
        (*pivot).parent = new_root;

        recalc_node(pivot);
        recalc_node(new_root);
    }
}

/// BST insert by `key_ns` (ties broken by pointer identity), then
/// rotate up while the heap property (treap priority) is violated.
unsafe fn treap_insert_locked(node: *mut DeadlineNode) {
    unsafe {
        (*node).left = core::ptr::null_mut();
        (*node).right = core::ptr::null_mut();
        (*node).parent = core::ptr::null_mut();
        (*node).subtree_min = (*node).key_ns;

        if DEADLINE_ROOT.is_null() {
            DEADLINE_ROOT = node;
            return;
        }

        // BST insert.
        let mut cur = DEADLINE_ROOT;
        let mut parent: *mut DeadlineNode;
        loop {
            parent = cur;
            let go_left = (*node).key_ns < (*cur).key_ns
                || ((*node).key_ns == (*cur).key_ns && (node as usize) < (cur as usize));
            if go_left {
                if (*cur).left.is_null() {
                    (*cur).left = node;
                    (*node).parent = cur;
                    break;
                } else {
                    cur = (*cur).left;
                }
            } else {
                if (*cur).right.is_null() {
                    (*cur).right = node;
                    (*node).parent = cur;
                    break;
                } else {
                    cur = (*cur).right;
                }
            }
        }
        let _ = parent;

        recalc_upwards(node);

        // Treap fix-up — rotate while parent has lower priority.
        loop {
            let p = (*node).parent;
            if p.is_null() {
                break;
            }
            if !treap_precedes(node, p) {
                break;
            }
            if (*p).left == node {
                rotate_right(p);
            } else {
                rotate_left(p);
            }
        }
    }
}

/// Rotate `node` down to a leaf using the heap property, then detach.
unsafe fn treap_remove_locked(node: *mut DeadlineNode) {
    unsafe {
        // Rotate the node down until it has no children.
        loop {
            let l = (*node).left;
            let r = (*node).right;
            if l.is_null() && r.is_null() {
                break;
            }
            if l.is_null() {
                rotate_left(node);
            } else if r.is_null() {
                rotate_right(node);
            } else if treap_precedes(l, r) {
                rotate_right(node);
            } else {
                rotate_left(node);
            }
        }

        let parent = (*node).parent;
        if parent.is_null() {
            DEADLINE_ROOT = core::ptr::null_mut();
        } else if (*parent).left == node {
            (*parent).left = core::ptr::null_mut();
        } else {
            (*parent).right = core::ptr::null_mut();
        }
        (*node).parent = core::ptr::null_mut();

        recalc_upwards(parent);

        (*node).left = core::ptr::null_mut();
        (*node).right = core::ptr::null_mut();
        (*node).subtree_min = DEADLINE_INACTIVE;
        (*node).key_ns = DEADLINE_INACTIVE;
    }
}

/// Locate the leftmost (min-key) node. Caller must hold `DEADLINE_LOCK`.
unsafe fn min_node_locked() -> *mut DeadlineNode {
    unsafe {
        let mut cur = DEADLINE_ROOT;
        if cur.is_null() {
            return core::ptr::null_mut();
        }
        while !(*cur).left.is_null() {
            cur = (*cur).left;
        }
        cur
    }
}

// ─────────────────────────── Public API ────────────────────────────

/// Arm a thread `FutexTimed` deadline. Bumps the caller's
/// `sched_ref` for the queue membership pin.
///
/// # Safety
/// `tcb` must be a live thread whose embedded `deadline_node` is in
/// the `Idle` state (caller responsibility — caller has already
/// transitioned the thread to a blocked state).
pub unsafe fn arm_thread_futex_timed(tcb: *mut Tcb, deadline_ns: u64) {
    unsafe { arm_thread(tcb, deadline_ns, DeadlineKind::FutexTimed) };
}

/// Arm a thread `IpcTimeout` deadline. Used by the `MP_CALL` and
/// `EQ_WAIT` block paths given a finite absolute deadline.
///
/// # Safety
/// As `arm_thread_futex_timed`.
pub unsafe fn arm_thread_ipc_timeout(tcb: *mut Tcb, deadline_ns: u64) {
    unsafe { arm_thread(tcb, deadline_ns, DeadlineKind::IpcTimeout) };
}

unsafe fn arm_thread(tcb: *mut Tcb, deadline_ns: u64, kind: DeadlineKind) {
    crate::kernel::bug::kassert!(deadline_ns != DEADLINE_INACTIVE);
    let node = unsafe { &raw mut (*tcb).deadline_node };
    let seq = unsafe { (*tcb).wait_seq };

    let irq = unsafe { save_irq_disable() };
    DEADLINE_LOCK.lock();
    // CAS + pin + treap insert under one lock so state and queue membership
    // never disagree — a concurrent `cancel_owner` can no longer observe a
    // `Queued`-but-unlinked node and remove/unpin one this arm is inserting.
    let prev_state = unsafe {
        (*node)
            .state
            .compare_exchange(
                DeadlineNodeState::Idle as u8,
                DeadlineNodeState::Queued as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
    };
    if prev_state.is_err() {
        // Already armed — caller layer is responsible for not double-arming.
        DEADLINE_LOCK.unlock();
        unsafe { restore_irq(irq) };
        return;
    }

    unsafe {
        // Membership pin, atomic with the state transition + tree publish.
        (*tcb).sched_ref_inc();
        (*node).key_ns = deadline_ns;
        (*node).kind = kind as u8;
        (*node).seq = seq;
        (*node).owner_obj = tcb as *mut KernelObject;
        treap_insert_locked(node);
        refresh_next_deadline_locked();
    }
    DEADLINE_LOCK.unlock();
    unsafe { restore_irq(irq) };
}

/// Arm a `Timer` fire deadline. Bumps the timer's `KernelObject.ref_count`
/// for the queue membership pin.
///
/// # Safety
/// `timer` must be a live `Timer` whose `deadline_node` is `Idle`.
/// Caller must hold the timer's `timer_lock` so `seq` matches the
/// live `Timer::deadline_seq`.
pub unsafe fn arm_timer(
    timer: *mut crate::event::timer::Timer,
    deadline_ns: u64,
    seq: u64,
) -> bool {
    crate::kernel::bug::kassert!(deadline_ns != DEADLINE_INACTIVE);
    let node = unsafe { &raw mut (*timer).deadline_node };

    let irq = unsafe { save_irq_disable() };
    DEADLINE_LOCK.lock();
    // CAS + pin + treap insert under one lock so state and queue membership
    // never disagree — a concurrent `cancel_timer` can no longer observe a
    // `Queued`-but-unlinked node and remove/unpin one this arm is inserting.
    let prev = unsafe {
        (*node).state.compare_exchange(
            DeadlineNodeState::Idle as u8,
            DeadlineNodeState::Queued as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
    };
    if prev.is_err() {
        // Node is `Queued` (already armed) or `Dispatching` (an in-flight fire
        // on another CPU owns it). Report the refusal so the caller can decide
        // to retry once the node returns to `Idle`.
        DEADLINE_LOCK.unlock();
        unsafe { restore_irq(irq) };
        return false;
    }

    unsafe {
        // Membership pin, atomic with the state transition + tree publish.
        (*(timer as *mut KernelObject))
            .ref_count
            .fetch_add(1, Ordering::AcqRel);
        (*node).key_ns = deadline_ns;
        (*node).kind = DeadlineKind::TimerFire as u8;
        (*node).seq = seq;
        (*node).owner_obj = timer as *mut KernelObject;
        treap_insert_locked(node);
        refresh_next_deadline_locked();
    }
    DEADLINE_LOCK.unlock();
    unsafe { restore_irq(irq) };
    true
}

/// Cancel a thread's armed deadline. Returns `true` if the node was
/// removed from the queue, `false` if it had already fired or was
/// never armed. Releases the membership pin on success.
///
/// # Safety
/// `tcb` must be a live thread.
pub unsafe fn cancel_thread(tcb: *mut Tcb) -> bool {
    unsafe { cancel_owner(&raw mut (*tcb).deadline_node, OwnerKind::Thread(tcb)) }
}

/// Cancel a timer's armed deadline. Returns `true` if removed.
///
/// # Safety
/// `timer` must be a live `Timer`.
pub unsafe fn cancel_timer(timer: *mut crate::event::timer::Timer) -> bool {
    unsafe { cancel_owner(&raw mut (*timer).deadline_node, OwnerKind::Timer(timer)) }
}

enum OwnerKind {
    Thread(*mut Tcb),
    Timer(*mut crate::event::timer::Timer),
}

unsafe fn cancel_owner(node: *mut DeadlineNode, owner: OwnerKind) -> bool {
    let irq = unsafe { save_irq_disable() };
    DEADLINE_LOCK.lock();
    // CAS + treap removal under one lock so state and queue membership never
    // disagree: a cancel can no longer observe a half-armed node (`Queued` but
    // not yet linked) and remove/unpin a node the armer is about to insert.
    let prev = unsafe {
        (*node).state.compare_exchange(
            DeadlineNodeState::Queued as u8,
            DeadlineNodeState::Idle as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
    };
    if prev.is_err() {
        // Either Idle (never armed / already fired) or Dispatching
        // (the dispatch loop owns the node and will run the callback;
        // cancel raced and lost). Either way, no detach work to do.
        DEADLINE_LOCK.unlock();
        unsafe { restore_irq(irq) };
        return false;
    }
    unsafe {
        treap_remove_locked(node);
        refresh_next_deadline_locked();
    }
    DEADLINE_LOCK.unlock();
    unsafe { restore_irq(irq) };

    // Release the membership pin we took at arm.
    unsafe {
        match owner {
            OwnerKind::Thread(tcb) => {
                crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(tcb);
            }
            OwnerKind::Timer(timer) => {
                crate::cap::release_object(timer as *mut KernelObject, ObjectType::Timer);
            }
        }
    }
    true
}

/// Per-tick dispatch: drain every node whose `key_ns <= now_ns` and
/// hand it to the appropriate callback. Stale-seq pops are dropped.
pub fn check_wakeups(now_ns: u64) {
    const BATCH: usize = 16;

    loop {
        let mut batch: [*mut DeadlineNode; BATCH] = [core::ptr::null_mut(); BATCH];
        let mut count = 0usize;
        let more;

        let irq = unsafe { save_irq_disable() };
        DEADLINE_LOCK.lock();
        unsafe {
            while count < BATCH {
                let node = min_node_locked();
                if node.is_null() {
                    break;
                }
                if (*node).key_ns > now_ns {
                    break;
                }
                // Transition Queued -> Dispatching. cancel races are
                // resolved by the CAS — losing cancel returns false
                // and leaves us as the dispatcher.
                if (*node)
                    .state
                    .compare_exchange(
                        DeadlineNodeState::Queued as u8,
                        DeadlineNodeState::Dispatching as u8,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    // Another path already moved this node out; should
                    // not happen because we hold the queue lock and
                    // detach happens under the same lock — but be
                    // defensive.
                    treap_remove_locked(node);
                    continue;
                }
                treap_remove_locked(node);
                batch[count] = node;
                count += 1;
            }
            more = !min_node_locked().is_null() && (*min_node_locked()).key_ns <= now_ns;
            refresh_next_deadline_locked();
        }
        DEADLINE_LOCK.unlock();
        unsafe { restore_irq(irq) };

        for i in 0..count {
            let node = batch[i];
            if node.is_null() {
                continue;
            }
            unsafe { dispatch_node(node, now_ns) };
        }

        if !more {
            break;
        }
    }
}

unsafe fn dispatch_node(node: *mut DeadlineNode, now_ns: u64) {
    unsafe {
        let kind = match DeadlineKind::from_u8((*node).kind) {
            Some(k) => k,
            None => {
                // Corrupt — defensive reset.
                (*node)
                    .state
                    .store(DeadlineNodeState::Idle as u8, Ordering::Release);
                return;
            }
        };
        let owner = (*node).owner_obj;
        let seq = (*node).seq;
        // Clear node fields before callback so the callback can safely
        // re-arm if it wants (e.g. repeating timer).
        (*node).owner_obj = core::ptr::null_mut();

        match kind {
            // Each thread-owned kind blocks under a different
            // `BlockedReason` family and demands a different wake
            // transition — `pipe_wait_wake_plan` only fires for
            // `is_pipe_wait()` reasons, so funnelling FutexTimed
            // (`FutexTimedBlocked`) through it would no-op and
            // silently leak the parked thread.
            DeadlineKind::FutexTimed => {
                let tcb = owner as *mut Tcb;
                if !tcb.is_null() && (*tcb).wait_seq == seq {
                    // FutexTimed parks on `BlockedReason::FutexTimedBlocked`
                    // PLUS membership in a futex bucket.
                    // `execute_timeout_wake_plan` removes the bucket
                    // entry and sets `futex_wakeup_result =
                    // SyscallError::Cancelled` (the conventional
                    // "futex wait was cancelled" code) before waking.
                    if let Some(plan) = crate::sched::control::prepare_timeout_wake_plan(tcb) {
                        let _ = crate::sched::control::execute_timeout_wake_plan(plan);
                    }
                }
                (*node)
                    .state
                    .store(DeadlineNodeState::Idle as u8, Ordering::Release);
                if !tcb.is_null() {
                    crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(tcb);
                }
            }
            DeadlineKind::IpcTimeout => {
                let tcb = owner as *mut Tcb;
                if !tcb.is_null() && (*tcb).wait_seq == seq {
                    // IpcTimeout parks a `MP_CALL` writer / reply waiter or
                    // an `EQ_WAIT` waiter. Waiter-queue detach is the
                    // syscall layer's responsibility on the timeout return
                    // path (pipe block helpers call `detach_waiter`;
                    // `EventQueue::wait_block` calls `cancel_waiter`).
                    //
                    // `wake_ipc_timeout` records `TimedOut` only when its
                    // own `Blocked → Runnable` transition succeeds — if a
                    // normal reply / publish wake had already retired the
                    // waiter, this dispatch is a no-op and the caller sees
                    // its real wake result instead of a spurious timeout.
                    let _ = crate::sched::control::wake_ipc_timeout(tcb);
                }
                (*node)
                    .state
                    .store(DeadlineNodeState::Idle as u8, Ordering::Release);
                if !tcb.is_null() {
                    crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(tcb);
                }
            }
            DeadlineKind::TimerFire => {
                let timer = owner as *mut crate::event::timer::Timer;
                // The fire rechecks `seq` under `timer_lock` (a set() on another
                // CPU may have re-armed since we popped); a superseded fire
                // returns None. For a repeating timer it returns the next
                // `(deadline, seq)` to re-arm.
                let reinsert = if !timer.is_null() {
                    crate::event::timer::Timer::fire_from_dispatch(timer, now_ns, seq)
                } else {
                    None
                };
                // Release the node to Idle BEFORE the periodic re-arm so the
                // arm's Idle→Queued CAS can land (we own the Dispatching state),
                // and BEFORE dropping our dispatch ref so the object stays live.
                (*node)
                    .state
                    .store(DeadlineNodeState::Idle as u8, Ordering::Release);
                if let Some((reinsert_deadline, reinsert_seq)) = reinsert {
                    // Best-effort: a concurrent `set()` may have re-armed first
                    // (node now Queued) — then this arm is refused and that
                    // set() takes precedence.
                    let _ = arm_timer(timer, reinsert_deadline, reinsert_seq);
                }
                if !timer.is_null() {
                    crate::cap::release_object(timer as *mut KernelObject, ObjectType::Timer);
                }
            }
        }
    }
}
