// SPDX-License-Identifier: GPL-2.0-only
//! Futex (Fast Userspace muTEX) implementation
//!
//! Provides kernel-mediated wait/wake on userspace memory words.
//! Used by pthread mutex, condvar, and other synchronization primitives.
//!
//! The futex hash table maps (VSpace*, vaddr) pairs to intrusive TCB wait
//! queues. Each bucket has its own spinlock for SMP scalability — threads
//! contending on different addresses never share a lock.
//!

use crate::mm::{SpinLock, VSpace, restore_irq, save_irq_disable};
use crate::sched::scheduler::scheduler;
use crate::sched::thread::Tcb;
use crate::syscall::{SyscallError, SyscallResult};

/// Number of hash buckets for the futex table.
const FUTEX_HASH_BUCKETS: usize = 64;

/// Per-bucket futex state with dedicated lock and O(1) tail pointer.
struct FutexBucket {
    lock: SpinLock,
    head: *mut Tcb,
    tail: *mut Tcb,
}

// SAFETY: FutexBucket is accessed only under its own lock with IRQs disabled.
unsafe impl Sync for FutexBucket {}

impl FutexBucket {
    const fn new() -> Self {
        Self {
            lock: SpinLock::new(),
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
        }
    }
}

static mut FUTEX_BUCKETS: [FutexBucket; FUTEX_HASH_BUCKETS] =
    [const { FutexBucket::new() }; FUTEX_HASH_BUCKETS];

/// Hash function for (vspace, vaddr) → bucket index.
#[inline]
fn futex_hash(vspace: *mut VSpace, vaddr: u64) -> usize {
    // Mix the VSpace pointer and virtual address for distribution.
    // The page-aligned vaddr is shifted right by 2 to mix low bits better.
    let v = vspace as u64;
    let h = v.wrapping_mul(0x517cc1b727220a95) ^ vaddr.wrapping_mul(0x6c62272e07bb0142);
    (h as usize >> 4) % FUTEX_HASH_BUCKETS
}

#[inline]
unsafe fn read_user_futex_word(addr: u64) -> Result<u32, SyscallError> {
    match unsafe { crate::arch::uaccess::copy_from_user::<u32>(addr) } {
        Some(word) => Ok(word),
        None => Err(SyscallError::BadAddress),
    }
}

/// Insert TCB at tail of bucket (O(1) with tail pointer).
///
/// # Safety
/// Caller must hold the bucket lock.
#[inline]
unsafe fn bucket_insert(bucket: &mut FutexBucket, tcb: *mut Tcb) {
    unsafe {
        if bucket.head.is_null() {
            bucket.head = tcb;
        } else {
            (*bucket.tail).futex_next = tcb;
        }
        bucket.tail = tcb;
    }
}

/// Unlink `node` from `bucket` given its predecessor `prev` and successor
/// `next`. Leaves `node`'s own `futex_*` fields untouched — the caller sets
/// them per its wake-vs-requeue disposition.
///
/// # Safety
/// Caller holds the bucket lock; `prev`/`node`/`next` must reflect the
/// bucket's current linkage at `node`.
#[inline]
unsafe fn bucket_unlink(bucket: &mut FutexBucket, prev: *mut Tcb, node: *mut Tcb, next: *mut Tcb) {
    unsafe {
        if prev.is_null() {
            bucket.head = next;
        } else {
            (*prev).futex_next = next;
        }
        if bucket.tail == node {
            bucket.tail = prev;
        }
    }
}

/// Remove a specific TCB from the futex wait table.
///
/// Called from TCB_STOP and the deadline-queue dispatch path.
/// Acquires the per-bucket lock internally.
pub unsafe fn futex_remove_thread(tcb: *mut Tcb) {
    unsafe {
        if (*tcb).futex_addr == 0 {
            return; // Not in any futex queue
        }

        let vspace = (*tcb).futex_vspace;
        let addr = (*tcb).futex_addr;
        let bucket_idx = futex_hash(vspace, addr);
        let bucket = &mut *(&raw mut FUTEX_BUCKETS[bucket_idx]);
        bucket.lock.lock();

        let mut prev: *mut Tcb = core::ptr::null_mut();
        let mut node = bucket.head;

        while !node.is_null() {
            if node == tcb {
                if prev.is_null() {
                    bucket.head = (*node).futex_next;
                } else {
                    (*prev).futex_next = (*node).futex_next;
                }
                // Update tail if we removed the last node
                if bucket.tail == tcb {
                    bucket.tail = prev; // prev is null if list is now empty
                }
                (*tcb).futex_next = core::ptr::null_mut();
                (*tcb).futex_addr = 0;
                (*tcb).futex_vspace = core::ptr::null_mut();
                bucket.lock.unlock();
                return;
            }
            prev = node;
            node = (*node).futex_next;
        }

        // Not found in bucket — clear state defensively
        (*tcb).futex_next = core::ptr::null_mut();
        (*tcb).futex_addr = 0;
        (*tcb).futex_vspace = core::ptr::null_mut();
        bucket.lock.unlock();
    }
}

/// FUTEX_WAIT: atomically check *addr == expected, then block.
///
/// Returns 0 on successful wake, BESALT_WOULD_BLOCK (9) if *addr != expected.
fn futex_wait(addr: u64, expected: u32) -> SyscallResult {
    unsafe {
        let irq = save_irq_disable();

        let current = scheduler().current();
        if current.is_null() || (*current).vspace_root.is_null() {
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        let vspace = (*current).vspace_root;
        let bucket_idx = futex_hash(vspace, addr);
        let bucket = &mut *(&raw mut FUTEX_BUCKETS[bucket_idx]);
        bucket.lock.lock();

        let user_word = match read_user_futex_word(addr) {
            Ok(word) => word,
            Err(err) => {
                bucket.lock.unlock();
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };
        if user_word != expected {
            bucket.lock.unlock();
            restore_irq(irq);
            // EAGAIN equivalent — value changed before we could block
            return SyscallResult::err(SyscallError::WouldBlock);
        }

        crate::task::wait::prepare_futex_block_locked(&mut *current, addr, vspace);

        // O(1) tail insertion
        bucket_insert(bucket, current);

        // Release bucket lock before reschedule (no lock held during switch)
        bucket.lock.unlock();
        scheduler().reschedule();

        // After wakeup: no lock held
        restore_irq(irq);

        SyscallResult::ok(0)
    }
}

/// FUTEX_WAIT_TIMEOUT: atomically check *addr == expected, then block with timeout.
///
/// The thread is placed in *both* the futex hash table (for futex_wake) and the
/// sleep queue (for timer-based wakeup). Whichever fires first removes the thread
/// from both queues.
///
/// Returns 0 on successful wake, BESALT_WOULD_BLOCK (9) if *addr != expected,
/// BESALT_CANCELLED (12) on timeout.
fn futex_wait_timeout(addr: u64, expected: u32, timeout_ns: u64) -> SyscallResult {
    unsafe {
        let irq = save_irq_disable();

        let current = scheduler().current();
        if current.is_null() || (*current).vspace_root.is_null() {
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        let vspace = (*current).vspace_root;
        let bucket_idx = futex_hash(vspace, addr);
        let bucket = &mut *(&raw mut FUTEX_BUCKETS[bucket_idx]);
        bucket.lock.lock();

        let user_word = match read_user_futex_word(addr) {
            Ok(word) => word,
            Err(err) => {
                bucket.lock.unlock();
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };
        if user_word != expected {
            bucket.lock.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::WouldBlock);
        }

        // Compute absolute wakeup time
        let now_ns = crate::arch::now_ns();
        let wakeup_ns = now_ns.saturating_add(timeout_ns);

        // Check for already-expired timeout
        if timeout_ns == 0 {
            bucket.lock.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::Cancelled);
        }

        crate::task::wait::prepare_futex_timed_block_locked(&mut *current, addr, vspace);

        // O(1) tail insertion
        bucket_insert(bucket, current);

        // Release bucket lock before context switch (no lock during switch)
        bucket.lock.unlock();

        // Insert into sleep queue and context-switch (acquires scheduler lock internally)
        let result = crate::sched::control::block_current_timed_wait(wakeup_ns);
        restore_irq(irq);

        match result {
            crate::sched::control::TimedWaitResult::TimedOut(_) => {
                SyscallResult::err(SyscallError::Cancelled)
            }
            crate::sched::control::TimedWaitResult::Completed => SyscallResult::ok(0),
        }
    }
}

/// FUTEX_WAKE: wake up to `count` threads waiting on the given address.
///
/// Returns the number of threads actually woken.
fn futex_wake(addr: u64, count: u32) -> SyscallResult {
    unsafe {
        let irq = save_irq_disable();

        let current = scheduler().current();
        if current.is_null() || (*current).vspace_root.is_null() {
            restore_irq(irq);
            return SyscallResult::ok(0);
        }

        let vspace = (*current).vspace_root;
        let bucket_idx = futex_hash(vspace, addr);
        let bucket = &mut *(&raw mut FUTEX_BUCKETS[bucket_idx]);
        bucket.lock.lock();

        let mut woken: u32 = 0;
        let mut prev: *mut Tcb = core::ptr::null_mut();
        let mut node = bucket.head;
        let mut wake_head: *mut Tcb = core::ptr::null_mut();
        let mut wake_tail: *mut Tcb = core::ptr::null_mut();

        while !node.is_null() && woken < count {
            let next = (*node).futex_next;

            // Match on both VSpace and address (threads in different processes
            // may hash to the same bucket)
            if (*node).futex_vspace == vspace && (*node).futex_addr == addr {
                // Remove from bucket
                if prev.is_null() {
                    bucket.head = next;
                } else {
                    (*prev).futex_next = next;
                }
                // Update tail if we removed the last node
                if bucket.tail == node {
                    bucket.tail = prev;
                }

                // Clear futex linkage (safe: node already removed from bucket above)
                (*node).futex_addr = 0;
                (*node).futex_vspace = core::ptr::null_mut();
                (*node).futex_next = core::ptr::null_mut();

                // Build a local wake list while bucket lock is held. We process
                // sleep-queue removal and scheduler enqueue after releasing the
                // bucket lock to avoid cross-subsystem lock nesting.
                if wake_head.is_null() {
                    wake_head = node;
                    wake_tail = node;
                } else {
                    (*wake_tail).futex_next = node;
                    wake_tail = node;
                }

                woken += 1;
                // Don't update prev — node was removed
                node = next;
            } else {
                prev = node;
                node = next;
            }
        }

        bucket.lock.unlock();

        let mut wake_node = wake_head;
        while !wake_node.is_null() {
            let next = (*wake_node).futex_next;
            (*wake_node).futex_next = core::ptr::null_mut();

            // Guard: check_wakeups may have already woken this thread
            // between bucket lock release and here.  blocked_reason would
            // have been cleared to None by check_wakeups.
            if (*wake_node).blocked_reason.is_none() {
                wake_node = next;
                continue;
            }

            let _ = crate::sched::control::execute_wake_plan(
                crate::sched::control::futex_wake_plan(wake_node),
            );
            wake_node = next;
        }

        restore_irq(irq);

        SyscallResult::ok(woken as u64)
    }
}

pub(crate) fn syscall_vspace_futex_wait(
    cap: &crate::cap::Capability,
    addr: u64,
    expected: u32,
    timeout_ns: u64,
) -> SyscallResult {
    use crate::cap::{CapRights, ObjectType};

    if let Err(e) = crate::syscall::validate_capability(cap, ObjectType::VSpace, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let target_vspace = cap.object as *mut VSpace;
    unsafe {
        let current = scheduler().current();
        if current.is_null() || (*current).vspace_root != target_vspace {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
    }

    if timeout_ns == 0 {
        futex_wait(addr, expected)
    } else {
        futex_wait_timeout(addr, expected, timeout_ns)
    }
}

pub(crate) fn syscall_vspace_futex_wake(
    cap: &crate::cap::Capability,
    addr: u64,
    count: u32,
) -> SyscallResult {
    use crate::cap::{CapRights, ObjectType};

    if let Err(e) = crate::syscall::validate_capability(cap, ObjectType::VSpace, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let target_vspace = cap.object as *mut VSpace;
    unsafe {
        let current = scheduler().current();
        if current.is_null() || (*current).vspace_root != target_vspace {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
    }

    futex_wake(addr, count)
}

/// Acquire the two futex bucket locks in ascending-index order so a pair of
/// requeues running in opposite directions can never deadlock. When both
/// indices are equal the single bucket is locked exactly once.
///
/// # Safety
/// Caller must hold no futex bucket lock.
#[inline]
unsafe fn lock_futex_buckets(idx_a: usize, idx_b: usize) {
    unsafe {
        if idx_a == idx_b {
            (*(&raw mut FUTEX_BUCKETS[idx_a])).lock.lock();
        } else {
            let (lo, hi) = if idx_a < idx_b {
                (idx_a, idx_b)
            } else {
                (idx_b, idx_a)
            };
            (*(&raw mut FUTEX_BUCKETS[lo])).lock.lock();
            (*(&raw mut FUTEX_BUCKETS[hi])).lock.lock();
        }
    }
}

/// Release the two futex bucket locks (single unlock when both equal).
///
/// # Safety
/// Caller currently holds the locks taken by [`lock_futex_buckets`].
#[inline]
unsafe fn unlock_futex_buckets(idx_a: usize, idx_b: usize) {
    unsafe {
        (*(&raw mut FUTEX_BUCKETS[idx_a])).lock.unlock();
        if idx_a != idx_b {
            (*(&raw mut FUTEX_BUCKETS[idx_b])).lock.unlock();
        }
    }
}

/// FUTEX_REQUEUE (`zx_futex_requeue` shape): wake up to `wake_count` waiters
/// on `addr`, then move up to `requeue_count` of the still-blocked `addr`
/// waiters onto `requeue_addr`. Both futexes live in `vspace`. Re-validating
/// `*addr == expected` under the bucket locks closes the classic requeue
/// lost-wakeup window. Returns the number of threads woken.
fn futex_requeue(
    vspace: *mut VSpace,
    addr: u64,
    wake_count: u32,
    requeue_addr: u64,
    requeue_count: u32,
    expected: u32,
) -> SyscallResult {
    unsafe {
        let irq = save_irq_disable();

        let idx_src = futex_hash(vspace, addr);
        let idx_dst = futex_hash(vspace, requeue_addr);
        lock_futex_buckets(idx_src, idx_dst);

        // Lost-wakeup guard: re-read the futex word under the locks.
        let user_word = match read_user_futex_word(addr) {
            Ok(word) => word,
            Err(err) => {
                unlock_futex_buckets(idx_src, idx_dst);
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };
        if user_word != expected {
            unlock_futex_buckets(idx_src, idx_dst);
            restore_irq(irq);
            return SyscallResult::err(SyscallError::WouldBlock);
        }

        // Single walk of the source bucket: peel the first `wake_count`
        // matching waiters into a wake list, the next `requeue_count` into a
        // requeue list. Both are unlinked here and processed after the walk,
        // so a same-bucket requeue never re-visits a node it just moved. The
        // `src` borrow is scoped to this block so the re-home below may take a
        // fresh `&mut` to the (possibly identical) destination bucket.
        let (wake_head, requeue_head, woken) = {
            let src = &mut *(&raw mut FUTEX_BUCKETS[idx_src]);
            let mut woken: u32 = 0;
            let mut requeued: u32 = 0;
            let mut wake_head: *mut Tcb = core::ptr::null_mut();
            let mut wake_tail: *mut Tcb = core::ptr::null_mut();
            let mut rq_head: *mut Tcb = core::ptr::null_mut();
            let mut rq_tail: *mut Tcb = core::ptr::null_mut();

            let mut prev: *mut Tcb = core::ptr::null_mut();
            let mut node = src.head;
            while !node.is_null() {
                let next = (*node).futex_next;
                if (*node).futex_vspace == vspace && (*node).futex_addr == addr {
                    if woken < wake_count {
                        bucket_unlink(src, prev, node, next);
                        (*node).futex_addr = 0;
                        (*node).futex_vspace = core::ptr::null_mut();
                        (*node).futex_next = core::ptr::null_mut();
                        if wake_head.is_null() {
                            wake_head = node;
                        } else {
                            (*wake_tail).futex_next = node;
                        }
                        wake_tail = node;
                        woken += 1;
                        node = next;
                        continue;
                    } else if requeued < requeue_count {
                        bucket_unlink(src, prev, node, next);
                        (*node).futex_next = core::ptr::null_mut();
                        if rq_head.is_null() {
                            rq_head = node;
                        } else {
                            (*rq_tail).futex_next = node;
                        }
                        rq_tail = node;
                        requeued += 1;
                        node = next;
                        continue;
                    } else {
                        break;
                    }
                }
                prev = node;
                node = next;
            }
            (wake_head, rq_head, woken)
        };

        // Re-home the requeued waiters onto `requeue_addr`. `futex_vspace` is
        // unchanged — both futexes belong to `vspace`. Updating `futex_addr`
        // is what lets a later `futex_wake` / `futex_remove_thread` (timeout)
        // locate them in the destination bucket.
        if !requeue_head.is_null() {
            let dst = &mut *(&raw mut FUTEX_BUCKETS[idx_dst]);
            let mut rq = requeue_head;
            while !rq.is_null() {
                let next = (*rq).futex_next;
                (*rq).futex_next = core::ptr::null_mut();
                (*rq).futex_addr = requeue_addr;
                bucket_insert(dst, rq);
                rq = next;
            }
        }

        unlock_futex_buckets(idx_src, idx_dst);

        // Wake the peeled list after dropping the bucket locks — the same
        // cross-subsystem lock discipline `futex_wake` uses.
        let mut wake_node = wake_head;
        while !wake_node.is_null() {
            let next = (*wake_node).futex_next;
            (*wake_node).futex_next = core::ptr::null_mut();
            if (*wake_node).blocked_reason.is_some() {
                let _ = crate::sched::control::execute_wake_plan(
                    crate::sched::control::futex_wake_plan(wake_node),
                );
            }
            wake_node = next;
        }

        restore_irq(irq);
        SyscallResult::ok(woken as u64)
    }
}

pub(crate) fn syscall_vspace_futex_requeue(
    cap: &crate::cap::Capability,
    addr: u64,
    requeue_addr: u64,
    wake_count: u32,
    requeue_count: u32,
    expected: u32,
) -> SyscallResult {
    use crate::cap::{CapRights, ObjectType};

    if let Err(e) = crate::syscall::validate_capability(cap, ObjectType::VSpace, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Both futex words must be in the user range and 4-byte aligned.
    for a in [addr, requeue_addr] {
        if a == 0 || a >= 0x0000_8000_0000_0000 || (a & 3) != 0 {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }
    }

    let target_vspace = cap.object as *mut VSpace;
    unsafe {
        let current = scheduler().current();
        if current.is_null() || (*current).vspace_root != target_vspace {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
    }

    futex_requeue(
        target_vspace,
        addr,
        wake_count,
        requeue_addr,
        requeue_count,
        expected,
    )
}
