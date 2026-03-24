//! Futex (Fast Userspace muTEX) implementation
//!
//! Provides kernel-mediated wait/wake on userspace memory words.
//! Used by pthread mutex, condvar, and other synchronization primitives.
//!
//! The futex hash table maps (VSpace*, vaddr) pairs to intrusive TCB wait
//! queues. Each bucket has its own spinlock for SMP scalability — threads
//! contending on different addresses never share a lock.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::mm::{save_irq_disable, restore_irq, SpinLock, VSpace};
use crate::sched::scheduler::scheduler;
use crate::sched::thread::{BlockedReason, Tcb, ThreadState};
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

static mut FUTEX_BUCKETS: [FutexBucket; FUTEX_HASH_BUCKETS] = [const { FutexBucket::new() }; FUTEX_HASH_BUCKETS];

/// Hash function for (vspace, vaddr) → bucket index.
#[inline]
fn futex_hash(vspace: *mut VSpace, vaddr: u64) -> usize {
    // Mix the VSpace pointer and virtual address for distribution.
    // The page-aligned vaddr is shifted right by 2 to mix low bits better.
    let v = vspace as u64;
    let h = v.wrapping_mul(0x517cc1b727220a95) ^ vaddr.wrapping_mul(0x6c62272e07bb0142);
    (h as usize >> 4) % FUTEX_HASH_BUCKETS
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

/// Remove a specific TCB from the futex wait table.
///
/// Called from TCB_SUSPEND and sleep_queue::check_wakeups (Blocked path).
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

/// Futex syscall dispatcher.
///
/// - `addr`: user virtual address of the futex word (u32)
/// - `op`: FUTEX_WAIT (0), FUTEX_WAKE (1), or FUTEX_WAIT_TIMEOUT (2)
/// - `val`: expected value (WAIT) or max wake count (WAKE)
/// - `extra`: timeout in nanoseconds (for FUTEX_WAIT_TIMEOUT)
pub fn syscall_futex(addr: u64, op: u64, val: u64, extra: u64) -> SyscallResult {
    // Validate address is in user range and aligned
    if addr == 0 || addr >= 0x0000_8000_0000_0000 || (addr & 3) != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    match op {
        0 => futex_wait(addr, val as u32),
        1 => futex_wake(addr, val as u32),
        2 => futex_wait_timeout(addr, val as u32, extra),
        _ => SyscallResult::err(SyscallError::InvalidOperation),
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

        // Read the user futex word. The kernel shares the user's page tables
        // so we can read the user address directly while in kernel mode.
        // SMAP: temporarily allow user memory access for the futex word read.
        let user_word = {
            let _guard = crate::arch::uaccess::UserAccessGuard::new();
            core::ptr::read_volatile(addr as *const u32)
        };
        if user_word != expected {
            bucket.lock.unlock();
            restore_irq(irq);
            // EAGAIN equivalent — value changed before we could block
            return SyscallResult::err(SyscallError::WouldBlock);
        }

        // Set up TCB for futex blocking
        (*current).futex_addr = addr;
        (*current).futex_vspace = vspace;
        (*current).futex_next = core::ptr::null_mut();
        (*current).state = ThreadState::Blocked;
        (*current).blocked_reason = Some(BlockedReason::FutexBlocked);

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

        // Read the user futex word
        // SMAP: temporarily allow user memory access for the futex word read.
        let user_word = {
            let _guard = crate::arch::uaccess::UserAccessGuard::new();
            core::ptr::read_volatile(addr as *const u32)
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

        // Set up TCB for futex + timed blocking
        (*current).futex_addr = addr;
        (*current).futex_vspace = vspace;
        (*current).futex_next = core::ptr::null_mut();
        (*current).futex_wakeup_result = 0;
        (*current).state = ThreadState::Blocked;
        (*current).blocked_reason = Some(BlockedReason::FutexTimedBlocked);

        // O(1) tail insertion
        bucket_insert(bucket, current);

        // Release bucket lock before context switch (no lock during switch)
        bucket.lock.unlock();

        // Insert into sleep queue and context-switch (acquires scheduler lock internally)
        scheduler().block_current_futex_timed(wakeup_ns);

        // After wakeup: no global lock held
        let result = (*current).futex_wakeup_result;
        restore_irq(irq);

        if result != 0 {
            SyscallResult::err(SyscallError::Cancelled)
        } else {
            SyscallResult::ok(0)
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

            if matches!((*wake_node).blocked_reason, Some(BlockedReason::FutexTimedBlocked)) {
                crate::sched::sleep_queue::remove(wake_node);
                // Re-check: check_wakeups may have won the race while we
                // waited for SLEEP_LOCK inside remove(). If blocked_reason
                // was cleared to None, the thread is already enqueued.
                if (*wake_node).blocked_reason.is_none() {
                    wake_node = next;
                    continue;
                }
                (*wake_node).timer_wakeup_ns = 0;
                (*wake_node).futex_wakeup_result = 0; // woken by wake, not timeout
            }

            (*wake_node).blocked_reason = None;
            (*wake_node).state = ThreadState::Ready;
            scheduler().enqueue(wake_node);
            wake_node = next;
        }

        restore_irq(irq);

        SyscallResult::ok(woken as u64)
    }
}
