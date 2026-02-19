//! Futex (Fast Userspace muTEX) implementation
//!
//! Provides kernel-mediated wait/wake on userspace memory words.
//! Used by pthread mutex, condvar, and other synchronization primitives.
//!
//! The futex hash table maps (VSpace*, vaddr) pairs to intrusive TCB wait
//! queues. Protected by SCHED_IPC_LOCK (no separate lock needed since all
//! futex operations also interact with the scheduler).
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::mm::{save_irq_disable, restore_irq, VSpace, SCHED_IPC_LOCK};
use crate::sched::scheduler::scheduler;
use crate::sched::thread::{BlockedReason, Tcb, ThreadState};
use crate::syscall::{SyscallError, SyscallResult};

/// Number of hash buckets for the futex table.
const FUTEX_HASH_BUCKETS: usize = 64;

/// Futex hash table: each bucket is the head of an intrusive singly-linked
/// list of TCBs blocked on futex_wait. Keyed by (VSpace*, vaddr).
///
/// Protected by SCHED_IPC_LOCK — all callers must hold it.
static mut FUTEX_TABLE: [*mut Tcb; FUTEX_HASH_BUCKETS] = [core::ptr::null_mut(); FUTEX_HASH_BUCKETS];

/// Hash function for (vspace, vaddr) → bucket index.
#[inline]
fn futex_hash(vspace: *mut VSpace, vaddr: u64) -> usize {
    // Mix the VSpace pointer and virtual address for distribution.
    // The page-aligned vaddr is shifted right by 2 to mix low bits better.
    let v = vspace as u64;
    let h = v.wrapping_mul(0x517cc1b727220a95) ^ vaddr.wrapping_mul(0x6c62272e07bb0142);
    (h as usize >> 4) % FUTEX_HASH_BUCKETS
}

/// Remove a specific TCB from the futex wait table.
///
/// Called from TCB_SUSPEND and TCB_RESUME (Blocked path).
/// Caller must hold SCHED_IPC_LOCK.
pub unsafe fn futex_remove_thread(tcb: *mut Tcb) {
    unsafe {
        if (*tcb).futex_addr == 0 {
            return; // Not in any futex queue
        }

        let vspace = (*tcb).futex_vspace;
        let addr = (*tcb).futex_addr;
        let bucket = futex_hash(vspace, addr);
        let head = &raw mut FUTEX_TABLE[bucket];

        let mut prev: *mut Tcb = core::ptr::null_mut();
        let mut node = *head;

        while !node.is_null() {
            if node == tcb {
                if prev.is_null() {
                    *head = (*node).futex_next;
                } else {
                    (*prev).futex_next = (*node).futex_next;
                }
                (*tcb).futex_next = core::ptr::null_mut();
                (*tcb).futex_addr = 0;
                (*tcb).futex_vspace = core::ptr::null_mut();
                return;
            }
            prev = node;
            node = (*node).futex_next;
        }

        // Not found in bucket — clear state defensively
        (*tcb).futex_next = core::ptr::null_mut();
        (*tcb).futex_addr = 0;
        (*tcb).futex_vspace = core::ptr::null_mut();
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
/// Returns 0 on successful wake, SALTY_WOULD_BLOCK (9) if *addr != expected.
fn futex_wait(addr: u64, expected: u32) -> SyscallResult {
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();

        let current = scheduler().current();
        if current.is_null() || (*current).vspace_root.is_null() {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        // Read the user futex word. The kernel shares the user's page tables
        // so we can read the user address directly while in kernel mode.
        let user_word = core::ptr::read_volatile(addr as *const u32);
        if user_word != expected {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            // EAGAIN equivalent — value changed before we could block
            return SyscallResult::err(SyscallError::WouldBlock);
        }

        // Set up TCB for futex blocking
        let vspace = (*current).vspace_root;
        (*current).futex_addr = addr;
        (*current).futex_vspace = vspace;
        (*current).futex_next = core::ptr::null_mut();
        (*current).state = ThreadState::Blocked;
        (*current).blocked_reason = Some(BlockedReason::FutexBlocked);

        // Insert into hash bucket (append to tail for FIFO fairness)
        let bucket = futex_hash(vspace, addr);
        let head = &raw mut FUTEX_TABLE[bucket];
        if (*head).is_null() {
            *head = current;
        } else {
            let mut tail = *head;
            while !(*tail).futex_next.is_null() {
                tail = (*tail).futex_next;
            }
            (*tail).futex_next = current;
        }

        // Reschedule — releases SCHED_IPC_LOCK before switch, reacquires on resume
        scheduler().reschedule();

        // After wakeup: SCHED_IPC_LOCK is held
        SCHED_IPC_LOCK.unlock();
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
/// Returns 0 on successful wake, SALTY_WOULD_BLOCK (9) if *addr != expected,
/// SALTY_CANCELLED (12) on timeout.
fn futex_wait_timeout(addr: u64, expected: u32, timeout_ns: u64) -> SyscallResult {
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();

        let current = scheduler().current();
        if current.is_null() || (*current).vspace_root.is_null() {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        // Read the user futex word
        let user_word = core::ptr::read_volatile(addr as *const u32);
        if user_word != expected {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::WouldBlock);
        }

        // Compute absolute wakeup time
        let now_ns = crate::arch::now_ns();
        let wakeup_ns = now_ns.saturating_add(timeout_ns);

        // Check for already-expired timeout
        if timeout_ns == 0 {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::Cancelled);
        }

        // Set up TCB for futex + timed blocking
        let vspace = (*current).vspace_root;
        (*current).futex_addr = addr;
        (*current).futex_vspace = vspace;
        (*current).futex_next = core::ptr::null_mut();
        (*current).futex_wakeup_result = 0;
        (*current).state = ThreadState::Blocked;
        (*current).blocked_reason = Some(BlockedReason::FutexTimedBlocked);

        // Insert into futex hash bucket (same as futex_wait)
        let bucket = futex_hash(vspace, addr);
        let head = &raw mut FUTEX_TABLE[bucket];
        if (*head).is_null() {
            *head = current;
        } else {
            let mut tail = *head;
            while !(*tail).futex_next.is_null() {
                tail = (*tail).futex_next;
            }
            (*tail).futex_next = current;
        }

        // Insert into sleep queue and context-switch (acquires scheduler lock internally)
        scheduler().block_current_futex_timed(wakeup_ns);

        // After wakeup: SCHED_IPC_LOCK is held
        let result = (*current).futex_wakeup_result;
        SCHED_IPC_LOCK.unlock();
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
        SCHED_IPC_LOCK.lock();

        let current = scheduler().current();
        if current.is_null() || (*current).vspace_root.is_null() {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::ok(0);
        }

        let vspace = (*current).vspace_root;
        let bucket = futex_hash(vspace, addr);
        let head = &raw mut FUTEX_TABLE[bucket];

        let mut woken: u32 = 0;
        let mut prev: *mut Tcb = core::ptr::null_mut();
        let mut node = *head;

        while !node.is_null() && woken < count {
            let next = (*node).futex_next;

            // Match on both VSpace and address (threads in different processes
            // may hash to the same bucket)
            if (*node).futex_vspace == vspace && (*node).futex_addr == addr {
                // Remove from bucket
                if prev.is_null() {
                    *head = next;
                } else {
                    (*prev).futex_next = next;
                }

                // Clear futex linkage (safe: node already removed from bucket above)
                (*node).futex_next = core::ptr::null_mut();
                (*node).futex_addr = 0;
                (*node).futex_vspace = core::ptr::null_mut();

                // If this was a timed wait, also remove from sleep queue
                // Hold scheduler lock across both sleep_queue::remove AND enqueue_unlocked
                if matches!((*node).blocked_reason, Some(BlockedReason::FutexTimedBlocked)) {
                    scheduler().lock();
                    crate::sched::sleep_queue::remove(node);
                    (*node).timer_wakeup_ns = 0;
                    (*node).futex_wakeup_result = 0; // woken by wake, not timeout
                    (*node).blocked_reason = None;
                    scheduler().enqueue_unlocked(node);
                    scheduler().unlock();
                } else {
                    (*node).blocked_reason = None;
                    scheduler().lock();
                    scheduler().enqueue_unlocked(node);
                    scheduler().unlock();
                }

                woken += 1;
                // Don't update prev — node was removed
                node = next;
            } else {
                prev = node;
                node = next;
            }
        }

        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);

        SyscallResult::ok(woken as u64)
    }
}
