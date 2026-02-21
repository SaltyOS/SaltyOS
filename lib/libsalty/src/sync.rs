//! Synchronization primitives: Mutex, Condvar, RWLock, Barrier, Once
//!
//! All implemented as pure userspace constructs on top of the kernel futex
//! syscall. No kernel objects are consumed for synchronization.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::syscall::{futex_wait, futex_wait_timeout, futex_wake};
use core::sync::atomic::{AtomicU32, Ordering};

#[inline]
fn monotonic_now_ns() -> u64 {
    crate::syscall::syscall(
        crate::consts::SYS_CLOCK_GETTIME,
        crate::consts::CLOCK_MONOTONIC as u64,
        0,
        0,
        0,
        0,
        0,
    )
    .value
}

#[inline]
fn remaining_timeout_ns(deadline_ns: u64) -> u64 {
    deadline_ns.saturating_sub(monotonic_now_ns())
}

// =========================================================================
// Mutex: futex-based, 3-state (0=unlocked, 1=locked, 2=locked+waiters)
// =========================================================================

/// Mutual exclusion lock.
///
/// State encoding:
/// - 0: unlocked
/// - 1: locked, no waiters
/// - 2: locked, one or more threads waiting
#[repr(C)]
pub struct Mutex {
    state: AtomicU32,
}

impl Mutex {
    pub const fn new() -> Self {
        Mutex {
            state: AtomicU32::new(0),
        }
    }

    /// Acquire the mutex, blocking if necessary.
    pub fn lock(&self) {
        // Fast path: uncontended CAS 0 → 1
        if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return;
        }

        // Slow path: swap to 2 (locked + waiters) and futex_wait
        loop {
            // If state was already non-zero, swap to 2
            let prev = self.state.swap(2, Ordering::Acquire);
            if prev == 0 {
                // We acquired the lock (and marked waiters — harmless)
                return;
            }
            // Block until state changes from 2
            futex_wait(self.futex_ptr(), 2);
        }
    }

    /// Acquire the mutex with a timeout in nanoseconds.
    /// Returns true if the lock was acquired, false on timeout.
    pub fn lock_timeout(&self, timeout_ns: u64) -> bool {
        let deadline_ns = monotonic_now_ns().saturating_add(timeout_ns);

        // Fast path: uncontended CAS 0 → 1
        if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return true;
        }

        // Slow path: swap to 2 (locked + waiters) and futex_wait_timeout
        loop {
            let prev = self.state.swap(2, Ordering::Acquire);
            if prev == 0 {
                return true;
            }

            let remaining_ns = remaining_timeout_ns(deadline_ns);
            if remaining_ns == 0 {
                // Timeout — try one last time before giving up
                if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    return true;
                }
                return false;
            }

            let err = futex_wait_timeout(self.futex_ptr(), 2, remaining_ns);
            if err == crate::consts::SALTY_CANCELLED {
                // Timeout — try one last time before giving up
                if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    return true;
                }
                return false;
            }
        }
    }

    /// Try to acquire the mutex without blocking.
    /// Returns true if the lock was acquired, false otherwise.
    pub fn try_lock(&self) -> bool {
        self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    /// Release the mutex.
    pub fn unlock(&self) {
        let prev = self.state.swap(0, Ordering::Release);
        if prev == 2 {
            // There were waiters — wake one
            futex_wake(self.futex_ptr(), 1);
        }
    }

    #[inline]
    fn futex_ptr(&self) -> *const u32 {
        // SAFETY: AtomicU32 has the same layout as u32
        &self.state as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// TypedMutex: RECURSIVE and ERRORCHECK mutex types
// =========================================================================

/// Mutex type constants
pub const MUTEX_NORMAL: u8 = 0;
pub const MUTEX_RECURSIVE: u8 = 1;
pub const MUTEX_ERRORCHECK: u8 = 2;

/// Typed mutex supporting NORMAL, RECURSIVE, and ERRORCHECK semantics.
///
/// Layout is `#[repr(C)]` for C ABI compatibility. Fits in 24 bytes.
#[repr(C)]
pub struct TypedMutex {
    /// Futex word: 0=unlocked, 1=locked, 2=locked+waiters
    state: AtomicU32,
    /// Mutex type (NORMAL, RECURSIVE, ERRORCHECK)
    mutex_type: u8,
    _pad: [u8; 3],
    /// Thread ID of the current owner (u64::MAX = no owner)
    owner: core::sync::atomic::AtomicU64,
    /// Recursion depth (RECURSIVE only)
    count: AtomicU32,
    _pad2: [u8; 4],
}

impl TypedMutex {
    pub const fn new(mutex_type: u8) -> Self {
        TypedMutex {
            state: AtomicU32::new(0),
            mutex_type,
            _pad: [0; 3],
            owner: core::sync::atomic::AtomicU64::new(u64::MAX),
            count: AtomicU32::new(0),
            _pad2: [0; 4],
        }
    }

    /// Get the current thread's ID from TLS.
    #[inline]
    fn current_thread_id() -> u64 {
        if let Some(tls) = crate::tls::current_tls() {
            unsafe { (*tls).thread_id }
        } else {
            0
        }
    }

    /// Lock the typed mutex. Returns 0 on success, errno on error.
    pub fn lock(&self) -> i32 {
        let tid = Self::current_thread_id();

        match self.mutex_type {
            MUTEX_RECURSIVE => {
                // If already owned by this thread, just increment count
                if self.owner.load(Ordering::Relaxed) == tid {
                    self.count.fetch_add(1, Ordering::Relaxed);
                    return 0;
                }
                self.lock_inner();
                self.owner.store(tid, Ordering::Relaxed);
                self.count.store(1, Ordering::Relaxed);
                0
            }
            MUTEX_ERRORCHECK => {
                // If already owned by this thread, return EDEADLK
                if self.owner.load(Ordering::Relaxed) == tid {
                    return 35; // EDEADLK
                }
                self.lock_inner();
                self.owner.store(tid, Ordering::Relaxed);
                0
            }
            _ => {
                self.lock_inner();
                0
            }
        }
    }

    /// Try to lock the typed mutex. Returns 0 on success, errno on error.
    pub fn try_lock(&self) -> i32 {
        let tid = Self::current_thread_id();

        match self.mutex_type {
            MUTEX_RECURSIVE => {
                if self.owner.load(Ordering::Relaxed) == tid {
                    self.count.fetch_add(1, Ordering::Relaxed);
                    return 0;
                }
                if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    self.owner.store(tid, Ordering::Relaxed);
                    self.count.store(1, Ordering::Relaxed);
                    0
                } else {
                    16 // EBUSY
                }
            }
            MUTEX_ERRORCHECK => {
                if self.owner.load(Ordering::Relaxed) == tid {
                    return 16; // EBUSY
                }
                if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    self.owner.store(tid, Ordering::Relaxed);
                    0
                } else {
                    16 // EBUSY
                }
            }
            _ => {
                if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    0
                } else {
                    16 // EBUSY
                }
            }
        }
    }

    /// Unlock the typed mutex. Returns 0 on success, errno on error.
    pub fn unlock(&self) -> i32 {
        match self.mutex_type {
            MUTEX_RECURSIVE => {
                let tid = Self::current_thread_id();
                if self.owner.load(Ordering::Relaxed) != tid {
                    return 1; // EPERM
                }
                let prev_count = self.count.fetch_sub(1, Ordering::Relaxed);
                if prev_count <= 1 {
                    // Final unlock
                    self.owner.store(u64::MAX, Ordering::Relaxed);
                    self.count.store(0, Ordering::Relaxed);
                    self.unlock_inner();
                }
                0
            }
            MUTEX_ERRORCHECK => {
                let tid = Self::current_thread_id();
                if self.owner.load(Ordering::Relaxed) != tid {
                    return 1; // EPERM
                }
                self.owner.store(u64::MAX, Ordering::Relaxed);
                self.unlock_inner();
                0
            }
            _ => {
                self.unlock_inner();
                0
            }
        }
    }

    /// Lock with timeout. Returns 0 on success, errno on error/timeout.
    pub fn lock_timeout(&self, timeout_ns: u64) -> i32 {
        let tid = Self::current_thread_id();

        match self.mutex_type {
            MUTEX_RECURSIVE => {
                if self.owner.load(Ordering::Relaxed) == tid {
                    self.count.fetch_add(1, Ordering::Relaxed);
                    return 0;
                }
                if !self.lock_inner_timeout(timeout_ns) {
                    return 110; // ETIMEDOUT
                }
                self.owner.store(tid, Ordering::Relaxed);
                self.count.store(1, Ordering::Relaxed);
                0
            }
            MUTEX_ERRORCHECK => {
                if self.owner.load(Ordering::Relaxed) == tid {
                    return 35; // EDEADLK
                }
                if !self.lock_inner_timeout(timeout_ns) {
                    return 110; // ETIMEDOUT
                }
                self.owner.store(tid, Ordering::Relaxed);
                0
            }
            _ => {
                if !self.lock_inner_timeout(timeout_ns) {
                    110 // ETIMEDOUT
                } else {
                    0
                }
            }
        }
    }

    /// Internal: acquire the futex lock (blocking).
    fn lock_inner(&self) {
        if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return;
        }
        loop {
            let prev = self.state.swap(2, Ordering::Acquire);
            if prev == 0 {
                return;
            }
            futex_wait(self.futex_ptr(), 2);
        }
    }

    /// Internal: acquire the futex lock with timeout. Returns true on success.
    fn lock_inner_timeout(&self, timeout_ns: u64) -> bool {
        let deadline_ns = monotonic_now_ns().saturating_add(timeout_ns);

        if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return true;
        }
        loop {
            let prev = self.state.swap(2, Ordering::Acquire);
            if prev == 0 {
                return true;
            }

            let remaining_ns = remaining_timeout_ns(deadline_ns);
            if remaining_ns == 0 {
                // Timeout — last-chance try
                if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    return true;
                }
                return false;
            }

            let err = futex_wait_timeout(self.futex_ptr(), 2, remaining_ns);
            if err == crate::consts::SALTY_CANCELLED {
                // Timeout — last-chance try
                if self.state.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    return true;
                }
                return false;
            }
        }
    }

    /// Internal: release the futex lock.
    fn unlock_inner(&self) {
        let prev = self.state.swap(0, Ordering::Release);
        if prev == 2 {
            futex_wake(self.futex_ptr(), 1);
        }
    }

    /// Unlock for condvar wait: fully releases the lock regardless of recursion
    /// depth, and returns the saved count for later restoration.
    ///
    /// Returns 0 if the caller is not the mutex owner (RECURSIVE/ERRORCHECK).
    /// The caller must check for 0 and skip the wait if ownership verification fails.
    pub(crate) fn condvar_unlock(&self) -> u32 {
        match self.mutex_type {
            MUTEX_RECURSIVE => {
                let tid = Self::current_thread_id();
                if self.owner.load(Ordering::Relaxed) != tid {
                    return 0; // Caller is not the owner
                }
                let saved = self.count.swap(0, Ordering::Relaxed);
                self.owner.store(u64::MAX, Ordering::Relaxed);
                self.unlock_inner();
                saved
            }
            MUTEX_ERRORCHECK => {
                let tid = Self::current_thread_id();
                if self.owner.load(Ordering::Relaxed) != tid {
                    return 0; // Caller is not the owner
                }
                self.owner.store(u64::MAX, Ordering::Relaxed);
                self.unlock_inner();
                1
            }
            _ => {
                self.unlock_inner();
                1
            }
        }
    }

    /// Re-lock after condvar wait: reacquires the lock and restores owner/count.
    pub(crate) fn condvar_relock(&self, saved_count: u32) {
        self.lock_inner();
        let tid = Self::current_thread_id();
        self.owner.store(tid, Ordering::Relaxed);
        if self.mutex_type == MUTEX_RECURSIVE {
            self.count.store(saved_count, Ordering::Relaxed);
        }
    }

    #[inline]
    fn futex_ptr(&self) -> *const u32 {
        &self.state as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// Condvar: futex-based, sequence counter
// =========================================================================

/// Condition variable.
///
/// Uses a sequence counter that increments on signal/broadcast. Waiters
/// record the current sequence, release the mutex, then futex_wait on the
/// counter. This avoids lost wakeups.
#[repr(C)]
pub struct Condvar {
    seq: AtomicU32,
}

impl Condvar {
    pub const fn new() -> Self {
        Condvar {
            seq: AtomicU32::new(0),
        }
    }

    /// Wait on the condition variable, releasing `mutex` atomically.
    ///
    /// The caller must hold `mutex`. It is released before blocking and
    /// re-acquired before returning. This is a cancellation point.
    pub fn wait(&self, mutex: &Mutex) {
        let current_seq = self.seq.load(Ordering::Relaxed);
        mutex.unlock();
        futex_wait(self.futex_ptr(), current_seq);
        mutex.lock();
        // Cancellation point: check after re-acquiring mutex
        check_cancellation();
    }

    /// Wait on the condition variable with a timeout in nanoseconds.
    ///
    /// Returns 0 on successful wake, 110 (ETIMEDOUT) on timeout.
    /// This is a cancellation point.
    pub fn wait_timeout(&self, mutex: &Mutex, timeout_ns: u64) -> i32 {
        let current_seq = self.seq.load(Ordering::Relaxed);
        mutex.unlock();
        let err = futex_wait_timeout(self.futex_ptr(), current_seq, timeout_ns);
        mutex.lock();
        // Cancellation point: check after re-acquiring mutex
        check_cancellation();
        if err == crate::consts::SALTY_CANCELLED { 110 } else { 0 }
    }

    /// Wait on the condition variable with a typed mutex (RECURSIVE/ERRORCHECK).
    ///
    /// Fully releases the mutex (saving recursion count), blocks, then
    /// re-acquires with the original count restored. This is a cancellation point.
    pub fn wait_typed(&self, mutex: &TypedMutex) -> i32 {
        let current_seq = self.seq.load(Ordering::Relaxed);
        let saved = mutex.condvar_unlock();
        if saved == 0 {
            return 1; // EPERM — caller doesn't own the mutex
        }
        futex_wait(self.futex_ptr(), current_seq);
        mutex.condvar_relock(saved);
        check_cancellation();
        0
    }

    /// Wait on the condition variable with a typed mutex and timeout.
    ///
    /// Returns 0 on successful wake, 110 (ETIMEDOUT) on timeout.
    /// This is a cancellation point.
    pub fn wait_timeout_typed(&self, mutex: &TypedMutex, timeout_ns: u64) -> i32 {
        let current_seq = self.seq.load(Ordering::Relaxed);
        let saved = mutex.condvar_unlock();
        if saved == 0 {
            return 1; // EPERM — caller doesn't own the mutex
        }
        let err = futex_wait_timeout(self.futex_ptr(), current_seq, timeout_ns);
        mutex.condvar_relock(saved);
        check_cancellation();
        if err == crate::consts::SALTY_CANCELLED { 110 } else { 0 }
    }

    /// Wake one waiting thread.
    pub fn signal(&self) {
        self.seq.fetch_add(1, Ordering::Release);
        futex_wake(self.futex_ptr(), 1);
    }

    /// Wake all waiting threads.
    pub fn broadcast(&self) {
        self.seq.fetch_add(1, Ordering::Release);
        futex_wake(self.futex_ptr(), u32::MAX);
    }

    #[inline]
    fn futex_ptr(&self) -> *const u32 {
        &self.seq as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// RWLock: futex-based, reader count + writer bit
// =========================================================================

/// Reader-writer lock.
///
/// State encoding (in a single u32):
/// - bits 30:0 = reader count (0..2^31-1)
/// - bit 31 = writer lock held
/// - A separate waiter word is used for writer wake ordering.
#[repr(C)]
pub struct RWLock {
    state: AtomicU32,
    writer_wake: AtomicU32,
}

const WRITER_BIT: u32 = 1 << 31;

impl RWLock {
    pub const fn new() -> Self {
        RWLock {
            state: AtomicU32::new(0),
            writer_wake: AtomicU32::new(0),
        }
    }

    /// Acquire a shared (read) lock.
    pub fn read_lock(&self) {
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & WRITER_BIT == 0 {
                // No writer — try to increment reader count
                if self.state.compare_exchange_weak(
                    s, s + 1, Ordering::Acquire, Ordering::Relaxed,
                ).is_ok() {
                    return;
                }
            } else {
                // Writer holds lock — wait for writer_wake
                futex_wait(self.writer_futex_ptr(), self.writer_wake.load(Ordering::Relaxed));
            }
        }
    }

    /// Release a shared (read) lock.
    pub fn read_unlock(&self) {
        let prev = self.state.fetch_sub(1, Ordering::Release);
        if prev == 1 {
            // Last reader — wake a waiting writer
            self.writer_wake.fetch_add(1, Ordering::Release);
            futex_wake(self.writer_futex_ptr(), 1);
        }
    }

    /// Acquire an exclusive (write) lock.
    pub fn write_lock(&self) {
        loop {
            // Try to set WRITER_BIT when state == 0 (no readers, no writers)
            if self.state.compare_exchange_weak(
                0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed,
            ).is_ok() {
                return;
            }
            // Wait for the state to become 0
            let s = self.state.load(Ordering::Relaxed);
            if s != 0 {
                futex_wait(self.writer_futex_ptr(), self.writer_wake.load(Ordering::Relaxed));
            }
        }
    }

    /// Release an exclusive (write) lock.
    pub fn write_unlock(&self) {
        self.state.fetch_and(!WRITER_BIT, Ordering::Release);
        // Wake all — both readers and writers
        self.writer_wake.fetch_add(1, Ordering::Release);
        futex_wake(self.writer_futex_ptr(), u32::MAX);
    }

    /// Try to acquire a shared (read) lock without blocking.
    /// Returns true if acquired, false if a writer holds the lock.
    pub fn try_read_lock(&self) -> bool {
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & WRITER_BIT != 0 {
                return false;
            }
            if self.state.compare_exchange_weak(
                s, s + 1, Ordering::Acquire, Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }

    /// Try to acquire an exclusive (write) lock without blocking.
    /// Returns true if acquired, false if any readers or writer hold the lock.
    pub fn try_write_lock(&self) -> bool {
        self.state
            .compare_exchange(0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Acquire a shared (read) lock with a timeout in nanoseconds.
    /// Returns true if acquired, false on timeout.
    pub fn read_lock_timeout(&self, timeout_ns: u64) -> bool {
        let deadline_ns = monotonic_now_ns().saturating_add(timeout_ns);
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & WRITER_BIT == 0 {
                if self.state.compare_exchange_weak(
                    s, s + 1, Ordering::Acquire, Ordering::Relaxed,
                ).is_ok() {
                    return true;
                }
                continue;
            }
            let remaining = remaining_timeout_ns(deadline_ns);
            if remaining == 0 {
                return false;
            }
            let wake_val = self.writer_wake.load(Ordering::Relaxed);
            let err = futex_wait_timeout(self.writer_futex_ptr(), wake_val, remaining);
            if err == crate::consts::SALTY_CANCELLED {
                // Timeout — one last try
                let s2 = self.state.load(Ordering::Relaxed);
                if s2 & WRITER_BIT == 0 {
                    if self.state.compare_exchange(
                        s2, s2 + 1, Ordering::Acquire, Ordering::Relaxed,
                    ).is_ok() {
                        return true;
                    }
                }
                return false;
            }
        }
    }

    /// Acquire an exclusive (write) lock with a timeout in nanoseconds.
    /// Returns true if acquired, false on timeout.
    pub fn write_lock_timeout(&self, timeout_ns: u64) -> bool {
        let deadline_ns = monotonic_now_ns().saturating_add(timeout_ns);
        loop {
            if self.state.compare_exchange_weak(
                0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
            let s = self.state.load(Ordering::Relaxed);
            if s != 0 {
                let remaining = remaining_timeout_ns(deadline_ns);
                if remaining == 0 {
                    return false;
                }
                let wake_val = self.writer_wake.load(Ordering::Relaxed);
                let err = futex_wait_timeout(self.writer_futex_ptr(), wake_val, remaining);
                if err == crate::consts::SALTY_CANCELLED {
                    // Timeout — one last try
                    if self.state.compare_exchange(
                        0, WRITER_BIT, Ordering::Acquire, Ordering::Relaxed,
                    ).is_ok() {
                        return true;
                    }
                    return false;
                }
            }
        }
    }

    #[inline]
    fn writer_futex_ptr(&self) -> *const u32 {
        &self.writer_wake as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// Barrier: count-down + futex broadcast
// =========================================================================

/// Thread barrier: blocks threads until `count` threads have arrived.
#[repr(C)]
pub struct Barrier {
    count: u32,
    waiting: AtomicU32,
    phase: AtomicU32,
}

impl Barrier {
    pub const fn new(count: u32) -> Self {
        Barrier {
            count,
            waiting: AtomicU32::new(0),
            phase: AtomicU32::new(0),
        }
    }

    /// Wait at the barrier. Returns true for exactly one thread (the "leader"
    /// that triggers the release), false for all others.
    pub fn wait(&self) -> bool {
        let phase = self.phase.load(Ordering::Relaxed);
        let prev = self.waiting.fetch_add(1, Ordering::AcqRel);

        if prev + 1 == self.count {
            // Last thread to arrive — reset counter and advance phase
            self.waiting.store(0, Ordering::Release);
            self.phase.fetch_add(1, Ordering::Release);
            futex_wake(self.phase_futex_ptr(), u32::MAX);
            true
        } else {
            // Wait for phase to change
            loop {
                futex_wait(self.phase_futex_ptr(), phase);
                if self.phase.load(Ordering::Acquire) != phase {
                    break;
                }
            }
            false
        }
    }

    #[inline]
    fn phase_futex_ptr(&self) -> *const u32 {
        &self.phase as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// Semaphore: futex-based counting semaphore
// =========================================================================

/// Maximum value for a POSIX semaphore.
pub const SEM_VALUE_MAX: u32 = i32::MAX as u32;

/// Counting semaphore.
///
/// The count itself is the futex word: waiters call `futex_wait(ptr, 0)` when
/// the count is zero, and `post` wakes one waiter when count transitions
/// from 0 to 1.
#[repr(C)]
pub struct Semaphore {
    count: AtomicU32,
}

impl Semaphore {
    pub const fn new(initial: u32) -> Self {
        Semaphore {
            count: AtomicU32::new(initial),
        }
    }

    /// Re-initialize the semaphore. Returns 0 on success, -1 if value exceeds
    /// SEM_VALUE_MAX.
    pub fn init(&self, value: u32) -> i32 {
        if value > SEM_VALUE_MAX {
            return -1;
        }
        self.count.store(value, Ordering::Release);
        if value > 0 {
            futex_wake(self.futex_ptr(), u32::MAX);
        }
        0
    }

    /// Decrement (wait). Blocks if the count is zero.
    pub fn wait(&self) {
        loop {
            let c = self.count.load(Ordering::Relaxed);
            if c > 0 {
                if self.count.compare_exchange_weak(
                    c, c - 1, Ordering::Acquire, Ordering::Relaxed,
                ).is_ok() {
                    return;
                }
            } else {
                futex_wait(self.futex_ptr(), 0);
            }
        }
    }

    /// Try to decrement without blocking.
    /// Returns true if decremented, false if count was zero.
    pub fn try_wait(&self) -> bool {
        loop {
            let c = self.count.load(Ordering::Relaxed);
            if c == 0 {
                return false;
            }
            if self.count.compare_exchange_weak(
                c, c - 1, Ordering::Acquire, Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }

    /// Decrement with timeout in nanoseconds.
    /// Returns 0 on success, 110 (ETIMEDOUT) on timeout.
    pub fn wait_timeout(&self, timeout_ns: u64) -> i32 {
        let deadline_ns = monotonic_now_ns().saturating_add(timeout_ns);
        loop {
            let c = self.count.load(Ordering::Relaxed);
            if c > 0 {
                if self.count.compare_exchange_weak(
                    c, c - 1, Ordering::Acquire, Ordering::Relaxed,
                ).is_ok() {
                    return 0;
                }
                continue;
            }
            let remaining = remaining_timeout_ns(deadline_ns);
            if remaining == 0 {
                // Last-chance try
                let c2 = self.count.load(Ordering::Relaxed);
                if c2 > 0 {
                    if self.count.compare_exchange(
                        c2, c2 - 1, Ordering::Acquire, Ordering::Relaxed,
                    ).is_ok() {
                        return 0;
                    }
                }
                return 110; // ETIMEDOUT
            }
            let err = futex_wait_timeout(self.futex_ptr(), 0, remaining);
            if err == crate::consts::SALTY_CANCELLED {
                // Last-chance try
                let c2 = self.count.load(Ordering::Relaxed);
                if c2 > 0 {
                    if self.count.compare_exchange(
                        c2, c2 - 1, Ordering::Acquire, Ordering::Relaxed,
                    ).is_ok() {
                        return 0;
                    }
                }
                return 110; // ETIMEDOUT
            }
        }
    }

    /// Increment (post). Returns 0 on success, -1 on overflow.
    pub fn post(&self) -> i32 {
        loop {
            let c = self.count.load(Ordering::Relaxed);
            if c >= SEM_VALUE_MAX {
                return -1;
            }
            if self.count.compare_exchange_weak(
                c, c + 1, Ordering::Release, Ordering::Relaxed,
            ).is_ok() {
                if c == 0 {
                    // Was zero, wake one waiter
                    futex_wake(self.futex_ptr(), 1);
                }
                return 0;
            }
        }
    }

    /// Get the current value.
    pub fn get_value(&self) -> i32 {
        self.count.load(Ordering::Relaxed) as i32
    }

    #[inline]
    fn futex_ptr(&self) -> *const u32 {
        &self.count as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// Once: run-exactly-once initialization
// =========================================================================

/// States for `Once`
const ONCE_UNINIT: u32 = 0;
const ONCE_RUNNING: u32 = 1;
const ONCE_COMPLETE: u32 = 2;

/// Execute a closure exactly once, even across multiple threads.
#[repr(C)]
pub struct Once {
    state: AtomicU32,
}

impl Once {
    pub const fn new() -> Self {
        Once {
            state: AtomicU32::new(ONCE_UNINIT),
        }
    }

    /// Execute `f` if this is the first call. All subsequent calls are no-ops.
    /// Concurrent callers block until the first caller's `f` returns.
    pub fn call_once(&self, f: unsafe extern "C" fn()) {
        match self.state.load(Ordering::Acquire) {
            ONCE_COMPLETE => return,
            ONCE_UNINIT => {
                if self.state.compare_exchange(
                    ONCE_UNINIT, ONCE_RUNNING, Ordering::Acquire, Ordering::Relaxed,
                ).is_ok() {
                    unsafe { f() };
                    self.state.store(ONCE_COMPLETE, Ordering::Release);
                    futex_wake(self.futex_ptr(), u32::MAX);
                    return;
                }
            }
            _ => {}
        }

        // Wait for ONCE_COMPLETE
        loop {
            let s = self.state.load(Ordering::Acquire);
            if s == ONCE_COMPLETE {
                return;
            }
            futex_wait(self.futex_ptr(), ONCE_RUNNING);
        }
    }

    #[inline]
    fn futex_ptr(&self) -> *const u32 {
        &self.state as *const AtomicU32 as *const u32
    }
}

// =========================================================================
// Cancellation support
// =========================================================================

/// Check for pending cancellation at a cancellation point.
///
/// If a cancellation is pending and enabled, invokes `pthread_testcancel()`
/// which runs cleanup handlers and calls `pthread_exit(PTHREAD_CANCELED)`.
fn check_cancellation() {
    if let Some(tls) = crate::tls::current_tls() {
        unsafe {
            let pending = core::ptr::read_volatile(&raw const (*tls).cancel_pending);
            if pending != 0 && (*tls).cancel_state == 0 {
                crate::pthread::pthread_testcancel();
            }
        }
    }
}
