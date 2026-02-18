//! Synchronization primitives: Mutex, Condvar, RWLock, Barrier, Once
//!
//! All implemented as pure userspace constructs on top of the kernel futex
//! syscall. No kernel objects are consumed for synchronization.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::syscall::{futex_wait, futex_wake};
use core::sync::atomic::{AtomicU32, Ordering};

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
    /// re-acquired before returning.
    pub fn wait(&self, mutex: &Mutex) {
        let current_seq = self.seq.load(Ordering::Relaxed);
        mutex.unlock();
        futex_wait(self.futex_ptr(), current_seq);
        mutex.lock();
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
    pub fn call_once(&self, f: fn()) {
        match self.state.load(Ordering::Acquire) {
            ONCE_COMPLETE => return,
            ONCE_UNINIT => {
                if self.state.compare_exchange(
                    ONCE_UNINIT, ONCE_RUNNING, Ordering::Acquire, Ordering::Relaxed,
                ).is_ok() {
                    f();
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
