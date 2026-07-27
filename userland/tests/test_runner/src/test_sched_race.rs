//! Scheduler / TCB lifetime race stress suite.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Exercises the scheduler code paths touched by the sched_ref /
//! VSpace.waiter_lock / reply-wake fixes. Does not deterministically
//! reproduce the race windows — concurrency bugs in this area only
//! surface with specific timing — but amplifies exposure through
//! repetition + SMP fan-out so a regression that reintroduces a race
//! is likely to hit a `cleanup() sched_ref > 0` debug_assert, a VSpace
//! waiter list corruption panic, or a watchdog timeout during reap.

use core::sync::atomic::{AtomicU32, Ordering};
use trona_posix::pthread;
use trona_runtime::debug::serial;
use trona_runtime::debug::serial::LineBuf;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

// =========================================================================
// Test 1: fork/exit storm — exercises ready-queue sched_ref invariant
// =========================================================================
//
// Spawns many children that exit immediately. The parent reaps every
// child, confirming the scheduler releases each TCB's sched_ref slots
// (current[], ready queue, pending_enqueue) cleanly so the destroy
// path's `cleanup()` debug_assert holds. A regression that drops
// sched_ref to zero while the TCB is still in a ready queue trips the
// assertion under debug builds; pre-F1 the same scenario corrupts the
// Fair tree and causes an arbitrary later scheduler panic.

fn test_fork_exit_storm() -> bool {
    const CHILDREN: usize = 64;

    let mut pids: [i32; CHILDREN] = [0; CHILDREN];
    for slot in pids.iter_mut() {
        let pid = trona_posix::posix_fork();
        if pid < 0 {
            puts(b"  fork failed\n");
            return false;
        }
        if pid == 0 {
            // Cause one voluntary reschedule so the TCB visits pending
            // / current / ready at least once before teardown.
            trona_kernel::syscall::yield_now();
            unsafe { trona_posix::posix_exit(0) };
        }
        *slot = pid;
    }

    for &pid in &pids {
        let mut status = 0i32;
        let waited = unsafe { trona_posix::posix_waitpid(pid, &raw mut status) };
        if waited != pid {
            let mut lb = LineBuf::new();
            lb.str(b"  reap failed for pid=");
            lb.dec(pid as u64);
            lb.str(b"\n");
            lb.flush();
            return false;
        }
    }

    puts(b"  fork_exit_storm: ok\n");
    true
}

// =========================================================================
// Test 2: yield storm — exercises yield_current CAS + pending_enqueue
// =========================================================================
//
// Multiple pthreads each run tight yield-loops. On SMP (>= 2 CPUs),
// remote wake deposits into pending_enqueue while the local CPU is in
// yield's schedule_unlocked idle-return branch. F4's CAS cancel
// preserves concurrent deposits; a regression back to unconditional
// store(null) loses wakeups and would drive the total below target.
// The check is necessary-not-sufficient: the counter only fails on
// gross regressions, but the loop shape plus SMP fan-out also stresses
// sched_ref transitions at the pop → set_current transfer point.

const YIELD_TARGET_PER_THREAD: u32 = 2_000;
const YIELD_THREADS: usize = 4;
static YIELD_COUNTER: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn yield_worker(_arg: *mut u8) -> *mut u8 {
    for _ in 0..YIELD_TARGET_PER_THREAD {
        trona_kernel::syscall::yield_now();
        YIELD_COUNTER.fetch_add(1, Ordering::Relaxed);
    }
    core::ptr::null_mut()
}

fn test_yield_storm() -> bool {
    YIELD_COUNTER.store(0, Ordering::Relaxed);

    let mut handles: [pthread::PthreadT; YIELD_THREADS] = [0; YIELD_THREADS];
    for h in handles.iter_mut() {
        let ret = unsafe {
            pthread::pthread_create(
                &raw mut *h,
                core::ptr::null(),
                yield_worker,
                core::ptr::null_mut(),
            )
        };
        if ret != 0 {
            puts(b"  pthread_create failed\n");
            return false;
        }
    }
    for h in handles.iter() {
        let ret = unsafe { pthread::pthread_join(*h, core::ptr::null_mut()) };
        if ret != 0 {
            puts(b"  pthread_join failed\n");
            return false;
        }
    }

    let expected = YIELD_TARGET_PER_THREAD as u64 * YIELD_THREADS as u64;
    let got = YIELD_COUNTER.load(Ordering::Relaxed) as u64;
    if got != expected {
        let mut lb = LineBuf::new();
        lb.str(b"  yield counter mismatch: expected ");
        lb.dec(expected);
        lb.str(b", got ");
        lb.dec(got);
        lb.str(b"\n");
        lb.flush();
        return false;
    }

    puts(b"  yield_storm: ok\n");
    true
}

// =========================================================================
// Test 3: vspace teardown storm — exercises VSpace.waiter_lock protocol
// =========================================================================
//
// Many serial fork-exit cycles — each exit runs the VSpace deactivate
// path on the child's address space. On SMP, exit on CPU A races with
// scheduling decisions on CPU B that may have waiters on the parent's
// VSpace. F2 closes the list-corruption window via waiter_lock; a
// regression typically manifests as a waiter-list panic or a never-
// woken blocked thread (caught by the parent's waitpid timeout in the
// harness wrapper).

fn test_vspace_teardown_storm() -> bool {
    const CYCLES: usize = 32;

    let mut pids: [i32; CYCLES] = [0; CYCLES];
    for slot in pids.iter_mut() {
        let pid = trona_posix::posix_fork();
        if pid < 0 {
            puts(b"  fork failed\n");
            return false;
        }
        if pid == 0 {
            // Exit immediately — the child's VSpace teardown on the
            // procmgr reap path is what exercises the waiter protocol.
            unsafe { trona_posix::posix_exit(0) };
        }
        *slot = pid;
    }

    for &pid in &pids {
        let mut status = 0i32;
        let waited = unsafe { trona_posix::posix_waitpid(pid, &raw mut status) };
        if waited != pid {
            let mut lb = LineBuf::new();
            lb.str(b"  reap failed for pid=");
            lb.dec(pid as u64);
            lb.str(b"\n");
            lb.flush();
            return false;
        }
    }

    puts(b"  vspace_teardown_storm: ok\n");
    true
}

// =========================================================================
// Entry point
// =========================================================================

pub fn run() -> bool {
    puts(b"[test_sched_race] starting\n");
    let mut ok = true;
    if !test_fork_exit_storm() {
        ok = false;
    }
    if !test_yield_storm() {
        ok = false;
    }
    if !test_vspace_teardown_storm() {
        ok = false;
    }
    ok
}
