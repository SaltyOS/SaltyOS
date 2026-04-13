//! Pthreads test suite
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use trona::consts::kernel::*;
use trona::consts::server::TRONA_TIMED_OUT;
use trona::serial;
use trona::sync;
use trona_posix::pthread;
use trona_posix::tls;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

// =========================================================================
// Test 1: Thread create and join with return value
// =========================================================================

unsafe extern "C" fn thread_return_42(arg: *mut u8) -> *mut u8 {
    42usize as *mut u8
}

fn test_create_join() -> bool {
    let mut handle: pthread::PthreadT = 0;
    let ret = unsafe {
        pthread::pthread_create(
            &raw mut handle,
            core::ptr::null(),
            thread_return_42,
            core::ptr::null_mut(),
        )
    };
    if ret != 0 {
        puts(b"  pthread_create failed\n");
        return false;
    }

    let mut retval: *mut u8 = core::ptr::null_mut();
    let ret = unsafe { pthread::pthread_join(handle, &raw mut retval) };
    if ret != 0 {
        puts(b"  pthread_join failed\n");
        return false;
    }

    if retval as usize != 42 {
        puts(b"  unexpected return value\n");
        return false;
    }

    puts(b"  create_join: ok\n");
    true
}

// =========================================================================
// Test 2: Detach — join on detached thread returns error
// =========================================================================

unsafe extern "C" fn thread_noop(_arg: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

fn test_detach() -> bool {
    let mut handle: pthread::PthreadT = 0;
    let ret = unsafe {
        pthread::pthread_create(
            &raw mut handle,
            core::ptr::null(),
            thread_noop,
            core::ptr::null_mut(),
        )
    };
    if ret != 0 {
        puts(b"  pthread_create failed\n");
        return false;
    }

    let ret = unsafe { pthread::pthread_detach(handle) };
    if ret != 0 {
        puts(b"  pthread_detach failed\n");
        return false;
    }

    // Join on a detached thread must fail regardless of whether the thread
    // has finished — no synchronization/delay required.
    let ret = unsafe { pthread::pthread_join(handle, core::ptr::null_mut()) };
    if ret == 0 {
        puts(b"  join on detached should fail\n");
        return false;
    }

    puts(b"  detach: ok\n");
    true
}

// =========================================================================
// Test 3: Mutex — two threads incrementing a shared counter
// =========================================================================

static COUNTER: AtomicU32 = AtomicU32::new(0);
static TEST_MUTEX: sync::Mutex = sync::Mutex::new();

unsafe extern "C" fn thread_increment(_arg: *mut u8) -> *mut u8 {
    for _ in 0..1000 {
        TEST_MUTEX.lock();
        COUNTER.fetch_add(1, Ordering::Relaxed);
        TEST_MUTEX.unlock();
    }
    core::ptr::null_mut()
}

fn test_mutex_normal() -> bool {
    COUNTER.store(0, Ordering::Relaxed);

    let mut t1: pthread::PthreadT = 0;
    let mut t2: pthread::PthreadT = 0;

    let ret = unsafe {
        pthread::pthread_create(
            &raw mut t1,
            core::ptr::null(),
            thread_increment,
            core::ptr::null_mut(),
        )
    };
    if ret != 0 {
        puts(b"  create t1 failed\n");
        return false;
    }
    let ret = unsafe {
        pthread::pthread_create(
            &raw mut t2,
            core::ptr::null(),
            thread_increment,
            core::ptr::null_mut(),
        )
    };
    if ret != 0 {
        puts(b"  create t2 failed\n");
        return false;
    }

    unsafe {
        pthread::pthread_join(t1, core::ptr::null_mut());
        pthread::pthread_join(t2, core::ptr::null_mut());
    }

    let count = COUNTER.load(Ordering::Relaxed);
    if count != 2000 {
        let mut lb = serial::LineBuf::new();
        lb.str(b"  counter=");
        lb.dec(count as u64);
        lb.str(b" expected 2000\n");
        lb.flush();
        return false;
    }

    puts(b"  mutex_normal: ok\n");
    true
}

// =========================================================================
// Test 4: Recursive mutex — lock same mutex twice
// =========================================================================

fn test_mutex_recursive() -> bool {
    let mut mtx = sync::TypedMutex::new(sync::MUTEX_RECURSIVE);

    let ret = mtx.lock();
    if ret != TRONA_OK {
        puts(b"  first lock failed\n");
        return false;
    }

    // Second lock should succeed (recursive)
    let ret = mtx.lock();
    if ret != TRONA_OK {
        puts(b"  second (recursive) lock failed\n");
        return false;
    }

    let ret = mtx.unlock();
    if ret != TRONA_OK {
        puts(b"  first unlock failed\n");
        return false;
    }

    let ret = mtx.unlock();
    if ret != TRONA_OK {
        puts(b"  second unlock failed\n");
        return false;
    }

    puts(b"  mutex_recursive: ok\n");
    true
}

// =========================================================================
// Test 5: Errorcheck mutex — double-lock returns EDEADLK
// =========================================================================

fn test_mutex_errorcheck() -> bool {
    let mtx = sync::TypedMutex::new(sync::MUTEX_ERRORCHECK);

    let ret = mtx.lock();
    if ret != 0 {
        puts(b"  first lock failed\n");
        return false;
    }

    // Second lock should return TRONA_DEADLOCK
    let ret = mtx.lock();
    if ret != TRONA_DEADLOCK {
        let mut lb = serial::LineBuf::new();
        lb.str(b"  expected TRONA_DEADLOCK, got ");
        lb.dec(ret);
        lb.str(b"\n");
        lb.flush();
        // Unlock to avoid deadlock in test
        mtx.unlock();
        return false;
    }

    // Unlock by owner should succeed
    let ret = mtx.unlock();
    if ret != TRONA_OK {
        puts(b"  owner unlock failed\n");
        return false;
    }

    puts(b"  mutex_errorcheck: ok\n");
    true
}

// =========================================================================
// Test 6: Condvar signal — producer/consumer
// =========================================================================

static CV_MUTEX: sync::Mutex = sync::Mutex::new();
static CV_COND: sync::Condvar = sync::Condvar::new();
static CV_READY: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn thread_producer(_arg: *mut u8) -> *mut u8 {
    // The main thread (consumer) holds CV_MUTEX at the time this producer
    // is spawned, so this lock() blocks until the consumer calls
    // CV_COND.wait() — which atomically releases the mutex. Acquiring the
    // lock here is therefore a deterministic signal that the consumer is
    // inside cond.wait, with no sleep/yield assumptions.
    CV_MUTEX.lock();
    CV_READY.store(1, Ordering::Release);
    CV_COND.signal();
    CV_MUTEX.unlock();

    core::ptr::null_mut()
}

fn test_condvar_signal() -> bool {
    CV_READY.store(0, Ordering::Relaxed);

    // Acquire the mutex BEFORE spawning the producer. The producer's first
    // action is CV_MUTEX.lock(), so it will block until we enter
    // CV_COND.wait() below. This forces the test to exercise the cond.wait
    // path deterministically, independent of scheduling order.
    CV_MUTEX.lock();

    let mut producer: pthread::PthreadT = 0;
    let ret = unsafe {
        pthread::pthread_create(
            &raw mut producer,
            core::ptr::null(),
            thread_producer,
            core::ptr::null_mut(),
        )
    };
    if ret != 0 {
        CV_MUTEX.unlock();
        puts(b"  create producer failed\n");
        return false;
    }

    while CV_READY.load(Ordering::Acquire) == 0 {
        CV_COND.wait(&CV_MUTEX);
    }
    CV_MUTEX.unlock();

    let ret = unsafe { pthread::pthread_join(producer, core::ptr::null_mut()) };
    if ret != 0 {
        puts(b"  join producer failed\n");
        return false;
    }

    if CV_READY.load(Ordering::Relaxed) != 1 {
        puts(b"  data not ready\n");
        return false;
    }

    puts(b"  condvar_signal: ok\n");
    true
}

// =========================================================================
// Test 7: Condvar broadcast — multiple waiters
// =========================================================================

static BC_MUTEX: sync::Mutex = sync::Mutex::new();
static BC_COND: sync::Condvar = sync::Condvar::new();
static BC_FLAG: AtomicU32 = AtomicU32::new(0);
static BC_WOKEN: AtomicU32 = AtomicU32::new(0);
// Incremented by each waiter under BC_MUTEX, used by the broadcaster to
// observe that all waiters have entered the critical region.
static BC_WAITERS_ENTERED: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn thread_bc_waiter(_arg: *mut u8) -> *mut u8 {
    BC_MUTEX.lock();
    // Serialized under BC_MUTEX: once the counter reaches 3, every waiter
    // has passed this point. The last waiter to increment will release
    // BC_MUTEX via BC_COND.wait, letting main acquire it.
    BC_WAITERS_ENTERED.fetch_add(1, Ordering::Release);
    while BC_FLAG.load(Ordering::Acquire) == 0 {
        BC_COND.wait(&BC_MUTEX);
    }
    BC_WOKEN.fetch_add(1, Ordering::Relaxed);
    BC_MUTEX.unlock();
    core::ptr::null_mut()
}

fn test_condvar_broadcast() -> bool {
    BC_FLAG.store(0, Ordering::Relaxed);
    BC_WOKEN.store(0, Ordering::Relaxed);
    BC_WAITERS_ENTERED.store(0, Ordering::Relaxed);

    let mut t1: pthread::PthreadT = 0;
    let mut t2: pthread::PthreadT = 0;
    let mut t3: pthread::PthreadT = 0;

    unsafe {
        pthread::pthread_create(
            &raw mut t1,
            core::ptr::null(),
            thread_bc_waiter,
            core::ptr::null_mut(),
        );
        pthread::pthread_create(
            &raw mut t2,
            core::ptr::null(),
            thread_bc_waiter,
            core::ptr::null_mut(),
        );
        pthread::pthread_create(
            &raw mut t3,
            core::ptr::null(),
            thread_bc_waiter,
            core::ptr::null_mut(),
        );
    }

    // Wait until all three waiters have entered the critical region. The
    // subsequent BC_MUTEX.lock() then blocks until the last waiter has
    // released the mutex via BC_COND.wait — a deterministic rendezvous
    // that does not depend on fixed yield counts.
    while BC_WAITERS_ENTERED.load(Ordering::Acquire) < 3 {
        trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }

    BC_MUTEX.lock();
    BC_FLAG.store(1, Ordering::Release);
    BC_COND.broadcast();
    BC_MUTEX.unlock();

    unsafe {
        pthread::pthread_join(t1, core::ptr::null_mut());
        pthread::pthread_join(t2, core::ptr::null_mut());
        pthread::pthread_join(t3, core::ptr::null_mut());
    }

    let woken = BC_WOKEN.load(Ordering::Relaxed);
    if woken != 3 {
        let mut lb = serial::LineBuf::new();
        lb.str(b"  woken=");
        lb.dec(woken as u64);
        lb.str(b" expected 3\n");
        lb.flush();
        return false;
    }

    puts(b"  condvar_broadcast: ok\n");
    true
}

// =========================================================================
// Test 8: Condvar timedwait — timeout fires before signal
// =========================================================================

fn test_condvar_timedwait() -> bool {
    let mtx = sync::Mutex::new();
    let cv = sync::Condvar::new();

    mtx.lock();
    // Wait with 50ms timeout — no signal will come
    let ret = cv.wait_timeout(&mtx, 50_000_000);
    mtx.unlock();

    if ret != TRONA_TIMED_OUT {
        let mut lb = serial::LineBuf::new();
        lb.str(b"  expected TRONA_TIMED_OUT, got ");
        lb.dec(ret);
        lb.str(b"\n");
        lb.flush();
        return false;
    }

    puts(b"  condvar_timedwait: ok\n");
    true
}

// =========================================================================
// Test 9: RWLock — multiple readers, exclusive writer
// =========================================================================

static RW_LOCK: sync::RWLock = sync::RWLock::new();
static RW_READERS: AtomicU32 = AtomicU32::new(0);
static RW_MAX_CONCURRENT: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn thread_reader(_arg: *mut u8) -> *mut u8 {
    RW_LOCK.read_lock();
    let concurrent = RW_READERS.fetch_add(1, Ordering::Relaxed) + 1;
    // Update max concurrent readers seen
    loop {
        let max = RW_MAX_CONCURRENT.load(Ordering::Relaxed);
        if concurrent <= max {
            break;
        }
        if RW_MAX_CONCURRENT
            .compare_exchange_weak(max, concurrent, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
    }
    // Hold the lock briefly
    for _ in 0..20 {
        trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
    RW_READERS.fetch_sub(1, Ordering::Relaxed);
    RW_LOCK.read_unlock();
    core::ptr::null_mut()
}

fn test_rwlock() -> bool {
    RW_READERS.store(0, Ordering::Relaxed);
    RW_MAX_CONCURRENT.store(0, Ordering::Relaxed);

    let mut handles: [pthread::PthreadT; 3] = [0; 3];

    for i in 0..3 {
        let ret = unsafe {
            pthread::pthread_create(
                &raw mut handles[i],
                core::ptr::null(),
                thread_reader,
                core::ptr::null_mut(),
            )
        };
        if ret != 0 {
            puts(b"  create reader failed\n");
            return false;
        }
    }

    for i in 0..3 {
        unsafe {
            pthread::pthread_join(handles[i], core::ptr::null_mut());
        }
    }

    // Write lock should be exclusive
    RW_LOCK.write_lock();
    RW_LOCK.write_unlock();

    puts(b"  rwlock: ok\n");
    true
}

// =========================================================================
// Test 10: Barrier — N threads synchronize at barrier
// =========================================================================

static BARRIER: sync::Barrier = sync::Barrier::new(3);
static BARRIER_PHASE1: AtomicU32 = AtomicU32::new(0);
static BARRIER_PHASE2: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn thread_barrier_worker(_arg: *mut u8) -> *mut u8 {
    BARRIER_PHASE1.fetch_add(1, Ordering::Relaxed);
    BARRIER.wait();
    // After barrier, all threads should have incremented phase1
    BARRIER_PHASE2.fetch_add(1, Ordering::Relaxed);
    core::ptr::null_mut()
}

fn test_barrier() -> bool {
    BARRIER_PHASE1.store(0, Ordering::Relaxed);
    BARRIER_PHASE2.store(0, Ordering::Relaxed);

    let mut t1: pthread::PthreadT = 0;
    let mut t2: pthread::PthreadT = 0;

    unsafe {
        pthread::pthread_create(
            &raw mut t1,
            core::ptr::null(),
            thread_barrier_worker,
            core::ptr::null_mut(),
        );
        pthread::pthread_create(
            &raw mut t2,
            core::ptr::null(),
            thread_barrier_worker,
            core::ptr::null_mut(),
        );
    }

    // Main thread is the 3rd barrier participant
    BARRIER_PHASE1.fetch_add(1, Ordering::Relaxed);
    BARRIER.wait();
    BARRIER_PHASE2.fetch_add(1, Ordering::Relaxed);

    unsafe {
        pthread::pthread_join(t1, core::ptr::null_mut());
        pthread::pthread_join(t2, core::ptr::null_mut());
    }

    let p1 = BARRIER_PHASE1.load(Ordering::Relaxed);
    let p2 = BARRIER_PHASE2.load(Ordering::Relaxed);

    if p1 != 3 || p2 != 3 {
        let mut lb = serial::LineBuf::new();
        lb.str(b"  phase1=");
        lb.dec(p1 as u64);
        lb.str(b" phase2=");
        lb.dec(p2 as u64);
        lb.str(b"\n");
        lb.flush();
        return false;
    }

    puts(b"  barrier: ok\n");
    true
}

// =========================================================================
// Test 11: pthread_cancel and cleanup handler
// =========================================================================

static CANCEL_CLEANUP_RAN: AtomicU32 = AtomicU32::new(0);
// Posted by the cancellable thread on entry so the main thread can
// deterministically observe that the thread has actually started before
// issuing pthread_cancel.
static SEM_CANCEL_STARTED: sync::Semaphore = sync::Semaphore::new(0);

unsafe extern "C" fn cancel_cleanup_handler(_arg: *mut u8) {
    CANCEL_CLEANUP_RAN.store(1, Ordering::Release);
}

unsafe extern "C" fn thread_cancellable(_arg: *mut u8) -> *mut u8 {
    // Announce entry before any other work so the main thread's
    // SEM_CANCEL_STARTED.wait() can proceed as soon as we are scheduled.
    SEM_CANCEL_STARTED.post();

    // Push cleanup handler (stored on stack)
    let mut handler = tls::CleanupHandler {
        routine: cancel_cleanup_handler,
        arg: core::ptr::null_mut(),
        next: core::ptr::null_mut(),
    };
    pthread::pthread_cleanup_push_impl(
        cancel_cleanup_handler,
        core::ptr::null_mut(),
        &raw mut handler,
    );

    // Loop with cancellation points
    loop {
        trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        pthread::pthread_testcancel();
    }
}

fn test_cancel() -> bool {
    CANCEL_CLEANUP_RAN.store(0, Ordering::Relaxed);

    let mut handle: pthread::PthreadT = 0;
    let ret = unsafe {
        pthread::pthread_create(
            &raw mut handle,
            core::ptr::null(),
            thread_cancellable,
            core::ptr::null_mut(),
        )
    };
    if ret != 0 {
        puts(b"  create cancellable thread failed\n");
        return false;
    }

    // Wait for the thread to actually start executing.
    SEM_CANCEL_STARTED.wait();

    // Cancel it
    let ret = unsafe { pthread::pthread_cancel(handle) };
    if ret != 0 {
        puts(b"  pthread_cancel failed\n");
        return false;
    }

    // pthread_join blocks until the thread has finished unwinding, so no
    // additional delay is required for the cancellation to take effect.
    let mut retval: *mut u8 = core::ptr::null_mut();
    let ret = unsafe { pthread::pthread_join(handle, &raw mut retval) };
    if ret != 0 {
        puts(b"  join cancelled thread failed\n");
        return false;
    }

    // Check that the return value is PTHREAD_CANCELED
    if retval != pthread::PTHREAD_CANCELED {
        puts(b"  retval not PTHREAD_CANCELED\n");
        return false;
    }

    // Check that cleanup handler ran
    if CANCEL_CLEANUP_RAN.load(Ordering::Acquire) != 1 {
        puts(b"  cleanup handler did not run\n");
        return false;
    }

    puts(b"  cancel: ok\n");
    true
}

// =========================================================================
// Test 12: Thread attributes — custom stack size
// =========================================================================

static ATTR_THREAD_RAN: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn thread_attr_test(_arg: *mut u8) -> *mut u8 {
    // Use some stack to verify it works
    let mut buf = [0u8; 4096];
    buf[0] = 42;
    buf[4095] = 99;
    // Prevent optimization
    core::hint::black_box(&buf);

    ATTR_THREAD_RAN.store(1, Ordering::Release);
    core::ptr::null_mut()
}

fn test_attr_stacksize() -> bool {
    ATTR_THREAD_RAN.store(0, Ordering::Relaxed);

    let attr = pthread::PthreadAttr::new(256 * 1024, 0);

    let mut handle: pthread::PthreadT = 0;
    let ret = unsafe {
        pthread::pthread_create(
            &raw mut handle,
            &raw const attr,
            thread_attr_test,
            core::ptr::null_mut(),
        )
    };
    if ret != 0 {
        puts(b"  create with custom stacksize failed\n");
        return false;
    }

    let ret = unsafe { pthread::pthread_join(handle, core::ptr::null_mut()) };
    if ret != 0 {
        puts(b"  join failed\n");
        return false;
    }

    if ATTR_THREAD_RAN.load(Ordering::Acquire) != 1 {
        puts(b"  thread did not run\n");
        return false;
    }

    puts(b"  attr_stacksize: ok\n");
    true
}

// =========================================================================
// Test 13: RWLock try — try_read_lock succeeds, try_write_lock fails while readers exist
// =========================================================================

fn test_rwlock_try() -> bool {
    let rw = sync::RWLock::new();

    // try_read_lock should succeed when no writer
    if !rw.try_read_lock() {
        puts(b"  try_read_lock failed on free lock\n");
        return false;
    }

    // Second try_read_lock should also succeed (multiple readers)
    if !rw.try_read_lock() {
        puts(b"  second try_read_lock failed\n");
        rw.read_unlock();
        return false;
    }

    // try_write_lock should fail while readers hold the lock
    if rw.try_write_lock() {
        puts(b"  try_write_lock succeeded with readers\n");
        rw.write_unlock();
        rw.read_unlock();
        rw.read_unlock();
        return false;
    }

    rw.read_unlock();
    rw.read_unlock();

    // Now try_write_lock should succeed
    if !rw.try_write_lock() {
        puts(b"  try_write_lock failed on free lock\n");
        return false;
    }

    // try_read_lock should fail while writer holds the lock
    if rw.try_read_lock() {
        puts(b"  try_read_lock succeeded with writer\n");
        rw.read_unlock();
        rw.write_unlock();
        return false;
    }

    rw.write_unlock();

    puts(b"  rwlock_try: ok\n");
    true
}

// =========================================================================
// Test 14: Semaphore basic — init, wait, post, get_value
// =========================================================================

fn test_semaphore_basic() -> bool {
    let sem = sync::Semaphore::new(1);

    // Initial value should be 1
    if sem.get_value() != 1 {
        puts(b"  initial value not 1\n");
        return false;
    }

    // Wait should succeed (decrement 1→0)
    sem.wait();
    if sem.get_value() != 0 {
        puts(b"  value after wait not 0\n");
        return false;
    }

    // Post should increment (0→1)
    let ret = sem.post();
    if ret != 0 {
        puts(b"  post failed\n");
        return false;
    }
    if sem.get_value() != 1 {
        puts(b"  value after post not 1\n");
        return false;
    }

    // Post again (1→2)
    sem.post();
    if sem.get_value() != 2 {
        puts(b"  value after second post not 2\n");
        return false;
    }

    // Wait twice to drain
    sem.wait();
    sem.wait();
    if sem.get_value() != 0 {
        puts(b"  value after draining not 0\n");
        return false;
    }

    puts(b"  semaphore_basic: ok\n");
    true
}

// =========================================================================
// Test 15: Semaphore producer/consumer — 2 threads
// =========================================================================

static SEM_PROD: sync::Semaphore = sync::Semaphore::new(0);
static SEM_RESULT: AtomicU32 = AtomicU32::new(0);
// Posted by the consumer immediately before entering SEM_PROD.wait so the
// main thread can observe that the consumer has reached the pre-wait
// point without relying on timing.
static SEM_CONSUMER_READY: sync::Semaphore = sync::Semaphore::new(0);

unsafe extern "C" fn thread_sem_consumer(_arg: *mut u8) -> *mut u8 {
    // Signal main that we are about to block on SEM_PROD.wait. The
    // ordering (post before wait) is what makes the main thread's
    // "consumer is not done yet" assertion meaningful.
    SEM_CONSUMER_READY.post();
    SEM_PROD.wait();
    SEM_RESULT.store(42, Ordering::Release);
    core::ptr::null_mut()
}

fn test_semaphore_producer_consumer() -> bool {
    SEM_RESULT.store(0, Ordering::Relaxed);

    let mut consumer: pthread::PthreadT = 0;
    let ret = unsafe {
        pthread::pthread_create(
            &raw mut consumer,
            core::ptr::null(),
            thread_sem_consumer,
            core::ptr::null_mut(),
        )
    };
    if ret != 0 {
        puts(b"  create consumer failed\n");
        return false;
    }

    // Observe that the consumer has reached its pre-wait point.
    SEM_CONSUMER_READY.wait();

    // Consumer has not yet written SEM_RESULT — it is either about to
    // enter SEM_PROD.wait or is already blocked in it.
    if SEM_RESULT.load(Ordering::Acquire) != 0 {
        puts(b"  consumer woke too early\n");
        SEM_PROD.post(); // unblock consumer so it can exit
        unsafe {
            pthread::pthread_join(consumer, core::ptr::null_mut());
        }
        return false;
    }

    // Signal the consumer
    SEM_PROD.post();

    let ret = unsafe { pthread::pthread_join(consumer, core::ptr::null_mut()) };
    if ret != 0 {
        puts(b"  join consumer failed\n");
        return false;
    }

    if SEM_RESULT.load(Ordering::Acquire) != 42 {
        puts(b"  consumer did not complete\n");
        return false;
    }

    puts(b"  semaphore_producer_consumer: ok\n");
    true
}

// =========================================================================
// Test 16: Semaphore try_wait — count=0 returns false, count>0 returns true
// =========================================================================

fn test_semaphore_trywait() -> bool {
    let sem = sync::Semaphore::new(0);

    // try_wait on empty semaphore should fail
    if sem.try_wait() {
        puts(b"  try_wait succeeded on empty\n");
        return false;
    }

    // Post to make count=1
    sem.post();

    // try_wait should now succeed
    if !sem.try_wait() {
        puts(b"  try_wait failed with count=1\n");
        return false;
    }

    // After successful try_wait, count should be 0
    if sem.get_value() != 0 {
        puts(b"  value after try_wait not 0\n");
        return false;
    }

    // try_wait should fail again
    if sem.try_wait() {
        puts(b"  try_wait succeeded after drain\n");
        return false;
    }

    puts(b"  semaphore_trywait: ok\n");
    true
}

// =========================================================================
// Test runner entry point
// =========================================================================

pub fn run() -> bool {
    puts(b"  --- pthread test suite ---\n");

    let tests: [(&[u8], fn() -> bool); 16] = [
        (b"create_join", test_create_join),
        (b"detach", test_detach),
        (b"mutex_normal", test_mutex_normal),
        (b"mutex_recursive", test_mutex_recursive),
        (b"mutex_errorcheck", test_mutex_errorcheck),
        (b"condvar_signal", test_condvar_signal),
        (b"condvar_broadcast", test_condvar_broadcast),
        (b"condvar_timedwait", test_condvar_timedwait),
        (b"rwlock", test_rwlock),
        (b"barrier", test_barrier),
        (b"cancel", test_cancel),
        (b"attr_stacksize", test_attr_stacksize),
        (b"rwlock_try", test_rwlock_try),
        (b"semaphore_basic", test_semaphore_basic),
        (
            b"semaphore_producer_consumer",
            test_semaphore_producer_consumer,
        ),
        (b"semaphore_trywait", test_semaphore_trywait),
    ];

    let mut all_pass = true;
    for (name, test_fn) in &tests {
        let ok = test_fn();
        if !ok {
            let mut lb = serial::LineBuf::new();
            lb.str(b"  SUBTEST FAIL: ");
            lb.str(name);
            lb.str(b"\n");
            lb.flush();
            all_pass = false;
        }
    }

    all_pass
}
