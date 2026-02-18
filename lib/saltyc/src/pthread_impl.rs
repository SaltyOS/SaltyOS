//! POSIX threads C ABI wrappers
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides standard pthread C functions by delegating to libsalty's Rust
//! implementations. Covers thread lifecycle, mutexes, condition variables,
//! reader-writer locks, barriers, and once-initialization.

use crate::errno;

// =========================================================================
// Opaque types matching POSIX sizes (all backed by libsalty's Rust structs)
// =========================================================================

/// pthread_t is an opaque pointer (same as libsalty's PthreadT).
pub type PthreadT = *mut u8;

/// pthread_mutex_t wraps libsalty's sync::Mutex (single AtomicU32 = 4 bytes).
/// Padded to 8 bytes for alignment.
#[repr(C)]
pub struct PthreadMutexT {
    inner: [u8; 8],
}

/// pthread_cond_t wraps libsalty's sync::Condvar (single AtomicU32 = 4 bytes).
/// Padded to 8 bytes for alignment.
#[repr(C)]
pub struct PthreadCondT {
    inner: [u8; 8],
}

/// pthread_rwlock_t wraps libsalty's sync::RWLock (two AtomicU32 = 8 bytes).
/// Padded to 16 bytes for alignment.
#[repr(C)]
pub struct PthreadRwlockT {
    inner: [u8; 16],
}

/// pthread_barrier_t wraps libsalty's sync::Barrier (u32 + 2×AtomicU32 = 12 bytes).
/// Padded to 16 bytes for alignment.
#[repr(C)]
pub struct PthreadBarrierT {
    inner: [u8; 16],
}

/// pthread_once_t wraps libsalty's sync::Once (single AtomicU32 = 4 bytes).
#[repr(C)]
pub struct PthreadOnceT {
    inner: [u8; 8],
}

/// pthread_attr_t (placeholder — attributes not yet implemented).
#[repr(C)]
pub struct PthreadAttrT {
    _unused: u64,
}

/// pthread_mutexattr_t (placeholder).
#[repr(C)]
pub struct PthreadMutexattrT {
    _unused: u32,
}

/// pthread_condattr_t (placeholder).
#[repr(C)]
pub struct PthreadCondattrT {
    _unused: u32,
}

/// pthread_rwlockattr_t (placeholder).
#[repr(C)]
pub struct PthreadRwlockattrT {
    _unused: u32,
}

/// pthread_barrierattr_t (placeholder).
#[repr(C)]
pub struct PthreadBarrierattrT {
    _unused: u32,
}

// =========================================================================
// Thread lifecycle
// =========================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_create(
    thread: *mut PthreadT,
    _attr: *const PthreadAttrT,
    start_routine: unsafe extern "C" fn(*mut u8) -> *mut u8,
    arg: *mut u8,
) -> i32 {
    unsafe {
        let ret = salty::pthread::pthread_create(
            thread as *mut salty::pthread::PthreadT,
            start_routine,
            arg,
        );
        if ret != 0 { errno::EAGAIN } else { 0 }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_join(thread: PthreadT, retval: *mut *mut u8) -> i32 {
    unsafe {
        let ret = salty::pthread::pthread_join(
            thread as salty::pthread::PthreadT,
            retval,
        );
        if ret != 0 { errno::EINVAL } else { 0 }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_exit(retval: *mut u8) -> ! {
    unsafe { salty::pthread::pthread_exit(retval) }
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_self() -> PthreadT {
    salty::pthread::pthread_self() as PthreadT
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_detach(thread: PthreadT) -> i32 {
    unsafe {
        let ret = salty::pthread::pthread_detach(thread as salty::pthread::PthreadT);
        if ret != 0 { errno::EINVAL } else { 0 }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_equal(t1: PthreadT, t2: PthreadT) -> i32 {
    if t1 == t2 { 1 } else { 0 }
}

// =========================================================================
// Mutex
// =========================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_init(
    mutex: *mut PthreadMutexT,
    _attr: *const PthreadMutexattrT,
) -> i32 {
    if mutex.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let m = &mut *(mutex as *mut salty::sync::Mutex);
        core::ptr::write(m, salty::sync::Mutex::new());
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut PthreadMutexT) -> i32 {
    if mutex.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let m = &*(mutex as *const salty::sync::Mutex);
        m.lock();
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut PthreadMutexT) -> i32 {
    if mutex.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let m = &*(mutex as *const salty::sync::Mutex);
        if m.try_lock() { 0 } else { errno::EBUSY }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut PthreadMutexT) -> i32 {
    if mutex.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let m = &*(mutex as *const salty::sync::Mutex);
        m.unlock();
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_destroy(_mutex: *mut PthreadMutexT) -> i32 {
    0
}

// =========================================================================
// Condition variable
// =========================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_init(
    cond: *mut PthreadCondT,
    _attr: *const PthreadCondattrT,
) -> i32 {
    if cond.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let c = &mut *(cond as *mut salty::sync::Condvar);
        core::ptr::write(c, salty::sync::Condvar::new());
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_wait(
    cond: *mut PthreadCondT,
    mutex: *mut PthreadMutexT,
) -> i32 {
    if cond.is_null() || mutex.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let c = &*(cond as *const salty::sync::Condvar);
        let m = &*(mutex as *const salty::sync::Mutex);
        c.wait(m);
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut PthreadCondT) -> i32 {
    if cond.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let c = &*(cond as *const salty::sync::Condvar);
        c.signal();
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut PthreadCondT) -> i32 {
    if cond.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let c = &*(cond as *const salty::sync::Condvar);
        c.broadcast();
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_destroy(_cond: *mut PthreadCondT) -> i32 {
    0
}

// =========================================================================
// Reader-writer lock
// =========================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_init(
    rwlock: *mut PthreadRwlockT,
    _attr: *const PthreadRwlockattrT,
) -> i32 {
    if rwlock.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let rw = &mut *(rwlock as *mut salty::sync::RWLock);
        core::ptr::write(rw, salty::sync::RWLock::new());
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_rdlock(rwlock: *mut PthreadRwlockT) -> i32 {
    if rwlock.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let rw = &*(rwlock as *const salty::sync::RWLock);
        rw.read_lock();
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_wrlock(rwlock: *mut PthreadRwlockT) -> i32 {
    if rwlock.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let rw = &*(rwlock as *const salty::sync::RWLock);
        rw.write_lock();
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_unlock(rwlock: *mut PthreadRwlockT) -> i32 {
    if rwlock.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        // POSIX says unlock works for both read and write locks.
        // RWLock is #[repr(C)] with `state: AtomicU32` as first field.
        // Bit 31 is the writer flag.
        let rw = &*(rwlock as *const salty::sync::RWLock);
        let state_ptr = rwlock as *const core::sync::atomic::AtomicU32;
        let state = (*state_ptr).load(core::sync::atomic::Ordering::Relaxed);
        if state & (1 << 31) != 0 {
            rw.write_unlock();
        } else {
            rw.read_unlock();
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_destroy(_rwlock: *mut PthreadRwlockT) -> i32 {
    0
}

// =========================================================================
// Barrier
// =========================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrier_init(
    barrier: *mut PthreadBarrierT,
    _attr: *const PthreadBarrierattrT,
    count: u32,
) -> i32 {
    if barrier.is_null() || count == 0 {
        return errno::EINVAL;
    }
    unsafe {
        let b = &mut *(barrier as *mut salty::sync::Barrier);
        core::ptr::write(b, salty::sync::Barrier::new(count));
    }
    0
}

/// PTHREAD_BARRIER_SERIAL_THREAD — returned by exactly one thread per barrier wait.
const PTHREAD_BARRIER_SERIAL_THREAD: i32 = -1;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrier_wait(barrier: *mut PthreadBarrierT) -> i32 {
    if barrier.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let b = &*(barrier as *const salty::sync::Barrier);
        if b.wait() {
            PTHREAD_BARRIER_SERIAL_THREAD
        } else {
            0
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrier_destroy(_barrier: *mut PthreadBarrierT) -> i32 {
    0
}

// =========================================================================
// Once
// =========================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_once(
    once_control: *mut PthreadOnceT,
    init_routine: fn(),
) -> i32 {
    if once_control.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let o = &*(once_control as *const salty::sync::Once);
        o.call_once(init_routine);
    }
    0
}

// =========================================================================
// Stubs for attr functions (minimal no-op implementations)
// =========================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_init(_attr: *mut PthreadAttrT) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_destroy(_attr: *mut PthreadAttrT) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setdetachstate(
    _attr: *mut PthreadAttrT,
    _detachstate: i32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setstacksize(
    _attr: *mut PthreadAttrT,
    _stacksize: usize,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_init(_attr: *mut PthreadMutexattrT) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_destroy(_attr: *mut PthreadMutexattrT) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_settype(
    _attr: *mut PthreadMutexattrT,
    _kind: i32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_condattr_init(_attr: *mut PthreadCondattrT) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_condattr_destroy(_attr: *mut PthreadCondattrT) -> i32 {
    0
}
