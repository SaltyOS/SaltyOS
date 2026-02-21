//! POSIX threads C ABI wrappers
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides standard pthread C functions by delegating to libsalty's Rust
//! implementations. Covers thread lifecycle, mutexes, condition variables,
//! reader-writer locks, barriers, and once-initialization.

use crate::errno;

/// Timespec for timed operations (matches time_impl.rs layout)
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// Convert an absolute timespec to a relative timeout in nanoseconds.
/// Returns 0 if the deadline has already passed.
fn timespec_to_relative_ns(abstime: &Timespec) -> u64 {
    let now = salty::syscall::syscall(salty::consts::SYS_CLOCK_GETTIME, 0, 0, 0, 0, 0, 0);
    let now_ns = now.value;
    let target_ns = (abstime.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(abstime.tv_nsec as u64);
    target_ns.saturating_sub(now_ns)
}

/// Validate a POSIX timespec: tv_sec must be non-negative, tv_nsec in [0, 999_999_999].
#[inline]
fn validate_timespec(ts: &Timespec) -> bool {
    ts.tv_sec >= 0 && ts.tv_nsec >= 0 && ts.tv_nsec < 1_000_000_000
}

// =========================================================================
// Opaque types matching POSIX sizes (all backed by libsalty's Rust structs)
// =========================================================================

/// pthread_t is an opaque pointer (same as libsalty's PthreadT).
pub type PthreadT = *mut u8;

/// pthread_mutex_t wraps libsalty's sync::Mutex or sync::TypedMutex.
/// 32 bytes: first 24 bytes for the mutex data, byte 24 = kind (0=NORMAL, 1=RECURSIVE, 2=ERRORCHECK).
#[repr(C, align(8))]
pub struct PthreadMutexT {
    inner: [u8; 32],
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

/// pthread_attr_t wraps libsalty's PthreadAttr.
#[repr(C)]
pub struct PthreadAttrT {
    /// Stack size in bytes (0 = default)
    stack_size: u64,
    /// Detach state: 0=joinable, 1=detached
    detach_state: u32,
    _pad: u32,
}

/// pthread_mutexattr_t stores mutex type (kind).
#[repr(C)]
pub struct PthreadMutexattrT {
    kind: i32,
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
    attr: *const PthreadAttrT,
    start_routine: unsafe extern "C" fn(*mut u8) -> *mut u8,
    arg: *mut u8,
) -> i32 {
    unsafe {
        let ret = salty::pthread::pthread_create(
            thread as *mut salty::pthread::PthreadT,
            attr as *const salty::pthread::PthreadAttr,
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

/// POSIX mutex type constants
const PTHREAD_MUTEX_NORMAL: i32 = 0;
const PTHREAD_MUTEX_RECURSIVE: i32 = 1;
const PTHREAD_MUTEX_ERRORCHECK: i32 = 2;

/// Offset of the kind byte within PthreadMutexT (byte 24)
const MUTEX_KIND_OFFSET: usize = 24;

/// Read the kind byte from a PthreadMutexT
#[inline]
unsafe fn mutex_kind(mutex: *const PthreadMutexT) -> u8 {
    unsafe { *((mutex as *const u8).add(MUTEX_KIND_OFFSET)) }
}

/// Write the kind byte into a PthreadMutexT
#[inline]
unsafe fn set_mutex_kind(mutex: *mut PthreadMutexT, kind: u8) {
    unsafe { *((mutex as *mut u8).add(MUTEX_KIND_OFFSET)) = kind; }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_init(
    mutex: *mut PthreadMutexT,
    attr: *const PthreadMutexattrT,
) -> i32 {
    if mutex.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        // Zero the entire structure first
        core::ptr::write_bytes(mutex as *mut u8, 0, core::mem::size_of::<PthreadMutexT>());

        let kind = if !attr.is_null() { (*attr).kind } else { 0 };
        if kind == PTHREAD_MUTEX_NORMAL || kind == 0 {
            let m = &mut *(mutex as *mut salty::sync::Mutex);
            core::ptr::write(m, salty::sync::Mutex::new());
            set_mutex_kind(mutex, 0);
        } else {
            let mt = kind as u8;
            let tm = &mut *(mutex as *mut salty::sync::TypedMutex);
            core::ptr::write(tm, salty::sync::TypedMutex::new(mt));
            set_mutex_kind(mutex, mt);
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut PthreadMutexT) -> i32 {
    if mutex.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        if mutex_kind(mutex) == 0 {
            let m = &*(mutex as *const salty::sync::Mutex);
            m.lock();
            0
        } else {
            let tm = &*(mutex as *const salty::sync::TypedMutex);
            tm.lock()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut PthreadMutexT) -> i32 {
    if mutex.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        if mutex_kind(mutex) == 0 {
            let m = &*(mutex as *const salty::sync::Mutex);
            if m.try_lock() { 0 } else { errno::EBUSY }
        } else {
            let tm = &*(mutex as *const salty::sync::TypedMutex);
            tm.try_lock()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut PthreadMutexT) -> i32 {
    if mutex.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        if mutex_kind(mutex) == 0 {
            let m = &*(mutex as *const salty::sync::Mutex);
            m.unlock();
            0
        } else {
            let tm = &*(mutex as *const salty::sync::TypedMutex);
            tm.unlock()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_timedlock(
    mutex: *mut PthreadMutexT,
    abstime: *const Timespec,
) -> i32 {
    if mutex.is_null() || abstime.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        if !validate_timespec(&*abstime) {
            return errno::EINVAL;
        }
        let kind = mutex_kind(mutex);
        if kind == 0 {
            // NORMAL mutex
            let m = &*(mutex as *const salty::sync::Mutex);
            if m.lock_timeout(timespec_to_relative_ns(&*abstime)) { 0 } else { errno::ETIMEDOUT }
        } else {
            // Typed mutex
            let tm = &*(mutex as *const salty::sync::TypedMutex);
            let ret = tm.lock_timeout(timespec_to_relative_ns(&*abstime));
            if ret == 0 { 0 } else { ret }
        }
    }
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
        let kind = mutex_kind(mutex);
        if kind == 0 {
            let m = &*(mutex as *const salty::sync::Mutex);
            c.wait(m);
            0
        } else {
            let tm = &*(mutex as *const salty::sync::TypedMutex);
            c.wait_typed(tm)
        }
    }
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
pub unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut PthreadCondT,
    mutex: *mut PthreadMutexT,
    abstime: *const Timespec,
) -> i32 {
    if cond.is_null() || mutex.is_null() || abstime.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        if !validate_timespec(&*abstime) {
            return errno::EINVAL;
        }
        let c = &*(cond as *const salty::sync::Condvar);
        let kind = mutex_kind(mutex);
        let timeout_ns = timespec_to_relative_ns(&*abstime);
        if timeout_ns == 0 {
            return errno::ETIMEDOUT;
        }
        if kind == 0 {
            let m = &*(mutex as *const salty::sync::Mutex);
            let ret = c.wait_timeout(m, timeout_ns);
            if ret == 110 {
                errno::ETIMEDOUT
            } else {
                ret
            }
        } else {
            let tm = &*(mutex as *const salty::sync::TypedMutex);
            let ret = c.wait_timeout_typed(tm, timeout_ns);
            if ret == 110 {
                errno::ETIMEDOUT
            } else {
                ret
            }
        }
    }
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_tryrdlock(rwlock: *mut PthreadRwlockT) -> i32 {
    if rwlock.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let rw = &*(rwlock as *const salty::sync::RWLock);
        if rw.try_read_lock() { 0 } else { errno::EBUSY }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_trywrlock(rwlock: *mut PthreadRwlockT) -> i32 {
    if rwlock.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let rw = &*(rwlock as *const salty::sync::RWLock);
        if rw.try_write_lock() { 0 } else { errno::EBUSY }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_timedrdlock(
    rwlock: *mut PthreadRwlockT,
    abstime: *const Timespec,
) -> i32 {
    if rwlock.is_null() || abstime.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        if !validate_timespec(&*abstime) {
            return errno::EINVAL;
        }
        let rw = &*(rwlock as *const salty::sync::RWLock);
        let timeout_ns = timespec_to_relative_ns(&*abstime);
        if timeout_ns == 0 {
            return if rw.try_read_lock() { 0 } else { errno::ETIMEDOUT };
        }
        if rw.read_lock_timeout(timeout_ns) { 0 } else { errno::ETIMEDOUT }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_timedwrlock(
    rwlock: *mut PthreadRwlockT,
    abstime: *const Timespec,
) -> i32 {
    if rwlock.is_null() || abstime.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        if !validate_timespec(&*abstime) {
            return errno::EINVAL;
        }
        let rw = &*(rwlock as *const salty::sync::RWLock);
        let timeout_ns = timespec_to_relative_ns(&*abstime);
        if timeout_ns == 0 {
            return if rw.try_write_lock() { 0 } else { errno::ETIMEDOUT };
        }
        if rw.write_lock_timeout(timeout_ns) { 0 } else { errno::ETIMEDOUT }
    }
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
    init_routine: unsafe extern "C" fn(),
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

/// Detach state constants
const PTHREAD_CREATE_JOINABLE: i32 = 0;
const PTHREAD_CREATE_DETACHED: i32 = 1;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_init(attr: *mut PthreadAttrT) -> i32 {
    if attr.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        (*attr).stack_size = 0; // 0 = default
        (*attr).detach_state = 0; // joinable
        (*attr)._pad = 0;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_destroy(_attr: *mut PthreadAttrT) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setdetachstate(
    attr: *mut PthreadAttrT,
    detachstate: i32,
) -> i32 {
    if attr.is_null() {
        return errno::EINVAL;
    }
    if detachstate != PTHREAD_CREATE_JOINABLE && detachstate != PTHREAD_CREATE_DETACHED {
        return errno::EINVAL;
    }
    unsafe { (*attr).detach_state = detachstate as u32; }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getdetachstate(
    attr: *const PthreadAttrT,
    detachstate: *mut i32,
) -> i32 {
    if attr.is_null() || detachstate.is_null() {
        return errno::EINVAL;
    }
    unsafe { *detachstate = (*attr).detach_state as i32; }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setstacksize(
    attr: *mut PthreadAttrT,
    stacksize: usize,
) -> i32 {
    if attr.is_null() {
        return errno::EINVAL;
    }
    // Minimum stack size: 16 KiB
    if stacksize < 16384 {
        return errno::EINVAL;
    }
    unsafe { (*attr).stack_size = stacksize as u64; }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getstacksize(
    attr: *const PthreadAttrT,
    stacksize: *mut usize,
) -> i32 {
    if attr.is_null() || stacksize.is_null() {
        return errno::EINVAL;
    }
    unsafe {
        let sz = (*attr).stack_size;
        *stacksize = if sz == 0 { 2 * 1024 * 1024 } else { sz as usize };
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_init(attr: *mut PthreadMutexattrT) -> i32 {
    if attr.is_null() {
        return errno::EINVAL;
    }
    unsafe { (*attr).kind = PTHREAD_MUTEX_NORMAL; }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_destroy(_attr: *mut PthreadMutexattrT) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_settype(
    attr: *mut PthreadMutexattrT,
    kind: i32,
) -> i32 {
    if attr.is_null() {
        return errno::EINVAL;
    }
    if kind < 0 || kind > 2 {
        return errno::EINVAL;
    }
    unsafe { (*attr).kind = kind; }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_gettype(
    attr: *const PthreadMutexattrT,
    kind: *mut i32,
) -> i32 {
    if attr.is_null() || kind.is_null() {
        return errno::EINVAL;
    }
    unsafe { *kind = (*attr).kind; }
    0
}

// =========================================================================
// Cancellation
// =========================================================================

/// PTHREAD_CANCELED sentinel value
const PTHREAD_CANCELED: *mut u8 = usize::MAX as *mut u8;

/// Cancel state constants
const PTHREAD_CANCEL_ENABLE: i32 = 0;
const PTHREAD_CANCEL_DISABLE: i32 = 1;

/// Cancel type constants
const PTHREAD_CANCEL_DEFERRED: i32 = 0;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cancel(thread: PthreadT) -> i32 {
    unsafe {
        let ret = salty::pthread::pthread_cancel(thread as salty::pthread::PthreadT);
        if ret != 0 { errno::ESRCH } else { 0 }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_setcancelstate(state: i32, oldstate: *mut i32) -> i32 {
    if state != PTHREAD_CANCEL_ENABLE && state != PTHREAD_CANCEL_DISABLE {
        return errno::EINVAL;
    }
    unsafe {
        let ret = salty::pthread::pthread_setcancelstate(state, oldstate);
        if ret != 0 { return errno::EINVAL; }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_setcanceltype(ctype: i32, oldtype: *mut i32) -> i32 {
    if ctype != PTHREAD_CANCEL_DEFERRED {
        return errno::EINVAL;
    }
    unsafe {
        let ret = salty::pthread::pthread_setcanceltype(ctype, oldtype);
        if ret != 0 { return errno::EINVAL; }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_testcancel() {
    unsafe { salty::pthread::pthread_testcancel(); }
}

/// Cleanup handler node (stack-allocated by caller).
#[repr(C)]
pub struct PthreadCleanupHandler {
    routine: unsafe extern "C" fn(*mut u8),
    arg: *mut u8,
    next: *mut PthreadCleanupHandler,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __pthread_cleanup_push(
    handler: *mut PthreadCleanupHandler,
    routine: unsafe extern "C" fn(*mut u8),
    arg: *mut u8,
) {
    unsafe {
        salty::pthread::pthread_cleanup_push_impl(
            routine,
            arg,
            handler as *mut salty::tls::CleanupHandler,
        );
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __pthread_cleanup_pop(
    _handler: *mut PthreadCleanupHandler,
    execute: i32,
) {
    unsafe {
        salty::pthread::pthread_cleanup_pop_impl(execute);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_condattr_init(_attr: *mut PthreadCondattrT) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_condattr_destroy(_attr: *mut PthreadCondattrT) -> i32 {
    0
}
