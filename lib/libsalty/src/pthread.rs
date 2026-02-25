//! POSIX threads (pthreads) implementation
//!
//! Provides pthread_create, pthread_join, pthread_exit, pthread_self,
//! pthread_detach, and pthread_cancel on top of SaltyOS kernel primitives
//! (TCB, SchedContext, futex, TLS).
//!
//! ## Handle lifetime safety
//!
//! `pthread_t` is a pointer into a global `ThreadControl` pool (not a pointer
//! to the thread's stack-resident TLS block). This eliminates use-after-free
//! on double-join, enables self-join detection, and makes detached-thread
//! cleanup safe.
//!
//! ## State machine
//!
//! ```text
//! UNUSED ──create──► RUNNING ──exit(joinable)──► EXITED ──join──► JOINED ──cleanup──► UNUSED
//!                       │                          │
//!                       ├──detach──► DETACHED      └──detach──► cleanup ──► UNUSED
//!                       │               │
//!                       │               └──exit──► DETACHED_EXITED ──reap──► UNUSED
//! ```
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::invoke;
use crate::ipc;
use crate::serial;
use crate::slot_alloc;
use crate::syscall::{futex_wait, futex_wake};
use crate::tls::{self, ThreadLocalBlock};
use crate::types::*;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Maximum concurrent threads per process (slot 0 = main thread)
const MAX_THREADS: usize = 64;

/// ThreadControl state constants
const TC_UNUSED: u32 = 0;
const TC_RUNNING: u32 = 1;
const TC_EXITED: u32 = 2;
const TC_JOINED: u32 = 3;
const TC_DETACHED: u32 = 4;
const TC_DETACHED_EXITED: u32 = 5;

/// Default thread stack size: 2 MiB
const DEFAULT_STACK_SIZE: u64 = 2 * 1024 * 1024;

/// Thread attributes for pthread_create.
#[repr(C)]
pub struct PthreadAttr {
    /// Stack size in bytes (0 = default 2 MiB)
    pub stack_size: u64,
    /// Detach state: 0 = joinable, 1 = detached
    pub detach_state: u32,
    /// Padding for alignment
    _pad: u32,
}

impl PthreadAttr {
    pub const fn default() -> Self {
        PthreadAttr {
            stack_size: 0,
            detach_state: 0,
            _pad: 0,
        }
    }

    pub const fn new(stack_size: u64, detach_state: u32) -> Self {
        PthreadAttr {
            stack_size,
            detach_state,
            _pad: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ThreadControl: per-thread lifecycle state, lives in a global pool
// ---------------------------------------------------------------------------

/// Per-thread control block. Lives in a static pool, not on the thread's stack.
///
/// Access is synchronized via CAS on `state`. Only the thread that successfully
/// CASes a slot from UNUSED→RUNNING owns it; only the joiner that CASes
/// EXITED→JOINED may clean it up.
///
/// Public so `PthreadT` can be used from external crates, but all fields
/// are private — external code treats this as an opaque handle.
#[repr(C)]
pub struct ThreadControl {
    /// Lifecycle state (TC_UNUSED / TC_RUNNING / TC_EXITED / TC_JOINED / TC_DETACHED / TC_DETACHED_EXITED)
    state: AtomicU32,
    /// Futex word for pthread_join synchronization (0 = not exited, 1 = exited)
    join_futex: AtomicU32,
    /// Return value from pthread_exit (set by exiting thread, read by joiner)
    exit_value: *mut u8,
    /// Thread ID (unique per thread within a process)
    thread_id: u64,
    /// Base address of the thread's stack allocation
    stack_base: u64,
    /// Size of the thread's stack allocation (bytes)
    stack_size: u64,
    /// CNode slot of the thread's TCB capability
    tcb_cap: u64,
    /// CNode slot of the thread's SchedContext capability
    sc_cap: u64,
    /// CNode slot of the IPC buffer frame capability
    frame_cap: u64,
    /// Pointer to the thread's TLS block (on its stack)
    tls_ptr: *mut ThreadLocalBlock,
}

// SAFETY: ThreadControl fields are accessed through raw pointers with
// synchronization provided by atomic CAS on `state`. The raw pointer
// fields (exit_value, tls_ptr) are only accessed by the owning thread
// or after the state CAS establishes a happens-before relationship.
unsafe impl Send for ThreadControl {}
unsafe impl Sync for ThreadControl {}

impl ThreadControl {
    const fn zeroed() -> Self {
        ThreadControl {
            state: AtomicU32::new(TC_UNUSED),
            join_futex: AtomicU32::new(0),
            exit_value: core::ptr::null_mut(),
            thread_id: 0,
            stack_base: 0,
            stack_size: 0,
            tcb_cap: 0,
            sc_cap: 0,
            frame_cap: 0,
            tls_ptr: core::ptr::null_mut(),
        }
    }

    #[inline]
    fn join_futex_ptr(&self) -> *const u32 {
        &self.join_futex as *const AtomicU32 as *const u32
    }
}

static mut THREAD_POOL: [ThreadControl; MAX_THREADS] =
    [const { ThreadControl::zeroed() }; MAX_THREADS];

/// Get a raw pointer to pool slot `index`.
#[inline]
fn pool_ptr(index: usize) -> *mut ThreadControl {
    // SAFETY: THREAD_POOL is a static array; we access it via raw pointer
    // (no intermediate reference) per Rust 2024 `static mut` rules.
    unsafe {
        let base = &raw mut THREAD_POOL as *mut ThreadControl;
        base.add(index)
    }
}

/// Rollback helper for pthread_create failures.
///
/// Cleans up caps (if allocated), unmaps stack, and returns pool slot.
///
/// # Safety
/// `tc` must be a valid pool slot pointer. `stack_addr`/`stack_size` must be
/// a valid mmap region (or null/0 if not yet allocated).
unsafe fn rollback_create(
    tc: *mut ThreadControl,
    stack_addr: *mut u8,
    stack_size: u64,
    caps_allocated: bool,
) {
    unsafe {
        if caps_allocated {
            let tcb_cap = (*tc).tcb_cap;
            let sc_cap = (*tc).sc_cap;
            let frame_cap = (*tc).frame_cap;
            if tcb_cap != 0 {
                invoke::cnode_delete(CAP_SELF_CSPACE, tcb_cap);
            }
            if sc_cap != 0 {
                invoke::cnode_delete(CAP_SELF_CSPACE, sc_cap);
            }
            if frame_cap != 0 {
                invoke::cnode_delete(CAP_SELF_CSPACE, frame_cap);
            }
        }
        if !stack_addr.is_null() && stack_size != 0 {
            crate::posix_mm::posix_munmap(stack_addr, stack_size);
        }
        (*tc).state.store(TC_UNUSED, Ordering::Release);
    }
}

/// IPC buffer mapping region: each thread gets one 4K page for its IPC buffer.
/// Start at a high address to avoid conflicts with mmap regions.
const IPC_BUF_REGION_BASE: u64 = 0x0000_7F00_0000_0000;
static IPC_BUF_NEXT: AtomicU64 = AtomicU64::new(IPC_BUF_REGION_BASE);

/// Monotonic thread ID counter
static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);

/// Well-known cap slots
const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_MMSRV_EP: u64 = 7;

/// Opaque thread handle (pointer to ThreadControl pool slot)
pub type PthreadT = *mut ThreadControl;

/// Initialize the main thread's ThreadControl slot (pool index 0).
///
/// Called from `tls::init_main_thread_tls()` during process startup.
///
/// # Safety
/// Must be called exactly once, after the main thread's TLS block is set up.
pub unsafe fn init_main_thread_control(tls: *mut ThreadLocalBlock) {
    unsafe {
        let tc = pool_ptr(0);
        (*tc).state.store(TC_RUNNING, Ordering::Relaxed);
        (*tc).thread_id = 0;
        (*tc).tcb_cap = 0; // CAP_SELF_TCB
        (*tc).tls_ptr = tls;
        (*tls).control = tc as *mut u8;
    }
}

/// Create a new thread.
///
/// Allocates a stack, TLS block, TCB, SchedContext, and IPC buffer frame,
/// then starts the thread running `start_fn(arg)`.
///
/// If `attr` is non-null, uses the specified stack size and detach state.
///
/// Returns 0 on success, negative errno on failure.
/// On success, `*thread_out` is set to the thread handle.
pub unsafe fn pthread_create(
    thread_out: *mut PthreadT,
    attr: *const PthreadAttr,
    start_fn: unsafe extern "C" fn(*mut u8) -> *mut u8,
    arg: *mut u8,
) -> i32 {
    unsafe {
        // Opportunistically reclaim detached-exited threads before taking a slot.
        reap_detached_zombies();

        // 1. Find a free slot in the thread pool (slot 0 is main thread)
        let mut slot_index = usize::MAX;
        for i in 1..MAX_THREADS {
            let tc = pool_ptr(i);
            if (*tc).state.compare_exchange(
                TC_UNUSED, TC_RUNNING,
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok() {
                slot_index = i;
                break;
            }
        }
        if slot_index == usize::MAX {
            serial::serial_puts(b"[PTHREAD] thread pool exhausted\n");
            return -1;
        }
        let tc = pool_ptr(slot_index);

        // 2. Determine stack size and detach state from attributes
        let stack_size = if !attr.is_null() && (*attr).stack_size != 0 {
            ((*attr).stack_size + 4095) & !4095
        } else {
            DEFAULT_STACK_SIZE
        };
        let detach_state = if !attr.is_null() { (*attr).detach_state } else { 0 };

        // Map stack pages via mmsrv mmap
        let stack_addr = crate::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            stack_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        if stack_addr == usize::MAX as *mut u8 || stack_addr.is_null() {
            serial::serial_puts(b"[PTHREAD] stack mmap failed\n");
            (*tc).state.store(TC_UNUSED, Ordering::Release);
            return -1;
        }
        let stack_base = stack_addr as u64;

        // 3. Fill ThreadControl fields
        let tid = NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed);
        (*tc).thread_id = tid;
        (*tc).stack_base = stack_base;
        (*tc).stack_size = stack_size;
        (*tc).join_futex.store(0, Ordering::Relaxed);
        (*tc).exit_value = core::ptr::null_mut();

        // If initially detached, update state
        if detach_state == 1 {
            (*tc).state.store(TC_DETACHED, Ordering::Release);
        }

        // 4. Place TLS block at the top of the stack
        let stack_top = stack_base + stack_size;
        let tls_addr = (stack_top - core::mem::size_of::<ThreadLocalBlock>() as u64) & !0xF;
        let tls = tls_addr as *mut ThreadLocalBlock;

        core::ptr::write_bytes(tls as *mut u8, 0, core::mem::size_of::<ThreadLocalBlock>());
        (*tls).self_ptr = tls;
        (*tls).thread_id = tid;
        (*tls).control = tc as *mut u8; // back-pointer to ThreadControl

        (*tc).tls_ptr = tls;

        // Effective stack pointer (below TLS block, 16-byte aligned)
        let user_rsp = tls_addr & !0xF;

        // 5. Allocate 3 consecutive CNode slots for TCB, SchedContext, IPC buffer frame
        let base_slot = match slot_alloc::slot_alloc_consecutive(3) {
            Some(s) => s,
            None => {
                serial::serial_puts(b"[PTHREAD] slot_alloc_consecutive(3) failed\n");
                crate::posix_mm::posix_munmap(stack_addr, stack_size);
                (*tc).state.store(TC_UNUSED, Ordering::Release);
                return -1;
            }
        };
        let tcb_slot = base_slot;
        let sc_slot = base_slot + 1;
        let frame_slot = base_slot + 2;

        (*tc).tcb_cap = tcb_slot;
        (*tc).sc_cap = sc_slot;
        (*tc).frame_cap = frame_slot;

        // 6. Request object allocation from mmsrv
        ipc::set_receive_slot_ctx(
            tls::current_ipc_ctx(),
            CAP_SELF_CSPACE,
            tcb_slot,
            0,
        );

        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = MM_ALLOC_THREAD_OBJECTS;
        msg.length = 0;

        let err = ipc::call_ctx(
            tls::current_ipc_ctx(),
            CAP_MMSRV_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            let mut lb = serial::LineBuf::new();
            lb.str(b"[PTHREAD] MM_ALLOC_THREAD_OBJECTS failed err=");
            lb.hex(err as u64);
            lb.str(b" label=");
            lb.hex(reply.label);
            lb.str(b"\n");
            lb.flush();
            rollback_create(tc, stack_addr, stack_size, false);
            return -1;
        }

        // 7. Configure TCB: share CSpace and VSpace with parent
        let err = invoke::tcb_set_space(tcb_slot, CAP_SELF_CSPACE, CAP_SELF_VSPACE);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_set_space failed\n");
            rollback_create(tc, stack_addr, stack_size, true);
            return -1;
        }

        // 7b. Set fault handler: route VMFaults to mmsrv (same badged EP as parent)
        let err = invoke::tcb_set_fault_handler(tcb_slot, CAP_MMSRV_EP);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_set_fault_handler failed\n");
            rollback_create(tc, stack_addr, stack_size, true);
            return -1;
        }

        // 8. Map IPC buffer frame
        let ipc_buf_vaddr = IPC_BUF_NEXT.fetch_add(4096, Ordering::Relaxed);
        let err = invoke::vspace_map(
            CAP_SELF_VSPACE,
            frame_slot,
            ipc_buf_vaddr,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] IPC buffer map failed\n");
            rollback_create(tc, stack_addr, stack_size, true);
            return -1;
        }

        let err = invoke::tcb_set_ipc_buffer(tcb_slot, ipc_buf_vaddr);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_set_ipc_buffer failed\n");
            rollback_create(tc, stack_addr, stack_size, true);
            return -1;
        }

        (*tls).ipc_ctx.ipc_buffer = ipc_buf_vaddr as *mut IpcBuffer;
        (*tls).ipc_ctx.send_cap_count = 0;

        // 9. Set TLS base for the new thread
        let err = invoke::tcb_set_tls_base(tcb_slot, tls_addr);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_set_tls_base failed\n");
            rollback_create(tc, stack_addr, stack_size, true);
            return -1;
        }

        // 10. Configure entry point: trampoline pops start_fn and arg from stack
        let trampoline_rsp = user_rsp - 8;
        let fake_ret = trampoline_rsp as *mut u64;
        *fake_ret = 0; // No return address — trampoline calls pthread_exit

        let stack_args = (trampoline_rsp - 16) as *mut u64;
        *(stack_args) = start_fn as u64;
        *(stack_args.add(1)) = arg as u64;

        let err = invoke::tcb_configure(
            tcb_slot,
            pthread_entry_trampoline as *const () as u64,
            trampoline_rsp - 16,
            ipc_buf_vaddr,
        );
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_configure failed\n");
            rollback_create(tc, stack_addr, stack_size, true);
            return -1;
        }

        // 11. Configure scheduling context
        let err = invoke::sc_configure(sc_slot, 10000, 100000);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] sc_configure failed\n");
            rollback_create(tc, stack_addr, stack_size, true);
            return -1;
        }

        let err = invoke::sc_bind(sc_slot, tcb_slot);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] sc_bind failed\n");
            rollback_create(tc, stack_addr, stack_size, true);
            return -1;
        }

        // 12. Resume the thread
        let err = invoke::tcb_resume(tcb_slot);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_resume failed\n");
            rollback_create(tc, stack_addr, stack_size, true);
            return -1;
        }

        // Return thread handle (pointer to pool slot)
        if !thread_out.is_null() {
            *thread_out = tc;
        }

        0
    }
}

/// Thread entry trampoline (naked — no compiler prologue).
///
/// Called with: [RSP+0] = start_fn, [RSP+8] = arg
/// Pops them into RDI/RSI and tail-calls the helper.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn pthread_entry_trampoline() {
    core::arch::naked_asm!(
        "pop rdi",
        "pop rsi",
        "jmp {helper}",
        helper = sym pthread_trampoline_helper,
    );
}

/// Helper called by the naked trampoline with start_fn in RDI and arg in RSI.
unsafe extern "C" fn pthread_trampoline_helper(
    start_fn: unsafe extern "C" fn(*mut u8) -> *mut u8,
    arg: *mut u8,
) -> ! {
    unsafe {
        let retval = start_fn(arg);
        pthread_exit(retval);
    }
}

/// Terminate the calling thread and store the return value.
///
/// If the thread is joinable (RUNNING), transitions to EXITED and wakes
/// any joiner. If detached, transitions to DETACHED_EXITED for deferred
/// cleanup by another live thread.
pub unsafe fn pthread_exit(retval: *mut u8) -> ! {
    unsafe {
        let self_tcb;

        if let Some(tls) = tls::current_tls() {
            let tc = (*tls).control as *mut ThreadControl;
            if !tc.is_null() {
                // Read tcb_cap before any state transition — a joiner on another
                // CPU could clean up the slot as soon as we set EXITED.
                self_tcb = (*tc).tcb_cap;

                // Store exit value (visible to joiner after state CAS Release)
                (*tc).exit_value = retval;

                // Try joinable path: RUNNING → EXITED
                if (*tc).state.compare_exchange(
                    TC_RUNNING, TC_EXITED,
                    Ordering::Release, Ordering::Relaxed,
                ).is_ok() {
                    (*tc).join_futex.store(1, Ordering::Release);
                    futex_wake((*tc).join_futex_ptr(), 1);
                } else {
                    // Must be DETACHED — mark for deferred cleanup by reaper.
                    let _ = (*tc).state.compare_exchange(
                        TC_DETACHED, TC_DETACHED_EXITED,
                        Ordering::Release, Ordering::Relaxed,
                    );
                }
            } else {
                self_tcb = CAP_SELF_TCB;
            }
        } else {
            self_tcb = CAP_SELF_TCB;
        }

        // Suspend self — we can't deallocate our own stack while running on it.
        // The joining thread or the process exit path handles cleanup.
        invoke::tcb_suspend_retry(self_tcb, 4);

        // Should never reach here
        loop {
            crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
    }
}

/// Clean up a thread's resources: suspend TCB, unmap stack, delete caps.
///
/// # Safety
/// Caller must own the ThreadControl slot (via successful CAS to JOINED).
unsafe fn cleanup_thread(tc: *mut ThreadControl) {
    unsafe {
        let tcb_cap = (*tc).tcb_cap;
        let sc_cap = (*tc).sc_cap;
        let frame_cap = (*tc).frame_cap;
        let stack_base = (*tc).stack_base;
        let stack_size = (*tc).stack_size;

        // Suspend the thread's TCB (should already be suspended)
        if tcb_cap != 0 {
            invoke::tcb_suspend_retry(tcb_cap, 4);
        }

        // Unmap and free the stack (this also destroys the TLS block)
        if stack_base != 0 && stack_size != 0 {
            crate::posix_mm::posix_munmap(stack_base as *mut u8, stack_size);
        }

        // Delete caps (TCB, SchedContext, IPC buffer frame)
        if tcb_cap != 0 {
            invoke::cnode_delete(CAP_SELF_CSPACE, tcb_cap);
        }
        if sc_cap != 0 {
            invoke::cnode_delete(CAP_SELF_CSPACE, sc_cap);
        }
        if frame_cap != 0 {
            invoke::cnode_delete(CAP_SELF_CSPACE, frame_cap);
        }

        // Return slot to pool
        (*tc).state.store(TC_UNUSED, Ordering::Release);
    }
}

/// Reclaim detached threads that have already exited.
///
/// Detached threads cannot reclaim their own stacks while running on them.
/// We mark them `TC_DETACHED_EXITED` in `pthread_exit` and clean them up from
/// another live thread at pthread API entry points.
unsafe fn reap_detached_zombies() {
    unsafe {
        for i in 1..MAX_THREADS {
            let tc = pool_ptr(i);
            if (*tc).state.compare_exchange(
                TC_DETACHED_EXITED, TC_JOINED,
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok() {
                cleanup_thread(tc);
            }
        }
    }
}

/// Process-exit sweep: reclaim already-exited thread resources.
///
/// Called from `posix_exit()` before notifying procmgr. This is a best-effort
/// final cleanup for exited thread slots that were not joined/detached-cleaned
/// yet. It only claims states that are already exited (never RUNNING).
pub unsafe fn process_exit_reap() {
    unsafe {
        for i in 1..MAX_THREADS {
            let tc = pool_ptr(i);

            // Detached thread that already exited and is awaiting reaper
            if (*tc).state.compare_exchange(
                TC_DETACHED_EXITED, TC_JOINED,
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok() {
                cleanup_thread(tc);
                continue;
            }

            // Joinable thread that exited but was never joined
            if (*tc).state.compare_exchange(
                TC_EXITED, TC_JOINED,
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok() {
                cleanup_thread(tc);
            }
        }
    }
}

/// Wait for a thread to terminate and retrieve its return value.
///
/// Blocks the caller until the target thread has called `pthread_exit` or
/// returned from its start function. On success, `*retval` (if non-null)
/// is set to the thread's exit value.
///
/// Returns 0 on success, -1 on error (null handle, self-join, detached,
/// or already joined).
pub unsafe fn pthread_join(thread: PthreadT, retval: *mut *mut u8) -> i32 {
    if thread.is_null() {
        return -1;
    }

    unsafe {
        // Joining is a natural safe point to reclaim detached-exited zombies.
        reap_detached_zombies();

        let tc = thread;

        // Self-join check: deadlock prevention
        if let Some(tls) = tls::current_tls() {
            if (*tls).control as *mut ThreadControl == tc {
                return -1; // EDEADLK
            }
        }

        // Wait for the thread to exit
        loop {
            let state = (*tc).state.load(Ordering::Acquire);
            if state == TC_EXITED {
                break;
            }
            if state != TC_RUNNING {
                // Thread is detached, unused, or already joined
                return -1;
            }

            // Block on the futex until the exiting thread sets join_futex=1
            let fval = (*tc).join_futex.load(Ordering::Acquire);
            if fval == 0 {
                futex_wait((*tc).join_futex_ptr(), 0);
            }
        }

        // Claim the right to join: CAS EXITED → JOINED
        if (*tc).state.compare_exchange(
            TC_EXITED, TC_JOINED,
            Ordering::AcqRel, Ordering::Relaxed,
        ).is_err() {
            // Another thread already joined or detached
            return -1;
        }

        // Read exit value (safe: CAS Release/Acquire provides happens-before)
        if !retval.is_null() {
            *retval = (*tc).exit_value;
        }

        // Cleanup: suspend TCB, munmap stack, delete caps, return slot
        cleanup_thread(tc);

        0
    }
}

/// Return the calling thread's handle.
///
/// Returns a pointer to the calling thread's ThreadControl pool slot.
pub fn pthread_self() -> PthreadT {
    match tls::current_tls() {
        Some(tls) => unsafe { (*tls).control as *mut ThreadControl },
        None => core::ptr::null_mut(),
    }
}

/// Sentinel value for PTHREAD_CANCELED
pub const PTHREAD_CANCELED: *mut u8 = usize::MAX as *mut u8;

/// Request cancellation of a thread.
///
/// Sets the `cancel_pending` flag on the target thread's TLS. The thread
/// will be cancelled at the next cancellation point (if deferred mode).
///
/// Returns 0 on success, -1 if the thread is not alive.
pub unsafe fn pthread_cancel(thread: PthreadT) -> i32 {
    if thread.is_null() {
        return -1;
    }
    unsafe {
        let state = (*thread).state.load(Ordering::Acquire);
        if state != TC_RUNNING && state != TC_DETACHED {
            return -1;
        }
        let tls = (*thread).tls_ptr;
        if tls.is_null() {
            return -1;
        }
        core::ptr::write_volatile(&raw mut (*tls).cancel_pending, 1);
    }
    0
}

/// Set cancellation state (ENABLE=0, DISABLE=1).
pub unsafe fn pthread_setcancelstate(state: i32, oldstate: *mut i32) -> i32 {
    if let Some(tls) = tls::current_tls() {
        unsafe {
            if !oldstate.is_null() {
                *oldstate = (*tls).cancel_state as i32;
            }
            (*tls).cancel_state = state as u32;
        }
        0
    } else {
        -1
    }
}

/// Set cancellation type (DEFERRED=0 only).
pub unsafe fn pthread_setcanceltype(ctype: i32, oldtype: *mut i32) -> i32 {
    if let Some(tls) = tls::current_tls() {
        unsafe {
            if !oldtype.is_null() {
                *oldtype = (*tls).cancel_type as i32;
            }
            (*tls).cancel_type = ctype as u32;
        }
        0
    } else {
        -1
    }
}

/// Test for pending cancellation and act on it.
///
/// If cancellation is pending and enabled, runs all cleanup handlers
/// and calls `pthread_exit(PTHREAD_CANCELED)`.
pub unsafe fn pthread_testcancel() {
    if let Some(tls) = tls::current_tls() {
        unsafe {
            let pending = core::ptr::read_volatile(&raw const (*tls).cancel_pending);
            if pending != 0 && (*tls).cancel_state == 0 {
                run_cleanup_handlers(tls);
                pthread_exit(PTHREAD_CANCELED);
            }
        }
    }
}

/// Push a cleanup handler onto the thread's cleanup stack.
pub unsafe fn pthread_cleanup_push_impl(
    routine: unsafe extern "C" fn(*mut u8),
    arg: *mut u8,
    handler: *mut tls::CleanupHandler,
) {
    if let Some(tls) = tls::current_tls() {
        unsafe {
            (*handler).routine = routine;
            (*handler).arg = arg;
            (*handler).next = (*tls).cleanup_stack;
            (*tls).cleanup_stack = handler;
        }
    }
}

/// Pop a cleanup handler from the thread's cleanup stack.
/// If `execute` is non-zero, calls the handler's routine.
pub unsafe fn pthread_cleanup_pop_impl(execute: i32) {
    if let Some(tls) = tls::current_tls() {
        unsafe {
            let handler = (*tls).cleanup_stack;
            if !handler.is_null() {
                (*tls).cleanup_stack = (*handler).next;
                if execute != 0 {
                    ((*handler).routine)((*handler).arg);
                }
            }
        }
    }
}

/// Run all cleanup handlers on the thread's cleanup stack (LIFO order).
unsafe fn run_cleanup_handlers(tls: *mut tls::ThreadLocalBlock) {
    unsafe {
        loop {
            let handler = (*tls).cleanup_stack;
            if handler.is_null() {
                break;
            }
            (*tls).cleanup_stack = (*handler).next;
            ((*handler).routine)((*handler).arg);
        }
    }
}

/// Mark a thread as detached (cannot be joined).
///
/// If the thread is still running, transitions RUNNING → DETACHED.
/// If the thread already exited, performs immediate cleanup.
///
/// Returns 0 on success, -1 on error.
pub unsafe fn pthread_detach(thread: PthreadT) -> i32 {
    if thread.is_null() {
        return -1;
    }
    unsafe {
        // Detach calls are also safe points for deferred cleanup.
        reap_detached_zombies();

        let tc = thread;

        // Try: thread is still running → mark as detached
        if (*tc).state.compare_exchange(
            TC_RUNNING, TC_DETACHED,
            Ordering::AcqRel, Ordering::Relaxed,
        ).is_ok() {
            // Wake any thread blocked in pthread_join's futex_wait loop.
            // The joiner will re-check state, see TC_DETACHED, and return -1.
            (*tc).join_futex.store(1, Ordering::Release);
            futex_wake((*tc).join_futex_ptr(), 1);
            return 0;
        }

        // Try: thread already exited → claim and clean up immediately
        if (*tc).state.compare_exchange(
            TC_EXITED, TC_JOINED,
            Ordering::AcqRel, Ordering::Relaxed,
        ).is_ok() {
            cleanup_thread(tc);
            return 0;
        }

        // Try: detached thread already exited and is waiting for reaper
        if (*tc).state.compare_exchange(
            TC_DETACHED_EXITED, TC_JOINED,
            Ordering::AcqRel, Ordering::Relaxed,
        ).is_ok() {
            cleanup_thread(tc);
            return 0;
        }

        // Already detached, joined, or unused
        -1
    }
}
