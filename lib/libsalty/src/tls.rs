//! Thread-Local Storage (TLS) block layout and accessors
//!
//! Each thread has a `ThreadLocalBlock` at the address pointed to by FS_BASE.
//! The x86_64 TLS ABI requires `%fs:0` to hold a self-pointer (`self_ptr`).
//!
//! The main thread's TLS block is statically allocated. Spawned threads have
//! their TLS blocks placed at the top of their stack (below the guard page).
//!
//! Thread lifecycle fields (stack, caps, join state) live in the ThreadControl
//! pool (`pthread.rs`), not here. TLS holds only per-thread runtime state.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::types::IpcContext;
use core::sync::atomic::{AtomicBool, Ordering};

/// Set to `true` after `init_main_thread_tls()` has configured FS_BASE.
/// Prevents `current_tls()` from reading `fs:[0]` when FS_BASE is 0,
/// which would fault on the unmapped zero page.
static TLS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Per-thread local storage block.
///
/// Layout is `#[repr(C)]` for ABI stability. The `self_ptr` field MUST be
/// first — the x86_64 TLS ABI mandates that `%fs:0` dereferences to the
/// TLS block's own address.
///
/// Lifecycle fields (stack base/size, cap slots, join state, exit value)
/// have been moved to `ThreadControl` in `pthread.rs`. The `control`
/// back-pointer connects this TLS block to its owning ThreadControl slot.
#[repr(C)]
pub struct ThreadLocalBlock {
    /// Self-pointer: `%fs:0 == &self` (x86_64 TLS ABI requirement)
    pub self_ptr: *mut ThreadLocalBlock,
    /// Per-thread IPC context (IPC buffer pointer + send-cap count)
    pub ipc_ctx: IpcContext,
    /// Thread ID (unique per thread within a process)
    pub thread_id: u64,
    /// Per-thread errno value
    pub errno: i32,
    /// Padding for alignment
    _pad0: i32,
    /// Back-pointer to owning ThreadControl slot (opaque to avoid circular deps)
    pub control: *mut u8,
    /// Cancellation state: 0=ENABLE, 1=DISABLE
    pub cancel_state: u32,
    /// Cancellation type: 0=DEFERRED (only type supported)
    pub cancel_type: u32,
    /// Set to 1 when cancellation has been requested
    pub cancel_pending: u32,
    _pad1: u32,
    /// LIFO stack of cleanup handlers (intrusive linked list)
    pub cleanup_stack: *mut CleanupHandler,
}

/// Cleanup handler node for pthread_cleanup_push/pop.
#[repr(C)]
pub struct CleanupHandler {
    pub routine: unsafe extern "C" fn(*mut u8),
    pub arg: *mut u8,
    pub next: *mut CleanupHandler,
}

unsafe impl Send for ThreadLocalBlock {}
unsafe impl Sync for ThreadLocalBlock {}
unsafe impl Send for CleanupHandler {}
unsafe impl Sync for CleanupHandler {}

impl ThreadLocalBlock {
    /// Create a zeroed TLS block with self_ptr set to null.
    /// The caller must set `self_ptr = &mut self as *mut _` after placement.
    pub const fn zeroed() -> Self {
        ThreadLocalBlock {
            self_ptr: core::ptr::null_mut(),
            ipc_ctx: IpcContext::new(),
            thread_id: 0,
            errno: 0,
            _pad0: 0,
            control: core::ptr::null_mut(),
            cancel_state: 0,
            cancel_type: 0,
            cancel_pending: 0,
            _pad1: 0,
            cleanup_stack: core::ptr::null_mut(),
        }
    }
}

/// Read the current thread's TLS block pointer from `%fs:0`.
///
/// Returns `None` if TLS has not been initialized for this process
/// (avoids faulting on the unmapped zero page when FS_BASE is 0).
#[inline]
pub fn current_tls() -> Option<*mut ThreadLocalBlock> {
    if !TLS_INITIALIZED.load(Ordering::Acquire) {
        return None;
    }
    let ptr: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, fs:[0]",
            out(reg) ptr,
            options(nostack, pure, readonly)
        );
    }
    if ptr == 0 {
        None
    } else {
        Some(ptr as *mut ThreadLocalBlock)
    }
}

/// Get a pointer to the current thread's IPC context from TLS.
///
/// Falls back to the global `__salty_ipc_ctx` if TLS is not initialized.
#[inline]
pub fn current_ipc_ctx() -> *mut IpcContext {
    if let Some(tls) = current_tls() {
        unsafe { &raw mut (*tls).ipc_ctx }
    } else {
        // Fallback for main thread before TLS is initialized
        &raw mut crate::__salty_ipc_ctx
    }
}

/// Get a pointer to the current thread's errno from TLS.
///
/// Falls back to a global errno if TLS is not initialized.
#[inline]
pub fn current_errno() -> *mut i32 {
    if let Some(tls) = current_tls() {
        unsafe { &raw mut (*tls).errno }
    } else {
        // Fallback: global errno for single-threaded / pre-TLS code
        &raw mut GLOBAL_ERRNO
    }
}

/// Global fallback errno (used before TLS is initialized)
static mut GLOBAL_ERRNO: i32 = 0;

/// Static TLS block for the main thread.
///
/// Allocated statically to avoid heap allocation during startup.
/// Initialized by `init_main_thread_tls()`.
static mut MAIN_THREAD_TLS: ThreadLocalBlock = ThreadLocalBlock::zeroed();

/// Initialize TLS for the main thread.
///
/// Called during process startup (from CRT or `_start`). Copies the
/// existing global IPC context into the TLS block and sets FS_BASE.
///
/// # Safety
/// Must be called exactly once during process initialization, before
/// any other threads are created.
pub unsafe fn init_main_thread_tls() {
    unsafe {
        let tls = &raw mut MAIN_THREAD_TLS;

        // Set self-pointer (x86_64 TLS ABI)
        (*tls).self_ptr = tls;

        // Copy global IPC context into TLS
        (*tls).ipc_ctx.ipc_buffer = crate::__salty_ipc_ctx.ipc_buffer;
        (*tls).ipc_ctx.send_cap_count = crate::__salty_ipc_ctx.send_cap_count;

        // Main thread is thread 0
        (*tls).thread_id = 0;

        // Set FS_BASE via kernel invoke
        let tls_addr = tls as u64;
        let err = crate::invoke::tcb_set_tls_base(0, tls_addr); // CAP_SELF_TCB = 0

        // Only mark TLS as initialized if the kernel accepted the base address.
        // If err != 0, TLS stays uninitialized — fallback to globals still works.
        if err == 0 {
            TLS_INITIALIZED.store(true, Ordering::Release);
        }

        // Initialize the main thread's ThreadControl pool slot (slot 0)
        crate::pthread::init_main_thread_control(tls);
    }
}
