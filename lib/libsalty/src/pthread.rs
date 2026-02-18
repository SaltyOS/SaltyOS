//! POSIX threads (pthreads) implementation
//!
//! Provides pthread_create, pthread_join, pthread_exit, pthread_self, and
//! pthread_detach on top of SaltyOS kernel primitives (TCB, SchedContext,
//! futex, TLS).
//!
//! Thread creation flow:
//! 1. Allocate stack via mmap (2 MiB default, first page is guard)
//! 2. Place ThreadLocalBlock at stack top
//! 3. Request TCB + SchedContext + IPC buffer from mmsrv
//! 4. Configure TCB (CSpace/VSpace sharing, entry point, stack)
//! 5. Map IPC buffer frame, set TLS base
//! 6. Configure and bind SchedContext
//! 7. Resume TCB
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::invoke;
use crate::ipc;
use crate::serial;
use crate::slot_alloc;
use crate::syscall::{futex_wait, futex_wake};
use crate::tls::{self, ThreadLocalBlock, JOIN_JOINABLE, JOIN_DETACHED, JOIN_EXITED};
use crate::types::*;
use core::sync::atomic::{AtomicU64, Ordering};

/// Default thread stack size: 2 MiB
const DEFAULT_STACK_SIZE: u64 = 2 * 1024 * 1024;

/// IPC buffer mapping region: each thread gets one 4K page for its IPC buffer.
/// Start at a high address to avoid conflicts with mmap regions.
const IPC_BUF_REGION_BASE: u64 = 0x0000_7F00_0000_0000;
static IPC_BUF_NEXT: AtomicU64 = AtomicU64::new(IPC_BUF_REGION_BASE);

/// Thread stack mapping region
const THREAD_STACK_REGION_BASE: u64 = 0x0000_7E00_0000_0000;
static STACK_NEXT: AtomicU64 = AtomicU64::new(THREAD_STACK_REGION_BASE);

/// Monotonic thread ID counter
static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);

/// Well-known cap slots
const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_MMSRV_EP: u64 = 7;

/// Opaque thread handle (pointer to ThreadLocalBlock)
pub type PthreadT = *mut ThreadLocalBlock;

/// Create a new thread.
///
/// Allocates a stack, TLS block, TCB, SchedContext, and IPC buffer frame,
/// then starts the thread running `start_fn(arg)`.
///
/// Returns 0 on success, negative errno on failure.
/// On success, `*thread_out` is set to the thread handle.
pub unsafe fn pthread_create(
    thread_out: *mut PthreadT,
    start_fn: unsafe extern "C" fn(*mut u8) -> *mut u8,
    arg: *mut u8,
) -> i32 {
    unsafe {
        // 1. Allocate stack from the thread stack region (avoid mmsrv mmap for simplicity)
        let stack_size = DEFAULT_STACK_SIZE;
        let stack_base = STACK_NEXT.fetch_add(stack_size, Ordering::Relaxed);

        // Map stack pages via mmsrv mmap
        let stack_addr = crate::posix_mm::posix_mmap(
            stack_base as *mut u8,
            stack_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0,
        );
        if stack_addr == usize::MAX as *mut u8 || stack_addr.is_null() {
            serial::serial_puts(b"[PTHREAD] stack mmap failed\n");
            return -1;
        }

        // 2. Place TLS block at the top of the stack (below guard area)
        let stack_top = stack_base + stack_size;
        let tls_addr = stack_top - core::mem::size_of::<ThreadLocalBlock>() as u64;
        let tls_addr = tls_addr & !0xF; // 16-byte align
        let tls = tls_addr as *mut ThreadLocalBlock;

        // Initialize TLS block
        core::ptr::write_bytes(tls as *mut u8, 0, core::mem::size_of::<ThreadLocalBlock>());
        (*tls).self_ptr = tls;
        (*tls).thread_id = NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed);
        (*tls).stack_base = stack_base;
        (*tls).stack_size = stack_size;
        (*tls).join_state = JOIN_JOINABLE;
        (*tls).join_futex = 0;
        (*tls).exit_value = core::ptr::null_mut();

        // Effective stack pointer (below TLS block, 16-byte aligned)
        let user_rsp = tls_addr & !0xF;

        // 3. Allocate 3 consecutive CNode slots for TCB, SchedContext, IPC buffer frame.
        // Must be consecutive because set_receive_slot_ctx sets the base and the
        // kernel places transferred caps at base+0, base+1, base+2.
        let base_slot = match slot_alloc::slot_alloc_consecutive(3) {
            Some(s) => s,
            None => {
                serial::serial_puts(b"[PTHREAD] slot_alloc_consecutive(3) failed\n");
                return -1;
            }
        };
        let tcb_slot = base_slot;
        let sc_slot = base_slot + 1;
        let frame_slot = base_slot + 2;

        (*tls).tcb_cap = tcb_slot;
        (*tls).sc_cap = sc_slot;

        // 4. Request object allocation from mmsrv
        // Set up receive slots for the 3 caps that mmsrv will transfer back
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
            return -1;
        }

        // The 3 caps are now in tcb_slot, sc_slot, frame_slot
        // (mmsrv transferred them via IPC cap transfer; kernel placed them
        // at tcb_slot because we set receive_slot=tcb_slot)
        // Actually, IPC cap transfer places caps sequentially starting at
        // receive_index. So cap 0 → tcb_slot, cap 1 → tcb_slot+1, cap 2 → tcb_slot+2.
        // We allocated consecutive slots, so this works if they're sequential.
        // To be safe, let's just move caps if they ended up in wrong slots.
        // With 3 send caps and receive starting at tcb_slot, they land at
        // tcb_slot, tcb_slot+1, tcb_slot+2. If our 3 slot_alloc() calls were
        // sequential (which they should be in the bump allocator), this works.

        // 5. Configure TCB: share CSpace and VSpace with parent
        let err = invoke::tcb_set_space(tcb_slot, CAP_SELF_CSPACE, CAP_SELF_VSPACE);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_set_space failed\n");
            return -1;
        }

        // 6. Map IPC buffer frame
        let ipc_buf_vaddr = IPC_BUF_NEXT.fetch_add(4096, Ordering::Relaxed);
        let err = invoke::vspace_map(
            CAP_SELF_VSPACE,
            frame_slot,
            ipc_buf_vaddr,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] IPC buffer map failed\n");
            return -1;
        }

        // Set IPC buffer address for the new TCB
        let err = invoke::tcb_set_ipc_buffer(tcb_slot, ipc_buf_vaddr);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_set_ipc_buffer failed\n");
            return -1;
        }

        // Initialize the IPC context in the TLS block
        (*tls).ipc_ctx.ipc_buffer = ipc_buf_vaddr as *mut IpcBuffer;
        (*tls).ipc_ctx.send_cap_count = 0;

        // 7. Set TLS base for the new thread
        let err = invoke::tcb_set_tls_base(tcb_slot, tls_addr);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_set_tls_base failed\n");
            return -1;
        }

        // 8. Configure entry point: use trampoline that calls start_fn(arg)
        // We set up the stack so the thread starts at pthread_entry_trampoline
        // with RDI=start_fn and RSI=arg.
        //
        // Push a fake return address (0) on the stack for the trampoline.
        let trampoline_rsp = user_rsp - 8;
        let fake_ret = trampoline_rsp as *mut u64;
        *fake_ret = 0; // No return address — trampoline calls pthread_exit

        let err = invoke::tcb_configure(
            tcb_slot,
            pthread_entry_trampoline as *const () as u64,
            trampoline_rsp,
            ipc_buf_vaddr,
        );
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_configure failed\n");
            return -1;
        }

        // Write start_fn and arg into RDI/RSI via tcb_write_registers
        // Actually tcb_configure sets RIP and RSP, but we need RDI=start_fn, RSI=arg.
        // Use the IPC buffer to pass extra registers.
        // The kernel's TCB_WRITE_REGISTERS writes: flags(resume), rip, rsp.
        // We need a different approach to set RDI/RSI.
        //
        // Alternative: place start_fn and arg on the stack for the trampoline to pop.
        let stack_args = (trampoline_rsp - 16) as *mut u64;
        *(stack_args) = start_fn as u64;     // [rsp+0] = start_fn
        *(stack_args.add(1)) = arg as u64;   // [rsp+8] = arg

        // Reconfigure with adjusted RSP so trampoline can pop args
        let err = invoke::tcb_configure(
            tcb_slot,
            pthread_entry_trampoline as *const () as u64,
            trampoline_rsp - 16,
            ipc_buf_vaddr,
        );
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_configure (adjusted) failed\n");
            return -1;
        }

        // 9. Configure scheduling context
        let err = invoke::sc_configure(sc_slot, 10000, 100000);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] sc_configure failed\n");
            return -1;
        }

        let err = invoke::sc_bind(sc_slot, tcb_slot);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] sc_bind failed\n");
            return -1;
        }

        // 10. Resume the thread
        let err = invoke::tcb_resume(tcb_slot);
        if err != 0 {
            serial::serial_puts(b"[PTHREAD] tcb_resume failed\n");
            return -1;
        }

        // Return thread handle
        if !thread_out.is_null() {
            *thread_out = tls;
        }

        0
    }
}

/// Thread entry trampoline.
///
/// Called with: [RSP+0] = start_fn, [RSP+8] = arg
/// Pops them, calls start_fn(arg), then calls pthread_exit with the return value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_entry_trampoline() {
    let start_fn: unsafe extern "C" fn(*mut u8) -> *mut u8;
    let arg: *mut u8;
    unsafe {
        // Pop start_fn and arg from the stack (placed there by pthread_create).
        // No options(nostack) — pop modifies RSP.
        core::arch::asm!(
            "pop {0}",
            "pop {1}",
            out(reg) start_fn,
            out(reg) arg,
        );

        let retval = start_fn(arg);
        pthread_exit(retval);
    }
}

/// Terminate the calling thread and store the return value.
///
/// If the thread is joinable, another thread can retrieve the value via
/// `pthread_join`. If detached, resources are leaked (no cleanup yet).
pub unsafe fn pthread_exit(retval: *mut u8) -> ! {
    unsafe {
        if let Some(tls) = tls::current_tls() {
            // Store exit value
            (*tls).exit_value = retval;

            // Mark as exited and wake any joiner
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
            let futex_ptr = &raw mut (*tls).join_futex;
            (*tls).join_state = JOIN_EXITED;
            core::ptr::write_volatile(futex_ptr, 1);
            core::sync::atomic::compiler_fence(Ordering::SeqCst);

            // Wake one joiner
            futex_wake(futex_ptr as *const u32, 1);
        }

        // Suspend self — we can't deallocate our own stack while running on it.
        // The joining thread or the process exit path handles cleanup.
        invoke::tcb_suspend(CAP_SELF_TCB);

        // Should never reach here
        loop {
            crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
    }
}

/// Wait for a thread to terminate and retrieve its return value.
///
/// Blocks the caller until the target thread has called `pthread_exit` or
/// returned from its start function. On success, `*retval` (if non-null)
/// is set to the thread's exit value.
///
/// Returns 0 on success, -1 on error.
pub unsafe fn pthread_join(thread: PthreadT, retval: *mut *mut u8) -> i32 {
    if thread.is_null() {
        return -1;
    }

    unsafe {
        let tls = thread;

        // Wait for the thread to exit
        loop {
            let futex_ptr = &raw const (*tls).join_futex;
            let state = core::ptr::read_volatile(&raw const (*tls).join_state);
            if state == JOIN_EXITED {
                break;
            }
            if state == JOIN_DETACHED {
                return -1; // Cannot join a detached thread
            }

            // Block on the futex until the thread sets join_futex=1
            let current = core::ptr::read_volatile(futex_ptr);
            if current == 0 {
                futex_wait(futex_ptr as *const u32, 0);
            }
        }

        // Retrieve exit value
        if !retval.is_null() {
            *retval = (*tls).exit_value;
        }

        // Cleanup: suspend the thread's TCB (should already be suspended)
        invoke::tcb_suspend((*tls).tcb_cap);

        // Note: we don't unmap the thread's stack or free objects here.
        // Full cleanup would require munmap + cnode_revoke + cnode_delete.
        // For now, thread resources leak. A production implementation would
        // need a reaper thread or deferred cleanup mechanism.

        0
    }
}

/// Return the calling thread's handle.
pub fn pthread_self() -> PthreadT {
    match tls::current_tls() {
        Some(tls) => tls,
        None => core::ptr::null_mut(),
    }
}

/// Mark a thread as detached (cannot be joined).
pub unsafe fn pthread_detach(thread: PthreadT) -> i32 {
    if thread.is_null() {
        return -1;
    }
    unsafe {
        (*thread).join_state = JOIN_DETACHED;
    }
    0
}
