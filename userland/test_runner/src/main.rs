//! SaltyOS Test Runner
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Unified test runner that consolidates all userland tests into a single
//! dynamically-linked binary. Spawned by init via procmgr.
//! Exit code 42 = all tests passed, 1 = failure.

#![no_std]
#![no_main]

extern crate salty;

mod test_hello;
mod test_fs;
mod test_mmap;
mod test_fork;
mod test_signal;
mod test_socket;
mod test_pipe;
mod test_time;
mod test_terminal;
mod test_epoll;
#[cfg(saltyc_sse2)]
mod test_sse;

use salty::consts::*;
use salty::ipc;
use salty::posix;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

// Standard child CSpace layout
const CAP_SELF_TCB: u64 = 0;
const CAP_MMSRV_EP: u64 = 7;
const CAP_READINESS_NTFN: u64 = 14;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn signal_ready() {
    let _ = salty::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // IPC buffer is pre-mapped by procmgr at 0x200000
    salty::salty_tcb_set_ipc_buffer(CAP_SELF_TCB, 0x200000);
    unsafe {
        ipc::ipc_context_init(&raw mut salty::__salty_ipc_ctx, 0x200000 as *mut IpcBuffer);
    }

    // Initialize per-process slot allocator from RTLD-exported globals
    unsafe {
        let base = *(&raw const salty::__salty_slot_base);
        let count = *(&raw const salty::__salty_slot_count);
        let cspace_ntfn = *(&raw const salty::__salty_cspace_ntfn);
        if base != 0 {
            salty::slot_alloc::slot_alloc_init(base, count, cspace_ntfn);
        } else {
            puts(b"[TEST_RUNNER] FATAL: slot pool not provided by RTLD/auxv\n");
            posix::posix_exit(1);
        }
    }

    puts(b"[TEST_RUNNER] SaltyOS Test Runner starting\n");
    signal_ready();

    let base_tests: [(&[u8], fn() -> bool); 10] = [
        (b"test_hello", test_hello::run),
        (b"test_fs", test_fs::run),
        (b"test_mmap", test_mmap::run),
        (b"test_fork", test_fork::run),
        (b"test_signal", test_signal::run),
        (b"test_socket", test_socket::run),
        (b"test_pipe", test_pipe::run),
        (b"test_time", test_time::run),
        (b"test_terminal", test_terminal::run),
        (b"test_epoll", test_epoll::run),
    ];
    #[cfg(saltyc_sse2)]
    let sse_tests: [(&[u8], fn() -> bool); 1] = [
        (b"test_sse", test_sse::run),
    ];
    #[cfg(not(saltyc_sse2))]
    let sse_tests: [(&[u8], fn() -> bool); 0] = [];

    let mut passed = 0u32;
    let mut failed = 0u32;

    fn run_suite(
        tests: &[(&[u8], fn() -> bool)],
        passed: &mut u32,
        failed: &mut u32,
    ) {
        for (name, test_fn) in tests {
            { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] Running "); lb.str(name); lb.str(b"...\n"); lb.flush(); }
            let result = test_fn();
            if result {
                { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] "); lb.str(name); lb.str(b" ... PASS\n"); lb.flush(); }
                *passed += 1;
            } else {
                { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] "); lb.str(name); lb.str(b" ... FAIL\n"); lb.flush(); }
                *failed += 1;
            }
        }
    }

    run_suite(&base_tests, &mut passed, &mut failed);
    run_suite(&sse_tests, &mut passed, &mut failed);

    { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] Results: "); lb.dec(passed as u64); lb.str(b" passed, "); lb.dec(failed as u64); lb.str(b" failed\n"); lb.flush(); }

    if failed == 0 {
        puts(b"[TEST_RUNNER] ALL TESTS PASSED\n");
        unsafe { posix::posix_exit(42) };
    } else {
        puts(b"[TEST_RUNNER] TESTS FAILED\n");
        unsafe { posix::posix_exit(1) };
    }
}
