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

use salty::consts::*;
use salty::ipc;
use salty::posix;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // IPC buffer is pre-mapped by procmgr at 0x200000
    salty::salty_tcb_set_ipc_buffer(CAP_SELF_TCB, 0x200000);
    unsafe {
        ipc::ipc_context_init(&raw mut salty::__salty_ipc_ctx, 0x200000 as *mut IpcBuffer);
    }

    puts(b"[TEST_RUNNER] SaltyOS Test Runner starting\n");

    let tests: [(&[u8], fn() -> bool); 8] = [
        (b"test_hello", test_hello::run),
        (b"test_fs", test_fs::run),
        (b"test_mmap", test_mmap::run),
        (b"test_fork", test_fork::run),
        (b"test_signal", test_signal::run),
        (b"test_socket", test_socket::run),
        (b"test_pipe", test_pipe::run),
        (b"test_time", test_time::run),
    ];

    let mut passed = 0u32;
    let mut failed = 0u32;

    for (name, test_fn) in &tests {
        { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] Running "); lb.str(name); lb.str(b"...\n"); lb.flush(); }

        let result = test_fn();
        if result {
            { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] "); lb.str(name); lb.str(b" ... PASS\n"); lb.flush(); }
            passed += 1;
        } else {
            { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] "); lb.str(name); lb.str(b" ... FAIL\n"); lb.flush(); }
            failed += 1;
        }
    }

    { let mut lb = LineBuf::new(); lb.str(b"[TEST_RUNNER] Results: "); lb.dec(passed as u64); lb.str(b" passed, "); lb.dec(failed as u64); lb.str(b" failed\n"); lb.flush(); }

    if failed == 0 {
        puts(b"[TEST_RUNNER] ALL TESTS PASSED\n");
        unsafe { posix::posix_exit(42) };
    } else {
        puts(b"[TEST_RUNNER] TESTS FAILED\n");
        unsafe { posix::posix_exit(1) };
    }
}
