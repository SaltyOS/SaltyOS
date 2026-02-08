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

use salty::consts::*;
use salty::ipc;
use salty::posix;
use salty::serial;
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

    let tests: [(&[u8], fn() -> bool); 5] = [
        (b"test_hello", test_hello::run),
        (b"test_fs", test_fs::run),
        (b"test_mmap", test_mmap::run),
        (b"test_fork", test_fork::run),
        (b"test_signal", test_signal::run),
    ];

    let mut passed = 0u32;
    let mut failed = 0u32;

    for (name, test_fn) in &tests {
        puts(b"[TEST_RUNNER] Running ");
        puts(name);
        puts(b"...\n");

        let result = test_fn();
        if result {
            puts(b"[TEST_RUNNER] ");
            puts(name);
            puts(b" ... PASS\n");
            passed += 1;
        } else {
            puts(b"[TEST_RUNNER] ");
            puts(name);
            puts(b" ... FAIL\n");
            failed += 1;
        }
    }

    puts(b"[TEST_RUNNER] Results: ");
    serial::serial_dec(passed as u64);
    puts(b" passed, ");
    serial::serial_dec(failed as u64);
    puts(b" failed\n");

    if failed == 0 {
        puts(b"[TEST_RUNNER] ALL TESTS PASSED\n");
        unsafe { posix::posix_exit(42) };
    } else {
        puts(b"[TEST_RUNNER] TESTS FAILED\n");
        unsafe { posix::posix_exit(1) };
    }
}
