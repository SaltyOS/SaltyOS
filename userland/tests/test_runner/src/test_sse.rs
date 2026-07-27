//! SSE/FPU test module
//!
//! Verifies that XMM registers survive syscalls and context switches
//! via the kernel's lazy FPU switching (#NM + XSAVE/XRSTOR).
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona_runtime::debug::serial;
use trona_runtime::debug::serial::LineBuf;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

unsafe extern "C" {
    fn test_sse_xmm0_syscall(input: u64) -> u64;
    fn test_sse_xmm1_load(value: u64);
    fn test_sse_xmm1_read() -> u64;
    fn test_sse_xmm0_yield_loop(input: u64, yields: u64) -> u64;
    fn test_sse_all_registers(patterns: *const u64, results: *mut u64);
}

/// Test: XMM registers survive a syscall (SYS_YIELD)
fn test_xmm_survives_syscall() -> bool {
    let input: u64 = 0xDEAD_BEEF_CAFE_BABE;
    // SAFETY: helper confines the XMM0/syscall probe to arch-owned assembly.
    let output = unsafe { test_sse_xmm0_syscall(input) };
    if output != input {
        let mut lb = LineBuf::new();
        lb.str(b"  XMM survives syscall: FAIL (expected ");
        lb.hex(input);
        lb.str(b", got ");
        lb.hex(output);
        lb.str(b")\n");
        lb.flush();
        return false;
    }
    puts(b"  XMM survives syscall: OK\n");
    true
}

/// Test: XMM registers survive fork + context switch (lazy FPU switching)
fn test_xmm_survives_fork() -> bool {
    let parent_val: u64 = 0x1122_3344_5566_7788;

    // Load a known value into XMM1 before fork
    // SAFETY: helper writes the test pattern to XMM1.
    unsafe {
        test_sse_xmm1_load(parent_val);
    }

    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"  XMM survives fork: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // Child: XMM1 should have the parent's value (copied via TCB_COPY_FPU)
        // SAFETY: helper reads the XMM1 test register.
        let child_read: u64;
        unsafe {
            child_read = test_sse_xmm1_read();
        }
        if child_read == parent_val {
            puts(b"  XMM survives fork (child): OK\n");
            unsafe {
                trona_posix::posix_exit(0);
            }
        } else {
            let mut lb = LineBuf::new();
            lb.str(b"  XMM survives fork (child): FAIL (expected ");
            lb.hex(parent_val);
            lb.str(b", got ");
            lb.hex(child_read);
            lb.str(b")\n");
            lb.flush();
            unsafe {
                trona_posix::posix_exit(1);
            }
        }
    }

    // Parent: verify our XMM1 is still intact after child ran
    // Yield a few times to force context switches
    for _ in 0..3 {
        let _ = trona_kernel::syscall::yield_now();
    }

    // SAFETY: helper reads the XMM1 test register.
    let parent_read: u64;
    unsafe {
        parent_read = test_sse_xmm1_read();
    }

    // Wait for child
    let mut status: i32 = 0;
    unsafe {
        trona_posix::posix_waitpid(pid, &mut status);
    }

    if parent_read != parent_val {
        let mut lb = LineBuf::new();
        lb.str(b"  XMM survives fork (parent): FAIL (expected ");
        lb.hex(parent_val);
        lb.str(b", got ");
        lb.hex(parent_read);
        lb.str(b")\n");
        lb.flush();
        return false;
    }

    puts(b"  XMM survives fork (parent): OK\n");
    // Child exit code 0 = child passed too
    status == 0
}

/// Test: All 16 XMM registers (XMM0-XMM15) survive multiple yields
///
/// Loads a unique 64-bit pattern into each XMM register, yields 3 times to
/// force context switches, then verifies all 16 registers are intact.
fn test_xmm_all_registers() -> bool {
    // Unique pattern per register: 0xAA00..00 | index
    let patterns: [u64; 16] = [
        0xAA00_0000_0000_0000,
        0xAA00_0000_0000_0001,
        0xAA00_0000_0000_0002,
        0xAA00_0000_0000_0003,
        0xAA00_0000_0000_0004,
        0xAA00_0000_0000_0005,
        0xAA00_0000_0000_0006,
        0xAA00_0000_0000_0007,
        0xAA00_0000_0000_0008,
        0xAA00_0000_0000_0009,
        0xAA00_0000_0000_000A,
        0xAA00_0000_0000_000B,
        0xAA00_0000_0000_000C,
        0xAA00_0000_0000_000D,
        0xAA00_0000_0000_000E,
        0xAA00_0000_0000_000F,
    ];

    let mut results: [u64; 16] = [0; 16];

    // SAFETY: helper loads XMM0-XMM15, issues yields, and stores them back.
    unsafe { test_sse_all_registers(patterns.as_ptr(), results.as_mut_ptr()) };

    for i in 0..16 {
        if results[i] != patterns[i] {
            let mut lb = LineBuf::new();
            lb.str(b"  XMM all registers: FAIL (xmm");
            lb.dec(i as u64);
            lb.str(b" expected ");
            lb.hex(patterns[i]);
            lb.str(b", got ");
            lb.hex(results[i]);
            lb.str(b")\n");
            lb.flush();
            return false;
        }
    }
    puts(b"  XMM all registers (0-15): OK\n");
    true
}

/// Test: FPU-free children don't corrupt FPU-using parent's XMM state
///
/// Parent runs a XMM0 load/yield/read sequence in assembly while a child does
/// no FPU work. XMM0 is ABI-volatile, so the value must not be kept live across
/// ordinary Rust calls.
fn test_xmm_no_fpu_threads() -> bool {
    let parent_val: u64 = 0xBBCC_DDEE_FF00_1122;

    // Fork a child that does NO FPU work — only yields
    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"  XMM no-FPU thread: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // Child: yield several times without touching any XMM register
        for _ in 0..5 {
            let _ = trona_kernel::syscall::yield_now();
        }
        unsafe {
            trona_posix::posix_exit(0);
        }
    }

    // Parent: hold XMM0 live only inside assembly while yielding to the child.
    // SAFETY: helper writes XMM0, issues direct TCB_YIELD invokes, and reads XMM0.
    let parent_read = unsafe { test_sse_xmm0_yield_loop(parent_val, 5) };

    let mut status: i32 = 0;
    unsafe {
        trona_posix::posix_waitpid(pid, &mut status);
    }

    if parent_read != parent_val {
        let mut lb = LineBuf::new();
        lb.str(b"  XMM no-FPU thread: FAIL (expected ");
        lb.hex(parent_val);
        lb.str(b", got ");
        lb.hex(parent_read);
        lb.str(b")\n");
        lb.flush();
        return false;
    }
    puts(b"  XMM no-FPU thread interference: OK\n");
    status == 0
}

/// Test: Parent and child both use XMM with different patterns
///
/// Both parent and child load distinct patterns into XMM0 inside assembly, then
/// yield repeatedly before reading the register back. This avoids relying on
/// ABI-volatile XMM0 across Rust calls.
fn test_xmm_heavy_context_switch() -> bool {
    let parent_pattern: u64 = 0x1111_2222_3333_4444;
    let child_pattern: u64 = 0x5555_6666_7777_8888;

    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"  XMM heavy ctx switch: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // SAFETY: helper confines the child XMM0 live range to assembly.
        let child_read = unsafe { test_sse_xmm0_yield_loop(child_pattern, 10) };

        if child_read == child_pattern {
            puts(b"  XMM heavy ctx switch (child): OK\n");
            unsafe {
                trona_posix::posix_exit(0);
            }
        } else {
            let mut lb = LineBuf::new();
            lb.str(b"  XMM heavy ctx switch (child): FAIL (expected ");
            lb.hex(child_pattern);
            lb.str(b", got ");
            lb.hex(child_read);
            lb.str(b")\n");
            lb.flush();
            unsafe {
                trona_posix::posix_exit(1);
            }
        }
    }

    // SAFETY: helper confines the parent XMM0 live range to assembly.
    let parent_read = unsafe { test_sse_xmm0_yield_loop(parent_pattern, 10) };

    let mut status: i32 = 0;
    unsafe {
        trona_posix::posix_waitpid(pid, &mut status);
    }

    if parent_read != parent_pattern {
        let mut lb = LineBuf::new();
        lb.str(b"  XMM heavy ctx switch (parent): FAIL (expected ");
        lb.hex(parent_pattern);
        lb.str(b", got ");
        lb.hex(parent_read);
        lb.str(b")\n");
        lb.flush();
        return false;
    }

    puts(b"  XMM heavy ctx switch (parent): OK\n");
    status == 0
}

pub fn run() -> bool {
    puts(b"[test_sse] Running SSE tests\n");
    let mut ok = true;
    if !test_xmm_survives_syscall() {
        ok = false;
    }
    if !test_xmm_survives_fork() {
        ok = false;
    }
    if !test_xmm_all_registers() {
        ok = false;
    }
    if !test_xmm_no_fpu_threads() {
        ok = false;
    }
    if !test_xmm_heavy_context_switch() {
        ok = false;
    }
    ok
}
