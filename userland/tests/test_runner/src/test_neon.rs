//! NEON/FPU test module
//!
//! Verifies that NEON/FP registers survive syscalls and context switches
//! via the kernel's lazy FPU switching on aarch64.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona_runtime::debug::serial;
use trona_runtime::debug::serial::LineBuf;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

unsafe extern "C" {
    fn test_neon_d0_syscall(input: u64) -> u64;
    fn test_neon_d1_load(value: u64);
    fn test_neon_d1_read() -> u64;
    fn test_neon_d0_yield_loop(input: u64, yields: u64) -> u64;
    fn test_neon_all_registers_asm(patterns: *const u64, results: *mut u64);
}

/// Test: D0 register survives a syscall (SYS_YIELD)
fn test_neon_survives_syscall() -> bool {
    let input: u64 = 0xDEAD_BEEF_CAFE_BABE;
    // SAFETY: helper confines the D0/syscall probe to arch-owned assembly.
    let output = unsafe { test_neon_d0_syscall(input) };
    if output != input {
        let mut lb = LineBuf::new();
        lb.str(b"  NEON survives syscall: FAIL (expected ");
        lb.hex(input);
        lb.str(b", got ");
        lb.hex(output);
        lb.str(b")\n");
        lb.flush();
        return false;
    }
    puts(b"  NEON survives syscall: OK\n");
    true
}

/// Test: D1 register survives fork + context switch (lazy FPU switching)
fn test_neon_survives_fork() -> bool {
    let parent_val: u64 = 0x1122_3344_5566_7788;

    // Load a known value into D1 before fork
    // SAFETY: helper writes the test pattern to D1.
    unsafe {
        test_neon_d1_load(parent_val);
    }

    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"  NEON survives fork: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // Child: D1 should have the parent's value (copied via FPU state)
        // SAFETY: helper reads the D1 test register.
        let child_read: u64;
        unsafe {
            child_read = test_neon_d1_read();
        }
        if child_read == parent_val {
            puts(b"  NEON survives fork (child): OK\n");
            // SAFETY: Exiting the child process with success status.
            unsafe {
                trona_posix::posix_exit(0);
            }
        } else {
            let mut lb = LineBuf::new();
            lb.str(b"  NEON survives fork (child): FAIL (expected ");
            lb.hex(parent_val);
            lb.str(b", got ");
            lb.hex(child_read);
            lb.str(b")\n");
            lb.flush();
            // SAFETY: Exiting the child process with failure status.
            unsafe {
                trona_posix::posix_exit(1);
            }
        }
    }

    // Parent: verify our D1 is still intact after child ran
    // Yield a few times to force context switches
    for _ in 0..3 {
        let _ = trona_kernel::syscall::yield_now();
    }

    // SAFETY: helper reads the D1 test register.
    let parent_read: u64;
    unsafe {
        parent_read = test_neon_d1_read();
    }

    // Wait for child
    let mut status: i32 = 0;
    // SAFETY: Waiting for the child process we just forked. status pointer is valid.
    unsafe {
        trona_posix::posix_waitpid(pid, &mut status);
    }

    if parent_read != parent_val {
        let mut lb = LineBuf::new();
        lb.str(b"  NEON survives fork (parent): FAIL (expected ");
        lb.hex(parent_val);
        lb.str(b", got ");
        lb.hex(parent_read);
        lb.str(b")\n");
        lb.flush();
        return false;
    }

    puts(b"  NEON survives fork (parent): OK\n");
    // Child exit code 0 = child passed too
    status == 0
}

/// Test: All 32 D registers (D0-D31) survive multiple yields
///
/// Loads a unique 64-bit pattern into each register, yields 3 times to
/// force context switches, then verifies all 32 registers are intact.
fn test_neon_all_registers() -> bool {
    // Unique pattern per register: 0xAA00..00 | index
    let patterns: [u64; 32] = [
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
        0xAA00_0000_0000_0010,
        0xAA00_0000_0000_0011,
        0xAA00_0000_0000_0012,
        0xAA00_0000_0000_0013,
        0xAA00_0000_0000_0014,
        0xAA00_0000_0000_0015,
        0xAA00_0000_0000_0016,
        0xAA00_0000_0000_0017,
        0xAA00_0000_0000_0018,
        0xAA00_0000_0000_0019,
        0xAA00_0000_0000_001A,
        0xAA00_0000_0000_001B,
        0xAA00_0000_0000_001C,
        0xAA00_0000_0000_001D,
        0xAA00_0000_0000_001E,
        0xAA00_0000_0000_001F,
    ];

    let mut results: [u64; 32] = [0; 32];

    // SAFETY: helper loads D0-D31, issues yields, and stores them back.
    unsafe { test_neon_all_registers_asm(patterns.as_ptr(), results.as_mut_ptr()) };

    for i in 0..32 {
        if results[i] != patterns[i] {
            let mut lb = LineBuf::new();
            lb.str(b"  NEON all registers: FAIL (d");
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
    puts(b"  NEON all registers (d0-d31): OK\n");
    true
}

/// Test: FPU-free children don't corrupt FPU-using parent's D0 state
///
/// Parent runs a D0 load/yield/read sequence in assembly while a child does no
/// FPU work. D0 is ABI-volatile, so the value must not be kept live across
/// ordinary Rust calls.
fn test_neon_no_fpu_threads() -> bool {
    let parent_val: u64 = 0xBBCC_DDEE_FF00_1122;

    // Fork a child that does NO FPU work -- only yields
    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"  NEON no-FPU thread: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // Child: yield several times without touching any NEON register
        for _ in 0..5 {
            let _ = trona_kernel::syscall::yield_now();
        }
        // SAFETY: Exiting the child process.
        unsafe {
            trona_posix::posix_exit(0);
        }
    }

    // Parent: hold D0 live only inside assembly while yielding to the child.
    // SAFETY: helper writes D0, issues direct TCB_YIELD invokes, and reads D0.
    let parent_read = unsafe { test_neon_d0_yield_loop(parent_val, 5) };

    let mut status: i32 = 0;
    // SAFETY: Waiting for the child process. status pointer is valid.
    unsafe {
        trona_posix::posix_waitpid(pid, &mut status);
    }

    if parent_read != parent_val {
        let mut lb = LineBuf::new();
        lb.str(b"  NEON no-FPU thread: FAIL (expected ");
        lb.hex(parent_val);
        lb.str(b", got ");
        lb.hex(parent_read);
        lb.str(b")\n");
        lb.flush();
        return false;
    }
    puts(b"  NEON no-FPU thread interference: OK\n");
    status == 0
}

/// Test: Parent and child both use NEON with different patterns
///
/// Both parent and child load distinct patterns into D0 inside assembly, then
/// yield repeatedly before reading the register back. This avoids relying on
/// ABI-volatile D0 across Rust calls.
fn test_neon_heavy_context_switch() -> bool {
    let parent_pattern: u64 = 0x1111_2222_3333_4444;
    let child_pattern: u64 = 0x5555_6666_7777_8888;

    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"  NEON heavy ctx switch: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // SAFETY: helper confines the child D0 live range to assembly.
        let child_read = unsafe { test_neon_d0_yield_loop(child_pattern, 10) };

        if child_read == child_pattern {
            puts(b"  NEON heavy ctx switch (child): OK\n");
            // SAFETY: Exiting the child process with success status.
            unsafe {
                trona_posix::posix_exit(0);
            }
        } else {
            let mut lb = LineBuf::new();
            lb.str(b"  NEON heavy ctx switch (child): FAIL (expected ");
            lb.hex(child_pattern);
            lb.str(b", got ");
            lb.hex(child_read);
            lb.str(b")\n");
            lb.flush();
            // SAFETY: Exiting the child process with failure status.
            unsafe {
                trona_posix::posix_exit(1);
            }
        }
    }

    // SAFETY: helper confines the parent D0 live range to assembly.
    let parent_read = unsafe { test_neon_d0_yield_loop(parent_pattern, 10) };

    let mut status: i32 = 0;
    // SAFETY: Waiting for the child process. status pointer is valid.
    unsafe {
        trona_posix::posix_waitpid(pid, &mut status);
    }

    if parent_read != parent_pattern {
        let mut lb = LineBuf::new();
        lb.str(b"  NEON heavy ctx switch (parent): FAIL (expected ");
        lb.hex(parent_pattern);
        lb.str(b", got ");
        lb.hex(parent_read);
        lb.str(b")\n");
        lb.flush();
        return false;
    }

    puts(b"  NEON heavy ctx switch (parent): OK\n");
    status == 0
}

pub fn run() -> bool {
    puts(b"[test_neon] Running NEON tests\n");
    let mut ok = true;
    if !test_neon_survives_syscall() {
        ok = false;
    }
    if !test_neon_survives_fork() {
        ok = false;
    }
    if !test_neon_all_registers() {
        ok = false;
    }
    if !test_neon_no_fpu_threads() {
        ok = false;
    }
    if !test_neon_heavy_context_switch() {
        ok = false;
    }
    ok
}
