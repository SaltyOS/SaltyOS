//! NEON/FPU test module
//!
//! Verifies that NEON/FP registers survive syscalls and context switches
//! via the kernel's lazy FPU switching on aarch64.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona::serial;
use trona::serial::LineBuf;
use trona::consts::*;
use trona_posix::proc as posix;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

/// Test: D0 register survives a syscall (SYS_YIELD)
fn test_neon_survives_syscall() -> bool {
    let input: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let output: u64;
    // SAFETY: fmov d0 <- input, yield via svc #0, fmov output <- d0.
    // Kernel does not use NEON, so D0 is untouched during the syscall.
    // If lazy switching is broken, D0 would be clobbered.
    unsafe {
        core::arch::asm!(
            "fmov d0, {input:x}",
            "mov x8, #8",            // SYS_YIELD
            "svc #0",
            "fmov {output:x}, d0",
            input = in(reg) input,
            output = out(reg) output,
            out("x8") _,
            out("x0") _, out("x1") _,
            out("x2") _, out("x3") _,
            out("x4") _, out("x5") _,
            out("x16") _, out("x17") _,
            out("x18") _,
            out("v0") _,
            options(nostack),
        );
    }
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
    // SAFETY: Writing to D1 with a known pattern. No memory aliasing concerns.
    unsafe {
        core::arch::asm!(
            "fmov d1, {0:x}",
            in(reg) parent_val,
            out("v1") _,
            options(nostack),
        );
    }

    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"  NEON survives fork: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // Child: D1 should have the parent's value (copied via FPU state)
        let child_read: u64;
        // SAFETY: Reading D1 which should contain the parent's FPU state
        // after fork. No memory aliasing concerns.
        unsafe {
            core::arch::asm!(
                "fmov {0:x}, d1",
                out(reg) child_read,
                options(nostack),
            );
        }
        if child_read == parent_val {
            puts(b"  NEON survives fork (child): OK\n");
            // SAFETY: Exiting the child process with success status.
            unsafe { trona_posix::posix_exit(0); }
        } else {
            let mut lb = LineBuf::new();
            lb.str(b"  NEON survives fork (child): FAIL (expected ");
            lb.hex(parent_val);
            lb.str(b", got ");
            lb.hex(child_read);
            lb.str(b")\n");
            lb.flush();
            // SAFETY: Exiting the child process with failure status.
            unsafe { trona_posix::posix_exit(1); }
        }
    }

    // Parent: verify our D1 is still intact after child ran
    // Yield a few times to force context switches
    for _ in 0..3 {
        let _ = trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }

    let parent_read: u64;
    // SAFETY: Reading D1 which should still hold the parent's value.
    // No memory aliasing concerns.
    unsafe {
        core::arch::asm!(
            "fmov {0:x}, d1",
            out(reg) parent_read,
            options(nostack),
        );
    }

    // Wait for child
    let mut status: i32 = 0;
    // SAFETY: Waiting for the child process we just forked. status pointer is valid.
    unsafe { trona_posix::posix_waitpid(pid, &mut status); }

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

    // SAFETY: Loading all 32 NEON D registers from the patterns array,
    // yielding to force context switches, then reading them back into results.
    // Both arrays are valid stack allocations with proper alignment.
    unsafe {
        // Load all 32 D registers
        core::arch::asm!(
            "ldr d0,  [{p}]",
            "ldr d1,  [{p}, #8]",
            "ldr d2,  [{p}, #16]",
            "ldr d3,  [{p}, #24]",
            "ldr d4,  [{p}, #32]",
            "ldr d5,  [{p}, #40]",
            "ldr d6,  [{p}, #48]",
            "ldr d7,  [{p}, #56]",
            "ldr d8,  [{p}, #64]",
            "ldr d9,  [{p}, #72]",
            "ldr d10, [{p}, #80]",
            "ldr d11, [{p}, #88]",
            "ldr d12, [{p}, #96]",
            "ldr d13, [{p}, #104]",
            "ldr d14, [{p}, #112]",
            "ldr d15, [{p}, #120]",
            "ldr d16, [{p}, #128]",
            "ldr d17, [{p}, #136]",
            "ldr d18, [{p}, #144]",
            "ldr d19, [{p}, #152]",
            "ldr d20, [{p}, #160]",
            "ldr d21, [{p}, #168]",
            "ldr d22, [{p}, #176]",
            "ldr d23, [{p}, #184]",
            "ldr d24, [{p}, #192]",
            "ldr d25, [{p}, #200]",
            "ldr d26, [{p}, #208]",
            "ldr d27, [{p}, #216]",
            "ldr d28, [{p}, #224]",
            "ldr d29, [{p}, #232]",
            "ldr d30, [{p}, #240]",
            "ldr d31, [{p}, #248]",
            p = in(reg) patterns.as_ptr(),
            out("v0") _, out("v1") _, out("v2") _, out("v3") _,
            out("v4") _, out("v5") _, out("v6") _, out("v7") _,
            out("v8") _, out("v9") _, out("v10") _, out("v11") _,
            out("v12") _, out("v13") _, out("v14") _, out("v15") _,
            out("v16") _, out("v17") _, out("v18") _, out("v19") _,
            out("v20") _, out("v21") _, out("v22") _, out("v23") _,
            out("v24") _, out("v25") _, out("v26") _, out("v27") _,
            out("v28") _, out("v29") _, out("v30") _, out("v31") _,
            options(nostack),
        );

        // Yield 3 times to force context switches
        for _ in 0..3 {
            core::arch::asm!(
                "mov x8, #8",
                "svc #0",
                out("x8") _,
                out("x0") _, out("x1") _,
                out("x2") _, out("x3") _,
                out("x4") _, out("x5") _,
                out("x16") _, out("x17") _,
                out("x18") _,
                options(nostack),
            );
        }

        // Read all 32 D registers back
        core::arch::asm!(
            "str d0,  [{r}]",
            "str d1,  [{r}, #8]",
            "str d2,  [{r}, #16]",
            "str d3,  [{r}, #24]",
            "str d4,  [{r}, #32]",
            "str d5,  [{r}, #40]",
            "str d6,  [{r}, #48]",
            "str d7,  [{r}, #56]",
            "str d8,  [{r}, #64]",
            "str d9,  [{r}, #72]",
            "str d10, [{r}, #80]",
            "str d11, [{r}, #88]",
            "str d12, [{r}, #96]",
            "str d13, [{r}, #104]",
            "str d14, [{r}, #112]",
            "str d15, [{r}, #120]",
            "str d16, [{r}, #128]",
            "str d17, [{r}, #136]",
            "str d18, [{r}, #144]",
            "str d19, [{r}, #152]",
            "str d20, [{r}, #160]",
            "str d21, [{r}, #168]",
            "str d22, [{r}, #176]",
            "str d23, [{r}, #184]",
            "str d24, [{r}, #192]",
            "str d25, [{r}, #200]",
            "str d26, [{r}, #208]",
            "str d27, [{r}, #216]",
            "str d28, [{r}, #224]",
            "str d29, [{r}, #232]",
            "str d30, [{r}, #240]",
            "str d31, [{r}, #248]",
            r = in(reg) results.as_mut_ptr(),
            options(nostack),
        );
    }

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

/// Test: FPU-free forks don't corrupt FPU-using parent's D0 state
///
/// Parent loads D0 pattern, forks a child that does NO FPU work (only yields),
/// then verifies its own D0 is intact. This validates that lazy switching
/// correctly skips save/restore for threads that never touch FPU.
fn test_neon_no_fpu_threads() -> bool {
    let parent_val: u64 = 0xBBCC_DDEE_FF00_1122;

    // SAFETY: Writing to D0 with a known pattern. No memory aliasing concerns.
    unsafe {
        core::arch::asm!(
            "fmov d0, {0:x}",
            in(reg) parent_val,
            out("v0") _,
            options(nostack),
        );
    }

    // Fork a child that does NO FPU work -- only yields
    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"  NEON no-FPU thread: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // Child: yield several times without touching any NEON register
        for _ in 0..5 {
            let _ = trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
        // SAFETY: Exiting the child process.
        unsafe { trona_posix::posix_exit(0); }
    }

    // Parent: yield to let child run (interleave context switches)
    for _ in 0..5 {
        let _ = trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }

    let parent_read: u64;
    // SAFETY: Reading D0 which should still hold the parent's value.
    unsafe {
        core::arch::asm!(
            "fmov {0:x}, d0",
            out(reg) parent_read,
            options(nostack),
        );
    }

    let mut status: i32 = 0;
    // SAFETY: Waiting for the child process. status pointer is valid.
    unsafe { trona_posix::posix_waitpid(pid, &mut status); }

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
/// Both parent and child load distinct patterns into D0, then alternate
/// yields. Afterward, each verifies its own pattern survived. This is the
/// core SMP lazy-switching stress test -- on multi-CPU systems, FPU ownership
/// migrates between CPUs.
fn test_neon_heavy_context_switch() -> bool {
    let parent_pattern: u64 = 0x1111_2222_3333_4444;
    let child_pattern: u64 = 0x5555_6666_7777_8888;

    // Parent loads its pattern
    // SAFETY: Writing to D0 with a known pattern. No memory aliasing concerns.
    unsafe {
        core::arch::asm!(
            "fmov d0, {0:x}",
            in(reg) parent_pattern,
            out("v0") _,
            options(nostack),
        );
    }

    let pid = trona_posix::posix_fork();
    if pid < 0 {
        puts(b"  NEON heavy ctx switch: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // Child: overwrite D0 with child-specific pattern
        // SAFETY: Writing to D0 with a known pattern. No memory aliasing concerns.
        unsafe {
            core::arch::asm!(
                "fmov d0, {0:x}",
                in(reg) child_pattern,
                out("v0") _,
                options(nostack),
            );
        }

        // Yield many times to stress FPU switching
        for _ in 0..10 {
            let _ = trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }

        let child_read: u64;
        // SAFETY: Reading D0 which should hold the child's pattern.
        unsafe {
            core::arch::asm!(
                "fmov {0:x}, d0",
                out(reg) child_read,
                options(nostack),
            );
        }

        if child_read == child_pattern {
            puts(b"  NEON heavy ctx switch (child): OK\n");
            // SAFETY: Exiting the child process with success status.
            unsafe { trona_posix::posix_exit(0); }
        } else {
            let mut lb = LineBuf::new();
            lb.str(b"  NEON heavy ctx switch (child): FAIL (expected ");
            lb.hex(child_pattern);
            lb.str(b", got ");
            lb.hex(child_read);
            lb.str(b")\n");
            lb.flush();
            // SAFETY: Exiting the child process with failure status.
            unsafe { trona_posix::posix_exit(1); }
        }
    }

    // Parent: yield many times, interleaving with child
    for _ in 0..10 {
        let _ = trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }

    let parent_read: u64;
    // SAFETY: Reading D0 which should still hold the parent's pattern.
    unsafe {
        core::arch::asm!(
            "fmov {0:x}, d0",
            out(reg) parent_read,
            options(nostack),
        );
    }

    let mut status: i32 = 0;
    // SAFETY: Waiting for the child process. status pointer is valid.
    unsafe { trona_posix::posix_waitpid(pid, &mut status); }

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
    if !test_neon_survives_syscall() { ok = false; }
    if !test_neon_survives_fork() { ok = false; }
    if !test_neon_all_registers() { ok = false; }
    if !test_neon_no_fpu_threads() { ok = false; }
    if !test_neon_heavy_context_switch() { ok = false; }
    ok
}
