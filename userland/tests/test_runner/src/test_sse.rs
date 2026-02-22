//! SSE/FPU test module
//!
//! Verifies that XMM registers survive syscalls and context switches
//! via the kernel's lazy FPU switching (#NM + XSAVE/XRSTOR).
//!
//! SPDX-License-Identifier: GPL-2.0-only

use salty::serial;
use salty::serial::LineBuf;
use salty::consts::*;
use salty::posix;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

/// Test: XMM registers survive a syscall (SYS_YIELD)
fn test_xmm_survives_syscall() -> bool {
    let input: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let output: u64;
    unsafe {
        // SAFETY: movq xmm0 ← input, yield, movq output ← xmm0.
        // Kernel is soft-float so XMM0 is untouched during the syscall.
        // If lazy switching is broken, XMM0 would be clobbered.
        core::arch::asm!(
            "movq xmm0, {input}",
            "mov rax, 8",       // SYS_YIELD
            "syscall",
            "movq {output}, xmm0",
            input = in(reg) input,
            output = out(reg) output,
            out("rax") _, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
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
    unsafe {
        core::arch::asm!(
            "movq xmm1, {}",
            in(reg) parent_val,
            options(nostack),
        );
    }

    let pid = unsafe { posix::posix_fork() };
    if pid < 0 {
        puts(b"  XMM survives fork: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // Child: XMM1 should have the parent's value (copied via TCB_COPY_FPU)
        let child_read: u64;
        unsafe {
            core::arch::asm!(
                "movq {}, xmm1",
                out(reg) child_read,
                options(nostack),
            );
        }
        if child_read == parent_val {
            puts(b"  XMM survives fork (child): OK\n");
            unsafe { posix::posix_exit(0); }
        } else {
            let mut lb = LineBuf::new();
            lb.str(b"  XMM survives fork (child): FAIL (expected ");
            lb.hex(parent_val);
            lb.str(b", got ");
            lb.hex(child_read);
            lb.str(b")\n");
            lb.flush();
            unsafe { posix::posix_exit(1); }
        }
    }

    // Parent: verify our XMM1 is still intact after child ran
    // Yield a few times to force context switches
    for _ in 0..3 {
        let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }

    let parent_read: u64;
    unsafe {
        core::arch::asm!(
            "movq {}, xmm1",
            out(reg) parent_read,
            options(nostack),
        );
    }

    // Wait for child
    let mut status: i32 = 0;
    unsafe { posix::posix_waitpid(pid, &mut status); }

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

    unsafe {
        // Load all 16 XMM registers
        core::arch::asm!(
            "movq xmm0, [{p}]",
            "movq xmm1, [{p} + 8]",
            "movq xmm2, [{p} + 16]",
            "movq xmm3, [{p} + 24]",
            "movq xmm4, [{p} + 32]",
            "movq xmm5, [{p} + 40]",
            "movq xmm6, [{p} + 48]",
            "movq xmm7, [{p} + 56]",
            "movq xmm8, [{p} + 64]",
            "movq xmm9, [{p} + 72]",
            "movq xmm10, [{p} + 80]",
            "movq xmm11, [{p} + 88]",
            "movq xmm12, [{p} + 96]",
            "movq xmm13, [{p} + 104]",
            "movq xmm14, [{p} + 112]",
            "movq xmm15, [{p} + 120]",
            p = in(reg) patterns.as_ptr(),
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nostack),
        );

        // Yield 3 times to force context switches
        for _ in 0..3 {
            core::arch::asm!(
                "mov rax, 8",
                "syscall",
                out("rax") _, out("rcx") _, out("r11") _,
                options(nostack),
            );
        }

        // Read all 16 XMM registers back
        core::arch::asm!(
            "movq [{r}], xmm0",
            "movq [{r} + 8], xmm1",
            "movq [{r} + 16], xmm2",
            "movq [{r} + 24], xmm3",
            "movq [{r} + 32], xmm4",
            "movq [{r} + 40], xmm5",
            "movq [{r} + 48], xmm6",
            "movq [{r} + 56], xmm7",
            "movq [{r} + 64], xmm8",
            "movq [{r} + 72], xmm9",
            "movq [{r} + 80], xmm10",
            "movq [{r} + 88], xmm11",
            "movq [{r} + 96], xmm12",
            "movq [{r} + 104], xmm13",
            "movq [{r} + 112], xmm14",
            "movq [{r} + 120], xmm15",
            r = in(reg) results.as_mut_ptr(),
            options(nostack),
        );
    }

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

/// Test: FPU-free forks don't corrupt FPU-using parent's XMM state
///
/// Parent loads XMM0 pattern, forks a child that does NO FPU work (only yields),
/// then verifies its own XMM0 is intact. This validates that lazy switching
/// correctly skips save/restore for threads that never touch FPU.
fn test_xmm_no_fpu_threads() -> bool {
    let parent_val: u64 = 0xBBCC_DDEE_FF00_1122;

    unsafe {
        core::arch::asm!(
            "movq xmm0, {}",
            in(reg) parent_val,
            out("xmm0") _,
            options(nostack),
        );
    }

    // Fork a child that does NO FPU work — only yields
    let pid = posix::posix_fork();
    if pid < 0 {
        puts(b"  XMM no-FPU thread: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // Child: yield several times without touching any XMM register
        for _ in 0..5 {
            let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
        unsafe { posix::posix_exit(0); }
    }

    // Parent: yield to let child run (interleave context switches)
    for _ in 0..5 {
        let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }

    let parent_read: u64;
    unsafe {
        core::arch::asm!(
            "movq {}, xmm0",
            out(reg) parent_read,
            options(nostack),
        );
    }

    let mut status: i32 = 0;
    unsafe { posix::posix_waitpid(pid, &mut status); }

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
/// Both parent and child load distinct patterns into XMM0, then alternate
/// yields. Afterward, each verifies its own pattern survived. This is the
/// core SMP lazy-switching stress test — on multi-CPU systems, FPU ownership
/// migrates between CPUs.
fn test_xmm_heavy_context_switch() -> bool {
    let parent_pattern: u64 = 0x1111_2222_3333_4444;
    let child_pattern: u64 = 0x5555_6666_7777_8888;

    // Parent loads its pattern
    unsafe {
        core::arch::asm!(
            "movq xmm0, {}",
            in(reg) parent_pattern,
            out("xmm0") _,
            options(nostack),
        );
    }

    let pid = posix::posix_fork();
    if pid < 0 {
        puts(b"  XMM heavy ctx switch: FAIL (fork failed)\n");
        return false;
    }

    if pid == 0 {
        // Child: overwrite XMM0 with child-specific pattern
        unsafe {
            core::arch::asm!(
                "movq xmm0, {}",
                in(reg) child_pattern,
                out("xmm0") _,
                options(nostack),
            );
        }

        // Yield many times to stress FPU switching
        for _ in 0..10 {
            let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }

        let child_read: u64;
        unsafe {
            core::arch::asm!(
                "movq {}, xmm0",
                out(reg) child_read,
                options(nostack),
            );
        }

        if child_read == child_pattern {
            puts(b"  XMM heavy ctx switch (child): OK\n");
            unsafe { posix::posix_exit(0); }
        } else {
            let mut lb = LineBuf::new();
            lb.str(b"  XMM heavy ctx switch (child): FAIL (expected ");
            lb.hex(child_pattern);
            lb.str(b", got ");
            lb.hex(child_read);
            lb.str(b")\n");
            lb.flush();
            unsafe { posix::posix_exit(1); }
        }
    }

    // Parent: yield many times, interleaving with child
    for _ in 0..10 {
        let _ = salty::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }

    let parent_read: u64;
    unsafe {
        core::arch::asm!(
            "movq {}, xmm0",
            out(reg) parent_read,
            options(nostack),
        );
    }

    let mut status: i32 = 0;
    unsafe { posix::posix_waitpid(pid, &mut status); }

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
    if !test_xmm_survives_syscall() { ok = false; }
    if !test_xmm_survives_fork() { ok = false; }
    if !test_xmm_all_registers() { ok = false; }
    if !test_xmm_no_fpu_threads() { ok = false; }
    if !test_xmm_heavy_context_switch() { ok = false; }
    ok
}
