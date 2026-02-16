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

pub fn run() -> bool {
    puts(b"[test_sse] Running SSE tests\n");
    let mut ok = true;
    if !test_xmm_survives_syscall() { ok = false; }
    if !test_xmm_survives_fork() { ok = false; }
    ok
}
