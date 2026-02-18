//! Raw system call interface
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Single inline-assembly wrapper for all SaltyOS kernel syscalls.
//!
//! # Register ABI
//!
//! | Register | Direction | Purpose |
//! |----------|-----------|---------|
//! | `rax` | in/out | Syscall number in, error code out |
//! | `rdi` | in | Argument 0 (e.g. cap slot) |
//! | `rsi` | in | Argument 1 (e.g. msginfo) |
//! | `rdx` | in/out | Argument 2 in, return value out |
//! | `r10` | in | Argument 3 |
//! | `r8` | in | Argument 4 |
//! | `r9` | in | Argument 5 |
//! | `rcx` | clobbered | Kernel overwrites with return RIP |
//! | `r11` | clobbered | Kernel overwrites with saved RFLAGS |
//!
//! `options(nostack)` is used because the `syscall` instruction does not
//! touch the user stack -- the kernel switches to its own per-thread stack.

use crate::types::SaltyResult;

/// Issue a raw syscall with up to 6 arguments.
///
/// Returns a [`SaltyResult`] with `error` (0 = success) and `value`
/// (syscall-specific return payload).
#[inline(always)]
pub fn syscall(
    num: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> SaltyResult {
    let error: u64;
    let value: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num => error,
            in("rdi") a0,
            in("rsi") a1,
            inlateout("rdx") a2 => value,
            in("r10") a3,
            in("r8") a4,
            in("r9") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    SaltyResult { error, value }
}

/// Futex wait: block if `*addr == expected`, return 0 on wake.
/// Returns SALTY_WOULD_BLOCK (9) if value changed.
#[inline]
pub fn futex_wait(addr: *const u32, expected: u32) -> u64 {
    syscall(
        crate::consts::SYS_FUTEX,
        addr as u64,
        crate::consts::FUTEX_WAIT,
        expected as u64,
        0,
        0,
        0,
    )
    .error
}

/// Futex wake: wake up to `count` threads waiting on `addr`.
/// Returns the number of threads actually woken.
#[inline]
pub fn futex_wake(addr: *const u32, count: u32) -> u64 {
    syscall(
        crate::consts::SYS_FUTEX,
        addr as u64,
        crate::consts::FUTEX_WAKE,
        count as u64,
        0,
        0,
        0,
    )
    .value
}
