//! Raw system call interface
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Inline assembly wrappers for the SaltyOS syscall ABI.

use crate::types::SaltyResult;

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
