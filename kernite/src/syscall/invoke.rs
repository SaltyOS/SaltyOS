// SPDX-License-Identifier: GPL-2.0-only
//! Capability invoke dispatch.

use super::{SyscallResult, lookup_invoke_target_locked};

pub(super) fn syscall_invoke(
    cap_ptr: u64,
    label: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> SyscallResult {
    let _ = crate::arch::next_invoke_seq();

    let target = match lookup_invoke_target_locked(cap_ptr) {
        Ok(t) => t,
        Err(e) => return SyscallResult::err(e),
    };

    target.invoke(label, arg0, arg1, arg2, arg3)
}
