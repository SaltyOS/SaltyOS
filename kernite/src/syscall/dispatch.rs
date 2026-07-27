// SPDX-License-Identifier: GPL-2.0-only
//! Top-level syscall dispatch.
//!
//! kernite exposes a single syscall: `Syscall::Invoke`. Every per-object
//! operation routes through it via an invoke label against an explicit
//! capability. There is no ambient kernel authority — randomness,
//! shutdown, clock, system accounting, and debug output are all reached
//! through dedicated capability objects.

use super::{Syscall, SyscallResult, invoke};

pub(crate) fn handle(
    syscall: u64,
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> SyscallResult {
    let syscall_num = match Syscall::try_from(syscall) {
        Ok(s) => s,
        Err(e) => return SyscallResult::err(e),
    };

    match syscall_num {
        Syscall::Invoke => invoke::syscall_invoke(cap_ptr, msg_info, mr0, mr1, mr2, mr3),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_handle_rust(
    syscall: u64,
    cap_ptr: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
) -> SyscallResult {
    let result = handle(syscall, cap_ptr, arg0, arg1, arg2, arg3, arg4);
    crate::object::drain_reaper();
    result
}
