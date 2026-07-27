// SPDX-License-Identifier: GPL-2.0-only
//! Inline IPC fastpath dispatched by the arch syscall entry.
//!
//! The arch entry calls `kernite_try_sys_invoke_fastpath` with the
//! User ABI tuple after marshalling it into System V; on a hit the
//! helper writes the resulting `SyscallResult` into a stack-allocated
//! out buffer and returns 1, on a miss returns 0 so the entry stub
//! falls through to `syscall_handle_rust`.
//!
//! Coverage:
//! * `MP_WRITE` — record-only, length ≤ 2, no carriers, peer parked
//!   on `PipeRead` or mailbox-eligible. Reply-marked writes use the
//!   slowpath because they may complete an `MP_CALL` waiter by txid.
//! * `MP_READ`  — mailbox-only peek + commit; ring path bails.

use super::Syscall;
use super::SyscallResult;
use super::cspace;

/// Try to handle a `SYS_INVOKE` on the inline fastpath. Returns 1 if
/// the call was handled (with `*out` populated); 0 means the slowpath
/// must run with no observable side effects from the fastpath try.
///
/// Stack-arg signature mirrors the System V translation the arch
/// stub performs — see `kernite/src/arch/x86_64/syscall.S` and the
/// aarch64 SVC handler in `kernite/src/arch/aarch64/exceptions.rs`.
///
/// # Safety
/// `out` must be a writeable, properly-aligned `SyscallResult` slot
/// owned by the caller for the duration of the call; the helper
/// writes to `*out` only when it returns 1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernite_try_sys_invoke_fastpath(
    syscall: u64,
    cap_ptr: u64,
    label: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    _arg3: u64,
    out: *mut SyscallResult,
) -> u64 {
    if syscall != Syscall::Invoke as u64 {
        return 0;
    }

    // Coarse label gate before the cap lookup — non-fastpath
    // labels skip the CAP_LOCK / type-check altogether.
    let mp_write = uapi::KERNITE_INV_MP_WRITE as u64;
    let mp_read = uapi::KERNITE_INV_MP_READ as u64;
    if label != mp_write && label != mp_read {
        return 0;
    }

    // Resolve the cap under CAP_LOCK. Bailing on lookup failure
    // (bad slot, wrong type, missing rights) drops to the slowpath
    // so the standard error path produces the canonical
    // `SyscallError`.
    let cap = match cspace::lookup_cap_locked(cap_ptr) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    // Per-label dispatch: each variant validates the obj_type its
    // helper expects, then forwards to the cspace::try_*_fastpath.
    // A type mismatch yields `None` (bail to slowpath) so the
    // standard error path mints the right `SyscallError`.
    let outcome: Option<SyscallResult> = if label == mp_write {
        if cap.obj_type == crate::cap::ObjectType::MessagePipe {
            cspace::try_mp_write_fastpath(&cap, arg0, arg1, arg2)
        } else {
            None
        }
    } else if label == mp_read {
        if cap.obj_type == crate::cap::ObjectType::MessagePipe {
            cspace::try_mp_read_fastpath(&cap)
        } else {
            None
        }
    } else {
        let _ = cap_ptr;
        None
    };

    match outcome {
        Some(result) => {
            // Advance the per-CPU invoke counter on hit only —
            // slowpath (`syscall_invoke`) advances it as its first
            // action, so miss must NOT touch it lest the seq
            // double-bumps when control falls through.
            let _ = crate::arch::next_invoke_seq();
            unsafe {
                *out = result;
            }
            // Match `syscall_handle_rust`'s post-handle reaper drain
            // so deferred object cleanup proceeds at the same cadence
            // as the slowpath.
            crate::object::drain_reaper();
            1
        }
        None => 0,
    }
}
