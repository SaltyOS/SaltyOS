// SPDX-License-Identifier: GPL-2.0-only
//
//! `NtLockFile` / `NtUnlockFile` entry — byte-range advisory
//! locks on a file.
//!
//! NT wire (regs[]):
//! - `regs[0]` low 32 bits: `FileHandle` (i32 fd)
//! - `regs[0]` bit 32: `FailImmediately` (0 = wait, 1 = no-wait)
//! - `regs[0]` bit 33: `ExclusiveLock` (0 = shared, 1 = exclusive)
//! - `regs[1]`: `ByteOffset` (u64)
//! - `regs[2]`: `Length` (u64, `0` = to EOF)
//! - `regs[3]` low 32 bits: `Key` (u32, currently ignored — NT
//!   uses it to disambiguate matching unlock calls; saltyos
//!   matches on `(owner, start, length)`)
//!
//! `NtUnlockFile` shares the wire shape minus the flag bits.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::byte_range_lock::ByteRangeLockKind;
use crate::ops::AckReplyIntent;
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

const NT_LOCK_FAIL_IMMEDIATELY: u64 = 1 << 32;
const NT_LOCK_EXCLUSIVE: u64 = 1 << 33;

pub(crate) unsafe fn handle_nt_lock_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let fail_immediately = (msg.regs[0] & NT_LOCK_FAIL_IMMEDIATELY) != 0;
        let exclusive = (msg.regs[0] & NT_LOCK_EXCLUSIVE) != 0;
        let byte_offset = msg.regs[1];
        let length = msg.regs[2];
        let kind = if exclusive {
            ByteRangeLockKind::Exclusive
        } else {
            ByteRangeLockKind::Shared
        };
        crate::ops::lock::do_byte_range_lock(
            state,
            client,
            fd,
            byte_offset,
            length,
            kind,
            fail_immediately,
            AckReplyIntent::NtIoStatusBlock,
            reply_lease,
        );
    }
}

pub(crate) unsafe fn handle_nt_unlock_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let byte_offset = msg.regs[1];
        let length = msg.regs[2];
        crate::ops::lock::do_byte_range_unlock(
            state,
            client,
            fd,
            byte_offset,
            length,
            AckReplyIntent::NtIoStatusBlock,
            reply_lease,
        );
    }
}
