// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_DUP` / `VFS_DUP2` / `VFS_DUP3` entries.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::ops::AckReplyIntent;
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

/// `VFS_DUP` — `regs[0] = old_fd`. Reply `regs[0] = new_fd`.
pub(crate) unsafe fn handle_dup(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let old_fd = msg.regs[0] as i32;
        crate::ops::dup::do_dup_lowest(
            state,
            client,
            old_fd,
            /* cloexec = */ false,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}

/// `VFS_DUP2` — `regs[0] = old_fd`, `regs[1] = new_fd`.
pub(crate) unsafe fn handle_dup2(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let old_fd = msg.regs[0] as i32;
        let new_fd = msg.regs[1] as i32;
        crate::ops::dup::do_dup_to_target(
            state,
            client,
            old_fd,
            new_fd,
            /* cloexec = */ false,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}

/// `VFS_DUP3` — `regs[0] = old_fd`, `regs[1] = new_fd`,
/// `regs[2] = flags` (POSIX `O_CLOEXEC` bit).
pub(crate) unsafe fn handle_dup3(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let old_fd = msg.regs[0] as i32;
        let new_fd = msg.regs[1] as i32;
        let flags = msg.regs[2] as u32;
        const POSIX_O_CLOEXEC: u32 = 0x80000;
        crate::ops::dup::do_dup_to_target(
            state,
            client,
            old_fd,
            new_fd,
            (flags & POSIX_O_CLOEXEC) != 0,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}
