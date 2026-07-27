// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_GETDENTS` entry.
//!
//! Wire layout:
//! - `regs[0]` — fd (i32).
//! - `regs[1]` — cookie (u64) — opaque per-call cursor; the
//!   first call passes `0`, subsequent calls echo back the
//!   `next_cursor` from the previous reply.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::ops::ReadDirReplyIntent;
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let cookie = msg.regs[1];
        crate::ops::dir::do_readdir_from_fd(
            state,
            client,
            fd,
            cookie,
            ReadDirReplyIntent::PosixGetDents,
            reply_lease,
        );
    }
}
