// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_CLOSE` entry. Wire layout: `regs[0] = fd`.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::ops::AckReplyIntent;
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
        crate::ops::close::do_close_fd(state, client, fd, AckReplyIntent::PosixAck, reply_lease);
    }
}
