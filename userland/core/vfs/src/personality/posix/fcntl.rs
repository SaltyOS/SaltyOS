// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_FCNTL` entry. `regs[0]=fd`, `regs[1]=cmd`, `regs[2]=arg`.

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
        let cmd = msg.regs[1] as u32;
        let arg = msg.regs[2];
        crate::ops::fcntl::do_fcntl(
            state,
            client,
            fd,
            cmd,
            arg,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}
