// SPDX-License-Identifier: GPL-2.0-only
//
//! `NtCreatePipe` entry — anonymous-pipe creation. Wire-isomorphic
//! with POSIX `pipe(2)` once the basaltc/win32 shim has narrowed
//! the read / write HANDLE pair to the POSIX `(read_fd, write_fd)`
//! shape.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::owner::VfsState;
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::types::ClientHandle;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let flags = msg.regs[0] as u32;
        match crate::ops::pipe::do_create_anonymous_pipe_pair(state, client, flags) {
            Ok((read_fd, write_fd)) => send_reply_ok_for_client(
                state,
                client,
                reply_lease,
                &[read_fd as u64, write_fd as u64],
            ),
            Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
        }
    }
}
