// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX `VFS_PIPE` / `VFS_PIPE2` entry.
//!
//! The pipe backing lives in `core::pipe`; this module only owns
//! POSIX wire decode and reply emission.

use trona_kernel::core_types::TronaMsg;

use crate::owner::VfsState;
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::types::ClientHandle;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        handle_pipe(state, client, msg, reply_lease);
    }
}

pub(crate) unsafe fn handle_pipe(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
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
