// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_IOCTL` handler.
//!
//! Per-fd device-control op. Resolves the fd to a vnode, then
//! invokes the neutral ioctl helper. The reply payload is raw
//! words returned by the vop: non-trivial ioctls (TIOCGWINSZ,
//! TCGETS, FIONREAD, etc.) expand into `regs[]` words, simple
//! acknowledgements into a single `regs[0]`.
//!
//! Ioctls that need backend round-trips (posix_ttysrv line
//! discipline mutations, blkdrv geometry queries) park on the
//! backend session through the data-op's `VopDataCtx`. The
//! current dispatch returns raw words through the sync Ready arm
//! only — Parked outcomes surface `EAGAIN` until the ioctl wire
//! grows a saved-reply slot threading scaffold.
//!
//! Wire layout:
//! - Request: `regs[0] = fd`, `regs[1] = cmd`, `regs[2] = arg`.
//! - Reply: cmd-dependent.

use trona_kernel::core_types::TronaMsg;

use crate::ops::IoctlReplyIntent;
use crate::owner::VfsState;
use crate::personality::wire::send_reply_err_for_client;
use crate::server::types::ClientHandle;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let cmd = msg.regs[1] as u32;
        let arg = msg.regs[2];

        match crate::personality::posix::device::fb_target_for_fd(state, client, fd) {
            Ok(Some(_)) => {
                crate::personality::posix::device::handle_fb_ioctl_for_fd(
                    state,
                    client,
                    fd,
                    cmd,
                    reply_lease,
                );
                return;
            }
            Ok(None) => {}
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        }

        crate::ops::ioctl::do_ioctl_from_fd(
            state,
            client,
            fd,
            cmd,
            arg,
            IoctlReplyIntent::PosixIoctl,
            reply_lease,
        );
    }
}
