// SPDX-License-Identifier: GPL-2.0-only
//
//! `NtDeviceIoControlFile` entry — wire-isomorphic with POSIX
//! `ioctl` once the basaltc/win32 shim has flattened the
//! `IO_STATUS_BLOCK` and `(InputBuffer, InputBufferLength,
//! OutputBuffer, OutputBufferLength)` quadruple into the POSIX
//! `(fd, request, argp)` triple.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::ops::IoctlReplyIntent;
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
        crate::ops::ioctl::do_ioctl_from_fd(
            state,
            client,
            fd,
            cmd,
            arg,
            IoctlReplyIntent::NtDeviceIoControlFile,
            reply_lease,
        );
    }
}
