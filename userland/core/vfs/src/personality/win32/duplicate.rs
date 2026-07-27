// SPDX-License-Identifier: GPL-2.0-only
//
//! NT `NtDuplicateObject` entry — same-process duplicate.
//!
//! Wire layout (`WIN32_NT_DUPLICATE_OBJECT = 0x54E`):
//! - `regs[0]` — source handle (i32 fd).
//! - `regs[1]` — target handle (i32 fd, `-1` = lowest free).
//! - `regs[2]` — options (currently ignored —
//!   `DUPLICATE_SAME_ACCESS` is the only mode the saltyos open
//!   path supports; `DUPLICATE_CLOSE_SOURCE` is left to the
//!   basaltc/win32 shim to apply post-duplicate).

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
        let source = msg.regs[0] as i32;
        let target = msg.regs[1] as i32;
        if target < 0 {
            crate::ops::dup::do_dup_lowest(
                state,
                client,
                source,
                /* cloexec = */ false,
                AckReplyIntent::NtIoStatusBlock,
                reply_lease,
            );
        } else {
            crate::ops::dup::do_dup_to_target(
                state,
                client,
                source,
                target,
                /* cloexec = */ false,
                AckReplyIntent::NtIoStatusBlock,
                reply_lease,
            );
        }
    }
}
