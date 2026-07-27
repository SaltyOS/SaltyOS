// SPDX-License-Identifier: GPL-2.0-only
//
//! `NtCreateSection` over a file handle — produces an MO bound to
//! the vnode for subsequent client-side mapping. The basaltc/win32
//! shim wraps the returned `mo_cap` into an NT section HANDLE
//! before returning to the win32 caller.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::owner::VfsState;
use crate::personality::wire::send_reply_err_for_client;
use crate::server::types::ClientHandle;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = match i32::try_from(msg.regs[0]) {
            Ok(v) => v,
            Err(_) => {
                send_reply_err_for_client(
                    state,
                    client,
                    reply_lease,
                    crate::core::error::VfsError::BadF,
                );
                return;
            }
        };
        match crate::ops::backing_mo::do_get_backing_mo_from_fd(state, client, fd) {
            Ok(backing) => {
                let mut out = TronaMsg::default();
                out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
                out.regs[0] = 0;
                out.regs[1] = backing.size;
                out.regs[2] = 0;
                out.length = 3;
                // vfs keeps `backing.mo_cap` (the section's MO); the win32
                // caller gets a disposable, non-executable copy. A mapped
                // section MO is data; executable code is conferred via ldsrv
                // (and the MO carries no EXECUTE after K1 anyway).
                let cap = match trona_runtime::core::slot_alloc::dup_for_transfer_with_rights(
                    trona_runtime::core::slot_alloc::resolved_cap_ref(backing.mo_cap),
                    (uapi::KERNITE_RIGHT_ALL & !uapi::KERNITE_RIGHT_EXECUTE) as u64,
                ) {
                    Some(c) => c,
                    None => {
                        send_reply_err_for_client(
                            state,
                            client,
                            reply_lease,
                            crate::core::error::VfsError::NoMem,
                        );
                        return;
                    }
                };
                crate::owner::op::reply_send_with_cap(reply_lease, &out, cap);
            }
            Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
        }
    }
}
