// SPDX-License-Identifier: GPL-2.0-only
//
//! NT `NtDeleteFile` entry.
//!
//! Wire layout (`WIN32_NT_DELETE_FILE = 0x557`):
//! ```text
//!   byte 0..24   OBJECT_ATTRIBUTES (header, 24 bytes)
//!   byte 24..32  UNICODE_STRING    (header)
//!   byte 32..    PathBuffer        (UTF-16LE)
//! ```
//!
//! Maps to [`UnlinkKind::Either`] — `meta.unlink` first, fall
//! back to `meta.rmdir` on `EISDIR`.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::{AckReplyIntent, UnlinkKind};
use crate::owner::VfsState;
use crate::owner::pending::WALK_PATH_MAX;
use crate::server::types::ClientHandle;

/// `NtDeleteFile` entry.
pub(crate) unsafe fn handle_nt_delete_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let mut path_utf8 = [0u8; super::nt_decode::NT_PATH_BUFFER_MAX];
        let Some((_oa, path_view)) =
            super::nt_decode::decode_object_attributes_with_path(msg, 0, &mut path_utf8)
        else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
            return;
        };
        let mut canon = [0u8; WALK_PATH_MAX];
        let (drives, drive_cwds) = super::lifecycle::path_context_for_client(state, client);
        let canonical = match super::path::canonicalize_nt_path(
            path_view.utf8,
            &drives,
            &drive_cwds,
            &mut canon,
        ) {
            Ok(p) => p,
            Err(e) => {
                super::reply::emit_ntstatus_error(reply_lease, e);
                return;
            }
        };
        let canonical_len = canonical.bytes.len();
        crate::ops::unlink_leaf::do_unlink_from_bytes(
            state,
            client,
            canonical.anchor_vkey,
            &canon[..canonical_len],
            canonical_len,
            UnlinkKind::Either,
            AckReplyIntent::NtIoStatusBlock,
            reply_lease,
        );
    }
}
