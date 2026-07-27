// SPDX-License-Identifier: GPL-2.0-only
//
//! NT attribute-query entries:
//! `NtQueryInformationFile` / `NtQueryAttributesFile` /
//! `NtQueryFullAttributesFile`.
//!
//! ## NtQueryInformationFile (`WIN32_NT_QUERY_INFORMATION_FILE = 0x545`)
//! ```text
//!   byte 0..4    FileHandle           (u32 fd)
//!   byte 4..8    Length               (u32, caller buffer cap)
//!   byte 8..12   FileInformationClass (u32)
//! ```
//!
//! ## NtQueryAttributesFile (`WIN32_NT_QUERY_ATTRIBUTES_FILE = 0x558`)
//! `NtQueryFullAttributesFile (0x559)` shares the wire shape:
//! ```text
//!   byte 0..24   OBJECT_ATTRIBUTES (header, 24 bytes)
//!   byte 24..32  UNICODE_STRING    (header)
//!   byte 32..    PathBuffer        (UTF-16LE)
//! ```

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::AttrReplyIntent;
use crate::owner::VfsState;
use crate::owner::pending::WALK_PATH_MAX;
use crate::server::types::ClientHandle;

// NT FILE_INFORMATION_CLASS values.
const FILE_BASIC_INFORMATION: u32 = 4;
const FILE_STANDARD_INFORMATION: u32 = 5;
const FILE_INTERNAL_INFORMATION: u32 = 6;
const FILE_EA_INFORMATION: u32 = 7;
const FILE_ACCESS_INFORMATION: u32 = 8;
const FILE_NAME_INFORMATION: u32 = 9;
const FILE_POSITION_INFORMATION: u32 = 14;
const FILE_MODE_INFORMATION: u32 = 16;
const FILE_ALIGNMENT_INFORMATION: u32 = 17;
const FILE_ALL_INFORMATION: u32 = 18;
const FILE_NETWORK_OPEN_INFORMATION: u32 = 34;

/// `NtQueryInformationFile` entry.
pub(crate) unsafe fn handle_nt_query_information_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let handle = (msg.regs[0] & 0xFFFF_FFFF) as i32;
        let _length = (msg.regs[0] >> 32) as u32;
        let info_class = (msg.regs[1] & 0xFFFF_FFFF) as u32;

        if handle < 0 {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::BadF);
            return;
        }
        let Some(open_h) = state.open_object_at(client, handle as usize) else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::BadF);
            return;
        };
        let (vnode_h, fd_offset) = match state.open_objects.get(open_h) {
            Some(obj) => (obj.vnode, obj.offset),
            None => {
                super::reply::emit_ntstatus_error(reply_lease, VfsError::BadF);
                return;
            }
        };

        // FilePositionInformation is a fd attribute, not a vop-
        // derived one. Emit directly without a getattr round trip.
        if info_class == FILE_POSITION_INFORMATION {
            super::reply::emit_file_position_information(reply_lease, fd_offset);
            return;
        }

        let reply_intent = match nt_info_class_to_reply_intent(info_class) {
            Some(i) => i,
            None => {
                super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
                return;
            }
        };

        crate::ops::attr::do_getattr_for_vnode(state, client, vnode_h, reply_intent, reply_lease);
    }
}

/// `NtQueryAttributesFile` / `NtQueryFullAttributesFile` entry.
///
/// Both are path-based; the Full variant additionally surfaces
/// allocation size + index in the reply (so we route to
/// `NtFileNetworkOpenInformation`), while the plain variant
/// returns just `FILE_BASIC_INFORMATION`.
pub(crate) unsafe fn handle_nt_query_attributes_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        decode_path_and_dispatch(
            state,
            client,
            msg,
            AttrReplyIntent::NtFileBasicInformation,
            reply_lease,
        );
    }
}

/// `NtQueryFullAttributesFile` entry — same wire shape as
/// `NtQueryAttributesFile`, but the reply class is
/// `FILE_NETWORK_OPEN_INFORMATION` (basic + standard merged).
pub(crate) unsafe fn handle_nt_query_full_attributes_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        decode_path_and_dispatch(
            state,
            client,
            msg,
            AttrReplyIntent::NtFileNetworkOpenInformation,
            reply_lease,
        );
    }
}

unsafe fn decode_path_and_dispatch(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_intent: AttrReplyIntent,
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
        crate::ops::attr::do_getattr_from_bytes(
            state,
            client,
            canonical.anchor_vkey,
            &canon[..canonical_len],
            canonical_len,
            /* follow_leaf_symlink = */ true,
            reply_intent,
            reply_lease,
        );
    }
}

fn nt_info_class_to_reply_intent(class: u32) -> Option<AttrReplyIntent> {
    Some(match class {
        FILE_BASIC_INFORMATION => AttrReplyIntent::NtFileBasicInformation,
        FILE_STANDARD_INFORMATION => AttrReplyIntent::NtFileStandardInformation,
        FILE_INTERNAL_INFORMATION => AttrReplyIntent::NtFileInternalInformation,
        FILE_EA_INFORMATION => AttrReplyIntent::NtFileEaInformation,
        FILE_ACCESS_INFORMATION => AttrReplyIntent::NtFileAccessInformation,
        FILE_NAME_INFORMATION => AttrReplyIntent::NtFileNameInformation,
        FILE_MODE_INFORMATION => AttrReplyIntent::NtFileModeInformation,
        FILE_ALIGNMENT_INFORMATION => AttrReplyIntent::NtFileAlignmentInformation,
        FILE_ALL_INFORMATION => AttrReplyIntent::NtFileAllInformation,
        FILE_NETWORK_OPEN_INFORMATION => AttrReplyIntent::NtFileNetworkOpenInformation,
        _ => return None,
    })
}
