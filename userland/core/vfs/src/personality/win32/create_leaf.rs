// SPDX-License-Identifier: GPL-2.0-only
//
//! NT path-based create-leaf entries —
//! `NtCreateSymbolicLinkObject` / `NtCreateNamedPipeFile`.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::{AckReplyIntent, CreateLeafKind};
use crate::owner::VfsState;
use crate::owner::namei_aux::{NameiAuxHandle, NameiAuxState};
use crate::owner::pending::WALK_PATH_MAX;
use crate::server::types::ClientHandle;

/// `NtCreateSymbolicLinkObject` — wire packs OBJECT_ATTRIBUTES at
/// byte 0 (link path) + UNICODE_STRING + UTF-16 buffer for the
/// target after.
pub(crate) unsafe fn handle_nt_create_symbolic_link_object(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        // Decode link path (OBJECT_ATTRIBUTES at byte 0).
        let mut link_utf8 = [0u8; super::nt_decode::NT_PATH_BUFFER_MAX];
        let Some((_oa, link_view)) =
            super::nt_decode::decode_object_attributes_with_path(msg, 0, &mut link_utf8)
        else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
            return;
        };
        let link_oa_size = ::core::mem::size_of::<super::types::ObjectAttributesHeader>();
        let link_usz_size = ::core::mem::size_of::<super::types::UnicodeStringHeader>();
        let link_utf16_len = link_view.header.length as usize;
        let target_usz_off = 0 + link_oa_size + link_usz_size + link_utf16_len;
        // Round up to 8-byte alignment.
        let target_usz_off = (target_usz_off + 7) & !7;

        // Decode target UNICODE_STRING.
        let mut target_utf8 = [0u8; crate::owner::pending::WALK_SYMLINK_TARGET_MAX];
        let Some(target_view) =
            super::nt_decode::decode_unicode_string(msg, target_usz_off, &mut target_utf8)
        else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
            return;
        };
        let target_len = target_view.utf8.len();

        // Canonicalise link path.
        let mut canon = [0u8; WALK_PATH_MAX];
        let (drives, drive_cwds) = super::lifecycle::path_context_for_client(state, client);
        let canonical = match super::path::canonicalize_nt_path(
            link_view.utf8,
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

        // Stash target bytes in the namei aux slot.
        let Some(aux_h) = state.namei_aux.alloc() else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::NoMem);
            return;
        };
        if let Some(slot) = state.namei_aux.get_mut(aux_h) {
            let mut buf = [0u8; crate::owner::pending::WALK_SYMLINK_TARGET_MAX];
            let take = target_len.min(buf.len());
            buf[..take].copy_from_slice(&target_utf8[..take]);
            *slot = NameiAuxState::Symlink {
                target: buf,
                target_len: take as u16,
            };
        }

        crate::ops::create_leaf::do_create_leaf_from_bytes(
            state,
            client,
            canonical.anchor_vkey,
            &canon[..canonical_len],
            canonical_len,
            CreateLeafKind::Symlink { mode: 0o777 },
            aux_h,
            AckReplyIntent::NtIoStatusBlock,
            reply_lease,
        );
    }
}

/// `NtCreateNamedPipeFile` — OBJECT_ATTRIBUTES + ShareAccess +
/// CreateDisposition + CreateOptions + pipe parameters.
/// Maps to POSIX `mkfifo(path, mode)` — pipe parameters
/// (read mode / completion mode / max instances / etc.) are
/// dropped because saltyos pipes are byte-stream FIFOs.
pub(crate) unsafe fn handle_nt_create_named_pipe_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        // OBJECT_ATTRIBUTES at byte 32 (after access / share /
        // disposition / options + pipe-specific u32 fields).
        let mut path_utf8 = [0u8; super::nt_decode::NT_PATH_BUFFER_MAX];
        let Some((_oa, path_view)) =
            super::nt_decode::decode_object_attributes_with_path(msg, 32, &mut path_utf8)
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

        crate::ops::create_leaf::do_create_leaf_from_bytes(
            state,
            client,
            canonical.anchor_vkey,
            &canon[..canonical_len],
            canonical_len,
            CreateLeafKind::Mkfifo { mode: 0o644 },
            NameiAuxHandle::INVALID,
            AckReplyIntent::NtIoStatusBlock,
            reply_lease,
        );
    }
}
