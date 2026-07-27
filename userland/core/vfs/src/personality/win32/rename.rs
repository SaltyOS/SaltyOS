// SPDX-License-Identifier: GPL-2.0-only
//
//! NT `NtRenameFile` entry — fd-based source + path-based dest.
//!
//! Wire layout (`WIN32_NT_RENAME_FILE = 0x55A`):
//! ```text
//!   byte 0..4    FileHandle           (i32 fd, source)
//!   byte 4..8    Flags                (u32, REPLACE_IF_EXISTS bit 0)
//!   byte 8..16   reserved
//!   byte 16..40  OBJECT_ATTRIBUTES    (header — destination dir)
//!   byte 40..48  UNICODE_STRING       (header — new file name)
//!   byte 48..    PathBuffer           (UTF-16LE)
//! ```
//!
//! The handle's vnode resolves to a (parent, name) pair by
//! looking up the directory entry the open object references.
//! The ops helper consumes `(old_parent_vnode_h, old_name)`
//! plus the canonicalised destination path and dispatches
//! `meta.rename` directly — no intermediate path lookup of the
//! source.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::identity::VnodeKey;
use crate::ops::AckReplyIntent;
use crate::owner::VfsState;
use crate::owner::pending::WALK_PATH_MAX;
use crate::server::open_object::{OpenObjectAccess, OpenObjectAnchor, OpenObjectFlags};
use crate::server::types::ClientHandle;

const REPLACE_IF_EXISTS: u32 = 0x1;

pub(crate) unsafe fn handle_nt_rename_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = (msg.regs[0] & 0xFFFF_FFFF) as i32;
        let flags = (msg.regs[0] >> 32) as u32;
        let replace = (flags & REPLACE_IF_EXISTS) != 0;
        let mut path_utf8 = [0u8; super::nt_decode::NT_PATH_BUFFER_MAX];
        let Some((oa, path_view)) =
            super::nt_decode::decode_object_attributes_with_path(msg, 16, &mut path_utf8)
        else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
            return;
        };
        rename_fd_to_path_bytes(
            state,
            client,
            fd,
            oa.header.root_directory,
            path_view.utf8,
            replace,
            reply_lease,
        );
    }
}

pub(crate) unsafe fn rename_fd_to_path_bytes(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    root_directory: u64,
    path_utf8: &[u8],
    replace: bool,
    reply_lease: ReplyLease,
) {
    unsafe {
        let old_anchor = match source_anchor_from_fd(state, client, fd) {
            Ok(anchor) => anchor,
            Err(e) => {
                super::reply::emit_ntstatus_error(reply_lease, e);
                return;
            }
        };
        let mut path_buf = [0u8; WALK_PATH_MAX];
        let (anchor_vkey, path_len) = match destination_path(
            state,
            client,
            old_anchor.parent_vkey,
            root_directory,
            path_utf8,
            &mut path_buf,
        ) {
            Ok(v) => v,
            Err(e) => {
                super::reply::emit_ntstatus_error(reply_lease, e);
                return;
            }
        };
        crate::ops::rename_link::do_rename_from_anchor_to_path(
            state,
            client,
            old_anchor,
            anchor_vkey,
            &path_buf[..path_len],
            path_len,
            !replace,
            AckReplyIntent::NtIoStatusBlock,
            reply_lease,
        );
    }
}

pub(crate) unsafe fn link_fd_to_path_bytes(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    root_directory: u64,
    path_utf8: &[u8],
    replace: bool,
    reply_lease: ReplyLease,
) {
    unsafe {
        let (target_vkey, relative_anchor_vkey) =
            match source_link_context_from_fd(state, client, fd) {
                Ok(ctx) => ctx,
                Err(e) => {
                    super::reply::emit_ntstatus_error(reply_lease, e);
                    return;
                }
            };
        if root_directory == 0 && is_relative_nt_path(path_utf8) && !relative_anchor_vkey.is_valid()
        {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::NotSup);
            return;
        }
        let mut path_buf = [0u8; WALK_PATH_MAX];
        let (anchor_vkey, path_len) = match destination_path(
            state,
            client,
            relative_anchor_vkey,
            root_directory,
            path_utf8,
            &mut path_buf,
        ) {
            Ok(v) => v,
            Err(e) => {
                super::reply::emit_ntstatus_error(reply_lease, e);
                return;
            }
        };
        crate::ops::rename_link::do_link_from_vkey_to_path(
            state,
            client,
            target_vkey,
            anchor_vkey,
            &path_buf[..path_len],
            path_len,
            !replace,
            AckReplyIntent::NtIoStatusBlock,
            reply_lease,
        );
    }
}

fn source_anchor_from_fd(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<OpenObjectAnchor, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let open_h = state
        .open_object_at(client, fd as usize)
        .ok_or(VfsError::BadF)?;
    let obj = state.open_objects.get(open_h).ok_or(VfsError::BadF)?;
    if (obj.access & OpenObjectAccess::DELETE) == 0 {
        return Err(VfsError::Acces);
    }
    let named = state
        .open_object_named_states
        .get(obj.named_state)
        .ok_or(VfsError::NotSup)?;
    if named.anchor.is_valid() {
        Ok(named.anchor)
    } else {
        Err(VfsError::NotSup)
    }
}

fn source_link_context_from_fd(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<(VnodeKey, VnodeKey), VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let open_h = state
        .open_object_at(client, fd as usize)
        .ok_or(VfsError::BadF)?;
    let obj = state.open_objects.get(open_h).ok_or(VfsError::BadF)?;
    let target_vkey = state
        .vnodes
        .get(obj.vnode)
        .map(|v| v.key)
        .filter(|key| key.is_valid())
        .ok_or(VfsError::BadF)?;
    let relative_anchor_vkey = state
        .open_object_named_states
        .get(obj.named_state)
        .map(|named| named.anchor.parent_vkey)
        .filter(|key| key.is_valid())
        .unwrap_or(VnodeKey::NONE);
    Ok((target_vkey, relative_anchor_vkey))
}

fn destination_path<'a>(
    state: &VfsState,
    client: ClientHandle,
    relative_anchor_vkey: VnodeKey,
    root_directory: u64,
    path_utf8: &[u8],
    out: &'a mut [u8; WALK_PATH_MAX],
) -> Result<(VnodeKey, usize), VfsError> {
    if path_utf8.is_empty() || path_utf8.len() > out.len() {
        return Err(VfsError::Inval);
    }
    if root_directory != 0 {
        let root_vkey = directory_vkey_from_fd(state, client, root_directory as i32)?;
        let len = normalise_relative_path(path_utf8, out)?;
        return Ok((root_vkey, len));
    }
    if is_relative_nt_path(path_utf8) {
        let len = normalise_relative_path(path_utf8, out)?;
        if !relative_anchor_vkey.is_valid() {
            return Err(VfsError::NotSup);
        }
        return Ok((relative_anchor_vkey, len));
    }
    let (drives, drive_cwds) = super::lifecycle::path_context_for_client(state, client);
    let canonical =
        unsafe { super::path::canonicalize_nt_path(path_utf8, &drives, &drive_cwds, out)? };
    Ok((canonical.anchor_vkey, canonical.bytes.len()))
}

fn directory_vkey_from_fd(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<VnodeKey, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let open_h = state
        .open_object_at(client, fd as usize)
        .ok_or(VfsError::BadF)?;
    let obj = state.open_objects.get(open_h).ok_or(VfsError::BadF)?;
    if (obj.flags & OpenObjectFlags::O_DIRECTORY) == 0 {
        return Err(VfsError::NotDir);
    }
    state
        .vnodes
        .get(obj.vnode)
        .map(|v| v.key)
        .filter(|key| key.is_valid())
        .ok_or(VfsError::BadF)
}

fn is_relative_nt_path(path: &[u8]) -> bool {
    !(path.first().copied() == Some(b'/')
        || path.first().copied() == Some(b'\\')
        || (path.len() >= 2 && path[1] == b':'))
}

fn normalise_relative_path(src: &[u8], out: &mut [u8; WALK_PATH_MAX]) -> Result<usize, VfsError> {
    if src.len() > out.len() {
        return Err(VfsError::NameTooLong);
    }
    let len =
        unsafe { super::path::normalize_separators(src.as_ptr(), src.len(), out.as_mut_ptr()) };
    for component in out[..len].split(|b| *b == b'/') {
        if component.is_empty() {
            continue;
        }
        let component = super::path::trim_trailing_dots_spaces(component);
        super::path::validate_no_forbidden_chars(component)?;
    }
    Ok(len)
}
