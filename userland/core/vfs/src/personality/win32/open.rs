// SPDX-License-Identifier: GPL-2.0-only
//
//! NT `NtCreateFile` / `NtOpenFile` entries.
//!
//! Wire layouts:
//!
//! ## NtCreateFile (`WIN32_NT_CREATE_FILE = 0x540`)
//! ```text
//!   byte 0..4    DesiredAccess        (u32)
//!   byte 4..8    FileAttributes       (u32)
//!   byte 8..12   ShareAccess          (u32)
//!   byte 12..16  CreateDisposition    (u32)
//!   byte 16..20  CreateOptions        (u32)
//!   byte 20..24  reserved (pad)
//!   byte 24..32  AllocationSize       (LARGE_INTEGER, i64)
//!   byte 32..56  OBJECT_ATTRIBUTES    (header, 24 bytes)
//!   byte 56..64  UNICODE_STRING       (header, 8 bytes)
//!   byte 64..    PathBuffer           (UTF-16LE)
//! ```
//!
//! ## NtOpenFile (`WIN32_NT_OPEN_FILE = 0x541`)
//! ```text
//!   byte 0..4    DesiredAccess        (u32)
//!   byte 4..8    ShareAccess          (u32)
//!   byte 8..12   OpenOptions          (u32)
//!   byte 12..16  reserved (pad)
//!   byte 16..40  OBJECT_ATTRIBUTES    (header, 24 bytes)
//!   byte 40..48  UNICODE_STRING       (header, 8 bytes)
//!   byte 48..    PathBuffer           (UTF-16LE)
//! ```

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::{CreateMode, OpenReplyIntent, VfsOpenSpec};
use crate::owner::VfsState;
use crate::owner::pending::WALK_PATH_MAX;
use crate::server::types::ClientHandle;

/// `NtCreateFile` entry.
pub(crate) unsafe fn handle_nt_create_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let desired_access = (msg.regs[0] & 0xFFFF_FFFF) as u32;
        let file_attributes = (msg.regs[0] >> 32) as u32;
        let share_access = (msg.regs[1] & 0xFFFF_FFFF) as u32;
        let creation_disposition = (msg.regs[1] >> 32) as u32;
        let create_options = (msg.regs[2] & 0xFFFF_FFFF) as u32;
        let _ = file_attributes;

        decode_and_dispatch(
            state,
            client,
            msg,
            /* oa_byte_off = */ 32,
            desired_access,
            share_access,
            creation_disposition,
            create_options,
            OpenReplyIntent::NtCreateFile {
                desired_access,
                share_access,
                create_options,
            },
            reply_lease,
        );
    }
}

/// `NtOpenFile` entry — strict-existing variant.
///
/// CreateDisposition is forced to `FILE_OPEN` regardless of the
/// caller's wire bits (the NT API does not let `NtOpenFile`
/// caller pass a disposition; we honour that on the
/// vfs side too).
pub(crate) unsafe fn handle_nt_open_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let desired_access = (msg.regs[0] & 0xFFFF_FFFF) as u32;
        let share_access = (msg.regs[0] >> 32) as u32;
        let open_options = (msg.regs[1] & 0xFFFF_FFFF) as u32;

        decode_and_dispatch(
            state,
            client,
            msg,
            /* oa_byte_off = */ 16,
            desired_access,
            share_access,
            super::consts::FILE_OPEN,
            open_options,
            OpenReplyIntent::NtOpenFile {
                desired_access,
                share_access,
                create_options: open_options,
            },
            reply_lease,
        );
    }
}

/// Shared decode-and-dispatch path between `NtCreateFile` and
/// `NtOpenFile`. Both ops project their wire shape onto the same
/// `(VfsOpenSpec, OpenReplyIntent)` pair before calling into
/// `ops::open::do_namei_open_from_bytes`.
unsafe fn decode_and_dispatch(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    oa_byte_off: usize,
    desired_access: u32,
    share_access: u32,
    creation_disposition: u32,
    options: u32,
    reply_intent: OpenReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        // 1. Decode OBJECT_ATTRIBUTES + UNICODE_STRING + UTF-16
        //    path body into a UTF-8 byte buffer.
        let mut path_utf8 = [0u8; super::nt_decode::NT_PATH_BUFFER_MAX];
        let Some((_oa, path_view)) =
            super::nt_decode::decode_object_attributes_with_path(msg, oa_byte_off, &mut path_utf8)
        else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
            return;
        };

        // 2. Canonicalise the NT path (strip \\?\, normalise
        //    separators, resolve drive letter) onto the namei
        //    walker's expected absolute-path shape.
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

        // 3. Project NT bits onto a personality-neutral spec.
        let Some(spec) =
            nt_request_to_spec(desired_access, share_access, creation_disposition, options)
        else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
            return;
        };

        // 4. Drive the walker through the same logic helper
        //    POSIX uses. Win32 caller never reaches a synthetic
        //    POSIX `TronaMsg` — both personalities are first-
        //    class peers of the vop chain at this point.
        crate::ops::open::do_namei_open_from_bytes(
            state,
            client,
            canonical.anchor_vkey,
            &canon[..canonical_len],
            canonical_len,
            spec,
            reply_intent,
            reply_lease,
        );
    }
}

/// Project NT `(DesiredAccess, ShareAccess, CreateDisposition,
/// CreateOptions)` onto a personality-neutral [`VfsOpenSpec`].
fn nt_request_to_spec(
    desired_access: u32,
    share_access: u32,
    creation_disposition: u32,
    options: u32,
) -> Option<VfsOpenSpec> {
    let access = super::policy::access_from_desired(desired_access)?;

    // ----- Create mode -----
    let create = match creation_disposition {
        super::consts::FILE_SUPERSEDE => CreateMode::Supersede,
        super::consts::FILE_OPEN => CreateMode::Open,
        super::consts::FILE_CREATE => CreateMode::Create,
        super::consts::FILE_OPEN_IF => CreateMode::OpenAlways,
        super::consts::FILE_OVERWRITE => CreateMode::Truncate,
        super::consts::FILE_OVERWRITE_IF => CreateMode::CreateAlways,
        _ => return None,
    };

    Some(VfsOpenSpec {
        access,
        create,
        // NT carries `FileAttributes` separately from `mode`; saltyos
        // collapses to a 0o644 default when a new leaf needs a POSIX
        // mode byte. The win32 caller's `FileAttributes` reaches the
        // reply emitter through a different payload.
        mode: 0o644,
        share: super::policy::share_from_access(share_access),
        delete_access: super::policy::delete_access_from_desired(desired_access),
        options: super::policy::options_from_nt(desired_access, options),
        // NT has no `O_CLOEXEC` analogue. The Win32 caller controls
        // handle-inheritance via `OBJECT_ATTRIBUTES.Attributes &
        // OBJ_INHERIT`; that bit lives in the OBJECT_ATTRIBUTES
        // header decoded above, not in the personality-neutral spec.
        fd_flags: 0,
    })
}
