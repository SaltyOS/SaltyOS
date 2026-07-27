// SPDX-License-Identifier: GPL-2.0-only
//
//! NT `NtSetInformationFile` dispatcher — splits on the
//! `FileInformationClass` argument and routes each sub-class to
//! the matching ops helper.
//!
//! `FilePositionInformation` (14) and `FileEndOfFileInformation`
//! (20) reach `super::io::handle_nt_set_information_file_io`
//! before this dispatcher runs (handled in `super::dispatch`).
//! The remaining sub-classes land here.
//!
//! Wire layout:
//! ```text
//!   byte 0..4    FileHandle             (i32 fd)
//!   byte 4..8    Length                 (u32, payload bytes)
//!   byte 8..12   FileInformationClass   (u32)
//!   byte 12..16  reserved
//!   byte 16..    payload (class-specific)
//! ```

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::{AckReplyIntent, SetAttrKind};
use crate::owner::VfsState;
use crate::server::open_object::OpenObjectAccess;
use crate::server::types::ClientHandle;

const FILE_BASIC_INFORMATION: u32 = 4;
const FILE_RENAME_INFORMATION: u32 = 10;
const FILE_LINK_INFORMATION: u32 = 11;
const FILE_DISPOSITION_INFORMATION: u32 = 13;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let info_class = (msg.regs[1] & 0xFFFF_FFFF) as u32;
        match info_class {
            FILE_BASIC_INFORMATION => handle_basic(state, client, msg, reply_lease),
            FILE_RENAME_INFORMATION => handle_rename(state, client, msg, reply_lease),
            FILE_LINK_INFORMATION => handle_link(state, client, msg, reply_lease),
            FILE_DISPOSITION_INFORMATION => handle_disposition(state, client, msg, reply_lease),
            _ => {
                let _ = (state, client);
                super::reply::emit_ntstatus_error(reply_lease, VfsError::NotSup);
            }
        }
    }
}

unsafe fn handle_rename(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = (msg.regs[0] & 0xFFFF_FFFF) as i32;
        let mut path_utf8 = [0u8; super::nt_decode::NT_PATH_BUFFER_MAX];
        let Some(info) = super::nt_decode::decode_file_rename_information(msg, 16, &mut path_utf8)
        else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
            return;
        };
        super::rename::rename_fd_to_path_bytes(
            state,
            client,
            fd,
            info.root_directory,
            info.new_name_utf8,
            info.replace_if_exists,
            reply_lease,
        );
    }
}

unsafe fn handle_link(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = (msg.regs[0] & 0xFFFF_FFFF) as i32;
        let mut path_utf8 = [0u8; super::nt_decode::NT_PATH_BUFFER_MAX];
        let Some(info) = super::nt_decode::decode_file_rename_information(msg, 16, &mut path_utf8)
        else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
            return;
        };
        super::rename::link_fd_to_path_bytes(
            state,
            client,
            fd,
            info.root_directory,
            info.new_name_utf8,
            info.replace_if_exists,
            reply_lease,
        );
    }
}

unsafe fn handle_basic(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = (msg.regs[0] & 0xFFFF_FFFF) as i32;
        let Some(fbi) = super::nt_decode::decode_file_basic_information(msg, 16) else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
            return;
        };
        let Some(vnode_h) = resolve_fd_vnode(state, client, fd) else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::BadF);
            return;
        };
        let kind = SetAttrKind::BasicBundle {
            creation_time_nanos: nt_filetime_to_posix_nanos(fbi.creation_time.0),
            last_access_nanos: nt_filetime_to_posix_nanos(fbi.last_access_time.0),
            last_write_nanos: nt_filetime_to_posix_nanos(fbi.last_write_time.0),
            change_time_nanos: nt_filetime_to_posix_nanos(fbi.change_time.0),
            nt_file_attributes: if fbi.file_attributes != 0 {
                Some(fbi.file_attributes)
            } else {
                None
            },
        };
        crate::ops::set_attr::do_setattr_for_vnode(
            state,
            client,
            vnode_h,
            kind,
            AckReplyIntent::NtIoStatusBlock,
            reply_lease,
        );
    }
}

unsafe fn handle_disposition(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = (msg.regs[0] & 0xFFFF_FFFF) as i32;
        let Some(delete_pending) = super::nt_decode::decode_file_disposition_information(msg, 16)
        else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
            return;
        };
        let Some(open_h) = (if fd >= 0 {
            state.open_object_at(client, fd as usize)
        } else {
            None
        }) else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::BadF);
            return;
        };
        let (access, named_h) = match state.open_objects.get(open_h) {
            Some(obj) => (obj.access, obj.named_state),
            None => {
                super::reply::emit_ntstatus_error(reply_lease, VfsError::BadF);
                return;
            }
        };
        if (access & OpenObjectAccess::DELETE) == 0 {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::Acces);
            return;
        }
        let Some(named) = state.open_object_named_states.get_mut(named_h) else {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::NotSup);
            return;
        };
        if !named.anchor.is_valid() {
            super::reply::emit_ntstatus_error(reply_lease, VfsError::NotSup);
            return;
        }
        named.deferred_unlink = if delete_pending { 1 } else { 0 };
        crate::personality::reply::emit_ack(
            reply_lease,
            AckReplyIntent::NtIoStatusBlock,
            0,
            Ok(()),
        );
    }
}

fn nt_filetime_to_posix_nanos(filetime_100ns: i64) -> Option<u64> {
    if filetime_100ns <= 0 {
        return None;
    }
    const NT_EPOCH_OFFSET_SECONDS: i64 = 11644473600;
    const NT_TICKS_PER_SECOND: i64 = 10_000_000;
    let seconds = filetime_100ns / NT_TICKS_PER_SECOND - NT_EPOCH_OFFSET_SECONDS;
    if seconds < 0 {
        return None;
    }
    let remainder_100ns = filetime_100ns % NT_TICKS_PER_SECOND;
    Some((seconds as u64) * 1_000_000_000 + (remainder_100ns as u64) * 100)
}

unsafe fn resolve_fd_vnode(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Option<crate::core::vnode::VnodeHandle> {
    if fd < 0 {
        return None;
    }
    let open_h = state.open_object_at(client, fd as usize)?;
    state.open_objects.get(open_h).map(|obj| obj.vnode)
}
