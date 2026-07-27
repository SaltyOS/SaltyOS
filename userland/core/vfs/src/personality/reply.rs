// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality-aware reply dispatchers — the seam where
//! `ops` results become POSIX or NT wire bytes.
//!
//! Each `ops` helper produces a personality-neutral result
//! ([`crate::ops::OpenResult`], `VAttr`, byte count, etc.).
//! The dispatch entry attached a [`crate::ops::OpenReplyIntent`]
//! / matching intent at issue time. The functions below consume
//! the result + intent pair and route to the matching
//! `personality/{posix,win32}/reply.rs` emitter.
//!
//! The dispatcher exists so `ops` callers do not need to
//! match on `Personality` themselves — they hand back a
//! `ReplyIntent` and let this layer pick the correct emitter.
//! That keeps the personality boundary on a single line of code
//! per logical operation, and the boundary stays auditable
//! (a single grep for `personality::reply::emit_*` enumerates
//! every wire emit site in vfs).

#![allow(dead_code)]

use trona_kernel::core_types::TronaMsg;
use trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::vop::IoctlReply;
use crate::ops::{AckReplyIntent, OpenReplyIntent, OpenResult};
use crate::personality::Personality;

/// First-entry name buffer cap on the bulk-readdir reply path.
pub(crate) const READDIR_FIRST_ENTRY_NAME_MAX: usize = 256;

/// Parsed first-entry projection plus the cursor / batch metadata
/// the dispatcher needs to render a readdir completion.
#[derive(Clone, Copy)]
pub(crate) struct ReaddirReplyData {
    pub next_cursor: u64,
    pub entries_written: u32,
    pub bytes_written: u32,
    pub first_entry_ino: u64,
    pub first_entry_dtype: u8,
    pub first_entry_name_len: usize,
    pub first_entry_name: [u8; READDIR_FIRST_ENTRY_NAME_MAX],
}

/// Dispatch the reply for an open + create-mode operation.
///
/// `intent` was attached at the dispatch entry that decoded the
/// inbound request. `result` is the personality-neutral outcome
/// from [`crate::ops::open::do_namei_open`] (once that
/// helper lands in the open vertical slice).
pub(crate) unsafe fn emit_open(
    reply_lease: ReplyLease,
    intent: OpenReplyIntent,
    result: Result<OpenResult, VfsError>,
) {
    match (intent, result) {
        (OpenReplyIntent::PosixOpen, Ok(r)) => unsafe {
            super::posix::reply::emit_open_ok(reply_lease, r);
        },
        (OpenReplyIntent::PosixOpen, Err(e)) => unsafe {
            super::posix::reply::emit_error(reply_lease, e);
        },
        (OpenReplyIntent::NtCreateFile { .. }, Ok(r)) => unsafe {
            super::win32::reply::emit_create_file_ok(reply_lease, r);
        },
        (OpenReplyIntent::NtCreateFile { .. }, Err(e)) => unsafe {
            super::win32::reply::emit_ntstatus_error(reply_lease, e);
        },
        (OpenReplyIntent::NtOpenFile { .. }, Ok(r)) => unsafe {
            super::win32::reply::emit_open_file_ok(reply_lease, r);
        },
        (OpenReplyIntent::NtOpenFile { .. }, Err(e)) => unsafe {
            super::win32::reply::emit_ntstatus_error(reply_lease, e);
        },
    }
}

/// Dispatch the reply for an ack-only operation (mutation +
/// no-payload success).
///
/// `information` is the per-op detail word the NT side packs into
/// `IoStatusBlock.Information`. POSIX ignores it.
pub(crate) unsafe fn emit_ack(
    reply_lease: ReplyLease,
    intent: AckReplyIntent,
    information: u64,
    result: Result<(), VfsError>,
) {
    match (intent, result) {
        (AckReplyIntent::PosixAck, Ok(())) => unsafe {
            super::posix::reply::emit_ack(reply_lease);
        },
        (AckReplyIntent::PosixAck, Err(e)) => unsafe {
            super::posix::reply::emit_error(reply_lease, e);
        },
        (AckReplyIntent::NtIoStatusBlock, Ok(())) => unsafe {
            super::win32::reply::emit_iosb_ack(reply_lease, information);
        },
        (AckReplyIntent::NtIoStatusBlock, Err(e)) => unsafe {
            super::win32::reply::emit_ntstatus_error(reply_lease, e);
        },
    }
}

/// Dup-family reply. POSIX `dup` / `dup2` / `dup3` return the new fd,
/// so success must carry it in `regs[0]` — the generic `emit_ack`
/// drops the value word on the POSIX side. NT still surfaces it via
/// `IoStatusBlock.Information`, unchanged from `emit_ack`.
pub(crate) unsafe fn emit_dup(
    reply_lease: ReplyLease,
    intent: AckReplyIntent,
    new_fd: u64,
    result: Result<(), VfsError>,
) {
    match (intent, result) {
        (AckReplyIntent::PosixAck, Ok(())) => unsafe {
            super::posix::reply::emit_value(reply_lease, new_fd);
        },
        (AckReplyIntent::PosixAck, Err(e)) => unsafe {
            super::posix::reply::emit_error(reply_lease, e);
        },
        (AckReplyIntent::NtIoStatusBlock, res) => unsafe {
            emit_ack(reply_lease, AckReplyIntent::NtIoStatusBlock, new_fd, res);
        },
    }
}

// Per-op dispatchers below mirror the pattern above. Their bodies
// land alongside the matching emitter in the corresponding
// vertical slice (stat / read / write / seek / dir / statvfs /
// setattr).

/// Dispatch the reply for an attribute-query operation.
///
/// Both POSIX (`stat` / `lstat` / `fstat` / `fstatat`) and NT
/// (`NtQueryInformationFile` / `NtQueryAttributesFile` /
/// `NtQueryFullAttributesFile`) hand the same personality-neutral
/// [`crate::core::file::VAttr`] in. The intent variant
/// selects which struct shape the wire emit packs.
pub(crate) unsafe fn emit_attr(
    reply_lease: ReplyLease,
    intent: crate::ops::AttrReplyIntent,
    attr_or_err: Result<crate::core::file::VAttr, VfsError>,
) {
    use crate::ops::AttrReplyIntent;
    match (intent, attr_or_err) {
        (AttrReplyIntent::PosixStat, Ok(attr)) => unsafe {
            super::posix::reply::emit_stat_ok(reply_lease, &attr);
        },
        (AttrReplyIntent::PosixStat, Err(e)) => unsafe {
            super::posix::reply::emit_error(reply_lease, e);
        },
        (
            AttrReplyIntent::NtFileBasicInformation | AttrReplyIntent::NtFileNetworkOpenInformation,
            Ok(attr),
        ) => unsafe {
            super::win32::reply::emit_file_basic_information(reply_lease, &attr);
        },
        (AttrReplyIntent::NtFileStandardInformation, Ok(attr)) => unsafe {
            super::win32::reply::emit_file_standard_information(reply_lease, &attr);
        },
        (AttrReplyIntent::NtFilePositionInformation, Ok(_attr)) => unsafe {
            // FilePositionInformation is a fd attribute, not a
            // vop-derived one — `do_getattr_for_vnode` does not
            // produce it. Surface STATUS_INVALID_PARAMETER if
            // anyone routes here.
            super::win32::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
        },
        (
            AttrReplyIntent::NtFileBasicInformation
            | AttrReplyIntent::NtFileStandardInformation
            | AttrReplyIntent::NtFileNetworkOpenInformation
            | AttrReplyIntent::NtFilePositionInformation
            | AttrReplyIntent::NtFileAllInformation
            | AttrReplyIntent::NtFileEaInformation
            | AttrReplyIntent::NtFileAccessInformation
            | AttrReplyIntent::NtFileNameInformation
            | AttrReplyIntent::NtFileAlignmentInformation
            | AttrReplyIntent::NtFileInternalInformation
            | AttrReplyIntent::NtFileModeInformation,
            Err(e),
        ) => unsafe {
            super::win32::reply::emit_ntstatus_error(reply_lease, e);
        },
        (
            AttrReplyIntent::NtFileAllInformation
            | AttrReplyIntent::NtFileEaInformation
            | AttrReplyIntent::NtFileAccessInformation
            | AttrReplyIntent::NtFileNameInformation
            | AttrReplyIntent::NtFileAlignmentInformation
            | AttrReplyIntent::NtFileInternalInformation
            | AttrReplyIntent::NtFileModeInformation,
            Ok(_),
        ) => unsafe {
            // Per-class emitters land alongside the matching
            // NtQueryInformationFile vertical slice. Until then
            // surface STATUS_NOT_SUPPORTED so the wire shape
            // stays observable.
            super::win32::reply::emit_ntstatus_error(reply_lease, VfsError::NotSup);
        },
    }
}

/// Dispatch the inline-mode read reply — short-read fast path
/// where the data is packed directly into the reply regs.
pub(crate) unsafe fn emit_read_inline(
    reply_lease: ReplyLease,
    intent: crate::ops::ReadReplyIntent,
    result: Result<crate::ops::io::InlineReadResult<'_>, VfsError>,
) {
    use crate::ops::ReadReplyIntent;
    match (intent, result) {
        (ReadReplyIntent::PosixRead, Ok(r)) => unsafe {
            super::posix::reply::emit_read_inline_ok(reply_lease, r.data);
        },
        (ReadReplyIntent::PosixRead, Err(e)) => unsafe {
            super::posix::reply::emit_error(reply_lease, e);
        },
        (ReadReplyIntent::NtReadFile, Ok(r)) => unsafe {
            super::win32::reply::emit_read_file_inline_ok(reply_lease, r.data);
        },
        (ReadReplyIntent::NtReadFile, Err(e)) => unsafe {
            super::win32::reply::emit_ntstatus_error(reply_lease, e);
        },
    }
}

/// Dispatch the SHM-mode read reply — caller's bulk SHM region
/// receives the data; reply only carries the byte count.
pub(crate) unsafe fn emit_read_shm(
    reply_lease: ReplyLease,
    intent: crate::ops::ReadReplyIntent,
    bytes_read_or_err: Result<u64, VfsError>,
) {
    use crate::ops::ReadReplyIntent;
    match (intent, bytes_read_or_err) {
        (ReadReplyIntent::PosixRead, Ok(n)) => unsafe {
            super::posix::reply::emit_read_count_ok(reply_lease, n);
        },
        (ReadReplyIntent::PosixRead, Err(e)) => unsafe {
            super::posix::reply::emit_error(reply_lease, e);
        },
        (ReadReplyIntent::NtReadFile, Ok(n)) => unsafe {
            super::win32::reply::emit_read_file_count_ok(reply_lease, n);
        },
        (ReadReplyIntent::NtReadFile, Err(e)) => unsafe {
            super::win32::reply::emit_ntstatus_error(reply_lease, e);
        },
    }
}

/// Dispatch an inline read completion whose payload has already
/// been staged by a backend completion router.
pub(crate) unsafe fn emit_read_inline_payload(
    reply_lease: ReplyLease,
    intent: crate::ops::ReadReplyIntent,
    bytes_read: u64,
    payload: Option<&[u8]>,
) {
    use crate::ops::ReadReplyIntent;
    let mut out = TronaMsg::default();
    let (count_idx, payload_off, len_extra) = match intent {
        ReadReplyIntent::PosixRead => (0usize, 1usize, 1u64),
        ReadReplyIntent::NtReadFile => {
            out.regs[0] = 0;
            (1usize, 2usize, 2u64)
        }
    };
    out.label = VFS_PUBLIC_REPLY_OK;
    out.regs[count_idx] = bytes_read;
    if let Some(bytes) = payload {
        let dst = (&raw mut out.regs[payload_off]) as *mut u8;
        let copy_len = bytes.len().min((out.regs.len() - payload_off) * 8);
        for (i, &b) in bytes[..copy_len].iter().enumerate() {
            unsafe { *dst.add(i) = b };
        }
        out.length = (len_extra + ((copy_len as u64) + 7) / 8) as u64;
    } else {
        out.length = (len_extra) as u64;
    }
    crate::owner::op::reply_send(reply_lease, &out);
}

/// Dispatch an inline read completion directly from a backend SHM
/// source pointer. The payload copy is capped to the reply-register
/// capacity, but `bytes_read` reports the backend transfer count.
pub(crate) unsafe fn emit_read_inline_from_ptr(
    reply_lease: ReplyLease,
    intent: crate::ops::ReadReplyIntent,
    bytes_read: u64,
    src: *const u8,
) {
    use crate::ops::ReadReplyIntent;
    let mut out = TronaMsg::default();
    let (count_idx, payload_off, len_extra) = match intent {
        ReadReplyIntent::PosixRead => (0usize, 1usize, 1u64),
        ReadReplyIntent::NtReadFile => {
            out.regs[0] = 0;
            (1usize, 2usize, 2u64)
        }
    };
    out.label = VFS_PUBLIC_REPLY_OK;
    out.regs[count_idx] = bytes_read;
    if !src.is_null() && bytes_read > 0 {
        let dst = (&raw mut out.regs[payload_off]) as *mut u8;
        let cap = ((out.regs.len() - payload_off) * 8) as u64;
        let n = bytes_read.min(cap);
        for i in 0..n as usize {
            unsafe { *dst.add(i) = *src.add(i) };
        }
        out.length = (len_extra + (n + 7) / 8) as u64;
    } else {
        out.length = (len_extra) as u64;
    }
    crate::owner::op::reply_send(reply_lease, &out);
}

/// Dispatch the reply for a write operation.
pub(crate) unsafe fn emit_write(
    reply_lease: ReplyLease,
    intent: crate::ops::WriteReplyIntent,
    bytes_written_or_err: Result<u64, VfsError>,
) {
    use crate::ops::WriteReplyIntent;
    match (intent, bytes_written_or_err) {
        (WriteReplyIntent::PosixWrite, Ok(n)) => unsafe {
            super::posix::reply::emit_write_count_ok(reply_lease, n);
        },
        (WriteReplyIntent::PosixWrite, Err(e)) => unsafe {
            super::posix::reply::emit_error(reply_lease, e);
        },
        (WriteReplyIntent::NtWriteFile, Ok(n)) => unsafe {
            super::win32::reply::emit_write_file_count_ok(reply_lease, n);
        },
        (WriteReplyIntent::NtWriteFile, Err(e)) => unsafe {
            super::win32::reply::emit_ntstatus_error(reply_lease, e);
        },
    }
}

/// Dispatch the reply for a seek operation.
///
/// POSIX `lseek` returns the new offset in `regs[0]`. NT
/// `NtSetInformationFile(FilePositionInformation)` returns just
/// an IoStatusBlock — the new offset is not echoed because the
/// caller already knows it (it asked for it).
pub(crate) unsafe fn emit_seek(
    reply_lease: ReplyLease,
    intent: crate::ops::SeekReplyIntent,
    new_offset_or_err: Result<u64, VfsError>,
) {
    use crate::ops::SeekReplyIntent;
    match (intent, new_offset_or_err) {
        (SeekReplyIntent::PosixSeek, Ok(off)) => unsafe {
            super::posix::reply::emit_seek_offset_ok(reply_lease, off);
        },
        (SeekReplyIntent::PosixSeek, Err(e)) => unsafe {
            super::posix::reply::emit_error(reply_lease, e);
        },
        (SeekReplyIntent::NtSetFilePosition, Ok(_)) => unsafe {
            super::win32::reply::emit_iosb_ack(reply_lease, 0);
        },
        (SeekReplyIntent::NtSetFilePosition, Err(e)) => unsafe {
            super::win32::reply::emit_ntstatus_error(reply_lease, e);
        },
    }
}

/// Dispatch the reply for an ioctl / DeviceIoControl operation.
pub(crate) unsafe fn emit_ioctl(
    reply_lease: ReplyLease,
    intent: crate::ops::IoctlReplyIntent,
    result: Result<IoctlReply, VfsError>,
) {
    use crate::ops::IoctlReplyIntent;
    match (intent, result) {
        (IoctlReplyIntent::PosixIoctl, Ok(reply)) => {
            let mut out = TronaMsg::default();
            out.label = VFS_PUBLIC_REPLY_OK;
            let count = (reply.word_count as usize).min(reply.words.len());
            out.length = count as u64;
            for i in 0..count {
                out.regs[i] = reply.words[i];
            }
            crate::owner::op::reply_send(reply_lease, &out);
        }
        (IoctlReplyIntent::PosixIoctl, Err(e)) => unsafe {
            super::posix::reply::emit_error(reply_lease, e);
        },
        (IoctlReplyIntent::NtDeviceIoControlFile, Ok(reply)) => unsafe {
            super::win32::reply::emit_device_io_control_ok(reply_lease, &reply);
        },
        (IoctlReplyIntent::NtDeviceIoControlFile, Err(e)) => unsafe {
            super::win32::reply::emit_ntstatus_error(reply_lease, e);
        },
    }
}

/// Dispatch the reply for a directory-enumeration operation.
///
/// The byte count carries the size of the packed dirent records
/// in the reply regs (POSIX `getdents` `regs[0]`, NT
/// `IoStatusBlock.Information`). Per-record layout is selected
/// by the variant — `PosixGetDents` packs Linux `dirent64`,
/// `NtFileDirectoryInformation` packs the NT struct of the same
/// name, etc.
pub(crate) unsafe fn emit_dir(
    reply_lease: ReplyLease,
    intent: crate::ops::ReadDirReplyIntent,
    bytes_packed_or_err: Result<u64, VfsError>,
) {
    use crate::ops::ReadDirReplyIntent;
    match (intent, bytes_packed_or_err) {
        (ReadDirReplyIntent::PosixGetDents, Ok(n)) => unsafe {
            super::posix::reply::emit_dir_count_ok(reply_lease, n);
        },
        (ReadDirReplyIntent::PosixGetDents, Err(e)) => unsafe {
            super::posix::reply::emit_error(reply_lease, e);
        },
        (
            ReadDirReplyIntent::NtFileDirectoryInformation
            | ReadDirReplyIntent::NtFileNamesInformation
            | ReadDirReplyIntent::NtFileFullDirectoryInformation
            | ReadDirReplyIntent::NtFileBothDirectoryInformation
            | ReadDirReplyIntent::NtFileIdFullDirectoryInformation
            | ReadDirReplyIntent::NtFileIdBothDirectoryInformation,
            Ok(n),
        ) => unsafe {
            super::win32::reply::emit_dir_information(reply_lease, n);
        },
        (
            ReadDirReplyIntent::NtFileDirectoryInformation
            | ReadDirReplyIntent::NtFileNamesInformation
            | ReadDirReplyIntent::NtFileFullDirectoryInformation
            | ReadDirReplyIntent::NtFileBothDirectoryInformation
            | ReadDirReplyIntent::NtFileIdFullDirectoryInformation
            | ReadDirReplyIntent::NtFileIdBothDirectoryInformation,
            Err(e),
        ) => unsafe {
            super::win32::reply::emit_ntstatus_error(reply_lease, e);
        },
    }
}

/// Dispatch a readlink-style byte payload. POSIX receives
/// `regs[0] = copied_len, regs[1..] = bytes`; Win32 receives a
/// leading success status word followed by the same length +
/// bytes. The copy is capped to the reply-register payload area.
pub(crate) unsafe fn emit_readlink_bytes(
    reply_lease: ReplyLease,
    personality: Personality,
    target: Result<&[u8], VfsError>,
) {
    let bytes = match target {
        Ok(bytes) => bytes,
        Err(e) => {
            super::wire::send_reply_err_typed(personality, reply_lease, e);
            return;
        }
    };
    let mut out = TronaMsg::default();
    let (len_idx, bytes_off, len_extra) = match personality {
        Personality::Win32 => {
            out.regs[0] = 0;
            (1usize, 2usize, 2u64)
        }
        Personality::Posix => (0usize, 1usize, 1u64),
    };
    out.label = VFS_PUBLIC_REPLY_OK;
    let copy_len = bytes.len().min((out.regs.len() - bytes_off) * 8);
    out.regs[len_idx] = copy_len as u64;
    let dst = (&raw mut out.regs[bytes_off]) as *mut u8;
    for (i, &b) in bytes[..copy_len].iter().enumerate() {
        unsafe { *dst.add(i) = b };
    }
    out.length = (len_extra + ((copy_len as u64) + 7) / 8) as u64;
    crate::owner::op::reply_send(reply_lease, &out);
}

/// Dispatch a getxattr-style reply: total value length plus the
/// inline bytes copied by the backend completion router.
pub(crate) unsafe fn emit_xattr_get(
    reply_lease: ReplyLease,
    personality: Personality,
    payload: Result<(usize, &[u8]), VfsError>,
) {
    let (val_len, bytes) = match payload {
        Ok(payload) => payload,
        Err(e) => {
            super::wire::send_reply_err_typed(personality, reply_lease, e);
            return;
        }
    };
    emit_xattr_pair(reply_lease, personality, val_len, bytes);
}

/// Dispatch a listxattr-style reply: total bytes needed plus the
/// inline bytes copied by the backend completion router.
pub(crate) unsafe fn emit_xattr_list(
    reply_lease: ReplyLease,
    personality: Personality,
    payload: Result<(usize, &[u8]), VfsError>,
) {
    let (bytes_needed, bytes) = match payload {
        Ok(payload) => payload,
        Err(e) => {
            super::wire::send_reply_err_typed(personality, reply_lease, e);
            return;
        }
    };
    emit_xattr_pair(reply_lease, personality, bytes_needed, bytes);
}

fn emit_xattr_pair(
    reply_lease: ReplyLease,
    personality: Personality,
    total_len: usize,
    bytes: &[u8],
) {
    let mut out = TronaMsg::default();
    let (total_idx, len_idx, bytes_off, len_extra) = match personality {
        Personality::Win32 => {
            out.regs[0] = 0;
            (1usize, 2usize, 3usize, 3u64)
        }
        Personality::Posix => (0usize, 1usize, 2usize, 2u64),
    };
    out.label = VFS_PUBLIC_REPLY_OK;
    let copy_len = bytes.len().min((out.regs.len() - bytes_off) * 8);
    out.regs[total_idx] = total_len as u64;
    out.regs[len_idx] = copy_len as u64;
    let dst = (&raw mut out.regs[bytes_off]) as *mut u8;
    for (i, &b) in bytes[..copy_len].iter().enumerate() {
        unsafe { *dst.add(i) = b };
    }
    out.length = (len_extra + ((copy_len as u64) + 7) / 8) as u64;
    crate::owner::op::reply_send(reply_lease, &out);
}

/// Dispatch a bulk-readdir reply carrying the first parsed entry
/// inline.
pub(crate) unsafe fn emit_readdir_batch(
    reply_lease: ReplyLease,
    intent: crate::ops::ReadDirReplyIntent,
    data: Result<ReaddirReplyData, VfsError>,
) {
    use crate::ops::ReadDirReplyIntent;
    let d = match data {
        Ok(data) => data,
        Err(e) => {
            unsafe { emit_dir(reply_lease, intent, Err(e)) };
            return;
        }
    };
    let mut out = TronaMsg::default();
    let (cursor_idx, entries_idx, bytes_idx, ino_idx, dtype_idx, name_len_idx, name_off, len_extra) =
        match intent {
            ReadDirReplyIntent::PosixGetDents => {
                let _dirent = super::posix::reply::make_dirent_projection(
                    d.first_entry_ino,
                    d.next_cursor,
                    d.first_entry_dtype,
                    &d.first_entry_name[..d.first_entry_name_len.min(READDIR_FIRST_ENTRY_NAME_MAX)],
                );
                (0, 1, 2, 3, 4, 5, 6, 6u64)
            }
            ReadDirReplyIntent::NtFileDirectoryInformation
            | ReadDirReplyIntent::NtFileNamesInformation
            | ReadDirReplyIntent::NtFileFullDirectoryInformation
            | ReadDirReplyIntent::NtFileBothDirectoryInformation
            | ReadDirReplyIntent::NtFileIdFullDirectoryInformation
            | ReadDirReplyIntent::NtFileIdBothDirectoryInformation => {
                out.regs[0] = 0;
                (1, 2, 3, 4, 5, 6, 7, 7u64)
            }
        };
    out.label = VFS_PUBLIC_REPLY_OK;
    out.regs[cursor_idx] = d.next_cursor;
    out.regs[entries_idx] = d.entries_written as u64;
    out.regs[bytes_idx] = d.bytes_written as u64;
    out.regs[ino_idx] = d.first_entry_ino;
    out.regs[dtype_idx] = d.first_entry_dtype as u64;
    let copy_len = d
        .first_entry_name_len
        .min(READDIR_FIRST_ENTRY_NAME_MAX)
        .min((out.regs.len() - name_off) * 8);
    out.regs[name_len_idx] = copy_len as u64;
    let dst = (&raw mut out.regs[name_off]) as *mut u8;
    for i in 0..copy_len {
        unsafe { *dst.add(i) = d.first_entry_name[i] };
    }
    out.length = (len_extra + ((copy_len as u64) + 7) / 8) as u64;
    crate::owner::op::reply_send(reply_lease, &out);
}

/// Dispatch the reply for a volume / statfs query.
pub(crate) unsafe fn emit_statfs(
    reply_lease: ReplyLease,
    intent: crate::ops::StatfsReplyIntent,
    stats_or_err: Result<crate::core::file::VStatfs, VfsError>,
) {
    use crate::ops::StatfsReplyIntent;
    match (intent, stats_or_err) {
        (StatfsReplyIntent::PosixStatvfs, Ok(stats)) => unsafe {
            super::posix::reply::emit_statvfs_ok(reply_lease, &stats);
        },
        (StatfsReplyIntent::PosixStatvfs, Err(e)) => unsafe {
            super::posix::reply::emit_error(reply_lease, e);
        },
        (
            StatfsReplyIntent::NtFileFsVolumeInformation
            | StatfsReplyIntent::NtFileFsSizeInformation
            | StatfsReplyIntent::NtFileFsAttributeInformation
            | StatfsReplyIntent::NtFileFsDeviceInformation,
            Ok(stats),
        ) => unsafe {
            super::win32::reply::emit_volume_information(reply_lease, intent, &stats);
        },
        (
            StatfsReplyIntent::NtFileFsVolumeInformation
            | StatfsReplyIntent::NtFileFsSizeInformation
            | StatfsReplyIntent::NtFileFsAttributeInformation
            | StatfsReplyIntent::NtFileFsDeviceInformation,
            Err(e),
        ) => unsafe {
            super::win32::reply::emit_ntstatus_error(reply_lease, e);
        },
    }
}
