// SPDX-License-Identifier: GPL-2.0-only
//
//! NT wire reply emitters.
//!
//! Each emitter consumes a [`trona_server::ReplyLease`] and
//! produces an NT-shaped reply: a leading `IO_STATUS_BLOCK` (status
//! word + per-op `Information` field) followed by the matching
//! `FILE_*_INFORMATION` payload where applicable.
//!
//! The label on every Win32 reply is
//! [`crate::ipc::protocol::public::VFS_PUBLIC_REPLY_OK`] — the
//! NTSTATUS distinguishes success vs failure inside the
//! IoStatusBlock, not the IPC label itself. (This mirrors the way
//! Windows itself separates the kernel-RPC outcome from the
//! op-level NTSTATUS.)
//!
//! `IO_STATUS_BLOCK.Information` holds the per-op detail:
//! * NtCreateFile / NtOpenFile — `FILE_OPENED` (1) /
//!   `FILE_CREATED` (2) / `FILE_OVERWRITTEN` (3) /
//!   `FILE_SUPERSEDED` (4), derived from
//!   [`crate::ops::OpenCreateAction`].
//! * NtReadFile / NtWriteFile — bytes transferred.
//! * NtQueryInformationFile / NtQueryVolumeInformationFile —
//!   byte size of the trailing `FILE_*_INFORMATION` struct.
//! * NtSet*Information / NtDeleteFile / NtRenameFile / etc — `0`.

#![allow(dead_code)]

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::file::{VAttr, VStatfs};
use crate::core::vop::IoctlReply;
use crate::ops::{OpenCreateAction, OpenResult, StatfsReplyIntent};
use crate::owner::op::reply_send;
use trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;

use super::types::IoStatusBlock;

// NT FILE_INFORMATION action codes for IoStatusBlock.Information.
// These match Windows' published values verbatim so a basaltc shim
// can hand them to the Win32 caller without translation.
const NT_FILE_SUPERSEDED: u64 = 0;
const NT_FILE_OPENED: u64 = 1;
const NT_FILE_CREATED: u64 = 2;
const NT_FILE_OVERWRITTEN: u64 = 3;
const NT_FILE_EXISTS: u64 = 4;
const NT_FILE_DOES_NOT_EXIST: u64 = 5;

const fn nt_action_for(action: OpenCreateAction) -> u64 {
    match action {
        OpenCreateAction::Opened => NT_FILE_OPENED,
        OpenCreateAction::Created => NT_FILE_CREATED,
        OpenCreateAction::Overwritten => NT_FILE_OVERWRITTEN,
        OpenCreateAction::Superseded => NT_FILE_SUPERSEDED,
    }
}

/// Pack an [`IoStatusBlock`] at byte offset 0 of `out.regs[..]`.
/// Returns the next-free byte offset (for trailing payload). The
/// ReplyLease is not consumed here — the caller chains
/// payload writes and finalises with [`reply_send`].
unsafe fn pack_iosb_at_zero(out: &mut TronaMsg, iosb: IoStatusBlock) -> usize {
    let size = ::core::mem::size_of::<IoStatusBlock>();
    unsafe {
        let dst = out.regs.as_mut_ptr() as *mut IoStatusBlock;
        ::core::ptr::write(dst, iosb);
    }
    size
}

/// Emit a typed-error reply — NT NTSTATUS-shaped.
///
/// Builds an `IoStatusBlock { Status: ntstatus, Information: 0 }`
/// at the start of regs and surfaces no payload. The basaltc /
/// win32 shim reads `regs[0..16]` as the IoStatusBlock and
/// projects the NTSTATUS back to the caller.
pub(crate) unsafe fn emit_ntstatus_error(reply_lease: ReplyLease, err: VfsError) {
    let status = super::consts::vfs_error_to_ntstatus(err);
    let iosb = IoStatusBlock {
        status,
        _reserved: 0,
        information: 0,
    };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    let written = unsafe { pack_iosb_at_zero(&mut out, iosb) };
    out.length = ((written + 7) / 8) as u64;
    reply_send(reply_lease, &out);
}

/// Emit a successful ack: `IoStatusBlock { Status: 0, Information:
/// info }`. Used by NT mutation ops that have no trailing payload
/// (rename / delete / set-info-file / flush / etc.).
pub(crate) unsafe fn emit_iosb_ack(reply_lease: ReplyLease, information: u64) {
    let iosb = IoStatusBlock {
        status: 0,
        _reserved: 0,
        information,
    };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    let written = unsafe { pack_iosb_at_zero(&mut out, iosb) };
    out.length = ((written + 7) / 8) as u64;
    reply_send(reply_lease, &out);
}

/// Emit a successful `NtCreateFile` reply.
///
/// Wire layout:
///
/// * `regs[0..16]` — `IoStatusBlock { Status: 0, Information:
///   <NT_FILE_* action code> }`.
/// * `regs[2]`     — returned NT HANDLE (we surface the saltyos
///   `fd` here; the basaltc shim widens it to a 64-bit
///   pointer-sized HANDLE before returning to the Win32 caller).
pub(crate) unsafe fn emit_create_file_ok(reply_lease: ReplyLease, result: OpenResult) {
    let iosb = IoStatusBlock {
        status: 0,
        _reserved: 0,
        information: nt_action_for(result.action),
    };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    let written = unsafe { pack_iosb_at_zero(&mut out, iosb) };
    out.regs[2] = result.fd as u64;
    out.length = (((written + 7) / 8).max(3)) as u64;
    reply_send(reply_lease, &out);
}

/// Emit a successful `NtOpenFile` reply.
///
/// Same wire layout as [`emit_create_file_ok`], but the action
/// code is forced to `FILE_OPENED` — `NtOpenFile` is the strict-
/// existing variant of `NtCreateFile`, so any successful return
/// is by definition an open of an existing leaf.
pub(crate) unsafe fn emit_open_file_ok(reply_lease: ReplyLease, result: OpenResult) {
    let iosb = IoStatusBlock {
        status: 0,
        _reserved: 0,
        information: NT_FILE_OPENED,
    };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    let written = unsafe { pack_iosb_at_zero(&mut out, iosb) };
    out.regs[2] = result.fd as u64;
    out.length = (((written + 7) / 8).max(3)) as u64;
    reply_send(reply_lease, &out);
}

/// Emit a successful `NtQueryInformationFile(FileBasicInformation)`.
///
/// Wire layout:
/// - `regs[0..16]` — `IoStatusBlock { Status: 0, Information:
///   sizeof(FILE_BASIC_INFORMATION) }`.
/// - `regs[16..]`  — `FILE_BASIC_INFORMATION` packed: 4 NT
///   FILETIMEs (creation / last_access / last_write / change)
///   + `FileAttributes` mask.
pub(crate) unsafe fn emit_file_basic_information(reply_lease: ReplyLease, attr: &VAttr) {
    use super::nt_reply::{posix_mode_to_win32_attributes, posix_nanos_to_nt_filetime};
    use super::types::FileBasicInformation;

    let fbi = FileBasicInformation {
        creation_time: posix_nanos_to_nt_filetime(attr.ctime),
        last_access_time: posix_nanos_to_nt_filetime(attr.atime),
        last_write_time: posix_nanos_to_nt_filetime(attr.mtime),
        change_time: posix_nanos_to_nt_filetime(attr.ctime),
        file_attributes: posix_mode_to_win32_attributes(attr.mode),
    };
    let fbi_size = ::core::mem::size_of::<FileBasicInformation>();
    let iosb = IoStatusBlock {
        status: 0,
        _reserved: 0,
        information: fbi_size as u64,
    };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    let next = unsafe { pack_iosb_at_zero(&mut out, iosb) };
    if let Some(_end) = unsafe { super::nt_reply::pack_file_basic_information(&mut out, next, fbi) }
    {
        out.length = ((next + fbi_size + 7) / 8) as u64;
        reply_send(reply_lease, &out);
    } else {
        unsafe { emit_ntstatus_error(reply_lease, VfsError::Inval) };
    }
}

/// Emit a successful `NtQueryInformationFile(FileStandardInformation)`.
///
/// Wire layout:
/// - `regs[0..16]` — `IoStatusBlock { Status: 0, Information:
///   sizeof(FILE_STANDARD_INFORMATION) }`.
/// - `regs[16..]`  — `FILE_STANDARD_INFORMATION`:
///   `AllocationSize` (rounded-up file size, here we surface the
///   actual size as the allocation hint), `EndOfFile` (file size
///   in bytes), `NumberOfLinks`, `DeletePending` (0 — vfs has no
///   per-handle delete flag), `Directory`.
pub(crate) unsafe fn emit_file_standard_information(reply_lease: ReplyLease, attr: &VAttr) {
    use super::types::{FileStandardInformation, LargeInteger};

    let is_dir = matches!(attr.kind, crate::core::vnode::VnodeKind::Directory);
    let fsi = FileStandardInformation {
        allocation_size: LargeInteger(attr.size as i64),
        end_of_file: LargeInteger(attr.size as i64),
        number_of_links: attr.nlink,
        delete_pending: 0,
        directory: if is_dir { 1 } else { 0 },
        _reserved: [0; 2],
    };
    let fsi_size = ::core::mem::size_of::<FileStandardInformation>();
    let iosb = IoStatusBlock {
        status: 0,
        _reserved: 0,
        information: fsi_size as u64,
    };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    let next = unsafe { pack_iosb_at_zero(&mut out, iosb) };
    if let Some(_end) =
        unsafe { super::nt_reply::pack_file_standard_information(&mut out, next, fsi) }
    {
        out.length = ((next + fsi_size + 7) / 8) as u64;
        reply_send(reply_lease, &out);
    } else {
        unsafe { emit_ntstatus_error(reply_lease, VfsError::Inval) };
    }
}

/// Emit a successful `NtQueryInformationFile(FilePositionInformation)`.
///
/// Wire layout: `IoStatusBlock + LARGE_INTEGER (current file
/// position)`.
pub(crate) unsafe fn emit_file_position_information(reply_lease: ReplyLease, offset: u64) {
    use super::types::LargeInteger;

    let li_size = ::core::mem::size_of::<LargeInteger>();
    let iosb = IoStatusBlock {
        status: 0,
        _reserved: 0,
        information: li_size as u64,
    };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    let next = unsafe { pack_iosb_at_zero(&mut out, iosb) };
    let total = out.regs.len() * 8;
    if next + li_size > total || next % ::core::mem::align_of::<LargeInteger>() != 0 {
        unsafe { emit_ntstatus_error(reply_lease, VfsError::Inval) };
        return;
    }
    unsafe {
        let dst = (out.regs.as_mut_ptr() as *mut u8).add(next) as *mut LargeInteger;
        ::core::ptr::write(dst, LargeInteger(offset as i64));
    }
    out.length = ((next + li_size + 7) / 8) as u64;
    reply_send(reply_lease, &out);
}

/// Emit a successful `NtDeviceIoControlFile` reply.
///
/// Wire layout:
/// - `regs[0..16]` — `IoStatusBlock { Status: 0, Information:
///   byte_count }`.
/// - `regs[16..]` — vop-provided output payload words.
pub(crate) unsafe fn emit_device_io_control_ok(reply_lease: ReplyLease, reply: &IoctlReply) {
    let iosb = IoStatusBlock {
        status: 0,
        _reserved: 0,
        information: reply.byte_count as u64,
    };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    let next = unsafe { pack_iosb_at_zero(&mut out, iosb) };
    let payload_word_start = next / 8;
    let count = (reply.word_count as usize)
        .min(reply.words.len())
        .min(out.regs.len().saturating_sub(payload_word_start));
    for i in 0..count {
        out.regs[payload_word_start + i] = reply.words[i];
    }
    out.length = (payload_word_start + count) as u64;
    reply_send(reply_lease, &out);
}

/// Emit a successful inline-mode `NtReadFile` reply.
///
/// Wire layout:
/// - `regs[0..16]` — `IoStatusBlock { Status: 0, Information:
///   bytes_read }`.
/// - `regs[16..]`  — read data packed 8 bytes per word.
pub(crate) unsafe fn emit_read_file_inline_ok(reply_lease: ReplyLease, data: &[u8]) {
    let iosb = IoStatusBlock {
        status: 0,
        _reserved: 0,
        information: data.len() as u64,
    };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    let next = unsafe { pack_iosb_at_zero(&mut out, iosb) };
    let payload_word_start = next / 8;
    let words = (data.len() + 7) / 8;
    for i in 0..words {
        if payload_word_start + i >= out.regs.len() {
            break;
        }
        let base = i * 8;
        let take = (data.len() - base).min(8);
        let mut word = [0u8; 8];
        word[..take].copy_from_slice(&data[base..base + take]);
        out.regs[payload_word_start + i] = u64::from_le_bytes(word);
    }
    out.length = (((next + data.len() + 7) / 8).min(32)) as u64;
    reply_send(reply_lease, &out);
}

/// Emit a successful SHM-mode `NtReadFile` reply: IoStatusBlock
/// whose `Information` field carries the byte count.
pub(crate) unsafe fn emit_read_file_count_ok(reply_lease: ReplyLease, bytes_read: u64) {
    unsafe { emit_iosb_ack(reply_lease, bytes_read) };
}

/// Emit a successful `NtWriteFile` reply.
pub(crate) unsafe fn emit_write_file_count_ok(reply_lease: ReplyLease, bytes_written: u64) {
    unsafe { emit_iosb_ack(reply_lease, bytes_written) };
}

/// Emit a successful `NtQueryDirectoryFile` reply: directory
/// records already packed into the trailing region of regs by the
/// dir helper, `IoStatusBlock.Information` = byte count.
pub(crate) unsafe fn emit_dir_information(reply_lease: ReplyLease, bytes_packed: u64) {
    unsafe { emit_iosb_ack(reply_lease, bytes_packed) };
}

/// Emit a successful `NtQueryVolumeInformationFile` reply.
///
/// Wire layout: `IO_STATUS_BLOCK` followed by the selected
/// `FILE_FS_*_INFORMATION` payload. Variable-length UTF-16 names
/// are capped to the reply register capacity.
pub(crate) unsafe fn emit_volume_information(
    reply_lease: ReplyLease,
    intent: StatfsReplyIntent,
    stats: &VStatfs,
) {
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    let payload_off = unsafe {
        pack_iosb_at_zero(
            &mut out,
            IoStatusBlock {
                status: 0,
                _reserved: 0,
                information: 0,
            },
        )
    };

    let payload_len = match intent {
        StatfsReplyIntent::NtFileFsVolumeInformation => {
            pack_file_fs_volume_information(&mut out, payload_off, stats)
        }
        StatfsReplyIntent::NtFileFsSizeInformation => {
            pack_file_fs_size_information(&mut out, payload_off, stats)
        }
        StatfsReplyIntent::NtFileFsAttributeInformation => {
            pack_file_fs_attribute_information(&mut out, payload_off, stats)
        }
        StatfsReplyIntent::NtFileFsDeviceInformation => {
            pack_file_fs_device_information(&mut out, payload_off)
        }
        StatfsReplyIntent::PosixStatvfs => None,
    };

    let Some(payload_len) = payload_len else {
        unsafe { emit_ntstatus_error(reply_lease, VfsError::Inval) };
        return;
    };

    let iosb = IoStatusBlock {
        status: 0,
        _reserved: 0,
        information: payload_len as u64,
    };
    unsafe {
        pack_iosb_at_zero(&mut out, iosb);
    }
    out.length = ((payload_off + payload_len + 7) / 8) as u64;
    reply_send(reply_lease, &out);
}

fn regs_bytes_mut(out: &mut TronaMsg) -> &mut [u8] {
    let byte_len = out.regs.len() * 8;
    unsafe { ::core::slice::from_raw_parts_mut(out.regs.as_mut_ptr() as *mut u8, byte_len) }
}

fn write_u8(out: &mut TronaMsg, off: usize, value: u8) -> bool {
    let bytes = regs_bytes_mut(out);
    if off >= bytes.len() {
        return false;
    }
    bytes[off] = value;
    true
}

fn write_u32(out: &mut TronaMsg, off: usize, value: u32) -> bool {
    let bytes = regs_bytes_mut(out);
    if off + 4 > bytes.len() {
        return false;
    }
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
    true
}

fn write_i64(out: &mut TronaMsg, off: usize, value: i64) -> bool {
    let bytes = regs_bytes_mut(out);
    if off + 8 > bytes.len() {
        return false;
    }
    bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
    true
}

fn write_utf16le_utf8(out: &mut TronaMsg, off: usize, s: &[u8]) -> Option<usize> {
    let bytes = regs_bytes_mut(out);
    if off > bytes.len() {
        return None;
    }
    super::utf16::utf8_to_utf16le_bytes(s, &mut bytes[off..])
}

fn statfs_block_size(stats: &VStatfs) -> u32 {
    if stats.frsize != 0 {
        stats.frsize
    } else if stats.bsize != 0 {
        stats.bsize
    } else {
        4096
    }
}

fn pack_file_fs_volume_information(
    out: &mut TronaMsg,
    off: usize,
    stats: &VStatfs,
) -> Option<usize> {
    // FILE_FS_VOLUME_INFORMATION:
    // LARGE_INTEGER creation, ULONG serial, ULONG label_len,
    // BOOLEAN supports_objects, WCHAR label[].
    let label_off = off + 18;
    let label_len = write_utf16le_utf8(out, label_off, stats.volume_label())?;
    if !write_i64(out, off, 0)
        || !write_u32(out, off + 8, stats.fsid as u32)
        || !write_u32(out, off + 12, label_len as u32)
        || !write_u8(out, off + 16, 0)
    {
        return None;
    }
    Some(18 + label_len)
}

fn pack_file_fs_size_information(out: &mut TronaMsg, off: usize, stats: &VStatfs) -> Option<usize> {
    const BYTES_PER_SECTOR: u32 = 512;
    let block_size = statfs_block_size(stats);
    let sectors_per_allocation_unit = (block_size / BYTES_PER_SECTOR).max(1);
    // FILE_FS_SIZE_INFORMATION:
    // LARGE_INTEGER total_units, LARGE_INTEGER available_units,
    // ULONG sectors_per_unit, ULONG bytes_per_sector.
    if !write_i64(out, off, stats.blocks.min(i64::MAX as u64) as i64)
        || !write_i64(out, off + 8, stats.bavail.min(i64::MAX as u64) as i64)
        || !write_u32(out, off + 16, sectors_per_allocation_unit)
        || !write_u32(out, off + 20, BYTES_PER_SECTOR)
    {
        return None;
    }
    Some(24)
}

fn pack_file_fs_attribute_information(
    out: &mut TronaMsg,
    off: usize,
    stats: &VStatfs,
) -> Option<usize> {
    let fs_name_off = off + 12;
    let fs_name_len = write_utf16le_utf8(out, fs_name_off, stats.fs_name())?;
    if !write_u32(out, off, 0)
        || !write_u32(out, off + 4, stats.namemax)
        || !write_u32(out, off + 8, fs_name_len as u32)
    {
        return None;
    }
    Some(12 + fs_name_len)
}

fn pack_file_fs_device_information(out: &mut TronaMsg, off: usize) -> Option<usize> {
    if !write_u32(out, off, 0) || !write_u32(out, off + 4, 0) {
        return None;
    }
    Some(8)
}
