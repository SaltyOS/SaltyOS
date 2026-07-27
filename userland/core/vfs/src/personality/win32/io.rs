// SPDX-License-Identifier: GPL-2.0-only
//
//! NT fd-based I/O entries — `NtReadFile` / `NtWriteFile` /
//! `NtFlushBuffersFile` + `NtSetInformationFile` for the
//! `FilePositionInformation` and `FileEndOfFileInformation`
//! sub-classes (the rest of NtSetInformationFile lands with
//! the mutation slice).
//!
//! Wire layouts (NT-native):
//!
//! ## NtReadFile (`WIN32_NT_READ_FILE = 0x543`)
//! ```text
//!   byte 0..4    FileHandle    (i32 fd)
//!   byte 4..8    Length        (u32, requested byte count)
//!   byte 8..16   ByteOffset    (LARGE_INTEGER, u64::MAX = current)
//!   byte 16..20  Flags         (u32, bit 0 = SHM mode)
//!   byte 20..24  ClientShmLen  (u32, SHM mode only)
//!   byte 24..32  ClientShmOff  (u64, SHM mode only)
//! ```
//!
//! ## NtWriteFile (`WIN32_NT_WRITE_FILE = 0x544`)
//! Same shape as NtReadFile; inline payload is packed into
//! `regs[4..]` byte-wise (8 per word) in inline mode.
//!
//! ## NtFlushBuffersFile (`WIN32_NT_FLUSH_BUFFERS_FILE = 0x549`)
//! ```text
//!   byte 0..4    FileHandle (i32 fd)
//! ```
//!
//! ## NtSetInformationFile (FilePosition / EOF)
//! ```text
//!   byte 0..4    FileHandle           (i32 fd)
//!   byte 4..8    Length               (u32, payload bytes)
//!   byte 8..12   FileInformationClass (u32, 14 = Position, 20 = EOF)
//!   byte 12..16  reserved
//!   byte 16..    payload (LARGE_INTEGER)
//! ```

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::{
    AckReplyIntent, ReadReplyIntent, SeekReplyIntent, WriteReplyIntent,
    io::{INLINE_WRITE_MAX, SeekWhence},
};
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

const NT_RW_FLAG_SHM: u32 = 0x0000_0001;

const FILE_POSITION_INFORMATION: u32 = 14;
const FILE_END_OF_FILE_INFORMATION: u32 = 20;

/// `NtReadFile` entry.
pub(crate) unsafe fn handle_nt_read_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = (msg.regs[0] & 0xFFFF_FFFF) as i32;
        let length = (msg.regs[0] >> 32) as u32;
        let byte_offset = msg.regs[1];
        let flags = (msg.regs[2] & 0xFFFF_FFFF) as u32;

        if (flags & NT_RW_FLAG_SHM) != 0 {
            let client_shm_len = (msg.regs[2] >> 32) as u64;
            let client_shm_offset = msg.regs[3];
            crate::ops::io::do_read_fd_shm(
                state,
                client,
                fd,
                byte_offset,
                length as usize,
                client_shm_offset,
                client_shm_len,
                ReadReplyIntent::NtReadFile,
                reply_lease,
            );
        } else {
            crate::ops::io::do_read_fd_inline(
                state,
                client,
                fd,
                byte_offset,
                length as usize,
                ReadReplyIntent::NtReadFile,
                reply_lease,
            );
        }
    }
}

/// `NtWriteFile` entry.
pub(crate) unsafe fn handle_nt_write_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = (msg.regs[0] & 0xFFFF_FFFF) as i32;
        let length = (msg.regs[0] >> 32) as u32;
        let byte_offset = msg.regs[1];
        let flags = (msg.regs[2] & 0xFFFF_FFFF) as u32;

        if (flags & NT_RW_FLAG_SHM) != 0 {
            let client_shm_len = (msg.regs[2] >> 32) as u64;
            let client_shm_offset = msg.regs[3];
            crate::ops::io::do_write_fd_shm(
                state,
                client,
                fd,
                byte_offset,
                length as usize,
                client_shm_offset,
                client_shm_len,
                WriteReplyIntent::NtWriteFile,
                reply_lease,
            );
            return;
        }
        // Inline payload at regs[4..].
        let effective_count = (length as usize).min(INLINE_WRITE_MAX);
        let mut scratch = [0u8; INLINE_WRITE_MAX];
        let words = (effective_count + 7) / 8;
        for i in 0..words {
            if 4 + i >= msg.regs.len() {
                break;
            }
            let word = msg.regs[4 + i].to_le_bytes();
            let base = i * 8;
            let take = (effective_count - base).min(8);
            scratch[base..base + take].copy_from_slice(&word[..take]);
        }
        crate::ops::io::do_write_fd_inline(
            state,
            client,
            fd,
            byte_offset,
            &scratch[..effective_count],
            WriteReplyIntent::NtWriteFile,
            reply_lease,
        );
    }
}

/// `NtFlushBuffersFile` entry.
pub(crate) unsafe fn handle_nt_flush_buffers_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = (msg.regs[0] & 0xFFFF_FFFF) as i32;
        crate::ops::io::do_fsync_fd(
            state,
            client,
            fd,
            AckReplyIntent::NtIoStatusBlock,
            reply_lease,
        );
    }
}

/// `NtSetInformationFile` — FilePosition / EOF sub-classes only.
/// Other sub-classes (Rename / Disposition / Basic) are routed
/// to the mutation slice.
///
/// Returns `true` if the info_class was handled here, `false`
/// if the caller should defer to the mutation slice.
pub(crate) unsafe fn handle_nt_set_information_file_io(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    info_class: u32,
    reply_lease: ReplyLease,
) -> bool {
    unsafe {
        match info_class {
            FILE_POSITION_INFORMATION => {
                let fd = (msg.regs[0] & 0xFFFF_FFFF) as i32;
                let Some(new_pos) = super::nt_decode::decode_file_position_information(msg, 16)
                else {
                    super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
                    return true;
                };
                if new_pos < 0 {
                    super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
                    return true;
                }
                crate::ops::io::do_seek_fd(
                    state,
                    client,
                    fd,
                    new_pos,
                    SeekWhence::Set,
                    SeekReplyIntent::NtSetFilePosition,
                    reply_lease,
                );
                true
            }
            FILE_END_OF_FILE_INFORMATION => {
                let fd = (msg.regs[0] & 0xFFFF_FFFF) as i32;
                let Some(new_size) = super::nt_decode::decode_file_end_of_file_information(msg, 16)
                else {
                    super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
                    return true;
                };
                crate::ops::io::do_truncate_fd(
                    state,
                    client,
                    fd,
                    new_size,
                    AckReplyIntent::NtIoStatusBlock,
                    reply_lease,
                );
                true
            }
            _ => false,
        }
    }
}
