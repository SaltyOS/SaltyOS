// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX fd-based I/O entries — `VFS_READ` / `VFS_WRITE` /
//! `VFS_SEEK` / `VFS_FSYNC` / `VFS_FDATASYNC` / `VFS_FTRUNCATE`.
//! Path-based `VFS_TRUNCATE` walks namei first and lands on the
//! `SetAttr` terminal.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::{
    AckReplyIntent, ReadReplyIntent, SeekReplyIntent, WriteReplyIntent,
    io::{INLINE_WRITE_MAX, SeekWhence},
};
use crate::owner::VfsState;
use crate::server::types::ClientHandle;
use trona_protocol::vfs::public::VFS_RW_FLAG_SHM;

/// `VFS_READ` entry.
///
/// Wire layout:
/// - `regs[0]` — fd (i32).
/// - `regs[1]` — file_offset (u64); `u64::MAX` for current.
/// - `regs[2]` — count (u64).
/// - `regs[3]` — flags (`VFS_RW_FLAG_SHM`).
/// - `regs[4..]` — SHM mode: `regs[4]=client_shm_offset`,
///   `regs[5]=client_shm_len`. Inline mode: ignored.
pub(crate) unsafe fn handle_read(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let offset_in = msg.regs[1];
        let count = msg.regs[2] as usize;
        let flags = msg.regs[3];
        if (flags & VFS_RW_FLAG_SHM) != 0 {
            let client_shm_offset = msg.regs[4];
            let client_shm_len = msg.regs[5];
            crate::ops::io::do_read_fd_shm(
                state,
                client,
                fd,
                offset_in,
                count,
                client_shm_offset,
                client_shm_len,
                ReadReplyIntent::PosixRead,
                reply_lease,
            );
        } else {
            match crate::personality::posix::device::pty_target_for_fd(state, client, fd) {
                Ok(Some(_)) => {
                    crate::personality::posix::device::handle_pty_read_inline_for_fd(
                        state,
                        client,
                        fd,
                        count,
                        reply_lease,
                    );
                    return;
                }
                Ok(None) => {}
                Err(e) => {
                    crate::personality::wire::send_reply_err_for_client(
                        state,
                        client,
                        reply_lease,
                        e,
                    );
                    return;
                }
            }
            // Socket fds have no vnode; serve plain read() from the
            // AF_UNIX ring and reply in the same inline format a file
            // read uses.
            if crate::personality::posix::socket::fd_is_socket(state, client, fd) {
                let cap = count.min(crate::ops::io::INLINE_READ_MAX);
                let mut sock_scratch = [0u8; crate::ops::io::INLINE_READ_MAX];
                match crate::personality::posix::socket::unix_plain_read(
                    state,
                    client,
                    fd,
                    &mut sock_scratch[..cap],
                ) {
                    Ok(n) => crate::personality::reply::emit_read_inline(
                        reply_lease,
                        ReadReplyIntent::PosixRead,
                        Ok(crate::ops::io::InlineReadResult {
                            data: &sock_scratch[..n],
                        }),
                    ),
                    Err(e) => crate::personality::wire::send_reply_err_for_client(
                        state,
                        client,
                        reply_lease,
                        e,
                    ),
                }
                return;
            }
            crate::ops::io::do_read_fd_inline(
                state,
                client,
                fd,
                offset_in,
                count,
                ReadReplyIntent::PosixRead,
                reply_lease,
            );
        }
    }
}

/// `VFS_WRITE` entry. Same wire shape as `VFS_READ` plus inline
/// payload bytes packed in `regs[4..]` for inline mode.
pub(crate) unsafe fn handle_write(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let offset_in = msg.regs[1];
        let count = msg.regs[2] as usize;
        let flags = msg.regs[3];
        if (flags & VFS_RW_FLAG_SHM) != 0 {
            let client_shm_offset = msg.regs[4];
            let client_shm_len = msg.regs[5];
            crate::ops::io::do_write_fd_shm(
                state,
                client,
                fd,
                offset_in,
                count,
                client_shm_offset,
                client_shm_len,
                WriteReplyIntent::PosixWrite,
                reply_lease,
            );
            return;
        }
        // Inline-mode: decode bytes from the wire's regs[4..] area
        // into a scratch buffer, clamped at INLINE_WRITE_MAX.
        let effective_count = count.min(INLINE_WRITE_MAX);
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
        match crate::personality::posix::device::pty_target_for_fd(state, client, fd) {
            Ok(Some(_)) => {
                crate::personality::posix::device::handle_pty_write_inline_for_fd(
                    state,
                    client,
                    fd,
                    &scratch[..effective_count],
                    reply_lease,
                );
                return;
            }
            Ok(None) => {}
            Err(e) => {
                crate::personality::wire::send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        }
        // Socket fds carry no vnode (SocketState lives in `personality_aux`),
        // so route plain write() to the AF_UNIX ring path instead of the
        // vnode/vop write, which would fail with EIO.
        if crate::personality::posix::socket::fd_is_socket(state, client, fd) {
            match crate::personality::posix::socket::unix_plain_write(
                state,
                client,
                fd,
                &scratch[..effective_count],
            ) {
                Ok(n) => crate::personality::wire::send_reply_ok_for_client(
                    state,
                    client,
                    reply_lease,
                    &[n as u64],
                ),
                Err(e) => crate::personality::wire::send_reply_err_for_client(
                    state,
                    client,
                    reply_lease,
                    e,
                ),
            }
            return;
        }
        crate::ops::io::do_write_fd_inline(
            state,
            client,
            fd,
            offset_in,
            &scratch[..effective_count],
            WriteReplyIntent::PosixWrite,
            reply_lease,
        );
    }
}

/// `VFS_SEEK` entry. Wire layout: `regs[0]=fd`, `regs[1]=offset`,
/// `regs[2]=whence`.
pub(crate) unsafe fn handle_seek(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let offset = msg.regs[1] as i64;
        let whence_u32 = msg.regs[2] as u32;
        let Some(whence) = SeekWhence::from_posix(whence_u32) else {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        };
        crate::ops::io::do_seek_fd(
            state,
            client,
            fd,
            offset,
            whence,
            SeekReplyIntent::PosixSeek,
            reply_lease,
        );
    }
}

/// `VFS_FSYNC` / `VFS_FDATASYNC` entry. Wire layout: `regs[0]=fd`.
pub(crate) unsafe fn handle_fsync(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        crate::ops::io::do_fsync_fd(state, client, fd, AckReplyIntent::PosixAck, reply_lease);
    }
}

/// `VFS_FTRUNCATE` entry. Wire layout: `regs[0]=fd`,
/// `regs[1]=new_size`.
///
/// Path-based `VFS_TRUNCATE` walks namei first and lands on the
/// mutation slice's `SetAttr` terminal — that path is not
/// handled here. The label dispatcher routes the path-based
/// case via the `setattr` entry once the mutation slice lands.
pub(crate) unsafe fn handle_ftruncate(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let new_size = msg.regs[1];
        crate::ops::io::do_truncate_fd(
            state,
            client,
            fd,
            new_size,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}
