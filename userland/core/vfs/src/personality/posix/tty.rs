// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_ISATTY` / `VFS_TCGETATTR` / `VFS_TCSETATTR` — terminal
//! query / control helpers routed through vfs.
//!
//! POSIX terminals reach vfs as `VnodeKind::CharDev` device vnodes
//! whose backing object is the pty server (`posix_ttysrv`). These
//! handlers resolve the `fd` to its open object, validate that the
//! underlying vnode is a tty (kind == `Char` and the device matches
//! a registered pty endpoint), and delegate to the device backend
//! for the termios payload.
//!
//! `isatty(fd)` is a tty-only existence check: returns `1` when the
//! resolved object is a tty, `0` otherwise. The wire follows the
//! POSIX `bool`-as-i32 convention.
//!
//! `tcgetattr` / `tcsetattr` carry a packed `struct termios` (the
//! 96-byte BSD shape used by basaltc) over `regs[]`; the device
//! backend's `tty_ioctl` entry handles the heavy lifting.
//!
//! ## Wire layout
//!
//! `VFS_ISATTY`:
//!   regs[0] = fd (i32)
//!   reply.regs[0] = 1 (is a tty) or 0 (not a tty)
//!
//! `VFS_TCGETATTR`:
//!   regs[0] = fd (i32)
//!   reply.regs[0..12] = packed termios bytes (96 bytes)
//!
//! `VFS_TCSETATTR`:
//!   regs[0] = fd (i32)
//!   regs[1] = optional_action (TCSANOW / TCSADRAIN / TCSAFLUSH)
//!   regs[2..14] = packed termios bytes
//!   reply: empty success.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::core::vnode::VnodeKind;
use crate::owner::VfsState;
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::types::ClientHandle;

// ---------------------------------------------------------------------------
// VFS_ISATTY
// ---------------------------------------------------------------------------

pub(crate) unsafe fn handle_isatty(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let fd = msg.regs[0] as i32;
    if fd < 0 {
        send_reply_err_for_client(state, client, reply_lease, VfsError::BadF);
        return;
    }
    let Some(open_h) = state.open_object_at(client, fd as usize) else {
        send_reply_err_for_client(state, client, reply_lease, VfsError::BadF);
        return;
    };
    let vh = match state.open_objects.get(open_h) {
        Some(o) => o.vnode,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::BadF);
            return;
        }
    };
    let is_tty = match state.vnodes.get(vh) {
        Some(v) => matches!(v.kind, VnodeKind::CharDev),
        None => false,
    };

    let mut out = TronaMsg::default();
    out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
    out.regs[0] = if is_tty { 1 } else { 0 };
    out.length = 1;
    crate::owner::op::reply_send(reply_lease, &out);
}

// ---------------------------------------------------------------------------
// VFS_TCGETATTR
// ---------------------------------------------------------------------------

/// Termios payload staging size: 6 scalar words (iflag/oflag/cflag/
/// lflag/ispeed/ospeed) + 32-byte c_cc = 80 bytes (10 words) at
/// regs[2..12]. device.rs forwards that register image to
/// posix_ttysrv, whose `handle_pty_tcsetattr` reads the same layout.
const TERMIOS_BYTES: usize = 80;
/// Minimum tcsetattr message length: regs[0]=fd, regs[1]=action,
/// regs[2..12]=termios → 12 words. Rejects truncated payloads that
/// would drop the tail of c_cc.
const TERMIOS_MIN_REGS: u64 = 12;

pub(crate) unsafe fn handle_tcgetattr(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        // Resolve the fd to its pty target; this honours a bound
        // `/dev/tty` handle (the caller session's controlling tty) and
        // rejects non-tty fds.
        let (pty_id, side) =
            match crate::personality::posix::device::pty_target_for_fd(state, client, fd) {
                Ok(Some(t)) => t,
                Ok(None) => {
                    send_reply_err_for_client(state, client, reply_lease, VfsError::NotTty);
                    return;
                }
                Err(e) => {
                    send_reply_err_for_client(state, client, reply_lease, e);
                    return;
                }
            };
        crate::personality::posix::device::handle_tcgetattr_for_pty(
            state,
            client,
            pty_id,
            side,
            reply_lease,
        );
    }
}

// ---------------------------------------------------------------------------
// VFS_TCSETATTR
// ---------------------------------------------------------------------------

pub(crate) unsafe fn handle_tcsetattr(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let action = msg.regs[1] as u32;
        if msg.length < TERMIOS_MIN_REGS {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }
        let (pty_id, side) =
            match crate::personality::posix::device::pty_target_for_fd(state, client, fd) {
                Ok(Some(t)) => t,
                Ok(None) => {
                    send_reply_err_for_client(state, client, reply_lease, VfsError::NotTty);
                    return;
                }
                Err(e) => {
                    send_reply_err_for_client(state, client, reply_lease, e);
                    return;
                }
            };

        // Snapshot the termios bytes off the wire — the device
        // backend's ioctl entry consumes them.
        let mut termios = [0u8; TERMIOS_BYTES];
        let src = (&raw const msg.regs[2]) as *const u8;
        for i in 0..TERMIOS_BYTES {
            termios[i] = *src.add(i);
        }
        crate::personality::posix::device::handle_tcsetattr_for_pty(
            state,
            client,
            pty_id,
            side,
            action,
            &termios,
            reply_lease,
        );
    }
}

// ---------------------------------------------------------------------------
// VFS_PTY_READY
// ---------------------------------------------------------------------------

pub(crate) unsafe fn handle_pty_ready(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let pty_id = msg.regs[0] as u16;
    let mut pending = [crate::owner::pending::PendingOpHandle::INVALID; 32];
    let mut pending_count = 0usize;
    state.pending_ops.for_each_active(|h, op| {
        if pending_count == pending.len() {
            return false;
        }
        if op.core.kind != crate::owner::op::OpKind::Pty {
            return true;
        }
        if let crate::owner::resume::Resume::Pty(r) = op.resume {
            if r.pty_index == pty_id && r.op_type == crate::owner::pty_completion::PTYRESUME_OP_READ
            {
                pending[pending_count] = h;
                pending_count += 1;
            }
        }
        true
    });
    let mut issued = 0u64;
    let mut failed = 0u64;
    for h in pending.iter().take(pending_count).copied() {
        if h == crate::owner::pending::PendingOpHandle::INVALID {
            continue;
        }
        match unsafe { crate::personality::posix::device::issue_pty_collect_for_ready(state, h) } {
            Ok(()) => issued += 1,
            Err(_) => failed += 1,
        }
    }
    send_reply_ok_for_client(state, client, reply_lease, &[pty_id as u64, issued, failed]);
}
