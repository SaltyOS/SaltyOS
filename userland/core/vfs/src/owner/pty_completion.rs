// SPDX-License-Identifier: GPL-2.0-only
//
//! posix_ttysrv `BackendSessionSlot::completion_fn` — completion
//! router for pty / ptmx / pts lifecycle ops.
//!
//! Pairs with `posix::device::issue_pty_*`. PtyResume's
//! `op_type` selects the reply shape: open returns a new pty fd,
//! read/write return byte counts (with an inline payload for read),
//! ioctl returns the requested attribute, and the tcgetattr /
//! tcsetattr arms decode the 80-byte termios payload.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::core::identity::FsInstanceId;
use crate::ipc::protocol::backend::VFS_BACKEND_REPLY_OK;
use crate::ipc::protocol::public::vfs_error_to_public_reply;
use crate::owner::VfsState;
use crate::owner::pending::{PendingKindPayload, TxId};
use crate::owner::resume::Resume;
use trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
use trona_server::ReplyLease;

// ---------------------------------------------------------------------------
// PtyResume `op_type` discriminator values
// ---------------------------------------------------------------------------

pub(crate) const PTYRESUME_OP_OPEN: u8 = 1;
pub(crate) const PTYRESUME_OP_READ: u8 = 2;
pub(crate) const PTYRESUME_OP_WRITE: u8 = 3;
pub(crate) const PTYRESUME_OP_IOCTL: u8 = 4;
pub(crate) const PTYRESUME_OP_TCGETATTR: u8 = 5;
pub(crate) const PTYRESUME_OP_TCSETATTR: u8 = 6;
pub(crate) const PTYRESUME_OP_CTTY_DEV: u8 = 7;

/// Termios payload size on the wire — 6 scalar words (`c_iflag,
/// c_oflag, c_cflag, c_lflag, c_ispeed, c_ospeed`) followed by the
/// 32-byte `c_cc` array, packed 8 bytes per `regs[]` slot. Matches
/// posix_ttysrv's `handle_pty_tc{set,get}attr` decode.
pub(crate) const TERMIOS_BYTES: usize = 80;
pub(crate) const TERMIOS_WORDS: usize = (TERMIOS_BYTES + 7) / 8; // 10

/// Registered into the posix_ttysrv `BackendSessionSlot::completion_fn`
/// at session-attach time.
pub(crate) unsafe fn pty_completion(
    state: &mut VfsState,
    _fs_id: FsInstanceId,
    _tx_id: TxId,
    _kind_payload: &PendingKindPayload,
    resume_ctx: Resume,
    backend_session_idx: u32,
    reply_lease: Option<ReplyLease>,
    reply_msg: &TronaMsg,
    personality: crate::personality::Personality,
) {
    let _ = personality;
    // Every return path below releases the backend-session credit
    // reserved at issue time — mirroring the saltyfs / fb / netsrv
    // completion routers so a posix_ttysrv session never leaks a
    // credit when an op completes (success, error, or stamping
    // mismatch).
    // Ioctls routed through the generic vop path (`devfs_ioctl` →
    // `do_ioctl_from_fd`) arrive with a `FillIoctlReply` resume rather
    // than `Resume::Pty`. Project posix_ttysrv's reply into the
    // per-command POSIX ioctl shape and emit it.
    if let Resume::Fs(crate::owner::resume::FsResume::FillIoctlReply { cmd, reply, .. }) =
        resume_ctx
    {
        let result = project_pty_ioctl_reply(cmd, reply_msg);
        state.backend_credit_release_for_session_idx(backend_session_idx);
        if let Some(l) = reply_lease {
            unsafe { crate::personality::reply::emit_ioctl(l, reply, result) };
        }
        return;
    }
    // `open("/dev/tty")` parked on a controlling-tty lookup: install +
    // bind the resolved pty (or fail the open when there is no ctty).
    if let Resume::Fs(crate::owner::resume::FsResume::BindCttyOpen {
        client,
        vnode_h,
        anchor,
        spec,
        action,
        reply,
    }) = resume_ctx
    {
        let found = reply_msg.label == VFS_BACKEND_REPLY_OK;
        let pty_id = reply_msg.regs[0] as u32;
        state.backend_credit_release_for_session_idx(backend_session_idx);
        unsafe {
            crate::ops::open::resume_bind_ctty_open(
                state,
                found,
                pty_id,
                client,
                vnode_h,
                anchor,
                spec,
                action,
                reply,
                reply_lease,
            );
        }
        return;
    }
    // Controlling-tty binding dump prefixing a tty-bearing init read:
    // cache the bindings into the snapshot and fire the read's first init
    // query. This op carries no client lease (it lives on the snapshot),
    // so `reply_lease` is `None` here.
    if let Resume::Fs(crate::owner::resume::FsResume::CttyDump { snapshot }) = resume_ctx {
        state.backend_credit_release_for_session_idx(backend_session_idx);
        crate::owner::init_rpc::ctty_dump_reply_complete(state, snapshot, reply_msg);
        return;
    }
    let pty_resume = match resume_ctx {
        Resume::Pty(r) => r,
        _ => {
            // Wrong-resume drop — finalise the lease through the
            // kernel cancel path so the caller observes a real
            // error rather than a stuck reply slot.
            if let Some(l) = reply_lease {
                crate::owner::op::reply_drop(l);
            }
            state.backend_credit_release_for_session_idx(backend_session_idx);
            return;
        }
    };
    if reply_lease
        .as_ref()
        .map(|l| l.epoch() != pty_resume.client_badge)
        .unwrap_or(false)
    {
        if let Some(l) = reply_lease {
            crate::owner::op::reply_drop(l);
        }
        state.backend_credit_release_for_session_idx(backend_session_idx);
        return;
    }

    if reply_msg.label != VFS_BACKEND_REPLY_OK {
        let err = VfsError::from_backend_reply(reply_msg.label);
        emit_error(reply_lease, err);
        state.backend_credit_release_for_session_idx(backend_session_idx);
        return;
    }

    match pty_resume.op_type {
        PTYRESUME_OP_OPEN => {
            // Reply: regs[0] = new pty fd / object slot. The caller
            // (open path) already paired the slot to a vnode so we
            // forward the slot directly.
            let mut out = TronaMsg::default();
            out.label = VFS_PUBLIC_REPLY_OK;
            out.regs[0] = reply_msg.regs[0];
            out.length = 1;
            send_reply(reply_lease, &out);
        }
        PTYRESUME_OP_READ => {
            // Reply: regs[0] = bytes_read, regs[1..] = data.
            let mut out = TronaMsg::default();
            out.label = VFS_PUBLIC_REPLY_OK;
            let len = (reply_msg.length as usize).min(out.regs.len());
            for i in 0..len {
                out.regs[i] = reply_msg.regs[i];
            }
            out.length = reply_msg.length;
            send_reply(reply_lease, &out);
        }
        PTYRESUME_OP_WRITE => {
            // Reply: regs[0] = bytes_written.
            let mut out = TronaMsg::default();
            out.label = VFS_PUBLIC_REPLY_OK;
            out.regs[0] = reply_msg.regs[0];
            out.length = 1;
            send_reply(reply_lease, &out);
        }
        PTYRESUME_OP_IOCTL => {
            // Reply: regs[0] = result, regs[1..] = optional payload.
            // Forward the backend reply verbatim — the caller knows
            // the per-cmd shape.
            let mut out = TronaMsg::default();
            out.label = VFS_PUBLIC_REPLY_OK;
            let len = (reply_msg.length as usize).min(out.regs.len());
            for i in 0..len {
                out.regs[i] = reply_msg.regs[i];
            }
            out.length = reply_msg.length;
            send_reply(reply_lease, &out);
        }
        PTYRESUME_OP_TCGETATTR => {
            // Reply: regs[0..10] = packed termios bytes (80 bytes).
            let mut out = TronaMsg::default();
            out.label = VFS_PUBLIC_REPLY_OK;
            for i in 0..TERMIOS_WORDS.min(out.regs.len()) {
                out.regs[i] = reply_msg.regs[i];
            }
            out.length = TERMIOS_WORDS as u64;
            send_reply(reply_lease, &out);
        }
        PTYRESUME_OP_TCSETATTR => {
            // Reply: 0-arg success.
            emit_ok_empty(reply_lease);
        }
        PTYRESUME_OP_CTTY_DEV => {
            // Reply: regs[0] = pty_id of the session's controlling tty.
            // Map it to a synthetic tty_dev: pty0 is the console, every
            // other pty is a pts numbered from TTY_DEV_PTS_BASE.
            let pty_id = reply_msg.regs[0];
            let tty_dev = if pty_id == 0 {
                trona_protocol::posix_abi::tty::TTY_DEV_CONSOLE
            } else {
                trona_protocol::posix_abi::tty::TTY_DEV_PTS_BASE + pty_id
            };
            let mut out = TronaMsg::default();
            out.label = VFS_PUBLIC_REPLY_OK;
            out.regs[0] = tty_dev;
            out.length = 1;
            send_reply(reply_lease, &out);
        }
        _ => {
            emit_error(reply_lease, VfsError::Inval);
        }
    }
    state.backend_credit_release_for_session_idx(backend_session_idx);
}

/// Project a posix_ttysrv `PTY_IOCTL` reply into the per-command POSIX
/// ioctl reply shape. `TIOCGWINSZ` packs `(rows, cols)` into a
/// `struct winsize`; other tty ioctls (e.g. `TIOCSWINSZ`, `TIOCSPGRP`)
/// carry no payload and surface as a zero-arg success.
fn project_pty_ioctl_reply(
    cmd: u32,
    reply_msg: &TronaMsg,
) -> Result<crate::core::vop::IoctlReply, VfsError> {
    if reply_msg.label != VFS_BACKEND_REPLY_OK {
        return Err(VfsError::from_backend_reply(reply_msg.label));
    }
    let mut out = crate::core::vop::IoctlReply::EMPTY;
    if cmd as u64 == trona_protocol::posix_abi::tty::TIOCGWINSZ {
        // posix_ttysrv reply: regs[0] = rows, regs[1] = cols. The POSIX client
        // reads a length-2 reply as `regs[0]` = ws_row and `regs[1]` = ws_col,
        // so surface the two values as separate words rather than one packed
        // winsize word.
        out.words[0] = reply_msg.regs[0] & 0xFFFF;
        out.words[1] = reply_msg.regs[1] & 0xFFFF;
        out.word_count = 2;
        out.byte_count = 8;
    }
    Ok(out)
}

fn send_reply(lease: Option<ReplyLease>, out: &TronaMsg) {
    if let Some(l) = lease {
        // SAFETY: The completion dispatcher owns the parked reply lease.
        crate::owner::op::reply_send(l, out);
    }
}

fn emit_ok_empty(lease: Option<ReplyLease>) {
    let Some(l) = lease else { return };
    let mut out = TronaMsg::default();
    out.label = VFS_PUBLIC_REPLY_OK;
    out.length = 0;
    // SAFETY: The completion dispatcher owns the parked reply lease.
    crate::owner::op::reply_send(l, &out);
}

fn emit_error(lease: Option<ReplyLease>, e: VfsError) {
    let Some(l) = lease else { return };
    let mut out = TronaMsg::default();
    out.label = vfs_error_to_public_reply(e);
    out.length = 0;
    // SAFETY: The completion dispatcher owns the parked reply lease.
    crate::owner::op::reply_send(l, &out);
}
