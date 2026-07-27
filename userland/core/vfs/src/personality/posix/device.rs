// SPDX-License-Identifier: GPL-2.0-only
//
//! Backend-driven character device routing — PTY master / slave,
//! framebuffer, the bridge devices that vfs cannot resolve from
//! its own state alone.
//!
//! `devfs/vops.rs` handles the inline character devices entirely
//! on its own:
//!
//! * `null` / `zero` — synthesised inside vfs.
//! * `urandom` — synthesised from the kernite RNG cap.
//! * `console` — substrate serial sink (write-only).
//!
//! Anything that requires interacting with another userland server
//! lands here:
//!
//! * `tty` / `ptmx` / `pts/N` — driven by `posix_ttysrv` over a
//!   dedicated `BackendSessionSlot`. Read parks until the line
//!   discipline produces input; write submits bytes for the same
//!   discipline to canonicalise.
//! * `fb0` — driven by `dispdrv` over its own session. Today the
//!   read / write surface is the framebuffer pixel array; future
//!   work narrows it to a typed control plane.
//!
//! Every backend-routed device shares the same shape: a single
//! `BACKEND_*` request that parks a `PendingOp`, and a completion
//! handler in the matching `fs::*` client that translates the
//! reply back into a `Resume::*` invocation. This module owns the
//! *issue* side; the matching completion router and `Resume`
//! variant ride on the personality layer.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::core::vnode::VnodeHandle;
use crate::ipc::protocol::correlation::{
    CORRELATION_BACKEND_DISPDRV, CORRELATION_BACKEND_POSIX_TTYSRV, CORRELATION_CLASS_DEV,
    CORRELATION_CLASS_PTY, CORRELATION_HEADER_REG_START, CORRELATION_KIND_REQUEST,
    CorrelationHeader, ensure_correlation_wire_length,
};
use crate::owner::VfsState;
use crate::owner::op::OpState;
use crate::owner::pending::{PendingOpHandle, TxId};
use crate::personality::wire::send_reply_err_for_client;
use crate::server::types::ClientHandle;

// ---------------------------------------------------------------------------
// posix_ttysrv-driven devices (Tty / Ptmx / PtySlave)
// ---------------------------------------------------------------------------

pub(crate) const PTY_SIDE_SLAVE: u8 = 0;
pub(crate) const PTY_SIDE_MASTER: u8 = 1;
pub(crate) const PTY_INLINE_MAX: usize = 152;

pub(crate) const PTY_READ: u64 = trona_protocol::posix::POSIX_TTYSRV_PTY_READ;
pub(crate) const PTY_WRITE: u64 = trona_protocol::posix::POSIX_TTYSRV_PTY_WRITE;
pub(crate) const PTY_MASTER_WRITE: u64 = trona_protocol::posix::POSIX_TTYSRV_PTY_MASTER_WRITE;
pub(crate) const PTY_COLLECT: u64 = trona_protocol::posix::POSIX_TTYSRV_PTY_COLLECT;
pub(crate) const PTY_TCGETATTR: u64 = trona_protocol::posix::POSIX_TTYSRV_PTY_TCGETATTR;
pub(crate) const PTY_TCSETATTR: u64 = trona_protocol::posix::POSIX_TTYSRV_PTY_TCSETATTR;
pub(crate) const PTY_IOCTL: u64 = trona_protocol::posix::POSIX_TTYSRV_PTY_IOCTL;
pub(crate) const PTY_CTTY_PTY_FOR_SID: u64 = trona_protocol::posix::POSIX_TTYSRV_CTTY_PTY_FOR_SID;
pub(crate) const PTY_CTTY_DUMP: u64 = trona_protocol::posix::POSIX_TTYSRV_CTTY_DUMP;

pub(crate) unsafe fn issue_pty_read_inline(
    state: &mut VfsState,
    pty_id: u32,
    side: u8,
    max_count: usize,
) -> Result<PendingOpHandle, VfsError> {
    let session = crate::owner::session::default_pty_session(state)?;
    let send_cap = state
        .backend_sessions
        .get(session)
        .map(|s| s.send_cap.as_raw())
        .ok_or(VfsError::SessionTornDown)?;
    if !state.backend_credit_reserve_for_session(session) {
        return Err(VfsError::Again);
    }
    let (handle, tx_id) = state.reserve_pending_for_pty(session).ok_or_else(|| {
        state.backend_credit_release_for_session(session);
        VfsError::NoMem
    })?;
    let mut req = TronaMsg::default();
    req.label = PTY_READ;
    req.regs[0] = pty_id as u64;
    req.regs[1] = max_count.min(PTY_INLINE_MAX) as u64;
    req.regs[2] = side as u64;
    req.length = 3;
    stamp_pty_async_request(state, session, &mut req, PTY_READ, tx_id)?;
    // SAFETY: `send_cap` is the live backend session endpoint while the
    // reserved credit is held, and `req` remains valid until the write returns.
    let send_err =
        unsafe { trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), send_cap, &raw const req) };
    if send_err != 0 {
        let _ = state.pending_ops.release(handle);
        state.backend_credit_release_for_session(session);
        return Err(VfsError::Io);
    }
    Ok(handle)
}

pub(crate) unsafe fn issue_pty_write_inline(
    state: &mut VfsState,
    pty_id: u32,
    side: u8,
    src: *const u8,
    len: usize,
) -> Result<PendingOpHandle, VfsError> {
    let session = crate::owner::session::default_pty_session(state)?;
    let send_cap = state
        .backend_sessions
        .get(session)
        .map(|s| s.send_cap.as_raw())
        .ok_or(VfsError::SessionTornDown)?;
    if !state.backend_credit_reserve_for_session(session) {
        return Err(VfsError::Again);
    }
    let (handle, tx_id) = state.reserve_pending_for_pty(session).ok_or_else(|| {
        state.backend_credit_release_for_session(session);
        VfsError::NoMem
    })?;
    let count = len.min(PTY_INLINE_MAX);
    let mut req = TronaMsg::default();
    let opcode = if side == PTY_SIDE_MASTER {
        PTY_MASTER_WRITE
    } else {
        PTY_WRITE
    };
    req.label = opcode;
    req.regs[0] = pty_id as u64;
    req.regs[1] = count as u64;
    if !src.is_null() && count != 0 {
        let dst = (&raw mut req.regs[2]) as *mut u8;
        for i in 0..count {
            unsafe {
                *dst.add(i) = *src.add(i);
            }
        }
    }
    req.length = 2 + ((count as u64 + 7) / 8);
    stamp_pty_async_request(state, session, &mut req, opcode, tx_id)?;
    // SAFETY: `send_cap` is the live backend session endpoint while the
    // reserved credit is held, and `req` remains valid until the write returns.
    let send_err =
        unsafe { trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), send_cap, &raw const req) };
    if send_err != 0 {
        let _ = state.pending_ops.release(handle);
        state.backend_credit_release_for_session(session);
        return Err(VfsError::Io);
    }
    Ok(handle)
}

fn stamp_pty_async_request(
    state: &mut VfsState,
    session: crate::owner::session::BackendSessionHandle,
    req: &mut TronaMsg,
    opcode: u64,
    tx_id: TxId,
) -> Result<(), VfsError> {
    let slot = state
        .backend_sessions
        .get_mut(session)
        .ok_or(VfsError::SessionTornDown)?;
    let session_id = slot.session_id;
    let request_seq = slot.alloc_target_seq();
    let words = CorrelationHeader {
        class: CORRELATION_CLASS_PTY,
        backend: CORRELATION_BACKEND_POSIX_TTYSRV,
        kind: CORRELATION_KIND_REQUEST,
        flags: 0,
        session: session_id,
        opcode: opcode as u16,
        _reserved0: 0,
        token: tx_id.raw(),
        request_seq,
        request_seq_secondary: 0,
    }
    .encode_words();
    req.regs[CORRELATION_HEADER_REG_START] = words[0];
    req.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
    req.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
    req.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
    ensure_correlation_wire_length(&mut req.length);
    Ok(())
}

/// Re-issue collection for a PTY read that is already parked on a
/// previous `PTY_READ` request. Called from `VFS_PTY_READY`.
pub(crate) unsafe fn issue_pty_collect_for_ready(
    state: &mut VfsState,
    handle: PendingOpHandle,
) -> Result<(), VfsError> {
    let (session_idx, tx_id, pty_id, side, max_count) = {
        let op = state
            .pending_ops
            .get(handle)
            .ok_or(VfsError::StaleIncarnation)?;
        let crate::owner::resume::Resume::Pty(r) = op.resume else {
            return Err(VfsError::Inval);
        };
        if r.op_type != crate::owner::pty_completion::PTYRESUME_OP_READ {
            return Err(VfsError::Inval);
        }
        if op.core.state == OpState::Running {
            return Ok(());
        }
        (
            op.core.backend_session_idx,
            op.core.tx_id,
            r.pty_index as u32,
            r.side,
            r.max_count as usize,
        )
    };
    let session = state
        .backend_sessions
        .handle_from_slot(session_idx)
        .ok_or(VfsError::SessionTornDown)?;
    let send_cap = state
        .backend_sessions
        .get(session)
        .map(|s| s.send_cap.as_raw())
        .ok_or(VfsError::SessionTornDown)?;
    let mut req = TronaMsg::default();
    req.label = PTY_COLLECT;
    req.regs[0] = pty_id as u64;
    req.regs[1] = max_count.min(PTY_INLINE_MAX) as u64;
    req.regs[2] = side as u64;
    req.length = 3;
    stamp_pty_async_request(state, session, &mut req, PTY_COLLECT, tx_id)?;
    if let Some(op) = state.pending_ops.get_mut(handle) {
        op.core.state = OpState::Running;
    }
    // SAFETY: `send_cap` is the live backend session endpoint and `req`
    // remains valid until the write returns.
    let err =
        unsafe { trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), send_cap, &raw const req) };
    if err != 0 {
        if let Some(op) = state.pending_ops.get_mut(handle) {
            op.core.state = OpState::Queued;
        }
        return Err(VfsError::Io);
    }
    Ok(())
}

pub(crate) unsafe fn pty_target_for_fd(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<Option<(u32, u8)>, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let Some(open_h) = state.open_object_at(client, fd as usize) else {
        return Err(VfsError::BadF);
    };
    let Some(obj) = state.open_objects.get(open_h) else {
        return Err(VfsError::BadF);
    };
    // A bound `/dev/tty` handle routes to the caller session's ctty pty.
    if obj.ctty_pty != u32::MAX {
        return Ok(Some((obj.ctty_pty, PTY_SIDE_SLAVE)));
    }
    let vnode_h = obj.vnode;
    Ok(pty_target_for_vnode(state, vnode_h))
}

pub(crate) fn pty_target_for_vnode(state: &VfsState, vnode_h: VnodeHandle) -> Option<(u32, u8)> {
    let vnode = state.vnodes.get(vnode_h)?;
    if !::core::ptr::eq(vnode.ops, &raw const crate::fs::devfs::DEVFS_VOPS) {
        return None;
    }
    if vnode.data.is_null() {
        return None;
    }
    let vdata = vnode.data as *const crate::fs::devfs::DevfsVnodeData;
    let data = unsafe { &*vdata };
    match data.kind {
        crate::fs::devfs::DevKind::Tty => Some((0, PTY_SIDE_SLAVE)),
        crate::fs::devfs::DevKind::Ptmx => Some((0, PTY_SIDE_MASTER)),
        crate::fs::devfs::DevKind::PtySlave => Some((data.sub_id, PTY_SIDE_SLAVE)),
        // `/dev/console` is the boot console tty, backed by pty0's slave.
        // Routing its data I/O through pty0 puts console reads/writes on the
        // line discipline (input editing, OPOST) instead of a write-only
        // serial sink, and makes the console a real readable terminal.
        crate::fs::devfs::DevKind::Console => Some((0, PTY_SIDE_SLAVE)),
        _ => None,
    }
}

pub(crate) unsafe fn handle_pty_read_inline_for_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    count: usize,
    reply_lease: trona_server::ReplyLease,
) -> bool {
    let (pty_id, side) = match unsafe { pty_target_for_fd(state, client, fd) } {
        Ok(Some(t)) => t,
        Ok(None) => return false,
        Err(e) => {
            send_reply_err_for_client(state, client, reply_lease, e);
            return true;
        }
    };
    match unsafe { issue_pty_read_inline(state, pty_id, side, count) } {
        Ok(handle) => {
            stamp_pty_resume(
                state,
                client,
                handle,
                pty_id,
                side,
                crate::owner::pty_completion::PTYRESUME_OP_READ,
                count.min(PTY_INLINE_MAX) as u32,
                reply_lease,
            );
        }
        Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
    }
    true
}

pub(crate) unsafe fn handle_pty_write_inline_for_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    data: &[u8],
    reply_lease: trona_server::ReplyLease,
) -> bool {
    let (pty_id, side) = match unsafe { pty_target_for_fd(state, client, fd) } {
        Ok(Some(t)) => t,
        Ok(None) => return false,
        Err(e) => {
            send_reply_err_for_client(state, client, reply_lease, e);
            return true;
        }
    };
    match unsafe { issue_pty_write_inline(state, pty_id, side, data.as_ptr(), data.len()) } {
        Ok(handle) => {
            stamp_pty_resume(
                state,
                client,
                handle,
                pty_id,
                side,
                crate::owner::pty_completion::PTYRESUME_OP_WRITE,
                data.len().min(PTY_INLINE_MAX) as u32,
                reply_lease,
            );
        }
        Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
    }
    true
}

// ---------------------------------------------------------------------------
// dispdrv-driven devices (Fb0)
// ---------------------------------------------------------------------------

pub(crate) const FB_GET_INFO: u64 = 0xA00;
pub(crate) const FB_GET_BACKING_MO: u64 = 0xA02;

fn stamp_fb_async_request(
    state: &mut VfsState,
    session: crate::owner::session::BackendSessionHandle,
    req: &mut TronaMsg,
    opcode: u64,
    tx_id: TxId,
) -> Result<(), VfsError> {
    let slot = state
        .backend_sessions
        .get_mut(session)
        .ok_or(VfsError::SessionTornDown)?;
    let session_id = slot.session_id;
    let request_seq = slot.alloc_target_seq();
    let words = CorrelationHeader {
        class: CORRELATION_CLASS_DEV,
        backend: CORRELATION_BACKEND_DISPDRV,
        kind: CORRELATION_KIND_REQUEST,
        flags: 0,
        session: session_id,
        opcode: opcode as u16,
        _reserved0: 0,
        token: tx_id.raw(),
        request_seq,
        request_seq_secondary: 0,
    }
    .encode_words();
    req.regs[CORRELATION_HEADER_REG_START] = words[0];
    req.regs[CORRELATION_HEADER_REG_START + 1] = words[1];
    req.regs[CORRELATION_HEADER_REG_START + 2] = words[2];
    req.regs[CORRELATION_HEADER_REG_START + 3] = words[3];
    ensure_correlation_wire_length(&mut req.length);
    Ok(())
}

pub(crate) unsafe fn issue_fb_get_info(
    state: &mut VfsState,
    vnode_h: VnodeHandle,
) -> Result<PendingOpHandle, VfsError> {
    let session = crate::owner::session::default_fb_session(state)?;
    let send_cap = state
        .backend_sessions
        .get(session)
        .map(|s| s.send_cap.as_raw())
        .ok_or(VfsError::SessionTornDown)?;
    if !state.backend_credit_reserve_for_session(session) {
        return Err(VfsError::Again);
    }
    let (handle, tx_id) = state
        .reserve_pending_for_fb(session, vnode_h)
        .ok_or_else(|| {
            state.backend_credit_release_for_session(session);
            VfsError::NoMem
        })?;
    let mut req = TronaMsg::default();
    req.label = FB_GET_INFO;
    req.length = 0;
    stamp_fb_async_request(state, session, &mut req, FB_GET_INFO, tx_id)?;
    // SAFETY: `send_cap` is the live backend session endpoint while the
    // reserved credit is held, and `req` remains valid until the write returns.
    let send_err =
        unsafe { trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), send_cap, &raw const req) };
    if send_err != 0 {
        let _ = state.pending_ops.release(handle);
        state.backend_credit_release_for_session(session);
        return Err(VfsError::Io);
    }
    Ok(handle)
}

/// Ask dispdrv for the framebuffer backing cap. Reply carries a
/// device-untyped cap; `mmap` maps it into the caller's vspace
/// through `MMAP_KIND_DEVICE`.
pub(crate) unsafe fn issue_fb_get_backing(
    state: &mut VfsState,
    vnode_h: VnodeHandle,
) -> Result<PendingOpHandle, VfsError> {
    let session = crate::owner::session::default_fb_session(state)?;
    let send_cap = state
        .backend_sessions
        .get(session)
        .map(|s| s.send_cap.as_raw())
        .ok_or(VfsError::SessionTornDown)?;
    if !state.backend_credit_reserve_for_session(session) {
        return Err(VfsError::Again);
    }
    let (handle, tx_id) = state
        .reserve_pending_for_fb(session, vnode_h)
        .ok_or_else(|| {
            state.backend_credit_release_for_session(session);
            VfsError::NoMem
        })?;
    let mut req = TronaMsg::default();
    req.label = FB_GET_BACKING_MO;
    req.regs[0] = vnode_h.slot() as u64;
    req.length = 1;
    stamp_fb_async_request(state, session, &mut req, FB_GET_BACKING_MO, tx_id)?;
    // SAFETY: `send_cap` is the live backend session endpoint while the
    // reserved credit is held, and `req` remains valid until the write returns.
    let send_err =
        unsafe { trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), send_cap, &raw const req) };
    if send_err != 0 {
        let _ = state.pending_ops.release(handle);
        state.backend_credit_release_for_session(session);
        return Err(VfsError::Io);
    }
    Ok(handle)
}

pub(crate) unsafe fn fb_target_for_fd(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<Option<VnodeHandle>, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let Some(open_h) = state.open_object_at(client, fd as usize) else {
        return Err(VfsError::BadF);
    };
    let vnode_h = state
        .open_objects
        .get(open_h)
        .map(|o| o.vnode)
        .ok_or(VfsError::BadF)?;
    if fb_target_for_vnode(state, vnode_h) {
        Ok(Some(vnode_h))
    } else {
        Ok(None)
    }
}

pub(crate) fn fb_target_for_vnode(state: &VfsState, vnode_h: VnodeHandle) -> bool {
    let Some(vnode) = state.vnodes.get(vnode_h) else {
        return false;
    };
    if !::core::ptr::eq(vnode.ops, &raw const crate::fs::devfs::DEVFS_VOPS) {
        return false;
    }
    if vnode.data.is_null() {
        return false;
    }
    let vdata = vnode.data as *const crate::fs::devfs::DevfsVnodeData;
    let data = unsafe { &*vdata };
    matches!(data.kind, crate::fs::devfs::DevKind::Fb0)
}

pub(crate) unsafe fn handle_fb_ioctl_for_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    cmd: u32,
    reply_lease: trona_server::ReplyLease,
) -> bool {
    let vnode_h = match unsafe { fb_target_for_fd(state, client, fd) } {
        Ok(Some(h)) => h,
        Ok(None) => return false,
        Err(e) => {
            send_reply_err_for_client(state, client, reply_lease, e);
            return true;
        }
    };
    let is_supported = (cmd as u64) == trona_protocol::posix_abi::tty::FBIOGET_VSCREENINFO
        || (cmd as u64) == trona_protocol::posix_abi::tty::FBIOGET_FSCREENINFO;
    if !is_supported {
        send_reply_err_for_client(state, client, reply_lease, VfsError::NotSup);
        return true;
    }
    match unsafe { issue_fb_get_info(state, vnode_h) } {
        Ok(handle) => {
            let client_badge = state
                .clients
                .get(client)
                .map(|c| c.client_badge)
                .unwrap_or(0);
            stamp_fb_resume(
                state,
                handle,
                vnode_h,
                crate::owner::fb_completion::FBRESUME_OP_GET_INFO,
                cmd,
                reply_lease,
                client_badge,
            );
        }
        Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
    }
    true
}

// ---------------------------------------------------------------------------
// Termios shims — `tcgetattr` / `tcsetattr`
// ---------------------------------------------------------------------------
//
// `posix/tty.rs` resolves the fd, validates that the underlying
// vnode is a tty, and delegates the termios snapshot fetch / set to
// the helpers below. Both routes fan into the per-mount-instance
// posix_ttysrv session; the matching reply path (Pty completion
// router) emits the termios bytes back to the caller.
//
// The PTY completion router decodes the reply and emits the matching
// `VFS_PUBLIC_REPLY_OK` payload, so termios calls use the same
// callback-backed PendingOp path as PTY read/write.

/// `tcgetattr(fd)` shim. Parks a `PendingOp` keyed off
/// `PTYRESUME_OP_TCGETATTR` and issues `PTY_TCGETATTR` against
/// posix_ttysrv. The pty completion router copies the
/// 80-byte termios payload from the backend reply into `regs[0..10]`
/// of the saved reply slot.
pub(crate) unsafe fn handle_tcgetattr_for_pty(
    state: &mut VfsState,
    client: ClientHandle,
    pty_id: u32,
    side: u8,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        match issue_pty_tcgetattr(state, pty_id) {
            Ok(handle) => stamp_pty_resume(
                state,
                client,
                handle,
                pty_id,
                side,
                crate::owner::pty_completion::PTYRESUME_OP_TCGETATTR,
                0,
                reply_lease,
            ),
            Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
        }
    }
}

/// `tcsetattr(fd, action, &termios)` shim. Termios bytes ride in
/// the `PTY_TCSETATTR` request payload.
pub(crate) unsafe fn handle_tcsetattr_for_pty(
    state: &mut VfsState,
    client: ClientHandle,
    pty_id: u32,
    side: u8,
    action: u32,
    termios: &[u8; 80],
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        match issue_pty_termios_set(state, pty_id, action, termios) {
            Ok(handle) => stamp_pty_resume(
                state,
                client,
                handle,
                pty_id,
                side,
                crate::owner::pty_completion::PTYRESUME_OP_TCSETATTR,
                0,
                reply_lease,
            ),
            Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
        }
    }
}

unsafe fn issue_pty_tcgetattr(
    state: &mut VfsState,
    pty_id: u32,
) -> Result<crate::owner::pending::PendingOpHandle, VfsError> {
    unsafe {
        let session = crate::owner::session::default_pty_session(state)?;
        let send_cap = state
            .backend_sessions
            .get(session)
            .map(|s| s.send_cap.as_raw())
            .ok_or(VfsError::SessionTornDown)?;
        if !state.backend_credit_reserve_for_session(session) {
            return Err(VfsError::Again);
        }
        let (handle, tx_id) = state.reserve_pending_for_pty(session).ok_or_else(|| {
            state.backend_credit_release_for_session(session);
            VfsError::NoMem
        })?;
        let mut req = TronaMsg::default();
        req.label = PTY_TCGETATTR;
        req.regs[0] = pty_id as u64;
        req.length = 1;
        stamp_pty_async_request(state, session, &mut req, PTY_TCGETATTR, tx_id)?;
        let send_err = trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), send_cap, &raw const req);
        if send_err != 0 {
            let _ = state.pending_ops.release(handle);
            state.backend_credit_release_for_session(session);
            return Err(VfsError::Io);
        }
        Ok(handle)
    }
}

/// Issue `CTTY_PTY_FOR_SID(sid)` against posix_ttysrv to find which pty
/// the session `sid` owns as its controlling terminal. Parks a
/// `PendingOp`; the completion maps the returned pty id to a synthetic
/// `tty_dev`. Async (never `mp_call`) so VFS never blocks on ttysrv,
/// which may be mid-`signal_vfs` back into VFS.
pub(crate) unsafe fn issue_pty_ctty_lookup(
    state: &mut VfsState,
    sid: u64,
) -> Result<crate::owner::pending::PendingOpHandle, VfsError> {
    unsafe {
        let session = crate::owner::session::default_pty_session(state)?;
        let send_cap = state
            .backend_sessions
            .get(session)
            .map(|s| s.send_cap.as_raw())
            .ok_or(VfsError::SessionTornDown)?;
        if !state.backend_credit_reserve_for_session(session) {
            return Err(VfsError::Again);
        }
        let (handle, tx_id) = state.reserve_pending_for_pty(session).ok_or_else(|| {
            state.backend_credit_release_for_session(session);
            VfsError::NoMem
        })?;
        let mut req = TronaMsg::default();
        req.label = PTY_CTTY_PTY_FOR_SID;
        req.regs[0] = sid;
        req.length = 1;
        stamp_pty_async_request(state, session, &mut req, PTY_CTTY_PTY_FOR_SID, tx_id)?;
        let send_err = trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), send_cap, &raw const req);
        if send_err != 0 {
            let _ = state.pending_ops.release(handle);
            state.backend_credit_release_for_session(session);
            return Err(VfsError::Io);
        }
        Ok(handle)
    }
}

/// Issue the posix_ttysrv controlling-tty binding dump
/// (`POSIX_TTYSRV_CTTY_DUMP`) that prefixes a tty-bearing init read.
/// Like [`issue_pty_ctty_lookup`] but carries no session id; the reply
/// returns every active `(sid → pty)` binding in one round-trip. The
/// caller stamps a `Resume::Fs(FsResume::CttyDump)` on the returned op
/// (no lease — it lives on the read's snapshot); the completion caches
/// the bindings and fires the read's first init query.
pub(crate) unsafe fn issue_pty_ctty_dump(
    state: &mut VfsState,
) -> Result<crate::owner::pending::PendingOpHandle, VfsError> {
    unsafe {
        // Use an already-live pty session ONLY — never establish one here.
        // This dump is best-effort tty enrichment for `/proc` / `kern.proc`
        // reads; establishing posix_ttysrv synchronously would block the
        // VFS reactor during boot (first such read before any real pty op)
        // and deadlock against ttysrv coming up. No live session → caller
        // skips the dump and the read proceeds with `tty_dev = 0`.
        let session =
            crate::owner::session::existing_default_pty_session(state).ok_or(VfsError::Again)?;
        let send_cap = state
            .backend_sessions
            .get(session)
            .map(|s| s.send_cap.as_raw())
            .ok_or(VfsError::SessionTornDown)?;
        if !state.backend_credit_reserve_for_session(session) {
            return Err(VfsError::Again);
        }
        let (handle, tx_id) = state.reserve_pending_for_pty(session).ok_or_else(|| {
            state.backend_credit_release_for_session(session);
            VfsError::NoMem
        })?;
        let mut req = TronaMsg::default();
        req.label = PTY_CTTY_DUMP;
        req.length = 0;
        stamp_pty_async_request(state, session, &mut req, PTY_CTTY_DUMP, tx_id)?;
        let send_err = trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), send_cap, &raw const req);
        if send_err != 0 {
            let _ = state.pending_ops.release(handle);
            state.backend_credit_release_for_session(session);
            return Err(VfsError::Io);
        }
        Ok(handle)
    }
}

/// `VFS_GET_CTTY_DEV` — resolve the calling session's controlling-terminal
/// device id. Asks init for the caller's POSIX session (sync; init never
/// blocks on VFS), then asks posix_ttysrv which pty that session owns
/// (async). The completion maps the pty id to a synthetic `tty_dev`.
pub(crate) unsafe fn handle_get_ctty_dev(
    state: &mut VfsState,
    client: ClientHandle,
    _msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let caller_badge = state
            .clients
            .get(client)
            .map(|c| c.client_badge)
            .unwrap_or(0);
        // Resolve the caller's POSIX session from init asynchronously
        // (init can call back into VFS, so a blocking query would risk the
        // init↔VFS reactor cycle). The pty ctty-lookup + reply run at
        // finalize via `CttyAction::GetCttyDev`.
        let plan = [crate::owner::init_rpc::InitStep {
            label: trona_protocol::posix::INIT_PGRP_SESSION,
            sub_op: trona_protocol::posix::INIT_PGRP_SUB_GET_SID_PGID_BY_BADGE,
            arg: caller_badge,
        }];
        crate::owner::init_rpc::begin_init_read(
            state,
            &plan,
            crate::owner::init_rpc::InitReadState::Ctty {
                client,
                action: crate::owner::init_rpc::CttyAction::GetCttyDev,
                sid: 0,
                pgid: 0,
            },
            0,
            caller_badge,
            reply_lease,
        );
    }
}

/// Issue `PTY_IOCTL(pty_id, cmd, arg)` against posix_ttysrv for a
/// tty device ioctl (`TIOCGWINSZ` / `TIOCSWINSZ` / `TIOCGPGRP` / …).
/// Parks a `PendingOp`; the completion projects the backend reply
/// into the per-command POSIX ioctl shape. Mirrors
/// [`issue_pty_tcgetattr`]; the correlation header rides in the high
/// `regs[]` slots, clear of `regs[0..3]`.
pub(crate) unsafe fn issue_pty_ioctl(
    state: &mut VfsState,
    pty_id: u32,
    cmd: u32,
    arg: u64,
    caller_sid: u64,
    caller_pgid: u64,
) -> Result<PendingOpHandle, VfsError> {
    unsafe {
        let session = crate::owner::session::default_pty_session(state)?;
        let send_cap = state
            .backend_sessions
            .get(session)
            .map(|s| s.send_cap.as_raw())
            .ok_or(VfsError::SessionTornDown)?;
        if !state.backend_credit_reserve_for_session(session) {
            return Err(VfsError::Again);
        }
        let (handle, tx_id) = state.reserve_pending_for_pty(session).ok_or_else(|| {
            state.backend_credit_release_for_session(session);
            VfsError::NoMem
        })?;
        let mut req = TronaMsg::default();
        req.label = PTY_IOCTL;
        req.regs[0] = pty_id as u64;
        req.regs[1] = cmd as u64;
        req.regs[2] = arg;
        // ctty-control ioctls carry the caller's POSIX session identity in
        // regs[3]/[4]; posix_ttysrv keys controlling-terminal ownership on
        // it. Other commands leave these clear — TIOCSWINSZ reuses regs[3]
        // for the column count.
        match cmd as u64 {
            trona_protocol::posix_abi::tty::TIOCSCTTY
            | trona_protocol::posix_abi::tty::TIOCSPGRP
            | trona_protocol::posix_abi::tty::TIOCGSID
            | trona_protocol::posix_abi::tty::TIOCNOTTY => {
                req.regs[3] = caller_sid;
                req.regs[4] = caller_pgid;
            }
            _ => {}
        }
        req.length = 3;
        stamp_pty_async_request(state, session, &mut req, PTY_IOCTL, tx_id)?;
        let send_err = trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), send_cap, &raw const req);
        if send_err != 0 {
            let _ = state.pending_ops.release(handle);
            state.backend_credit_release_for_session(session);
            return Err(VfsError::Io);
        }
        Ok(handle)
    }
}

/// Issue `PTY_TCSETATTR` with the 80-byte termios snapshot packed
/// into `regs[2..12]`. `action` (TCSANOW / TCSADRAIN / TCSAFLUSH)
/// rides in `regs[1]`.
unsafe fn issue_pty_termios_set(
    state: &mut VfsState,
    pty_id: u32,
    action: u32,
    termios: &[u8; 80],
) -> Result<crate::owner::pending::PendingOpHandle, VfsError> {
    unsafe {
        let session = crate::owner::session::default_pty_session(state)?;
        let send_cap = state
            .backend_sessions
            .get(session)
            .map(|s| s.send_cap.as_raw())
            .ok_or(VfsError::SessionTornDown)?;
        if !state.backend_credit_reserve_for_session(session) {
            return Err(VfsError::Again);
        }
        let (handle, tx_id) = state.reserve_pending_for_pty(session).ok_or_else(|| {
            state.backend_credit_release_for_session(session);
            VfsError::NoMem
        })?;
        let mut req = TronaMsg::default();
        req.label = PTY_TCSETATTR;
        req.regs[0] = pty_id as u64;
        req.regs[1] = action as u64;
        let src = termios.as_ptr() as *const u64;
        for i in 0..10 {
            req.regs[2 + i] = *src.add(i);
        }
        req.length = 12;
        stamp_pty_async_request(state, session, &mut req, PTY_TCSETATTR, tx_id)?;
        let send_err = trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), send_cap, &raw const req);
        if send_err != 0 {
            let _ = state.pending_ops.release(handle);
            state.backend_credit_release_for_session(session);
            return Err(VfsError::Io);
        }
        Ok(handle)
    }
}

fn stamp_pty_resume(
    state: &mut VfsState,
    client: ClientHandle,
    handle: crate::owner::pending::PendingOpHandle,
    pty_id: u32,
    side: u8,
    op_type: u8,
    max_count: u32,
    reply_lease: trona_server::ReplyLease,
) {
    let client_badge = state
        .clients
        .get(client)
        .map(|c| c.client_badge)
        .unwrap_or(0);
    if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
        handle,
        client_badge,
        Some(reply_lease),
        crate::owner::resume::Resume::Pty(crate::owner::resume::PtyResume {
            pty_index: pty_id as u16,
            side,
            op_type,
            max_count,
            client_badge,
        }),
    ) {
        send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
    }
}

/// Stamp a freshly-reserved PendingOp with a `Resume::Fb` payload.
/// `vnode_h` identifies the FB vnode the request was issued
/// against (the same handle the caller passed to
/// [`issue_fb_get_backing`] etc.). `op_type` is one of the
/// `FBRESUME_OP_*` values declared in
/// [`crate::owner::fb_completion`].
pub(crate) fn stamp_fb_resume(
    state: &mut VfsState,
    handle: crate::owner::pending::PendingOpHandle,
    vnode_h: VnodeHandle,
    op_type: u8,
    request: u32,
    reply_lease: trona_server::ReplyLease,
    client_badge: u64,
) {
    if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
        handle,
        client_badge,
        Some(reply_lease),
        crate::owner::resume::Resume::Fb(crate::owner::resume::FbResume {
            vnode_slot: vnode_h.slot(),
            op_type,
            request,
            client_badge,
        }),
    ) {
        crate::personality::wire::send_error_reply(reply_lease, VfsError::Io);
    }
}
