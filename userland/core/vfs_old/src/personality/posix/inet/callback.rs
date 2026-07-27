// SPDX-License-Identifier: GPL-2.0-only
//! netsrv async callback table and completion handler.

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_posix::types::*;
use trona_protocol::posix::posix::*;
use trona_protocol::posix::server::*;
use trona_protocol::posix::vfs::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::ipc_ctx;
use crate::owner::op::{OpCore, OpKind, OwnerPostOp};
use crate::owner::pending::{PendingOpHandle, PendingOpState};
use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::server::types::*;

// ======================================================================
// Pending operations table — unified through `pending_ops` arena.
// ======================================================================
//
// The former `inet_pending` fixed array + `PendingInetOp` struct have
// been retired: every in-flight netsrv op now lives in the shared
// `VfsState::pending_ops` arena as a `PendingOpState::Net` entry. The
// `alloc_pending` / `find_pending` / `clear_pending_badge` /
// `dump_pending_inet` helpers below sit directly on top of that arena
// and require no private table.

// Rate-limit counters for inet log output now live on `VfsState`
// (`logged_inet_ops`, `logged_inet_callbacks`,
// `logged_inet_recv_results`). Local accessor helpers read and bump
// them under the owner's single-threaded invariant. Callers that took
// the prior `*(&raw mut LOGGED_*)` statics now thread `&mut VfsState`
// into the call site.

pub(super) fn has_pending_capacity(state: &mut crate::owner::VfsState) -> bool {
    // Probe the unified `pending_ops` arena for one free slot. If
    // successful we immediately release — the actual reservation
    // happens inside [`alloc_pending`] so we don't hold an unpopulated
    // slot across the capacity check. Inet ops issue infrequently
    // enough that the double allocate/release cost is negligible.
    match state.pending_ops.alloc() {
        Some(h) => {
            let _ = state.pending_ops.release(h);
            true
        }
        None => false,
    }
}

pub(super) fn has_pending_for_conn_op(
    state: &crate::owner::VfsState,
    conn_id: u32,
    op_type: u8,
) -> bool {
    let mut found = false;
    state.pending_ops.for_each_active(|_h, op| {
        if let PendingOpState::Net {
            conn_id: op_conn,
            op_type: pending_op_type,
            ..
        } = op.op_state
        {
            if op_conn == conn_id && pending_op_type == op_type {
                found = true;
                return false;
            }
        }
        true
    });
    found
}

pub(super) fn alloc_pending(
    state: &mut crate::owner::VfsState,
    conn_id: u32,
    op_type: u8,
    op: OpCore,
    client_badge: u64,
) -> Option<PendingOpHandle> {
    use crate::owner::resume::{NetResume, Resume};
    let Some((handle, _tx)) = state.reserve_net_pending(conn_id, op_type) else {
        return None;
    };
    let netsrv_gen = state.next_netsrv_gen;
    let stamped = state.stamp_net_resume_ctx_op(
        handle,
        client_badge,
        op,
        Resume::Net(NetResume {
            conn_id,
            netsrv_gen,
            op_type,
        }),
    );
    if !stamped {
        let _ = state.pending_ops.release(handle);
        return None;
    }
    Some(handle)
}

fn inet_op_kind(op_type: u8) -> OpKind {
    match op_type {
        INET_OP_CONNECT => OpKind::InetConnect,
        INET_OP_ACCEPT => OpKind::InetAccept,
        INET_OP_RECV => OpKind::InetRecv,
        INET_OP_RECVFROM => OpKind::InetRecvFrom,
        _ => OpKind::InetRecv,
    }
}

pub(super) fn find_pending(
    state: &mut crate::owner::VfsState,
    conn_id: u32,
    op_type: u8,
) -> Option<(OpCore, u64)> {
    // Locate a live Net-class pending op matching (conn_id, op_type).
    // The `for_each_active` iterator has `&op` semantics so we take a
    // snapshot and then release through `&mut` outside the callback.
    let mut found: Option<(PendingOpHandle, OpCore, u64)> = None;
    state.pending_ops.for_each_active(|h, op| {
        if let PendingOpState::Net {
            conn_id: op_conn,
            op_type: op_opt,
            ..
        } = op.op_state
        {
            if op_conn == conn_id && op_opt == op_type {
                found = Some((h, op.reply_op, op.client_badge));
                return false;
            }
        }
        true
    });
    let (handle, op, badge) = found?;
    let _ = state.pending_ops.release(handle);
    Some((
        if op.reply_slot != 0 {
            op
        } else {
            OpCore {
                request_id: 0,
                reply_slot: 0,
                kind: inet_op_kind(op_type),
            }
        },
        badge,
    ))
}

pub(crate) unsafe fn clear_pending_badge(
    state: &mut crate::owner::VfsState,
    client_badge: u64,
) -> bool {
    use crate::owner::pending::{PendingOpHandle, PendingOpState};
    const MAX_VICTIMS: usize = 16;
    let mut victims: [(PendingOpHandle, OpCore); MAX_VICTIMS] =
        [(PendingOpHandle::INVALID, OpCore::INVALID); MAX_VICTIMS];
    let mut count = 0usize;
    state.pending_ops.for_each_active(|h, op| {
        if count >= MAX_VICTIMS {
            return false;
        }
        if matches!(op.op_state, PendingOpState::Net { .. }) && op.client_badge == client_badge {
            let op_kind = match op.op_state {
                PendingOpState::Net { op_type, .. } => inet_op_kind(op_type),
                _ => OpKind::InetRecv,
            };
            victims[count] = (
                h,
                if op.reply_op.reply_slot != 0 {
                    op.reply_op
                } else {
                    OpCore {
                        request_id: 0,
                        reply_slot: 0,
                        kind: op_kind,
                    }
                },
            );
            count += 1;
        }
        true
    });
    let mut cleared = false;
    for idx in 0..count {
        let (handle, op) = victims[idx];
        if op.reply_slot != 0 {
            let mut wake = TronaMsg::zeroed();
            wake.label = TRONA_INVALID_OPERATION;
            unsafe { state.complete_op(op, OwnerPostOp::None, &raw const wake) };
            cleared = true;
        }
        let _ = state.pending_ops.release(handle);
    }
    cleared
}

pub(crate) fn dump_pending_inet(state: &crate::owner::VfsState) {
    use crate::owner::pending::PendingOpState;
    let mut active = 0u32;
    state.pending_ops.for_each_active(|_h, op| {
        if let PendingOpState::Net {
            conn_id, op_type, ..
        } = op.op_state
        {
            active += 1;
            trona_runtime::uinfo!(|_lb| {
                _lb.str(b"  inet pending: conn=");
                _lb.dec(conn_id as u64);
                _lb.str(b" op=");
                _lb.dec(op_type as u64);
                _lb.str(b" reply_slot=");
                _lb.hex(op.reply_op.reply_slot);
                _lb.str(b" badge=");
                _lb.hex(op.client_badge);
                _lb.str(b"\n");
            });
        }
        true
    });
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] pending inet (net-class): ");
        _lb.dec(active as u64);
        _lb.str(b"\n");
    });
}

pub(super) fn log_ipv4(lb: &mut trona_runtime::debug::serial::LineBuf, ip: u32) {
    lb.dec(((ip >> 24) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 16) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec(((ip >> 8) & 0xFF) as u64);
    lb.putc(b'.');
    lb.dec((ip & 0xFF) as u64);
}

pub(super) fn log_inet_op(
    state: &mut crate::owner::VfsState,
    op: &[u8],
    fd: i32,
    conn_id: u32,
    ip: u32,
    port: u16,
    len: usize,
) {
    if state.logged_inet_ops >= 20 {
        return;
    }
    state.logged_inet_ops += 1;
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[VFS] inet ");
        _lb.str(op);
        if fd >= 0 {
            _lb.str(b" fd=");
            _lb.dec(fd as u64);
        }
        _lb.str(b" conn=");
        _lb.dec(conn_id as u64);
        if ip != 0 || port != 0 {
            _lb.str(b" ip=");
            log_ipv4(&mut _lb, ip);
            _lb.str(b" port=");
            _lb.dec(port as u64);
        }
        if len != 0 {
            _lb.str(b" len=");
            _lb.dec(len as u64);
        }
        _lb.putc(b'\n');
    });
}

pub(super) fn log_inet_recv_result(
    state: &mut crate::owner::VfsState,
    fd: i32,
    conn_id: u32,
    src_ip: u32,
    len: usize,
    data: &[u8],
) {
    if state.logged_inet_recv_results >= 24 {
        return;
    }
    state.logged_inet_recv_results += 1;
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[VFS] inet recvfrom result fd=");
        _lb.dec(fd as u64);
        _lb.str(b" conn=");
        _lb.dec(conn_id as u64);
        _lb.str(b" src=");
        log_ipv4(&mut _lb, src_ip);
        _lb.str(b" len=");
        _lb.dec(len as u64);
        let preview_len = core::cmp::min(data.len(), 8);
        if preview_len > 0 {
            _lb.str(b" bytes=");
            let mut i = 0;
            while i < preview_len {
                if i != 0 {
                    _lb.putc(b':');
                }
                _lb.hex(data[i] as u64);
                i += 1;
            }
        }
        _lb.putc(b'\n');
    });
}

// fd_is_nonblocking removed — callers now read flags from OpenObject directly.

pub(super) unsafe fn find_inet_fd_by_conn_badge(
    state: &crate::owner::VfsState,
    badge: u64,
    conn_id: u32,
) -> Option<i32> {
    unsafe {
        let (slot, epoch) = state.badge_map.lookup(badge)?;
        let h = ClientHandle::new(slot, epoch);
        for fd in 0..MAX_CLIENT_OBJECTS {
            if let Some(obj) = state.open_object_at(h, fd)
                && obj.kind() == ObjectKind::InetSocket
                && obj.inet_socket_id() == Some(conn_id)
            {
                return Some(fd as i32);
            }
        }
        None
    }
}

// ======================================================================

/// Ensure VFS has registered its shared backend callback EP with netsrv.
///
/// This is intentionally lazy so VFS startup does not block on netsrv/network
/// availability (e.g. `--no-net` runs).
pub(super) unsafe fn ensure_inet_callback_registered(state: &mut crate::owner::VfsState) -> bool {
    // SAFETY: Single-threaded VFS server initialization/dispatch.
    unsafe {
        if state.netsrv_callback_registered {
            return true;
        }

        if !crate::backend::prepare_backend_callback_endpoint(state) {
            return false;
        }

        // Call netsrv with NET_REGISTER_VFS, transferring a plain copy of our
        // shared backend callback endpoint. netsrv rebadges that cap locally for
        // callback sends.
        ipc::set_send_cap_ctx(ipc_ctx(), 0, crate::backend::backend_callback_ep());

        let mut msg = TronaMsg::zeroed();
        msg.label = NET_REGISTER_VFS;
        msg.length = 0;
        let mut resp = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), netsrv_ep(), &raw const msg, &raw mut resp);
        if err != 0 || resp.label != TRONA_OK {
            crate::puts(b"[VFS] inet: failed to register with netsrv\n");
            return false;
        }

        state.netsrv_callback_registered = true;
        // Bump the netsrv generation so any stale callback stamped with
        // the prior gen is dropped by a future netsrv-wire migration.
        state.next_netsrv_gen = state.next_netsrv_gen.wrapping_add(1);
        if state.next_netsrv_gen == 0 {
            state.next_netsrv_gen = 1;
        }
        true
    }
}

// ======================================================================
// Helper: allocate a new fd for an inet socket
// ======================================================================

pub(super) unsafe fn alloc_inet_fd(
    state: &mut crate::owner::VfsState,
    badge: u64,
    conn_id: u32,
) -> Option<i32> {
    unsafe {
        let (slot, epoch) = state.badge_map.lookup(badge)?;
        let h = ClientHandle::new(slot, epoch);
        let fd = state.reserve_fd_owned(h)?;
        match state.open_object_at_mut(h, fd as usize) {
            Some(obj) => {
                obj.set_inet_socket(conn_id);
                obj.offset = 0;
                obj.flags = 0;
                obj.nonblocking = 0;
            }
            None => {
                state.slot_release(h, fd as usize);
                return None;
            }
        }
        Some(fd)
    }
}

// ======================================================================
// Callback handler: NET_COMPLETE from netsrv
// ======================================================================

/// Handle async completion callback from netsrv.
///
/// Called when VFS receives IPC with badge == NETSRV_CALLBACK_BADGE.
pub(crate) unsafe fn handle_netsrv_callback(
    state: &mut crate::owner::VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    // SAFETY: Single-threaded VFS; IPC context valid.
    unsafe {
        let conn_id = (*msg).regs[0] as u32;
        let result = (*msg).regs[1];
        let op_type = (*msg).regs[2] as u8;
        let mut replied_to_pending = false;
        let mut woke_poll_fd: i32 = -1;

        if let Some((op, client_badge)) = find_pending(state, conn_id, op_type) {
            replied_to_pending = true;
            let mut client_reply = TronaMsg::zeroed();

            match op_type {
                INET_OP_CONNECT => {
                    client_reply.label = result;
                }
                INET_OP_RECV => {
                    client_reply.label = result;
                    if result == TRONA_OK {
                        let data_len = (*msg).regs[3] as usize;
                        // Cap to max bytes that fit in regs[4..20] (16 regs * 8 = 128)
                        let actual_len = if data_len > 128 { 128 } else { data_len };
                        client_reply.regs[0] = actual_len as u64;
                        if actual_len > 0 {
                            let src = &(*msg).regs[4] as *const u64 as *const u8;
                            let dst = &raw mut client_reply.regs[1] as *mut u8;
                            for i in 0..actual_len {
                                *dst.add(i) = *src.add(i);
                            }
                        }
                        client_reply.length = 1 + ((actual_len as u64 + 7) / 8);
                    } else {
                        client_reply.regs[0] = 0;
                        client_reply.length = 1;
                    }
                }
                INET_OP_RECVFROM => {
                    client_reply.label = result;
                    if result == TRONA_OK {
                        let data_len = (*msg).regs[3] as usize;
                        // Cap to max bytes that fit in regs[7..20] (13 regs * 8 = 104)
                        let actual_len = if data_len > 104 { 104 } else { data_len };
                        let src_ip = (*msg).regs[4] as u32;
                        let src_port = (*msg).regs[5] as u16;
                        let timestamp_ns = (*msg).regs[6];
                        client_reply.regs[0] = actual_len as u64;
                        client_reply.regs[1] = src_ip as u64;
                        client_reply.regs[2] = src_port as u64;
                        client_reply.regs[3] = timestamp_ns;
                        if actual_len > 0 {
                            let src = &(*msg).regs[7] as *const u64 as *const u8;
                            let dst = &raw mut client_reply.regs[4] as *mut u8;
                            for i in 0..actual_len {
                                *dst.add(i) = *src.add(i);
                            }
                        }
                        client_reply.length = 4 + ((actual_len as u64 + 7) / 8);
                    } else {
                        client_reply.regs[0] = 0;
                        client_reply.length = 1;
                    }
                }
                INET_OP_ACCEPT => {
                    client_reply.label = result;
                    if result == TRONA_OK {
                        let new_conn_id = (*msg).regs[3] as u32;
                        let remote_ip = (*msg).regs[4] as u32;
                        let remote_port = (*msg).regs[5] as u16;

                        match alloc_inet_fd(state, client_badge, new_conn_id) {
                            Some(new_fd) => {
                                client_reply.regs[0] = new_fd as u64;
                                client_reply.regs[1] = remote_ip as u64;
                                client_reply.regs[2] = remote_port as u64;
                                client_reply.length = 3;
                            }
                            None => {
                                client_reply.label = TRONA_OUT_OF_MEMORY;
                            }
                        }
                    }
                }
                _ => {
                    client_reply.label = TRONA_INVALID_OPERATION;
                }
            }

            state.complete_op(op, OwnerPostOp::None, &raw const client_reply);
        }

        // Poll wakeup for non-blocking connect and unsolicited data-ready.
        // Deferred to poll.rs integration.
        let _ = woke_poll_fd;

        if state.logged_inet_callbacks < 32 {
            state.logged_inet_callbacks += 1;
            trona_runtime::udebug!(|_lb| {
                _lb.str(b"[VFS] inet callback conn=");
                _lb.dec(conn_id as u64);
                _lb.str(b" op=");
                _lb.dec(op_type as u64);
                _lb.str(b" result=");
                _lb.hex(result);
                _lb.str(b" pending=");
                _lb.dec(replied_to_pending as u64);
                _lb.str(b" wake_fd=");
                if woke_poll_fd >= 0 {
                    _lb.dec(woke_poll_fd as u64);
                } else {
                    _lb.str(b"none");
                }
                _lb.putc(b'\n');
            });
        }

        // Reply OK to netsrv (completing the callback IPC)
        (*reply).label = TRONA_OK;
    }
}
