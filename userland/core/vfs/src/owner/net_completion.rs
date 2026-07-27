// SPDX-License-Identifier: GPL-2.0-only
//
//! netsrv `BackendSessionSlot::completion_fn` — completion router
//! for the inet socket family.
//!
//! Pairs with `posix::inet::handle` (the issue side). When netsrv
//! answers a parked `PendingOp` the dispatcher pulls the saved
//! `Resume::Net` payload out of the slot and routes here. The
//! router uses `NetResume::op_type` (one of `NETRESUME_OP_*`) to
//! pick the matching reply emitter.
//!
//! `kind_payload.words[0..2]` carries the `(slot, epoch)` of the
//! `SocketState` arena entry the operation belongs to — stamped at
//! `reserve_pending_for_net` time. The router refuses to update a
//! socket whose `netsrv_gen` no longer matches the parked snapshot,
//! which lets a netsrv re-registration cycle invalidate every
//! in-flight reply without touching client state.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::identity::FsInstanceId;
use crate::core::socket::{
    NETRESUME_OP_ACCEPT, NETRESUME_OP_BIND, NETRESUME_OP_CONNECT, NETRESUME_OP_LISTEN,
    NETRESUME_OP_RECV, NETRESUME_OP_SEND, NETRESUME_OP_SHUTDOWN, SocketLifeState, SocketState,
};
use crate::ipc::protocol::backend::VFS_BACKEND_REPLY_OK;
use crate::owner::VfsState;
use crate::owner::pending::{PendingKindPayload, TxId};
use crate::owner::resume::Resume;
use trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;

/// Registered into the netsrv `BackendSessionSlot::completion_fn`
/// at session-attach time. See module docs for the `kind_payload`
/// + `NetResume::op_type` contract.
pub(crate) unsafe fn netsrv_completion(
    state: &mut VfsState,
    _fs_id: FsInstanceId,
    _tx_id: TxId,
    kind_payload: &PendingKindPayload,
    resume_ctx: Resume,
    backend_session_idx: u32,
    reply_lease: Option<ReplyLease>,
    reply_msg: &TronaMsg,
    personality: crate::personality::Personality,
) {
    // Every return path in this completion fn must release the
    // backend-session credit reserved by the issuing site —
    // mirroring the saltyfs / fb completion routers — so a netsrv
    // session never leaks a credit when an op completes (success,
    // error, or stamping mismatch).
    let net_resume = match resume_ctx {
        Resume::Net(r) => r,
        _ => {
            // Saltyfs / pty / fb / pager / placeholder landing on
            // the netsrv completion fn is a stamping bug. Drop
            // the lease via the kernel cancel path so the caller
            // observes a real error rather than a stuck reply
            // slot.
            if let Some(l) = reply_lease {
                crate::owner::op::reply_drop(l);
            }
            state.backend_credit_release_for_session_idx(backend_session_idx);
            return;
        }
    };

    // Recover the SocketState handle from the kind payload. A
    // missing slot (re-allocated since the issue) drops the reply.
    let sock_slot = kind_payload.words[0] as u32;
    let sock_epoch = kind_payload.words[1] as u32;
    let sock_h: Handle<SocketState> = Handle::new(sock_slot, sock_epoch);
    if state.sockets.get(sock_h).is_none() {
        if let Some(l) = reply_lease {
            crate::owner::op::reply_drop(l);
        }
        state.backend_credit_release_for_session_idx(backend_session_idx);
        return;
    }

    // Validate netsrv generation — a re-registration cycle on the
    // netsrv side bumps the global epoch and stale replies must not
    // mutate client state.
    let cur_gen = state.sockets.get(sock_h).map(|s| s.netsrv_gen).unwrap_or(0);
    if cur_gen != net_resume.netsrv_gen {
        if let Some(l) = reply_lease {
            crate::owner::op::reply_drop(l);
        }
        state.backend_credit_release_for_session_idx(backend_session_idx);
        return;
    }
    let cur_conn = state
        .sockets
        .get(sock_h)
        .map(|s| s.conn_id)
        .unwrap_or(u32::MAX);
    if cur_conn != net_resume.conn_id {
        if let Some(l) = reply_lease {
            crate::owner::op::reply_drop(l);
        }
        state.backend_credit_release_for_session_idx(backend_session_idx);
        return;
    }

    // Translate backend status → public-reply label. Anything
    // other than `OK` short-circuits the per-op emitter and
    // surfaces the personality-projected error code on the reply.
    if reply_msg.label != VFS_BACKEND_REPLY_OK {
        let err = VfsError::from_backend_reply(reply_msg.label);
        crate::personality::posix::inet_wait::wake_matching(
            state,
            sock_h,
            crate::personality::posix::inet_wait::InetWaitKind::Error,
        );
        emit_error(reply_lease, personality, err);
        state.backend_credit_release_for_session_idx(backend_session_idx);
        return;
    }

    match net_resume.op_type {
        NETRESUME_OP_BIND => {
            if let Some(s) = state.sockets.get_mut(sock_h) {
                s.state = SocketLifeState::Bound;
            }
            emit_ok_empty(reply_lease, personality);
        }
        NETRESUME_OP_LISTEN => {
            if let Some(s) = state.sockets.get_mut(sock_h) {
                s.state = SocketLifeState::Listening;
            }
            crate::personality::posix::inet_wait::wake_matching(
                state,
                sock_h,
                crate::personality::posix::inet_wait::InetWaitKind::Accept,
            );
            emit_ok_empty(reply_lease, personality);
        }
        NETRESUME_OP_CONNECT => {
            // Reply: regs[0] = conn_id, regs[1] = peer_addr_len,
            // regs[2..] = peer sockaddr bytes.
            let conn_id = reply_msg.regs[0] as u32;
            let peer_len = reply_msg.regs[1] as usize;
            if let Some(s) = state.sockets.get_mut(sock_h) {
                s.state = SocketLifeState::Connected;
                s.conn_id = conn_id;
                if peer_len != 0 {
                    s.peer_addr_len = peer_len as u32;
                    copy_peer_addr_in(s, reply_msg, 2, peer_len);
                }
            }
            crate::personality::posix::inet_wait::wake_matching(
                state,
                sock_h,
                crate::personality::posix::inet_wait::InetWaitKind::Connect,
            );
            crate::personality::posix::inet_wait::wake_matching(
                state,
                sock_h,
                crate::personality::posix::inet_wait::InetWaitKind::Writable,
            );
            emit_ok_empty(reply_lease, personality);
        }
        NETRESUME_OP_ACCEPT => {
            // Reply: regs[0] = new_conn_id, regs[1] = peer_addr_len,
            // regs[2..] = peer sockaddr bytes.
            let new_conn_id = reply_msg.regs[0] as u32;
            let peer_len = reply_msg.regs[1] as usize;
            let client_id = reply_lease
                .as_ref()
                .map(|l| (l.epoch() & 0xFFFF_FFFF) as u32)
                .unwrap_or(0);
            let mut peer = [0u8; crate::core::socket::SOCKADDR_STORAGE_BYTES];
            let src = (&raw const reply_msg.regs[2]) as *const u8;
            let copy_len = peer_len.min(peer.len());
            for i in 0..copy_len {
                unsafe {
                    peer[i] = *src.add(i);
                }
            }
            let fd = match crate::personality::posix::socket::install_accepted_inet_socket(
                state,
                client_id,
                sock_h,
                new_conn_id,
                &peer[..copy_len],
            ) {
                Ok(fd) => fd,
                Err(e) => {
                    emit_error(reply_lease, personality, e);
                    state.backend_credit_release_for_session_idx(backend_session_idx);
                    return;
                }
            };
            let mut out = TronaMsg::default();
            out.label = VFS_PUBLIC_REPLY_OK;
            out.regs[0] = fd as u64;
            out.regs[1] = copy_len as u64;
            let dst = (&raw mut out.regs[2]) as *mut u8;
            for i in 0..copy_len.min(120) {
                unsafe {
                    *dst.add(i) = peer[i];
                }
            }
            out.length = (2 + ((copy_len + 7) / 8)) as u64;
            crate::personality::posix::inet_wait::wake_matching(
                state,
                sock_h,
                crate::personality::posix::inet_wait::InetWaitKind::Readable,
            );
            send_reply(reply_lease, personality, &out);
        }
        NETRESUME_OP_SEND => {
            // Reply: regs[0] = bytes_written.
            let mut out = TronaMsg::default();
            out.label = VFS_PUBLIC_REPLY_OK;
            out.regs[0] = reply_msg.regs[0];
            out.length = 1;
            crate::personality::posix::inet_wait::wake_matching(
                state,
                sock_h,
                crate::personality::posix::inet_wait::InetWaitKind::Writable,
            );
            send_reply(reply_lease, personality, &out);
        }
        NETRESUME_OP_RECV => {
            // Reply: regs[0] = bytes_read, regs[1] = peer_addr_len
            // (0 for connected sockets), regs[2..2+peer_words] =
            // peer sockaddr bytes (recvfrom-style), then payload
            // bytes. Forwarded to the caller verbatim — the
            // personality projection on the caller side knows the
            // per-op layout.
            let mut out = TronaMsg::default();
            out.label = VFS_PUBLIC_REPLY_OK;
            let len_words = reply_msg.length as usize;
            for i in 0..len_words.min(out.regs.len()) {
                out.regs[i] = reply_msg.regs[i];
            }
            out.length = reply_msg.length;
            // Clear the parked recv marker on the SocketState.
            if let Some(s) = state.sockets.get_mut(sock_h) {
                s.pending_recv_op = 0;
            }
            crate::personality::posix::inet_wait::wake_matching(
                state,
                sock_h,
                crate::personality::posix::inet_wait::InetWaitKind::Readable,
            );
            send_reply(reply_lease, personality, &out);
        }
        NETRESUME_OP_SHUTDOWN => {
            if let Some(s) = state.sockets.get_mut(sock_h) {
                s.state = SocketLifeState::Closed;
            }
            crate::personality::posix::inet_wait::wake_matching(
                state,
                sock_h,
                crate::personality::posix::inet_wait::InetWaitKind::Hup,
            );
            emit_ok_empty(reply_lease, personality);
        }
        _ => {
            emit_error(reply_lease, personality, VfsError::Inval);
        }
    }
    state.backend_credit_release_for_session_idx(backend_session_idx);
}

fn send_reply(
    lease: Option<ReplyLease>,
    personality: crate::personality::Personality,
    out: &TronaMsg,
) {
    let _ = personality; // Wire shape was already set by the caller.
    if let Some(l) = lease {
        // SAFETY: The completion dispatcher owns the parked reply lease.
        crate::owner::op::reply_send(l, out);
    }
}

fn emit_ok_empty(lease: Option<ReplyLease>, personality: crate::personality::Personality) {
    let Some(l) = lease else { return };
    // SAFETY: The completion dispatcher owns the parked reply lease.
    crate::personality::wire::send_reply_ok_typed(personality, l, &[])
}

fn emit_error(
    lease: Option<ReplyLease>,
    personality: crate::personality::Personality,
    e: VfsError,
) {
    let Some(l) = lease else { return };
    // SAFETY: The completion dispatcher owns the parked reply lease.
    crate::personality::wire::send_reply_err_typed(personality, l, e)
}

fn copy_peer_addr_in(sock: &mut SocketState, reply_msg: &TronaMsg, word_start: usize, len: usize) {
    let cap = len.min(sock.peer_addr.len());
    let regs_len = reply_msg.regs.len();
    let mut written = 0usize;
    let mut idx = word_start;
    while written < cap && idx < regs_len {
        let word = reply_msg.regs[idx].to_le_bytes();
        let take = (cap - written).min(8);
        sock.peer_addr[written..written + take].copy_from_slice(&word[..take]);
        written += take;
        idx += 1;
    }
}
