// SPDX-License-Identifier: GPL-2.0-only
//! Deferred reply storage for AF_UNIX socket fileops.
//!
//! Saved-caller parking via `PendingOp` of kind `PO_KIND_SOCKET_WAIT`.
//! The body is too large for the 64-byte `scratch[]` budget (data
//! buffer 144 B + 2× source addr 63 B + fd_numbers 16 B + handles +
//! flags ≈ 310 B), so it lives in a `payload_ref` typed buffer
//! (PAYLOAD_BUF_BYTES = 384 B). `scratch[CHAIN_NEXT_OP_ID]` keeps the
//! per-key arrival-order chain like the TTY/PIPE/INET waiters; the
//! key is the unix socket handle the waiter is parked on, so peer
//! mutations / shutdowns wake the right chain.

use trona_kernel::core_types::*;
use uapi::*;

use crate::fileops::tty_wait::{release_reply_slot, save_current_caller, send_saved_reply};
use crate::owner::VfsState;
use crate::owner::pending_ops::{self, PAYLOAD_BUF_BYTES, PO_KIND_SOCKET_WAIT, PendingOpId};
use crate::server::types::ClientHandle;
use crate::server::unix_socket_object::{
    UNIX_SOCKET_ADDR_MAX, UNIX_SOCKET_MAX_RIGHTS, UnixSocketHandle,
};
use crate::vfs_core::vnode::VnodeHandle;

pub(crate) const INLINE_SEND_MAX: usize = 144;

pub(crate) const UNIX_OP_DGRAM_READ: u8 = 1;
pub(crate) const UNIX_OP_DGRAM_SEND: u8 = 2;
pub(crate) const UNIX_OP_STREAM_READ: u8 = 3;
pub(crate) const UNIX_OP_STREAM_WRITE: u8 = 4;
pub(crate) const UNIX_OP_SENDMSG_STREAM: u8 = 5;
pub(crate) const UNIX_OP_RECVMSG_DGRAM: u8 = 6;
pub(crate) const UNIX_OP_RECVMSG_STREAM: u8 = 7;
pub(crate) const UNIX_OP_ACCEPT: u8 = 8;
pub(crate) const UNIX_OP_CONNECT_STREAM: u8 = 9;

#[derive(Clone, Copy)]
pub(crate) enum TryOutcome {
    Filled,
    WouldBlock,
}

// scratch layout for PO_KIND_SOCKET_WAIT:
//   scratch[0] = next_op_id (chain link; PendingOpId::NONE = tail)
//   scratch[1] = socket handle raw (chain key)
//   scratch[2] = kind (u8) | fd_count (u8) | source_path_len (u8) |
//                source_abstract_len (u8) | data_len (u16) packed
//   scratch[3] = target handle raw
//   scratch[4] = source_name_vnode raw
//   scratch[5] = msg_flags (i32, sign-extended)
//   scratch[6] = msg_aux
//   scratch[7] = want_count (u16) packed in low 16
const SOCK_CHAIN_NEXT: usize = 0;
const SOCK_KEY_SOCKET: usize = 1;
const SOCK_PACKED: usize = 2;
const SOCK_TARGET: usize = 3;
const SOCK_SRC_VNODE: usize = 4;
const SOCK_MSG_FLAGS: usize = 5;
const SOCK_MSG_AUX: usize = 6;
const SOCK_WANT: usize = 7;

#[inline]
fn encode_packed(kind: u8, fd_count: u8, src_path_len: u8, src_abs_len: u8, data_len: u16) -> u64 {
    (kind as u64)
        | ((fd_count as u64) << 8)
        | ((src_path_len as u64) << 16)
        | ((src_abs_len as u64) << 24)
        | ((data_len as u64) << 32)
}

#[inline]
fn decode_kind(packed: u64) -> u8 {
    (packed & 0xFF) as u8
}

#[inline]
fn decode_fd_count(packed: u64) -> u8 {
    ((packed >> 8) & 0xFF) as u8
}

#[inline]
fn decode_src_path_len(packed: u64) -> u8 {
    ((packed >> 16) & 0xFF) as u8
}

#[inline]
fn decode_src_abs_len(packed: u64) -> u8 {
    ((packed >> 24) & 0xFF) as u8
}

#[inline]
fn decode_data_len(packed: u64) -> u16 {
    ((packed >> 32) & 0xFFFF) as u16
}

#[inline]
fn handle_to_raw(h: UnixSocketHandle) -> u64 {
    (h.slot() as u64) | ((h.epoch() as u64) << 32)
}

#[inline]
fn raw_to_handle(raw: u64) -> UnixSocketHandle {
    UnixSocketHandle::new((raw & 0xFFFF_FFFF) as u32, (raw >> 32) as u32)
}

#[inline]
fn vnode_handle_to_raw(h: VnodeHandle) -> u64 {
    (h.slot() as u64) | ((h.epoch() as u64) << 32)
}

#[inline]
fn raw_to_vnode_handle(raw: u64) -> VnodeHandle {
    VnodeHandle::new((raw & 0xFFFF_FFFF) as u32, (raw >> 32) as u32)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketWaitPayload {
    source_path: [u8; UNIX_SOCKET_ADDR_MAX],
    source_abstract_name: [u8; UNIX_SOCKET_ADDR_MAX],
    fd_numbers: [i32; UNIX_SOCKET_MAX_RIGHTS],
    data: [u8; INLINE_SEND_MAX],
}

const _: () = assert!(core::mem::size_of::<SocketWaitPayload>() <= PAYLOAD_BUF_BYTES);

unsafe fn write_payload(payload_ref: u32, body: &SocketWaitPayload) -> bool {
    unsafe {
        let Some(buf) = pending_ops::payload_bytes_mut(payload_ref) else {
            return false;
        };
        let dst = buf.as_mut_ptr() as *mut SocketWaitPayload;
        core::ptr::write(dst, *body);
        true
    }
}

unsafe fn read_payload(payload_ref: u32) -> Option<SocketWaitPayload> {
    unsafe {
        let buf = pending_ops::payload_bytes(payload_ref)?;
        let src = buf.as_ptr() as *const SocketWaitPayload;
        Some(core::ptr::read(src))
    }
}

fn lookup_badge(state: &VfsState, client: ClientHandle) -> u64 {
    state.clients.get(client).map(|c| c.badge).unwrap_or(0)
}

unsafe fn append_to_chain(op_id: PendingOpId, socket_raw: u64) {
    unsafe {
        let mut tail: Option<PendingOpId> = None;
        pending_ops::for_each_active_kind(PO_KIND_SOCKET_WAIT, |candidate_id, candidate| {
            if candidate_id == op_id {
                return;
            }
            if candidate.scratch[SOCK_KEY_SOCKET] != socket_raw {
                return;
            }
            if candidate.scratch[SOCK_CHAIN_NEXT] == PendingOpId::NONE.raw() {
                tail = Some(candidate_id);
            }
        });
        if let Some(tail_id) = tail {
            if let Some(tail_op) = pending_ops::get_mut(tail_id) {
                tail_op.scratch[SOCK_CHAIN_NEXT] = op_id.raw();
            }
        }
    }
}

unsafe fn splice_from_chain(target: PendingOpId, socket_raw: u64) {
    unsafe {
        let target_raw = target.raw();
        let next_after_target = pending_ops::get(target)
            .map(|op| op.scratch[SOCK_CHAIN_NEXT])
            .unwrap_or(PendingOpId::NONE.raw());
        let mut predecessor: Option<PendingOpId> = None;
        pending_ops::for_each_active_kind(PO_KIND_SOCKET_WAIT, |candidate_id, candidate| {
            if candidate_id == target {
                return;
            }
            if candidate.scratch[SOCK_KEY_SOCKET] != socket_raw {
                return;
            }
            if candidate.scratch[SOCK_CHAIN_NEXT] == target_raw {
                predecessor = Some(candidate_id);
            }
        });
        if let Some(pred_id) = predecessor {
            if let Some(pred_op) = pending_ops::get_mut(pred_id) {
                pred_op.scratch[SOCK_CHAIN_NEXT] = next_after_target;
            }
        }
    }
}

pub(crate) struct DeferContext<'a> {
    pub(crate) client: ClientHandle,
    pub(crate) socket: UnixSocketHandle,
    pub(crate) target: UnixSocketHandle,
    pub(crate) source_name_vnode: VnodeHandle,
    pub(crate) source_path: &'a [u8],
    pub(crate) source_abstract_name: &'a [u8],
    pub(crate) want_count: usize,
    pub(crate) data: &'a [u8],
    pub(crate) fd_numbers: &'a [i32],
    pub(crate) msg_flags: i32,
    pub(crate) msg_aux: u64,
}

impl<'a> DeferContext<'a> {
    pub(crate) fn for_read(
        client: ClientHandle,
        socket: UnixSocketHandle,
        want_count: usize,
    ) -> Self {
        Self {
            client,
            socket,
            target: UnixSocketHandle::INVALID,
            source_name_vnode: VnodeHandle::INVALID,
            source_path: &[],
            source_abstract_name: &[],
            want_count,
            data: &[],
            fd_numbers: &[],
            msg_flags: 0,
            msg_aux: 0,
        }
    }
}

/// Park a Unix-socket request as a deferred waiter. The caller must
/// have proven the request is blocking (nonblocking branch already took
/// `TRONA_WOULD_BLOCK`) before reaching here.
///
/// On success the reply is left with `REPLY_DEFERRED_LABEL` and `true`
/// is returned. On failure the reply already carries the appropriate
/// error label and `false` is returned.
pub(crate) unsafe fn defer_unix_socket_op(
    state: &mut VfsState,
    kind: u8,
    ctx: DeferContext<'_>,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let badge = lookup_badge(state, ctx.client);
        let Some(reply_slot) = save_current_caller(reply) else {
            return false;
        };
        let Some(op_id) = pending_ops::alloc(PO_KIND_SOCKET_WAIT, badge, ctx.client, reply_slot)
        else {
            release_reply_slot(reply_slot);
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return false;
        };
        let Some(payload_ref) = pending_ops::alloc_payload() else {
            let leftover_slot = pending_ops::take_reply_and_free(op_id);
            if leftover_slot != 0 {
                release_reply_slot(leftover_slot);
            }
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return false;
        };

        let path_len = core::cmp::min(ctx.source_path.len(), UNIX_SOCKET_ADDR_MAX);
        let abs_len = core::cmp::min(ctx.source_abstract_name.len(), UNIX_SOCKET_ADDR_MAX);
        let data_len = core::cmp::min(ctx.data.len(), INLINE_SEND_MAX);
        let fd_count = core::cmp::min(ctx.fd_numbers.len(), UNIX_SOCKET_MAX_RIGHTS);
        let want_count = core::cmp::min(ctx.want_count, u16::MAX as usize) as u16;

        let mut payload = SocketWaitPayload {
            source_path: [0; UNIX_SOCKET_ADDR_MAX],
            source_abstract_name: [0; UNIX_SOCKET_ADDR_MAX],
            fd_numbers: [-1; UNIX_SOCKET_MAX_RIGHTS],
            data: [0; INLINE_SEND_MAX],
        };
        payload.source_path[..path_len].copy_from_slice(&ctx.source_path[..path_len]);
        payload.source_abstract_name[..abs_len]
            .copy_from_slice(&ctx.source_abstract_name[..abs_len]);
        payload.fd_numbers[..fd_count].copy_from_slice(&ctx.fd_numbers[..fd_count]);
        payload.data[..data_len].copy_from_slice(&ctx.data[..data_len]);

        if !write_payload(payload_ref, &payload) {
            pending_ops::release_payload(payload_ref);
            let leftover_slot = pending_ops::take_reply_and_free(op_id);
            if leftover_slot != 0 {
                release_reply_slot(leftover_slot);
            }
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return false;
        }

        let socket_raw = handle_to_raw(ctx.socket);
        if let Some(op) = pending_ops::get_mut(op_id) {
            op.payload_ref = payload_ref;
            op.scratch[SOCK_CHAIN_NEXT] = PendingOpId::NONE.raw();
            op.scratch[SOCK_KEY_SOCKET] = socket_raw;
            op.scratch[SOCK_PACKED] = encode_packed(
                kind,
                fd_count as u8,
                path_len as u8,
                abs_len as u8,
                data_len as u16,
            );
            op.scratch[SOCK_TARGET] = handle_to_raw(ctx.target);
            op.scratch[SOCK_SRC_VNODE] = vnode_handle_to_raw(ctx.source_name_vnode);
            op.scratch[SOCK_MSG_FLAGS] = ctx.msg_flags as i64 as u64;
            op.scratch[SOCK_MSG_AUX] = ctx.msg_aux;
            op.scratch[SOCK_WANT] = want_count as u64;
        } else {
            pending_ops::release_payload(payload_ref);
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return false;
        }

        append_to_chain(op_id, socket_raw);
        (*reply).label = crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}

/// Best-effort cleanup of resources retained on a waiter (the bound
/// source name vnode for SOCK_DGRAM/SOCK_SEQPACKET sendmsg). fd numbers
/// were intentionally NOT retained at park time, so nothing to release
/// for fd_count.
unsafe fn release_waiter_resources(state: &mut VfsState, source_name_vnode: VnodeHandle) {
    unsafe {
        if source_name_vnode.is_valid() {
            state.release_socket_name_vnode(source_name_vnode);
        }
    }
}

/// Re-evaluate every active Unix-socket waiter once. Single-pass — drive
/// must NOT be re-entered from inside any `try_*_to_reply` helper, only
/// from the owner-loop `drive_deferred_waiters` site or from explicit
/// post-mutation calls in `release_open_file` / `handle_shutdown_owned`
/// / `try_unix_accept` rollback.
pub(crate) unsafe fn drive_unix_socket_waiters(state: &mut VfsState) {
    unsafe {
        // Snapshot every active waiter's metadata up-front so the
        // try_*_to_reply calls below don't alias the
        // for_each_active_kind callback's &mut PendingOp.
        #[derive(Clone, Copy)]
        struct WaiterSnapshot {
            op_id: PendingOpId,
            socket_raw: u64,
            target: UnixSocketHandle,
            src_vnode: VnodeHandle,
            client: ClientHandle,
            kind: u8,
            fd_count: u8,
            src_path_len: u8,
            src_abs_len: u8,
            data_len: u16,
            want_count: u16,
            msg_flags: i32,
            msg_aux: u64,
            payload_ref: u32,
        }
        const ZERO_SNAPSHOT: WaiterSnapshot = WaiterSnapshot {
            op_id: PendingOpId::NONE,
            socket_raw: 0,
            target: UnixSocketHandle::INVALID,
            src_vnode: VnodeHandle::INVALID,
            client: ClientHandle::INVALID,
            kind: 0,
            fd_count: 0,
            src_path_len: 0,
            src_abs_len: 0,
            data_len: 0,
            want_count: 0,
            msg_flags: 0,
            msg_aux: 0,
            payload_ref: 0,
        };
        let mut snaps = [ZERO_SNAPSHOT; pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_SOCKET_WAIT, |op_id, op| {
            if count >= snaps.len() {
                return;
            }
            let packed = op.scratch[SOCK_PACKED];
            snaps[count] = WaiterSnapshot {
                op_id,
                socket_raw: op.scratch[SOCK_KEY_SOCKET],
                target: raw_to_handle(op.scratch[SOCK_TARGET]),
                src_vnode: raw_to_vnode_handle(op.scratch[SOCK_SRC_VNODE]),
                client: pending_ops::unpack_client_handle(op.client_handle_raw),
                kind: decode_kind(packed),
                fd_count: decode_fd_count(packed),
                src_path_len: decode_src_path_len(packed),
                src_abs_len: decode_src_abs_len(packed),
                data_len: decode_data_len(packed),
                want_count: op.scratch[SOCK_WANT] as u16,
                msg_flags: op.scratch[SOCK_MSG_FLAGS] as i64 as i32,
                msg_aux: op.scratch[SOCK_MSG_AUX],
                payload_ref: op.payload_ref,
            };
            count += 1;
        });
        for i in 0..count {
            let s = snaps[i];
            // The op may have been freed by an earlier iteration's try
            // helper (peer-side mutation cascading into another
            // waiter's reply path); confirm liveness before continuing.
            if pending_ops::get(s.op_id).is_none() {
                continue;
            }
            let Some(payload) = read_payload(s.payload_ref) else {
                continue;
            };
            let socket = raw_to_handle(s.socket_raw);
            let mut out = TronaMsg::zeroed();
            let outcome = match s.kind {
                UNIX_OP_DGRAM_READ => crate::fileops::socket::try_unix_dgram_read_to_reply(
                    state,
                    socket,
                    s.want_count as usize,
                    &raw mut out,
                ),
                UNIX_OP_DGRAM_SEND => crate::fileops::socket::try_unix_dgram_send_to_reply(
                    state,
                    s.client,
                    socket,
                    s.target,
                    s.src_vnode,
                    &payload.source_path,
                    s.src_path_len as usize,
                    &payload.source_abstract_name,
                    s.src_abs_len as usize,
                    &payload.data[..s.data_len as usize],
                    &payload.fd_numbers[..s.fd_count as usize],
                    /* deferred = */ true,
                    &raw mut out,
                ),
                UNIX_OP_STREAM_READ => crate::fileops::socket::try_unix_stream_read_to_reply(
                    state,
                    socket,
                    s.want_count as usize,
                    &raw mut out,
                ),
                UNIX_OP_STREAM_WRITE => crate::fileops::socket::try_unix_stream_write_to_reply(
                    state,
                    socket,
                    &payload.data[..s.data_len as usize],
                    &raw mut out,
                ),
                UNIX_OP_SENDMSG_STREAM => crate::fileops::socket::try_unix_sendmsg_stream_to_reply(
                    state,
                    s.client,
                    socket,
                    &payload.data[..s.data_len as usize],
                    &payload.fd_numbers[..s.fd_count as usize],
                    /* deferred = */ true,
                    &raw mut out,
                ),
                UNIX_OP_RECVMSG_DGRAM => crate::fileops::socket::try_unix_recvmsg_dgram_to_reply(
                    state,
                    s.client,
                    socket,
                    s.msg_flags,
                    s.want_count as usize,
                    s.msg_aux,
                    &raw mut out,
                ),
                UNIX_OP_RECVMSG_STREAM => crate::fileops::socket::try_unix_recvmsg_stream_to_reply(
                    state,
                    s.client,
                    socket,
                    s.msg_flags,
                    s.want_count as usize,
                    s.msg_aux,
                    &raw mut out,
                ),
                UNIX_OP_ACCEPT => crate::fileops::socket::try_unix_accept_to_reply(
                    state,
                    s.client,
                    socket,
                    &raw mut out,
                ),
                UNIX_OP_CONNECT_STREAM => crate::fileops::socket::try_unix_connect_stream_to_reply(
                    state,
                    socket,
                    s.target,
                    s.src_vnode,
                    &payload.source_path,
                    s.src_path_len as usize,
                    &payload.source_abstract_name,
                    s.src_abs_len as usize,
                    s.msg_flags,
                    &raw mut out,
                ),
                _ => {
                    out.label = TRONA_INVALID_OPERATION;
                    out.length = 0;
                    TryOutcome::Filled
                }
            };

            match outcome {
                TryOutcome::Filled => {
                    splice_from_chain(s.op_id, s.socket_raw);
                    let reply_slot = pending_ops::take_reply_and_free(s.op_id);
                    if reply_slot != 0 {
                        send_saved_reply(reply_slot, &raw const out);
                    }
                }
                TryOutcome::WouldBlock => {
                    // Stay parked.
                }
            }
        }
    }
}

/// Cancel every waiter whose subject is `handle`. Used when a socket
/// fd's underlying `OpenFile` description is finally dropped
/// (`release_open_file` OBJ_SOCKET branch).
///
/// Peer-side waiters (a peer's `read`/`recvmsg` parked on this socket
/// being writable) are NOT cancelled here — they are explicitly woken
/// via `drive_unix_socket_waiters` after `peer_closed = 1` is set,
/// where the appropriate `try_*` branch returns `Filled` with EOF
/// semantics. This helper fires the disposition reply directly (close
/// path, not a generic badge cancel).
pub(crate) unsafe fn cancel_unix_socket_waiters_for_handle(
    state: &mut VfsState,
    handle: UnixSocketHandle,
) {
    unsafe {
        let socket_raw = handle_to_raw(handle);
        let mut targets = [(PendingOpId::NONE, VnodeHandle::INVALID); pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_SOCKET_WAIT, |op_id, op| {
            if op.scratch[SOCK_KEY_SOCKET] != socket_raw {
                return;
            }
            if count < targets.len() {
                let src = raw_to_vnode_handle(op.scratch[SOCK_SRC_VNODE]);
                targets[count] = (op_id, src);
                count += 1;
            }
        });
        let mut out = TronaMsg::zeroed();
        out.label = TRONA_INVALID_OPERATION;
        out.length = 0;
        for i in 0..count {
            let (op_id, src_vnode) = targets[i];
            release_waiter_resources(state, src_vnode);
            splice_from_chain(op_id, socket_raw);
            let reply_slot = pending_ops::take_reply_and_free(op_id);
            if reply_slot != 0 {
                send_saved_reply(reply_slot, &raw const out);
            }
        }
    }
}

/// Cancel every waiter belonging to `badge`. Invoked by
/// `cancel_waiters_for_badge` on `VFS_CLIENT_EXIT`. Splices the ops
/// out of their per-socket chains and releases per-waiter aux state
/// (bound source vnode); the reply ships from `pending_ops::
/// drain_cancelled` per the disposition recorded by the caller's
/// subsequent `pending_ops::cancel_for_badge`.
pub(crate) unsafe fn cancel_unix_socket_waiters_for_badge(state: &mut VfsState, badge: u64) {
    if badge == 0 {
        return;
    }
    unsafe {
        let mut targets =
            [(PendingOpId::NONE, 0u64, VnodeHandle::INVALID); pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_SOCKET_WAIT, |op_id, op| {
            if op.badge != badge {
                return;
            }
            if count < targets.len() {
                let socket_raw = op.scratch[SOCK_KEY_SOCKET];
                let src = raw_to_vnode_handle(op.scratch[SOCK_SRC_VNODE]);
                targets[count] = (op_id, socket_raw, src);
                count += 1;
            }
        });
        for i in 0..count {
            let (op_id, socket_raw, src_vnode) = targets[i];
            release_waiter_resources(state, src_vnode);
            splice_from_chain(op_id, socket_raw);
        }
    }
}
