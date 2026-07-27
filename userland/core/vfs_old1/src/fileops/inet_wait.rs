// SPDX-License-Identifier: GPL-2.0-only
//! Deferred reply storage for AF_INET sockets parked on netsrv async
//! completions.
//!
//! VFS parks the saved caller in a `PendingOp` of kind
//! `PO_KIND_INET_WAIT` keyed by `(conn_id, op_type)`. Multiple waiters
//! on the same key form a per-key FIFO via `scratch[CHAIN_NEXT_OP_ID]`
//! intra-pool linkage (same pattern as TTY/PIPE chains in
//! `tty_wait.rs`). The first waiter for a key fires `NET_*_WAIT`;
//! subsequent waiters chain into the FIFO and merely set
//! `needs_rearm` when they become the new head — actual NET_*_WAIT
//! IPC happens in `drive_inet_waiters` (called from the owner-loop's
//! idle-tick path AFTER any pending reply has been flushed), never
//! inside `handle_netsrv_completion` itself, because netsrv's
//! `notify_vfs_completion` blocks on `call_ctx(callback_ep)` and any
//! sync NET_* call from within the callback handler would deadlock.

use core::sync::atomic::{AtomicU64, Ordering};

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::posix::server::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::fileops::tty_wait::{save_current_caller, send_saved_reply};
use crate::owner::VfsState;
use crate::owner::pending_ops::{self, PO_KIND_INET_WAIT, PendingOp, PendingOpId};
use crate::server::types::ClientHandle;

pub(crate) const NETSRV_CALLBACK_BADGE: u64 = 0x4E37D;
const INET_RECV_INLINE_MAX: usize = 152;

// Diagnostic counter for completions that arrived without a matching
// parked waiter (close-after-arm race or netsrv ring overflow).
// Owner-thread only, but `AtomicU64` keeps it Sync-safe in the static
// without requiring an unsafe cell wrapper.
static INET_COMPLETION_DROPS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn bump_drops() {
    INET_COMPLETION_DROPS.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn inet_completion_drops() -> u64 {
    INET_COMPLETION_DROPS.load(Ordering::Relaxed)
}

// scratch layout for PO_KIND_INET_WAIT:
//   scratch[0] = next_op_id (chain link; PendingOpId::NONE = tail)
//   scratch[1] = (conn_id u32, op_type u8 in low byte of high u32) packed
//   scratch[2] = max_len u16 | flags u32 in high u32 | needs_rearm u8 in bit 32+8
const INET_CHAIN_NEXT: usize = 0;
const INET_KEY: usize = 1;
const INET_AUX: usize = 2;

#[inline]
fn encode_key(conn_id: u32, op_type: u8) -> u64 {
    (conn_id as u64) | ((op_type as u64) << 32)
}

#[inline]
fn decode_conn_id(key: u64) -> u32 {
    (key & 0xFFFF_FFFF) as u32
}

#[inline]
fn decode_op_type(key: u64) -> u8 {
    ((key >> 32) & 0xFF) as u8
}

#[inline]
fn encode_aux(max_len: u16, flags: u32, needs_rearm: u8) -> u64 {
    (max_len as u64) | ((flags as u64) << 16) | ((needs_rearm as u64) << 48)
}

#[inline]
fn decode_max_len(aux: u64) -> u16 {
    (aux & 0xFFFF) as u16
}

#[inline]
fn decode_flags(aux: u64) -> u32 {
    ((aux >> 16) & 0xFFFF_FFFF) as u32
}

#[inline]
fn decode_needs_rearm(aux: u64) -> u8 {
    ((aux >> 48) & 0xFF) as u8
}

fn lookup_badge(state: &VfsState, client: ClientHandle) -> u64 {
    state.clients.get(client).map(|c| c.badge).unwrap_or(0)
}

unsafe fn find_chain_head(conn_id: u32, op_type: u8) -> Option<PendingOpId> {
    unsafe {
        let key = encode_key(conn_id, op_type);
        const MAX_PAIRS: usize = pending_ops::MAX_PENDING_OPS;
        let mut ids = [PendingOpId::NONE; MAX_PAIRS];
        let mut nexts = [0u64; MAX_PAIRS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_INET_WAIT, |op_id, op| {
            if op.scratch[INET_KEY] != key {
                return;
            }
            if count >= MAX_PAIRS {
                return;
            }
            ids[count] = op_id;
            nexts[count] = op.scratch[INET_CHAIN_NEXT];
            count += 1;
        });
        for i in 0..count {
            let mut is_head = true;
            for j in 0..count {
                if i == j {
                    continue;
                }
                if nexts[j] == ids[i].raw() {
                    is_head = false;
                    break;
                }
            }
            if is_head {
                return Some(ids[i]);
            }
        }
        None
    }
}

unsafe fn find_chain_tail(conn_id: u32, op_type: u8) -> Option<PendingOpId> {
    unsafe {
        let head = find_chain_head(conn_id, op_type)?;
        let mut cursor = head;
        loop {
            let next_raw = pending_ops::get(cursor)
                .map(|op| op.scratch[INET_CHAIN_NEXT])
                .unwrap_or(PendingOpId::NONE.raw());
            if next_raw == PendingOpId::NONE.raw() {
                return Some(cursor);
            }
            cursor = PendingOpId::from_raw(next_raw);
        }
    }
}

unsafe fn splice_from_chain(target: PendingOpId, conn_id: u32, op_type: u8) {
    unsafe {
        let key = encode_key(conn_id, op_type);
        let target_raw = target.raw();
        let next_after_target = pending_ops::get(target)
            .map(|op| op.scratch[INET_CHAIN_NEXT])
            .unwrap_or(PendingOpId::NONE.raw());
        let mut predecessor: Option<PendingOpId> = None;
        pending_ops::for_each_active_kind(PO_KIND_INET_WAIT, |candidate_id, candidate| {
            if candidate_id == target {
                return;
            }
            if candidate.scratch[INET_KEY] != key {
                return;
            }
            if candidate.scratch[INET_CHAIN_NEXT] == target_raw {
                predecessor = Some(candidate_id);
            }
        });
        if let Some(pred_id) = predecessor {
            if let Some(pred_op) = pending_ops::get_mut(pred_id) {
                pred_op.scratch[INET_CHAIN_NEXT] = next_after_target;
            }
        }
    }
}

/// Park a blocking inet operation. Allocates a `PendingOp`, links it
/// into the per-key FIFO. If this is the only waiter for the key, the
/// caller's dispatch path must subsequently fire `NET_*_WAIT` (via
/// `arm_or_cancel_head`) to register interest with netsrv. If a
/// waiter already exists for the same key, this slot's `needs_rearm`
/// stays 0 — `handle_netsrv_completion` will set it on the new head
/// when the previous head completes.
///
/// Returns `Some(true)` when the caller should fire `NET_*_WAIT` after
/// the dispatch path returns (because the slot is now the only head),
/// `Some(false)` when an earlier waiter is still ahead, and `None` on
/// pool exhaustion / saved-caller failure (reply already populated).
pub(crate) unsafe fn defer_inet_op(
    state: &mut VfsState,
    client: ClientHandle,
    conn_id: u32,
    op_type: u8,
    max_len: u16,
    flags: u32,
    reply: *mut TronaMsg,
) -> Option<bool> {
    unsafe {
        // If registration with netsrv hasn't happened yet, parking the
        // saved caller would create a permanently stuck waiter (netsrv
        // would silently drop completions because VFS_REGISTERED is
        // false on its side). Try once now — if it still fails, return
        // a transport error to the caller rather than parking.
        if !try_register_with_netsrv(state) {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return None;
        }
        let badge = lookup_badge(state, client);
        let Some(reply_slot) = save_current_caller(reply) else {
            return None;
        };

        let prev_tail = find_chain_tail(conn_id, op_type);
        let Some(op_id) = pending_ops::alloc(PO_KIND_INET_WAIT, badge, client, reply_slot) else {
            crate::fileops::tty_wait::release_reply_slot(reply_slot);
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return None;
        };
        if let Some(op) = pending_ops::get_mut(op_id) {
            op.scratch[INET_CHAIN_NEXT] = PendingOpId::NONE.raw();
            op.scratch[INET_KEY] = encode_key(conn_id, op_type);
            op.scratch[INET_AUX] = encode_aux(max_len, flags, 0);
        }

        if let Some(tail_id) = prev_tail {
            if let Some(tail_op) = pending_ops::get_mut(tail_id) {
                tail_op.scratch[INET_CHAIN_NEXT] = op_id.raw();
            }
            (*reply).label = crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
            (*reply).length = 0;
            Some(false)
        } else {
            (*reply).label = crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
            (*reply).length = 0;
            Some(true)
        }
    }
}

fn netsrv_call(req: *const TronaMsg, reply: *mut TronaMsg) -> i32 {
    unsafe { ipc::call_ctx(crate::ipc_ctx(), crate::netsrv_ep(), req, reply) }
}

/// Fire `NET_*_WAIT` to arm the netsrv-side pending slot for an
/// `(conn_id, op_type)` pair. Returns `0` on success or an error label
/// on transport / netsrv failure (caller cancels the parked slot in
/// that case).
fn arm_wait_call(op_type: u8, conn_id: u32, max_len: u16, flags: u32) -> u64 {
    let mut req = TronaMsg::zeroed();
    let mut resp = TronaMsg::zeroed();
    let label = match op_type {
        INET_OP_RECV => NET_RECV_WAIT,
        INET_OP_ACCEPT => NET_ACCEPT_WAIT,
        INET_OP_RECVFROM => NET_RECVFROM_WAIT,
        // INET_OP_CONNECT: NET_CONNECT itself sets pending_connect on
        // the netsrv side, so completion arrives without an explicit
        // wait label. Treat as a no-op arm.
        _ => return TRONA_OK,
    };
    req.label = label;
    req.regs[0] = conn_id as u64;
    if op_type == INET_OP_RECV || op_type == INET_OP_RECVFROM {
        req.regs[1] = max_len as u64;
        req.regs[2] = flags as u64;
        req.length = 3;
    } else {
        req.length = 1;
    }
    let err = netsrv_call(&raw const req, &raw mut resp);
    if err != 0 {
        return TRONA_INVALID_OPERATION;
    }
    if resp.label != TRONA_PENDING && resp.label != TRONA_OK {
        return resp.label;
    }
    TRONA_OK
}

/// Fire NET_*_WAIT immediately for a freshly-parked waiter that became
/// the FIFO head. On failure, cancels the slot, sends an error reply
/// to the saved caller.
pub(crate) unsafe fn arm_or_cancel_head(_state: &mut VfsState, conn_id: u32, op_type: u8) {
    unsafe {
        let Some(head) = find_chain_head(conn_id, op_type) else {
            return;
        };
        let (max_len, flags) = match pending_ops::get(head) {
            Some(op) => {
                let aux = op.scratch[INET_AUX];
                (decode_max_len(aux), decode_flags(aux))
            }
            None => return,
        };
        let err = arm_wait_call(op_type, conn_id, max_len, flags);
        if err == TRONA_OK {
            return;
        }
        bump_drops();
        let mut out = TronaMsg::zeroed();
        out.label = err;
        out.length = 0;
        splice_from_chain(head, conn_id, op_type);
        let reply_slot = pending_ops::take_reply_and_free(head);
        if reply_slot != 0 {
            send_saved_reply(reply_slot, &raw const out);
        }
    }
}

unsafe fn fill_completion_connect(msg: *const TronaMsg, reply: *mut TronaMsg) {
    unsafe {
        let result = (*msg).regs[1];
        (*reply).label = result;
        (*reply).length = 0;
    }
}

unsafe fn fill_completion_recv(msg: *const TronaMsg, reply: *mut TronaMsg) {
    unsafe {
        let result = (*msg).regs[1];
        if result != TRONA_OK {
            (*reply).label = result;
            (*reply).length = 0;
            return;
        }
        let data_len = core::cmp::min((*msg).regs[3] as usize, INET_RECV_INLINE_MAX);
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = data_len as u64;
        if data_len > 0 {
            // NET_COMPLETE INET_OP_RECV puts data starting at regs[4].
            // Sync NET_RECV reply uses regs[1..]. Copy across the offset
            // shift.
            let src = &raw const (*msg).regs[4] as *const u8;
            let dst = &raw mut (*reply).regs[1] as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, data_len);
        }
        (*reply).length = 1 + ((data_len as u64 + 7) / 8);
    }
}

unsafe fn fill_completion_accept(
    state: &mut VfsState,
    msg: *const TronaMsg,
    waiter_client: ClientHandle,
    reply: *mut TronaMsg,
) {
    unsafe {
        let result = (*msg).regs[1];
        if result != TRONA_OK {
            (*reply).label = result;
            (*reply).length = 0;
            return;
        }
        let new_conn_id = (*msg).regs[3] as u32;
        if new_conn_id == 0 {
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return;
        }
        let Some(new_fd) = state.alloc_socket_client_slot(waiter_client, new_conn_id, 0) else {
            // Mirror the sync handle_accept_owned rollback: tell netsrv
            // to close the orphaned conn_id and surface OOM.
            let mut close_req = TronaMsg::zeroed();
            let mut close_resp = TronaMsg::zeroed();
            close_req.label = NET_CLOSE;
            close_req.length = 1;
            close_req.regs[0] = new_conn_id as u64;
            let _ = netsrv_call(&raw const close_req, &raw mut close_resp);
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return;
        };
        (*reply).label = TRONA_OK;
        (*reply).length = 1;
        (*reply).regs[0] = new_fd as u64;
    }
}

unsafe fn fill_completion_recvfrom(msg: *const TronaMsg, reply: *mut TronaMsg) {
    unsafe {
        let result = (*msg).regs[1];
        if result != TRONA_OK {
            (*reply).label = result;
            (*reply).length = 0;
            return;
        }
        let data_len = core::cmp::min((*msg).regs[3] as usize, INET_RECV_INLINE_MAX);
        (*reply).label = TRONA_OK;
        (*reply).regs[0] = data_len as u64;
        (*reply).regs[1] = (*msg).regs[4];
        (*reply).regs[2] = (*msg).regs[5];
        (*reply).regs[3] = (*msg).regs[6];
        if data_len > 0 {
            let src = &raw const (*msg).regs[7] as *const u8;
            let dst = &raw mut (*reply).regs[4] as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, data_len);
        }
        (*reply).length = 4 + ((data_len as u64 + 7) / 8);
    }
}

/// Handle a NET_COMPLETE callback delivered to the dedicated callback
/// endpoint. `reply` carries the response back to netsrv (which is
/// blocked on `call_ctx(callback_ep)`); we always return TRONA_OK so
/// netsrv unblocks and can drain the next completion.
///
/// Late completions (no matching waiter — typically because the
/// client's fd was closed and `cancel_inet_waiters_for_conn` ran first)
/// are silently dropped and counted in `INET_COMPLETION_DROPS`.
pub(crate) unsafe fn handle_netsrv_completion(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let conn_id = (*msg).regs[0] as u32;
        let op_type = (*msg).regs[2] as u8;

        let Some(head) = find_chain_head(conn_id, op_type) else {
            bump_drops();
            (*reply).label = TRONA_OK;
            (*reply).length = 0;
            return;
        };

        let (cli_handle, next_op_id) = match pending_ops::get(head) {
            Some(op) => {
                let cli = pending_ops::unpack_client_handle(op.client_handle_raw);
                let next = PendingOpId::from_raw(op.scratch[INET_CHAIN_NEXT]);
                (cli, next)
            }
            None => {
                bump_drops();
                (*reply).label = TRONA_OK;
                (*reply).length = 0;
                return;
            }
        };

        let mut out = TronaMsg::zeroed();
        match op_type {
            INET_OP_CONNECT => fill_completion_connect(msg, &raw mut out),
            INET_OP_RECV => fill_completion_recv(msg, &raw mut out),
            INET_OP_ACCEPT => fill_completion_accept(state, msg, cli_handle, &raw mut out),
            INET_OP_RECVFROM => fill_completion_recvfrom(msg, &raw mut out),
            _ => {
                out.label = TRONA_INVALID_OPERATION;
                out.length = 0;
            }
        }
        splice_from_chain(head, conn_id, op_type);
        let reply_slot = pending_ops::take_reply_and_free(head);
        if reply_slot != 0 {
            send_saved_reply(reply_slot, &raw const out);
        }

        // If a successor waiter is queued, mark it for re-arm. Actual
        // NET_*_WAIT IPC happens in drive_inet_waiters AFTER this
        // dispatch path returns and the reply to netsrv has been sent.
        if !next_op_id.is_none() {
            if let Some(succ_op) = pending_ops::get_mut(next_op_id) {
                let aux = succ_op.scratch[INET_AUX];
                let max_len = decode_max_len(aux);
                let flags = decode_flags(aux);
                succ_op.scratch[INET_AUX] = encode_aux(max_len, flags, 1);
            }
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 0;
    }
}

/// Single-pass over PO_KIND_INET_WAIT pool flushing any heads flagged
/// `needs_rearm`. Called from the owner-loop's idle-tick path AFTER
/// dispatch returns and the previous NET_COMPLETE reply has been
/// written out — so netsrv is awake and can accept a new
/// `NET_*_WAIT` call.
pub(crate) unsafe fn drive_inet_waiters(_state: &mut VfsState) {
    unsafe {
        // Collect (op_id, conn_id, op_type, max_len, flags) for every
        // op flagged needs_rearm before mutating, to avoid aliasing the
        // for_each_active_kind callback's &mut PendingOp.
        let mut targets =
            [(PendingOpId::NONE, 0u32, 0u8, 0u16, 0u32); pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_INET_WAIT, |op_id, op| {
            let aux = op.scratch[INET_AUX];
            if decode_needs_rearm(aux) == 0 {
                return;
            }
            if count < targets.len() {
                let key = op.scratch[INET_KEY];
                targets[count] = (
                    op_id,
                    decode_conn_id(key),
                    decode_op_type(key),
                    decode_max_len(aux),
                    decode_flags(aux),
                );
                count += 1;
            }
        });
        for i in 0..count {
            let (op_id, conn_id, op_type, max_len, flags) = targets[i];
            // Clear needs_rearm before the (potentially blocking) call.
            if let Some(op) = pending_ops::get_mut(op_id) {
                let aux = op.scratch[INET_AUX];
                op.scratch[INET_AUX] = encode_aux(decode_max_len(aux), decode_flags(aux), 0);
            }
            let err = arm_wait_call(op_type, conn_id, max_len, flags);
            if err == TRONA_OK {
                continue;
            }
            // Re-arm failed; tear down this slot. Successor (if any)
            // becomes the new head and gets needs_rearm=1.
            bump_drops();
            let mut out = TronaMsg::zeroed();
            out.label = err;
            out.length = 0;
            let next_raw = pending_ops::get(op_id)
                .map(|op| op.scratch[INET_CHAIN_NEXT])
                .unwrap_or(PendingOpId::NONE.raw());
            splice_from_chain(op_id, conn_id, op_type);
            let reply_slot = pending_ops::take_reply_and_free(op_id);
            if reply_slot != 0 {
                send_saved_reply(reply_slot, &raw const out);
            }
            let next_id = PendingOpId::from_raw(next_raw);
            if !next_id.is_none() {
                if let Some(succ) = pending_ops::get_mut(next_id) {
                    let aux = succ.scratch[INET_AUX];
                    succ.scratch[INET_AUX] = encode_aux(decode_max_len(aux), decode_flags(aux), 1);
                }
            }
        }
    }
}

/// Cancel every waiter targeting `conn_id`. Called from
/// `release_open_file` BEFORE NET_CLOSE so any late NET_COMPLETE
/// arriving after close becomes a silent drop. Replies fire here
/// (this is NOT the badge-cancel path — the disposition is
/// "client closed the fd intentionally", not "client died").
pub(crate) unsafe fn cancel_inet_waiters_for_conn(_state: &mut VfsState, conn_id: u32) {
    if conn_id == 0 {
        return;
    }
    unsafe {
        let mut targets = [(PendingOpId::NONE, 0u8); pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_INET_WAIT, |op_id, op| {
            let key = op.scratch[INET_KEY];
            if decode_conn_id(key) != conn_id {
                return;
            }
            if count < targets.len() {
                targets[count] = (op_id, decode_op_type(key));
                count += 1;
            }
        });
        let mut out = TronaMsg::zeroed();
        out.label = TRONA_INVALID_OPERATION;
        out.length = 0;
        for i in 0..count {
            let (op_id, op_type) = targets[i];
            splice_from_chain(op_id, conn_id, op_type);
            let reply_slot = pending_ops::take_reply_and_free(op_id);
            if reply_slot != 0 {
                send_saved_reply(reply_slot, &raw const out);
            }
        }
    }
}

/// Cancel every waiter belonging to `badge`. Invoked from
/// `cancel_waiters_for_badge` on `VFS_CLIENT_EXIT`. This splices the
/// targeted ops out of their FIFO chains; the actual reply ships from
/// `pending_ops::drain_cancelled` via the cancel disposition recorded
/// by the caller's subsequent `pending_ops::cancel_for_badge`.
pub(crate) unsafe fn cancel_inet_waiters_for_badge(_state: &mut VfsState, badge: u64) {
    if badge == 0 {
        return;
    }
    unsafe {
        let mut targets = [(PendingOpId::NONE, 0u32, 0u8); pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_INET_WAIT, |op_id, op| {
            if op.badge != badge {
                return;
            }
            if count < targets.len() {
                let key = op.scratch[INET_KEY];
                targets[count] = (op_id, decode_conn_id(key), decode_op_type(key));
                count += 1;
            }
        });
        for i in 0..count {
            let (op_id, conn_id, op_type) = targets[i];
            splice_from_chain(op_id, conn_id, op_type);
        }
    }
}

/// Idempotent attempt to publish the VFS callback endpoint to netsrv.
///
/// netsrv depends on vfs (vfs.service is started first) so the very
/// first attempts during VFS boot will fail with a transport error or
/// stale `netsrv_ep` until netsrv comes up. The owner-loop idle timer
/// keeps calling this helper until `netsrv_registered` flips. After
/// success, subsequent calls are no-ops.
///
/// Until registration succeeds, any `notify_vfs_completion` from netsrv
/// would be silently dropped on the netsrv side because
/// `VFS_REGISTERED == false` — so VFS must NOT arm any
/// `NET_*_WAIT` until this call has succeeded. `defer_inet_op` honours
/// that by short-circuiting when `netsrv_registered` is still false.
pub(crate) fn try_register_with_netsrv(state: &mut VfsState) -> bool {
    if state.netsrv_registered {
        return true;
    }
    if crate::netsrv_ep() == 0 || state.netsrv_callback_ep == 0 {
        return false;
    }
    let mut req = TronaMsg::zeroed();
    let mut resp = TronaMsg::zeroed();
    req.label = NET_REGISTER_VFS;
    req.length = 0;
    unsafe {
        ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, state.netsrv_callback_ep);
    }
    let err = unsafe {
        ipc::call_ctx(
            crate::ipc_ctx(),
            crate::netsrv_ep(),
            &raw const req,
            &raw mut resp,
        )
    };
    if err == 0 && resp.label == TRONA_OK {
        state.netsrv_registered = true;
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] registered callback EP with netsrv\n");
        });
        true
    } else {
        false
    }
}
