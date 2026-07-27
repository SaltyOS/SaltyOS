// SPDX-License-Identifier: GPL-2.0-only
//! Deferred terminal / poll / pipe / FIFO-open waits, parked as
//! `PendingOp` entries.
//!
//! All waiter classes share one storage substrate now: `pending_ops`.
//! Each `defer_*` allocates a `PendingOp` of the appropriate
//! `PO_KIND_*_WAIT` kind, stashes per-kind state in `scratch[]` (or in
//! `payload_ref` when the body exceeds the 64-byte scratch budget), and
//! returns `REPLY_DEFERRED_LABEL` to the dispatch path. `drive_*`
//! re-evaluates parked waiters by walking the pool through
//! `pending_ops::for_each_active_kind`, peeling head-first per
//! `(key)` chain when arrival order matters (TTY per pty/side, PIPE
//! per pipe handle).
//!
//! Cancel pipeline: `vfs_cancel_for_badge` invokes
//! `cancel_waiters_for_badge` here for per-kind cleanup hooks (FIFO
//! open releases the just-allocated client slot, INET/SOCKET release
//! peer-state aux), then calls `pending_ops::cancel_for_badge` which
//! marks every pending op for the badge as `CANCELLED`. The eventual
//! `pending_ops::drain_cancelled` ships the disposition reply.
//!
//! Capacity: per-kind tables collapsed into the shared
//! `MAX_PENDING_OPS = 256` budget. Net concurrent-waiter capacity goes
//! up (was ~128 across 8 fixed tables); per-kind hogging a runaway
//! number of slots can starve other kinds. Acceptable for now; revisit
//! with per-kind soft caps if profiling shows it.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_posix::consts::*;
use trona_protocol::posix::server::*;
use uapi::*;

use crate::owner::VfsState;
use crate::owner::pending_ops::{
    self, PAYLOAD_BUF_BYTES, PO_KIND_EPOLL_WAIT, PO_KIND_FIFO_OPEN, PO_KIND_PIPE_READ_WAIT,
    PO_KIND_PIPE_WRITE_WAIT, PO_KIND_POLL_WAIT, PO_KIND_TTY_WAIT, PendingOp, PendingOpId,
};
use crate::server::pipe_object::PipeHandle;
use crate::server::types::ClientHandle;

pub(crate) const REPLY_DEFERRED_LABEL: u64 = u64::MAX - 1;

pub(crate) const CONSOLE_TTY_ID: u32 = 0;
pub(crate) const MAX_TTY_IDS: usize = 4;
pub(crate) const TTY_NTFN_BITS_MASK: u64 = (1u64 << MAX_TTY_IDS) - 1;

const TTY_SIDE_SLAVE: u64 = 0;
const TTY_SIDE_MASTER: u64 = 1;

// Scratch index conventions. Every chained kind reserves
// `scratch[CHAIN_NEXT_OP_ID]` for the FIFO link to the next waiter on
// the same key (`PendingOpId::NONE` = tail). Remaining scratch slots
// carry kind-specific operands.
const CHAIN_NEXT_OP_ID: usize = 0;

// TTY_WAIT scratch layout:
//   scratch[0] = next_op_id (chain link)
//   scratch[1] = pty_id (u32, low 32 bits) | side (u32, high 32 bits — 0 slave / 1 master)
//   scratch[2] = max_count
const TTY_KEY: usize = 1;
const TTY_MAX_COUNT: usize = 2;

// PIPE_READ_WAIT / PIPE_WRITE_WAIT scratch layout:
//   scratch[0] = next_op_id (chain link)
//   scratch[1] = pipe_handle (raw u64 — chain key)
//   scratch[2] = fd
//   scratch[3] = max_count (read) | data_len (write — payload_ref carries body)
const PIPE_PIPE_HANDLE: usize = 1;
const PIPE_FD: usize = 2;
const PIPE_COUNT_OR_LEN: usize = 3;

// EPOLL_WAIT scratch layout (no chain — flat list, drive scans by deadline):
//   scratch[0] = epfd (i32, sign-extended u64)
//   scratch[1] = maxevents (u32)
//   scratch[2] = deadline_ns
const EPOLL_EPFD: usize = 0;
const EPOLL_MAXEVENTS: usize = 1;
const EPOLL_DEADLINE: usize = 2;

// FIFO_OPEN scratch layout (no chain):
//   scratch[0] = pipe_handle (raw u64)
//   scratch[1] = fd
//   scratch[2] = accmode (u32)
const FIFO_PIPE_HANDLE: usize = 0;
const FIFO_FD: usize = 1;
const FIFO_ACCMODE: usize = 2;

// POLL_WAIT body lives in payload (POLL_INLINE_MAX_FDS bumps would
// overflow scratch). Layout in `payload_bytes`:
//   u8  nfds
//   u64 deadline_ns
//   [i32; POLL_INLINE_MAX_FDS] fds
//   [i16; POLL_INLINE_MAX_FDS] events
#[repr(C)]
#[derive(Clone, Copy)]
struct PollWaitBody {
    nfds: u8,
    _pad0: [u8; 7],
    deadline_ns: u64,
    fds: [i32; crate::fileops::poll::POLL_INLINE_MAX_FDS],
    events: [i16; crate::fileops::poll::POLL_INLINE_MAX_FDS],
}

const _: () = assert!(core::mem::size_of::<PollWaitBody>() <= PAYLOAD_BUF_BYTES);

// PIPE_WRITE_WAIT body lives in payload (144-byte inline buffer
// overflows scratch).
#[repr(C)]
#[derive(Clone, Copy)]
struct PipeWriteWaitBody {
    data_len: u16,
    _pad: [u8; 6],
    data: [u8; crate::fileops::pipe::PIPE_INLINE_WRITE_MAX],
}

const _: () = assert!(core::mem::size_of::<PipeWriteWaitBody>() <= PAYLOAD_BUF_BYTES);

#[inline]
fn encode_tty_key(pty_id: u32, side: u64) -> u64 {
    (pty_id as u64) | (side << 32)
}

#[inline]
fn decode_tty_pty_id(key: u64) -> u32 {
    (key & 0xFFFF_FFFF) as u32
}

#[inline]
fn decode_tty_side(key: u64) -> u64 {
    key >> 32
}

#[inline]
pub(crate) fn tty_id_for_device(dev_type: u8, pty_id: u32) -> Option<u32> {
    match dev_type {
        DEV_CONSOLE => Some(CONSOLE_TTY_ID),
        DEV_PTY_SLAVE | DEV_PTMX => Some(pty_id),
        _ => None,
    }
}

#[inline]
pub(crate) fn tty_side_for_device(dev_type: u8) -> Option<u64> {
    match dev_type {
        DEV_PTMX => Some(TTY_SIDE_MASTER),
        DEV_CONSOLE | DEV_PTY_SLAVE => Some(TTY_SIDE_SLAVE),
        _ => None,
    }
}

pub(crate) fn save_current_caller(reply: *mut TronaMsg) -> Option<u64> {
    unsafe {
        let Some(slot) = trona_runtime::core::slot_alloc::slot_alloc() else {
            (*reply).label = TRONA_OUT_OF_MEMORY;
            (*reply).length = 0;
            return None;
        };
        let err = trona_kernel::invoke::cnode_save_caller(CAP_SELF_CSPACE, slot);
        if err != 0 {
            let _ = trona_kernel::invoke::cnode_delete(CAP_SELF_CSPACE, slot);
            let _ = trona_runtime::core::slot_alloc::slot_free(slot);
            (*reply).label = TRONA_INVALID_OPERATION;
            (*reply).length = 0;
            return None;
        }
        Some(slot)
    }
}

pub(crate) unsafe fn release_reply_slot(slot: u64) {
    if slot == 0 {
        return;
    }
    unsafe {
        let _ = trona_kernel::invoke::cnode_delete(CAP_SELF_CSPACE, slot);
    }
    let _ = trona_runtime::core::slot_alloc::slot_free(slot);
}

pub(crate) unsafe fn send_saved_reply(slot: u64, msg: *const TronaMsg) {
    if slot == 0 {
        return;
    }
    unsafe {
        let _ = ipc::send_ctx(crate::ipc_ctx(), slot, msg);
        release_reply_slot(slot);
    }
}

#[inline]
fn lookup_badge(state: &VfsState, client: ClientHandle) -> u64 {
    state.clients.get(client).map(|c| c.badge).unwrap_or(0)
}

/// Reserve a `PendingOp` slot for a waiter and stash the provided
/// scratch words. The reply slot is the saved-caller cap. On
/// allocation failure the caller is responsible for the saved-caller
/// rollback (see callers' `release_reply_slot` paths).
unsafe fn alloc_wait_op(
    kind: pending_ops::PendingOpKind,
    badge: u64,
    cli_handle: ClientHandle,
    reply_slot: u64,
    scratch: &[u64],
) -> Option<PendingOpId> {
    unsafe {
        let op_id = pending_ops::alloc(kind, badge, cli_handle, reply_slot)?;
        let Some(op) = pending_ops::get_mut(op_id) else {
            // Should never happen: we just allocated.
            pending_ops::free(op_id);
            return None;
        };
        for (idx, value) in scratch.iter().enumerate() {
            if idx >= op.scratch.len() {
                break;
            }
            op.scratch[idx] = *value;
        }
        Some(op_id)
    }
}

/// Append `op_id` as the new tail of the per-key chain identified by
/// `is_in_chain(op)`. Walks the pool by `kind`, finds the existing
/// tail (last node whose `scratch[CHAIN_NEXT_OP_ID]` is `NONE`), and
/// links it forward. If no chain exists yet, `op_id` becomes the head
/// implicitly (its own `next_op_id` is already `NONE`).
unsafe fn append_to_chain(
    kind: pending_ops::PendingOpKind,
    op_id: PendingOpId,
    mut is_same_chain: impl FnMut(&PendingOp) -> bool,
) {
    unsafe {
        let mut tail: Option<PendingOpId> = None;
        pending_ops::for_each_active_kind(kind, |candidate_id, candidate| {
            if candidate_id == op_id {
                return;
            }
            if !is_same_chain(candidate) {
                return;
            }
            if candidate.scratch[CHAIN_NEXT_OP_ID] == PendingOpId::NONE.raw() {
                tail = Some(candidate_id);
            }
        });
        if let Some(tail_id) = tail {
            if let Some(tail_op) = pending_ops::get_mut(tail_id) {
                tail_op.scratch[CHAIN_NEXT_OP_ID] = op_id.raw();
            }
        }
    }
}

/// Locate the head of the per-key chain identified by `is_same_chain`.
/// The head is the active op whose `op_id` no other same-chain op
/// references via `scratch[CHAIN_NEXT_OP_ID]`. Returns `None` if no
/// chain matches the predicate.
unsafe fn find_chain_head(
    kind: pending_ops::PendingOpKind,
    mut is_same_chain: impl FnMut(&PendingOp) -> bool,
) -> Option<PendingOpId> {
    unsafe {
        // Two-pass: collect (op_id, next_op_id) pairs for the chain,
        // then pick the entry no other entry's `next_op_id` points at.
        const MAX_CHAIN_PAIRS: usize = pending_ops::MAX_PENDING_OPS;
        let mut ids = [PendingOpId::NONE; MAX_CHAIN_PAIRS];
        let mut nexts = [PendingOpId::NONE.raw(); MAX_CHAIN_PAIRS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(kind, |op_id, op| {
            if !is_same_chain(op) {
                return;
            }
            if count >= MAX_CHAIN_PAIRS {
                return;
            }
            ids[count] = op_id;
            nexts[count] = op.scratch[CHAIN_NEXT_OP_ID];
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

/// Splice `target` out of its same-chain neighbours by patching the
/// predecessor's `next_op_id` to skip past it. Caller-owned cleanup
/// (reply, payload, slot release) happens elsewhere.
unsafe fn splice_from_chain(
    kind: pending_ops::PendingOpKind,
    target: PendingOpId,
    mut is_same_chain: impl FnMut(&PendingOp) -> bool,
) {
    unsafe {
        let target_raw = target.raw();
        let next_after_target = pending_ops::get(target)
            .map(|op| op.scratch[CHAIN_NEXT_OP_ID])
            .unwrap_or(PendingOpId::NONE.raw());
        let mut predecessor: Option<PendingOpId> = None;
        pending_ops::for_each_active_kind(kind, |candidate_id, candidate| {
            if candidate_id == target {
                return;
            }
            if !is_same_chain(candidate) {
                return;
            }
            if candidate.scratch[CHAIN_NEXT_OP_ID] == target_raw {
                predecessor = Some(candidate_id);
            }
        });
        if let Some(pred_id) = predecessor {
            if let Some(pred_op) = pending_ops::get_mut(pred_id) {
                pred_op.scratch[CHAIN_NEXT_OP_ID] = next_after_target;
            }
        }
    }
}

// =================================================================
// TTY_WAIT (per pty / side) chain
// =================================================================

pub(crate) unsafe fn try_tty_read_to_reply(
    pty_id: u32,
    side: u64,
    max_len: usize,
    reply: *mut TronaMsg,
) -> Result<bool, u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut resp = TronaMsg::zeroed();
        req.label = POSIX_TTYSRV_PTY_READ;
        req.length = 3;
        req.regs[0] = pty_id as u64;
        req.regs[1] = max_len as u64;
        req.regs[2] = side;
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            crate::posix_ttysrv_ep(),
            &raw const req,
            &raw mut resp,
        );
        if err != 0 || resp.label != TRONA_OK {
            return Err(TRONA_INVALID_OPERATION);
        }

        let actual = core::cmp::min(resp.regs[0] as usize, max_len);
        if actual == 0 {
            return Ok(false);
        }

        (*reply).label = TRONA_OK;
        (*reply).regs[0] = actual as u64;
        (*reply).length = 1 + ((actual as u64 + 7) / 8);
        let src = &raw const resp.regs[1] as *const u8;
        let dst = &raw mut (*reply).regs[1] as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, actual);
        Ok(true)
    }
}

pub(crate) unsafe fn defer_tty_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    pty_id: u32,
    side: u64,
    max_count: usize,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        if (pty_id as usize) >= MAX_TTY_IDS {
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return false;
        }
        let badge = lookup_badge(state, cli_handle);
        let Some(reply_slot) = save_current_caller(reply) else {
            return false;
        };
        let scratch = [
            PendingOpId::NONE.raw(),
            encode_tty_key(pty_id, side),
            max_count as u64,
            0,
            0,
            0,
            0,
            0,
        ];
        let Some(op_id) = alloc_wait_op(PO_KIND_TTY_WAIT, badge, cli_handle, reply_slot, &scratch)
        else {
            release_reply_slot(reply_slot);
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return false;
        };
        append_to_chain(PO_KIND_TTY_WAIT, op_id, |candidate| {
            candidate.scratch[TTY_KEY] == encode_tty_key(pty_id, side)
        });
        (*reply).label = REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}

unsafe fn drive_tty_read_chain(_state: &mut VfsState, pty_id: u32, side: u64) {
    unsafe {
        let key = encode_tty_key(pty_id, side);
        loop {
            let Some(head) = find_chain_head(PO_KIND_TTY_WAIT, |op| op.scratch[TTY_KEY] == key)
            else {
                return;
            };
            let max_count = match pending_ops::get(head) {
                Some(op) => op.scratch[TTY_MAX_COUNT] as usize,
                None => return,
            };
            let mut out = TronaMsg::zeroed();
            match try_tty_read_to_reply(pty_id, side, max_count, &raw mut out) {
                Ok(true) => {
                    splice_from_chain(PO_KIND_TTY_WAIT, head, |op| op.scratch[TTY_KEY] == key);
                    let reply_slot = pending_ops::take_reply_and_free(head);
                    if reply_slot != 0 {
                        send_saved_reply(reply_slot, &raw const out);
                    }
                }
                Ok(false) => {
                    return;
                }
                Err(err) => {
                    out.label = err;
                    out.length = 0;
                    splice_from_chain(PO_KIND_TTY_WAIT, head, |op| op.scratch[TTY_KEY] == key);
                    let reply_slot = pending_ops::take_reply_and_free(head);
                    if reply_slot != 0 {
                        send_saved_reply(reply_slot, &raw const out);
                    }
                }
            }
        }
    }
}

pub(crate) unsafe fn drive_tty_read_waiters(state: &mut VfsState, ntfn_badge: u64) {
    unsafe {
        for pty_id in 0..MAX_TTY_IDS {
            if (ntfn_badge & (1u64 << pty_id)) == 0 {
                continue;
            }
            // Slave-side and master-side both share the per-pty
            // notification bit; the kernel ntfn does not distinguish
            // sides, so drive both chains.
            drive_tty_read_chain(state, pty_id as u32, TTY_SIDE_SLAVE);
            drive_tty_read_chain(state, pty_id as u32, TTY_SIDE_MASTER);
        }
    }
}

// =================================================================
// POLL_WAIT (flat — drive scans every active waiter, no chain)
// =================================================================

fn poll_deadline_ns(timeout_ms: i32) -> u64 {
    if timeout_ms < 0 {
        0
    } else {
        crate::fileops::poll::monotonic_now_ns()
            .saturating_add((timeout_ms as u64).saturating_mul(1_000_000))
    }
}

#[inline]
fn poll_waiter_expired(deadline_ns: u64, now_ns: u64) -> bool {
    deadline_ns != 0 && now_ns >= deadline_ns
}

unsafe fn write_poll_body(payload_ref: u32, body: &PollWaitBody) -> bool {
    unsafe {
        let Some(buf) = pending_ops::payload_bytes_mut(payload_ref) else {
            return false;
        };
        let dst = buf.as_mut_ptr() as *mut PollWaitBody;
        core::ptr::write(dst, *body);
        true
    }
}

unsafe fn read_poll_body(payload_ref: u32) -> Option<PollWaitBody> {
    unsafe {
        let buf = pending_ops::payload_bytes(payload_ref)?;
        let src = buf.as_ptr() as *const PollWaitBody;
        Some(core::ptr::read(src))
    }
}

pub(crate) unsafe fn defer_poll(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    msg: *const TronaMsg,
    nfds: usize,
    timeout_ms: i32,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let badge = lookup_badge(state, cli_handle);
        let Some(reply_slot) = save_current_caller(reply) else {
            return false;
        };
        let Some(op_id) = alloc_wait_op(PO_KIND_POLL_WAIT, badge, cli_handle, reply_slot, &[0; 0])
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
        let mut body = PollWaitBody {
            nfds: nfds as u8,
            _pad0: [0; 7],
            deadline_ns: poll_deadline_ns(timeout_ms),
            fds: [-1; crate::fileops::poll::POLL_INLINE_MAX_FDS],
            events: [0; crate::fileops::poll::POLL_INLINE_MAX_FDS],
        };
        for idx in 0..nfds {
            body.fds[idx] = (*msg).regs[2 + idx * 2] as i32;
            body.events[idx] = (*msg).regs[2 + idx * 2 + 1] as i16;
        }
        if !write_poll_body(payload_ref, &body) {
            pending_ops::release_payload(payload_ref);
            let leftover_slot = pending_ops::take_reply_and_free(op_id);
            if leftover_slot != 0 {
                release_reply_slot(leftover_slot);
            }
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return false;
        }
        if let Some(op) = pending_ops::get_mut(op_id) {
            op.payload_ref = payload_ref;
        } else {
            pending_ops::release_payload(payload_ref);
        }
        (*reply).label = REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}

pub(crate) unsafe fn drive_poll_waiters(state: &mut VfsState) {
    unsafe {
        let now_ns = crate::fileops::poll::monotonic_now_ns();
        // Collect targets first so the callback's &mut PendingOp does
        // not alias subsequent take_reply_and_free.
        let mut targets =
            [(PendingOpId::NONE, 0u32, ClientHandle::INVALID, 0u64); pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_POLL_WAIT, |op_id, op| {
            if count < targets.len() {
                let cli = pending_ops::unpack_client_handle(op.client_handle_raw);
                targets[count] = (op_id, op.payload_ref, cli, 0);
                count += 1;
            }
        });
        for i in 0..count {
            let (op_id, payload_ref, client, _) = targets[i];
            let Some(body) = read_poll_body(payload_ref) else {
                continue;
            };
            let mut out = TronaMsg::zeroed();
            let ready = crate::fileops::poll::fill_poll_reply(
                state,
                client,
                body.nfds as usize,
                &body.fds,
                &body.events,
                &raw mut out,
            );
            if ready != 0 || poll_waiter_expired(body.deadline_ns, now_ns) {
                let reply_slot = pending_ops::take_reply_and_free(op_id);
                if reply_slot != 0 {
                    send_saved_reply(reply_slot, &raw const out);
                }
            }
        }
    }
}

// =================================================================
// EPOLL_WAIT (flat — same shape as POLL_WAIT, but state in scratch)
// =================================================================

pub(crate) unsafe fn defer_epoll_wait(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    epfd: i32,
    maxevents: usize,
    timeout_ms: i32,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let badge = lookup_badge(state, cli_handle);
        let Some(reply_slot) = save_current_caller(reply) else {
            return false;
        };
        let scratch = [
            epfd as i64 as u64,
            maxevents as u64,
            poll_deadline_ns(timeout_ms),
            0,
            0,
            0,
            0,
            0,
        ];
        let Some(_op_id) =
            alloc_wait_op(PO_KIND_EPOLL_WAIT, badge, cli_handle, reply_slot, &scratch)
        else {
            release_reply_slot(reply_slot);
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return false;
        };
        (*reply).label = REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}

pub(crate) unsafe fn drive_epoll_waiters(state: &mut VfsState) {
    unsafe {
        let now_ns = crate::fileops::poll::monotonic_now_ns();
        let mut targets = [(PendingOpId::NONE, 0i32, 0u32, ClientHandle::INVALID, 0u64);
            pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_EPOLL_WAIT, |op_id, op| {
            if count < targets.len() {
                let epfd = op.scratch[EPOLL_EPFD] as i64 as i32;
                let maxevents = op.scratch[EPOLL_MAXEVENTS] as u32;
                let deadline = op.scratch[EPOLL_DEADLINE];
                let cli = pending_ops::unpack_client_handle(op.client_handle_raw);
                targets[count] = (op_id, epfd, maxevents, cli, deadline);
                count += 1;
            }
        });
        for i in 0..count {
            let (op_id, epfd, maxevents, client, deadline) = targets[i];
            let mut out = TronaMsg::zeroed();
            let ready = match crate::fileops::poll::fill_epoll_wait_reply(
                state,
                client,
                epfd,
                maxevents as usize,
                &raw mut out,
            ) {
                Ok(c) => c,
                Err(label) => {
                    out.label = label;
                    out.length = 0;
                    1
                }
            };
            if ready != 0 || poll_waiter_expired(deadline, now_ns) {
                let reply_slot = pending_ops::take_reply_and_free(op_id);
                if reply_slot != 0 {
                    send_saved_reply(reply_slot, &raw const out);
                }
            }
        }
    }
}

// =================================================================
// PIPE_READ_WAIT / PIPE_WRITE_WAIT (per pipe handle chain)
// =================================================================

unsafe fn write_pipe_write_body(payload_ref: u32, body: &PipeWriteWaitBody) -> bool {
    unsafe {
        let Some(buf) = pending_ops::payload_bytes_mut(payload_ref) else {
            return false;
        };
        let dst = buf.as_mut_ptr() as *mut PipeWriteWaitBody;
        core::ptr::write(dst, *body);
        true
    }
}

unsafe fn read_pipe_write_body(payload_ref: u32) -> Option<PipeWriteWaitBody> {
    unsafe {
        let buf = pending_ops::payload_bytes(payload_ref)?;
        let src = buf.as_ptr() as *const PipeWriteWaitBody;
        Some(core::ptr::read(src))
    }
}

fn pipe_handle_for_fd(state: &VfsState, cli_handle: ClientHandle, fd: usize) -> Option<PipeHandle> {
    let of = state.client_open_file(cli_handle, fd)?;
    if of.pipe.is_valid() {
        Some(of.pipe)
    } else {
        None
    }
}

#[inline]
fn pipe_handle_to_raw(handle: PipeHandle) -> u64 {
    let slot = handle.slot() as u64;
    let epoch = handle.epoch() as u64;
    slot | (epoch << 32)
}

pub(crate) unsafe fn defer_pipe_read(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: usize,
    max_count: usize,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let Some(pipe) = pipe_handle_for_fd(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return false;
        };
        let pipe_raw = pipe_handle_to_raw(pipe);
        let badge = lookup_badge(state, cli_handle);
        let Some(reply_slot) = save_current_caller(reply) else {
            return false;
        };
        let scratch = [
            PendingOpId::NONE.raw(),
            pipe_raw,
            fd as u64,
            max_count as u64,
            0,
            0,
            0,
            0,
        ];
        let Some(op_id) = alloc_wait_op(
            PO_KIND_PIPE_READ_WAIT,
            badge,
            cli_handle,
            reply_slot,
            &scratch,
        ) else {
            release_reply_slot(reply_slot);
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return false;
        };
        append_to_chain(PO_KIND_PIPE_READ_WAIT, op_id, |candidate| {
            candidate.scratch[PIPE_PIPE_HANDLE] == pipe_raw
        });
        (*reply).label = REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}

pub(crate) unsafe fn defer_pipe_write(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: usize,
    data: *const u8,
    data_len: usize,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let Some(pipe) = pipe_handle_for_fd(state, cli_handle, fd) else {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return false;
        };
        let pipe_raw = pipe_handle_to_raw(pipe);
        let badge = lookup_badge(state, cli_handle);
        let Some(reply_slot) = save_current_caller(reply) else {
            return false;
        };
        let scratch = [
            PendingOpId::NONE.raw(),
            pipe_raw,
            fd as u64,
            data_len as u64,
            0,
            0,
            0,
            0,
        ];
        let Some(op_id) = alloc_wait_op(
            PO_KIND_PIPE_WRITE_WAIT,
            badge,
            cli_handle,
            reply_slot,
            &scratch,
        ) else {
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
        let mut body = PipeWriteWaitBody {
            data_len: data_len as u16,
            _pad: [0; 6],
            data: [0; crate::fileops::pipe::PIPE_INLINE_WRITE_MAX],
        };
        let copy_len = core::cmp::min(data_len, body.data.len());
        core::ptr::copy_nonoverlapping(data, body.data.as_mut_ptr(), copy_len);
        if !write_pipe_write_body(payload_ref, &body) {
            pending_ops::release_payload(payload_ref);
            let leftover_slot = pending_ops::take_reply_and_free(op_id);
            if leftover_slot != 0 {
                release_reply_slot(leftover_slot);
            }
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return false;
        }
        if let Some(op) = pending_ops::get_mut(op_id) {
            op.payload_ref = payload_ref;
        } else {
            pending_ops::release_payload(payload_ref);
        }
        append_to_chain(PO_KIND_PIPE_WRITE_WAIT, op_id, |candidate| {
            candidate.scratch[PIPE_PIPE_HANDLE] == pipe_raw
        });
        (*reply).label = REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}

unsafe fn drive_pipe_read_chain(state: &mut VfsState, pipe_raw: u64) {
    unsafe {
        loop {
            let Some(head) = find_chain_head(PO_KIND_PIPE_READ_WAIT, |op| {
                op.scratch[PIPE_PIPE_HANDLE] == pipe_raw
            }) else {
                return;
            };
            let (cli_handle, fd, max_count) = match pending_ops::get(head) {
                Some(op) => (
                    pending_ops::unpack_client_handle(op.client_handle_raw),
                    op.scratch[PIPE_FD] as usize,
                    op.scratch[PIPE_COUNT_OR_LEN] as usize,
                ),
                None => return,
            };
            let mut out = TronaMsg::zeroed();
            match crate::fileops::pipe::try_pipe_read_to_reply(
                state,
                cli_handle,
                fd,
                max_count,
                &raw mut out,
            ) {
                Ok(true) => {
                    splice_from_chain(PO_KIND_PIPE_READ_WAIT, head, |op| {
                        op.scratch[PIPE_PIPE_HANDLE] == pipe_raw
                    });
                    let reply_slot = pending_ops::take_reply_and_free(head);
                    if reply_slot != 0 {
                        send_saved_reply(reply_slot, &raw const out);
                    }
                }
                Ok(false) => return,
                Err(label) => {
                    out.label = label;
                    out.length = 0;
                    splice_from_chain(PO_KIND_PIPE_READ_WAIT, head, |op| {
                        op.scratch[PIPE_PIPE_HANDLE] == pipe_raw
                    });
                    let reply_slot = pending_ops::take_reply_and_free(head);
                    if reply_slot != 0 {
                        send_saved_reply(reply_slot, &raw const out);
                    }
                }
            }
        }
    }
}

unsafe fn drive_pipe_write_chain(state: &mut VfsState, pipe_raw: u64) {
    unsafe {
        loop {
            let Some(head) = find_chain_head(PO_KIND_PIPE_WRITE_WAIT, |op| {
                op.scratch[PIPE_PIPE_HANDLE] == pipe_raw
            }) else {
                return;
            };
            let (cli_handle, fd, payload_ref, data_len) = match pending_ops::get(head) {
                Some(op) => (
                    pending_ops::unpack_client_handle(op.client_handle_raw),
                    op.scratch[PIPE_FD] as usize,
                    op.payload_ref,
                    op.scratch[PIPE_COUNT_OR_LEN] as usize,
                ),
                None => return,
            };
            let Some(body) = read_pipe_write_body(payload_ref) else {
                splice_from_chain(PO_KIND_PIPE_WRITE_WAIT, head, |op| {
                    op.scratch[PIPE_PIPE_HANDLE] == pipe_raw
                });
                let _ = pending_ops::take_reply_and_free(head);
                continue;
            };
            let mut out = TronaMsg::zeroed();
            match crate::fileops::pipe::try_pipe_write_to_reply(
                state,
                cli_handle,
                fd,
                body.data.as_ptr(),
                core::cmp::min(data_len, body.data.len()),
                &raw mut out,
            ) {
                Ok(true) => {
                    splice_from_chain(PO_KIND_PIPE_WRITE_WAIT, head, |op| {
                        op.scratch[PIPE_PIPE_HANDLE] == pipe_raw
                    });
                    let reply_slot = pending_ops::take_reply_and_free(head);
                    if reply_slot != 0 {
                        send_saved_reply(reply_slot, &raw const out);
                    }
                }
                Ok(false) => return,
                Err(label) => {
                    out.label = label;
                    out.length = 0;
                    splice_from_chain(PO_KIND_PIPE_WRITE_WAIT, head, |op| {
                        op.scratch[PIPE_PIPE_HANDLE] == pipe_raw
                    });
                    let reply_slot = pending_ops::take_reply_and_free(head);
                    if reply_slot != 0 {
                        send_saved_reply(reply_slot, &raw const out);
                    }
                }
            }
        }
    }
}

pub(crate) unsafe fn drive_pipe_waiters(state: &mut VfsState) {
    unsafe {
        // Collect distinct pipe_raw values present in either chain
        // and drive each. Distinct keys are bounded by MAX_PENDING_OPS.
        let mut keys = [0u64; pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        let mut push = |key: u64, keys: &mut [u64], count: &mut usize| {
            for i in 0..*count {
                if keys[i] == key {
                    return;
                }
            }
            if *count < keys.len() {
                keys[*count] = key;
                *count += 1;
            }
        };
        pending_ops::for_each_active_kind(PO_KIND_PIPE_READ_WAIT, |_id, op| {
            push(op.scratch[PIPE_PIPE_HANDLE], &mut keys, &mut count);
        });
        for i in 0..count {
            drive_pipe_read_chain(state, keys[i]);
        }
        count = 0;
        pending_ops::for_each_active_kind(PO_KIND_PIPE_WRITE_WAIT, |_id, op| {
            push(op.scratch[PIPE_PIPE_HANDLE], &mut keys, &mut count);
        });
        for i in 0..count {
            drive_pipe_write_chain(state, keys[i]);
        }
    }
}

// =================================================================
// FIFO_OPEN (flat — independent waiters, drive sweeps every active)
// =================================================================

pub(crate) unsafe fn defer_fifo_open(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: usize,
    pipe: PipeHandle,
    accmode: u32,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let badge = lookup_badge(state, cli_handle);
        let Some(reply_slot) = save_current_caller(reply) else {
            let _ = state.release_client_slot(cli_handle, fd);
            return false;
        };
        let scratch = [
            pipe_handle_to_raw(pipe),
            fd as u64,
            accmode as u64,
            0,
            0,
            0,
            0,
            0,
        ];
        let Some(_op_id) =
            alloc_wait_op(PO_KIND_FIFO_OPEN, badge, cli_handle, reply_slot, &scratch)
        else {
            release_reply_slot(reply_slot);
            let _ = state.release_client_slot(cli_handle, fd);
            (*reply).label = TRONA_BUSY;
            (*reply).length = 0;
            return false;
        };
        (*reply).label = REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}

pub(crate) unsafe fn drive_fifo_open_waiters(state: &mut VfsState) {
    unsafe {
        let mut targets = [(PendingOpId::NONE, 0u64, 0u64, 0u32); pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_FIFO_OPEN, |op_id, op| {
            if count < targets.len() {
                let pipe_raw = op.scratch[FIFO_PIPE_HANDLE];
                let fd = op.scratch[FIFO_FD];
                let accmode = op.scratch[FIFO_ACCMODE] as u32;
                targets[count] = (op_id, pipe_raw, fd, accmode);
                count += 1;
            }
        });
        for i in 0..count {
            let (op_id, pipe_raw, fd, accmode) = targets[i];
            let pipe = raw_to_pipe_handle(pipe_raw);
            let (read_refs, write_refs) = state.pipe_refcounts(pipe).unwrap_or((0, 0));
            let ready = if accmode == O_RDONLY {
                write_refs != 0
            } else {
                read_refs != 0
            };
            if !ready {
                continue;
            }
            let mut out = TronaMsg::zeroed();
            out.label = TRONA_OK;
            out.length = 1;
            out.regs[0] = fd;
            let reply_slot = pending_ops::take_reply_and_free(op_id);
            if reply_slot != 0 {
                send_saved_reply(reply_slot, &raw const out);
            }
        }
    }
}

#[inline]
fn raw_to_pipe_handle(raw: u64) -> PipeHandle {
    PipeHandle::new((raw & 0xFFFF_FFFF) as u32, (raw >> 32) as u32)
}

// =================================================================
// Combined drive entry points
// =================================================================

pub(crate) fn next_poll_timeout_ns(_state: &VfsState) -> u64 {
    let now_ns = crate::fileops::poll::monotonic_now_ns();
    let mut earliest = u64::MAX;
    unsafe {
        pending_ops::for_each_active_kind(PO_KIND_POLL_WAIT, |_id, op| {
            if let Some(body) = read_poll_body(op.payload_ref) {
                if body.deadline_ns != 0 {
                    earliest = earliest.min(body.deadline_ns);
                }
            }
        });
        pending_ops::for_each_active_kind(PO_KIND_EPOLL_WAIT, |_id, op| {
            let deadline = op.scratch[EPOLL_DEADLINE];
            if deadline != 0 {
                earliest = earliest.min(deadline);
            }
        });
    }
    if earliest == u64::MAX {
        0
    } else if earliest <= now_ns {
        1
    } else {
        earliest.saturating_sub(now_ns)
    }
}

pub(crate) unsafe fn drive_deferred_waiters(state: &mut VfsState) {
    unsafe {
        drive_pipe_waiters(state);
        drive_fifo_open_waiters(state);
        drive_poll_waiters(state);
        drive_epoll_waiters(state);
        crate::fileops::socket_wait::drive_unix_socket_waiters(state);
        // NOTE: `drive_inet_waiters` is intentionally NOT called from
        // here. It performs synchronous `NET_*_WAIT` IPC to netsrv,
        // and `drive_deferred_waiters` runs both immediately after
        // `dispatch_request` (before the dispatch reply has been sent
        // by the next `reply_recv_any_ctx` at the top of the loop)
        // and from owner mutation paths (release_open_file,
        // handle_shutdown_owned, etc.). Calling `drive_inet_waiters`
        // there would block on netsrv while netsrv is itself blocked
        // on the unsent NET_COMPLETE reply, deadlocking both servers.
        // The owner loop drives inet rearm explicitly from its idle
        // tick path, AFTER any pending reply has been flushed.
    }
}

pub(crate) unsafe fn handle_tty_notification(state: &mut VfsState, ntfn_badge: u64) {
    unsafe {
        drive_tty_read_waiters(state, ntfn_badge);
        drive_deferred_waiters(state);
    }
}

// =================================================================
// Cancel pipeline — per-kind cleanup BEFORE pending_ops::cancel_for_badge
// =================================================================

/// Per-kind cleanup hooks for ops that match `badge`. Each helper
/// runs on the owner thread, releases per-kind aux state (FIFO open's
/// pre-allocated client slot, INET FIFO chain successor promotion,
/// SOCKET unix peer name vnode), and SPLICES the op out of any chain
/// it was on so subsequent `pending_ops::cancel_for_badge` /
/// `drain_cancelled` ship the disposition reply cleanly.
///
/// The reply slot itself is NOT released here — `drain_cancelled`
/// owns that based on the cancel disposition recorded by
/// `cancel_for_badge`.
pub(crate) unsafe fn cancel_waiters_for_badge(state: &mut VfsState, badge: u64) {
    if badge == 0 {
        return;
    }
    unsafe {
        // FIFO_OPEN: the pre-allocated client slot must be released
        // before the op is freed.
        let mut fifo_targets =
            [(PendingOpId::NONE, ClientHandle::INVALID, 0usize); pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_FIFO_OPEN, |op_id, op| {
            if op.badge != badge {
                return;
            }
            if count < fifo_targets.len() {
                let cli = pending_ops::unpack_client_handle(op.client_handle_raw);
                let fd = op.scratch[FIFO_FD] as usize;
                fifo_targets[count] = (op_id, cli, fd);
                count += 1;
            }
        });
        for i in 0..count {
            let (_op_id, cli, fd) = fifo_targets[i];
            let _ = state.release_client_slot(cli, fd);
        }

        // TTY/PIPE chain splice: cancelled ops must be removed from
        // their per-key chain so successors keep walking the list
        // without dangling references.
        let mut tty_targets = [(PendingOpId::NONE, 0u64); pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_TTY_WAIT, |op_id, op| {
            if op.badge != badge {
                return;
            }
            if count < tty_targets.len() {
                tty_targets[count] = (op_id, op.scratch[TTY_KEY]);
                count += 1;
            }
        });
        for i in 0..count {
            let (op_id, key) = tty_targets[i];
            splice_from_chain(PO_KIND_TTY_WAIT, op_id, |op| op.scratch[TTY_KEY] == key);
        }

        let mut pipe_targets = [(PendingOpId::NONE, 0u64); pending_ops::MAX_PENDING_OPS];
        let mut count = 0usize;
        pending_ops::for_each_active_kind(PO_KIND_PIPE_READ_WAIT, |op_id, op| {
            if op.badge != badge {
                return;
            }
            if count < pipe_targets.len() {
                pipe_targets[count] = (op_id, op.scratch[PIPE_PIPE_HANDLE]);
                count += 1;
            }
        });
        for i in 0..count {
            let (op_id, key) = pipe_targets[i];
            splice_from_chain(PO_KIND_PIPE_READ_WAIT, op_id, |op| {
                op.scratch[PIPE_PIPE_HANDLE] == key
            });
        }

        count = 0;
        pending_ops::for_each_active_kind(PO_KIND_PIPE_WRITE_WAIT, |op_id, op| {
            if op.badge != badge {
                return;
            }
            if count < pipe_targets.len() {
                pipe_targets[count] = (op_id, op.scratch[PIPE_PIPE_HANDLE]);
                count += 1;
            }
        });
        for i in 0..count {
            let (op_id, key) = pipe_targets[i];
            splice_from_chain(PO_KIND_PIPE_WRITE_WAIT, op_id, |op| {
                op.scratch[PIPE_PIPE_HANDLE] == key
            });
        }

        crate::fileops::socket_wait::cancel_unix_socket_waiters_for_badge(state, badge);
        crate::fileops::inet_wait::cancel_inet_waiters_for_badge(state, badge);
    }
}

// =================================================================
// Backend completion cascade hook for waiter PendingOps.
// =================================================================

pub(crate) unsafe fn complete_wait_op(
    _state: &mut VfsState,
    _completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    // No `PO_KIND_*_WAIT` op currently lands in the backend completion
    // ring. INET waits use netsrv's `NET_COMPLETE` callback path
    // (`handle_netsrv_completion`), not the backend RPC ring; the
    // other wait kinds are owner-mutation-driven via
    // `drive_*_waiters`. The `inet_wait::arm_wait_call` migration to
    // deferred dispatch will route INET wait completions through this
    // hook once landed.
    false
}
