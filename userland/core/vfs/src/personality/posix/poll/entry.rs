// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_POLL` — block until any fd in a caller-supplied set
//! transitions to a requested readiness state, or until the
//! caller-supplied timeout fires.
//!
//! ## Wire layout
//!
//! - `regs[0]` = `nfds` (count of `pollfd` entries inline below).
//! - `regs[1]` = `timeout_ns` (`0` = non-blocking, `u64::MAX` =
//!   infinite, otherwise an absolute monotonic-clock deadline).
//! - `regs[2..2 + 3 * nfds]` = three regs per pollfd: `fd`,
//!   `events_requested`, and (initially-zero) `revents`. The reply
//!   echoes the same triple back with `revents` populated.
//!
//! ## Algorithm
//!
//! 1. Walk every `pollfd`, query the underlying object's current
//!    readiness (local rings for pipe / UNIX socket, `NET_POLL_STATUS`
//!    for INET sockets), and compute a per-fd `revents` mask.
//! 2. If any fd already shows readiness (or the wait set is empty,
//!    or `timeout_ns == 0`) reply immediately.
//! 3. Otherwise allocate a [`PendingOpHandle`], stamp a
//!    `Resume::Poll` payload that records the parked fd set,
//!    and enqueue this op onto every fd's wait queue
//!    (UNIX-socket / PTY / pipe / INET — whichever applies). The
//!    matching wake-up driver completes the op directly through
//!    [`complete_waiter`], which re-runs the readiness query before
//!    replying.

use trona_kernel::core_types::TronaMsg;

use crate::arena::Arena;
use crate::core::error::VfsError;
use crate::core::identity::VnodeKey;
use crate::core::socket::SocketBacking;
use crate::owner::PollWaiter;
use crate::owner::VfsState;
use crate::owner::op::{OpKind, OpState};
use crate::owner::pending::{PendingOpHandle, alloc_pending};
use crate::owner::resume::{PollResume, Resume};
use crate::personality::posix::types::{POLLFD_INLINE_MAX, PollFd};
use crate::personality::wire::send_reply_err_for_client;
use crate::server::types::ClientHandle;

const POLLIN: u16 = 0x0001;
const POLLOUT: u16 = 0x0004;
const POLLERR: u16 = 0x0008;
const POLLHUP: u16 = 0x0010;
const POLLNVAL: u16 = 0x0020;

const POLLFD_REGS_PER_ENTRY: usize = 3;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let nfds = msg.regs[0] as usize;
        let timeout_ns = msg.regs[1];

        if nfds > POLLFD_INLINE_MAX {
            // Larger sets must use the bulk SHM region; inline path
            // tops out at ten poll entries because regs[0..1] hold
            // the header and each entry consumes three regs.
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }

        let mut entries: [PollFd; POLLFD_INLINE_MAX] = [PollFd::default(); POLLFD_INLINE_MAX];
        for i in 0..nfds {
            let base = 2 + i * POLLFD_REGS_PER_ENTRY;
            entries[i].fd = msg.regs[base] as i32;
            entries[i].events = msg.regs[base + 1] as i16;
            entries[i].revents = 0;
        }

        // First pass — compute current readiness on every fd. If
        // any fd already satisfies its mask, return immediately.
        let mut ready_count = 0u64;
        for i in 0..nfds {
            entries[i].revents =
                current_revents(state, client, entries[i].fd, entries[i].events as u16) as i16;
            if entries[i].revents != 0 {
                ready_count += 1;
            }
        }
        if ready_count > 0 || timeout_ns == 0 || nfds == 0 {
            emit_reply(reply_lease, &entries[..nfds], ready_count);
            return;
        }

        // Otherwise the caller wants to block. Park the reply
        // endpoint lease in a local PendingOp and enqueue that op on
        // every watched object's readiness queue. Finite deadlines are driven by
        // the owner reactor's kernel Timer; timeout completion
        // re-runs the readiness query and emits a successful
        // zero-ready reply when nothing became ready.
        // `timeout_ns` is a relative duration from the caller; convert to an
        // absolute monotonic deadline for the park timer. `u64::MAX` blocks
        // forever; the `timeout_ns == 0` nonblocking case already returned above.
        let deadline_ns = if timeout_ns == u64::MAX {
            u64::MAX
        } else {
            crate::owner::timer::monotonic_now_ns().saturating_add(timeout_ns)
        };
        match park_poll_wait(state, client, &entries, nfds, deadline_ns, reply_lease) {
            Ok(()) => {}
            Err((e, reply_lease)) => {
                send_reply_err_for_client(state, client, reply_lease, e);
            }
        }
    }
}

fn park_poll_wait(
    state: &mut VfsState,
    client: ClientHandle,
    entries: &[PollFd; POLLFD_INLINE_MAX],
    nfds: usize,
    deadline_ns: u64,
    reply_lease: trona_server::ReplyLease,
) -> Result<(), (VfsError, trona_server::ReplyLease)> {
    let client_id = state.clients.get(client).map(|c| c.client_id).unwrap_or(0);
    let client_badge = reply_lease.epoch();
    let Some(op_h) = alloc_pending(
        state,
        OpKind::Poll,
        client_id,
        client_badge,
        u32::MAX,
        0,
        VnodeKey::NONE,
    ) else {
        return Err((VfsError::NoMem, reply_lease));
    };
    let resume = Resume::Poll(PollResume {
        client,
        nfds: nfds as u8,
        entries: *entries,
    });
    if let Err(Some(reply_lease)) =
        state.stamp_resume_ctx(op_h, client_badge, Some(reply_lease), resume)
    {
        let _ = state.pending_ops.release(op_h);
        return Err((VfsError::Io, reply_lease));
    }
    if let Some(op) = state.pending_ops.get_mut(op_h) {
        op.core.state = OpState::Running;
        op.deadline_ns = if deadline_ns == u64::MAX {
            0
        } else {
            deadline_ns
        };
    }
    for entry in entries.iter().take(nfds) {
        if enqueue_poll_entry(state, client, op_h, *entry).is_err() {
            complete_waiter(state, op_h, Some(VfsError::NoMem));
            return Ok(());
        }
    }
    if deadline_ns != u64::MAX {
        if let Err(e) = crate::owner::timer::rearm_poll_timer(state) {
            complete_waiter(state, op_h, Some(e));
        }
    }
    Ok(())
}

fn enqueue_poll_entry(
    state: &mut VfsState,
    client: ClientHandle,
    op_h: PendingOpHandle,
    entry: PollFd,
) -> Result<(), VfsError> {
    if entry.fd < 0 {
        return Ok(());
    }
    let Some(cli) = state.clients.get(client) else {
        return Err(VfsError::BadF);
    };
    let Some(open_h) = cli.slot_table.lookup(entry.fd as u32) else {
        return Ok(());
    };
    let (obj_vnode, obj_kind, personality_aux) = match state.open_objects.get(open_h) {
        Some(o) => (o.vnode, o.kind, o.personality_aux),
        None => return Ok(()),
    };

    // Socket fds carry no vnode; classify by obj.kind so a blocking poll on a
    // socket enqueues the readiness waiter (via personality_aux) instead of
    // parking with no waiter and never waking. Mirrors current_revents.
    if obj_kind == crate::server::open_object::OpenObjectKind::Socket {
        if let Some(sock_h) = state.sockets.handle_from_slot(personality_aux) {
            let backing = state
                .sockets
                .get(sock_h)
                .map(|s| s.backing)
                .unwrap_or(SocketBacking::Unset);
            if backing == SocketBacking::Inet {
                if (entry.events as u16 & POLLIN) != 0 {
                    crate::personality::posix::inet_wait::enqueue(
                        state,
                        sock_h,
                        op_h,
                        crate::personality::posix::inet_wait::InetWaitKind::Readable,
                    )?;
                }
                if (entry.events as u16 & POLLOUT) != 0 {
                    crate::personality::posix::inet_wait::enqueue(
                        state,
                        sock_h,
                        op_h,
                        crate::personality::posix::inet_wait::InetWaitKind::Writable,
                    )?;
                }
            } else {
                if (entry.events as u16 & POLLIN) != 0 {
                    crate::personality::posix::socket_wait::enqueue(
                        state,
                        sock_h,
                        op_h,
                        crate::personality::posix::socket_wait::SocketWaitKind::Recv,
                    )?;
                }
                if (entry.events as u16 & POLLOUT) != 0 {
                    crate::personality::posix::socket_wait::enqueue(
                        state,
                        sock_h,
                        op_h,
                        crate::personality::posix::socket_wait::SocketWaitKind::Send,
                    )?;
                }
            }
        }
        return Ok(());
    }

    let kind = state
        .vnodes
        .get(obj_vnode)
        .map(|v| v.kind)
        .unwrap_or(crate::core::vnode::VnodeKind::Empty);
    match kind {
        crate::core::vnode::VnodeKind::Pipe | crate::core::vnode::VnodeKind::Fifo => {
            if let Some(pipe_h) = state.pipes.handle_from_slot(personality_aux) {
                if (entry.events as u16 & POLLIN) != 0 {
                    crate::owner::pipe_wait::enqueue(
                        state,
                        pipe_h,
                        op_h,
                        crate::owner::pipe_wait::PipeWaitKind::Read,
                    )?;
                }
                if (entry.events as u16 & POLLOUT) != 0 {
                    crate::owner::pipe_wait::enqueue(
                        state,
                        pipe_h,
                        op_h,
                        crate::owner::pipe_wait::PipeWaitKind::Write,
                    )?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn complete_waiter(
    state: &mut VfsState,
    op_h: PendingOpHandle,
    error: Option<VfsError>,
) {
    let (core, resume, parked) = match state.pending_ops.get_mut(op_h) {
        Some(op) => (op.core, op.resume, ::core::mem::take(&mut op.reply_lease)),
        None => return,
    };
    let Some(parked) = parked else {
        let _ = state.pending_ops.release(op_h);
        return;
    };
    let lease = parked.unpark();
    if let Some(err) = error {
        crate::personality::wire::send_reply_err_for_op(&core, lease, err);
        remove_waiters_for_op(state, op_h);
        let _ = state.pending_ops.release(op_h);
        let _ = crate::owner::timer::rearm_poll_timer(state);
        return;
    }
    let Resume::Poll(poll) = resume else {
        crate::personality::wire::send_reply_err_for_op(&core, lease, VfsError::Inval);
        remove_waiters_for_op(state, op_h);
        let _ = state.pending_ops.release(op_h);
        let _ = crate::owner::timer::rearm_poll_timer(state);
        return;
    };
    let mut entries = poll.entries;
    let nfds = usize::from(poll.nfds).min(entries.len());
    let mut ready_count = 0u64;
    for entry in entries.iter_mut().take(nfds) {
        entry.revents = current_revents(state, poll.client, entry.fd, entry.events as u16) as i16;
        if entry.revents != 0 {
            ready_count += 1;
        }
    }
    unsafe {
        emit_reply(lease, &entries[..nfds], ready_count);
    }
    remove_waiters_for_op(state, op_h);
    let _ = state.pending_ops.release(op_h);
    let _ = crate::owner::timer::rearm_poll_timer(state);
}

fn current_revents(state: &mut VfsState, client: ClientHandle, fd: i32, events: u16) -> u16 {
    if fd < 0 {
        // POSIX: negative fd silently treated as no-op (revents = 0).
        return 0;
    }
    let cli = match state.clients.get(client) {
        Some(c) => c,
        None => return POLLNVAL,
    };
    let oh = match cli.slot_table.lookup(fd as u32) {
        Some(h) => h,
        None => return POLLNVAL,
    };
    let (vnode_h, personality_aux, obj_kind) = match state.open_objects.get(oh) {
        Some(o) => (o.vnode, o.personality_aux, o.kind),
        None => return POLLNVAL,
    };

    // Socket fds carry no vnode (identified by OpenObjectKind::Socket, peer slot
    // in personality_aux); classify by obj.kind, not vnode.kind, so an empty
    // socket reports no readiness and a ready one reports POLLIN/POLLOUT.
    if obj_kind == crate::server::open_object::OpenObjectKind::Socket {
        return socket_revents(state, personality_aux, events);
    }

    let kind = state
        .vnodes
        .get(vnode_h)
        .map(|v| v.kind)
        .unwrap_or(crate::core::vnode::VnodeKind::Empty);
    let mut revents: u16 = 0;
    match kind {
        crate::core::vnode::VnodeKind::Pipe | crate::core::vnode::VnodeKind::Fifo => {
            // Pipes / FIFOs are readable when the buffer holds bytes,
            // writable when there is at least one byte of buffer
            // headroom. Pipe state lives at `obj.personality_aux`.
            if (events & POLLIN) != 0 && pipe_has_data(state, personality_aux) {
                revents |= POLLIN;
            }
            if (events & POLLOUT) != 0 && pipe_has_room(state, personality_aux) {
                revents |= POLLOUT;
            }
        }
        crate::core::vnode::VnodeKind::Socket => {
            revents |= socket_revents(state, personality_aux, events);
        }
        crate::core::vnode::VnodeKind::Regular | crate::core::vnode::VnodeKind::CharDev => {
            // Regular files and character devices are always
            // considered ready under POSIX.
            revents |= events & (POLLIN | POLLOUT);
        }
        _ => {}
    }
    revents
}

fn remove_waiters_for_op(state: &mut VfsState, target: PendingOpHandle) {
    {
        let waiters = &mut state.poll_waiters;
        state.pipes.for_each_active_mut(|_, pipe| {
            unlink_waiters_from_head(waiters, &mut pipe.readiness_wait_head, target);
            true
        });
    }
    {
        let waiters = &mut state.poll_waiters;
        state.sockets.for_each_active_mut(|_, sock| {
            unlink_waiters_from_head(waiters, &mut sock.wait_queue.head, target);
            unlink_waiters_from_head(waiters, &mut sock.inet_wait_queue.head, target);
            true
        });
    }
}

fn unlink_waiters_from_head(
    waiters: &mut Arena<PollWaiter>,
    head: &mut u32,
    target: PendingOpHandle,
) {
    let mut prev_idx: Option<u32> = None;
    let mut cur_idx = *head;
    while cur_idx != u32::MAX {
        let Some(waiter_h) = waiters.handle_from_slot(cur_idx) else {
            break;
        };
        let (next_idx, target_op) = match waiters.get(waiter_h) {
            Some(w) => (w.next, w.target_op),
            None => break,
        };
        if target_op == target {
            match prev_idx {
                Some(p_idx) => {
                    if let Some(prev_h) = waiters.handle_from_slot(p_idx) {
                        if let Some(prev) = waiters.get_mut(prev_h) {
                            prev.next = next_idx;
                        }
                    }
                }
                None => {
                    *head = next_idx;
                }
            }
            waiters.release(waiter_h);
            cur_idx = next_idx;
        } else {
            prev_idx = Some(cur_idx);
            cur_idx = next_idx;
        }
    }
}

fn pipe_has_data(state: &VfsState, slot: u32) -> bool {
    let Some(h) = state.pipes.handle_from_slot(slot) else {
        return false;
    };
    state
        .pipes
        .get(h)
        .map(|p| p.data_head != p.data_tail)
        .unwrap_or(false)
}

fn pipe_has_room(state: &VfsState, slot: u32) -> bool {
    let Some(h) = state.pipes.handle_from_slot(slot) else {
        return false;
    };
    state
        .pipes
        .get(h)
        .map(|p| {
            let head = usize::from(p.data_head);
            let tail = usize::from(p.data_tail);
            let used = if head >= tail {
                head - tail
            } else {
                crate::server::consts::PIPE_BUF_SIZE - tail + head
            };
            used < crate::server::consts::PIPE_BUF_SIZE.saturating_sub(1)
        })
        .unwrap_or(false)
}

fn socket_revents(state: &mut VfsState, slot: u32, events: u16) -> u16 {
    let Some(h) = state.sockets.handle_from_slot(slot) else {
        return 0;
    };
    let backing = state
        .sockets
        .get(h)
        .map(|s| s.backing)
        .unwrap_or(SocketBacking::Unset);
    if backing == SocketBacking::Inet {
        let conn_id = state.sockets.get(h).map(|s| s.conn_id).unwrap_or(u32::MAX);
        if conn_id == u32::MAX {
            return POLLNVAL;
        }
        return match crate::personality::posix::inet::poll_status(state, conn_id, events) {
            Ok(mask) => mask & (events | POLLERR | POLLHUP | POLLNVAL),
            Err(_) => POLLERR,
        };
    }
    let mut revents = 0u16;
    if (events & POLLIN) != 0 && socket_has_data(state, h) {
        revents |= POLLIN;
    }
    if (events & POLLOUT) != 0 && socket_has_room(state, h) {
        revents |= POLLOUT;
    }
    revents
}

fn socket_has_data(
    state: &VfsState,
    h: crate::arena::handle::Handle<crate::core::socket::SocketState>,
) -> bool {
    state
        .sockets
        .get(h)
        .map(|s| s.rx.head != s.rx.tail)
        .unwrap_or(false)
}

fn socket_has_room(
    state: &VfsState,
    h: crate::arena::handle::Handle<crate::core::socket::SocketState>,
) -> bool {
    let Some(sock) = state.sockets.get(h) else {
        return false;
    };
    if sock.is_unix() {
        let remote_h = match state.sockets.handle_from_slot(sock.remote) {
            Some(r) if r.epoch() == sock.remote_epoch => r,
            _ => return false,
        };
        return state
            .sockets
            .get(remote_h)
            .map(|remote| remote.rx.avail() != 0)
            .unwrap_or(false);
    }
    sock.tx.avail() != 0
}

unsafe fn emit_reply(reply_lease: trona_server::ReplyLease, entries: &[PollFd], ready_count: u64) {
    let mut out = TronaMsg::default();
    out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
    out.regs[0] = ready_count;
    out.regs[1] = entries.len() as u64;
    for (i, e) in entries.iter().enumerate() {
        let base = 2 + i * POLLFD_REGS_PER_ENTRY;
        out.regs[base] = e.fd as u32 as u64;
        out.regs[base + 1] = e.events as u16 as u64;
        out.regs[base + 2] = e.revents as u16 as u64;
    }
    out.length = (2 + entries.len() * POLLFD_REGS_PER_ENTRY) as u64;
    crate::owner::op::reply_send(reply_lease, &out);
}
