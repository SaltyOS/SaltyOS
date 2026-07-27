// SPDX-License-Identifier: GPL-2.0-only
//
//! Wait-queue helpers for UNIX-domain socket blocking operations.
//!
//! `accept(2)` on a listening UNIX socket parks the caller until a
//! peer `connect(2)` arrives; `recv(2)` parks until either a peer
//! `send` or a `shutdown(SHUT_WR)` advances the receive ring;
//! `connect(2)` parks the connecting side until the listener
//! removes its entry from the backlog.
//!
//! The queue is a singly-linked list anchored on the socket's
//! [`SocketState::wait_queue`]; each waiter is a [`PendingOpHandle`]
//! paired with a small typed `kind` discriminator so the wakeup helper
//! can resume the right `Resume` arm.

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::socket::SocketState;
use crate::owner::VfsState;
use crate::owner::pending::PendingOpHandle;

/// What the parked op is waiting for. The wakeup driver inspects
/// this to decide whether a given queue advance applies (e.g.,
/// a `recv` waiter does not wake when an `accept` becomes ready).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketWaitKind {
    Accept = 0,
    Recv = 1,
    Send = 2,
    Connect = 3,
}

/// Push a parked op onto the socket's wait queue. The op itself
/// must already be in `Running` state with a `Resume::*` payload
/// stamped — the queue carries only the handle.
pub(crate) fn enqueue(
    state: &mut VfsState,
    sock_h: Handle<SocketState>,
    op_h: PendingOpHandle,
    kind: SocketWaitKind,
) -> Result<(), VfsError> {
    let waiter_h = state.poll_waiters.alloc().ok_or(VfsError::NoMem)?;

    if let Some(w) = state.poll_waiters.get_mut(waiter_h) {
        w.target_op = op_h;
        w.kind_byte = kind as u8;
        w.next = u32::MAX;
    }

    if let Some(sock) = state.sockets.get_mut(sock_h) {
        let prev_head = sock.wait_queue.head;
        if let Some(w) = state.poll_waiters.get_mut(waiter_h) {
            w.next = prev_head;
        }
        if let Some(sock) = state.sockets.get_mut(sock_h) {
            sock.wait_queue.head = waiter_h.slot();
        }
    }

    Ok(())
}

/// Wake every waiter on the socket's queue whose `kind` matches
/// `wake_kind`. The driver invokes this from `connect` (waking
/// `Accept`), from `send` (waking `Recv`), from `recv` (waking
/// `Send`), and from `accept` (waking `Connect`). Returns the
/// number of waiters actually woken.
pub(crate) fn wake_matching(
    state: &mut VfsState,
    sock_h: Handle<SocketState>,
    wake_kind: SocketWaitKind,
) -> u32 {
    let mut woken = 0u32;
    let mut prev_idx: Option<u32> = None;
    let mut cur_idx = state
        .sockets
        .get(sock_h)
        .map(|s| s.wait_queue.head)
        .unwrap_or(u32::MAX);

    while cur_idx != u32::MAX {
        let waiter_h = match state.poll_waiters.handle_from_slot(cur_idx) {
            Some(h) => h,
            None => break,
        };
        let (this_kind, next_idx, target_op) = match state.poll_waiters.get(waiter_h) {
            Some(p) => (p.kind_byte, p.next, p.target_op),
            None => break,
        };
        let next = next_idx;
        if this_kind == wake_kind as u8 {
            // Splice this entry out of the chain.
            match prev_idx {
                Some(p_idx) => {
                    if let Some(prev_h) = state.poll_waiters.handle_from_slot(p_idx) {
                        if let Some(p) = state.poll_waiters.get_mut(prev_h) {
                            p.next = next;
                        }
                    }
                }
                None => {
                    if let Some(sock) = state.sockets.get_mut(sock_h) {
                        sock.wait_queue.head = next;
                    }
                }
            }
            crate::personality::posix::poll::complete_waiter(state, target_op, None);
            state.poll_waiters.release(waiter_h);
            woken += 1;
            cur_idx = next;
        } else {
            prev_idx = Some(cur_idx);
            cur_idx = next;
        }
    }
    woken
}

/// Drain every waiter regardless of kind — used at socket close /
/// peer-shutdown so blocked callers receive an `EBADF`-class wake
/// rather than hanging forever. Each waiter's PendingOp is
/// surfaced as `SessionTornDown`.
pub(crate) fn drain_all(state: &mut VfsState, sock_h: Handle<SocketState>) -> u32 {
    let mut woken = 0u32;
    let mut cur_idx = state
        .sockets
        .get(sock_h)
        .map(|s| s.wait_queue.head)
        .unwrap_or(u32::MAX);

    if let Some(sock) = state.sockets.get_mut(sock_h) {
        sock.wait_queue.head = u32::MAX;
    }

    while cur_idx != u32::MAX {
        let waiter_h = match state.poll_waiters.handle_from_slot(cur_idx) {
            Some(h) => h,
            None => break,
        };
        let (next_idx, target_op) = match state.poll_waiters.get(waiter_h) {
            Some(p) => (p.next, p.target_op),
            None => break,
        };
        crate::personality::posix::poll::complete_waiter(
            state,
            target_op,
            Some(VfsError::SessionTornDown),
        );
        state.poll_waiters.release(waiter_h);
        woken += 1;
        cur_idx = next_idx;
    }
    woken
}
