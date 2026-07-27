// SPDX-License-Identifier: GPL-2.0-only
//
//! Wait-queue helpers for INET socket operations driven through
//! `netsrv`.
//!
//! Unlike UNIX-domain sockets — where vfs owns both endpoints and
//! advances the queue inline — INET socket readiness is driven by
//! callbacks from netsrv. netsrv watches its own packet rings and
//! posts `NETSRV_*` notifications back to vfs's pager / netsrv
//! callback EP whenever a socket transitions to readable / writable
//! / error / hup. The driver translates each notification into a
//! [`wake_matching`] call against the matching socket's queue.
//!
//! Structure mirrors the UNIX-domain queue in
//! [`crate::personality::posix::socket_wait`] so a personality wrapper can
//! treat both with the same selector logic.

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::socket::SocketState;
use crate::owner::VfsState;
use crate::owner::pending::PendingOpHandle;

/// Wakeup kinds — distinct from the UNIX-domain queue's kinds even
/// though some labels coincide, because the netsrv callback wire
/// is independent of the UNIX-domain ring advance.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InetWaitKind {
    Readable = 0,
    Writable = 1,
    Accept = 2,
    Connect = 3,
    Error = 4,
    Hup = 5,
}

pub(crate) fn enqueue(
    state: &mut VfsState,
    sock_h: Handle<SocketState>,
    op_h: PendingOpHandle,
    kind: InetWaitKind,
) -> Result<(), VfsError> {
    let waiter_h = state.poll_waiters.alloc().ok_or(VfsError::NoMem)?;
    if let Some(w) = state.poll_waiters.get_mut(waiter_h) {
        w.target_op = op_h;
        w.kind_byte = kind as u8;
        w.next = u32::MAX;
    }
    let prev_head = state
        .sockets
        .get(sock_h)
        .map(|s| s.inet_wait_queue.head)
        .unwrap_or(u32::MAX);
    if let Some(w) = state.poll_waiters.get_mut(waiter_h) {
        w.next = prev_head;
    }
    if let Some(s) = state.sockets.get_mut(sock_h) {
        s.inet_wait_queue.head = waiter_h.slot();
    }
    Ok(())
}

pub(crate) fn wake_matching(
    state: &mut VfsState,
    sock_h: Handle<SocketState>,
    wake_kind: InetWaitKind,
) -> u32 {
    let mut woken = 0u32;
    let mut prev_idx: Option<u32> = None;
    let mut cur_idx = state
        .sockets
        .get(sock_h)
        .map(|s| s.inet_wait_queue.head)
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
            match prev_idx {
                Some(p_idx) => {
                    if let Some(prev_h) = state.poll_waiters.handle_from_slot(p_idx) {
                        if let Some(p) = state.poll_waiters.get_mut(prev_h) {
                            p.next = next;
                        }
                    }
                }
                None => {
                    if let Some(s) = state.sockets.get_mut(sock_h) {
                        s.inet_wait_queue.head = next;
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

pub(crate) fn drain_all(state: &mut VfsState, sock_h: Handle<SocketState>) -> u32 {
    let mut woken = 0u32;
    let mut cur_idx = state
        .sockets
        .get(sock_h)
        .map(|s| s.inet_wait_queue.head)
        .unwrap_or(u32::MAX);
    if let Some(s) = state.sockets.get_mut(sock_h) {
        s.inet_wait_queue.head = u32::MAX;
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
