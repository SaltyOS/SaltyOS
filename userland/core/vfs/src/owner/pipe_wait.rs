// SPDX-License-Identifier: GPL-2.0-only
//! Pipe-backed readiness wait queues.
//!
//! Anonymous pipes, FIFOs, and future pipefs-backed endpoints share
//! the same `PipeState` ring. Readiness wakeups therefore live at
//! the owner layer rather than inside a POSIX personality module.

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::pipe::PipeState;
use crate::owner::VfsState;
use crate::owner::pending::PendingOpHandle;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PipeWaitKind {
    Read = 0,
    Write = 1,
}

pub(crate) fn enqueue(
    state: &mut VfsState,
    pipe_h: Handle<PipeState>,
    op_h: PendingOpHandle,
    kind: PipeWaitKind,
) -> Result<(), VfsError> {
    let waiter_h = state.poll_waiters.alloc().ok_or(VfsError::NoMem)?;
    if let Some(w) = state.poll_waiters.get_mut(waiter_h) {
        w.target_op = op_h;
        w.kind_byte = kind as u8;
        w.next = u32::MAX;
    }
    let prev_head = state
        .pipes
        .get(pipe_h)
        .map(|p| p.readiness_wait_head)
        .unwrap_or(u32::MAX);
    if let Some(w) = state.poll_waiters.get_mut(waiter_h) {
        w.next = prev_head;
    }
    if let Some(p) = state.pipes.get_mut(pipe_h) {
        p.readiness_wait_head = waiter_h.slot();
    }
    Ok(())
}

pub(crate) fn wake_matching(
    state: &mut VfsState,
    pipe_h: Handle<PipeState>,
    wake_kind: PipeWaitKind,
) -> u32 {
    let mut woken = 0u32;
    let mut prev_idx: Option<u32> = None;
    let mut cur_idx = state
        .pipes
        .get(pipe_h)
        .map(|p| p.readiness_wait_head)
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
                    if let Some(p) = state.pipes.get_mut(pipe_h) {
                        p.readiness_wait_head = next;
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

pub(crate) fn drain_all(state: &mut VfsState, pipe_h: Handle<PipeState>) -> u32 {
    let mut woken = 0u32;
    let mut cur_idx = state
        .pipes
        .get(pipe_h)
        .map(|p| p.readiness_wait_head)
        .unwrap_or(u32::MAX);
    if let Some(p) = state.pipes.get_mut(pipe_h) {
        p.readiness_wait_head = u32::MAX;
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
