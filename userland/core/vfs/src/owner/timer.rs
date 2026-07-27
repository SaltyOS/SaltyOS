// SPDX-License-Identifier: GPL-2.0-only
//
//! Owner-local kernel Timer plumbing.
//!
//! The owner reactor already fans frontend, backend-session, and
//! pager events through one EventQueue. Finite `poll(2)` waits need
//! the same lost-wakeup-free path: the first timed wait lazily
//! retypes an `OBJ_TIMER`, arms it against `owner_eq`, and timer
//! records complete any expired parked poll ops from the owner
//! thread.

use trona_kernel::core_types::Cap;
use trona_runtime::core::slot_alloc::OwnedCap;

use crate::core::error::VfsError;
use crate::ipc::cookie::{KIND_TIMER, encode_cookie};
use crate::owner::VfsState;
use crate::owner::op::{OpKind, OpState};
use crate::owner::pending::PendingOpHandle;

const TIMER_SLOT: u32 = 0;
const TIMER_EPOCH: u32 = 1;

#[inline]
pub(crate) const fn owner_timer_cookie() -> u64 {
    encode_cookie(KIND_TIMER, TIMER_SLOT, TIMER_EPOCH)
}

#[inline]
pub(crate) fn monotonic_now_ns() -> u64 {
    let clock = trona_runtime::client::caps::clock_cap().addr();
    if clock == 0 {
        0
    } else {
        trona_kernel::syscall::clock_read_monotonic(clock)
    }
}

fn ensure_owner_timer(state: &mut VfsState) -> Result<Cap, VfsError> {
    if state.owner_timer_cap.as_raw() != 0 {
        return Ok(state.owner_timer_cap.as_raw());
    }
    match trona_runtime::core::slot_alloc::alloc_object(uapi::KERNITE_OBJ_TIMER as u64, 0) {
        Ok(cap) => {
            // SAFETY: `cap` is the fresh Timer cap from alloc_object, solely owned
            // by state.owner_timer_cap; the returned raw is a borrow of the same
            // slot for the immediate arm.
            state.owner_timer_cap = unsafe { OwnedCap::adopt_received(cap) };
            Ok(cap)
        }
        Err(_) => Err(VfsError::NoMem),
    }
}

fn arm_owner_timer(state: &mut VfsState, deadline_ns: u64) -> Result<(), VfsError> {
    let timer = ensure_owner_timer(state)?;
    let r = trona_kernel::syscall::invoke(
        timer,
        uapi::KERNITE_INV_TIMER_SET as u64,
        deadline_ns,
        0,
        state.owner_eq.as_raw(),
        owner_timer_cookie(),
    );
    if r.error != 0 {
        return Err(VfsError::Io);
    }
    state.owner_timer_deadline_ns = deadline_ns;
    Ok(())
}

fn cancel_owner_timer(state: &mut VfsState) {
    if state.owner_timer_cap.as_raw() != 0 {
        let _ = trona_kernel::syscall::invoke(
            state.owner_timer_cap.as_raw(),
            uapi::KERNITE_INV_TIMER_CANCEL as u64,
            0,
            0,
            0,
            0,
        );
    }
    state.owner_timer_deadline_ns = 0;
}

pub(crate) fn rearm_poll_timer(state: &mut VfsState) -> Result<(), VfsError> {
    let mut nearest = u64::MAX;
    state.pending_ops.for_each_active(|_, op| {
        if op.core.kind == OpKind::Poll
            && !op.core.cancelled
            && matches!(op.core.state, OpState::Queued | OpState::Running)
            && op.deadline_ns != 0
            && op.deadline_ns < nearest
        {
            nearest = op.deadline_ns;
        }
        true
    });

    if nearest == u64::MAX {
        if state.owner_timer_deadline_ns != 0 {
            cancel_owner_timer(state);
        }
        return Ok(());
    }

    if state.owner_timer_deadline_ns == nearest {
        return Ok(());
    }
    arm_owner_timer(state, nearest)
}

pub(crate) fn handle_owner_timer(state: &mut VfsState, cookie: u64) {
    if cookie != owner_timer_cookie() {
        return;
    }

    let now = monotonic_now_ns();
    if now == 0 {
        let _ = rearm_poll_timer(state);
        return;
    }

    loop {
        let mut expired = PendingOpHandle::INVALID;
        state.pending_ops.for_each_active(|h, op| {
            if op.core.kind == OpKind::Poll
                && !op.core.cancelled
                && matches!(op.core.state, OpState::Queued | OpState::Running)
                && op.deadline_ns != 0
                && op.deadline_ns <= now
            {
                expired = h;
                return false;
            }
            true
        });

        if !expired.is_valid() {
            break;
        }
        crate::personality::posix::poll::complete_waiter(state, expired, None);
    }

    let _ = rearm_poll_timer(state);
}
