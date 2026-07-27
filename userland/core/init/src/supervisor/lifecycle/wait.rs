// SPDX-License-Identifier: GPL-2.0-only
//
//! `INIT_WAIT(target_pid, options, deadline_ns?)`
//! handler.
//!
//! `handle_wait` either resolves immediately (returning the reaped
//! child's pid + status), reports a nonblocking/deadline wait as
//! retryable, or parks the caller's request MessagePipe endpoint in
//! their `ProcessRecord`. When a parked child eventually transitions
//! to Zombie, [`crate::supervisor::lifecycle::exit::finalize_exit`]
//! resolves the parked wait via `reply-marked MP_WRITE`.

use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::TRONA_OK;
use trona_protocol::posix_abi::file::{WNOHANG, WUNTRACED};
use trona_server::MpReplyTarget;
use uapi::{
    KERNITE_ERR_ALREADY_EXISTS, KERNITE_ERR_INVALID_ARGUMENT, KERNITE_ERR_NOT_FOUND,
    KERNITE_ERR_TIMED_OUT, KERNITE_ERR_WOULD_BLOCK,
};

use crate::supervisor::SupervisorState;
use crate::supervisor::proc_table::ProcessState;

#[derive(Clone, Copy)]
pub enum WaitOutcome {
    Resolved,
    Parked,
}

pub fn encode_wait_status(status: i32) -> u64 {
    if status >= 0 {
        ((status as u64) & 0xff) << 8
    } else {
        ((-status) as u64) & 0x7f
    }
}

/// Handle `INIT_WAIT`. Returns `Resolved` if a Zombie child was
/// found and the caller's reply has been filled in; returns `Parked`
/// if the dispatcher-supplied reply endpoint has been stashed in the
/// caller's `ProcessRecord` and the dispatcher should not immediately
/// send a reply.
pub fn handle_wait(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply_target: MpReplyTarget,
    reply: &mut TronaMsg,
) -> WaitOutcome {
    let target = request.regs[0] as u32 as i32;
    let options = request.regs[1];
    let deadline_ns = if request.length >= 3 {
        request.regs[2]
    } else {
        0
    };

    let reaped = if target == -1 {
        state
            .procs
            .find_zombie_for_parent_mut(caller_pid)
            .map(|zombie| {
                let pid = zombie.pid;
                let status = zombie.exit_status;
                zombie.state = ProcessState::Reaped;
                (pid, status)
            })
    } else if target > 0 {
        let pid = target as u32;
        state
            .procs
            .get_mut(pid)
            .filter(|p| p.parent_pid == caller_pid && p.state == ProcessState::Zombie)
            .map(|zombie| {
                let pid = zombie.pid;
                let status = zombie.exit_status;
                zombie.state = ProcessState::Reaped;
                (pid, status)
            })
    } else {
        None
    };

    if let Some((pid, status)) = reaped {
        state.procs.release(pid);
        reply.label = TRONA_OK;
        reply.length = 2;
        reply.regs[0] = pid as u64;
        reply.regs[1] = encode_wait_status(status);
        return WaitOutcome::Resolved;
    }

    if (options & WUNTRACED) != 0 {
        let stopped = if target == -1 {
            state
                .procs
                .iter_mut_active()
                .find(|p| {
                    p.parent_pid == caller_pid
                        && p.state == ProcessState::Stopped
                        && !p.stop_reported
                })
                .map(|p| {
                    p.stop_reported = true;
                    (p.pid, p.stop_status)
                })
        } else if target > 0 {
            let pid = target as u32;
            state
                .procs
                .get_mut(pid)
                .filter(|p| {
                    p.parent_pid == caller_pid
                        && p.state == ProcessState::Stopped
                        && !p.stop_reported
                })
                .map(|p| {
                    p.stop_reported = true;
                    (p.pid, p.stop_status)
                })
        } else {
            None
        };
        if let Some((pid, status)) = stopped {
            reply.label = TRONA_OK;
            reply.length = 2;
            reply.regs[0] = pid as u64;
            reply.regs[1] = status as u64;
            return WaitOutcome::Resolved;
        }
    }

    let has_wait_target = if target == -1 {
        state
            .procs
            .iter_active()
            .any(|p| p.parent_pid == caller_pid)
    } else if target > 0 {
        let pid = target as u32;
        state
            .procs
            .get(pid)
            .is_some_and(|p| p.parent_pid == caller_pid)
    } else {
        false
    };
    if !has_wait_target {
        reply.label = KERNITE_ERR_NOT_FOUND as u64;
        return WaitOutcome::Resolved;
    }

    if (options & WNOHANG) != 0 {
        reply.label = KERNITE_ERR_WOULD_BLOCK as u64;
        return WaitOutcome::Resolved;
    }

    if deadline_ns != 0 {
        let now_ns = trona_kernel::syscall::clock_read_monotonic(
            trona_runtime::client::caps::clock_cap().addr(),
        );
        reply.label = if now_ns >= deadline_ns {
            KERNITE_ERR_TIMED_OUT as u64
        } else {
            KERNITE_ERR_WOULD_BLOCK as u64
        };
        return WaitOutcome::Resolved;
    }

    let Some(parent) = state.procs.get_mut(caller_pid) else {
        reply.label = KERNITE_ERR_INVALID_ARGUMENT as u64;
        return WaitOutcome::Resolved;
    };
    if !parent.waitpid_parked_reply.is_none() {
        reply.label = KERNITE_ERR_ALREADY_EXISTS as u64;
        return WaitOutcome::Resolved;
    }
    if reply_target.is_none() {
        reply.label = KERNITE_ERR_INVALID_ARGUMENT as u64;
        return WaitOutcome::Resolved;
    }
    parent.waitpid_parked_reply = reply_target;
    parent.waitpid_parked_target = target;
    WaitOutcome::Parked
}
