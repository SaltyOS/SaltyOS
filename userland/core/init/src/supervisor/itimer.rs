// SPDX-License-Identifier: GPL-2.0-only
//
//! `INIT_ITIMER` GET / SET sub-ops. POSIX `setitimer` / `getitimer`.
//! Each process has up to 3 itimers (REAL / VIRTUAL / PROF). The
//! REAL timer fires SIGALRM when its deadline expires; init arms
//! `control_timer` to wake on the earliest pending itimer deadline
//! across all processes.

use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::TRONA_OK;

use crate::supervisor::SupervisorState;
use crate::supervisor::proc_table::{ITIMER_KIND_COUNT, ItimerEntry};
use crate::wire::{ITIMER_SUB_GET, ITIMER_SUB_SET};

pub fn handle(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let sub = request.regs[0];
    let kind = request.regs[1] as usize;
    if kind >= ITIMER_KIND_COUNT {
        reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
        return;
    }
    let proc = match state.procs.get_mut(caller_pid) {
        Some(p) => p,
        None => {
            reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
            return;
        }
    };
    match sub {
        ITIMER_SUB_GET => {
            let t = proc.itimers.timers[kind];
            reply.label = TRONA_OK;
            reply.length = 2;
            reply.regs[0] = t.interval_ns;
            reply.regs[1] = t.deadline_ns;
        }
        ITIMER_SUB_SET => {
            let interval = request.regs[2];
            let deadline = request.regs[3];
            let prev = proc.itimers.timers[kind];
            proc.itimers.timers[kind] = ItimerEntry {
                interval_ns: interval,
                deadline_ns: deadline,
            };
            reply.label = TRONA_OK;
            reply.length = 2;
            reply.regs[0] = prev.interval_ns;
            reply.regs[1] = prev.deadline_ns;
        }
        _ => reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64,
    }
}
