// SPDX-License-Identifier: GPL-2.0-only
//
//! `INIT_RLIMIT` GET / SET sub-ops. Per-process soft / hard limits.
//! Limits are stored in the proc-table and consulted by every server
//! that needs to enforce them (mmsrv for RLIMIT_AS / RLIMIT_DATA, vfs
//! for RLIMIT_NOFILE, etc.).

use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::TRONA_OK;

use crate::supervisor::SupervisorState;
use crate::supervisor::proc_table::RLIMIT_KIND_COUNT;
use crate::wire::{RLIMIT_SUB_GET, RLIMIT_SUB_SET};

pub fn handle(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let sub = request.regs[0];
    let kind = request.regs[1] as usize;
    if kind >= RLIMIT_KIND_COUNT {
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
        RLIMIT_SUB_GET => {
            reply.label = TRONA_OK;
            reply.length = 2;
            reply.regs[0] = proc.rlimits.limits[kind].soft;
            reply.regs[1] = proc.rlimits.limits[kind].hard;
        }
        RLIMIT_SUB_SET => {
            let new_soft = request.regs[2];
            let new_hard = request.regs[3];
            // Hard limit can only ever go down (CAP_SYS_RESOURCE
            // doesn't exist yet — once euid==0 priv check is wired
            // through, root will be allowed to raise).
            if new_hard > proc.rlimits.limits[kind].hard {
                reply.label = trona_protocol::common::TRONA_PERMISSION_DENIED;
                return;
            }
            if new_soft > new_hard {
                reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
                return;
            }
            proc.rlimits.limits[kind].soft = new_soft;
            proc.rlimits.limits[kind].hard = new_hard;
            reply.label = TRONA_OK;
            reply.length = 0;
        }
        _ => reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64,
    }
}
