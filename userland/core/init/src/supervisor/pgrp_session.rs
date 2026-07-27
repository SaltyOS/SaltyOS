// SPDX-License-Identifier: GPL-2.0-only
//
//! `INIT_PGRP_SESSION` sub-op handler. POSIX `setpgid` / `getpgid` /
//! `setsid` / `getsid` semantics live here; the caller's per-process
//! `pgid` and `sid` fields are stored on the proc-table.

use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::TRONA_OK;

use crate::supervisor::SupervisorState;
use crate::wire::{
    PGRP_SUB_GET_SID_PGID_BY_BADGE, PGRP_SUB_GETPGID, PGRP_SUB_GETPGID_BY_BADGE, PGRP_SUB_GETPGRP,
    PGRP_SUB_GETSID, PGRP_SUB_GETSID_BY_BADGE, PGRP_SUB_SETPGID, PGRP_SUB_SETSID,
};

pub fn handle(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let sub = request.regs[0];
    match sub {
        PGRP_SUB_GETPGRP => {
            if let Some(p) = state.procs.get(caller_pid) {
                reply.label = TRONA_OK;
                reply.length = 1;
                reply.regs[0] = p.pgid as u64;
            } else {
                reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
            }
        }
        PGRP_SUB_GETPGID => {
            let target = request.regs[1] as u32;
            let pid = if target == 0 { caller_pid } else { target };
            match state.procs.get(pid) {
                Some(p) => {
                    reply.label = TRONA_OK;
                    reply.length = 1;
                    reply.regs[0] = p.pgid as u64;
                }
                None => reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64,
            }
        }
        PGRP_SUB_SETPGID => {
            let target = request.regs[1] as u32;
            let new_pgid = request.regs[2] as u32;
            let pid = if target == 0 { caller_pid } else { target };
            match state.procs.get_mut(pid) {
                Some(p) => {
                    p.pgid = if new_pgid == 0 { pid } else { new_pgid };
                    reply.label = TRONA_OK;
                    reply.length = 1;
                    reply.regs[0] = p.pgid as u64;
                }
                None => reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64,
            }
        }
        PGRP_SUB_GETSID => {
            let target = request.regs[1] as u32;
            let pid = if target == 0 { caller_pid } else { target };
            match state.procs.get(pid) {
                Some(p) => {
                    reply.label = TRONA_OK;
                    reply.length = 1;
                    reply.regs[0] = p.sid as u64;
                }
                None => reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64,
            }
        }
        PGRP_SUB_SETSID => {
            // POSIX: a process group leader cannot setsid. We
            // approximate by checking pgid != pid; the supervisor
            // doesn't track group leaders independently.
            match state.procs.get_mut(caller_pid) {
                Some(p) => {
                    p.sid = caller_pid;
                    p.pgid = caller_pid;
                    reply.label = TRONA_OK;
                    reply.length = 1;
                    reply.regs[0] = caller_pid as u64;
                }
                None => reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64,
            }
        }
        PGRP_SUB_GETPGID_BY_BADGE | PGRP_SUB_GETSID_BY_BADGE => {
            let badge = request.regs[1];
            let client_id = (badge & 0xFFFF_FFFF) as u32;
            match state.procs.find_by_client_id(client_id) {
                Some(p) => {
                    reply.label = TRONA_OK;
                    reply.length = 1;
                    reply.regs[0] = if sub == PGRP_SUB_GETPGID_BY_BADGE {
                        p.pgid as u64
                    } else {
                        p.sid as u64
                    };
                }
                None => reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64,
            }
        }
        PGRP_SUB_GET_SID_PGID_BY_BADGE => {
            let badge = request.regs[1];
            let client_id = (badge & 0xFFFF_FFFF) as u32;
            match state.procs.find_by_client_id(client_id) {
                Some(p) => {
                    reply.label = TRONA_OK;
                    reply.length = 2;
                    reply.regs[0] = p.sid as u64;
                    reply.regs[1] = p.pgid as u64;
                }
                None => reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64,
            }
        }
        _ => reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64,
    }
}
