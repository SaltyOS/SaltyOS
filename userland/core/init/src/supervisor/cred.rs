// SPDX-License-Identifier: GPL-2.0-only
//
//! `INIT_CRED` sub-op handler. POSIX wrappers send a sub-op id in
//! `regs[0]`, plus arg payload in `regs[1..]`. We mutate the caller's
//! `CredFields` in the proc-table and reply with the new value (or
//! the queried value).

use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::TRONA_OK;

use crate::supervisor::SupervisorState;
use crate::supervisor::proc_table::{CredFields, MAX_GROUPS};
use crate::wire::{
    CRED_SUB_GETEGID, CRED_SUB_GETEUID, CRED_SUB_GETGID, CRED_SUB_GETGROUPS, CRED_SUB_GETRESGID,
    CRED_SUB_GETRESUID, CRED_SUB_GETUID, CRED_SUB_SETEGID, CRED_SUB_SETEUID, CRED_SUB_SETGID,
    CRED_SUB_SETGROUPS, CRED_SUB_SETREGID, CRED_SUB_SETRESGID, CRED_SUB_SETRESUID,
    CRED_SUB_SETREUID, CRED_SUB_SETUID, CRED_SUB_UMASK,
};

pub fn handle(
    state: &mut SupervisorState,
    request: &TronaMsg,
    caller_pid: u32,
    reply: &mut TronaMsg,
) {
    let sub_op = request.regs[0];
    let proc = match state.procs.get_mut(caller_pid) {
        Some(p) => p,
        None => {
            reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
            return;
        }
    };

    match sub_op {
        CRED_SUB_GETUID => emit(reply, proc.cred.uid as u64),
        CRED_SUB_GETGID => emit(reply, proc.cred.gid as u64),
        CRED_SUB_GETEUID => emit(reply, proc.cred.euid as u64),
        CRED_SUB_GETEGID => emit(reply, proc.cred.egid as u64),
        CRED_SUB_GETRESUID => {
            reply.label = TRONA_OK;
            reply.length = 3;
            reply.regs[0] = proc.cred.uid as u64;
            reply.regs[1] = proc.cred.euid as u64;
            reply.regs[2] = proc.cred.suid as u64;
        }
        CRED_SUB_GETRESGID => {
            reply.label = TRONA_OK;
            reply.length = 3;
            reply.regs[0] = proc.cred.gid as u64;
            reply.regs[1] = proc.cred.egid as u64;
            reply.regs[2] = proc.cred.sgid as u64;
        }
        CRED_SUB_SETUID => {
            let new_uid = request.regs[1] as u32;
            if !privileged_or_match(&proc.cred, new_uid) {
                reply.label = trona_protocol::common::TRONA_PERMISSION_DENIED;
                return;
            }
            proc.cred.uid = new_uid;
            proc.cred.euid = new_uid;
            proc.cred.suid = new_uid;
            emit(reply, 0);
        }
        CRED_SUB_SETGID => {
            let new_gid = request.regs[1] as u32;
            proc.cred.gid = new_gid;
            proc.cred.egid = new_gid;
            proc.cred.sgid = new_gid;
            emit(reply, 0);
        }
        CRED_SUB_SETEUID => {
            proc.cred.euid = request.regs[1] as u32;
            emit(reply, 0);
        }
        CRED_SUB_SETEGID => {
            proc.cred.egid = request.regs[1] as u32;
            emit(reply, 0);
        }
        CRED_SUB_SETREUID => {
            proc.cred.uid = request.regs[1] as u32;
            proc.cred.euid = request.regs[2] as u32;
            emit(reply, 0);
        }
        CRED_SUB_SETREGID => {
            proc.cred.gid = request.regs[1] as u32;
            proc.cred.egid = request.regs[2] as u32;
            emit(reply, 0);
        }
        CRED_SUB_SETRESUID => {
            proc.cred.uid = request.regs[1] as u32;
            proc.cred.euid = request.regs[2] as u32;
            proc.cred.suid = request.regs[3] as u32;
            emit(reply, 0);
        }
        CRED_SUB_SETRESGID => {
            proc.cred.gid = request.regs[1] as u32;
            proc.cred.egid = request.regs[2] as u32;
            proc.cred.sgid = request.regs[3] as u32;
            emit(reply, 0);
        }
        CRED_SUB_GETGROUPS => {
            reply.label = TRONA_OK;
            reply.length = 1 + proc.cred.groups_len as u64;
            reply.regs[0] = proc.cred.groups_len as u64;
            for i in 0..proc.cred.groups_len as usize {
                reply.regs[1 + i] = proc.cred.groups[i] as u64;
            }
        }
        CRED_SUB_SETGROUPS => {
            let n = (request.regs[1] as usize).min(MAX_GROUPS);
            proc.cred.groups_len = n as u8;
            for i in 0..n {
                proc.cred.groups[i] = request.regs[2 + i] as u32;
            }
            emit(reply, 0);
        }
        CRED_SUB_UMASK => {
            let prev = proc.cred.umask;
            proc.cred.umask = request.regs[1] as u32;
            emit(reply, prev as u64);
        }
        _ => {
            reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64;
        }
    }
}

fn emit(reply: &mut TronaMsg, value: u64) {
    reply.label = TRONA_OK;
    reply.length = 1;
    reply.regs[0] = value;
}

fn privileged_or_match(cred: &CredFields, target_uid: u32) -> bool {
    cred.euid == 0 || cred.uid == target_uid || cred.suid == target_uid
}
