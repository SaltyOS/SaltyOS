//! Process group, session, and UID/GID handlers
//! Moved from crate root module for POSIX subsystem separation.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::*;

use crate::proc_table::{find_by_badge, find_by_pid, proctab, PROC_ZOMBIE};

pub(crate) unsafe fn handle_setpgid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;
        let mut pgid = msg.regs[1] as u32;

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };
        let caller_pid = proctab(caller_idx).pid;
        let caller_sid = proctab(caller_idx).posix().sid;

        // pid=0 means self
        if target_pid == 0 {
            target_pid = caller_pid;
        }
        // pgid=0 means pgid=pid
        if pgid == 0 {
            pgid = target_pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        if target_pid != caller_pid && proctab(ti).ppid != caller_pid {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }

        if proctab(ti).posix().sid != caller_sid {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }

        if proctab(ti).pid == proctab(ti).posix().sid {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }

        // Idempotent: target already in the requested group
        if proctab(ti).posix().pgid == pgid {
            reply.label = crate::TRONA_OK;
            reply.length = 0;
            return;
        }

        // POSIX: the target process group must already exist in the caller's session.
        // A group exists as long as any non-FREE process has that pgid -- we can't
        // rely on find_by_pid(pgid) because the group leader may have already exited.
        if pgid != target_pid {
            let target_sid = proctab(ti).posix().sid;
            let mut pg_exists = false;
            for i in 0..crate::proc_table::proctab_cap() {
                let p = proctab(i);
                if p.state != crate::proc_table::PROC_FREE
                    && p.posix().pgid == pgid
                    && p.posix().sid == target_sid
                {
                    pg_exists = true;
                    break;
                }
            }
            if !pg_exists {
                reply.label = crate::TRONA_NOT_FOUND;
                return;
            }
        }

        proctab(ti).posix_mut().pgid = pgid;
        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_getpgid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;

        if target_pid == 0 {
            let Some(caller_idx) = find_by_badge(badge) else {
                reply.label = crate::TRONA_NOT_FOUND;
                return;
            };
            target_pid = proctab(caller_idx).pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).posix().pgid as u64;
    }
}

pub(crate) unsafe fn handle_setsid(reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let Some(idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };
        let pid = proctab(idx).pid;
        if proctab(idx).posix().pgid == pid {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }
        proctab(idx).posix_mut().sid = pid;
        proctab(idx).posix_mut().pgid = pid;
        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = pid as u64;
    }
}

pub(crate) unsafe fn handle_getsid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;

        if target_pid == 0 {
            let Some(caller_idx) = find_by_badge(badge) else {
                reply.label = crate::TRONA_NOT_FOUND;
                return;
            };
            target_pid = proctab(caller_idx).pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).posix().sid as u64;
    }
}

pub(crate) unsafe fn handle_getpgid_badge(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        // Zombies are effectively dead -- don't report their pgid
        if proctab(ti).state == PROC_ZOMBIE {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        }

        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).posix().pgid as u64;
    }
}

pub(crate) unsafe fn handle_getsid_badge(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).posix().sid as u64;
    }
}

pub(crate) unsafe fn handle_getuid(reply: &mut TronaMsg, _badge: u64) {
    reply.label = crate::TRONA_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_geteuid(reply: &mut TronaMsg, _badge: u64) {
    reply.label = crate::TRONA_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_getgid(reply: &mut TronaMsg, _badge: u64) {
    reply.label = crate::TRONA_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_getegid(reply: &mut TronaMsg, _badge: u64) {
    reply.label = crate::TRONA_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_getgroups(reply: &mut TronaMsg) {
    reply.label = crate::TRONA_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}
