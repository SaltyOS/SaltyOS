//! Process group, session, and UID/GID handlers
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

use besalt::types::*;

use crate::proc_table::{find_by_badge, find_by_pid, proctab, PROC_ZOMBIE};

pub(crate) unsafe fn handle_setpgid(msg: &BesaltMsg, reply: &mut BesaltMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;
        let mut pgid = msg.regs[1] as u32;

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = super::BESALT_NOT_FOUND;
            return;
        };
        let caller_pid = proctab(caller_idx).pid;
        let caller_sid = proctab(caller_idx).sid;

        // pid=0 means self
        if target_pid == 0 {
            target_pid = caller_pid;
        }
        // pgid=0 means pgid=pid
        if pgid == 0 {
            pgid = target_pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = super::BESALT_NOT_FOUND;
            return;
        };

        if target_pid != caller_pid && proctab(ti).ppid != caller_pid {
            reply.label = super::BESALT_INVALID_OPERATION;
            return;
        }

        if proctab(ti).sid != caller_sid {
            reply.label = super::BESALT_INVALID_OPERATION;
            return;
        }

        if proctab(ti).pid == proctab(ti).sid {
            reply.label = super::BESALT_INVALID_OPERATION;
            return;
        }

        // Idempotent: target already in the requested group
        if proctab(ti).pgid == pgid {
            reply.label = super::BESALT_OK;
            reply.length = 0;
            return;
        }

        // POSIX: the target process group must already exist in the caller's session.
        // A group exists as long as any non-FREE process has that pgid -- we can't
        // rely on find_by_pid(pgid) because the group leader may have already exited.
        if pgid != target_pid {
            let target_sid = proctab(ti).sid;
            let mut pg_exists = false;
            for i in 0..crate::proc_table::proctab_cap() {
                let p = proctab(i);
                if p.state != crate::proc_table::PROC_FREE
                    && p.pgid == pgid
                    && p.sid == target_sid
                {
                    pg_exists = true;
                    break;
                }
            }
            if !pg_exists {
                reply.label = super::BESALT_NOT_FOUND;
                return;
            }
        }

        proctab(ti).pgid = pgid;
        reply.label = super::BESALT_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_getpgid(msg: &BesaltMsg, reply: &mut BesaltMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;

        if target_pid == 0 {
            let Some(caller_idx) = find_by_badge(badge) else {
                reply.label = super::BESALT_NOT_FOUND;
                return;
            };
            target_pid = proctab(caller_idx).pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = super::BESALT_NOT_FOUND;
            return;
        };

        reply.label = super::BESALT_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).pgid as u64;
    }
}

pub(crate) unsafe fn handle_setsid(reply: &mut BesaltMsg, badge: u64) {
    unsafe {
        let Some(idx) = find_by_badge(badge) else {
            reply.label = super::BESALT_NOT_FOUND;
            return;
        };
        let pid = proctab(idx).pid;
        if proctab(idx).pgid == pid {
            reply.label = super::BESALT_INVALID_OPERATION;
            return;
        }
        proctab(idx).sid = pid;
        proctab(idx).pgid = pid;
        reply.label = super::BESALT_OK;
        reply.length = 1;
        reply.regs[0] = pid as u64;
    }
}

pub(crate) unsafe fn handle_getsid(msg: &BesaltMsg, reply: &mut BesaltMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;

        if target_pid == 0 {
            let Some(caller_idx) = find_by_badge(badge) else {
                reply.label = super::BESALT_NOT_FOUND;
                return;
            };
            target_pid = proctab(caller_idx).pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = super::BESALT_NOT_FOUND;
            return;
        };

        reply.label = super::BESALT_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).sid as u64;
    }
}

pub(crate) unsafe fn handle_getpgid_badge(msg: &BesaltMsg, reply: &mut BesaltMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = super::BESALT_NOT_FOUND;
            return;
        };

        // Zombies are effectively dead -- don't report their pgid
        if proctab(ti).state == PROC_ZOMBIE {
            reply.label = super::BESALT_NOT_FOUND;
            return;
        }

        reply.label = super::BESALT_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).pgid as u64;
    }
}

pub(crate) unsafe fn handle_getsid_badge(msg: &BesaltMsg, reply: &mut BesaltMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = super::BESALT_NOT_FOUND;
            return;
        };

        reply.label = super::BESALT_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).sid as u64;
    }
}

pub(crate) unsafe fn handle_getuid(reply: &mut BesaltMsg, _badge: u64) {
    reply.label = super::BESALT_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_geteuid(reply: &mut BesaltMsg, _badge: u64) {
    reply.label = super::BESALT_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_getgid(reply: &mut BesaltMsg, _badge: u64) {
    reply.label = super::BESALT_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_getegid(reply: &mut BesaltMsg, _badge: u64) {
    reply.label = super::BESALT_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_getgroups(reply: &mut BesaltMsg) {
    reply.label = super::BESALT_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}
