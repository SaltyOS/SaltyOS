//! Process group, session, and UID/GID handlers
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

use salty::types::*;

use crate::proc_table::{find_by_badge, find_by_pid, proctab};

pub(crate) unsafe fn handle_setpgid(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;
        let mut pgid = msg.regs[1] as u32;

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = super::SALTY_NOT_FOUND;
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
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };

        if target_pid != caller_pid && proctab(ti).ppid != caller_pid {
            reply.label = super::SALTY_INVALID_OPERATION;
            return;
        }

        if proctab(ti).sid != caller_sid {
            reply.label = super::SALTY_INVALID_OPERATION;
            return;
        }

        if proctab(ti).pid == proctab(ti).sid {
            reply.label = super::SALTY_INVALID_OPERATION;
            return;
        }

        if pgid != target_pid {
            let Some(gi) = find_by_pid(pgid) else {
                reply.label = super::SALTY_NOT_FOUND;
                return;
            };
            if proctab(gi).sid != proctab(ti).sid {
                reply.label = super::SALTY_INVALID_OPERATION;
                return;
            }
        }

        proctab(ti).pgid = pgid;
        reply.label = super::SALTY_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_getpgid(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;

        if target_pid == 0 {
            let Some(caller_idx) = find_by_badge(badge) else {
                reply.label = super::SALTY_NOT_FOUND;
                return;
            };
            target_pid = proctab(caller_idx).pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };

        reply.label = super::SALTY_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).pgid as u64;
    }
}

pub(crate) unsafe fn handle_setsid(reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let Some(idx) = find_by_badge(badge) else {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };
        let pid = proctab(idx).pid;
        if proctab(idx).pgid == pid {
            reply.label = super::SALTY_INVALID_OPERATION;
            return;
        }
        proctab(idx).sid = pid;
        proctab(idx).pgid = pid;
        reply.label = super::SALTY_OK;
        reply.length = 1;
        reply.regs[0] = pid as u64;
    }
}

pub(crate) unsafe fn handle_getsid(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;

        if target_pid == 0 {
            let Some(caller_idx) = find_by_badge(badge) else {
                reply.label = super::SALTY_NOT_FOUND;
                return;
            };
            target_pid = proctab(caller_idx).pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };

        reply.label = super::SALTY_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).sid as u64;
    }
}

pub(crate) unsafe fn handle_getpgid_badge(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };

        reply.label = super::SALTY_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).pgid as u64;
    }
}

pub(crate) unsafe fn handle_getsid_badge(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };

        reply.label = super::SALTY_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).sid as u64;
    }
}

pub(crate) unsafe fn handle_getuid(reply: &mut SaltyMsg, _badge: u64) {
    reply.label = super::SALTY_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_geteuid(reply: &mut SaltyMsg, _badge: u64) {
    reply.label = super::SALTY_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_getgid(reply: &mut SaltyMsg, _badge: u64) {
    reply.label = super::SALTY_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_getegid(reply: &mut SaltyMsg, _badge: u64) {
    reply.label = super::SALTY_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

pub(crate) unsafe fn handle_getgroups(reply: &mut SaltyMsg) {
    reply.label = super::SALTY_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}
