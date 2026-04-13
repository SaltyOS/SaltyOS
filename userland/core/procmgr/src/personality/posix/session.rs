//! Process group, session, and UID/GID handlers
//! Moved from crate root module for POSIX subsystem separation.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::*;

use crate::base::proc_table::{find_by_badge, find_by_pid, proctab, ProcessState};

unsafe fn for_each_process_in_session_mut(
    sid: u32,
    mut f: impl FnMut(&mut crate::base::proc_table::Process),
) {
    unsafe {
        for i in 0..crate::base::proc_table::proctab_cap() {
            let p = proctab(i);
            if p.state == crate::base::proc_table::ProcessState::Free {
                continue;
            }
            if p.sid == sid {
                f(p);
            }
        }
    }
}

pub(crate) unsafe fn handle_setpgid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;
        let mut pgid = msg.regs[1] as u32;

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
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
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        if target_pid != caller_pid && proctab(ti).ppid != caller_pid {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }

        if proctab(ti).sid != caller_sid {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }

        if proctab(ti).pid == proctab(ti).sid {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }

        // Idempotent: target already in the requested group
        if proctab(ti).pgid == pgid {
            reply.label = crate::TRONA_OK;
            reply.length = 0;
            return;
        }

        // POSIX: the target process group must already exist in the caller's session.
        // A group exists as long as any non-FREE process has that pgid -- we can't
        // rely on find_by_pid(pgid) because the group leader may have already exited.
        if pgid != target_pid {
            let target_sid = proctab(ti).sid;
            let mut pg_exists = false;
            for i in 0..crate::base::proc_table::proctab_cap() {
                let p = proctab(i);
                if p.state != crate::base::proc_table::ProcessState::Free && p.pgid == pgid && p.sid == target_sid
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

        proctab(ti).pgid = pgid;
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
        reply.regs[0] = proctab(ti).pgid as u64;
    }
}

pub(crate) unsafe fn handle_setsid(reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let Some(idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };
        let pid = proctab(idx).pid;
        if proctab(idx).pgid == pid {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }
        proctab(idx).sid = pid;
        proctab(idx).pgid = pid;
        proctab(idx).ctty_dev = 0;
        proctab(idx).ctty_pgrp = 0;
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
        reply.regs[0] = proctab(ti).sid as u64;
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
        if proctab(ti).state == ProcessState::Zombie {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        }

        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).pgid as u64;
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
        reply.regs[0] = proctab(ti).sid as u64;
    }
}

pub(crate) unsafe fn handle_get_session_tty_badge(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).ctty_dev;
    }
}

pub(crate) unsafe fn handle_set_session_tty(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let tty_dev = msg.regs[1];
        let fg_pgrp = msg.regs[2] as u32;

        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        let sid = proctab(ti).sid;
        for_each_process_in_session_mut(sid, |p| {
            p.ctty_dev = tty_dev;
            p.ctty_pgrp = fg_pgrp;
        });

        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_clear_session_tty(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        let sid = proctab(ti).sid;
        for_each_process_in_session_mut(sid, |p| {
            p.ctty_dev = 0;
            p.ctty_pgrp = 0;
        });

        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_set_session_tty_pgrp(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let fg_pgrp = msg.regs[1] as u32;

        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        let sid = proctab(ti).sid;
        for_each_process_in_session_mut(sid, |p| {
            p.ctty_pgrp = fg_pgrp;
        });

        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_getuid(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(idx).posix().uid as u64;
    }
}

pub(crate) unsafe fn handle_geteuid(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(idx).posix().euid as u64;
    }
}

pub(crate) unsafe fn handle_getgid(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(idx).posix().gid as u64;
    }
}

pub(crate) unsafe fn handle_getegid(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(idx).posix().egid as u64;
    }
}

pub(crate) unsafe fn handle_getgroups(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let p = proctab(idx).posix();
        let n = p.ngroups as usize;
        let requested = msg.regs[0] as i32;
        if requested == 0 {
            reply.label = crate::TRONA_OK;
            reply.length = 1;
            reply.regs[0] = n as u64;
            return;
        }
        if (requested as usize) < n {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }
        reply.regs[0] = n as u64;
        let mut ri = 1usize;
        let mut gi = 0usize;
        while gi < n {
            let lo = p.groups[gi] as u64;
            let hi = if gi + 1 < n {
                p.groups[gi + 1] as u64
            } else {
                0
            };
            reply.regs[ri] = lo | (hi << 32);
            ri += 1;
            gi += 2;
        }
        reply.label = crate::TRONA_OK;
        reply.length = ri as u64;
    }
}

pub(crate) unsafe fn handle_setuid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let uid = msg.regs[0] as u32;
        let p = proctab(idx).posix();
        if p.euid == 0 {
            let pm = proctab(idx).posix_mut();
            pm.uid = uid;
            pm.euid = uid;
            pm.suid = uid;
        } else if uid == p.uid || uid == p.suid {
            proctab(idx).posix_mut().euid = uid;
        } else {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }
        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_setgid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let gid = msg.regs[0] as u32;
        let p = proctab(idx).posix();
        if p.euid == 0 {
            let pm = proctab(idx).posix_mut();
            pm.gid = gid;
            pm.egid = gid;
            pm.sgid = gid;
        } else if gid == p.gid || gid == p.sgid {
            proctab(idx).posix_mut().egid = gid;
        } else {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }
        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_seteuid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let new_euid = msg.regs[0] as u32;
        let p = proctab(idx).posix();
        if p.euid == 0 || new_euid == p.uid || new_euid == p.suid {
            proctab(idx).posix_mut().euid = new_euid;
            reply.label = crate::TRONA_OK;
            reply.length = 0;
        } else {
            reply.label = crate::TRONA_INVALID_OPERATION;
        }
    }
}

pub(crate) unsafe fn handle_setegid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let new_egid = msg.regs[0] as u32;
        let p = proctab(idx).posix();
        if p.euid == 0 || new_egid == p.gid || new_egid == p.sgid {
            proctab(idx).posix_mut().egid = new_egid;
            reply.label = crate::TRONA_OK;
            reply.length = 0;
        } else {
            reply.label = crate::TRONA_INVALID_OPERATION;
        }
    }
}

pub(crate) unsafe fn handle_setreuid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let ruid = msg.regs[0] as u32;
        let euid = msg.regs[1] as u32;
        let p = proctab(idx).posix();
        let old_uid = p.uid;
        let old_euid = p.euid;
        let old_suid = p.suid;
        let privileged = old_euid == 0;
        let new_uid = if ruid == u32::MAX { old_uid } else { ruid };
        let new_euid = if euid == u32::MAX { old_euid } else { euid };
        if !privileged {
            if ruid != u32::MAX && ruid != old_uid && ruid != old_euid {
                reply.label = crate::TRONA_INVALID_OPERATION;
                return;
            }
            if euid != u32::MAX && euid != old_uid && euid != old_euid && euid != old_suid {
                reply.label = crate::TRONA_INVALID_OPERATION;
                return;
            }
        }
        let pm = proctab(idx).posix_mut();
        pm.uid = new_uid;
        pm.euid = new_euid;
        if ruid != u32::MAX || new_euid != old_euid {
            pm.suid = new_euid;
        }
        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_setregid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let rgid = msg.regs[0] as u32;
        let egid = msg.regs[1] as u32;
        let p = proctab(idx).posix();
        let old_gid = p.gid;
        let old_egid = p.egid;
        let old_sgid = p.sgid;
        let privileged = p.euid == 0;
        let new_gid = if rgid == u32::MAX { old_gid } else { rgid };
        let new_egid = if egid == u32::MAX { old_egid } else { egid };
        if !privileged {
            if rgid != u32::MAX && rgid != old_gid && rgid != old_egid {
                reply.label = crate::TRONA_INVALID_OPERATION;
                return;
            }
            if egid != u32::MAX && egid != old_gid && egid != old_egid && egid != old_sgid {
                reply.label = crate::TRONA_INVALID_OPERATION;
                return;
            }
        }
        let pm = proctab(idx).posix_mut();
        pm.gid = new_gid;
        pm.egid = new_egid;
        if rgid != u32::MAX || new_egid != old_egid {
            pm.sgid = new_egid;
        }
        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_setgroups(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let p = proctab(idx).posix();
        if p.euid != 0 {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }
        let count = msg.regs[0] as usize;
        if count > crate::base::proc_table::NGROUPS_MAX {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }
        let pm = proctab(idx).posix_mut();
        pm.ngroups = count as u32;
        let mut gi = 0usize;
        let mut ri = 1usize;
        while gi < count {
            let packed = msg.regs[ri];
            pm.groups[gi] = packed as u32;
            gi += 1;
            if gi < count {
                pm.groups[gi] = (packed >> 32) as u32;
                gi += 1;
            }
            ri += 1;
        }
        while gi < crate::base::proc_table::NGROUPS_MAX {
            pm.groups[gi] = 0;
            gi += 1;
        }
        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_get_creds_by_badge(msg: &TronaMsg, reply: &mut TronaMsg) {
    let target_badge = msg.regs[0];
    let Some(idx) = find_by_badge(target_badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        if !proctab(idx).is_posix() {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        }
        let p = proctab(idx).posix();
        reply.label = crate::TRONA_OK;
        reply.regs[0] = p.uid as u64;
        reply.regs[1] = p.euid as u64;
        reply.regs[2] = p.gid as u64;
        reply.regs[3] = p.egid as u64;
        let n = p.ngroups as usize;
        reply.regs[4] = n as u64;
        let mut gi = 0usize;
        let mut ri = 5usize;
        while gi < n {
            let lo = p.groups[gi] as u64;
            let hi = if gi + 1 < n {
                p.groups[gi + 1] as u64
            } else {
                0
            };
            reply.regs[ri] = lo | (hi << 32);
            ri += 1;
            gi += 2;
        }
        reply.length = ri as u64;
    }
}

pub(crate) unsafe fn handle_getresuid(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let p = proctab(idx).posix();
        reply.label = crate::TRONA_OK;
        reply.length = 3;
        reply.regs[0] = p.uid as u64;
        reply.regs[1] = p.euid as u64;
        reply.regs[2] = p.suid as u64;
    }
}

pub(crate) unsafe fn handle_getresgid(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let p = proctab(idx).posix();
        reply.label = crate::TRONA_OK;
        reply.length = 3;
        reply.regs[0] = p.gid as u64;
        reply.regs[1] = p.egid as u64;
        reply.regs[2] = p.sgid as u64;
    }
}

pub(crate) unsafe fn handle_setresuid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let ruid = msg.regs[0] as u32;
        let euid = msg.regs[1] as u32;
        let suid = msg.regs[2] as u32;
        let p = proctab(idx).posix();
        let cur_uid = p.uid;
        let cur_euid = p.euid;
        let cur_suid = p.suid;
        let privileged = cur_euid == 0;
        if !privileged {
            if ruid != u32::MAX && ruid != cur_uid && ruid != cur_euid && ruid != cur_suid {
                reply.label = crate::TRONA_INVALID_OPERATION;
                return;
            }
            if euid != u32::MAX && euid != cur_uid && euid != cur_euid && euid != cur_suid {
                reply.label = crate::TRONA_INVALID_OPERATION;
                return;
            }
            if suid != u32::MAX && suid != cur_uid && suid != cur_euid && suid != cur_suid {
                reply.label = crate::TRONA_INVALID_OPERATION;
                return;
            }
        }
        let pm = proctab(idx).posix_mut();
        if ruid != u32::MAX {
            pm.uid = ruid;
        }
        if euid != u32::MAX {
            pm.euid = euid;
        }
        if suid != u32::MAX {
            pm.suid = suid;
        }
        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_setresgid(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let rgid = msg.regs[0] as u32;
        let egid = msg.regs[1] as u32;
        let sgid = msg.regs[2] as u32;
        let p = proctab(idx).posix();
        let cur_gid = p.gid;
        let cur_egid = p.egid;
        let cur_sgid = p.sgid;
        let privileged = p.euid == 0;
        if !privileged {
            if rgid != u32::MAX && rgid != cur_gid && rgid != cur_egid && rgid != cur_sgid {
                reply.label = crate::TRONA_INVALID_OPERATION;
                return;
            }
            if egid != u32::MAX && egid != cur_gid && egid != cur_egid && egid != cur_sgid {
                reply.label = crate::TRONA_INVALID_OPERATION;
                return;
            }
            if sgid != u32::MAX && sgid != cur_gid && sgid != cur_egid && sgid != cur_sgid {
                reply.label = crate::TRONA_INVALID_OPERATION;
                return;
            }
        }
        let pm = proctab(idx).posix_mut();
        if rgid != u32::MAX {
            pm.gid = rgid;
        }
        if egid != u32::MAX {
            pm.egid = egid;
        }
        if sgid != u32::MAX {
            pm.sgid = sgid;
        }
        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_getrlimit(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let resource = msg.regs[0] as usize;
        if resource >= crate::base::proc_table::RLIM_NLIMITS {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }
        let p = proctab(idx).posix();
        reply.label = crate::TRONA_OK;
        reply.length = 2;
        reply.regs[0] = p.rlimits[resource][0];
        reply.regs[1] = p.rlimits[resource][1];
    }
}

pub(crate) unsafe fn handle_setrlimit(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let resource = msg.regs[0] as usize;
        let new_cur = msg.regs[1];
        let new_max = msg.regs[2];
        if resource >= crate::base::proc_table::RLIM_NLIMITS {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }
        if new_cur > new_max {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }
        let p = proctab(idx).posix();
        let old_max = p.rlimits[resource][1];
        if new_max > old_max && p.euid != 0 {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }
        let pm = proctab(idx).posix_mut();
        pm.rlimits[resource][0] = new_cur;
        pm.rlimits[resource][1] = new_max;
        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}
