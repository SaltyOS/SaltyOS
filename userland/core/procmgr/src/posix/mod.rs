//! POSIX subsystem extension for procmgr.
//! All POSIX-specific IPC handlers and state management live here.
//! SPDX-License-Identifier: GPL-2.0-only

pub(crate) mod exit_wait;
pub(crate) mod session;
pub(crate) mod signal;
pub(crate) mod timer;

use trona::protocol::*;
use trona::types::core::*;

use crate::proc_table::{find_by_badge, find_by_pid, proctab, PROC_FREE, MAX_EXE_PATH_LEN};

// ---- POSIX signal numbers ----
pub(crate) const PM_SIGKILL: usize = 9;
pub(crate) const PM_SIGALRM: usize = 14;
pub(crate) const PM_SIGCHLD: usize = 17;
pub(crate) const PM_SIGCONT: usize = 18;
pub(crate) const PM_SIGSTOP: usize = 19;
pub(crate) const PM_SIGTSTP: usize = 20;
pub(crate) const PM_SIGTTIN: usize = 21;
pub(crate) const PM_SIGTTOU: usize = 22;

// ---- POSIX wait options ----
pub(crate) const WNOHANG: u32 = 1;
pub(crate) const WUNTRACED: u32 = 2;

/// Check whether the caller identified by `badge` is a POSIX subsystem process.
pub(crate) fn is_posix_caller(badge: u64) -> bool {
    if let Some(idx) = find_by_badge(badge) {
        unsafe { proctab(idx).is_posix() }
    } else {
        // Unknown caller — default to POSIX for backward compatibility
        true
    }
}

pub(crate) unsafe fn handle_umask(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = crate::TRONA_NOT_FOUND;
        return;
    };
    unsafe {
        let p = proctab(idx);
        let old = p.posix().umask;
        p.posix_mut().umask = (msg.regs[0] as u32) & 0o777;
        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = old as u64;
    }
}

pub(crate) unsafe fn handle_get_exe_path(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        let Some(idx) = find_by_pid(pid) else {
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] GET_EXE_PATH pid=");
                _lb.hex(pid as u64);
                _lb.str(b" -> not found\n");
            });
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        let p = &*proctab(idx);
        let posix = p.posix();
        let mut exe_len = 0usize;
        while exe_len < MAX_EXE_PATH_LEN && posix.exe_path[exe_len] != 0 {
            exe_len += 1;
        }
        if exe_len == 0 {
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] GET_EXE_PATH pid=");
                _lb.hex(pid as u64);
                _lb.str(b" -> empty\n");
            });
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        }

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] GET_EXE_PATH pid=");
            _lb.hex(pid as u64);
            _lb.str(b" -> '");
            _lb.bytes(&posix.exe_path[..exe_len]);
            _lb.str(b"'\n");
        });

        reply.regs[0] = exe_len as u64;
        let dst = &mut reply.regs[1] as *mut u64 as *mut u8;
        for i in 0..exe_len {
            *dst.add(i) = posix.exe_path[i];
        }
        reply.label = crate::TRONA_OK;
        reply.length = 1 + ((exe_len as u64 + 7) / 8);
    }
}

/// Dispatch a POSIX-specific IPC label.
/// Returns Some(skip_reply) if the label was handled, None if not a POSIX label.
pub(crate) unsafe fn dispatch_posix(
    label: u64,
    msg: &TronaMsg,
    reply: &mut TronaMsg,
    badge: u64,
) -> Option<bool> {
    unsafe {
        match label {
            PM_FORK => {
                crate::fork_exec::handle_fork(msg, reply, badge);
                Some(false)
            }
            PM_EXEC => {
                crate::fork_exec::handle_exec(msg, reply, badge);
                Some(reply.label == 0)
            }
            PM_WAIT => {
                let skip = exit_wait::handle_wait(msg, reply, badge);
                Some(skip)
            }
            PM_KILL => {
                signal::handle_kill(msg, reply, badge);
                Some(false)
            }
            PM_KILL_PGID => {
                signal::handle_kill_pgid(msg, reply);
                Some(false)
            }
            PM_SIGACTION => {
                signal::handle_sigaction(msg, reply, badge);
                Some(false)
            }
            PM_SETITIMER => {
                timer::handle_setitimer(msg, reply, badge);
                Some(false)
            }
            PM_GETITIMER => {
                timer::handle_getitimer(msg, reply, badge);
                Some(false)
            }
            PM_GETUID => {
                session::handle_getuid(reply, badge);
                Some(false)
            }
            PM_GETGID => {
                session::handle_getgid(reply, badge);
                Some(false)
            }
            PM_SETPGID => {
                session::handle_setpgid(msg, reply, badge);
                Some(false)
            }
            PM_GETPGID => {
                session::handle_getpgid(msg, reply, badge);
                Some(false)
            }
            PM_SETSID => {
                session::handle_setsid(reply, badge);
                Some(false)
            }
            PM_GETSID => {
                session::handle_getsid(msg, reply, badge);
                Some(false)
            }
            PM_GETEUID => {
                session::handle_geteuid(reply, badge);
                Some(false)
            }
            PM_GETEGID => {
                session::handle_getegid(reply, badge);
                Some(false)
            }
            PM_GETGROUPS => {
                session::handle_getgroups(reply);
                Some(false)
            }
            PM_GETPGID_BADGE => {
                session::handle_getpgid_badge(msg, reply);
                Some(false)
            }
            PM_GETSID_BADGE => {
                session::handle_getsid_badge(msg, reply);
                Some(false)
            }
            PM_UMASK => {
                handle_umask(msg, reply, badge);
                Some(false)
            }
            PM_GET_EXE_PATH => {
                handle_get_exe_path(msg, reply);
                Some(false)
            }
            _ => None,
        }
    }
}
