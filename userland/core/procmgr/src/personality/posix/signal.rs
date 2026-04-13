//! Signal handling
//! Moved from crate root module for POSIX subsystem separation.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::*;

use crate::base::proc_table::{
    find_by_badge, find_by_pid, proctab, proctab_cap, NSIG, ProcessState,
    SIG_DISP_CATCH, SIG_DISP_DFL, SIG_DISP_IGN,
};

fn signal_ntfn(ntfn: Cap, bits: u64) {
    trona::syscall::syscall(trona::SYS_SIGNAL, ntfn, bits, 0, 0, 0, 0);
}

fn sig_default_is_terminate(sig: usize) -> bool {
    !matches!(
        sig,
        super::PM_SIGCHLD
            | super::PM_SIGCONT
            | super::PM_SIGSTOP
            | super::PM_SIGTSTP
            | super::PM_SIGTTIN
            | super::PM_SIGTTOU
    )
}

fn sig_default_is_stop(sig: usize) -> bool {
    matches!(
        sig,
        super::PM_SIGTSTP | super::PM_SIGTTIN | super::PM_SIGTTOU
    )
}

unsafe fn sig_stop_proc(idx: usize, sig: usize) {
    unsafe {
        if proctab(idx).state != ProcessState::Running {
            return;
        }

        let _ = trona::invoke::tcb_suspend(proctab(idx).tcb_cap);
        proctab(idx).state = ProcessState::Stopped;
        proctab(idx).stop_status = ((sig as i32) << 8) | 0x7f;

        let ppid = proctab(idx).ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if (proctab(pi).state == ProcessState::Running || proctab(pi).state == ProcessState::Stopped)
                && proctab(pi).is_posix()
                && proctab(pi).signal_ntfn != 0
                && proctab(pi).posix().sig_disposition[super::PM_SIGCHLD] == SIG_DISP_CATCH
            {
                signal_ntfn(proctab(pi).signal_ntfn, 1u64 << super::PM_SIGCHLD);
            }
        }
    }
}

pub(crate) unsafe fn terminate_proc(idx: usize, sig: usize) -> bool {
    unsafe {
        let exit_code = (sig & 0x7f) as i32;
        crate::lifecycle::exit::core_exit_sequence(idx, exit_code);
        proctab(idx).state != ProcessState::Free
    }
}

/// Deliver a signal to a single process by table index.
/// Returns true if the signal was delivered (or ignored), false if target invalid.
pub(crate) unsafe fn deliver_signal_to(ti: usize, sig: usize) -> bool {
    unsafe {
        if proctab(ti).state != ProcessState::Running && proctab(ti).state != ProcessState::Stopped {
            return false;
        }

        let target_is_posix = proctab(ti).is_posix();

        // SIGKILL: always terminate
        if sig == super::PM_SIGKILL {
            return terminate_proc(ti, sig);
        }

        // SIGSTOP: always stop
        if sig == super::PM_SIGSTOP {
            sig_stop_proc(ti, sig);
            return true;
        }

        // SIGCONT: resume stopped
        if sig == super::PM_SIGCONT {
            if proctab(ti).state == ProcessState::Stopped {
                trona::invoke::invoke(proctab(ti).tcb_cap, trona::TCB_RESUME, 0, 0, 0, 0);
                proctab(ti).state = ProcessState::Running;
                proctab(ti).stop_status = 0;

                let ppid = proctab(ti).ppid;
                if let Some(pi) = find_by_pid(ppid) {
                    if (proctab(pi).state == ProcessState::Running || proctab(pi).state == ProcessState::Stopped)
                        && proctab(pi).is_posix()
                        && proctab(pi).signal_ntfn != 0
                        && proctab(pi).posix().sig_disposition[super::PM_SIGCHLD] == SIG_DISP_CATCH
                    {
                        signal_ntfn(proctab(pi).signal_ntfn, 1u64 << super::PM_SIGCHLD);
                    }
                }
            }
            if target_is_posix
                && proctab(ti).posix().sig_disposition[sig] == SIG_DISP_CATCH
                && proctab(ti).signal_ntfn != 0
            {
                signal_ntfn(proctab(ti).signal_ntfn, 1u64 << sig);
            }
            return true;
        }

        // Cannot deliver most signals to stopped processes
        if proctab(ti).state != ProcessState::Running {
            return true;
        }

        let disp = if target_is_posix {
            proctab(ti).posix().sig_disposition[sig]
        } else {
            SIG_DISP_DFL
        };

        if disp == SIG_DISP_IGN {
            return true;
        }

        if disp == SIG_DISP_DFL {
            if sig_default_is_stop(sig) {
                sig_stop_proc(ti, sig);
            } else if sig_default_is_terminate(sig) {
                return terminate_proc(ti, sig);
            }
            return true;
        }

        // SIG_DISP_CATCH: deliver via notification
        if target_is_posix && proctab(ti).signal_ntfn != 0 {
            signal_ntfn(proctab(ti).signal_ntfn, 1u64 << sig);
        }
        true
    }
}

pub(crate) unsafe fn handle_kill(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let target_pid = msg.regs[0] as u32;
        let sig = msg.regs[1] as usize;

        if sig == 0 || sig >= NSIG {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        // pid==0: send signal to all processes in caller's process group.
        if target_pid == 0 {
            let caller_pgid = proctab(caller_idx).pgid;
            let mut delivered = false;
            for i in 0..proctab_cap() {
                if proctab(i).state != ProcessState::Free && proctab(i).pgid == caller_pgid {
                    delivered |= deliver_signal_to(i, sig);
                }
            }
            if !delivered {
                reply.label = crate::TRONA_NOT_FOUND;
                return;
            }
            reply.label = crate::TRONA_OK;
            reply.length = 0;
            return;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        if !deliver_signal_to(ti, sig) {
            reply.label = trona::TRONA_BUSY;
            return;
        }

        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

/// PM_KILL_PGID: send signal to an explicit process group.
/// Called by posix_ttysrv when ISIG chars arrive (e.g., Ctrl-C -> SIGINT to fg_pgrp).
/// msg.regs[0] = target_pgid, msg.regs[1] = sig
pub(crate) unsafe fn handle_kill_pgid(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let target_pgid = msg.regs[0] as u32;
        let sig = msg.regs[1] as usize;

        if sig == 0 || sig >= NSIG {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        let mut delivered = false;
        for i in 0..proctab_cap() {
            if proctab(i).state != ProcessState::Free && proctab(i).pgid == target_pgid {
                delivered |= deliver_signal_to(i, sig);
            }
        }

        if !delivered {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        }

        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}

/// PM_INJECT_CAP: inject a capability into a child's CSpace.
/// Called by init after pm_spawn to deliver NeedEP/CopyCap caps.
///   msg.regs[0] = target PID
///   msg.regs[1] = dst_slot in child's CSpace
///   msg.regs[2] = badge to apply (0 = plain move/copy)
///   extra_caps[0] = cap to inject (received at CAP_RECV_SCRATCH)
pub(crate) unsafe fn handle_inject_cap(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        let dst_slot = msg.regs[1];
        let badge = if msg.length >= 3 { msg.regs[2] } else { 0 };

        let idx = match find_by_pid(pid) {
            Some(i) => i,
            None => {
                reply.label = crate::TRONA_INVALID_ARGUMENT;
                return;
            }
        };

        let child_cn = proctab(idx).cnode_cap;
        if child_cn == 0 {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        // Cap was received at CAP_RECV_SCRATCH via IPC cap transfer.
        // Plain injection moves the cap into the child slot. Badged injection
        // mints a derived endpoint into the child and clears the scratch slot.
        let err = if badge == 0 {
            trona::invoke::cnode_move(
                child_cn,
                dst_slot,
                crate::CAP_SELF_CSPACE,
                crate::CAP_RECV_SCRATCH,
            )
        } else {
            let mint_err = trona::invoke::cnode_mint(
                crate::CAP_SELF_CSPACE,
                crate::CAP_RECV_SCRATCH,
                child_cn,
                dst_slot,
                badge,
            );
            let _ = trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, crate::CAP_RECV_SCRATCH);
            mint_err
        };
        reply.label = if err == 0 {
            crate::TRONA_OK
        } else {
            crate::TRONA_INVALID_OPERATION
        };
    }
}

/// PM_RESUME: resume a process that was spawned with START_SUSPENDED.
///   msg.regs[0] = target PID
pub(crate) unsafe fn handle_resume(msg: &TronaMsg, reply: &mut TronaMsg) -> bool {
    unsafe {
        let pid = msg.regs[0] as u32;
        let idx = match find_by_pid(pid) {
            Some(i) => i,
            None => {
                reply.label = crate::TRONA_NOT_FOUND;
                return false;
            }
        };

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] pm_resume enter pid=");
            _lb.hex(pid as u64);
            _lb.str(b" state=");
            _lb.dec(proctab(idx).state as u64);
            _lb.str(b" wait_ready=");
            _lb.dec(if proctab(idx).wait_ready_on_resume {
                1
            } else {
                0
            });
            _lb.str(b"\n");
        });

        if proctab(idx).state == ProcessState::Free || proctab(idx).state == ProcessState::Zombie {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return false;
        }

        if proctab(idx).state == ProcessState::Running {
            reply.label = crate::TRONA_OK;
            reply.length = 0;
            return false;
        }

        proctab(idx).state = ProcessState::Running;
        proctab(idx).stop_status = 0;

        if proctab(idx).wait_ready_on_resume {
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] pm_resume immediate-resume-for-readiness pid=");
                _lb.hex(pid as u64);
                _lb.str(b"\n");
            });
            let err = trona::invoke::tcb_resume(proctab(idx).tcb_cap);
            if err != 0 {
                proctab(idx).state = ProcessState::Stopped;
                reply.label = crate::TRONA_INVALID_OPERATION;
                return false;
            }

            proctab(idx).wait_ready_on_resume = false;
            // ready_badge_bit and ready_timeout_ns already set from spawn time
            if crate::base::readiness::defer_readiness(idx) {
                trona::udebug!(|_lb| {
                    _lb.str(b"[PROCMGR] pm_resume deferred-readiness-reply pid=");
                    _lb.hex(pid as u64);
                    _lb.str(b"\n");
                });
                return true;
            }
            // Defer failed — release the badge bit, clear fields, reply immediately
            {
                let p = proctab(idx);
                crate::base::readiness::free_readiness_bit(p.ready_badge_bit);
                p.ready_badge_bit = crate::base::readiness::BIT_NONE;
                p.ready_timeout_ns = 0;
            }
        } else if crate::server::enqueue_post_reply_resume(proctab(idx).tcb_cap) {
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] pm_resume queued-post-reply pid=");
                _lb.hex(pid as u64);
                _lb.str(b" tcb=");
                _lb.hex(proctab(idx).tcb_cap);
                _lb.str(b"\n");
            });
        } else {
            trona::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] WARN: post-reply resume queue full, resuming immediately\n");
            });
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] pm_resume fallback-immediate pid=");
                _lb.hex(pid as u64);
                _lb.str(b"\n");
            });
            let err = trona::invoke::tcb_resume(proctab(idx).tcb_cap);
            if err != 0 {
                proctab(idx).state = ProcessState::Stopped;
                reply.label = crate::TRONA_INVALID_OPERATION;
                return false;
            }
        }

        reply.label = crate::TRONA_OK;
        reply.length = 0;
        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] pm_resume reply-ready pid=");
            _lb.hex(pid as u64);
            _lb.str(b"\n");
        });
        return false;
    }
}

pub(crate) unsafe fn handle_sigaction(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let sig = msg.regs[0] as usize;
        let disp = msg.regs[1] as u8;

        if sig == 0 || sig >= NSIG || sig == super::PM_SIGKILL || sig == super::PM_SIGSTOP {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }
        if disp > SIG_DISP_CATCH {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some(idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };
        proctab(idx).posix_mut().sig_disposition[sig] = disp;
        reply.label = crate::TRONA_OK;
        reply.length = 0;
    }
}
