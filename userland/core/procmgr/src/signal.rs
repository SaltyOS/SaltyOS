//! Signal handling
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

use salty::serial::LineBuf;
use salty::types::*;

use crate::proc_table::{
    cleanup_proc_resources, find_by_badge, find_by_pid,
    proctab, proctab_cap,
    NSIG,
    PROC_FREE, PROC_RUNNING, PROC_STOPPED, PROC_ZOMBIE,
    SIG_DISP_CATCH, SIG_DISP_DFL, SIG_DISP_IGN,
};
use crate::exit_wait::free_proc_alloc_slots;

fn signal_ntfn(ntfn: Cap, bits: u64) {
    salty::syscall::syscall(salty::SYS_SIGNAL, ntfn, bits, 0, 0, 0, 0);
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
    matches!(sig, super::PM_SIGTSTP | super::PM_SIGTTIN | super::PM_SIGTTOU)
}

unsafe fn sig_stop_proc(idx: usize, sig: usize) {
    unsafe {
        if proctab(idx).state != PROC_RUNNING {
            return;
        }

        salty::invoke::invoke(proctab(idx).tcb_cap, salty::TCB_SUSPEND, 0, 0, 0, 0);
        proctab(idx).state = PROC_STOPPED;
        proctab(idx).stop_status = ((sig as i32) << 8) | 0x7f;

        let ppid = proctab(idx).ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if (proctab(pi).state == PROC_RUNNING || proctab(pi).state == PROC_STOPPED)
                && proctab(pi).signal_ntfn != 0
                && proctab(pi).sig_disposition[super::PM_SIGCHLD] == SIG_DISP_CATCH
            {
                signal_ntfn(proctab(pi).signal_ntfn, 1u64 << super::PM_SIGCHLD);
            }
        }
    }
}

unsafe fn sig_terminate_proc(idx: usize, sig: usize) {
    unsafe {
        let exit_code = (sig & 0x7f) as i32;

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] SIGKILL/terminate PID="); lb.hex(proctab(idx).pid as u64);
        lb.str(b" sig="); lb.hex(sig as u64); lb.str(b"\n"); lb.flush(); }

        salty::invoke::invoke(proctab(idx).tcb_cap, salty::TCB_SUSPEND, 0, 0, 0, 0);
        proctab(idx).state = PROC_ZOMBIE;
        proctab(idx).exit_code = exit_code;

        // Deliver SIGCHLD to parent
        let ppid = proctab(idx).ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if (proctab(pi).state == PROC_RUNNING || proctab(pi).state == PROC_STOPPED)
                && proctab(pi).signal_ntfn != 0
                && proctab(pi).sig_disposition[super::PM_SIGCHLD] == SIG_DISP_CATCH
            {
                signal_ntfn(proctab(pi).signal_ntfn, 1u64 << super::PM_SIGCHLD);
            }
        }

        // Wake specific-child waiter
        if proctab(idx).waiter_reply != 0 {
            let mut wake = SaltyMsg::zeroed();
            wake.label = super::SALTY_OK;
            wake.length = 2;
            wake.regs[0] = exit_code as u64;
            wake.regs[1] = proctab(idx).pid as u64;

            let waiter_cap = proctab(idx).waiter_reply;
            salty::ipc::send_ctx(super::ipc_ctx(), waiter_cap, &raw const wake);
            salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, waiter_cap);
            (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(waiter_cap);
            proctab(idx).waiter_reply = 0;
            proctab(idx).waiter_pid = 0;
            free_proc_alloc_slots(idx);
            cleanup_proc_resources(idx, super::CAP_SELF_CSPACE);
            return;
        }

        // Wake any-child waiter on parent
        if let Some(pi) = find_by_pid(ppid) {
            if proctab(pi).waiting_for_any != 0 {
                let mut wake = SaltyMsg::zeroed();
                wake.label = super::SALTY_OK;
                wake.length = 2;
                wake.regs[0] = exit_code as u64;
                wake.regs[1] = proctab(idx).pid as u64;

                let waiter_cap = proctab(pi).any_waiter_reply;
                salty::ipc::send_ctx(super::ipc_ctx(), waiter_cap, &raw const wake);
                salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, waiter_cap);
                (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(waiter_cap);
                proctab(pi).any_waiter_reply = 0;
                proctab(pi).waiting_for_any = 0;
                free_proc_alloc_slots(idx);
                cleanup_proc_resources(idx, super::CAP_SELF_CSPACE);
            }
        }
    }
}

/// Deliver a signal to a single process by table index.
/// Returns true if the signal was delivered (or ignored), false if target invalid.
unsafe fn deliver_signal_to(ti: usize, sig: usize) -> bool {
    unsafe {
        if proctab(ti).state != PROC_RUNNING && proctab(ti).state != PROC_STOPPED {
            return false;
        }

        // SIGKILL: always terminate
        if sig == super::PM_SIGKILL {
            sig_terminate_proc(ti, sig);
            return true;
        }

        // SIGSTOP: always stop
        if sig == super::PM_SIGSTOP {
            sig_stop_proc(ti, sig);
            return true;
        }

        // SIGCONT: resume stopped
        if sig == super::PM_SIGCONT {
            if proctab(ti).state == PROC_STOPPED {
                salty::invoke::invoke(proctab(ti).tcb_cap, salty::TCB_RESUME, 0, 0, 0, 0);
                proctab(ti).state = PROC_RUNNING;
                proctab(ti).stop_status = 0;

                let ppid = proctab(ti).ppid;
                if let Some(pi) = find_by_pid(ppid) {
                    if (proctab(pi).state == PROC_RUNNING || proctab(pi).state == PROC_STOPPED)
                        && proctab(pi).signal_ntfn != 0
                        && proctab(pi).sig_disposition[super::PM_SIGCHLD] == SIG_DISP_CATCH
                    {
                        signal_ntfn(proctab(pi).signal_ntfn, 1u64 << super::PM_SIGCHLD);
                    }
                }
            }
            if proctab(ti).sig_disposition[sig] == SIG_DISP_CATCH && proctab(ti).signal_ntfn != 0 {
                signal_ntfn(proctab(ti).signal_ntfn, 1u64 << sig);
            }
            return true;
        }

        // Cannot deliver most signals to stopped processes
        if proctab(ti).state != PROC_RUNNING {
            return true;
        }

        let disp = proctab(ti).sig_disposition[sig];

        if disp == SIG_DISP_IGN {
            return true;
        }

        if disp == SIG_DISP_DFL {
            if sig_default_is_stop(sig) {
                sig_stop_proc(ti, sig);
            } else if sig_default_is_terminate(sig) {
                sig_terminate_proc(ti, sig);
            }
            return true;
        }

        // SIG_DISP_CATCH: deliver via notification
        if proctab(ti).signal_ntfn != 0 {
            signal_ntfn(proctab(ti).signal_ntfn, 1u64 << sig);
        }
        true
    }
}

pub(crate) unsafe fn handle_kill(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let target_pid = msg.regs[0] as u32;
        let sig = msg.regs[1] as usize;

        if sig == 0 || sig >= NSIG {
            reply.label = super::SALTY_INVALID_ARGUMENT;
            return;
        }

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };

        // pid==0: send signal to all processes in caller's process group.
        if target_pid == 0 {
            let caller_pgid = proctab(caller_idx).pgid;
            let mut delivered = false;
            for i in 0..proctab_cap() {
                if proctab(i).state != PROC_FREE && proctab(i).pgid == caller_pgid {
                    delivered |= deliver_signal_to(i, sig);
                }
            }
            if !delivered {
                reply.label = super::SALTY_NOT_FOUND;
                return;
            }
            reply.label = super::SALTY_OK;
            reply.length = 0;
            return;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };

        if !deliver_signal_to(ti, sig) {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        }

        reply.label = super::SALTY_OK;
        reply.length = 0;
    }
}

/// POSIX_PM_KILL_PGID: send signal to an explicit process group.
/// Called by ttyd when ISIG chars arrive (e.g., Ctrl-C -> SIGINT to fg_pgrp).
/// msg.regs[0] = target_pgid, msg.regs[1] = sig
pub(crate) unsafe fn handle_kill_pgid(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let target_pgid = msg.regs[0] as u32;
        let sig = msg.regs[1] as usize;

        if sig == 0 || sig >= NSIG {
            reply.label = super::SALTY_INVALID_ARGUMENT;
            return;
        }

        let mut delivered = false;
        for i in 0..proctab_cap() {
            if proctab(i).state != PROC_FREE && proctab(i).pgid == target_pgid {
                delivered |= deliver_signal_to(i, sig);
            }
        }

        if !delivered {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        }

        reply.label = super::SALTY_OK;
        reply.length = 0;
    }
}

/// PM_INJECT_CAP: inject a capability into a child's CSpace.
/// Called by init after pm_spawn to deliver NeedEP/CopyCap caps.
///   msg.regs[0] = target PID
///   msg.regs[1] = dst_slot in child's CSpace
///   extra_caps[0] = cap to inject (received at CAP_RECV_SCRATCH)
pub(crate) unsafe fn handle_inject_cap(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        let dst_slot = msg.regs[1];

        let idx = match find_by_pid(pid) {
            Some(i) => i,
            None => {
                reply.label = super::SALTY_INVALID_ARGUMENT;
                return;
            }
        };

        let child_cn = proctab(idx).cnode_cap;
        if child_cn == 0 {
            reply.label = super::SALTY_INVALID_ARGUMENT;
            return;
        }

        // Cap was received at CAP_RECV_SCRATCH via IPC cap transfer.
        // Move it into the child slot so the scratch slot is freed for the
        // next injected cap in the same boot sequence.
        let err = salty::invoke::cnode_move(
            child_cn, dst_slot,
            super::CAP_SELF_CSPACE, super::CAP_RECV_SCRATCH,
        );
        reply.label = if err == 0 { super::SALTY_OK } else { super::SALTY_INVALID_OPERATION };
    }
}

/// PM_RESUME: resume a process that was spawned with START_SUSPENDED.
///   msg.regs[0] = target PID
pub(crate) unsafe fn handle_resume(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        let idx = match find_by_pid(pid) {
            Some(i) => i,
            None => {
                reply.label = super::SALTY_NOT_FOUND;
                return;
            }
        };

        if proctab(idx).state == PROC_FREE || proctab(idx).state == PROC_ZOMBIE {
            reply.label = super::SALTY_INVALID_OPERATION;
            return;
        }

        if proctab(idx).state == PROC_RUNNING {
            reply.label = super::SALTY_OK;
            reply.length = 0;
            return;
        }

        let err = salty::invoke::tcb_resume(proctab(idx).tcb_cap);
        if err != 0 {
            reply.label = super::SALTY_INVALID_OPERATION;
            return;
        }

        proctab(idx).state = PROC_RUNNING;
        proctab(idx).stop_status = 0;
        reply.label = super::SALTY_OK;
        reply.length = 0;
    }
}

pub(crate) unsafe fn handle_sigaction(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let sig = msg.regs[0] as usize;
        let disp = msg.regs[1] as u8;

        if sig == 0 || sig >= NSIG || sig == super::PM_SIGKILL || sig == super::PM_SIGSTOP {
            reply.label = super::SALTY_INVALID_ARGUMENT;
            return;
        }
        if disp > SIG_DISP_CATCH {
            reply.label = super::SALTY_INVALID_ARGUMENT;
            return;
        }

        let Some(idx) = find_by_badge(badge) else {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };
        proctab(idx).sig_disposition[sig] = disp;
        reply.label = super::SALTY_OK;
        reply.length = 0;
    }
}
