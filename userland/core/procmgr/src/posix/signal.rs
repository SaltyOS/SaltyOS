//! Signal handling
//! Moved from crate root module for POSIX subsystem separation.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::*;

use super::exit_wait::free_proc_alloc_slots;
use crate::proc_table::{
    cleanup_proc_resources, find_by_badge, find_by_pid, proctab, proctab_cap, NSIG, PROC_FREE,
    PROC_RUNNING, PROC_STOPPED, PROC_ZOMBIE, SIG_DISP_CATCH, SIG_DISP_DFL, SIG_DISP_IGN,
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
        if proctab(idx).state != PROC_RUNNING {
            return;
        }

        let _ = trona::invoke::tcb_suspend_retry(proctab(idx).tcb_cap, 64);
        trona::syscall::syscall(trona::SYS_YIELD, 0, 0, 0, 0, 0, 0);
        proctab(idx).state = PROC_STOPPED;
        proctab(idx).posix_mut().stop_status = ((sig as i32) << 8) | 0x7f;

        let ppid = proctab(idx).ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if (proctab(pi).state == PROC_RUNNING || proctab(pi).state == PROC_STOPPED)
                && proctab(pi).posix().signal_ntfn != 0
                && proctab(pi).posix().sig_disposition[super::PM_SIGCHLD] == SIG_DISP_CATCH
            {
                signal_ntfn(proctab(pi).posix().signal_ntfn, 1u64 << super::PM_SIGCHLD);
            }
        }
    }
}

pub(crate) unsafe fn terminate_proc(idx: usize, sig: usize) -> bool {
    unsafe {
        let exit_code = (sig & 0x7f) as i32;

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] SIGKILL/terminate PID=");
            _lb.hex(proctab(idx).pid as u64);
            _lb.str(b" sig=");
            _lb.hex(sig as u64);
            _lb.str(b"\n");
        });

        let mut susp_err = trona::invoke::tcb_suspend_retry(proctab(idx).tcb_cap, 64);
        if susp_err != 0 {
            // Last resort: nanosleep to let the target CPU's IRQ window
            // open (ep_lock/ntfn_lock hold IRQs off, delaying IPI delivery).
            trona::syscall::syscall(trona::SYS_NANOSLEEP, 2_000_000, 0, 0, 0, 0, 0);
            susp_err = trona::invoke::tcb_suspend_retry(proctab(idx).tcb_cap, 64);
        }

        // Never tear down process resources unless the target TCB is known
        // suspended; otherwise a still-running thread can execute from freed
        // mappings and fault nondeterministically.
        if susp_err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] terminate: suspend failed PID=");
                _lb.hex(proctab(idx).pid as u64);
                _lb.str(b" err=");
                _lb.hex(susp_err as u64);
                _lb.str(b"\n");
            });
            return false;
        }
        // Yield to ensure the target CPU has fully completed the context
        // switch and all memory operations from the stopped thread are
        // visible before we free its resources.
        trona::syscall::syscall(trona::SYS_YIELD, 0, 0, 0, 0, 0, 0);

        // Deregister from mmsrv so it stops processing faults for this process
        if proctab(idx).mmsrv_registered {
            let tcb_cap = proctab(idx).tcb_cap;
            let pid = proctab(idx).pid;
            let badge = proctab(idx).badge;
            crate::spawn_tx::clear_fault_handler(tcb_cap, pid);
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona::protocol::MM_DEREGISTER;
            mm_msg.length = 1;
            mm_msg.regs[0] = badge;
            let _ = trona::ipc::call_ctx(
                crate::ipc_ctx(),
                crate::CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            proctab(idx).mmsrv_registered = false;
        }

        // Notify VFS to tear down fd state for this process
        {
            let mut vfs_msg = TronaMsg::zeroed();
            vfs_msg.label = trona::protocol::VFS_CLIENT_EXIT;
            vfs_msg.length = 1;
            vfs_msg.regs[0] = proctab(idx).badge;
            for _ in 0..16 {
                let err = trona::ipc::nbsend_ctx(
                    crate::ipc_ctx(),
                    crate::CAP_VFS_EP,
                    &raw const vfs_msg,
                );
                if err == 0 {
                    break;
                }
                trona::syscall::syscall(trona::SYS_YIELD, 0, 0, 0, 0, 0, 0);
            }
        }

        proctab(idx).state = PROC_ZOMBIE;
        proctab(idx).exit_code = exit_code;

        // Deliver SIGCHLD to parent
        let ppid = proctab(idx).ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if (proctab(pi).state == PROC_RUNNING || proctab(pi).state == PROC_STOPPED)
                && proctab(pi).posix().signal_ntfn != 0
                && proctab(pi).posix().sig_disposition[super::PM_SIGCHLD] == SIG_DISP_CATCH
            {
                signal_ntfn(proctab(pi).posix().signal_ntfn, 1u64 << super::PM_SIGCHLD);
            }
        }

        // Wake specific-child waiter
        if proctab(idx).posix().waiter_reply != 0 {
            let mut wake = TronaMsg::zeroed();
            wake.label = crate::TRONA_OK;
            wake.length = 2;
            wake.regs[0] = exit_code as u64;
            wake.regs[1] = proctab(idx).pid as u64;

            let waiter_cap = proctab(idx).posix().waiter_reply;
            let send_err = trona::ipc::send_ctx(crate::ipc_ctx(), waiter_cap, &raw const wake);
            trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, waiter_cap);
            (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(waiter_cap);
            proctab(idx).posix_mut().waiter_reply = 0;
            proctab(idx).posix_mut().waiter_pid = 0;
            let parent_alive = find_by_pid(ppid).is_some();
            if send_err == 0 || !parent_alive {
                free_proc_alloc_slots(idx);
                cleanup_proc_resources(idx, crate::CAP_SELF_CSPACE);
            }
            return true;
        }

        // Wake any-child waiter on parent
        if let Some(pi) = find_by_pid(ppid) {
            if proctab(pi).posix().waiting_for_any != 0 {
                let mut wake = TronaMsg::zeroed();
                wake.label = crate::TRONA_OK;
                wake.length = 2;
                wake.regs[0] = exit_code as u64;
                wake.regs[1] = proctab(idx).pid as u64;

                let waiter_cap = proctab(pi).posix().any_waiter_reply;
                let send_err = trona::ipc::send_ctx(crate::ipc_ctx(), waiter_cap, &raw const wake);
                trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, waiter_cap);
                (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(waiter_cap);
                proctab(pi).posix_mut().any_waiter_reply = 0;
                proctab(pi).posix_mut().waiting_for_any = 0;
                if send_err == 0 {
                    free_proc_alloc_slots(idx);
                    cleanup_proc_resources(idx, crate::CAP_SELF_CSPACE);
                }
            }
        }

        true
    }
}

/// Deliver a signal to a single process by table index.
/// Returns true if the signal was delivered (or ignored), false if target invalid.
pub(crate) unsafe fn deliver_signal_to(ti: usize, sig: usize) -> bool {
    unsafe {
        if proctab(ti).state != PROC_RUNNING && proctab(ti).state != PROC_STOPPED {
            return false;
        }

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
            if proctab(ti).state == PROC_STOPPED {
                trona::invoke::invoke(proctab(ti).tcb_cap, trona::TCB_RESUME, 0, 0, 0, 0);
                proctab(ti).state = PROC_RUNNING;
                proctab(ti).posix_mut().stop_status = 0;

                let ppid = proctab(ti).ppid;
                if let Some(pi) = find_by_pid(ppid) {
                    if (proctab(pi).state == PROC_RUNNING || proctab(pi).state == PROC_STOPPED)
                        && proctab(pi).posix().signal_ntfn != 0
                        && proctab(pi).posix().sig_disposition[super::PM_SIGCHLD] == SIG_DISP_CATCH
                    {
                        signal_ntfn(proctab(pi).posix().signal_ntfn, 1u64 << super::PM_SIGCHLD);
                    }
                }
            }
            if proctab(ti).posix().sig_disposition[sig] == SIG_DISP_CATCH && proctab(ti).posix().signal_ntfn != 0 {
                signal_ntfn(proctab(ti).posix().signal_ntfn, 1u64 << sig);
            }
            return true;
        }

        // Cannot deliver most signals to stopped processes
        if proctab(ti).state != PROC_RUNNING {
            return true;
        }

        let disp = proctab(ti).posix().sig_disposition[sig];

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
        if proctab(ti).posix().signal_ntfn != 0 {
            signal_ntfn(proctab(ti).posix().signal_ntfn, 1u64 << sig);
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
            let caller_pgid = proctab(caller_idx).posix().pgid;
            let mut delivered = false;
            for i in 0..proctab_cap() {
                if proctab(i).state != PROC_FREE && proctab(i).posix().pgid == caller_pgid {
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
            if proctab(i).state != PROC_FREE && proctab(i).posix().pgid == target_pgid {
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
///   extra_caps[0] = cap to inject (received at CAP_RECV_SCRATCH)
pub(crate) unsafe fn handle_inject_cap(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        let dst_slot = msg.regs[1];

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
        // Move it into the child slot so the scratch slot is freed for the
        // next injected cap in the same boot sequence.
        let err = trona::invoke::cnode_move(
            child_cn,
            dst_slot,
            crate::CAP_SELF_CSPACE,
            crate::CAP_RECV_SCRATCH,
        );
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
            _lb.dec(if proctab(idx).wait_ready_on_resume { 1 } else { 0 });
            _lb.str(b"\n");
        });

        if proctab(idx).state == PROC_FREE || proctab(idx).state == PROC_ZOMBIE {
            reply.label = crate::TRONA_INVALID_OPERATION;
            return false;
        }

        if proctab(idx).state == PROC_RUNNING {
            reply.label = crate::TRONA_OK;
            reply.length = 0;
            return false;
        }

        proctab(idx).state = PROC_RUNNING;
        if proctab(idx).is_posix() {
            proctab(idx).posix_mut().stop_status = 0;
        }

        if proctab(idx).wait_ready_on_resume {
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] pm_resume immediate-resume-for-readiness pid=");
                _lb.hex(pid as u64);
                _lb.str(b"\n");
            });
            let err = trona::invoke::tcb_resume(proctab(idx).tcb_cap);
            if err != 0 {
                proctab(idx).state = PROC_STOPPED;
                reply.label = crate::TRONA_INVALID_OPERATION;
                return false;
            }

            proctab(idx).wait_ready_on_resume = false;
            // ready_ntfn and ready_timeout_ns already set from spawn time
            if crate::readiness::defer_readiness(idx) {
                trona::udebug!(|_lb| {
                    _lb.str(b"[PROCMGR] pm_resume deferred-readiness-reply pid=");
                    _lb.hex(pid as u64);
                    _lb.str(b"\n");
                });
                return true;
            }
            // Defer failed — clear fields, reply immediately
            proctab(idx).ready_ntfn = 0;
            proctab(idx).ready_timeout_ns = 0;
        } else if crate::POST_REPLY_RESUME_TCB == 0 {
            crate::POST_REPLY_RESUME_TCB = proctab(idx).tcb_cap;
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] pm_resume queued-post-reply pid=");
                _lb.hex(pid as u64);
                _lb.str(b" tcb=");
                _lb.hex(proctab(idx).tcb_cap);
                _lb.str(b"\n");
            });
        } else {
            trona::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] WARN: post-reply resume slot busy, resuming immediately\n");
            });
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] pm_resume fallback-immediate pid=");
                _lb.hex(pid as u64);
                _lb.str(b"\n");
            });
            let err = trona::invoke::tcb_resume(proctab(idx).tcb_cap);
            if err != 0 {
                proctab(idx).state = PROC_STOPPED;
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
