//! Waitpid handler
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::*;

use crate::base::proc_table::{
    cleanup_proc_resources, find_by_badge, find_by_pid, proctab, proctab_cap,
    ProcessState,
};
use crate::lifecycle::exit::free_proc_alloc_slots;

pub(crate) unsafe fn handle_wait(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) -> bool {
    unsafe {
        let child_pid = msg.regs[0] as u32;
        let options = msg.regs[1] as u32;

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return false;
        };
        let caller_pid = proctab(caller_idx).pid;

        // waitpid(-1): wait for any child
        if child_pid == u32::MAX {
            let mut zombie_idx: Option<usize> = None;
            let mut stopped_idx: Option<usize> = None;
            let mut has_living = false;
            let mut _child_count: u32 = 0;

            for i in 0..proctab_cap() {
                if proctab(i).state != ProcessState::Free && proctab(i).ppid == caller_pid {
                    _child_count += 1;
                    if proctab(i).state == ProcessState::Zombie && zombie_idx.is_none() {
                        zombie_idx = Some(i);
                    } else if proctab(i).state == ProcessState::Stopped && stopped_idx.is_none() {
                        stopped_idx = Some(i);
                    }
                    if proctab(i).state == ProcessState::Running || proctab(i).state == ProcessState::Stopped {
                        has_living = true;
                    }
                }
            }
            if let Some(zi) = zombie_idx {
                reply.label = crate::TRONA_OK;
                reply.length = 2;
                reply.regs[0] = proctab(zi).exit_code as u64;
                reply.regs[1] = proctab(zi).pid as u64;
                free_proc_alloc_slots(zi);
                cleanup_proc_resources(zi, crate::CAP_SELF_CSPACE);
                return false;
            }

            if (options & crate::personality::posix::WUNTRACED) != 0 {
                if let Some(si) = stopped_idx {
                    reply.label = crate::TRONA_OK;
                    reply.length = 2;
                    reply.regs[0] = proctab(si).stop_status as u64;
                    reply.regs[1] = proctab(si).pid as u64;
                    return false;
                }
            }

            if !has_living {
                reply.label = crate::TRONA_NOT_FOUND;
                return false;
            }

            if (options & crate::personality::posix::WNOHANG) != 0 {
                reply.label = crate::TRONA_OK;
                reply.length = 2;
                reply.regs[0] = 0;
                reply.regs[1] = 0;
                return false;
            }

            // Block
            let reply_slot = match (&mut *(&raw mut crate::ALLOCATOR)).alloc_single_slot() {
                Some(s) => s,
                None => {
                    reply.label = crate::TRONA_OUT_OF_MEMORY;
                    return false;
                }
            };
            let err = trona::invoke::cnode_save_caller(crate::CAP_SELF_CSPACE, reply_slot);
            if err != 0 {
                (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(reply_slot);
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return false;
            }
            proctab(caller_idx).any_waiter_reply = reply_slot;
            proctab(caller_idx).waiting_for_any = 1;
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] WAIT(-1) blocking parent PID=");
                _lb.hex(caller_pid as u64);
                _lb.str(b"\n");
            });
            return true;
        }

        // waitpid(specific child)
        let Some(ci) = find_by_pid(child_pid) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return false;
        };
        if proctab(ci).ppid != caller_pid {
            reply.label = crate::TRONA_NOT_FOUND;
            return false;
        }

        if proctab(ci).state == ProcessState::Zombie {
            reply.label = crate::TRONA_OK;
            reply.length = 2;
            reply.regs[0] = proctab(ci).exit_code as u64;
            reply.regs[1] = proctab(ci).pid as u64;
            free_proc_alloc_slots(ci);
            cleanup_proc_resources(ci, crate::CAP_SELF_CSPACE);
            return false;
        }

        if (options & crate::personality::posix::WUNTRACED) != 0 && proctab(ci).state == ProcessState::Stopped {
            reply.label = crate::TRONA_OK;
            reply.length = 2;
            reply.regs[0] = proctab(ci).stop_status as u64;
            reply.regs[1] = proctab(ci).pid as u64;
            return false;
        }

        if (options & crate::personality::posix::WNOHANG) != 0 {
            reply.label = crate::TRONA_OK;
            reply.length = 2;
            reply.regs[0] = 0;
            reply.regs[1] = 0;
            return false;
        }

        // Block
        let reply_slot = match (&mut *(&raw mut crate::ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => {
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return false;
            }
        };
        let err = trona::invoke::cnode_save_caller(crate::CAP_SELF_CSPACE, reply_slot);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] save_caller failed for WAIT, err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(reply_slot);
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return false;
        }
        proctab(ci).waiter_reply = reply_slot;
        proctab(ci).waiter_pid = caller_pid;
        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] WAIT blocking for PID=");
            _lb.hex(child_pid as u64);
            _lb.str(b"\n");
        });
        true
    }
}
