//! Exit and wait handlers
//! Moved from crate root module for POSIX subsystem separation.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::ipc;
use trona::types::core::*;

use crate::proc_table::{
    alloc_proc, cleanup_proc_resources, find_by_badge, find_by_pid, proctab, proctab_cap,
    MAX_NAME_LEN, PROC_FREE, PROC_RUNNING, PROC_STOPPED, PROC_ZOMBIE, SIG_DISP_CATCH,
};

fn signal_ntfn(ntfn: Cap, bits: u64) {
    trona::syscall::syscall(trona::SYS_SIGNAL, ntfn, bits, 0, 0, 0, 0);
}

/// Respawn a process by crafting a synthetic PM_SPAWN message.
/// Called from handle_exit when the process has the respawn flag set.
unsafe fn respawn_process(binary: &[u8; MAX_NAME_LEN]) {
    unsafe {
        let mut name_len = 0usize;
        while name_len < MAX_NAME_LEN && binary[name_len] != 0 {
            name_len += 1;
        }
        if name_len == 0 {
            return;
        }

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] Respawning: ");
            _lb.bytes(&binary[..name_len]);
            _lb.str(b"\n");
        });

        // Build synthetic spawn message
        let mut msg = TronaMsg::zeroed();
        msg.label = crate::PM_SPAWN;
        let packed_name_words = (name_len as u64 + 7) / 8;
        msg.regs[0] = name_len as u64;
        // policy: SPAWN_READY_IMMEDIATE, no initrd, no display, default cnode
        msg.regs[1] = trona::SPAWN_READY_IMMEDIATE;
        msg.regs[2] = 0; // timeout
        msg.regs[3] = trona::SPAWN_FLAG_RESPAWN; // preserve respawn flag
        msg.regs[4] = 0; // no spawn args
        msg.length = 5 + packed_name_words;

        let dst = &raw mut msg.regs[5] as *mut u8;
        for i in 0..name_len {
            *dst.add(i) = binary[i];
        }

        let mut reply = TronaMsg::zeroed();
        let alloc = &mut *(&raw mut crate::ALLOCATOR);
        let _ = crate::spawn_tx::handle_spawn_tx(&msg, &mut reply, 0, alloc);

        if reply.label == crate::TRONA_OK {
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] Respawned PID=");
                _lb.hex(reply.regs[0]);
                _lb.str(b"\n");
            });
        } else {
            // Retry once after a short delay
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] Respawn failed, retrying...\n");
            });
            trona::syscall::syscall(trona::SYS_NANOSLEEP, 100_000_000, 0, 0, 0, 0, 0);
            let mut reply2 = TronaMsg::zeroed();
            let _ = crate::spawn_tx::handle_spawn_tx(&msg, &mut reply2, 0, alloc);
            if reply2.label != crate::TRONA_OK {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] Respawn retry failed\n");
                });
            }
        }
    }
}

/// Free allocator-tracked bitmap slots for a process. Must be called BEFORE
/// cleanup_proc_resources so that slot_base/slot_count are still valid for
/// cap revocation.
///
/// This function:
/// 1. Frees any outstanding waiter reply slots (revoke + free bitmap)
/// 2. Revokes + frees the exec frame range (separate from primary slots)
/// 3. Frees the primary slot range bitmap (caps revoked by cleanup_proc_resources)
pub(crate) unsafe fn free_proc_alloc_slots(idx: usize) {
    unsafe {
        let alloc = &mut *(&raw mut crate::ALLOCATOR);

        // Free any outstanding waiter reply slots (POSIX waitpid only)
        if proctab(idx).is_posix() {
            if proctab(idx).posix().waiter_reply != 0 {
                let wr = proctab(idx).posix().waiter_reply;
                trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, wr);
                alloc.free_single_slot(wr);
                proctab(idx).posix_mut().waiter_reply = 0;
            }
            if proctab(idx).posix().any_waiter_reply != 0 {
                let awr = proctab(idx).posix().any_waiter_reply;
                trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, awr);
                alloc.free_single_slot(awr);
                proctab(idx).posix_mut().any_waiter_reply = 0;
            }
        }

        // Free any outstanding deferred readiness reply slot
        if proctab(idx).pending_ready_reply != 0 {
            let pr = proctab(idx).pending_ready_reply;
            trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, pr);
            alloc.free_single_slot(pr);
            proctab(idx).pending_ready_reply = 0;
        }

        // Free primary slot range bitmap (caps are revoked by cleanup_proc_resources)
        if proctab(idx).slot_count > 0 {
            alloc.free_slots(proctab(idx).slot_base, proctab(idx).slot_count as usize);
            // Don't zero slot_base/slot_count here -- cleanup_proc_resources
            // still needs them for cap revocation. They get zeroed there.
        }
    }
}

pub(crate) unsafe fn handle_exit(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let raw_code = msg.regs[0] as i32;
        let exit_code = raw_code << 8;

        let Some(idx) = find_by_badge(badge) else {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] EXIT from unknown badge=");
                _lb.hex(badge);
                _lb.str(b"\n");
            });
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] EXIT PID=");
            _lb.hex(proctab(idx).pid as u64);
            _lb.str(b" code=");
            _lb.hex(exit_code as u64);
            _lb.str(b"\n");
        });

        // Deregister from mmsrv if registered
        if proctab(idx).mmsrv_registered {
            let tcb_cap = proctab(idx).tcb_cap;
            let pid = proctab(idx).pid;
            crate::spawn_tx::clear_fault_handler(tcb_cap, pid);
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona::protocol::MM_DEREGISTER;
            mm_msg.length = 1;
            mm_msg.regs[0] = badge;
            let _ = ipc::call_ctx(
                crate::ipc_ctx(),
                crate::CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
        }

        // Ensure VFS tears down all per-client fd state/refcounts for this badge.
        // Use non-blocking send so PM_EXIT path cannot wedge waiting for VFS reply.
        let mut vfs_msg = TronaMsg::zeroed();
        vfs_msg.label = trona::protocol::VFS_CLIENT_EXIT;
        vfs_msg.length = 1;
        vfs_msg.regs[0] = badge;
        let mut vfs_err = 0i32;
        let mut vfs_sent = false;
        for _ in 0..16 {
            vfs_err = ipc::nbsend_ctx(crate::ipc_ctx(), crate::CAP_VFS_EP, &raw const vfs_msg);
            if vfs_err == 0 {
                vfs_sent = true;
                break;
            }
            trona::syscall::syscall(trona::SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
        if !vfs_sent {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] EXIT: VFS client-exit sync failed err=");
                _lb.hex(vfs_err as u64);
                _lb.str(b" badge=");
                _lb.hex(badge);
                _lb.str(b"\n");
            });
        }

        // If a readiness wait is pending, the child died before signaling ready.
        // Reply TRONA_BUSY to the original spawn/resume caller.
        if proctab(idx).pending_ready_reply != 0 {
            let reply_slot = proctab(idx).pending_ready_reply;
            let mut ready_reply = TronaMsg::zeroed();
            ready_reply.label = trona::TRONA_BUSY;
            let _ = ipc::send_ctx(crate::ipc_ctx(), reply_slot, &raw const ready_reply);
            trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, reply_slot);
            (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(reply_slot);
            proctab(idx).pending_ready_reply = 0;
            proctab(idx).pending_ready_deadline_ns = 0;
        }

        proctab(idx).state = PROC_ZOMBIE;
        proctab(idx).exit_code = exit_code;

        // Save respawn info before cleanup clears it
        let should_respawn = proctab(idx).respawn;
        let mut saved_binary = [0u8; MAX_NAME_LEN];
        if should_respawn {
            saved_binary = proctab(idx).respawn_binary;
        }

        let susp_err = trona::invoke::tcb_suspend_retry(proctab(idx).tcb_cap, 64);
        if susp_err != 0 {
            trona::syscall::syscall(trona::SYS_NANOSLEEP, 2_000_000, 0, 0, 0, 0, 0);
            let _ = trona::invoke::tcb_suspend_retry(proctab(idx).tcb_cap, 64);
        }
        trona::syscall::syscall(trona::SYS_YIELD, 0, 0, 0, 0, 0, 0);

        // Deliver SIGCHLD to parent (parent is always POSIX — init)
        let ppid = proctab(idx).ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if proctab(pi).is_posix()
                && proctab(pi).state == PROC_RUNNING
                && proctab(pi).posix().signal_ntfn != 0
                && proctab(pi).posix().sig_disposition[super::PM_SIGCHLD] == SIG_DISP_CATCH
            {
                signal_ntfn(proctab(pi).posix().signal_ntfn, 1u64 << super::PM_SIGCHLD);
            }
        }

        // Wake specific-child waiter (POSIX waitpid only)
        if proctab(idx).is_posix() && proctab(idx).posix().waiter_reply != 0 {
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] Waking waiter for PID=");
                _lb.hex(proctab(idx).pid as u64);
                _lb.str(b"\n");
            });

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
            let preserve_zombie = send_err != 0 && parent_alive;
            if !preserve_zombie {
                // Reply delivered — safe to reap zombie
                free_proc_alloc_slots(idx);
                cleanup_proc_resources(idx, crate::CAP_SELF_CSPACE);
                if should_respawn {
                    respawn_process(&saved_binary);
                }
            }
            return;
        }

        // Wake any-child waiter on parent (POSIX waitpid(-1) only)
        let mut reaped = false;
        if let Some(pi) = find_by_pid(ppid) {
            if proctab(pi).is_posix() && proctab(pi).posix().waiting_for_any != 0 {
                trona::udebug!(|_lb| {
                    _lb.str(b"[PROCMGR] Waking any-waiter parent PID=");
                    _lb.hex(proctab(pi).pid as u64);
                    _lb.str(b" for child PID=");
                    _lb.hex(proctab(idx).pid as u64);
                    _lb.str(b"\n");
                });

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
                let preserve_zombie = send_err != 0;
                if !preserve_zombie {
                    // Reply delivered — safe to reap zombie
                    free_proc_alloc_slots(idx);
                    cleanup_proc_resources(idx, crate::CAP_SELF_CSPACE);
                    reaped = true;
                }
                // If the wake fails, the parent is still alive but no longer
                // blocked on the saved reply cap. Keep the zombie so the
                // parent's retrying waitpid(-1) can collect it.
            }
        }

        // Respawnable process with no waiter: reap immediately and respawn
        if !reaped && should_respawn {
            free_proc_alloc_slots(idx);
            cleanup_proc_resources(idx, crate::CAP_SELF_CSPACE);
            reaped = true;
        }

        if reaped && should_respawn {
            respawn_process(&saved_binary);
        }
    }
}

/// Returns true if caller is blocked (skip reply).
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
                if proctab(i).state != PROC_FREE && proctab(i).ppid == caller_pid {
                    _child_count += 1;
                    if proctab(i).state == PROC_ZOMBIE && zombie_idx.is_none() {
                        zombie_idx = Some(i);
                    } else if proctab(i).state == PROC_STOPPED && stopped_idx.is_none() {
                        stopped_idx = Some(i);
                    }
                    if proctab(i).state == PROC_RUNNING || proctab(i).state == PROC_STOPPED {
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

            if (options & super::WUNTRACED) != 0 {
                if let Some(si) = stopped_idx {
                    reply.label = crate::TRONA_OK;
                    reply.length = 2;
                    reply.regs[0] = proctab(si).posix().stop_status as u64;
                    reply.regs[1] = proctab(si).pid as u64;
                    return false;
                }
            }

            if !has_living {
                reply.label = crate::TRONA_NOT_FOUND;
                return false;
            }

            if (options & super::WNOHANG) != 0 {
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
            proctab(caller_idx).posix_mut().any_waiter_reply = reply_slot;
            proctab(caller_idx).posix_mut().waiting_for_any = 1;
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

        if proctab(ci).state == PROC_ZOMBIE {
            reply.label = crate::TRONA_OK;
            reply.length = 2;
            reply.regs[0] = proctab(ci).exit_code as u64;
            reply.regs[1] = proctab(ci).pid as u64;
            free_proc_alloc_slots(ci);
            cleanup_proc_resources(ci, crate::CAP_SELF_CSPACE);
            return false;
        }

        if (options & super::WUNTRACED) != 0 && proctab(ci).state == PROC_STOPPED {
            reply.label = crate::TRONA_OK;
            reply.length = 2;
            reply.regs[0] = proctab(ci).posix().stop_status as u64;
            reply.regs[1] = proctab(ci).pid as u64;
            return false;
        }

        if (options & super::WNOHANG) != 0 {
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
        proctab(ci).posix_mut().waiter_reply = reply_slot;
        proctab(ci).posix_mut().waiter_pid = caller_pid;
        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] WAIT blocking for PID=");
            _lb.hex(child_pid as u64);
            _lb.str(b"\n");
        });
        true
    }
}
