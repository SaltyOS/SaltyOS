//! Exit and wait handlers
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

use salty::ipc;
use salty::serial::LineBuf;
use salty::types::*;

use crate::proc_table::{
    alloc_proc, cleanup_proc_resources, find_by_badge, find_by_pid, proctab, proctab_cap,
    MAX_NAME_LEN, PROC_FREE, PROC_RUNNING, PROC_STOPPED, PROC_ZOMBIE, SIG_DISP_CATCH,
};

fn signal_ntfn(ntfn: Cap, bits: u64) {
    salty::syscall::syscall(salty::SYS_SIGNAL, ntfn, bits, 0, 0, 0, 0);
}

/// Respawn a process by crafting a synthetic POSIX_PM_SPAWN message.
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

        let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] Respawning: ");
        lb.bytes(&binary[..name_len]);
        lb.str(b"\n");
        lb.flush();

        // Build synthetic spawn message
        let mut msg = SaltyMsg::zeroed();
        msg.label = super::PM_SPAWN;
        let packed_name_words = (name_len as u64 + 7) / 8;
        msg.regs[0] = name_len as u64;
        // policy: SPAWN_READY_IMMEDIATE, no initrd, no display, default cnode
        msg.regs[1] = salty::SPAWN_READY_IMMEDIATE;
        msg.regs[2] = 0; // timeout
        msg.regs[3] = salty::SPAWN_FLAG_RESPAWN; // preserve respawn flag
        msg.regs[4] = 0; // no spawn args
        msg.length = 5 + packed_name_words;

        let dst = &raw mut msg.regs[5] as *mut u8;
        for i in 0..name_len {
            *dst.add(i) = binary[i];
        }

        let mut reply = SaltyMsg::zeroed();
        let alloc = &mut *(&raw mut super::ALLOCATOR);
        super::spawn_tx::handle_spawn_tx(&msg, &mut reply, 0, alloc);

        if reply.label == super::SALTY_OK {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] Respawned PID=");
            lb.hex(reply.regs[0]);
            lb.str(b"\n");
            lb.flush();
        } else {
            // Retry once after a short delay
            salty::serial::serial_puts(b"[PROCMGR] Respawn failed, retrying...\n");
            salty::syscall::syscall(salty::SYS_NANOSLEEP, 100_000_000, 0, 0, 0, 0, 0);
            let mut reply2 = SaltyMsg::zeroed();
            super::spawn_tx::handle_spawn_tx(&msg, &mut reply2, 0, alloc);
            if reply2.label != super::SALTY_OK {
                salty::serial::serial_puts(b"[PROCMGR] Respawn retry failed\n");
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
        let alloc = &mut *(&raw mut super::ALLOCATOR);

        // Free any outstanding waiter reply slots
        if proctab(idx).waiter_reply != 0 {
            salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, proctab(idx).waiter_reply);
            alloc.free_single_slot(proctab(idx).waiter_reply);
            proctab(idx).waiter_reply = 0;
        }
        if proctab(idx).any_waiter_reply != 0 {
            salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, proctab(idx).any_waiter_reply);
            alloc.free_single_slot(proctab(idx).any_waiter_reply);
            proctab(idx).any_waiter_reply = 0;
        }

        // Free primary slot range bitmap (caps are revoked by cleanup_proc_resources)
        if proctab(idx).slot_count > 0 {
            alloc.free_slots(proctab(idx).slot_base, proctab(idx).slot_count as usize);
            // Don't zero slot_base/slot_count here -- cleanup_proc_resources
            // still needs them for cap revocation. They get zeroed there.
        }
    }
}

pub(crate) unsafe fn handle_exit(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let raw_code = msg.regs[0] as i32;
        let exit_code = raw_code << 8;

        let Some(idx) = find_by_badge(badge) else {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] EXIT from unknown badge=");
            lb.hex(badge);
            lb.str(b"\n");
            lb.flush();
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] EXIT PID=");
            lb.hex(proctab(idx).pid as u64);
            lb.str(b" code=");
            lb.hex(exit_code as u64);
            lb.str(b"\n");
            lb.flush();
        }

        // Deregister from mmsrv if registered
        if proctab(idx).mmsrv_registered {
            let mut mm_msg = SaltyMsg::zeroed();
            let mut mm_reply = SaltyMsg::zeroed();
            mm_msg.label = salty::consts::MM_DEREGISTER;
            mm_msg.length = 1;
            mm_msg.regs[0] = badge;
            let _ = ipc::call_ctx(
                super::ipc_ctx(),
                super::CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
        }

        // Ensure VFS tears down all per-client fd state/refcounts for this badge.
        // Use non-blocking send so PM_EXIT path cannot wedge waiting for VFS reply.
        let mut vfs_msg = SaltyMsg::zeroed();
        vfs_msg.label = salty::consts::POSIX_VFS_CLIENT_EXIT;
        vfs_msg.length = 1;
        vfs_msg.regs[0] = badge;
        let mut vfs_err = 0i32;
        let mut vfs_sent = false;
        for _ in 0..16 {
            vfs_err = ipc::nbsend_ctx(super::ipc_ctx(), super::CAP_VFS_EP, &raw const vfs_msg);
            if vfs_err == 0 {
                vfs_sent = true;
                break;
            }
            salty::syscall::syscall(salty::SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
        if !vfs_sent {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] EXIT: VFS client-exit sync failed err=");
            lb.hex(vfs_err as u64);
            lb.str(b" badge=");
            lb.hex(badge);
            lb.str(b"\n");
            lb.flush();
        }

        proctab(idx).state = PROC_ZOMBIE;
        proctab(idx).exit_code = exit_code;

        // Save respawn info before cleanup clears it
        let should_respawn = proctab(idx).respawn;
        let mut saved_binary = [0u8; MAX_NAME_LEN];
        if should_respawn {
            saved_binary = proctab(idx).respawn_binary;
        }

        let susp_err = salty::invoke::tcb_suspend_retry(proctab(idx).tcb_cap, 16);
        if susp_err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] WARN: tcb_suspend failed in exit PID=");
            lb.hex(proctab(idx).pid as u64);
            lb.str(b"\n");
            lb.flush();
        }

        // Deliver SIGCHLD to parent
        let ppid = proctab(idx).ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if proctab(pi).state == PROC_RUNNING
                && proctab(pi).signal_ntfn != 0
                && proctab(pi).sig_disposition[super::PM_SIGCHLD] == SIG_DISP_CATCH
            {
                signal_ntfn(proctab(pi).signal_ntfn, 1u64 << super::PM_SIGCHLD);
            }
        }

        // Wake specific-child waiter
        if proctab(idx).waiter_reply != 0 {
            {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] Waking waiter for PID=");
                lb.hex(proctab(idx).pid as u64);
                lb.str(b"\n");
                lb.flush();
            }

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
            if should_respawn {
                respawn_process(&saved_binary);
            }
            return;
        }

        // Wake any-child waiter on parent
        let mut reaped = false;
        if let Some(pi) = find_by_pid(ppid) {
            if proctab(pi).waiting_for_any != 0 {
                {
                    let mut lb = LineBuf::new();
                    lb.str(b"[PROCMGR] Waking any-waiter parent PID=");
                    lb.hex(proctab(pi).pid as u64);
                    lb.str(b" for child PID=");
                    lb.hex(proctab(idx).pid as u64);
                    lb.str(b"\n");
                    lb.flush();
                }

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
                reaped = true;
            }
        }

        // Respawnable process with no waiter: reap immediately and respawn
        if !reaped && should_respawn {
            free_proc_alloc_slots(idx);
            cleanup_proc_resources(idx, super::CAP_SELF_CSPACE);
            reaped = true;
        }

        if reaped && should_respawn {
            respawn_process(&saved_binary);
        }
    }
}

/// Returns true if caller is blocked (skip reply).
pub(crate) unsafe fn handle_wait(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let child_pid = msg.regs[0] as u32;
        let options = msg.regs[1] as u32;

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = super::SALTY_NOT_FOUND;
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
                reply.label = super::SALTY_OK;
                reply.length = 2;
                reply.regs[0] = proctab(zi).exit_code as u64;
                reply.regs[1] = proctab(zi).pid as u64;
                free_proc_alloc_slots(zi);
                cleanup_proc_resources(zi, super::CAP_SELF_CSPACE);
                return false;
            }

            if (options & super::WUNTRACED) != 0 {
                if let Some(si) = stopped_idx {
                    reply.label = super::SALTY_OK;
                    reply.length = 2;
                    reply.regs[0] = proctab(si).stop_status as u64;
                    reply.regs[1] = proctab(si).pid as u64;
                    return false;
                }
            }

            if !has_living {
                reply.label = super::SALTY_NOT_FOUND;
                return false;
            }

            if (options & super::WNOHANG) != 0 {
                reply.label = super::SALTY_OK;
                reply.length = 2;
                reply.regs[0] = 0;
                reply.regs[1] = 0;
                return false;
            }

            // Block
            let reply_slot = match (&mut *(&raw mut super::ALLOCATOR)).alloc_single_slot() {
                Some(s) => s,
                None => {
                    reply.label = super::SALTY_OUT_OF_MEMORY;
                    return false;
                }
            };
            let err = salty::invoke::cnode_save_caller(super::CAP_SELF_CSPACE, reply_slot);
            if err != 0 {
                (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(reply_slot);
                reply.label = super::SALTY_OUT_OF_MEMORY;
                return false;
            }
            proctab(caller_idx).any_waiter_reply = reply_slot;
            proctab(caller_idx).waiting_for_any = 1;
            {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] WAIT(-1) blocking parent PID=");
                lb.hex(caller_pid as u64);
                lb.str(b"\n");
                lb.flush();
            }
            return true;
        }

        // waitpid(specific child)
        let Some(ci) = find_by_pid(child_pid) else {
            reply.label = super::SALTY_NOT_FOUND;
            return false;
        };
        if proctab(ci).ppid != caller_pid {
            reply.label = super::SALTY_NOT_FOUND;
            return false;
        }

        if proctab(ci).state == PROC_ZOMBIE {
            reply.label = super::SALTY_OK;
            reply.length = 2;
            reply.regs[0] = proctab(ci).exit_code as u64;
            reply.regs[1] = proctab(ci).pid as u64;
            free_proc_alloc_slots(ci);
            cleanup_proc_resources(ci, super::CAP_SELF_CSPACE);
            return false;
        }

        if (options & super::WUNTRACED) != 0 && proctab(ci).state == PROC_STOPPED {
            reply.label = super::SALTY_OK;
            reply.length = 2;
            reply.regs[0] = proctab(ci).stop_status as u64;
            reply.regs[1] = proctab(ci).pid as u64;
            return false;
        }

        if (options & super::WNOHANG) != 0 {
            reply.label = super::SALTY_OK;
            reply.length = 2;
            reply.regs[0] = 0;
            reply.regs[1] = 0;
            return false;
        }

        // Block
        let reply_slot = match (&mut *(&raw mut super::ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => {
                reply.label = super::SALTY_OUT_OF_MEMORY;
                return false;
            }
        };
        let err = salty::invoke::cnode_save_caller(super::CAP_SELF_CSPACE, reply_slot);
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] save_caller failed for WAIT, err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(reply_slot);
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return false;
        }
        proctab(ci).waiter_reply = reply_slot;
        proctab(ci).waiter_pid = caller_pid;
        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] WAIT blocking for PID=");
            lb.hex(child_pid as u64);
            lb.str(b"\n");
            lb.flush();
        }
        true
    }
}
