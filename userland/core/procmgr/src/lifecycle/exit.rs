//! Exit handler and process cleanup
//! SPDX-License-Identifier: GPL-2.0-only

use trona::ipc;
use trona::types::core::*;

use crate::base::proc_table::{
    cleanup_proc_resources, find_by_badge, find_by_pid, proctab, ProcessState, MAX_NAME_LEN,
    SIG_DISP_CATCH,
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
        let _ = crate::lifecycle::spawn::handle_spawn_tx(&msg, &mut reply, 0, alloc);

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
            let _ = crate::lifecycle::spawn::handle_spawn_tx(&msg, &mut reply2, 0, alloc);
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

        // Free any outstanding waiter reply slots.
        if proctab(idx).waiter_reply != 0 {
            let wr = proctab(idx).waiter_reply;
            trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, wr);
            alloc.free_single_slot(wr);
            proctab(idx).waiter_reply = 0;
        }
        if proctab(idx).any_waiter_reply != 0 {
            let awr = proctab(idx).any_waiter_reply;
            trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, awr);
            alloc.free_single_slot(awr);
            proctab(idx).any_waiter_reply = 0;
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

/// Unified teardown sequence. Called from handle_exit, terminate_proc,
/// and complete_readiness_timeout.
pub(crate) unsafe fn core_exit_sequence(idx: usize, exit_code: i32) {
    unsafe {
        let p = proctab(idx);
        if matches!(
            p.state,
            ProcessState::Exiting | ProcessState::Zombie | ProcessState::Free
        ) {
            return;
        }
        let badge = p.badge;
        let kind = p.personality_kind();
        p.state = ProcessState::Exiting;

        // 1. Suspend TCB while cap is still live
        let _ = trona::invoke::tcb_suspend(p.tcb_cap);

        // 2. Cancel pending readiness wait
        if p.pending_ready_reply != 0 {
            let reply_slot = p.pending_ready_reply;
            let mut ready_reply = TronaMsg::zeroed();
            ready_reply.label = trona::TRONA_BUSY;
            let _ = ipc::send_ctx(crate::ipc_ctx(), reply_slot, &raw const ready_reply);
            trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, reply_slot);
            (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(reply_slot);
            p.pending_ready_reply = 0;
            p.pending_ready_deadline_ns = 0;
            crate::base::readiness::free_readiness_bit(p.ready_badge_bit);
            p.ready_badge_bit = crate::base::readiness::BIT_NONE;
        }

        // 3. Deregister from mmsrv
        if p.mmsrv_registered {
            let _ = crate::base::mmsrv_ipc::quiesce_and_deregister_mmsrv_client(
                p.tcb_cap, p.pid, badge,
            );
            p.mmsrv_registered = false;
        }

        // 4. Personality pre-teardown (Win32 provider exit)
        kind.pre_teardown(badge);

        // 5. Core resource reclamation
        let _ = crate::base::alloc::reclaim_owner(trona::caps::rsrcsrv_ep(), badge);
        crate::lifecycle::thread::drop_all_threads(idx);
        crate::base::cspace::deregister_client(badge);

        // 6. Personality post-teardown (VFS client exit)
        kind.post_teardown(badge);

        // 7. Zombie transition
        proctab(idx).state = ProcessState::Zombie;
        proctab(idx).exit_code = exit_code;

        // 8. Save respawn info before potential reap
        let should_respawn = proctab(idx).respawn;
        let mut saved_binary = [0u8; MAX_NAME_LEN];
        if should_respawn {
            saved_binary = proctab(idx).respawn_binary;
        }

        // 9. SIGCHLD to parent
        let ppid = proctab(idx).ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if proctab(pi).is_posix()
                && proctab(pi).state == ProcessState::Running
                && proctab(pi).signal_ntfn != 0
                && proctab(pi).posix().sig_disposition[crate::personality::posix::PM_SIGCHLD]
                    == SIG_DISP_CATCH
            {
                signal_ntfn(
                    proctab(pi).signal_ntfn,
                    1u64 << crate::personality::posix::PM_SIGCHLD,
                );
            }
        }

        // 10. Wake waiters and reap
        wake_waiters_and_maybe_reap(idx, should_respawn, &saved_binary);
    }
}

unsafe fn wake_waiters_and_maybe_reap(
    idx: usize,
    should_respawn: bool,
    saved_binary: &[u8; MAX_NAME_LEN],
) {
    unsafe {
        let exit_code = proctab(idx).exit_code;
        let ppid = proctab(idx).ppid;

        // Specific-child waiter
        if proctab(idx).waiter_reply != 0 {
            let mut wake = TronaMsg::zeroed();
            wake.label = crate::TRONA_OK;
            wake.length = 2;
            wake.regs[0] = exit_code as u64;
            wake.regs[1] = proctab(idx).pid as u64;

            let waiter_cap = proctab(idx).waiter_reply;
            let send_err = ipc::send_ctx(crate::ipc_ctx(), waiter_cap, &raw const wake);
            trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, waiter_cap);
            (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(waiter_cap);
            proctab(idx).waiter_reply = 0;
            proctab(idx).waiter_pid = 0;
            let parent_alive = find_by_pid(ppid).is_some();
            if send_err == 0 || !parent_alive {
                free_proc_alloc_slots(idx);
                cleanup_proc_resources(idx, crate::CAP_SELF_CSPACE);
                if should_respawn {
                    respawn_process(saved_binary);
                }
            }
            return;
        }

        // Any-child waiter on parent
        let mut reaped = false;
        if let Some(pi) = find_by_pid(ppid) {
            if proctab(pi).waiting_for_any != 0 {
                let mut wake = TronaMsg::zeroed();
                wake.label = crate::TRONA_OK;
                wake.length = 2;
                wake.regs[0] = exit_code as u64;
                wake.regs[1] = proctab(idx).pid as u64;

                let waiter_cap = proctab(pi).any_waiter_reply;
                let send_err = ipc::send_ctx(crate::ipc_ctx(), waiter_cap, &raw const wake);
                trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, waiter_cap);
                (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(waiter_cap);
                proctab(pi).any_waiter_reply = 0;
                proctab(pi).waiting_for_any = 0;
                if send_err == 0 {
                    free_proc_alloc_slots(idx);
                    cleanup_proc_resources(idx, crate::CAP_SELF_CSPACE);
                    reaped = true;
                }
            }
        }

        if !reaped && should_respawn {
            free_proc_alloc_slots(idx);
            cleanup_proc_resources(idx, crate::CAP_SELF_CSPACE);
            reaped = true;
        }

        if reaped && should_respawn {
            respawn_process(saved_binary);
        }
    }
}

pub(crate) unsafe fn handle_exit(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let raw_code = msg.regs[0] as i32;
        let exit_code = raw_code << 8;

        let Some(idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        core_exit_sequence(idx, exit_code);
    }
}
