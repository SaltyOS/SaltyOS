//! CSpace registration handler (PM_REGISTER).
//!
//! The historical procmgr-side CSpace expansion protocol
//! (`EXPAND_CLIENTS` table + bound-notification badge fan-out + per-child
//! sub-CNode grant via `handle_one_expansion`) was retired alongside
//! init's CSpace redesign: every userspace process now drives its own
//! CSpace expansion through `trona_runtime::core::slot_alloc::self_expand`, which goes
//! straight to rsrcsrv (no procmgr round-trip).
//!
//! All that remains here is `handle_register`, the PM_REGISTER
//! Call-handler that records init-spawned services in procmgr's process
//! table.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::*;

use crate::base::proc_table::{
    NEXT_PID, ProcessState, alloc_proc, find_by_badge, monotonic_now_ns, proctab,
};
use crate::personality::PersonalityKind;

/// Handle PM_REGISTER (Call): register an init-spawned service in the proc table.
/// msg.regs[0] = badge used for this child
/// msg.regs[1] = parent pid (0 if unknown)
/// IPC buffer caps[0] = child's CNode cap (transferred via cap slot)
///
/// The historical third register parameter (`ntfn_slot`) is gone — the
/// procmgr-mediated CSpace expansion bound-notification path was retired
/// when every process started doing its own substrate-side expansion.
pub(crate) unsafe fn handle_register(msg: &TronaMsg, reply: &mut TronaMsg, _badge: u64) {
    let reg_badge = msg.regs[0];
    let parent_pid = if msg.length >= 2 {
        msg.regs[1] as u32
    } else {
        0
    };

    unsafe {
        if parent_pid != 0 && find_by_badge(parent_pid as u64).is_none() {
            if let Some(parent_idx) = alloc_proc() {
                proctab(parent_idx).set_personality_kind(PersonalityKind::Posix);
                proctab(parent_idx).pid = parent_pid;
                proctab(parent_idx).badge = parent_pid as u64;
                proctab(parent_idx).state = ProcessState::Running;
                proctab(parent_idx).start_time_ns = monotonic_now_ns();
            }
        }

        // The CNode cap was transferred to CAP_RECV_SCRATCH by cap transfer.
        let child_cn_scratch = crate::CAP_RECV_SCRATCH;

        // Verify we received a cap by probing it.
        let cn_info = trona_kernel::invoke::cnode_get_info(child_cn_scratch);
        if cn_info.error != 0 {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        // Move CNode cap from scratch to a permanent allocator-managed slot.
        // Must use cnode_move (not cnode_copy) to avoid creating a CDT child,
        // which would prevent cnode_delete(scratch) from clearing the slot.
        let cn_perm = match (&mut *(&raw mut crate::ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => {
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return;
            }
        };
        let err = trona_kernel::invoke::cnode_move(
            crate::CAP_SELF_CSPACE,
            cn_perm,
            crate::CAP_SELF_CSPACE,
            child_cn_scratch,
        );
        if err != 0 {
            (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(cn_perm);
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        let ci = match alloc_proc() {
            Some(i) => i,
            None => {
                trona_kernel::invoke::cnode_delete(crate::CAP_SELF_CSPACE, cn_perm);
                (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(cn_perm);
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        proctab(ci).set_personality_kind(PersonalityKind::Posix);
        proctab(ci).pid = NEXT_PID;
        NEXT_PID += 1;
        let new_pid = proctab(ci).pid;
        proctab(ci).ppid = parent_pid;
        proctab(ci).completion_observer_pid = parent_pid;
        proctab(ci).sid = new_pid;
        proctab(ci).pgid = new_pid;
        proctab(ci).badge = reg_badge;
        proctab(ci).state = ProcessState::Running;
        proctab(ci).cnode_cap = cn_perm;

        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] PM_REGISTER badge=");
            _lb.hex(reg_badge);
            _lb.str(b" pid=");
            _lb.hex(proctab(ci).pid as u64);
            _lb.str(b"\n");
        });

        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ci).pid as u64;
    }
}
