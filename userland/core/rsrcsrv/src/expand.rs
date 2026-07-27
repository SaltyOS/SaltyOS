// SPDX-License-Identifier: GPL-2.0-only
//
//! substrate slot-allocator carve-out. rsrcsrv cannot depend on its own
//! `RSRC_ALLOC` IPC for CSpace expansion (the call would recurse into
//! its own MP_READ loop). Instead it installs this handler before
//! servicing the first request — substrate's `slot_alloc` invokes it
//! directly when the alloc envelope is exhausted, retyping a fresh
//! CNode out of rsrcsrv's local untyped pool and grafting it into
//! the allocator-supplied expansion window.

use trona_kernel::syscall;
use trona_runtime::core::slot_alloc::{
    ExpandProgress, ExternalExpandPlan, commit_external_expand_locked,
};
use uapi::{
    KERNITE_INV_CNODE_DELETE, KERNITE_INV_CNODE_MOVE, KERNITE_INV_CNODE_SET_GUARD,
    KERNITE_OBJ_CNODE,
};

use crate::caps::{CAP_SELF_CSPACE, self_expand_temp_slot};

/// Substrate calls this with the global slot freelist mutex held.
///
/// rsrcsrv cannot issue RSRC_ALLOC to itself, so it retypes a CNode from its
/// own untyped pool, installs it in the runtime allocator's deterministic
/// expansion window, then commits that exact plan back to `slot_alloc`.
pub unsafe fn rsrcsrv_self_expand(plan: ExternalExpandPlan) -> ExpandProgress {
    let temp = self_expand_temp_slot();
    unsafe {
        crate::main_loop::with_state_mut(|state| {
            let chunk_idx =
                match state
                    .untyped
                    .try_retype(KERNITE_OBJ_CNODE, plan.cnode_size_bits, temp)
                {
                    Some(idx) => idx,
                    None => return ExpandProgress::Failed,
                };
            let _ = syscall::invoke(temp, KERNITE_INV_CNODE_SET_GUARD, 0, 0, 0, 0);
            let move_err = syscall::invoke(
                CAP_SELF_CSPACE,
                KERNITE_INV_CNODE_MOVE,
                plan.root_slot,
                CAP_SELF_CSPACE,
                temp,
                0,
            );
            if move_err.error != 0 {
                // The CNode was retyped into `temp` but the move out failed, so
                // it is still a live child of `chunk_idx`. Delete it before
                // releasing the chunk's live count — otherwise the accounting
                // would claim the chunk has drained while the kernel still
                // holds the CNode, and `drain_and_reset` would loop forever on
                // a refused (HasChildren) reset.
                let _ = syscall::invoke(CAP_SELF_CSPACE, KERNITE_INV_CNODE_DELETE, temp, 0, 0, 0);
                state.untyped.release_one(chunk_idx);
                return ExpandProgress::Failed;
            }
            if !commit_external_expand_locked(plan) {
                let _ = syscall::invoke(
                    CAP_SELF_CSPACE,
                    KERNITE_INV_CNODE_DELETE,
                    plan.root_slot,
                    0,
                    0,
                    0,
                );
                state.untyped.release_one(chunk_idx);
                return ExpandProgress::Failed;
            }
            ExpandProgress::Completed
        })
    }
}
