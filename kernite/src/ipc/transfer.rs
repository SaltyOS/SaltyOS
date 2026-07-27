// SPDX-License-Identifier: GPL-2.0-only
//! Cap-transfer primitives shared by `MessagePipe` syscalls.
//!
//! Owns the install-record type (`InstalledCap`) and the low-level
//! CNode rollback helper used during partial-install recovery.
//! Higher-level syscall integration (reading the IPC buffer, resolving
//! receive slots, driving the rollback decision) stays in
//! `syscall::pipe` since it depends on the current TCB and the
//! syscall-layer error mapping.

use crate::cap::{CapSlot, INVALID_SLOT};
use crate::ipc::message_pipe::{CarrierSlots, MP_MSG_CAPS};

/// Identity of a cap installed into a receiver's CSpace by
/// MessagePipe carrier delivery.
///
/// The triple `(dest_addr, slot, generation)` survives across the
/// CAP_LOCK release that may sit between install and any subsequent
/// rollback decision. `slot` is the global cap slot the sender
/// originally pushed; `generation` is the slot's reuse counter at
/// the moment of install. Comparing both before any rollback
/// `take_ref` defends against a third-party that may have freed and
/// re-allocated the same global slot to an unrelated capability —
/// rollback skips that entry instead of stealing whatever
/// unrelated capability happens to occupy the destination now.
#[derive(Clone, Copy)]
pub(crate) struct InstalledCap {
    pub dest_addr: u64,
    pub slot: CapSlot,
    pub generation: u64,
}

impl InstalledCap {
    pub(crate) const fn null() -> Self {
        Self {
            dest_addr: INVALID_SLOT as u64,
            slot: INVALID_SLOT,
            generation: 0,
        }
    }
}

/// CAP_LOCK-held helper: undo a partially-completed install by taking
/// each successfully-installed `CapRef` back out of the receiver
/// CNode and putting it back into the carrier array. The outer
/// rollback path then handles refunding the carriers (typically by
/// pushing them back into the originating `MessagePipeCore` ring or
/// by dropping them via `CDT::delete_capability`).
///
/// # Safety
/// Caller must hold `CAP_LOCK`. `sites[i]` must be a `(idx, cnode)`
/// pair recorded at the corresponding successful install in the
/// upper-layer `install_carriers_into_receiver`; passing a stale
/// pair is a UAF against the receiver CNode.
pub(crate) unsafe fn rollback_installed_locked(
    carriers: &mut CarrierSlots,
    sites: &[(usize, *mut crate::cap::CNode); MP_MSG_CAPS],
    count: usize,
) {
    for i in 0..count {
        let (idx, cnode) = sites[i];
        if cnode.is_null() {
            continue;
        }
        if let Some(capref) = unsafe { (&mut *cnode).take_ref(idx) } {
            // Snapshot the slot's reuse epoch under CAP_LOCK so a
            // later free + reuse race in the carrier-disposal path
            // (delete vs. ring re-push) is observable.
            let epoch = crate::cap::get_generation(capref.slot);
            carriers.0[i] = crate::ipc::message_pipe::CarrierEntry {
                slot: capref.slot,
                epoch,
            };
        }
    }
}
