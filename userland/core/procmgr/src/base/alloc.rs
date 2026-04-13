//! Procmgr's slot reservation + rsrcsrv-backed object allocation helper.
//!
//! procmgr does not own any untyped capabilities of its own. All kernel
//! object allocation is delegated to rsrcsrv via the RES_* protocol; this
//! module is responsible only for:
//!
//!  - Reserving contiguous CSpace slot ranges in procmgr's own CNode.
//!  - Realizing kernel objects (TCB / VSpace / CNode / SC / Endpoint /
//!    Notification / Frame / MO) into reserved slots by calling rsrcsrv with
//!    `owner_id = child_pid` so the resulting handles are accounted to the
//!    child being spawned.
//!  - Tracking (slot, handle) pairs so a spawn transaction can rollback by
//!    sending RES_FREE_HANDLE for every realized object.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::Cap;
use trona::types::TronaMsg;

/// Maximum objects tracked explicitly per reservation. Rollback also sweeps
/// the full reserved slot range defensively, so this limit is best-effort.
const MAX_RESERVE_OBJECTS: usize = 128;

// ---- Data structures ----

#[derive(Clone, Copy)]
struct ReservedObject {
    /// Absolute CSpace slot in procmgr's own CNode where the cap landed.
    slot: Cap,
    /// rsrcsrv handle for this object — used by RES_FREE_HANDLE on rollback.
    handle: u64,
    committed: bool,
}

impl ReservedObject {
    const fn empty() -> Self {
        ReservedObject {
            slot: 0,
            handle: 0,
            committed: false,
        }
    }
}

struct Reservation {
    active: bool,
    /// Absolute base slot in procmgr's CSpace.
    slot_base: Cap,
    /// Number of slots reserved.
    slot_count: usize,
    /// rsrcsrv owner_id — child pid that all allocations in this reservation
    /// are accounted to.
    owner_id: u64,
    objects: [ReservedObject; MAX_RESERVE_OBJECTS],
    object_count: usize,
    /// Next slot offset within the reservation for sequential allocation.
    next_offset: usize,
}

impl Reservation {
    const fn empty() -> Self {
        Reservation {
            active: false,
            slot_base: 0,
            slot_count: 0,
            owner_id: 0,
            objects: {
                const E: ReservedObject = ReservedObject::empty();
                [E; MAX_RESERVE_OBJECTS]
            },
            object_count: 0,
            next_offset: 0,
        }
    }
}

// ===========================================================================
// Allocator
// ===========================================================================

pub struct Allocator {
    reservation: Reservation,
    cap_self_cspace: Cap,
}

impl Allocator {
    pub const fn new() -> Self {
        Allocator {
            reservation: Reservation::empty(),
            cap_self_cspace: 0,
        }
    }

    /// Initialize the allocator. Call once at procmgr startup.
    pub fn init(&mut self, cap_self_cspace: Cap) {
        self.cap_self_cspace = cap_self_cspace;
    }

    // -----------------------------------------------------------------------
    // Slot management (no kernel objects involved)
    // -----------------------------------------------------------------------

    pub fn alloc_slots(&mut self, count: usize) -> Option<(Cap, usize)> {
        let base = trona::slot_alloc::slot_alloc_consecutive(count as u64)?;
        Some((base, count))
    }

    pub fn mark_slot_used(&mut self, _slot: Cap) {}

    pub fn free_slots(&mut self, base: Cap, count: usize) {
        trona::slot_alloc::slot_free_range(base, count as u64);
    }

    pub fn alloc_single_slot(&mut self) -> Option<Cap> {
        trona::slot_alloc::slot_alloc()
    }

    pub fn free_single_slot(&mut self, slot: Cap) {
        let _ = trona::slot_alloc::slot_free(slot);
    }

    // -----------------------------------------------------------------------
    // Transactional reservation
    // -----------------------------------------------------------------------

    /// Reserve `total_slots` contiguous capability slots for a spawn /
    /// fork operation. `owner_id` is the rsrcsrv-side owner all allocations
    /// will be charged to (typically child pid). Only one reservation can be
    /// active at a time (single-threaded procmgr).
    pub fn reserve(&mut self, owner_id: u64, total_slots: usize) -> bool {
        if self.reservation.active {
            return false;
        }
        let slot_base = match trona::slot_alloc::slot_alloc_consecutive(total_slots as u64) {
            Some(base) => base,
            None => return false,
        };
        self.reservation = Reservation {
            active: true,
            slot_base,
            slot_count: total_slots,
            owner_id,
            objects: {
                const E: ReservedObject = ReservedObject::empty();
                [E; MAX_RESERVE_OBJECTS]
            },
            object_count: 0,
            next_offset: 0,
        };
        true
    }

    pub fn reservation_slot(&self, offset: usize) -> Cap {
        self.reservation.slot_base + offset as Cap
    }

    pub fn reservation_owner(&self) -> u64 {
        self.reservation.owner_id
    }

    /// Commit the reservation: mark it inactive, slots stay allocated.
    /// Returns (base, count) for recording in the process table.
    pub fn commit(&mut self) -> (Cap, u16) {
        let base = self.reservation.slot_base;
        let count = self.reservation.slot_count as u16;
        self.reservation.active = false;
        (base, count)
    }

    /// Rollback by asking rsrcsrv to free every recorded handle, then
    /// defensively revoke + delete any caps still in the reservation slot
    /// range, and finally free the slot range itself.
    pub fn rollback(&mut self, rsrcsrv_ep: Cap) {
        if !self.reservation.active {
            return;
        }

        let owner = self.reservation.owner_id;
        let n = self.reservation.object_count;
        for i in 0..n {
            let obj = self.reservation.objects[n - 1 - i];
            if obj.committed && obj.handle != 0 {
                let _ = free_handle(rsrcsrv_ep, owner, obj.handle);
            }
        }

        // Defensive sweep — handles wider than the explicit object table or
        // any leftover caps that bypassed the reservation accounting.
        for off in 0..self.reservation.slot_count {
            let slot = self.reservation.slot_base + off as Cap;
            let err = trona::invoke::cnode_revoke(self.cap_self_cspace, slot);
            if err != 0 {
                trona::invoke::cnode_delete(self.cap_self_cspace, slot);
            }
        }

        trona::slot_alloc::slot_free_range(
            self.reservation.slot_base,
            self.reservation.slot_count as u64,
        );

        self.reservation = Reservation::empty();
    }

    // -----------------------------------------------------------------------
    // rsrcsrv-backed object realization
    // -----------------------------------------------------------------------

    /// Realize a kernel object at the next reservation offset by calling
    /// rsrcsrv RES_ALLOC_OBJECT. The cap is delivered via cap_transfer into
    /// the reserved slot, and the rsrcsrv handle is recorded for rollback.
    pub fn realize_via_rsrcsrv_next(
        &mut self,
        rsrcsrv_ep: Cap,
        obj_type: u64,
        size_bits: u64,
    ) -> Result<Cap, i32> {
        if !self.reservation.active {
            return Err(trona::TRONA_INVALID_OPERATION as i32);
        }
        if self.reservation.next_offset >= self.reservation.slot_count {
            return Err(trona::TRONA_OUT_OF_MEMORY as i32);
        }
        let offset = self.reservation.next_offset;
        self.reservation.next_offset += 1;
        let slot = self.reservation_slot(offset);
        let handle = alloc_object_into_slot(
            rsrcsrv_ep,
            self.reservation.owner_id,
            obj_type,
            size_bits,
            self.cap_self_cspace,
            slot,
        )?;
        self.record_object(slot, handle);
        Ok(slot)
    }

    /// Realize a kernel object at a specific reservation offset.
    pub fn realize_via_rsrcsrv_at(
        &mut self,
        rsrcsrv_ep: Cap,
        obj_type: u64,
        size_bits: u64,
        offset: usize,
    ) -> Result<Cap, i32> {
        if !self.reservation.active {
            return Err(trona::TRONA_INVALID_OPERATION as i32);
        }
        if offset >= self.reservation.slot_count {
            return Err(trona::TRONA_OUT_OF_MEMORY as i32);
        }
        let slot = self.reservation_slot(offset);
        let handle = alloc_object_into_slot(
            rsrcsrv_ep,
            self.reservation.owner_id,
            obj_type,
            size_bits,
            self.cap_self_cspace,
            slot,
        )?;
        if offset >= self.reservation.next_offset {
            self.reservation.next_offset = offset + 1;
        }
        self.record_object(slot, handle);
        Ok(slot)
    }

    fn record_object(&mut self, slot: Cap, handle: u64) {
        if self.reservation.object_count < MAX_RESERVE_OBJECTS {
            let idx = self.reservation.object_count;
            self.reservation.objects[idx] = ReservedObject {
                slot,
                handle,
                committed: true,
            };
            self.reservation.object_count += 1;
        }
    }
}

// ===========================================================================
// Standalone helpers (no reservation involved)
// ===========================================================================

/// Allocate a single object outside any reservation context. Used for ad-hoc
/// allocations (one-off frames, scratch endpoints, etc.) where the caller
/// owns the lifecycle.
pub fn alloc_single(
    rsrcsrv_ep: Cap,
    owner_id: u64,
    obj_type: u64,
    size_bits: u64,
) -> Result<(Cap, u64), i32> {
    let slot = trona::slot_alloc::slot_alloc().ok_or(trona::TRONA_OUT_OF_MEMORY as i32)?;
    match alloc_object_into_slot(
        rsrcsrv_ep,
        owner_id,
        obj_type,
        size_bits,
        crate::CAP_SELF_CSPACE,
        slot,
    ) {
        Ok(handle) => Ok((slot, handle)),
        Err(e) => {
            let _ = trona::slot_alloc::slot_free(slot);
            Err(e)
        }
    }
}

pub fn free_handle(rsrcsrv_ep: Cap, owner_id: u64, handle: u64) -> i32 {
    let mut req = TronaMsg::zeroed();
    req.label = trona::protocol::RES_FREE_HANDLE;
    req.length = 2;
    req.regs[0] = owner_id;
    req.regs[1] = handle;
    let mut resp = TronaMsg::zeroed();
    let err = unsafe {
        trona::ipc::call_ctx(crate::ipc_ctx(), rsrcsrv_ep, &raw const req, &raw mut resp)
    };
    if err != 0 {
        return err;
    }
    resp.label as i32
}

pub fn reclaim_owner(rsrcsrv_ep: Cap, owner_id: u64) -> i32 {
    let mut req = TronaMsg::zeroed();
    req.label = trona::protocol::RES_RECLAIM_OWNER;
    req.length = 1;
    req.regs[0] = owner_id;
    let mut resp = TronaMsg::zeroed();
    let err = unsafe {
        trona::ipc::call_ctx(crate::ipc_ctx(), rsrcsrv_ep, &raw const req, &raw mut resp)
    };
    if err != 0 {
        return err;
    }
    resp.label as i32
}

// ---------------------------------------------------------------------------
// Internal: single rsrcsrv RES_ALLOC_OBJECT call. Sets the receive slot to
// `dest_slot` so the cap_transfer in the reply lands directly there.
// ---------------------------------------------------------------------------

fn alloc_object_into_slot(
    rsrcsrv_ep: Cap,
    owner_id: u64,
    obj_type: u64,
    size_bits: u64,
    cap_self_cspace: Cap,
    dest_slot: Cap,
) -> Result<u64, i32> {
    unsafe {
        trona::ipc::set_receive_slot_ctx(crate::ipc_ctx(), cap_self_cspace, dest_slot, 0);
    }
    let mut req = TronaMsg::zeroed();
    req.label = trona::protocol::RES_ALLOC_OBJECT;
    req.length = 4;
    req.regs[0] = owner_id;
    req.regs[1] = obj_type;
    req.regs[2] = size_bits;
    req.regs[3] = 0;
    let mut resp = TronaMsg::zeroed();
    let err = unsafe {
        trona::ipc::call_ctx(crate::ipc_ctx(), rsrcsrv_ep, &raw const req, &raw mut resp)
    };
    if err != 0 {
        return Err(err);
    }
    if resp.label != trona::TRONA_OK {
        return Err(resp.label as i32);
    }
    Ok(resp.regs[0])
}
