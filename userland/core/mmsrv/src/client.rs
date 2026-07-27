// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-client state — the control record (`ClientState`) and the
//! address-space record (`ClientVm`), held in parallel arrays by
//! `ClientTable`.
//!
//! `ClientState` is the reactor-facing control plane: VSpace cap,
//! request MP recv side, Watch cookie, heap / mmap watermarks. It is
//! `Copy` plain-old-data. `ClientVm` is the per-process VM: two
//! `trona_server` slabs (regions + reservations) each shadowed by a
//! base-sorted index, grown on demand through the injected
//! `PageBacking`. It is *not* `Copy` (it owns page buffers) and never
//! frees on `Drop` — every teardown path calls `release(&mut backing)`.
//!
//! Init creates one entry per spawn via `MM_REGISTER_CLIENT`; the
//! per-client request MP's Watch cookie carries `client_id` so
//! service-EQ events resolve to a slot in O(1).

use crate::region::{MappedRegion, RegionId, ReservationId, ReservedRange};
use trona_protocol::control;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::spawn::layout::VmClientLayout;
use trona_server::slab::{BaseSortedIndex, PageBacking, SlabId, TrackedSlab};
use uapi::{KERNITE_ERR_INVALID_ARGUMENT, KERNITE_ERR_OUT_OF_MEMORY};

pub const MAX_CLIENTS: usize = 128;

/// Next per-slot epoch: increment, mask to the control-cap badge's epoch
/// width, and skip the 0 sentinel on wrap.
fn next_epoch(g: u64) -> u64 {
    let n = g.wrapping_add(1) & control::EPOCH_MAX;
    if n == 0 { 1 } else { n }
}

/// Pending secondary operand of a two-step admin verb (fork parent+child,
/// cross-client stage dst+src). A single slot suffices: init is the sole,
/// serial lifecycle driver, so at most one two-operand verb is in flight.
/// Overwritten by a fresh `set_partner`, consumed by the operate step, and
/// cleared when the named secondary deregisters — self-healing against an
/// orphaned step 1.
struct PendingPartner {
    active: bool,
    secondary_slot: usize,
    secondary_epoch: u64,
    nonce: u64,
}

impl PendingPartner {
    const fn empty() -> Self {
        Self {
            active: false,
            secondary_slot: 0,
            secondary_epoch: 0,
            nonce: 0,
        }
    }
}

/// Per-client control record. Not `Copy` because the capability fields
/// are [`OwnedCap`]: their destructors delete the kernel objects when
/// the entry is vacated via [`ClientTable::vacate`].
///
/// `watch_cap` stays a raw `u64` — it is pool-managed by `WatchPool`
/// and must be returned to the pool with `pool.free(watch_cap)`, not
/// deleted through `delete_and_free`.
pub struct ClientState {
    pub client_id: u32,
    pub pid_for_diagnostics: u32,
    /// Client's VSpace cap (page-table root). Owned by this entry;
    /// deleted on deregister.
    pub vspace_cap: OwnedCap,
    /// Recv side of the per-client request MessagePipe. Owned by this
    /// entry; deleted on deregister.
    pub request_mp_recv: OwnedCap,
    /// Send side of the per-client request MessagePipe, retained for
    /// `MM_BIND_CLIENT_SELF`. Owned by this entry; deleted on
    /// deregister. `OwnedCap::null()` means "not registered" (core
    /// servers that never call `MM_BIND_CLIENT_SELF`).
    pub request_mp_send: OwnedCap,
    /// Pool-managed Watch cap armed over `request_mp_recv`'s
    /// `STATE_READABLE` bit on the service EQ. NOT an `OwnedCap` —
    /// must be returned to `WatchPool` with `pool.free(watch_cap)`.
    pub watch_cap: u64,
    /// Encoded `EventLoop` cookie that the kernel publishes
    /// back through `EventRecord.cookie` whenever the Watch fires.
    pub watch_cookie: u64,
    /// Per-process VA window contract. Mutable only by `install`,
    /// `commit_exec_txn`, and `inherit_vm_layout_from` — every other
    /// placement decision (anonymous mmap, image reservations, exec-replace
    /// staging) consults this field as the immutable base/limit pair.
    pub layout: VmClientLayout,
    /// Mutable break cursor inside `layout.heap_base..layout.heap_limit`.
    pub heap_current: u64,
    /// Mutable mmap placement cursor inside `layout.mmap_base..layout.mmap_limit`.
    pub mmap_hint: u64,
    /// Monotonic per-client transaction id used by exec_replace.
    /// Wraps after `u64::MAX`, but the next-id-after-wrap path is
    /// guarded so the 0 sentinel is never reissued.
    pub next_txn_id: u64,
    /// Dedicated per-slot reuse counter for control-cap ABA safety.
    /// Captured into a per-client control cap's badge at register and
    /// bumped on every [`ClientTable::vacate`], so a control cap naming a
    /// recycled slot fails the epoch check in
    /// [`ClientTable::resolve_control`]. Distinct from `next_txn_id` and
    /// from any slab epoch; persists across install / vacate cycles.
    pub epoch: u64,
    pub active: u8,
}

impl ClientState {
    pub const fn empty() -> Self {
        Self {
            client_id: 0,
            pid_for_diagnostics: 0,
            vspace_cap: OwnedCap::null(),
            request_mp_recv: OwnedCap::null(),
            request_mp_send: OwnedCap::null(),
            watch_cap: 0,
            watch_cookie: 0,
            layout: VmClientLayout::zero(),
            heap_current: 0,
            mmap_hint: 0,
            next_txn_id: 1,
            epoch: 1,
            active: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ClientVm — per-process address-space record.
// ---------------------------------------------------------------------------

/// A client's regions + reservations, each stored in a `TrackedSlab`
/// shadowed by a `BaseSortedIndex` for overlap / gap queries.
///
/// Geometry rule: a region's `base` / `length` are duplicated into
/// `regions_index`, so any change to a region's extent must go through
/// `vacate_region` + `install_region` (which keep the index in sync) —
/// never `region_mut`. `region_mut` is for non-geometry fields only
/// (prot, backing, flags). The same rule holds for reservations.
///
/// Not `Copy` and no `Drop`: the owner moves a `ClientVm` by value (slab
/// pointers travel with it) and must call `release(&mut backing)` before
/// the value is discarded.
pub struct ClientVm {
    regions_slab: TrackedSlab<MappedRegion>,
    regions_index: BaseSortedIndex,
    reservations_slab: TrackedSlab<ReservedRange>,
    reservations_index: BaseSortedIndex,
}

/// Failure of [`ClientVm::install_region`], carrying the un-published
/// `MappedRegion` back so the caller can run site-appropriate cleanup
/// (unmap the kernel VMA, release the backing) and recover ownership.
pub enum InstallError {
    /// `fork_policy` is inconsistent with `backing` (the validate backstop).
    InvalidPolicy(MappedRegion),
    /// The region's VA range overlaps a live region in this VM.
    Overlap(MappedRegion),
    /// Slab / index capacity exhausted. Unreachable when the caller
    /// reserved capacity first (the `reserve_region_capacity` discipline).
    OutOfMemory(MappedRegion),
}

impl InstallError {
    /// Recover the region whose install failed, for caller-side cleanup.
    pub fn into_region(self) -> MappedRegion {
        match self {
            InstallError::InvalidPolicy(r)
            | InstallError::Overlap(r)
            | InstallError::OutOfMemory(r) => r,
        }
    }

    /// The userland error code matching this failure.
    pub fn code(&self) -> u64 {
        match self {
            InstallError::InvalidPolicy(_) | InstallError::Overlap(_) => {
                KERNITE_ERR_INVALID_ARGUMENT as u64
            }
            InstallError::OutOfMemory(_) => KERNITE_ERR_OUT_OF_MEMORY as u64,
        }
    }
}

impl ClientVm {
    /// Empty VM with no backing buffers. The first `install_*` lazily
    /// allocates each slab's starter page.
    pub const fn empty() -> Self {
        Self {
            regions_slab: TrackedSlab::empty(),
            regions_index: BaseSortedIndex::empty(),
            reservations_slab: TrackedSlab::empty(),
            reservations_index: BaseSortedIndex::empty(),
        }
    }

    // ---- regions ----

    /// Install `region` and return its handle, or hand the region back
    /// (in [`InstallError`]) so the caller can clean up. Validates the
    /// fork policy and rejects an overlapping VA range, then reserves
    /// index capacity so the post-`slot_alloc` insert is infallible. On
    /// any failure the VM is left unchanged and the region is returned.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn install_region(
        &mut self,
        region: MappedRegion,
        backing: &mut impl PageBacking,
    ) -> Result<RegionId, InstallError> {
        // Backstop: never publish a region whose `fork_policy` is
        // inconsistent with its `backing` — the last line of defence
        // against an invalid (policy, backing) pair reaching a VSpace.
        if !region.validate_fork_policy() {
            return Err(InstallError::InvalidPolicy(region));
        }
        unsafe {
            // Reject an overlapping range up front: `BaseSortedIndex::insert`
            // does not detect overlap, so without this an overlapping region
            // would corrupt the index and alias a live mapping.
            if self
                .regions_index
                .first_overlap(region.base, region.length)
                .is_some()
            {
                return Err(InstallError::Overlap(region));
            }
            if !self.regions_index.reserve_entries(1, backing) {
                return Err(InstallError::OutOfMemory(region));
            }
            // Extract geometry before the move into slot_alloc.
            let (base, length) = (region.base, region.length);
            let sid = match self.regions_slab.slot_alloc_or_return(region, backing) {
                Ok(sid) => sid,
                Err(region) => return Err(InstallError::OutOfMemory(region)),
            };
            if !self.regions_index.insert(base, length, sid.idx, backing) {
                // Recover the region from the slab before freeing the slot so
                // the caller can release its backing (unreachable: index
                // capacity was just reserved).
                let region = self
                    .regions_slab
                    .slot_get_mut(sid)
                    .map(|slot| core::mem::replace(slot, MappedRegion::tombstone()))
                    .unwrap_or_else(MappedRegion::tombstone);
                self.regions_slab.slot_free(sid);
                return Err(InstallError::OutOfMemory(region));
            }
            Ok(RegionId::from_slab(sid))
        }
    }

    /// Ensure the regions slab and its index can absorb `count` more
    /// `install_region` calls without growing — making the subsequent
    /// publishes infallible after kernel side effects have already been
    /// applied (the reserve-before-publish discipline `fork` and the
    /// `MapPlan` family rely on). A single `reserve_region_capacity(n)`
    /// is required for an `n`-fragment split: `n` separate
    /// `reserve_region_capacity(1)` calls do *not* compose, because each
    /// only guarantees room for one beyond the current high-water mark.
    /// Returns `false` on memory exhaustion.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn reserve_region_capacity(
        &mut self,
        count: u32,
        backing: &mut impl PageBacking,
    ) -> bool {
        unsafe {
            self.regions_slab.reserve_slots(count, backing)
                && self.regions_index.reserve_entries(count, backing)
        }
    }

    /// Remove the region named by `id`, returning the record. Frees no
    /// pages (the slab buffer is reclaimed only by `release`), so no
    /// backing is required. Returns `None` for a stale handle.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn vacate_region(&mut self, id: RegionId) -> Option<MappedRegion> {
        unsafe {
            // MappedRegion is not Copy (may contain OwnedCap); move it
            // out of the slab slot before freeing the slot.
            let slot_ref = self.regions_slab.slot_get_mut(id.slab())?;
            let region = core::mem::replace(slot_ref, MappedRegion::tombstone());
            self.regions_index.remove_slot(id.idx());
            self.regions_slab.slot_free(id.slab());
            Some(region)
        }
    }

    /// Shared reference to the region named by `id`, or `None` if stale.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn region(&self, id: RegionId) -> Option<&MappedRegion> {
        unsafe { self.regions_slab.slot_get(id.slab()) }
    }

    /// Mutable reference for in-place updates of non-geometry fields. See
    /// the geometry rule on [`ClientVm`].
    ///
    /// # Safety
    /// Single-threaded server invariant. The caller must not change
    /// `base` / `length` through this reference.
    pub unsafe fn region_mut(&mut self, id: RegionId) -> Option<&mut MappedRegion> {
        unsafe { self.regions_slab.slot_get_mut(id.slab()) }
    }

    /// Handle of the region whose range contains `va`, or `None`.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn find_region(&self, va: u64) -> Option<RegionId> {
        unsafe {
            let slot = self.regions_index.first_overlap(va, 1)?;
            let epoch = self.regions_slab.generation_at(slot);
            if epoch == 0 {
                return None;
            }
            Some(RegionId::from_slab(SlabId { idx: slot, epoch }))
        }
    }

    /// Iterate `(RegionId, &MappedRegion)` over every live region.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn iter_regions(&self) -> impl Iterator<Item = (RegionId, &MappedRegion)> + '_ {
        let it = unsafe { self.regions_slab.iter() };
        it.map(|(sid, r)| (RegionId::from_slab(sid), r))
    }

    /// Base-sorted region index, for the gap allocator and overlap
    /// checks (`crate::va_alloc`).
    pub fn regions_index(&self) -> &BaseSortedIndex {
        &self.regions_index
    }

    /// Owned copy of the `(RegionId, MappedRegion)` at base-sorted index
    /// position `pos`, or `None` if `pos` is out of range or the slot is
    /// stale. Because it returns owned values and holds no borrow, a
    /// caller may walk every region by position (`0..regions_index().count()`)
    /// while mutating this or a sibling VM between steps — `fork` uses
    /// this to update parent regions in place and install child regions
    /// as it goes. Correct only while no region is *added or removed*
    /// from this VM during the walk; in-place field updates are fine.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn region_snapshot_at(&self, pos: u32) -> Option<(RegionId, MappedRegion)> {
        unsafe {
            let entry = self.regions_index.at(pos)?;
            let epoch = self.regions_slab.generation_at(entry.slot);
            if epoch == 0 {
                return None;
            }
            let id = SlabId {
                idx: entry.slot,
                epoch,
            };
            // MappedRegion is not Copy; clone the scalar fields into a
            // fresh record. The backing reference is duplicated via
            // the registry / OwnedCap dup path by the caller (fork);
            // here we carry over the raw handle so the caller can
            // inspect which registry slot to retain_by_handle.
            let r = self.regions_slab.slot_get(id)?;
            let region = r.snapshot();
            Some((RegionId::from_slab(id), region))
        }
    }

    /// Epoch of the regions slab slot `slot`, or 0 if empty — lets the
    /// gap allocator (`crate::va_alloc`) rebuild a full `RegionId` from a
    /// bare `BaseSortedIndex` entry slot.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn region_generation_at(&self, slot: u32) -> u32 {
        unsafe { self.regions_slab.generation_at(slot) }
    }

    // ---- reservations ----

    /// Install `reservation` and return its handle. Same publish /
    /// rollback discipline as [`install_region`](Self::install_region).
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn install_reservation(
        &mut self,
        reservation: ReservedRange,
        backing: &mut impl PageBacking,
    ) -> Option<ReservationId> {
        unsafe {
            if !self.reservations_index.reserve_entries(1, backing) {
                return None;
            }
            let sid = self.reservations_slab.slot_alloc(reservation, backing)?;
            if !self.reservations_index.insert(
                reservation.base,
                reservation.length,
                sid.idx,
                backing,
            ) {
                self.reservations_slab.slot_free(sid);
                return None;
            }
            Some(ReservationId::from_slab(sid))
        }
    }

    /// Remove the reservation named by `id`, returning the record.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn vacate_reservation(&mut self, id: ReservationId) -> Option<ReservedRange> {
        unsafe {
            let reservation = *self.reservations_slab.slot_get(id.slab())?;
            self.reservations_index.remove_slot(id.idx());
            self.reservations_slab.slot_free(id.slab());
            Some(reservation)
        }
    }

    /// Shared reference to the reservation named by `id`.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn reservation(&self, id: ReservationId) -> Option<&ReservedRange> {
        unsafe { self.reservations_slab.slot_get(id.slab()) }
    }

    /// Mutable reference to the reservation named by `id` (non-geometry
    /// fields only).
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn reservation_mut(&mut self, id: ReservationId) -> Option<&mut ReservedRange> {
        unsafe { self.reservations_slab.slot_get_mut(id.slab()) }
    }

    /// Handle of the reservation whose range contains `va`, or `None`.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn find_reservation(&self, va: u64) -> Option<ReservationId> {
        unsafe {
            let slot = self.reservations_index.first_overlap(va, 1)?;
            let epoch = self.reservations_slab.generation_at(slot);
            if epoch == 0 {
                return None;
            }
            Some(ReservationId::from_slab(SlabId { idx: slot, epoch }))
        }
    }

    /// Iterate `(ReservationId, &ReservedRange)` over every live
    /// reservation.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn iter_reservations(
        &self,
    ) -> impl Iterator<Item = (ReservationId, &ReservedRange)> + '_ {
        let it = unsafe { self.reservations_slab.iter() };
        it.map(|(sid, r)| (ReservationId::from_slab(sid), r))
    }

    /// Number of live reservations.
    pub fn reservation_count(&self) -> usize {
        self.reservations_slab.len()
    }

    /// Base-sorted reservation index, for the gap allocator.
    pub fn reservations_index(&self) -> &BaseSortedIndex {
        &self.reservations_index
    }

    /// Epoch of the reservations slab slot `slot`, or 0 if empty.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn reservation_generation_at(&self, slot: u32) -> u32 {
        unsafe { self.reservations_slab.generation_at(slot) }
    }

    /// Ensure the reservations slab and its index can absorb `count` more
    /// `install_reservation` calls without growing — used by `fork` to
    /// make the per-reservation inherit infallible after the parent
    /// snapshot. Returns `false` on memory exhaustion.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn reserve_reservation_capacity(
        &mut self,
        count: u32,
        backing: &mut impl PageBacking,
    ) -> bool {
        unsafe {
            self.reservations_slab.reserve_slots(count, backing)
                && self.reservations_index.reserve_entries(count, backing)
        }
    }

    /// Owned copy of the `(ReservationId, ReservedRange)` at base-sorted
    /// index position `pos`. Mirrors
    /// [`region_snapshot_at`](Self::region_snapshot_at): returns owned
    /// values and holds no borrow, so `fork` can walk the parent's
    /// reservations by position while installing each into the child
    /// between steps.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn reservation_snapshot_at(
        &self,
        pos: u32,
    ) -> Option<(ReservationId, ReservedRange)> {
        unsafe {
            let entry = self.reservations_index.at(pos)?;
            let epoch = self.reservations_slab.generation_at(entry.slot);
            if epoch == 0 {
                return None;
            }
            let id = SlabId {
                idx: entry.slot,
                epoch,
            };
            let reservation = *self.reservations_slab.slot_get(id)?;
            Some((ReservationId::from_slab(id), reservation))
        }
    }

    // ---- teardown ----

    /// Release every backing buffer and reset to the empty state,
    /// invalidating all previously-issued handles. Frees only the slab /
    /// index bookkeeping pages — the kernel backing of individual
    /// regions (MO caps, frames) must already have been torn down by the
    /// caller.
    ///
    /// # Safety
    /// Single-threaded server invariant. No live references into the VM
    /// may remain.
    pub unsafe fn release(&mut self, backing: &mut impl PageBacking) {
        unsafe {
            self.regions_slab.release(backing);
            self.regions_index.release(backing);
            self.reservations_slab.release(backing);
            self.reservations_index.release(backing);
        }
    }
}

// ---------------------------------------------------------------------------
// PendingExecVm — staged image for an in-flight exec transaction.
// ---------------------------------------------------------------------------

/// Per-client exec transaction state. mmsrv stages the new image's
/// regions into `staged_vm` (a fresh, separate `ClientVm`) and remembers
/// the `pending_vspace_cap` that init retyped for the post-exec VSpace.
/// On commit the live `ClientVm` is swapped out for `staged_vm` and the
/// client's `vspace_cap` is replaced with `pending_vspace_cap`; on abort
/// the staged VM and pending VSpace are returned for teardown.
///
/// `active == 0` means no exec transaction is in flight. `txn_id`
/// monotonically increases per client so callers can issue
/// `MM_STAGE_IMAGE_REGION(STAGE_FLAG_EXEC_TXN, txn_id)` without racing an
/// aborted prior transaction. `staged_vm` is empty whenever `active == 0`
/// (commit / abort move it out and leave it empty).
pub struct PendingExecVm {
    pub txn_id: u64,
    /// VSpace cap for the staged exec image. Owned by this struct
    /// while the transaction is in flight; moved out on commit or
    /// abort so the caller can tear it down.
    pub pending_vspace_cap: OwnedCap,
    /// Caller-provided exec source MemoryObject (READ|EXECUTE), held for
    /// the whole transaction so `EXEC_MO_SRC` stage ops can map sub-ranges
    /// of it (a dup for TEXT/RODATA, an `MO_CLONE_RANGE` child for DATA)
    /// without re-sending the cap per segment. NOT registered in
    /// `MoRegistry` — it is a VFS-owned external cap and the registry would
    /// mis-free it on vacate. Dropped on commit / abort / vacate; the
    /// staged mappings hold their own per-MO refs so the object survives.
    pub exec_mo_cap: OwnedCap,
    pub staged_vm: ClientVm,
    /// Layout for the staged image. `commit_exec_txn` swaps it into
    /// `ClientState.layout` and resets `heap_current` / `mmap_hint` from
    /// it; abort drops it without touching the live entry.
    pub pending_layout: VmClientLayout,
    pub active: u8,
}

impl PendingExecVm {
    pub const fn empty() -> Self {
        Self {
            txn_id: 0,
            pending_vspace_cap: OwnedCap::null(),
            exec_mo_cap: OwnedCap::null(),
            staged_vm: ClientVm::empty(),
            pending_layout: VmClientLayout::zero(),
            active: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SavedClientCaps — moved-out caps returned by ClientTable::vacate.
// ---------------------------------------------------------------------------

/// Caps moved out of a `ClientState` by [`ClientTable::vacate`].
///
/// The caller must:
/// 1. Disarm the Watch (`pool.free(watch_cap)`) before dropping this.
/// 2. Let the `OwnedCap` fields drop to delete the kernel objects.
///    `pending_vspace_cap` is `OwnedCap::null()` when no exec
///    transaction was in flight.
pub struct SavedClientCaps {
    pub client_id: u32,
    pub pid_for_diagnostics: u32,
    pub vspace_cap: OwnedCap,
    pub request_mp_recv: OwnedCap,
    pub request_mp_send: OwnedCap,
    /// Pool-managed Watch slot — NOT dropped via `OwnedCap`. Caller
    /// calls `pool.free(watch_cap)` before dropping this struct.
    pub watch_cap: u64,
    pub watch_cookie: u64,
    /// Non-null only when an exec transaction was in flight at vacate
    /// time. Caller must tear down its staged regions then let this
    /// drop (or pass to `delete_and_free`).
    pub pending_vspace_cap: OwnedCap,
}

// ---------------------------------------------------------------------------
// ClientTable — parallel arrays of control + VM + exec-staging records.
// ---------------------------------------------------------------------------

pub struct ClientTable {
    entries: [ClientState; MAX_CLIENTS],
    vm: [ClientVm; MAX_CLIENTS],
    pending_exec: [PendingExecVm; MAX_CLIENTS],
    /// Single-slot pending secondary operand for the two-step admin verbs.
    pending_partner: PendingPartner,
}

impl ClientTable {
    pub const fn new() -> Self {
        Self {
            entries: [const { ClientState::empty() }; MAX_CLIENTS],
            vm: [const { ClientVm::empty() }; MAX_CLIENTS],
            pending_exec: [const { PendingExecVm::empty() }; MAX_CLIENTS],
            pending_partner: PendingPartner::empty(),
        }
    }

    pub fn alloc(&mut self) -> Option<usize> {
        for (idx, e) in self.entries.iter().enumerate() {
            if e.active == 0 {
                return Some(idx);
            }
        }
        None
    }

    /// Stamp a freshly-allocated entry. `client_id` is supplied by the
    /// caller (init owns the namespace) — pinning the id at the
    /// supervisor side lets `MM_REGISTER_FAULT_PIPE` and every
    /// subsequent call carry the same identifier without round-trip
    /// overhead.
    ///
    /// The VM and exec-staging slots for `idx` are already empty (a
    /// fresh `ClientTable` or a prior `vacate` released them), so this
    /// touches only the control record.
    pub fn install(
        &mut self,
        idx: usize,
        client_id: u32,
        pid_for_diagnostics: u32,
        vspace_cap: OwnedCap,
        request_mp_recv: OwnedCap,
        request_mp_send: OwnedCap,
        watch_cap: u64,
        watch_cookie: u64,
        layout: VmClientLayout,
    ) {
        let e = &mut self.entries[idx];
        e.client_id = client_id;
        e.pid_for_diagnostics = pid_for_diagnostics;
        e.vspace_cap = vspace_cap;
        e.request_mp_recv = request_mp_recv;
        e.request_mp_send = request_mp_send;
        e.watch_cap = watch_cap;
        e.watch_cookie = watch_cookie;
        e.layout = layout;
        e.heap_current = layout.heap_base;
        e.mmap_hint = layout.mmap_base;
        e.next_txn_id = 1;
        e.active = 1;
    }

    /// Tear down a client slot: release its VM and any staged exec VM
    /// backing, then clear the control record. The caller must already
    /// have torn down the kernel backing of every region (MO caps,
    /// frames) — `release` reclaims only the slab bookkeeping pages.
    ///
    /// Returns a `SavedClientCaps` carrying the owned caps so the
    /// caller can perform watch cancellation and pool cleanup before
    /// the caps are dropped.
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn vacate(
        &mut self,
        idx: usize,
        backing: &mut impl PageBacking,
    ) -> Option<SavedClientCaps> {
        let e = self.entries.get_mut(idx)?;
        if e.active == 0 {
            return None;
        }
        // Extract the diagnostic scalars before moving caps out.
        let client_id = e.client_id;
        let pid_for_diagnostics = e.pid_for_diagnostics;
        let watch_cap = e.watch_cap;
        let watch_cookie = e.watch_cookie;
        // Move owned caps out of the entry, replacing with nulls so
        // the entry's Drop (via `ClientState::empty()` overwrite below)
        // does not double-free.
        let vspace_cap = core::mem::replace(&mut e.vspace_cap, OwnedCap::null());
        let request_mp_recv = core::mem::replace(&mut e.request_mp_recv, OwnedCap::null());
        let request_mp_send = core::mem::replace(&mut e.request_mp_send, OwnedCap::null());
        // Bump the dedicated per-slot epoch so a control cap naming this
        // slot fails the epoch check once the slot is reused.
        let bumped = next_epoch(e.epoch);
        // Reset the entry to empty (nulls + inactive), then restore the
        // bumped epoch (empty() resets it to the start value).
        *e = ClientState::empty();
        e.epoch = bumped;
        unsafe {
            self.vm[idx].release(backing);
            self.pending_exec[idx].staged_vm.release(backing);
        }
        let pending = &mut self.pending_exec[idx];
        pending.active = 0;
        pending.txn_id = 0;
        // Free the held exec source MO (if any); the staged regions were
        // released above, dropping their dups with the slab.
        let _exec_mo = core::mem::replace(&mut pending.exec_mo_cap, OwnedCap::null());
        // Move out the pending VSpace cap too (null replaces it).
        let pending_vspace_cap =
            core::mem::replace(&mut pending.pending_vspace_cap, OwnedCap::null());
        Some(SavedClientCaps {
            client_id,
            pid_for_diagnostics,
            vspace_cap,
            request_mp_recv,
            request_mp_send,
            watch_cap,
            watch_cookie,
            pending_vspace_cap,
        })
    }

    pub fn entry(&self, idx: usize) -> Option<&ClientState> {
        self.entries.get(idx).filter(|e| e.active != 0)
    }

    /// Mirror the parent's layout + cursors onto the child after
    /// `MM_FORK_VSPACE`. Init registers the child with the parent's layout
    /// already (via `BootstrapPlan.client_layout`), so this step just
    /// copies the parent's *cursors* (`heap_current`, `mmap_hint`) on top
    /// of the cursors seeded from the registered layout. Capability
    /// endpoints and VSpace caps stay child-owned; only placement metadata
    /// is copied.
    pub fn inherit_vm_layout_from(&mut self, parent_idx: usize, child_idx: usize) -> bool {
        let (parent_layout, parent_heap_current, parent_mmap_hint) = {
            let parent = match self.entries.get(parent_idx) {
                Some(p) if p.active != 0 => p,
                _ => return false,
            };
            (parent.layout, parent.heap_current, parent.mmap_hint)
        };
        let Some(child) = self.entries.get_mut(child_idx) else {
            return false;
        };
        if child.active == 0 {
            return false;
        }
        child.layout = parent_layout;
        child.heap_current = parent_heap_current;
        child.mmap_hint = parent_mmap_hint;
        true
    }

    pub fn vm(&self, idx: usize) -> Option<&ClientVm> {
        if self.entries.get(idx).filter(|e| e.active != 0).is_some() {
            Some(&self.vm[idx])
        } else {
            None
        }
    }

    pub fn vm_mut(&mut self, idx: usize) -> Option<&mut ClientVm> {
        if self.entries.get(idx).filter(|e| e.active != 0).is_some() {
            Some(&mut self.vm[idx])
        } else {
            None
        }
    }

    /// Disjoint mutable access to a client's control record and VM, for
    /// handlers that mutate both. The `self_vm` page backing is a
    /// separate `ServerState` field, so a handler takes it as a third
    /// disjoint borrow at the call site.
    pub fn entry_and_vm_mut(&mut self, idx: usize) -> Option<(&mut ClientState, &mut ClientVm)> {
        let entry = self.entries.get_mut(idx)?;
        if entry.active == 0 {
            return None;
        }
        Some((entry, &mut self.vm[idx]))
    }

    pub fn find_by_client_id(&self, client_id: u32) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .find(|(_, e)| e.active != 0 && e.client_id == client_id)
            .map(|(i, _)| i)
    }

    /// Per-slot epoch for the slot `idx`, used to mint a per-client control
    /// cap's badge at register time. `None` if the slot is inactive.
    pub fn epoch_of(&self, idx: usize) -> Option<u64> {
        self.entries
            .get(idx)
            .filter(|e| e.active != 0)
            .map(|e| e.epoch)
    }

    /// Resolve a presented control-cap badge to its client slot, or `None`
    /// if the tag is wrong, it is the ROOT cap, the slot is inactive, or
    /// the badge's epoch no longer matches the slot. This is both the
    /// authorization (only init holds control caps) and the target
    /// identification for every per-client admin verb — there is no
    /// trusted `client_id` argument to consult.
    pub fn resolve_control(&self, badge: u64) -> Option<usize> {
        if !control::tag_matches(badge) || control::is_root(badge) {
            return None;
        }
        let slot = control::slot_of(badge) as usize;
        let e = self.entries.get(slot)?;
        if e.active == 0 || e.epoch != control::epoch_of(badge) {
            return None;
        }
        Some(slot)
    }

    /// Record the secondary operand of a two-step verb, capturing its
    /// current epoch for the ABA re-check at consume time. Overwrites any
    /// stale pending — a fresh transaction supersedes an orphaned one.
    pub fn set_partner(&mut self, secondary_slot: usize, nonce: u64) {
        let epoch = self
            .entries
            .get(secondary_slot)
            .map(|e| e.epoch)
            .unwrap_or(0);
        self.pending_partner = PendingPartner {
            active: true,
            secondary_slot,
            secondary_epoch: epoch,
            nonce,
        };
    }

    /// Consume the pending secondary for `nonce`. Always clears the pending
    /// slot (consume-once = replay guard). Returns the secondary slot only
    /// if the pending is active, the nonce matches, and the secondary is
    /// still live at its captured epoch (ABA guard).
    pub fn consume_partner(&mut self, nonce: u64) -> Option<usize> {
        let pending = core::mem::replace(&mut self.pending_partner, PendingPartner::empty());
        if !pending.active || pending.nonce != nonce {
            return None;
        }
        let e = self.entries.get(pending.secondary_slot)?;
        if e.active == 0 || e.epoch != pending.secondary_epoch {
            return None;
        }
        Some(pending.secondary_slot)
    }

    /// Clear any pending secondary naming `slot` — called when that slot
    /// deregisters so a later operate step cannot consume a dead operand.
    pub fn clear_partner_naming(&mut self, slot: usize) {
        if self.pending_partner.active && self.pending_partner.secondary_slot == slot {
            self.pending_partner = PendingPartner::empty();
        }
    }

    /// Resolve a diagnostics pid to a client slot (for `MM_LIST_VMAS`,
    /// which addresses the target process by pid).
    pub fn find_by_pid(&self, pid: u32) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .find(|(_, e)| e.active != 0 && e.pid_for_diagnostics == pid)
            .map(|(i, _)| i)
    }

    /// Sum of every active client's mapped-region lengths — the
    /// system-wide committed virtual address space, in bytes
    /// (`MM_GET_COMMIT_AS`).
    ///
    /// # Safety
    /// Single-threaded server invariant.
    pub unsafe fn total_committed_as(&self) -> u64 {
        let mut total = 0u64;
        for (idx, e) in self.entries.iter().enumerate() {
            if e.active == 0 {
                continue;
            }
            for (_, r) in unsafe { self.vm[idx].iter_regions() } {
                total = total.saturating_add(r.length);
            }
        }
        total
    }

    pub fn pending_exec(&self, idx: usize) -> Option<&PendingExecVm> {
        self.pending_exec.get(idx).filter(|p| p.active != 0)
    }

    pub fn pending_exec_mut(&mut self, idx: usize) -> Option<&mut PendingExecVm> {
        let p = self.pending_exec.get_mut(idx)?;
        if p.active == 0 {
            return None;
        }
        Some(p)
    }

    /// Open an exec transaction for `idx`. Returns the new txn_id, or
    /// `None` if there is already a pending exec on this client. The
    /// staged VM is already empty (the invariant on `PendingExecVm`), so
    /// the image handler installs regions into it directly.
    /// `pending_layout` is the new image's planned layout; commit swaps
    /// it into the live entry and resets the cursors.
    pub fn begin_exec_txn(
        &mut self,
        idx: usize,
        pending_vspace_cap: OwnedCap,
        exec_mo_cap: OwnedCap,
        pending_layout: VmClientLayout,
    ) -> Option<u64> {
        if self.entries.get(idx).filter(|e| e.active != 0).is_none() {
            return None;
        }
        if self.pending_exec[idx].active != 0 {
            return None;
        }
        let entry = &mut self.entries[idx];
        let mut txn_id = entry.next_txn_id;
        entry.next_txn_id = entry.next_txn_id.wrapping_add(1);
        if entry.next_txn_id == 0 {
            entry.next_txn_id = 1;
        }
        if txn_id == 0 {
            txn_id = 1;
            entry.next_txn_id = 2;
        }
        let pending = &mut self.pending_exec[idx];
        pending.txn_id = txn_id;
        pending.pending_vspace_cap = pending_vspace_cap;
        pending.exec_mo_cap = exec_mo_cap;
        pending.pending_layout = pending_layout;
        pending.active = 1;
        Some(txn_id)
    }

    /// Commit the exec transaction: install the staged VM as the live VM,
    /// swap in the pending VSpace cap, and atomically replace the live
    /// layout with `pending_layout`. Returns the *old* vspace cap and
    /// the fully-owned pre-commit `ClientVm` so the caller can decommit
    /// its regions, drop their caps, and `release` its backing.
    /// `None` when no transaction is in flight or the txn_id mismatches.
    pub fn commit_exec_txn(&mut self, idx: usize, txn_id: u64) -> Option<(OwnedCap, ClientVm)> {
        if self.entries.get(idx).filter(|e| e.active != 0).is_none() {
            return None;
        }
        let pending = &mut self.pending_exec[idx];
        if pending.active == 0 || pending.txn_id != txn_id {
            return None;
        }
        // The exec source MO was held only for staging. Drop it now
        // (delete-and-free); the staged mappings (TEXT/RODATA dups, DATA
        // MO_CLONE_RANGE children) hold their own per-MO refs, so the
        // object survives the commit.
        let _exec_mo = core::mem::replace(&mut pending.exec_mo_cap, OwnedCap::null());
        // Move the new VSpace cap out; replace with null so the slot's
        // Drop does nothing (the cap is now the caller's responsibility
        // via old_vspace's Drop after the swap).
        let new_vspace = core::mem::replace(&mut pending.pending_vspace_cap, OwnedCap::null());
        let staged = core::mem::replace(&mut pending.staged_vm, ClientVm::empty());
        let new_layout = core::mem::replace(&mut pending.pending_layout, VmClientLayout::zero());
        pending.active = 0;
        pending.txn_id = 0;

        let old_vm = core::mem::replace(&mut self.vm[idx], staged);
        // Swap old and new VSpace caps atomically: move old out, move
        // new in. The returned old_vspace is dropped by the caller
        // after it has decommitted the old regions.
        let old_vspace = core::mem::replace(&mut self.entries[idx].vspace_cap, new_vspace);
        // Atomically replace the layout and reset cursors from it so the
        // new image's anonymous mmap / brk allocations start fresh.
        let entry = &mut self.entries[idx];
        entry.layout = new_layout;
        entry.heap_current = new_layout.heap_base;
        entry.mmap_hint = new_layout.mmap_base;
        Some((old_vspace, old_vm))
    }

    /// Abort an exec transaction. Returns the pending vspace cap and the
    /// staged `ClientVm` so the caller can tear them down. The pending
    /// layout is dropped; the live entry's layout is untouched.
    pub fn abort_exec_txn(&mut self, idx: usize, txn_id: u64) -> Option<(OwnedCap, ClientVm)> {
        let pending = self.pending_exec.get_mut(idx)?;
        if pending.active == 0 || pending.txn_id != txn_id {
            return None;
        }
        // Drop the held exec source MO; staged mappings retain their own refs.
        let _exec_mo = core::mem::replace(&mut pending.exec_mo_cap, OwnedCap::null());
        let _pending_layout =
            core::mem::replace(&mut pending.pending_layout, VmClientLayout::zero());
        let pending_vspace = core::mem::replace(&mut pending.pending_vspace_cap, OwnedCap::null());
        let staged = core::mem::replace(&mut pending.staged_vm, ClientVm::empty());
        pending.active = 0;
        pending.txn_id = 0;
        Some((pending_vspace, staged))
    }
}
