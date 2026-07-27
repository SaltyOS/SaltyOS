// SPDX-License-Identifier: GPL-2.0-only
//
//! MapPlan family — the publication layer between the self-tier
//! handlers (`crate::mmap`) and the per-client `ClientVm`.
//!
//! Every region mutation a handler performs is a multi-step sequence of
//! kernel side effects (commit / map / unmap / protect) plus a slab
//! publication. The fault dispatcher TCB also reads the regions slab,
//! but **only under `STATE_LOCK`** — the same lock the policy reactor
//! holds while running these plans — so a half-applied mutation is never
//! *observed* by a concurrent reader. What these plans must still
//! guarantee is `no_partial_publish` in the sense of *rollback
//! consistency*: a handler must either fully publish or fully roll back
//! before it returns (releasing the lock), so the committed state is
//! always self-consistent.
//!
//! The discipline that makes this hold:
//!  1. **Reserve slab/index capacity first** (`reserve_region_capacity`)
//!     so the publish after the kernel side effects is infallible.
//!  2. **Duplicate per-fragment backing before** the kernel op, so a
//!     split that fails leaves the original region untouched.
//!  3. On kernel failure, undo the duplicated backings (their release is
//!     the exact inverse of the duplication) and return — nothing is
//!     published.
//!
//! `duplicate_backing` and `release_region_backing` are exact inverses:
//! anon/cow/image take a registry refcount, shm/file copy the cap (and
//! shm bumps the map count); releasing reverses precisely that.
//! Duplication copies the backing's offset verbatim — the caller rebases
//! each fragment to its own position with `rebase_backing`, so offset
//! arithmetic happens in exactly one place.

use crate::client::ClientVm;
use crate::kernel_vm;
use crate::mo_registry::MoRegistry;
use crate::region::kernel_region_kind;
use crate::region::{
    BackingDescriptor, ForkPolicy, MappedRegion, RegionId, ReservationId, ReservationPurpose,
    ReservedRange, max_prot_for_region_type,
};
use crate::self_vm::SelfVm;
use crate::va_alloc;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_server::frame_alloc::FrameAllocator;
use trona_server::slab::ReservationKind;
use uapi::{
    KERNITE_CAP_SELF_CSPACE, KERNITE_ERR_INSUFFICIENT_RIGHTS, KERNITE_ERR_INVALID_ARGUMENT,
    KERNITE_ERR_NOT_FOUND, KERNITE_ERR_OUT_OF_MEMORY, KERNITE_ERR_OUT_OF_RANGE,
    KERNITE_PAGE_BYTES as KERNITE_PAGE_BYTES_U32, KERNITE_PAGE_FLAG_EXECUTABLE,
    KERNITE_PAGE_FLAG_USER, KERNITE_PAGE_FLAG_WRITABLE, KERNITE_RIGHT_ALL,
};

const KERNITE_PAGE_BYTES: u64 = KERNITE_PAGE_BYTES_U32 as u64;

// ---------------------------------------------------------------------------
// Flag / shaping helpers
// ---------------------------------------------------------------------------

/// Translate a POSIX-ish `prot` bitset (bit1 = write, bit2 = exec) into
/// the kernel page-flag bits, always with the USER bit set.
pub(crate) fn perms_bits(prot: u8) -> u64 {
    (KERNITE_PAGE_FLAG_USER as u64)
        | if prot & 0x2 != 0 {
            KERNITE_PAGE_FLAG_WRITABLE as u64
        } else {
            0
        }
        | if prot & 0x4 != 0 {
            KERNITE_PAGE_FLAG_EXECUTABLE as u64
        } else {
            0
        }
}

/// Pack `(page_count, perms, region_kind)` into the `count_and_flags`
/// word `VSPACE_MAP_MO` expects: pages in bits 63:32, kernel region kind
/// in bits 31:24, page flags in the low bits.
fn map_count_and_flags(pages: u64, prot: u8, region_type: u8) -> u64 {
    (pages << 32) | perms_bits(prot) | ((kernel_region_kind(region_type) as u64) << 24)
}

// ---------------------------------------------------------------------------
// Kernel-op helpers. The `kernel_vm` wrappers are safe (only
// `commit_mo_pages` is `unsafe`, contained below), so these are plain
// functions.
// ---------------------------------------------------------------------------

/// Unmap `pages` pages starting at `base` from `vspace`. Best-effort:
/// per-page errors are ignored (the page may already be absent).
fn unmap_range(vspace: u64, base: u64, pages: u64) {
    for p in 0..pages {
        let _ = kernel_vm::vspace_unmap(vspace, base + p * KERNITE_PAGE_BYTES);
    }
}

/// Commit `pages` pages at `offset_pages` in `mo_cap` through the kernel
/// PMM. Returns the kernel error (or OOM) on short commit.
fn commit_range(mo_cap: u64, offset_pages: u64, pages: u64) -> Result<(), u64> {
    if pages == 0 {
        return Ok(());
    }
    // SAFETY: `mo_cap` is a live MO cap owned by the caller's region /
    // staging path; mmsrv is single-threaded under STATE_LOCK.
    let err = unsafe { kernel_vm::commit_mo_pages(mo_cap, offset_pages, pages) };
    if err != 0 {
        return Err(err as u64);
    }
    Ok(())
}

/// Map `pages` pages of `mo_cap` (at `mo_offset_pages`) into `vspace` at
/// `va_base` with `prot` / `region_type`. On a short or failed map the
/// partially-mapped pages are unmapped and an error returned, so the
/// caller never observes a half-mapped range.
fn map_mo_range(
    vspace: u64,
    mo_cap: u64,
    va_base: u64,
    mo_offset_pages: u64,
    pages: u64,
    prot: u8,
    region_type: u8,
) -> Result<(), u64> {
    let count_and_flags = map_count_and_flags(pages, prot, region_type);
    let (err, mapped) = kernel_vm::vspace_map_mo_with_count(
        vspace,
        mo_cap,
        va_base,
        mo_offset_pages,
        count_and_flags,
    );
    if err == 0 && mapped == pages {
        return Ok(());
    }
    unmap_range(vspace, va_base, mapped.min(pages));
    Err(if err != 0 {
        err as u64
    } else {
        KERNITE_ERR_OUT_OF_MEMORY as u64
    })
}

/// Re-protect `pages` pages at `base` in `vspace` to `prot`.
fn protect_range(vspace: u64, base: u64, pages: u64, prot: u8) -> Result<(), u64> {
    let (err, _changed) = kernel_vm::vspace_protect_range(vspace, base, pages, perms_bits(prot));
    if err != 0 {
        return Err(err as u64);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Capability helpers (for per-mapping cap copies: shm / file-backed)
// ---------------------------------------------------------------------------

/// Make an independent copy of capability slot `src` into a fresh stable
/// slot, returning the new slot. Used to give each fragment of a split
/// shm / file-backed region its own cap to revoke on teardown.
pub(crate) fn dup_cap(src: u64) -> Option<u64> {
    let dst = trona_runtime::core::slot_alloc::alloc_slot()?;
    let err = kernel_vm::cnode_copy_ref(
        KERNITE_CAP_SELF_CSPACE as u64,
        trona_runtime::core::slot_alloc::resolved_cap_ref(src),
        KERNITE_CAP_SELF_CSPACE as u64,
        trona_runtime::core::slot_alloc::resolved_cap_ref(dst.addr()),
        KERNITE_RIGHT_ALL as u64,
    );
    if err != 0 {
        // copy failed: `dst` (OwnedSlot) Drop frees the empty slot.
        return None;
    }
    Some(dst.into_raw())
}

/// Like [`dup_cap`] but mints the copy with an attenuated `rights` mask, so the
/// region's durable backing cap bounds its mapping's `max_prot` by construction
/// (e.g. a read-only-data region's cap carries no EXECUTE, so the kernel refuses
/// a later `mprotect(+X)`). `cnode_copy` can only narrow rights, so `rights` must
/// be a subset of the source cap's.
pub(crate) fn dup_cap_with_rights(src: u64, rights: u64) -> Option<u64> {
    let dst = trona_runtime::core::slot_alloc::alloc_slot()?;
    let err = kernel_vm::cnode_copy_ref(
        KERNITE_CAP_SELF_CSPACE as u64,
        trona_runtime::core::slot_alloc::resolved_cap_ref(src),
        KERNITE_CAP_SELF_CSPACE as u64,
        trona_runtime::core::slot_alloc::resolved_cap_ref(dst.addr()),
        rights,
    );
    if err != 0 {
        // copy failed: `dst` (OwnedSlot) Drop frees the empty slot.
        return None;
    }
    Some(dst.into_raw())
}

// ---------------------------------------------------------------------------
// Backing duplication / release — exact inverses
// ---------------------------------------------------------------------------

/// Release a region's kernel-side backing ownership (no VSpace unmap —
/// that is the caller's separate step). This is the single definition of
/// "drop one backing reference" and the exact inverse of both
/// `install`-time MO creation and [`duplicate_backing`].
pub(crate) fn release_region_backing(
    backing: BackingDescriptor,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) {
    match backing {
        // Registry-owned MOs: drop one refcount; frees frames at zero.
        BackingDescriptor::Anon { mo_handle, .. }
        | BackingDescriptor::CowChild { mo_handle, .. }
        | BackingDescriptor::Image { mo_handle, .. } => {
            let _ = mo_registry.release_by_handle(mo_handle.0 as usize, frames);
        }
        // File-backed: OwnedCap drops at end of arm, deleting the cap.
        BackingDescriptor::FileBacked { .. } => {}
        // SHM: OwnedCap drops at end of arm + registry map count.
        BackingDescriptor::Shm { shm_idx, .. } => {
            if let Ok(idx) = usize::try_from(shm_idx) {
                let _ = mo_registry.dec_map_count(idx, frames);
            }
        }
        BackingDescriptor::Device { .. } => {}
    }
}

/// Produce an independent backing handle that shares `orig`'s underlying
/// storage: registry-owned MOs take an extra refcount, shm / file-backed
/// mappings get a fresh cap copy (and shm bumps the map count). The
/// returned backing copies `orig`'s offset *verbatim*; the caller rebases
/// it to the fragment's position with [`rebase_backing`]. Returns `None`
/// on OOM (cap-copy failure), having mutated nothing.
fn duplicate_backing(
    orig: &BackingDescriptor,
    mo_registry: &mut MoRegistry,
) -> Option<BackingDescriptor> {
    match orig {
        BackingDescriptor::Anon {
            mo_handle,
            mo_offset,
        } => {
            if !mo_registry.retain_by_handle(mo_handle.0 as usize) {
                return None;
            }
            Some(BackingDescriptor::Anon {
                mo_handle: *mo_handle,
                mo_offset: *mo_offset,
            })
        }
        BackingDescriptor::CowChild {
            mo_handle,
            mo_offset,
            parent_region,
        } => {
            if !mo_registry.retain_by_handle(mo_handle.0 as usize) {
                return None;
            }
            Some(BackingDescriptor::CowChild {
                mo_handle: *mo_handle,
                mo_offset: *mo_offset,
                parent_region: *parent_region,
            })
        }
        BackingDescriptor::Image {
            mo_handle,
            mo_offset,
            image_kind,
        } => {
            if !mo_registry.retain_by_handle(mo_handle.0 as usize) {
                return None;
            }
            Some(BackingDescriptor::Image {
                mo_handle: *mo_handle,
                mo_offset: *mo_offset,
                image_kind: *image_kind,
            })
        }
        BackingDescriptor::Shm {
            mo_cap,
            shm_idx,
            mo_offset,
        } => {
            // SAFETY: dup_cap minted a fresh copy of the MO cap into a new global
            // slot; this OwnedCap is its sole owner.
            let copy = unsafe { OwnedCap::adopt_received(dup_cap(mo_cap.as_raw())?) };
            // Bump the shared map count to match the new mapping; on failure
            // (invalid shm slot — unreachable for a live region) drop the
            // freshly-dup'd cap and report failure rather than under-counting.
            let idx = usize::try_from(*shm_idx).ok()?;
            if !mo_registry.inc_map_count(idx) {
                return None;
            }
            Some(BackingDescriptor::Shm {
                mo_cap: copy,
                shm_idx: *shm_idx,
                mo_offset: *mo_offset,
            })
        }
        BackingDescriptor::FileBacked {
            mo_cap,
            mo_offset,
            file_id0,
            file_id1,
            file_offset,
            file_size,
            backing_kind,
            writeback,
        } => {
            // SAFETY: dup_cap minted a fresh copy of the MO cap into a new global
            // slot; this OwnedCap is its sole owner.
            let copy = unsafe { OwnedCap::adopt_received(dup_cap(mo_cap.as_raw())?) };
            Some(BackingDescriptor::FileBacked {
                mo_cap: copy,
                mo_offset: *mo_offset,
                file_id0: *file_id0,
                file_id1: *file_id1,
                file_offset: *file_offset,
                file_size: *file_size,
                backing_kind: *backing_kind,
                writeback: *writeback,
            })
        }
        BackingDescriptor::Device { phys_addr, length } => Some(BackingDescriptor::Device {
            phys_addr: *phys_addr,
            length: *length,
        }),
    }
}

/// Rebase a backing (whose offset currently matches the *region* base)
/// to a fragment that starts `page_delta` pages into the region and
/// spans `frag_pages` pages. MO-backed variants advance their page
/// offset; a device mapping advances its physical base and resizes its
/// length to the fragment.
fn rebase_backing(backing: &mut BackingDescriptor, page_delta: u32, frag_pages: u64) {
    match backing {
        BackingDescriptor::Anon { mo_offset, .. }
        | BackingDescriptor::CowChild { mo_offset, .. }
        | BackingDescriptor::FileBacked { mo_offset, .. }
        | BackingDescriptor::Shm { mo_offset, .. }
        | BackingDescriptor::Image { mo_offset, .. } => *mo_offset += page_delta,
        BackingDescriptor::Device { phys_addr, length } => {
            *phys_addr += page_delta as u64 * KERNITE_PAGE_BYTES;
            *length = frag_pages * KERNITE_PAGE_BYTES;
        }
    }
}

// ---------------------------------------------------------------------------
// MappingPlan — install one MO-backed region (mmap / mmap_mo / shm_map /
// heap growth). The caller creates the MO (or moves in a cap), builds
// the `backing`, then applies. On `Err` the caller frees its MO; on
// `Ok` the published region owns the backing reference.
// ---------------------------------------------------------------------------

pub(crate) struct MappingPlan {
    pub va_base: u64,
    pub pages: u64,
    pub prot: u8,
    pub region_type: u8,
    /// Fork inheritance policy stored on the published region. Validated
    /// against `backing` before any kernel side effect in [`Self::apply`].
    pub fork_policy: ForkPolicy,
    pub lazy: bool,
    /// MO cap to commit (if eager) and map.
    pub mo_cap: u64,
    /// Page offset into `mo_cap` for the kernel map.
    pub mo_offset_pages: u64,
    /// Commit `[mo_offset_pages, +pages)` before mapping (anon eager,
    /// shm). `false` for lazy anon and pager-backed MOs.
    pub eager_commit: bool,
    /// Backing descriptor stored on the published region.
    pub backing: BackingDescriptor,
    /// Reservation this mapping lives inside, if any.
    pub reservation: Option<ReservationId>,
    pub stack_allocator_badge: u64,
    pub guard_reservation_id: Option<ReservationId>,
}

impl MappingPlan {
    /// Reserve → (eager commit) → map → publish. On kernel failure the
    /// partial map is rolled back and `Err(code)` returned with nothing
    /// published; the caller frees the MO.
    ///
    /// # Safety
    /// Single-threaded server invariant; `vspace` / `mo_cap` valid.
    pub(crate) unsafe fn apply(
        self,
        vm: &mut ClientVm,
        vspace: u64,
        self_vm: &mut SelfVm,
    ) -> Result<RegionId, u64> {
        // Validate the (fork_policy, backing) pair BEFORE any kernel side
        // effect: apply commits/maps and only then publishes, so a mismatch
        // first caught at install time would strand a mapped VMA with no
        // region record. Reject up front instead.
        if !self.fork_policy.valid_for(&self.backing) {
            return Err(KERNITE_ERR_INVALID_ARGUMENT as u64);
        }
        if !unsafe { vm.reserve_region_capacity(1, self_vm) } {
            return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
        }
        if self.eager_commit {
            commit_range(self.mo_cap, self.mo_offset_pages, self.pages)?;
        }
        map_mo_range(
            vspace,
            self.mo_cap,
            self.va_base,
            self.mo_offset_pages,
            self.pages,
            self.prot,
            self.region_type,
        )?;
        let region = MappedRegion {
            base: self.va_base,
            length: self.pages * KERNITE_PAGE_BYTES,
            prot: self.prot,
            max_prot: max_prot_for_region_type(self.region_type),
            region_type: self.region_type,
            fork_policy: self.fork_policy,
            lazy: self.lazy,
            backing: self.backing,
            reservation: self.reservation,
            stack_allocator_badge: self.stack_allocator_badge,
            guard_reservation_id: self.guard_reservation_id,
        };
        match unsafe { vm.install_region(region, self_vm) } {
            Ok(rid) => Ok(rid),
            Err(e) => {
                // The kernel map (commit + map_mo_range above) is already
                // applied; undo it. Per this plan's contract the caller frees
                // the MO, so the recovered region's cap (if any) drops here
                // and we only unmap the VMA.
                let code = e.code();
                let _ = e.into_region();
                unmap_range(vspace, self.va_base, self.pages);
                Err(code)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Region split — the shared core of partial unmap and partial mprotect.
// ---------------------------------------------------------------------------

/// What a split does to the middle (hole) sub-range.
#[derive(Clone, Copy)]
pub(crate) enum SplitOp {
    /// Unmap the hole: VSpace-unmap it and decommit its MO pages; the
    /// hole's backing reference is dropped (it is never duplicated, so
    /// there is nothing to release).
    Unmap,
    /// Re-protect the hole to `new_prot`; the hole survives as its own
    /// region with an independent backing.
    Mprotect { new_prot: u8 },
}

/// Apply `op` to the sub-range `[hole_base, hole_base + hole_pages)` of
/// the region named by `id`, splitting it into up to three fragments
/// (before / hole / after). The caller has already validated that the
/// hole lies strictly within the region (a whole-region operation is
/// handled by the fast paths in [`unmap`] / [`mprotect`]).
///
/// Sequencing (rollback-consistent): reserve capacity for every
/// surviving fragment, duplicate the backings the survivors beyond the
/// first need, run the kernel op, then publish by vacating the original
/// and installing the fragments. Fragment 0 inherits the original
/// region's backing reference (the original is vacated without releasing
/// it); the others are duplicated. On a duplication or kernel failure
/// nothing is published and the duplicated backings are released.
///
/// # Safety
/// Single-threaded server invariant; `vspace` valid.
pub(crate) unsafe fn split_region(
    vm: &mut ClientVm,
    id: RegionId,
    hole_base: u64,
    hole_pages: u64,
    op: SplitOp,
    vspace: u64,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) -> Result<(), u64> {
    // Read the region's Copy-safe fields before vacating. `MappedRegion`
    // is not Copy (backing may be OwnedCap), so we borrow, extract what
    // we need, then vacate to take ownership of the backing.
    let (
        region_base,
        region_length,
        region_prot,
        region_type,
        region_lazy,
        region_reservation,
        region_stack_badge,
        region_guard_id,
        region_fork_policy,
    ) = {
        let Some(r) = (unsafe { vm.region(id) }) else {
            return Err(KERNITE_ERR_NOT_FOUND as u64);
        };
        (
            r.base,
            r.length,
            r.prot,
            r.region_type,
            r.lazy,
            r.reservation,
            r.stack_allocator_badge,
            r.guard_reservation_id,
            r.fork_policy,
        )
    };
    // A guarded stack is an atomic unit: a partial unmap / mprotect would
    // split it into fragments that each copy `guard_reservation_id`,
    // leaving several regions claiming one guard. Reject the split — the
    // whole-region `unmap` / `mprotect` paths handle stacks correctly.
    if region_guard_id.is_some() {
        return Err(KERNITE_ERR_INVALID_ARGUMENT as u64);
    }
    let region_pages = region_length / KERNITE_PAGE_BYTES;
    let hole_off_pages = (hole_base - region_base) / KERNITE_PAGE_BYTES;
    let before_pages = hole_off_pages;
    let after_pages = region_pages - hole_off_pages - hole_pages;

    // Build the surviving-fragment list as
    // `(base, pages, prot, page_delta_into_region)`. The middle (hole)
    // fragment only survives for mprotect.
    let mut frags: [(u64, u64, u8, u32); 3] = [(0, 0, 0, 0); 3];
    let mut nfrags = 0usize;
    if before_pages > 0 {
        frags[nfrags] = (region_base, before_pages, region_prot, 0);
        nfrags += 1;
    }
    if let SplitOp::Mprotect { new_prot } = op {
        if hole_pages > 0 {
            frags[nfrags] = (hole_base, hole_pages, new_prot, hole_off_pages as u32);
            nfrags += 1;
        }
    }
    if after_pages > 0 {
        let after_base = hole_base + hole_pages * KERNITE_PAGE_BYTES;
        frags[nfrags] = (
            after_base,
            after_pages,
            region_prot,
            (hole_off_pages + hole_pages) as u32,
        );
        nfrags += 1;
    }

    // Reserve publish capacity for every surviving fragment up front.
    if !unsafe { vm.reserve_region_capacity(nfrags as u32, self_vm) } {
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    }

    // Duplicate backings for fragments 1..nfrags by borrowing from the
    // live slab entry. The original region is NOT vacated yet — we keep
    // it intact so that on any failure we can return Err with the
    // original region still in the slab (no state change visible).
    // Fragment 0 will inherit the original's backing when we vacate
    // after the kernel op succeeds.
    let mut frag_backing: [Option<BackingDescriptor>; 2] = [None, None];
    for i in 1..nfrags {
        // Borrow the live backing for duplication. The slab entry is
        // still valid because we haven't vacated it.
        let src = match unsafe { vm.region(id) } {
            Some(r) => &r.backing,
            None => {
                for j in 1..i {
                    if let Some(b) = frag_backing[j - 1].take() {
                        release_region_backing(b, mo_registry, frames);
                    }
                }
                return Err(KERNITE_ERR_NOT_FOUND as u64);
            }
        };
        match duplicate_backing(src, mo_registry) {
            Some(b) => frag_backing[i - 1] = Some(b),
            None => {
                for j in 1..i {
                    if let Some(b) = frag_backing[j - 1].take() {
                        release_region_backing(b, mo_registry, frames);
                    }
                }
                return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
            }
        }
    }

    // Kernel side effect on the hole. On failure roll the duplicated
    // backings back; the original region is still in the slab, so no
    // restore is needed — we just return Err.
    let kernel_result = match op {
        SplitOp::Unmap => {
            // Unmap the hole from the VSpace only — deliberately NOT
            // decommitting the hole's MO pages. The MO may be shared
            // (Shm / SHARED_ANON / forked CowChild / FileBacked), so
            // freeing its frames here would corrupt other mappers. The
            // hole's frames are reclaimed when the surviving fragments
            // later unmap and the MO's refcount / map_count reaches zero
            // — the same discipline the whole-region `unmap` path relies
            // on. (Over-retention is bounded by the region's own size.)
            unmap_range(vspace, hole_base, hole_pages);
            Ok(())
        }
        SplitOp::Mprotect { new_prot } => protect_range(vspace, hole_base, hole_pages, new_prot),
    };
    if let Err(code) = kernel_result {
        for slot in frag_backing.iter_mut() {
            if let Some(b) = slot.take() {
                release_region_backing(b, mo_registry, frames);
            }
        }
        return Err(code);
    }

    // Kernel op succeeded. Now vacate the original record: fragment 0
    // inherits its backing, fragments 1..nfrags use the pre-duplicated
    // backings above. Capacity was reserved, so each install is infallible.
    let orig = match unsafe { vm.vacate_region(id) } {
        Some(r) => r,
        None => {
            // Should not happen (we already read the region above), but
            // release the duplicates defensively rather than leak them.
            for slot in frag_backing.iter_mut() {
                if let Some(b) = slot.take() {
                    release_region_backing(b, mo_registry, frames);
                }
            }
            return Err(KERNITE_ERR_NOT_FOUND as u64);
        }
    };
    let orig_backing = orig.backing;
    // Reprotect / unmap splits preserve the original region's ceiling.
    let region_max_prot = orig.max_prot;

    // Fragment 0 consumes orig_backing directly (we own it after vacate).
    // Handle it outside the loop to avoid borrow-vs-move conflicts with
    // the FileBacked/Shm OwnedCap inside BackingDescriptor.
    {
        let (base, pages, prot, page_delta) = frags[0];
        let mut backing = orig_backing;
        rebase_backing(&mut backing, page_delta, pages);
        let fragment = MappedRegion {
            base,
            length: pages * KERNITE_PAGE_BYTES,
            prot,
            max_prot: region_max_prot,
            region_type: region_type,
            fork_policy: region_fork_policy,
            lazy: region_lazy,
            backing,
            reservation: region_reservation,
            stack_allocator_badge: region_stack_badge,
            guard_reservation_id: region_guard_id,
        };
        let installed = unsafe { vm.install_region(fragment, self_vm) };
        debug_assert!(
            installed.is_ok(),
            "split fragment publish failed despite reserved capacity"
        );
        // Fragments reuse the original kernel mapping; on the unreachable
        // failure the recovered region drops here (its cap, if any, freed),
        // but the shared mapping must NOT be unmapped nor its backing
        // released — that would corrupt memory still mapped by the peers.
        let _ = installed;
    }

    // Fragments 1..nfrags use the pre-duplicated backings from frag_backing[i-1].
    for i in 1..nfrags {
        let (base, pages, prot, page_delta) = frags[i];
        let mut backing = match frag_backing[i - 1].take() {
            Some(b) => b,
            None => continue,
        };
        rebase_backing(&mut backing, page_delta, pages);
        let fragment = MappedRegion {
            base,
            length: pages * KERNITE_PAGE_BYTES,
            prot,
            max_prot: region_max_prot,
            region_type: region_type,
            fork_policy: region_fork_policy,
            lazy: region_lazy,
            backing,
            reservation: region_reservation,
            stack_allocator_badge: region_stack_badge,
            guard_reservation_id: region_guard_id,
        };
        let installed = unsafe { vm.install_region(fragment, self_vm) };
        debug_assert!(
            installed.is_ok(),
            "split fragment publish failed despite reserved capacity"
        );
        // Fragments reuse the original kernel mapping; on the unreachable
        // failure the recovered region drops here (its cap, if any, freed),
        // but the shared mapping must NOT be unmapped nor its backing
        // released — that would corrupt memory still mapped by the peers.
        let _ = installed;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// unmap / mprotect — full-region fast path + split slow path.
// ---------------------------------------------------------------------------

/// Unmap `[base, base + pages*PAGE)` from the region containing `base`.
/// A range covering the whole region drops it; a strict sub-range splits
/// it. The kernel unmap + backing teardown of the removed pages is done
/// here.
///
/// # Safety
/// Single-threaded server invariant.
pub(crate) unsafe fn unmap(
    vm: &mut ClientVm,
    base: u64,
    pages: u64,
    vspace: u64,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) -> Result<(), u64> {
    let Some(id) = (unsafe { vm.find_region(base) }) else {
        return Err(KERNITE_ERR_NOT_FOUND as u64);
    };
    let (region_base, region_va_end, region_length) = {
        let Some(r) = (unsafe { vm.region(id) }) else {
            return Err(KERNITE_ERR_NOT_FOUND as u64);
        };
        (r.base, r.va_end(), r.length)
    };
    let end = base + pages * KERNITE_PAGE_BYTES;
    if base < region_base || end > region_va_end {
        return Err(KERNITE_ERR_INVALID_ARGUMENT as u64);
    }
    if base == region_base && end == region_va_end {
        // Whole-region unmap: kernel unmap + drop the backing. If this is
        // a guarded stack, drop its guard reservation in the same step so
        // the stack and its guard never outlive one another.
        unmap_range(vspace, region_base, region_length / KERNITE_PAGE_BYTES);
        if let Some(removed) = unsafe { vm.vacate_region(id) } {
            release_region_backing(removed.backing, mo_registry, frames);
            if let Some(guard_id) = removed.guard_reservation_id {
                unsafe { vm.vacate_reservation(guard_id) };
            }
        }
        Ok(())
    } else {
        unsafe {
            split_region(
                vm,
                id,
                base,
                pages,
                SplitOp::Unmap,
                vspace,
                self_vm,
                mo_registry,
                frames,
            )
        }
    }
}

/// Unmap every mapped fragment that overlaps `[base, base + pages*PAGE)`.
/// Holes are ignored, so callers can apply POSIX `munmap` and `MAP_FIXED`
/// replacement semantics without first coalescing region records.
///
/// # Safety
/// Single-threaded server invariant.
pub(crate) unsafe fn force_unmap_range(
    vm: &mut ClientVm,
    base: u64,
    pages: u64,
    vspace: u64,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) -> Result<(), u64> {
    if pages == 0 {
        return Ok(());
    }
    let bytes = pages
        .checked_mul(KERNITE_PAGE_BYTES)
        .ok_or(KERNITE_ERR_OUT_OF_RANGE as u64)?;
    let end = base
        .checked_add(bytes)
        .ok_or(KERNITE_ERR_OUT_OF_RANGE as u64)?;

    loop {
        let remaining = end - base;
        let Some(id) = (unsafe { va_alloc::range_overlaps_mapping(vm, base, remaining) }) else {
            return Ok(());
        };
        let (region_base, region_end) = {
            let Some(r) = (unsafe { vm.region(id) }) else {
                return Err(KERNITE_ERR_NOT_FOUND as u64);
            };
            (r.base, r.va_end())
        };
        let isect_base = core::cmp::max(base, region_base);
        let isect_end = core::cmp::min(end, region_end);
        if isect_end <= isect_base {
            return Err(KERNITE_ERR_OUT_OF_RANGE as u64);
        }
        let isect_pages = (isect_end - isect_base) / KERNITE_PAGE_BYTES;
        unsafe {
            unmap(
                vm,
                isect_base,
                isect_pages,
                vspace,
                self_vm,
                mo_registry,
                frames,
            )?;
        }
    }
}

/// Re-protect `[base, base + pages*PAGE)` of the region containing
/// `base` to `new_prot`. A whole-region range updates the record in
/// place; a sub-range splits.
///
/// # Safety
/// Single-threaded server invariant.
pub(crate) unsafe fn mprotect(
    vm: &mut ClientVm,
    base: u64,
    pages: u64,
    new_prot: u8,
    vspace: u64,
    self_vm: &mut SelfVm,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) -> Result<(), u64> {
    let Some(id) = (unsafe { vm.find_region(base) }) else {
        return Err(KERNITE_ERR_NOT_FOUND as u64);
    };
    let (region_base, region_va_end, region_max_prot) = {
        let Some(r) = (unsafe { vm.region(id) }) else {
            return Err(KERNITE_ERR_NOT_FOUND as u64);
        };
        (r.base, r.va_end(), r.max_prot)
    };
    let end = base + pages * KERNITE_PAGE_BYTES;
    if base < region_base || end > region_va_end {
        return Err(KERNITE_ERR_INVALID_ARGUMENT as u64);
    }
    // Defence-in-depth: reject a reprotect that exceeds the region's
    // ceiling (the kernel's cap-derived `VmArea.max_prot` is authoritative).
    // Keeps image text non-writable and rodata non-executable (W^X).
    if new_prot & !region_max_prot != 0 {
        return Err(KERNITE_ERR_INSUFFICIENT_RIGHTS as u64);
    }
    if base == region_base && end == region_va_end {
        protect_range(vspace, base, pages, new_prot)?;
        if let Some(r) = unsafe { vm.region_mut(id) } {
            r.prot = new_prot;
        }
        Ok(())
    } else {
        unsafe {
            split_region(
                vm,
                id,
                base,
                pages,
                SplitOp::Mprotect { new_prot },
                vspace,
                self_vm,
                mo_registry,
                frames,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// reserve / unreserve — pure bookkeeping (no kernel op), so they reduce
// to the fallible install / vacate on the reservation slab.
// ---------------------------------------------------------------------------

/// Insert a `ReservedRange`. Pure bookkeeping — no kernel side effect —
/// so a fallible install with no rollback is sufficient.
///
/// # Safety
/// Single-threaded server invariant.
pub(crate) unsafe fn reserve_range(
    vm: &mut ClientVm,
    base: u64,
    length: u64,
    kind: ReservationKind,
    owner_badge: u64,
    self_vm: &mut SelfVm,
) -> Result<ReservationId, u64> {
    let range = ReservedRange {
        base,
        length,
        kind,
        purpose: ReservationPurpose::General,
        owner_badge,
        stack_region_id: None,
    };
    unsafe { vm.install_reservation(range, self_vm) }.ok_or(KERNITE_ERR_OUT_OF_MEMORY as u64)
}

/// Remove the reservation covering `base`. No kernel side effect.
///
/// # Safety
/// Single-threaded server invariant.
pub(crate) unsafe fn unreserve_range(vm: &mut ClientVm, base: u64) -> Result<(), u64> {
    let Some(id) = (unsafe { vm.find_reservation(base) }) else {
        return Err(KERNITE_ERR_NOT_FOUND as u64);
    };
    // Stack guards are owned by their stack's lifecycle (created with the
    // stack, dropped when it unmaps). A client must not drop one directly,
    // or its stack would be left with a dangling guard link and an
    // unprotected overflow gap.
    if matches!(
        unsafe { vm.reservation(id) }.map(|r| r.kind),
        Some(ReservationKind::Guard)
    ) {
        return Err(KERNITE_ERR_INVALID_ARGUMENT as u64);
    }
    unsafe { vm.vacate_reservation(id) };
    Ok(())
}

// ---------------------------------------------------------------------------
// Stack guard band — an unmapped reservation immediately below every stack.
// ---------------------------------------------------------------------------

/// Default width of the unmapped guard band placed below a runtime
/// (`MM_MMAP`) stack — one page, matching the default `pthread` guard.
/// Staged stacks instead carry their own guard size (the loader's
/// `guard_pages`) over the wire. A stack (which grows down) that overruns
/// its lowest page runs into this never-mapped range and faults, instead
/// of silently growing into an adjacent mapping.
pub(crate) const STACK_GUARD_BYTES: u64 = KERNITE_PAGE_BYTES;

/// Reserve the guard band `[stack_base - STACK_GUARD_BYTES, stack_base)`
/// for a stack whose lowest mapped page is at `stack_base`. The returned
/// [`ReservationId`] is `kind == Guard`; its `stack_region_id` is left
/// `None` until the caller installs the stack region and back-patches it
/// (the stack does not exist yet when the guard is reserved). The
/// region's own `guard_reservation_id` is set to this id at install.
///
/// Reserving the guard first keeps rollback trivial: it is pure
/// bookkeeping with no kernel side effect, so a failed stack map only has
/// to `vacate_reservation` the guard. Returns `None` on slab exhaustion
/// or if `stack_base` is below one guard band (no room for a guard).
///
/// # Safety
/// Single-threaded server invariant.
pub(crate) unsafe fn reserve_stack_guard(
    vm: &mut ClientVm,
    stack_base: u64,
    guard_bytes: u64,
    owner_badge: u64,
    self_vm: &mut SelfVm,
) -> Option<ReservationId> {
    let guard_base = stack_base.checked_sub(guard_bytes)?;
    let guard = ReservedRange {
        base: guard_base,
        length: guard_bytes,
        kind: ReservationKind::Guard,
        purpose: ReservationPurpose::General,
        owner_badge,
        stack_region_id: None,
    };
    unsafe { vm.install_reservation(guard, self_vm) }
}

/// Like [`reserve_stack_guard`] but first verifies the guard band is free
/// in `vm`. Used for stacks placed by an external layout (staged spawn /
/// exec images), where — unlike the `MM_MMAP` path that places
/// `size + guard` itself — the guard slot below `stack_base` is not
/// guaranteed free (the loader's `guard_pages` may be zero).
///
/// Distinguishes the two `None`-ish outcomes the caller must treat
/// differently:
/// * `Ok(Some(id))` — guard reserved.
/// * `Ok(None)` — no room below, or the slot is already occupied; the
///   stack lands without a tracked guard (an intentional state when the
///   layout left no guard gap). Not an error.
/// * `Err(code)` — the guard slot was free but the reservation slab is
///   exhausted; the caller must propagate this as a staging failure
///   rather than silently dropping a guard the layout asked for.
///
/// # Safety
/// Single-threaded server invariant.
pub(crate) unsafe fn reserve_stack_guard_if_free(
    vm: &mut ClientVm,
    stack_base: u64,
    guard_bytes: u64,
    owner_badge: u64,
    self_vm: &mut SelfVm,
) -> Result<Option<ReservationId>, u64> {
    if guard_bytes == 0 {
        // The layout requested no guard (`guard_pages == 0`).
        return Ok(None);
    }
    let Some(guard_base) = stack_base.checked_sub(guard_bytes) else {
        return Ok(None);
    };
    let free = unsafe {
        crate::va_alloc::range_overlaps_mapping(vm, guard_base, guard_bytes).is_none()
            && crate::va_alloc::range_overlaps_reservation(vm, guard_base, guard_bytes, None)
                .is_none()
    };
    if !free {
        return Ok(None);
    }
    match unsafe { reserve_stack_guard(vm, stack_base, guard_bytes, owner_badge, self_vm) } {
        Some(id) => Ok(Some(id)),
        None => Err(KERNITE_ERR_OUT_OF_MEMORY as u64),
    }
}
