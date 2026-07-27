// SPDX-License-Identifier: GPL-2.0-only
//
//! Canonical per-client memory-region vocabulary.
//!
//! This module owns the policy-side types every mmsrv layer shares: the
//! region-kind tag space (`REGION_*` + [`kernel_region_kind`]), the typed
//! slab handles ([`RegionId`] / [`ReservationId`]) that wrap
//! [`trona_server::slab::SlabId`], the polymorphic [`BackingDescriptor`],
//! the [`MappedRegion`] policy record, and the [`ReservedRange`] arena /
//! guard record.
//!
//! The growable slab + index machinery and the neutral
//! [`ReservationKind`](trona_server::slab::ReservationKind) discriminant
//! live in `trona_server::slab`; the per-client container that owns the
//! slabs is `crate::client::ClientVm`. Region and reservation records are
//! created and mutated only through the `MapPlan` family in `crate::txn`
//! — direct slab mutation outside that path violates the
//! `no_partial_publish` invariant.

use trona_runtime::core::slot_alloc::OwnedCap;
use trona_server::slab::{ReservationKind, SlabId};

// ---------------------------------------------------------------------------
// Region type tags (u8).
//
// Values 0..=7 are bit-identical to the kernel's `KERNITE_REGION_KIND_*`
// byte (`kernite/include/uapi/vmem.h`); they are passed straight
// through `VSPACE_FLAG_REGION_KIND_SHIFT` on every `VSPACE_MAP_MO`.
//
// Values 8.. are mmsrv-private classifications that the kernel does
// not understand. When sending one of these over the wire, route it
// through `kernel_region_kind()` — never shift the raw byte into
// `VSPACE_FLAG_REGION_KIND_MASK`.
// ---------------------------------------------------------------------------

// Kernel-shared subset: values are bit-identical to the kernel's
// `KERNITE_REGION_KIND_*` (`kernite/include/uapi/vmem.h`), so
// `kernel_region_kind` returns them unchanged.
pub(crate) const REGION_NONE: u8 = 0;
/// Executable `PT_LOAD` segment of the main program image.
pub(crate) const REGION_IMAGE_TEXT: u8 = 1;
/// Writable `PT_LOAD` segment of the main program image backed by the
/// file.
pub(crate) const REGION_IMAGE_DATA: u8 = 2;
/// Anonymous zero-fill tail of an ELF `PT_LOAD` (`memsz > filesz`).
pub(crate) const REGION_IMAGE_BSS: u8 = 3;
pub(crate) const REGION_HEAP: u8 = 4;
/// User/thread stack region. Set by `MAP_STACK` or by the spawner when
/// it reserves the initial stack range. Feeds `VmStk` in procfs.
pub(crate) const REGION_STACK: u8 = 5;
pub(crate) const REGION_MMAP: u8 = 6;
/// Read-only mapping of a shared library (or any image-shared rodata).
pub(crate) const REGION_SHARED_LIB: u8 = 7;

// mmsrv-private classifications (>= 8). Translate via `kernel_region_kind()`
// before sending to the kernel.
pub(crate) const REGION_SPAWN: u8 = 8;
pub(crate) const REGION_SHARED_RO: u8 = 9;
pub(crate) const REGION_FILE_SHARED: u8 = 10;
pub(crate) const REGION_IPC: u8 = 11;
/// Shared memory region published by `MM_SHM_MAP`
/// (`BackingDescriptor::ShmFrames`).
pub(crate) const REGION_SHM: u8 = 12;

/// Translate a mmsrv `region_type` byte into the kernel `REGION_KIND_*`
/// byte that goes into `VSPACE_FLAG_REGION_KIND_MASK`.
///
/// Values 0..=7 round-trip identically. mmsrv-private kinds (>= 8) map
/// to the closest kernel-recognised category so the kernel's per-VmArea
/// accounting and stack-bound invariants still receive a sensible tag.
#[inline]
pub(crate) const fn kernel_region_kind(t: u8) -> u8 {
    // Region types 0..=7 round-trip identically to the kernel's
    // `KERNITE_REGION_KIND_*` values, so the canonical kinds return `t`
    // unchanged. mmsrv-private kinds (>= 8) collapse to the closest
    // kernel-recognised category.
    match t {
        REGION_SPAWN => REGION_NONE,
        REGION_SHARED_RO => REGION_SHARED_LIB,
        REGION_FILE_SHARED => REGION_MMAP,
        REGION_IPC => REGION_NONE,
        REGION_SHM => REGION_MMAP,
        _ if t <= REGION_SHARED_LIB => t,
        _ => REGION_NONE,
    }
}

/// The mmsrv-side `MM_MPROTECT` ceiling for a region, by `region_type`
/// (PROT_* encoding: READ=1, WRITE=2, EXEC=4).
///
/// Defence-in-depth: the kernel's per-`VmArea` `max_prot` (derived from
/// the backing cap's rights) is the authoritative ceiling. This mirror
/// lets mmsrv reject an over-broad reprotect early (EACCES) for image
/// segments so text stays non-writable and rodata non-executable (W^X).
/// Non-image regions get a permissive ceiling — the kernel governs them.
#[inline]
pub(crate) fn max_prot_for_region_type(region_type: u8) -> u8 {
    const R: u8 = 0x1;
    const W: u8 = 0x2;
    const X: u8 = 0x4;
    match region_type {
        REGION_IMAGE_TEXT => R | X,
        REGION_SHARED_LIB => R,
        REGION_IMAGE_DATA | REGION_IMAGE_BSS => R | W,
        _ => R | W | X,
    }
}

// ---------------------------------------------------------------------------
// Typed handles — RegionId / ReservationId
//
// Both wrap a `trona_server::slab::SlabId` so a region handle cannot be
// confused with a reservation handle at a call site. `idx == 0` is the
// reserved sentinel, so the all-zero pattern is always invalid and safe
// to default-construct.
// ---------------------------------------------------------------------------

/// Stable handle to a `MappedRegion` slot in a per-client `regions_slab`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub(crate) struct RegionId(pub(crate) SlabId);

impl RegionId {
    /// Wrap a raw slab handle returned by `TrackedSlab::slot_alloc`.
    #[inline]
    pub(crate) const fn from_slab(id: SlabId) -> Self {
        Self(id)
    }

    /// The underlying slab handle, for `slot_get` / `slot_get_mut` /
    /// `slot_free`.
    #[inline]
    pub(crate) const fn slab(self) -> SlabId {
        self.0
    }

    /// Slab slot index — also the bare `BaseSortedIndex` slot key.
    #[inline]
    pub(crate) const fn idx(self) -> u32 {
        self.0.idx
    }

    /// Slot incarnation epoch.
    #[inline]
    pub(crate) const fn epoch(self) -> u32 {
        self.0.epoch
    }

    /// Reconstruct from a packed `u64` (`idx` low, `epoch` high) — the
    /// inverse of the wire packing done by `MM_MMAP`'s reply.
    #[inline]
    pub(crate) const fn unpack(packed: u64) -> Self {
        Self(SlabId {
            idx: packed as u32,
            epoch: (packed >> 32) as u32,
        })
    }
}

/// Stable handle to a `ReservedRange` slot in a per-client
/// `reservations_slab`. Same shape and semantics as [`RegionId`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub(crate) struct ReservationId(pub(crate) SlabId);

impl ReservationId {
    /// Wrap a raw slab handle returned by `TrackedSlab::slot_alloc`.
    #[inline]
    pub(crate) const fn from_slab(id: SlabId) -> Self {
        Self(id)
    }

    /// The underlying slab handle, for `slot_get` / `slot_get_mut` /
    /// `slot_free`.
    #[inline]
    pub(crate) const fn slab(self) -> SlabId {
        self.0
    }

    /// Slab slot index — also the bare `BaseSortedIndex` slot key.
    #[inline]
    pub(crate) const fn idx(self) -> u32 {
        self.0.idx
    }

    /// Pack into a single `u64` for the wire (`idx` low, `epoch` high).
    /// Returned to the caller by `MM_RESERVE_RANGE`.
    #[inline]
    pub(crate) const fn pack(self) -> u64 {
        ((self.0.epoch as u64) << 32) | self.0.idx as u64
    }

    /// Reconstruct from a packed `u64` — the inverse of [`pack`](Self::pack).
    /// Used by `MM_UNMAP_IMAGE` to recover the image reservation from its id.
    #[inline]
    pub(crate) const fn unpack(packed: u64) -> Self {
        Self(SlabId {
            idx: packed as u32,
            epoch: (packed >> 32) as u32,
        })
    }
}

// ---------------------------------------------------------------------------
// BackingDescriptor — typed enum replacing the old grab-bag of
// `mo_cap` / `mo_offset` / `backing_kind` / `backing_id*` /
// `backing_file_*` fields.
// ---------------------------------------------------------------------------

/// Image segment classification for the `Image` variant of
/// [`BackingDescriptor`]. Mirrors the user-visible region_type values
/// `REGION_IMAGE_TEXT` / `REGION_IMAGE_DATA` / `REGION_IMAGE_BSS` /
/// `REGION_SHARED_LIB` so procfs / sysctlfs can project the kind without
/// re-deriving from `region_type`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub(crate) enum ImageKind {
    Text = 0,
    RoData = 1,
    Data = 2,
    Bss = 3,
}

/// Whether and how a [`MappedRegion`] is inherited by a child VSpace on
/// `fork`. Stored on the region rather than derived at fork time, because
/// the same backing can carry different inheritance: an
/// [`Anon`](BackingDescriptor::Anon) mapping is `InheritCow` when
/// `MAP_PRIVATE` but `InheritShare` when `MAP_SHARED` — the share-ness is
/// not recoverable from the backing alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ForkPolicy {
    /// Child maps the *same* backing object (no copy): read-only sharing
    /// for image text / rodata, writable sharing for `MAP_SHARED` anon,
    /// SHM, and shared file mappings.
    InheritShare,
    /// Child gets a copy-on-write fork of the backing (private semantics).
    InheritCow,
    /// Not inherited — the child's VSpace receives nothing for this region
    /// (device mappings, and regions the caller excludes by VA).
    Exclude,
}

impl ForkPolicy {
    /// A `(policy, backing)` pair is valid iff the policy's inheritance
    /// mechanism can act on that backing. `Exclude` fits any backing;
    /// `InheritShare` needs a shareable MO (anon / shm / file / image
    /// text-rodata); `InheritCow` needs a COW-forkable backing (anon /
    /// cow-child / writable image data-bss). `Device` is shareable by
    /// nobody and COW-forkable by nobody, so it is only ever `Exclude`.
    /// Enforced as a backstop in `install_region`, and before kernel side
    /// effects in `MappingPlan::apply`.
    pub(crate) fn valid_for(self, backing: &BackingDescriptor) -> bool {
        match self {
            ForkPolicy::Exclude => true,
            ForkPolicy::InheritShare => match backing {
                BackingDescriptor::Anon { .. }
                | BackingDescriptor::FileBacked { .. }
                | BackingDescriptor::Shm { .. } => true,
                BackingDescriptor::Image { image_kind, .. } => {
                    matches!(image_kind, ImageKind::Text | ImageKind::RoData)
                }
                _ => false,
            },
            ForkPolicy::InheritCow => match backing {
                BackingDescriptor::Anon { .. } | BackingDescriptor::CowChild { .. } => true,
                BackingDescriptor::Image { image_kind, .. } => {
                    matches!(image_kind, ImageKind::Data | ImageKind::Bss)
                }
                _ => false,
            },
        }
    }
}

/// An index into `MoRegistry` — the canonical domain handle for MOs
/// whose lifetime is governed by the registry (anonymous, COW, image).
/// The registry is the sole owner of the kernel cap; holders of a
/// `MoHandle` never delete or free the underlying cap directly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub(crate) struct MoHandle(pub(crate) u32);

/// Polymorphic backing storage. Variants that hold a registry-managed
/// MO carry a [`MoHandle`] (domain handle, registry is the cap owner);
/// variants with caller-transferred caps carry an [`OwnedCap`] (this
/// region record is the cap owner). The enum is therefore NOT `Copy`.
///
/// [`MappedRegion`] embeds this and is also not `Copy`.
#[derive(Debug)]
pub(crate) enum BackingDescriptor {
    /// Anonymous private mapping. `mo_handle` indexes the backing pages
    /// in `MoRegistry`; `mo_offset` is a page offset into that MO.
    Anon { mo_handle: MoHandle, mo_offset: u32 },
    /// Copy-on-write child segment of a forked parent. `parent_region`
    /// records the parent's [`RegionId`] for cross-client visibility.
    CowChild {
        mo_handle: MoHandle,
        mo_offset: u32,
        parent_region: RegionId,
    },
    /// File-backed mapping. `file_id0` / `file_id1` identify the file in
    /// VFS terms; `file_offset` / `file_size` describe the backed
    /// extent. `backing_kind` distinguishes
    /// `MMAP_BACKING_FILE` / `_MOUNT` / `_DEVICE` so writeback / sync
    /// paths can route appropriately. `mo_cap` is caller-transferred;
    /// this record is the cap owner and frees it on drop.
    FileBacked {
        mo_cap: OwnedCap,
        mo_offset: u32,
        file_id0: u64,
        file_id1: u64,
        file_offset: u64,
        file_size: u64,
        backing_kind: u8,
        writeback: bool,
    },
    /// SHM mapping backed by a registered shared MemoryObject (the live,
    /// MO-backed SHM model — the canonical SHM ABI). `mo_cap` is this
    /// mapping's own caller-transferred cap copy of the shared MO;
    /// `shm_idx` is the `MoRegistry` slot of the shared object, tracked
    /// for map-count refcounting on unmap; `mo_offset` is the page
    /// offset into the MO for partial SHM mappings.
    Shm {
        mo_cap: OwnedCap,
        shm_idx: u32,
        mo_offset: u32,
    },
    /// Direct device mapping (e.g. framebuffer, MMIO register page).
    /// `phys_addr` is the physical base; mmsrv maps it through
    /// `VSPACE_MAP_DEVICE_RANGE`.
    Device { phys_addr: u64, length: u64 },
    /// Image segment from the program ELF/PE. `mo_handle` indexes the
    /// per-image MO in `MoRegistry`; `mo_offset` is the page offset
    /// within it.
    Image {
        mo_handle: MoHandle,
        mo_offset: u32,
        image_kind: ImageKind,
    },
}

impl BackingDescriptor {
    /// Return the raw cap slot for MO-backed variants. For
    /// registry-managed variants (`Anon`/`CowChild`/`Image`) the caller
    /// must pass the `MoRegistry` and resolve the cap through the handle;
    /// this method returns 0 for those (and for `Device`). Use
    /// [`mo_handle`](Self::mo_handle) + registry lookup for those cases.
    ///
    /// For `FileBacked` and `Shm` the cap is caller-owned and this
    /// returns the raw slot directly.
    pub(crate) fn owned_mo_cap_raw(&self) -> u64 {
        match self {
            BackingDescriptor::FileBacked { mo_cap, .. }
            | BackingDescriptor::Shm { mo_cap, .. } => mo_cap.as_raw(),
            _ => 0,
        }
    }

    /// Return the `MoHandle` for registry-managed variants. Returns
    /// `None` for `FileBacked`, `Shm`, and `Device`.
    pub(crate) fn mo_handle(&self) -> Option<MoHandle> {
        match self {
            BackingDescriptor::Anon { mo_handle, .. }
            | BackingDescriptor::CowChild { mo_handle, .. }
            | BackingDescriptor::Image { mo_handle, .. } => Some(*mo_handle),
            _ => None,
        }
    }

    /// Return the page offset within the MO if applicable.
    pub(crate) fn mo_offset(&self) -> u32 {
        match self {
            BackingDescriptor::Anon { mo_offset, .. }
            | BackingDescriptor::CowChild { mo_offset, .. }
            | BackingDescriptor::FileBacked { mo_offset, .. }
            | BackingDescriptor::Shm { mo_offset, .. }
            | BackingDescriptor::Image { mo_offset, .. } => *mo_offset,
            BackingDescriptor::Device { .. } => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// MappedRegion — the per-mapping policy record. Stack guard information
// lives in `ReservedRange(kind=Guard)`; the back-link is
// `guard_reservation_id`.
// ---------------------------------------------------------------------------

/// Per-mapping policy record. Stored in a client's `regions_slab`. A
/// region is live exactly while its slab slot is occupied — the slab is
/// the authoritative liveness record. The backing storage is described
/// by `backing` rather than a flat collection of fields. The transaction
/// primitive (see `crate::txn`) is the only path that may install,
/// shrink, or extend a region.
///
/// Not `Copy` because [`BackingDescriptor`] may contain [`OwnedCap`]
/// fields (`FileBacked`, `Shm`). The slab's `slot_free` calls
/// `drop_in_place`, which runs the `OwnedCap` destructor correctly.
pub(crate) struct MappedRegion {
    pub(crate) base: u64,
    pub(crate) length: u64,
    pub(crate) prot: u8,
    /// Defence-in-depth `MM_MPROTECT` ceiling (PROT_* encoding: READ=1,
    /// WRITE=2, EXEC=4). A reprotect that exceeds this is rejected early.
    /// Image segments are tight (text R|X, rodata R, data/bss R|W) so W^X
    /// holds; other regions are permissive and rely on the kernel's
    /// cap-derived `VmArea.max_prot` as the authoritative ceiling.
    pub(crate) max_prot: u8,
    pub(crate) region_type: u8,
    /// Fork inheritance policy — how a child VSpace receives this region on
    /// `fork`: share the same backing, COW-fork it, or exclude it. Stored
    /// (not derived) so MAP_SHARED vs MAP_PRIVATE anon are distinguishable;
    /// validated against `backing` by [`ForkPolicy::valid_for`].
    pub(crate) fork_policy: ForkPolicy,
    pub(crate) lazy: bool,
    pub(crate) backing: BackingDescriptor,
    /// Reservation that this mapping lives inside, if any. Carried
    /// across `fork` via the `ForkPlan` reservation remap.
    pub(crate) reservation: Option<ReservationId>,
    /// `REGION_STACK`-only: the badge that allocated this stack via
    /// `MM_ALLOC_STACK_REGION`. Zero for stacks that came in via
    /// `posix_mmap(MAP_STACK)`.
    pub(crate) stack_allocator_badge: u64,
    /// `REGION_STACK`-only back-link to the matching guard reservation
    /// (`ReservedRange(kind=Guard)`). Used by `StackFreePlan` to drop
    /// both halves atomically and by the unmap path to veto a solo
    /// stack-mapping unmap.
    pub(crate) guard_reservation_id: Option<ReservationId>,
}

impl MappedRegion {
    /// First VA past the end of this mapping. `length` is a byte count,
    /// so this is `base + length` (saturating).
    #[inline]
    pub(crate) fn va_end(&self) -> u64 {
        self.base.saturating_add(self.length)
    }

    /// Backstop check that this region's `fork_policy` is consistent with
    /// its `backing` (see [`ForkPolicy::valid_for`]). `install_region`
    /// refuses to publish a region that fails this.
    #[inline]
    pub(crate) fn validate_fork_policy(&self) -> bool {
        self.fork_policy.valid_for(&self.backing)
    }

    /// Placeholder value used by `mem::replace` when moving a
    /// `MappedRegion` out of a slab slot before freeing the slot.
    /// The tombstone carries a `Device` backing with zero length so
    /// that if it is ever accidentally dropped, no OwnedCap destructor
    /// fires and no registry refcount is touched.
    #[inline]
    pub(crate) fn tombstone() -> Self {
        Self {
            base: 0,
            length: 0,
            prot: 0,
            max_prot: 0,
            region_type: 0,
            fork_policy: ForkPolicy::Exclude,
            lazy: false,
            backing: BackingDescriptor::Device {
                phys_addr: 0,
                length: 0,
            },
            reservation: None,
            stack_allocator_badge: 0,
            guard_reservation_id: None,
        }
    }

    /// Produce a shallow copy of this region's scalar fields for use by
    /// `region_snapshot_at`. Registry-managed backings (`Anon`,
    /// `CowChild`, `Image`) are copied verbatim (their `MoHandle` is
    /// `Copy`). Caller-owned backings (`FileBacked`, `Shm`) hold an
    /// `OwnedCap` that cannot be shallow-copied, so they are replaced with
    /// a `Device(0,0)` tombstone; `fork_policy` is preserved regardless. A
    /// fork that must share such a region (`InheritShare`) therefore
    /// re-reads the *live* parent region and dups its cap rather than the
    /// tombstoned snapshot. The caller is responsible for incrementing any
    /// registry refcount before the snapshot's backing is used as a live
    /// reference.
    pub(crate) fn snapshot(&self) -> Self {
        let backing = match &self.backing {
            BackingDescriptor::Anon {
                mo_handle,
                mo_offset,
            } => BackingDescriptor::Anon {
                mo_handle: *mo_handle,
                mo_offset: *mo_offset,
            },
            BackingDescriptor::CowChild {
                mo_handle,
                mo_offset,
                parent_region,
            } => BackingDescriptor::CowChild {
                mo_handle: *mo_handle,
                mo_offset: *mo_offset,
                parent_region: *parent_region,
            },
            BackingDescriptor::Image {
                mo_handle,
                mo_offset,
                image_kind,
            } => BackingDescriptor::Image {
                mo_handle: *mo_handle,
                mo_offset: *mo_offset,
                image_kind: *image_kind,
            },
            BackingDescriptor::Device { phys_addr, length } => BackingDescriptor::Device {
                phys_addr: *phys_addr,
                length: *length,
            },
            // FileBacked / Shm carry OwnedCap — cannot shallow-copy. The
            // fork share path re-reads the live region for these; provide
            // a tombstone so an accidental drop touches no cap.
            BackingDescriptor::FileBacked { .. } | BackingDescriptor::Shm { .. } => {
                BackingDescriptor::Device {
                    phys_addr: 0,
                    length: 0,
                }
            }
        };
        Self {
            base: self.base,
            length: self.length,
            prot: self.prot,
            max_prot: self.max_prot,
            region_type: self.region_type,
            fork_policy: self.fork_policy,
            lazy: self.lazy,
            backing,
            reservation: self.reservation,
            stack_allocator_badge: self.stack_allocator_badge,
            guard_reservation_id: self.guard_reservation_id,
        }
    }
}

// ---------------------------------------------------------------------------
// ReservedRange + ReservationKind policy
// ---------------------------------------------------------------------------

/// Whether a [`ReservationKind`] is inherited across `fork`.
///
/// `Arena` / `Guard` / `Exclusion` are inherited so the child keeps the
/// parent's VA shape; `System` (per-process scratch) is not — the child
/// re-establishes its own. This is mmsrv policy layered over the neutral
/// `trona_server` discriminant.
#[inline]
pub(crate) fn reservation_kind_inherits_on_fork(kind: ReservationKind) -> bool {
    !matches!(kind, ReservationKind::System)
}

/// What a [`ReservedRange`] is for — mmsrv-local provenance layered over the
/// neutral [`ReservationKind`]. Keeps `MM_UNMAP_IMAGE` from tearing down a plain
/// arena: only an `Image` reservation (the load envelope of a mapped image) is a
/// valid teardown handle.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReservationPurpose {
    /// A general VA reservation (arena gap-fill, guard, exclusion zone).
    General,
    /// The reserved load envelope of a mapped image; its tagged regions are
    /// unmapped as a unit by `MM_UNMAP_IMAGE`.
    Image,
}

/// VA range explicitly owned by a client without (necessarily) being
/// mapped. Stored in a client's `reservations_slab`. Used by the gap
/// allocator to avoid sparse arena holes and by the unmap path to
/// enforce stack-guard protection.
#[derive(Clone, Copy)]
pub(crate) struct ReservedRange {
    pub(crate) base: u64,
    pub(crate) length: u64,
    pub(crate) kind: ReservationKind,
    /// mmsrv-local provenance (image envelope vs general reservation).
    pub(crate) purpose: ReservationPurpose,
    /// Caller badge that owns this reservation. Zero for unowned
    /// `Exclusion` zones (e.g. the null guard).
    pub(crate) owner_badge: u64,
    /// `kind == Guard` only: back-link to the stack mapping this guard
    /// protects. `None` for non-stack guard ranges.
    pub(crate) stack_region_id: Option<RegionId>,
}

impl ReservedRange {
    /// First VA past the end of this reservation (`base + length`,
    /// saturating).
    #[inline]
    pub(crate) fn end(&self) -> u64 {
        self.base.saturating_add(self.length)
    }
}
