// SPDX-License-Identifier: GPL-2.0-only

//! Memory Object (MO)
//!
//! Zircon-style virtual memory object with seL4 capability integration.
//! Pages are stored in a 4-level radix tree. COW cloning uses a
//! cap-refcounted parent chain.
//!
//! ## Ownership Model
//!
//! PMM owns all physical frames. MO borrows frames with `FrameOwner::MoData`
//! tag. VSpace is an observer — reverse maps on the MO track observers.

use crate::cap::object::{KernelObject, ObjectType};
use crate::mm::SpinLock;
use crate::mm::radix_tree::RadixTree;

// ---------------------------------------------------------------------------
// VmHierarchyState — per-COW-tree serialization lock object
// ---------------------------------------------------------------------------

/// Per-COW-tree serialization lock object (Zircon `VmHierarchyState`).
///
/// Every [`MemoryObject`] in one COW tree — a hidden parent and all its
/// transitive children — shares a single `VmHierarchyState`. Its `lock`
/// is the outermost per-tree lock: it serializes COW topology mutation,
/// page-identity resolution / break, reverse-map membership changes, and
/// write-protect across the whole tree, so the snapshot freeze window and
/// the downgrade-vs-split race are closed by construction rather than by
/// per-operation validation. Acquired OUTSIDE `VSpace.lock`; ordering is
/// `CAP_LOCK -> VmHierarchyState.lock -> VSpace.lock -> commit_lock |
/// rmap_lock -> FRAME_LOCK`.
///
/// Allocated from untyped by userspace (`OBJ_VM_HIERARCHY_STATE` retype)
/// and supplied to the tree-creating syscalls, mirroring the
/// [`MessagePipeCore`](crate::ipc::message_pipe::MessagePipeCore) shared-
/// core pattern. Lifetime is the `KernelObject` refcount: one user-cap
/// reference plus one internal reference per bound MO, reaped when the
/// tree's last MO drops its reference. One-shot — once bound to a tree it
/// is never rebound.
#[repr(C)]
pub struct VmHierarchyState {
    /// Refcount header (MUST be first field for the `*mut VmHierarchyState`
    /// <-> `*mut KernelObject` cast used by the refcount / reaper paths).
    pub header: KernelObject,
    /// The per-tree serialization lock. See type docs for ordering.
    pub lock: SpinLock,
    /// One-shot guard, set true under `lock` when this state is first bound
    /// to a COW tree. A second bind attempt is rejected so a state object
    /// can never be shared between two distinct trees.
    pub bound: core::sync::atomic::AtomicBool,
    /// Per-tree TLB range-change accumulator. Multi-page, tree-lock-held
    /// operations record their `(vspace, va)` PTE changes here instead of a
    /// per-page remote shootdown, then flush coalesced after the locks drop.
    /// Touched only under `lock`.
    pub rcl: crate::mm::vspace::RangeChangeList,
}

// SAFETY: `header.ref_count` is atomic and every other access to a tree's
// shared state is serialized by `lock`; the object is shared by raw
// pointer across CPUs exactly like `MessagePipeCore`.
unsafe impl Sync for VmHierarchyState {}

impl VmHierarchyState {
    /// Construct a fresh, unbound tree-state object. Refcount starts at 1
    /// for the userspace cap; each bound MO adds one internal reference.
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::VmHierarchyState, 0),
            lock: SpinLock::new(),
            bound: core::sync::atomic::AtomicBool::new(false),
            rcl: crate::mm::vspace::RangeChangeList::new(),
        }
    }

    /// Drain the accumulated TLB range-changes into a detached list, leaving the
    /// in-tree accumulator empty. Call this while STILL holding the tree lock;
    /// the returned list is flushed by the caller AFTER the tree + VSpace locks
    /// drop — the post-unlock seam the future sync-shootdown protocol swaps to
    /// `*_sync` (see the `project_sync_tlb_shootdown` note).
    ///
    /// # Safety
    /// Caller holds `(*state).lock`; `state` is non-null and live.
    pub unsafe fn drain_rcl(state: *mut Self) -> crate::mm::vspace::RangeChangeList {
        unsafe { core::mem::replace(&mut (*state).rcl, crate::mm::vspace::RangeChangeList::new()) }
    }
}

// ---------------------------------------------------------------------------
// Physical address tag bits (stored in radix tree leaf entries)
// ---------------------------------------------------------------------------

/// Bit 0: page is backed by an untyped source (not PMM).
pub const PHYS_TAG_UNTYPED: u64 = 1;

/// Bit 1: commit in-progress sentinel. A BUSY entry means a thread has
/// reserved this slot and is allocating a frame outside the commit_lock.
pub const PHYS_TAG_BUSY: u64 = 2;

/// Bit 2: file-backed pager reported a permanent fault for this page.
/// This is a zero-phys tombstone: it is not a committed frame and must
/// route future faults to the normal fault-delivery path without
/// consuming a pending pager-request slot.
pub const PHYS_TAG_PAGER_FAILED: u64 = 4;

/// Bit 3: page is a frame borrowed from an immortal device-untyped (the
/// initrd). Never owned by the PMM (`pmm_set_owner`) and never freed on
/// destroy/evict — the device-untyped owns it for the system lifetime.
pub const PHYS_TAG_BORROWED: u64 = 8;

/// Mask covering all tag bits (bits [11:0]). Physical addresses are always
/// page-aligned so the low 12 bits are available for tags.
pub const PHYS_TAG_MASK: u64 = 0xFFF;

/// Outcome of [`MemoryObject::evict_clean_page`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvictResult {
    /// Page was clean and resident: unmapped from every VSpace and freed.
    /// A later access re-faults and the pager re-supplies it.
    Evicted,
    /// Page (or one of its mappings) is dirty / written-back-pending. It is
    /// left resident and mapped; the caller must write it back first.
    Dirty,
    /// Page is not resident in this MO's own radix (already gone, BUSY, or a
    /// pager-fail tombstone). Nothing to do.
    NotResident,
}

/// Release one committed MO data page. PMM-backed pages return to the global
/// PMM; pages committed from an untyped keep `MoData` as their live owner and
/// carry the source untyped in `FrameMeta::source_ut`, so they return to that
/// exact untyped here.
///
/// # Safety
/// `mo` must be the live owner of `entry` at `page_idx`, the caller must have
/// removed the radix entry or otherwise made it unreachable, and every live PTE
/// mapping must already have been unmapped/released.
pub(crate) unsafe fn release_resident_data_page(
    mo: *mut MemoryObject,
    page_idx: usize,
    entry: u64,
) {
    if entry == 0 || entry & PHYS_TAG_BUSY != 0 || entry & PHYS_TAG_BORROWED != 0 {
        return;
    }
    let phys = entry & !PHYS_TAG_MASK;
    if phys == 0 {
        return;
    }

    if entry & PHYS_TAG_UNTYPED != 0 {
        let ut = crate::mm::pmm_source_untyped(phys);
        crate::kernel::bug::kassert!(
            !ut.is_null(),
            "untyped-backed MO page missing PMM source_untyped"
        );
        unsafe {
            (*ut).release_committed_mo_page(phys, mo, page_idx);
        }
    } else {
        crate::mm::pmm_free(
            phys,
            &crate::mm::frame::FrameOwner::MoData {
                mo,
                page_idx: page_idx as u32,
            },
        );
    }
}

// ---------------------------------------------------------------------------
// MoKind
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MoKind {
    Anon = 0,
    CowChild = 1,
    FileBacked = 2,
    Shm = 3,
    /// Immutable frames borrowed from the immortal initrd device-untyped:
    /// zero-copy, never owned/committed/evicted/freed by this MO, populated
    /// once via `populate_borrowed`. The exec-conferring path marks it R-X.
    BorrowedFrames = 4,
}

// ---------------------------------------------------------------------------
// PageSource
// ---------------------------------------------------------------------------

/// The effective source of a `MemoryObject` page, resolved through the COW
/// chain under the per-tree serialization lock. Produced by
/// [`MemoryObject::effective_page_source_locked`] — the single authority every
/// VM operation consults so none re-derives backing semantics.
///
/// The result is valid only for the *continuous* tree-lock hold under which it
/// was produced: `Resident` and `Zero` must be acted on within that hold; only
/// `Pager` (which parks on the pager) may cross a lock drop, and the caller
/// MUST re-classify after re-acquiring.
pub enum PageSource {
    /// The page resolves to a frame at `depth` in the COW chain (`depth == 0`
    /// is local). `untyped_backed` carries the `PHYS_TAG_UNTYPED` accounting bit.
    Resident {
        phys: u64,
        depth: usize,
        untyped_backed: bool,
        /// The frame is borrowed from an immortal device-untyped
        /// (`PHYS_TAG_BORROWED`): map read-only without stamping PMM
        /// ownership on it, and never free it.
        borrowed: bool,
    },
    /// Absent with no external source: its logical content is zero. The caller
    /// commits a zero page, or (for a pure read) returns zeros without committing.
    Zero,
    /// Absent, and a pager on this object or a COW ancestor must supply it.
    Pager {
        pager_mo: *mut MemoryObject,
        pager_idx: usize,
    },
    /// A pager fetch for this page failed (a `PHYS_TAG_PAGER_FAILED` tombstone
    /// anywhere on the chain), or the page's effective source is an external
    /// (file-backed) object whose pager is gone. Neither resident nor
    /// recoverable here: the fault path delivers a thread fault (SIGBUS), the
    /// MO syscalls return `IoError`.
    Failed,
}

// ---------------------------------------------------------------------------
// Reverse map
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReverseMapEntry {
    pub vspace: *mut crate::mm::vspace::VSpace, // 8
    pub va_start: u64,                          // 8
    pub page_count: u32,                        // 4
    pub mo_offset: u32,                         // 4
    pub perms: u8,                              // 1
    pub _pad: [u8; 7],                          // 7 (explicit, matches repr(C) alignment to 32)
}
// Total: 32 bytes. Overflow page: (4096 - 8) / 32 = 127 entries.
const _: () = assert!(core::mem::size_of::<ReverseMapEntry>() == 32);

/// Sentinel pointer value marking a slot reserved by an in-flight
/// `reserve_slot` that has not yet been committed with `add_reserved` or
/// released via `release_ticket`. Any non-zero, non-canonical-VSpace value
/// would do; `0x1` is unmappable and unambiguous in debug dumps.
pub const RMAP_VSPACE_PENDING: *mut crate::mm::vspace::VSpace = 0x1 as *mut _;

impl ReverseMapEntry {
    pub const EMPTY: Self = Self {
        vspace: core::ptr::null_mut(),
        va_start: 0,
        page_count: 0,
        mo_offset: 0,
        perms: 0,
        _pad: [0; 7],
    };

    /// Slot is free and may be claimed by the next `reserve_slot` / `add`.
    pub fn is_empty(&self) -> bool {
        self.vspace.is_null()
    }

    /// Slot has been reserved by an in-flight mapper and is neither free
    /// nor authoritative. Readers (total / destroy walk / for_each) must
    /// skip PENDING slots.
    pub fn is_pending(&self) -> bool {
        self.vspace == RMAP_VSPACE_PENDING
    }

    /// Slot is committed and carries authoritative mapping metadata.
    pub fn is_live(&self) -> bool {
        !self.vspace.is_null() && self.vspace != RMAP_VSPACE_PENDING
    }
}

const RMAP_INLINE: usize = 8;
const RMAP_OVERFLOW_ENTRIES: usize = (4096 - 8) / core::mem::size_of::<ReverseMapEntry>();

#[repr(C)]
pub struct ReverseMapPage {
    pub entries: [ReverseMapEntry; RMAP_OVERFLOW_ENTRIES],
    pub next: *mut ReverseMapPage,
}

#[repr(C)]
pub struct ReverseMaps {
    pub inline: [ReverseMapEntry; RMAP_INLINE],
    pub overflow: *mut ReverseMapPage,
}

/// Owned handle to a PENDING slot in a `ReverseMaps`, consumed by exactly
/// one of `add_reserved` (commit) or `release_ticket` (cancel).
///
/// The handle carries a raw pointer into the owning MO's rmap storage plus
/// a back-pointer to the parent `MemoryObject`; both remain valid while the
/// caller holds a mapping reference to the MO for the full reservation
/// lifetime.
///
/// Every ticket is consumed via `add_reserved` or `release_ticket` on every
/// non-panic path — reserve and its matching commit run inside one per-tree
/// serialization-lock region with no fallible `?` between them (the `unmap`
/// interior split precomputes its geometry before reserving) — so a ticket
/// never reaches `Drop` with a still-PENDING slot. `Drop` therefore only
/// `crate::kernel::bug::kassert!`s that invariant; a PENDING slot at drop is a discipline bug.
#[must_use = "RevMapTicket must be consumed via add_reserved or release_ticket"]
pub struct RevMapTicket {
    slot: *mut ReverseMapEntry,
    mo: *mut MemoryObject,
}

impl RevMapTicket {
    fn into_slot(self) -> *mut ReverseMapEntry {
        let s = self.slot;
        core::mem::forget(self);
        s
    }
}

impl Drop for RevMapTicket {
    fn drop(&mut self) {
        // With the discipline above, a ticket never reaches `Drop` with a
        // still-PENDING slot on a non-panic path (every reserve has a matching
        // `add_reserved` / `release_ticket` and no fallible `?` runs between
        // them). Assert that in debug; on panic unwind the kernel is already
        // aborting, so leaving the slot is moot. (Release builds compile the
        // check out — `Drop` becomes a no-op.)
        crate::kernel::bug::kassert!(
            self.mo.is_null() || self.slot.is_null() || !unsafe { (*self.slot).is_pending() },
            "RevMapTicket dropped with a PENDING slot — a reserve outlived its \
             tree-lock guard without a matching add_reserved / release_ticket"
        );
    }
}

/// Error returned by `reserve_slot` when overflow-page allocation fails.
pub struct RmapOutOfMemory;

impl ReverseMaps {
    pub const fn new() -> Self {
        Self {
            inline: [ReverseMapEntry::EMPTY; RMAP_INLINE],
            overflow: core::ptr::null_mut(),
        }
    }

    /// `true` iff every slot (inline + overflow) is EMPTY. Existence of an
    /// overflow page alone does NOT make the rmap non-empty — a MO that
    /// grew overflow for a transient burst and then had every entry removed
    /// is still "all empty" by this predicate. Used by the MO_CLONE
    /// pristine check and the MO-destroy convergence condition.
    pub fn is_all_empty(&self) -> bool {
        for s in self.inline.iter() {
            if !s.is_empty() {
                return false;
            }
        }
        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &*page };
            for slot in p.entries.iter() {
                if !slot.is_empty() {
                    return false;
                }
            }
            page = unsafe { (*page).next };
        }
        true
    }

    /// Number of live reverse-map entries across inline + overflow pages.
    /// PENDING slots are excluded — the rmap is not authoritative until the
    /// reserving mapper commits.
    pub fn total(&self) -> usize {
        let mut count = 0usize;
        for s in self.inline.iter() {
            if s.is_live() {
                count += 1;
            }
        }
        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &*page };
            for slot in p.entries.iter() {
                if slot.is_live() {
                    count += 1;
                }
            }
            page = unsafe { (*page).next };
        }
        count
    }

    /// Find the first empty slot and fill it with `entry`. Returns `false`
    /// if no empty slot is available (caller must run `ensure_slot` first).
    ///
    /// Skips PENDING slots — those are reserved by an in-flight mapper.
    pub fn add(&mut self, entry: ReverseMapEntry) -> bool {
        for s in self.inline.iter_mut() {
            if s.is_empty() {
                *s = entry;
                return true;
            }
        }
        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &mut *page };
            for slot in p.entries.iter_mut() {
                if slot.is_empty() {
                    *slot = entry;
                    return true;
                }
            }
            page = p.next;
        }
        false
    }

    /// Ensure at least one empty slot exists, allocating an overflow page
    /// from PMM if necessary. Returns `false` on PMM exhaustion.
    pub fn ensure_slot(&mut self, mo: *mut MemoryObject) -> bool {
        for s in self.inline.iter() {
            if s.is_empty() {
                return true;
            }
        }
        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &*page };
            for slot in p.entries.iter() {
                if slot.is_empty() {
                    return true;
                }
            }
            page = unsafe { (*page).next };
        }

        let owner = crate::mm::frame::FrameOwner::MoMeta {
            mo,
            subkind: crate::mm::frame::MoMetaKind::Rmap,
        };
        let Some(phys) = crate::mm::pmm_alloc(&owner) else {
            return false;
        };
        let page_ptr = crate::mm::phys_to_virt(phys) as *mut ReverseMapPage;
        unsafe {
            core::ptr::write_bytes(page_ptr as *mut u8, 0, crate::mm::PAGE_SIZE);
            self.add_overflow_page(page_ptr);
        }
        true
    }

    /// Reserve a slot for a future `add_reserved` commit, marking it PENDING
    /// so that no other mapper can fill it in the meantime. The returned
    /// ticket carries a raw pointer to the reserved slot that remains valid
    /// for the lifetime of the parent `MemoryObject` (slots are never moved
    /// once allocated; see the non-compacting `remove`/`replace` semantics).
    ///
    /// Allocates an overflow page from PMM if no inline or existing-overflow
    /// slot is free. Returns `Err(RmapOutOfMemory)` if that allocation fails
    /// — no side effects on that path.
    pub fn reserve_slot(&mut self, mo: *mut MemoryObject) -> Result<RevMapTicket, RmapOutOfMemory> {
        // Scan inline first.
        for s in self.inline.iter_mut() {
            if s.is_empty() {
                s.vspace = RMAP_VSPACE_PENDING;
                return Ok(RevMapTicket {
                    slot: s as *mut _,
                    mo,
                });
            }
        }
        // Scan existing overflow pages.
        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &mut *page };
            for slot in p.entries.iter_mut() {
                if slot.is_empty() {
                    slot.vspace = RMAP_VSPACE_PENDING;
                    return Ok(RevMapTicket {
                        slot: slot as *mut _,
                        mo,
                    });
                }
            }
            page = p.next;
        }

        // No slot available — allocate a fresh overflow page.
        let owner = crate::mm::frame::FrameOwner::MoMeta {
            mo,
            subkind: crate::mm::frame::MoMetaKind::Rmap,
        };
        let Some(phys) = crate::mm::pmm_alloc(&owner) else {
            return Err(RmapOutOfMemory);
        };
        let page_ptr = crate::mm::phys_to_virt(phys) as *mut ReverseMapPage;
        unsafe {
            core::ptr::write_bytes(page_ptr as *mut u8, 0, crate::mm::PAGE_SIZE);
            self.add_overflow_page(page_ptr);
            // First entry of the freshly-added page is guaranteed empty.
            let slot = &mut (*page_ptr).entries[0] as *mut ReverseMapEntry;
            (*slot).vspace = RMAP_VSPACE_PENDING;
            Ok(RevMapTicket { slot, mo })
        }
    }

    /// Commit a reservation by overwriting the PENDING slot with `entry`.
    /// Infallible given a ticket produced on this same `ReverseMaps`.
    ///
    /// # Safety
    /// The ticket must have been produced by [`reserve_slot`] on **this**
    /// `ReverseMaps` and not yet consumed. The slot pointer remains valid
    /// because `ReverseMaps` never relocates entries.
    pub unsafe fn add_reserved(&mut self, ticket: RevMapTicket, entry: ReverseMapEntry) {
        let slot = ticket.into_slot();
        unsafe {
            crate::kernel::bug::kassert!((*slot).is_pending(), "add_reserved on non-PENDING slot");
            *slot = entry;
        }
    }

    /// Cancel a reservation, returning the PENDING slot to the EMPTY state.
    ///
    /// # Safety
    /// Same contract as `add_reserved`.
    pub unsafe fn release_ticket(&mut self, ticket: RevMapTicket) {
        let slot = ticket.into_slot();
        unsafe {
            crate::kernel::bug::kassert!(
                (*slot).is_pending(),
                "release_ticket on non-PENDING slot"
            );
            *slot = ReverseMapEntry::EMPTY;
        }
    }

    /// # Safety
    /// `page_ptr` must point to a zeroed PMM page.
    pub unsafe fn add_overflow_page(&mut self, page_ptr: *mut ReverseMapPage) {
        unsafe {
            (*page_ptr).next = self.overflow;
        }
        self.overflow = page_ptr;
    }

    /// Clear the live entry matching `(vspace, va_start)`. Non-compacting —
    /// produces a hole in the storage. PENDING slots are not matched
    /// because `vspace == RMAP_VSPACE_PENDING` is never a real VSpace.
    pub fn remove(&mut self, vspace: *mut crate::mm::vspace::VSpace, va_start: u64) {
        for slot in self.inline.iter_mut() {
            if slot.is_live() && slot.vspace == vspace && slot.va_start == va_start {
                *slot = ReverseMapEntry::EMPTY;
                return;
            }
        }
        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &mut *page };
            for slot in p.entries.iter_mut() {
                if slot.is_live() && slot.vspace == vspace && slot.va_start == va_start {
                    *slot = ReverseMapEntry::EMPTY;
                    return;
                }
            }
            page = p.next;
        }
    }

    pub fn replace(
        &mut self,
        vspace: *mut crate::mm::vspace::VSpace,
        va_start: u64,
        entry: ReverseMapEntry,
    ) -> bool {
        for slot in self.inline.iter_mut() {
            if slot.is_live() && slot.vspace == vspace && slot.va_start == va_start {
                *slot = entry;
                return true;
            }
        }
        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &mut *page };
            for slot in p.entries.iter_mut() {
                if slot.is_live() && slot.vspace == vspace && slot.va_start == va_start {
                    *slot = entry;
                    return true;
                }
            }
            page = p.next;
        }
        false
    }

    /// Iterate live reverse-map entries. Skips EMPTY and PENDING slots.
    pub fn for_each<F: FnMut(&ReverseMapEntry)>(&self, f: &mut F) {
        for s in self.inline.iter() {
            if s.is_live() {
                f(s);
            }
        }
        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &*page };
            for entry in &p.entries {
                if entry.is_live() {
                    f(entry);
                }
            }
            page = p.next;
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COW_FLATTEN_THRESHOLD: usize = 8;

// ---------------------------------------------------------------------------
// MemoryObject
// ---------------------------------------------------------------------------

/// Capability-exposed virtual memory object.
///
/// `header` must be first for `*mut MemoryObject` → `*mut KernelObject` cast.
#[repr(C)]
pub struct MemoryObject {
    pub header: KernelObject,
    pub kind: MoKind,
    pub page_count: u32,
    /// Page-index offset of this MO's page 0 within `cow_parent`'s page
    /// space (Zircon `parent_offset_`). A locally-uncommitted page `i`
    /// resolves to `cow_parent` page `i + cow_parent_offset`. Zero for a
    /// root MO (`cow_parent` null) or a full 1:1 clone. Read/written under
    /// `commit_lock` alongside `cow_parent`; offsets accumulate down the
    /// chain in `resolve_page_depth` and fold on lazy-collapse.
    pub cow_parent_offset: u32,
    /// 4-level radix tree: page_idx → PhysAddr.
    pub pages: RadixTree,
    /// Which VSpaces map this MO's pages.
    pub reverse_maps: ReverseMaps,
    /// Direct pointer to the parent MO in the COW chain (null = no parent).
    /// Valid when `kind == CowChild`.
    ///
    /// Lifetime is governed by `KernelObject.ref_count`, not by any cap slot:
    /// `mo_clone` calls `increment_refcount(parent)` once, and `destroy` (or
    /// the lazy-collapse rewire) calls `release_object(parent, MemoryObject)`
    /// exactly once. The reaper finalizes parent only when its refcount
    /// reaches zero, so a child's `cow_parent` always points at a live MO.
    ///
    /// Reads / writes go through `commit_lock` (see `resolve_page_depth` and
    /// the lazy-collapse rewire in `destroy`); the walker never holds two
    /// `commit_lock`s at once and pins each next parent before releasing the
    /// current one (hand-over-hand), so reaper / lazy-collapse never observes
    /// the walker mid-step on a now-stale link.
    pub cow_parent: *mut MemoryObject,
    /// Intrusive child list: head of children whose cow_parent points to this MO.
    pub first_child: *mut MemoryObject,
    /// Next sibling in parent's child list.
    pub next_sibling: *mut MemoryObject,
    /// Physical address of the untyped carve holding this struct.
    pub untyped_phys: u64,
    /// Protects every access to `pages` (the radix tree of committed
    /// physical addresses): both readers (`resolve_page_depth`,
    /// `is_local_committed`) and writers (`commit_page` / `cow_resolve_page`
    /// / decommit / resize-shrink) take this lock. Parent-chain traversal
    /// in `resolve_page_depth` acquires each MO's `commit_lock` in turn
    /// and never holds two at once.
    /// Lock ordering: `VSpace.lock → commit_lock → ut.alloc_lock → FRAME_LOCK`.
    /// Disjoint from `rmap_lock` — holding both simultaneously is forbidden.
    pub commit_lock: SpinLock,
    /// Protects `reverse_maps` across every writer / reader path
    /// (register/unmap split/cleanup/destroy/total). Disjoint from
    /// `commit_lock` (radix tree) so rmap contention does not serialize
    /// page commits, and vice versa.
    /// Lock ordering: `VSpace.lock → MO.rmap_lock → FRAME_LOCK`.
    pub rmap_lock: SpinLock,
    /// Attached pager (file-backed MO supplier). Null when no pager
    /// is bound. Set by `MO_ATTACH_PAGER`; cleared by destroy /
    /// `PAGER_DETACH`. The pointer carries one refcount reservation on
    /// the pager object so the pager cannot be reaped while an MO
    /// still references it. Mutation requires `commit_lock`.
    pub pager: *mut crate::cap::pager::Pager,
    /// Pager-internal MO id allocated by `Pager::alloc_mo_id` at
    /// attach time. The fault path uses this in
    /// `KERNITE_EVENT_TYPE_PAGER_REQUEST.object_id` so userspace can
    /// resolve back to its file/offset translation table without
    /// exposing kernel pointers. `0` ⇔ `pager` is null.
    pub pager_mo_id: u64,
    /// Generation snapshot of the attached pager's `cancel_epoch` at
    /// attach time. Re-validated before fault delivery; a mismatch
    /// means the pager was revoked / re-bound and the fault must
    /// surface as SIGBUS rather than queue a stale request.
    pub pager_epoch: u64,
    /// Intrusive link in the owning pager's attached-MO list,
    /// threaded through `Pager.attached_mo_head`. Mutation requires
    /// `Pager.lock`.
    pub pager_next: *mut MemoryObject,
    /// Shared per-COW-tree serialization state ([`VmHierarchyState`]).
    /// Null while this MO is standalone (a tree of one); non-null and
    /// shared by every MO in the tree once bound by a tree-creating
    /// syscall (`MO_CLONE` / snapshot / fork). When non-null the tree lock
    /// is `(*hierarchy_state).lock`. Carries one refcount reservation on
    /// the state object, released in `destroy`. Published under
    /// `hierarchy_bind_lock` and read with `Acquire`; bound exactly once.
    pub hierarchy_state: core::sync::atomic::AtomicPtr<VmHierarchyState>,
    /// Per-MO lock covering this MO while `hierarchy_state` is still null
    /// (standalone) and serializing the standalone -> bound transition.
    /// Nests OUTSIDE `(*hierarchy_state).lock` (only ever during the bind)
    /// and outside `VSpace.lock`. A path that takes this lock must re-read
    /// `hierarchy_state` under it and restart against the tree lock if the
    /// MO was bound while it waited.
    pub hierarchy_bind_lock: SpinLock,
}

impl MemoryObject {
    /// Construct a fresh MO. Every caller must pick the right `MoKind`
    /// at creation so that per-kind accounting (anon vs file vs shm vs
    /// CoW child) is correct from first commit. Changing the kind after
    /// pages are committed would skew the PMM per-kind counters.
    pub fn new(_phys: u64, page_count: u32, kind: MoKind) -> Self {
        Self {
            header: KernelObject::new(ObjectType::MemoryObject, 0),
            kind,
            page_count,
            cow_parent_offset: 0,
            pages: RadixTree::empty(),
            reverse_maps: ReverseMaps::new(),
            cow_parent: core::ptr::null_mut(),
            first_child: core::ptr::null_mut(),
            next_sibling: core::ptr::null_mut(),
            untyped_phys: _phys,
            commit_lock: SpinLock::new(),
            rmap_lock: SpinLock::new(),
            pager: core::ptr::null_mut(),
            pager_mo_id: 0,
            pager_epoch: 0,
            pager_next: core::ptr::null_mut(),
            hierarchy_state: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            hierarchy_bind_lock: SpinLock::new(),
        }
    }

    /// Minimum untyped carve size. Just the struct itself — radix tree
    /// nodes are allocated separately from PMM.
    pub const fn required_bytes(_page_count: u32) -> usize {
        let struct_size = core::mem::size_of::<Self>();
        // Align to 64 bytes for cache line
        (struct_size + 63) & !63
    }

    // -----------------------------------------------------------------------
    // Reverse-map surface (`rmap_lock`-protected wrappers)
    // -----------------------------------------------------------------------
    //
    // Every writer / reader of `reverse_maps` must go through these helpers.
    // Direct `self.reverse_maps.X` access from outside this module is a bug:
    // it would bypass the MO-level synchronization domain that protects
    // `reverse_maps` against concurrent mutation from different VSpaces.
    //
    // Lock ordering (see `mm/mod.rs`):
    //   `VSpace.lock → MO.rmap_lock → FRAME_LOCK`.
    //
    // Callers may already hold `VSpace.lock`; `rmap_lock` is acquired inside
    // these wrappers. `FRAME_LOCK` is acquired transitively via `pmm_alloc`
    // inside `reserve_slot` / `ensure_slot`.

    #[inline]
    fn rmap_enter(&self) -> u64 {
        let irq = unsafe { crate::mm::vspace::save_irq_disable() };
        self.rmap_lock.lock();
        irq
    }

    #[inline]
    fn rmap_leave(&self, irq: u64) {
        self.rmap_lock.unlock();
        unsafe { crate::mm::vspace::restore_irq(irq) }
    }

    /// Reserve a PENDING slot for a future `rmap_add_reserved` commit.
    ///
    /// # Safety
    /// `self` must be a live MemoryObject. Caller must consume the returned
    /// ticket via `rmap_add_reserved` or `rmap_release_ticket`; leaking it
    /// leaks a PENDING slot (debug asserts on Drop).
    pub unsafe fn rmap_reserve_slot(&mut self) -> Result<RevMapTicket, RmapOutOfMemory> {
        let mo_ptr: *mut Self = self;
        let irq = self.rmap_enter();
        let result = self.reverse_maps.reserve_slot(mo_ptr);
        self.rmap_leave(irq);
        result
    }

    /// Commit a reservation by overwriting the PENDING slot with `entry`.
    ///
    /// # Safety
    /// `ticket` must have been produced by a prior `rmap_reserve_slot` on
    /// this same MO.
    pub unsafe fn rmap_add_reserved(&mut self, ticket: RevMapTicket, entry: ReverseMapEntry) {
        let irq = self.rmap_enter();
        unsafe { self.reverse_maps.add_reserved(ticket, entry) };
        self.rmap_leave(irq);
    }

    /// Cancel a reservation, returning the PENDING slot to EMPTY.
    ///
    /// # Safety
    /// Same contract as `rmap_add_reserved`.
    pub unsafe fn rmap_release_ticket(&mut self, ticket: RevMapTicket) {
        let irq = self.rmap_enter();
        unsafe { self.reverse_maps.release_ticket(ticket) };
        self.rmap_leave(irq);
    }

    /// Remove the live rmap entry matching `(vspace, va_start)`, if any.
    pub fn rmap_remove(&mut self, vspace: *mut crate::mm::vspace::VSpace, va_start: u64) {
        let irq = self.rmap_enter();
        self.reverse_maps.remove(vspace, va_start);
        self.rmap_leave(irq);
    }

    /// Replace the live rmap entry matching `(vspace, va_start)` with
    /// `entry`. Returns `false` if no matching entry was found.
    pub fn rmap_replace(
        &mut self,
        vspace: *mut crate::mm::vspace::VSpace,
        va_start: u64,
        entry: ReverseMapEntry,
    ) -> bool {
        let irq = self.rmap_enter();
        let r = self.reverse_maps.replace(vspace, va_start, entry);
        self.rmap_leave(irq);
        r
    }

    /// Total live rmap entries. PENDING slots are excluded.
    pub fn rmap_total(&self) -> usize {
        let irq = self.rmap_enter();
        let t = self.reverse_maps.total();
        self.rmap_leave(irq);
        t
    }

    /// `true` iff the rmap has zero live AND zero PENDING entries.
    pub fn rmap_is_all_empty(&self) -> bool {
        let irq = self.rmap_enter();
        let r = self.reverse_maps.is_all_empty();
        self.rmap_leave(irq);
        r
    }

    /// Harvest hardware PTE dirty bits for one MO page through the
    /// reverse-map table. When `clear_pte_dirty` is true the sampled
    /// PTE dirty bit is cleared and the owning VSpace is shot down,
    /// so later writes re-dirty the mapping and can be distinguished
    /// from the writeback currently in flight.
    ///
    /// This intentionally holds `rmap_lock` while touching PTEs.
    /// Unmap/split paths update rmap metadata before clearing the
    /// corresponding PTE, so the lock keeps the page-table page live
    /// for this sampling window without taking `VSpace.lock` in the
    /// forbidden `MO.rmap_lock -> VSpace.lock` order.
    pub fn rmap_harvest_page_dirty(
        &self,
        page_idx: usize,
        phys: u64,
        clear_pte_dirty: bool,
    ) -> bool {
        let irq = self.rmap_enter();
        let mut dirty = false;
        self.reverse_maps.for_each(&mut |entry| {
            let first = entry.mo_offset as usize;
            let count = entry.page_count as usize;
            let Some(last) = first.checked_add(count) else {
                return;
            };
            if page_idx < first || page_idx >= last || entry.vspace.is_null() {
                return;
            }
            let va = entry.va_start.saturating_add(
                ((page_idx - first) as u64).saturating_mul(crate::mm::PAGE_SIZE as u64),
            );
            // SAFETY: `entry` is LIVE under `rmap_lock`; unmap cannot
            // remove the rmap entry or free its page-table path until
            // this harvest releases the lock.
            let vspace = unsafe { &mut *entry.vspace };
            let Some(pte) = vspace.read_entry(va, 1) else {
                return;
            };
            if pte & crate::mm::vspace::ENTRY_PRESENT == 0 {
                return;
            }
            if pte & crate::mm::vspace::ENTRY_ADDR_MASK != phys {
                return;
            }
            if pte & crate::mm::vspace::ENTRY_DIRTY == 0 {
                return;
            }

            dirty = true;
            let _ = crate::mm::pmm_update_flags(phys, crate::mm::frame::FRAME_FLAG_DIRTY, 0);
            if clear_pte_dirty {
                let new_pte = pte & !crate::mm::vspace::ENTRY_DIRTY;
                if vspace.write_entry(va, 1, new_pte).is_ok() {
                    crate::arch::paging::invlpg(va);
                    vspace.tlb_shootdown(va);
                }
            }
        });
        self.rmap_leave(irq);
        dirty
    }

    /// Reclaim a CLEAN, resident, own-radix page for the pager. Every present
    /// mapping of the page is **demoted to a demand PTE** (so a later access
    /// re-faults → `EVENT_TYPE_PAGER_REQUEST` → the pager re-supplies — a zero
    /// PTE would instead fall through to a user fault), and the frame is freed.
    ///
    ///  * [`EvictResult::Evicted`] — page was clean: unmapped from every VSpace
    ///    and freed.
    ///  * [`EvictResult::Dirty`] — the frame's `FRAME_FLAG_DIRTY` is set (the
    ///    kernel's frame-level dirty authority, into which any live PTE dirty
    ///    bit is folded). The frame is left resident; its demand PTEs re-fault
    ///    onto it, so the caller writes it back and retries. On aarch64, where
    ///    the hardware dirty bit is not surfaced into the logical PTE, any page
    ///    that had a writable mapping is conservatively treated as dirty.
    ///  * [`EvictResult::NotResident`] — nothing resident to evict.
    ///
    /// The page is BUSY-tagged for the duration so a concurrent fault cannot
    /// re-map the frame out from under the free (`resolve_page_depth` skips
    /// BUSY). The unmap walk holds `rmap_lock` (never `VSpace.lock`) while
    /// touching PTEs — the same discipline as `rmap_harvest_page_dirty`, which
    /// relies on unmap/split updating rmap metadata before clearing a PTE so
    /// the lock keeps each page-table page live. A single pass over the full
    /// reverse map (no fixed-size batch) cannot loop forever or invert the
    /// `VSpace.lock -> rmap_lock` order. `commit_lock` is taken standalone for
    /// the BUSY tag and the final decision; the frame is freed outside locks.
    pub fn evict_clean_page(&mut self, page_idx: usize) -> EvictResult {
        // Borrowed frames are immutable and never PMM-owned: there is nothing
        // to evict, and freeing one would hand an initrd frame to `pmm_free`.
        if self.kind == MoKind::BorrowedFrames {
            return EvictResult::NotResident;
        }
        let self_ptr: *mut MemoryObject = self;

        // 0. Resolve a clean, resident, own-radix page and mark it BUSY so a
        //    concurrent fault/commit cannot re-map or re-commit it while the
        //    unmap+free is in flight (resolve_page_depth / commit skip BUSY).
        self.commit_lock.lock();
        let entry = self.pages.get(page_idx);
        if entry == 0 || entry & PHYS_TAG_BUSY != 0 || entry & PHYS_TAG_PAGER_FAILED != 0 {
            self.commit_lock.unlock();
            return EvictResult::NotResident;
        }
        let phys = entry & !PHYS_TAG_MASK;
        if phys == 0 {
            self.commit_lock.unlock();
            return EvictResult::NotResident;
        }
        let busy_entry = entry | PHYS_TAG_BUSY;
        let _ = self.pages.set_existing(page_idx, busy_entry);
        self.commit_lock.unlock();

        // 1. Demote every present mapping of `page_idx` to a demand PTE in one
        //    pass over the reverse map, folding any captured dirty bit into the
        //    frame flag. Held under rmap_lock without VSpace.lock, matching
        //    rmap_harvest_page_dirty. `saw_writable` feeds the aarch64
        //    conservative-dirty fallback below.
        let mut saw_writable = false;
        {
            let irq = self.rmap_enter();
            self.reverse_maps.for_each(&mut |e| {
                let first = e.mo_offset as usize;
                let Some(last) = first.checked_add(e.page_count as usize) else {
                    return;
                };
                if page_idx < first || page_idx >= last || e.vspace.is_null() {
                    return;
                }
                let va = e.va_start.saturating_add(
                    ((page_idx - first) as u64).saturating_mul(crate::mm::PAGE_SIZE as u64),
                );
                // SAFETY: `e` is LIVE under rmap_lock, which keeps the rmap
                // entry and its page-table path alive for this walk. VSpace
                // pointers are valid for system lifetime (memory-model-audit).
                let vspace = unsafe { &mut *e.vspace };
                if let Some(old) = vspace.demote_leaf_to_demand(va, phys) {
                    crate::arch::paging::invlpg(va);
                    vspace.tlb_shootdown(va);
                    crate::mm::pmm_release_mapping(phys);
                    if old & crate::mm::vspace::ENTRY_WRITABLE != 0 {
                        saw_writable = true;
                    }
                    if old & crate::mm::vspace::ENTRY_DIRTY != 0 {
                        // Fold an x86 PTE dirty bit (including a write that
                        // raced this unmap) into the frame's dirty flag, the
                        // cross-arch dirty authority consulted at step 2.
                        let _ = crate::mm::pmm_update_flags(
                            phys,
                            crate::mm::frame::FRAME_FLAG_DIRTY,
                            0,
                        );
                    }
                }
            });
            self.rmap_leave(irq);
        }

        // 2. Decide using FRAME_FLAG_DIRTY, the cross-arch dirty authority: a
        //    prior harvest may have set it while clearing the PTE dirty bit,
        //    and step 1 folds any live PTE dirty into it. On aarch64 the
        //    hardware dirty bit is not surfaced into the logical PTE, so a page
        //    that had any writable mapping is treated conservatively as dirty
        //    rather than freed (it may have been written without a trace).
        let frame_dirty = match crate::mm::pmm_update_flags(phys, 0, 0) {
            Some(flags) => flags & crate::mm::frame::FRAME_FLAG_DIRTY != 0,
            // Frame tracking unavailable: cannot prove clean — refuse to drop.
            None => true,
        } || (cfg!(target_arch = "aarch64") && saw_writable);

        // 3. Commit under commit_lock. Only act if the entry is still our
        //    BUSY-tagged frame (no concurrent remove/replace).
        self.commit_lock.lock();
        if self.pages.get(page_idx) != busy_entry {
            self.commit_lock.unlock();
            return EvictResult::NotResident;
        }
        if frame_dirty {
            // Restore the original (non-BUSY) entry. The frame stays resident
            // and its demand PTEs re-fault onto it; the caller writes it back.
            let _ = self.pages.set_existing(page_idx, entry);
            self.commit_lock.unlock();
            return EvictResult::Dirty;
        }
        self.pages.remove(page_idx);
        self.commit_lock.unlock();

        // 4. Free the now-unmapped, clean frame outside all MO locks.
        unsafe { release_resident_data_page(self_ptr, page_idx, entry) };
        EvictResult::Evicted
    }

    /// Initialize a pristine MO as a borrowed-frames view over `page_count`
    /// contiguous frames starting at `base_phys` (a run inside the immortal
    /// initrd device-untyped). Flips `kind` to `BorrowedFrames` and fills the
    /// radix with `phys | PHYS_TAG_BORROWED`; the frames are never owned,
    /// committed, evicted, or freed by this MO. One-shot: refuses a non-pristine
    /// MO. On radix-allocation failure the partial fill is rolled back, leaving
    /// the MO pristine. The caller validates `base_phys` / `page_count` against
    /// the device-untyped region (alignment, bounds, immortality).
    ///
    /// # Safety
    /// `self` is a live MO exclusively held by the caller; `base_phys` is
    /// page-aligned and the whole run lies within an immortal device-untyped.
    pub unsafe fn populate_borrowed<A: crate::mm::node_alloc::NodeAllocator>(
        &mut self,
        base_phys: u64,
        page_count: usize,
        alloc: &mut A,
    ) -> Result<(), ()> {
        self.commit_lock.lock();
        // One-shot on a pristine standalone MO: no pages, pager, or COW links.
        if self.kind != MoKind::Anon
            || !self.pages.is_empty()
            || !self.pager.is_null()
            || !self.cow_parent.is_null()
            || !self.first_child.is_null()
        {
            self.commit_lock.unlock();
            return Err(());
        }
        for i in 0..page_count {
            let entry = (base_phys + (i as u64) * crate::mm::PAGE_SIZE as u64) | PHYS_TAG_BORROWED;
            let ok = unsafe { self.pages.insert(i, entry, alloc) };
            if !ok {
                for j in 0..i {
                    self.pages.remove(j);
                }
                self.commit_lock.unlock();
                return Err(());
            }
        }
        self.kind = MoKind::BorrowedFrames;
        self.page_count = page_count as u32;
        self.commit_lock.unlock();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Page resolution
    // -----------------------------------------------------------------------

    /// Resident-only view of [`effective_page_source_locked`]: returns
    /// `(phys, depth, untyped_backed)` when page `index` is resident somewhere
    /// on the COW chain (depth 0 = local, depth > 0 = from an ancestor), and
    /// `None` for every non-resident source — logical zero, a pager that must
    /// be driven, or a pager-failure tombstone. The classifier is the single
    /// chain-walk authority; this is the thin accessor the resident-only
    /// callers share (page-flag update, writeback harvest, CoW-break source,
    /// has-page queries).
    ///
    /// # Safety
    /// The caller holds this MO's per-tree serialization lock.
    pub unsafe fn resolve_page_depth_locked(&self, index: usize) -> Option<(u64, usize, bool)> {
        match unsafe { self.effective_page_source_locked(index) } {
            PageSource::Resident {
                phys,
                depth,
                untyped_backed,
                borrowed: _,
            } => Some((phys, depth, untyped_backed)),
            _ => None,
        }
    }

    /// Classify the *effective source* of page `index` through the COW chain:
    /// the single authority for "what backs this page and how to populate it".
    ///
    /// Unlike [`resolve_page_depth_locked`], this distinguishes logical zero
    /// from pager failure and from a gone external source, so a pager-backed
    /// page can never silently degrade to zero-fill:
    ///
    /// - resident anywhere on the chain → [`PageSource::Resident`];
    /// - a `PHYS_TAG_PAGER_FAILED` tombstone anywhere → [`PageSource::Failed`];
    /// - absent with a pager on this object or an ancestor →
    ///   [`PageSource::Pager`] naming that pager-bearing object;
    /// - absent with no pager: the chain root's kind decides — `FileBacked`
    ///   (an external source whose pager is gone) → [`PageSource::Failed`],
    ///   `Anon` / `Shm` → [`PageSource::Zero`].
    ///
    /// Source *class* is decided by `MoKind` (anonymous versus external), not by
    /// pager presence: a `FileBacked` object whose pager was detached is
    /// `Failed`, not `Zero` — testing `pager != null` first would wrongly zero it.
    ///
    /// Non-blocking: reads the chain hand-over-hand under each `commit_lock`
    /// (never two at once); commits nothing, allocates nothing, never wakes or
    /// reschedules — safe under the tree lock and the RFC-0002 acyclicity
    /// invariant.
    ///
    /// # Safety
    /// The caller holds this MO's per-tree serialization lock for the whole
    /// classify-then-act sequence (see [`PageSource`]).
    pub unsafe fn effective_page_source_locked(&self, index: usize) -> PageSource {
        if index >= self.page_count as usize {
            return PageSource::Failed;
        }

        self.commit_lock.lock();
        let entry = self.pages.get(index);
        let next_parent = self.cow_parent;
        let next_off = self.cow_parent_offset as usize;
        let self_has_pager = !self.pager.is_null();
        let self_kind = self.kind;
        self.commit_lock.unlock();

        if entry != 0 && entry & PHYS_TAG_BUSY == 0 {
            if entry & PHYS_TAG_PAGER_FAILED != 0 {
                return PageSource::Failed;
            }
            let phys = entry & !PHYS_TAG_MASK;
            if phys != 0 {
                return PageSource::Resident {
                    phys,
                    depth: 0,
                    untyped_backed: entry & PHYS_TAG_UNTYPED != 0,
                    borrowed: entry & PHYS_TAG_BORROWED != 0,
                };
            }
        }

        // The first pager-bearing object on the chain (this object or the
        // nearest ancestor) supplies an absent page; record it as we descend.
        let mut pager_source: Option<(*mut MemoryObject, usize)> = if self_has_pager {
            Some((self as *const MemoryObject as *mut MemoryObject, index))
        } else {
            None
        };

        if next_parent.is_null() {
            return Self::absent_source_class(pager_source, self_kind);
        }

        let mut depth: usize = 1;
        let mut current = next_parent;
        let mut idx = index + next_off;
        loop {
            // SAFETY: the per-tree lock keeps every `cow_parent` link stable,
            // so `current` cannot be reaped or re-parented mid-walk.
            let cur_mo = unsafe { &*current };
            cur_mo.commit_lock.lock();
            let p = cur_mo.pages.get(idx);
            let nxt = cur_mo.cow_parent;
            let nxt_off = cur_mo.cow_parent_offset as usize;
            let cur_has_pager = !cur_mo.pager.is_null();
            let cur_kind = cur_mo.kind;
            cur_mo.commit_lock.unlock();

            if p != 0 && p & PHYS_TAG_BUSY == 0 {
                if p & PHYS_TAG_PAGER_FAILED != 0 {
                    return PageSource::Failed;
                }
                let phys = p & !PHYS_TAG_MASK;
                if phys != 0 {
                    return PageSource::Resident {
                        phys,
                        depth,
                        untyped_backed: p & PHYS_TAG_UNTYPED != 0,
                        borrowed: p & PHYS_TAG_BORROWED != 0,
                    };
                }
            }
            if pager_source.is_none() && cur_has_pager {
                pager_source = Some((current, idx));
            }
            if nxt.is_null() {
                return Self::absent_source_class(pager_source, cur_kind);
            }
            idx += nxt_off;
            current = nxt;
            depth += 1;
        }
    }

    /// Decide the source of an absent page once the whole chain has been walked
    /// without finding a resident frame or a failure tombstone: a recorded pager
    /// supplies it, else the chain root's kind decides zero versus fault.
    #[inline]
    fn absent_source_class(
        pager_source: Option<(*mut MemoryObject, usize)>,
        root_kind: MoKind,
    ) -> PageSource {
        if let Some((pager_mo, pager_idx)) = pager_source {
            PageSource::Pager {
                pager_mo,
                pager_idx,
            }
        } else {
            match root_kind {
                MoKind::FileBacked => PageSource::Failed,
                _ => PageSource::Zero,
            }
        }
    }

    /// Acquire this MO's per-tree serialization lock — its [`VmHierarchyState`]
    /// lock when bound, else its `hierarchy_bind_lock` — re-checking the choice
    /// under the lock against a concurrent first-snapshot bind. Returns the held
    /// lock; the caller releases it via the returned pointer. For MO-cap
    /// syscalls, which hold the MO cap so the MO and its state stay alive.
    ///
    /// # Safety
    /// `self` is a live MO that stays alive until the returned lock is released.
    pub unsafe fn lock_tree(&self) -> *const SpinLock {
        loop {
            let state = self
                .hierarchy_state
                .load(core::sync::atomic::Ordering::Acquire);
            if state.is_null() {
                self.hierarchy_bind_lock.lock();
                if self
                    .hierarchy_state
                    .load(core::sync::atomic::Ordering::Acquire)
                    .is_null()
                {
                    return &self.hierarchy_bind_lock as *const SpinLock;
                }
                self.hierarchy_bind_lock.unlock();
            } else {
                unsafe { (*state).lock.lock() };
                if self
                    .hierarchy_state
                    .load(core::sync::atomic::Ordering::Acquire)
                    == state
                {
                    return unsafe { &(*state).lock as *const SpinLock };
                }
                unsafe { (*state).lock.unlock() };
            }
        }
    }

    /// Check if a page is locally committed (exists in own radix tree).
    /// Returns false for BUSY entries (commit in-progress).
    ///
    /// Reads `self.pages` under `commit_lock` so the observation is
    /// coherent with concurrent commit/decommit writers.
    pub fn is_local_committed(&self, index: usize) -> bool {
        self.commit_lock.lock();
        let entry = self.pages.get(index);
        self.commit_lock.unlock();
        entry != 0 && (entry & PHYS_TAG_BUSY == 0) && (entry & PHYS_TAG_PAGER_FAILED == 0)
    }

    /// Check whether the local radix entry is a pager-fail tombstone.
    pub fn is_pager_failed(&self, index: usize) -> bool {
        self.commit_lock.lock();
        let entry = self.pages.get(index);
        self.commit_lock.unlock();
        entry & PHYS_TAG_PAGER_FAILED != 0
    }

    /// Commit a page: insert phys into the radix tree at `index`.
    ///
    /// # Safety
    /// `alloc` must be a valid NodeAllocator.
    pub unsafe fn commit_page<A: crate::mm::node_alloc::NodeAllocator>(
        &mut self,
        index: usize,
        phys: u64,
        alloc: &mut A,
    ) -> bool {
        if index >= self.page_count as usize {
            return false;
        }
        // SAFETY: alloc is valid, tree not concurrently modified.
        unsafe { self.pages.insert(index, phys, alloc) }
    }

    /// Record a COW-resolved page (same as commit, semantically distinct).
    ///
    /// # Safety
    /// Same as `commit_page`.
    pub unsafe fn cow_resolve_page<A: crate::mm::node_alloc::NodeAllocator>(
        &mut self,
        index: usize,
        new_phys: u64,
        alloc: &mut A,
    ) -> bool {
        // SAFETY: same preconditions as commit_page.
        unsafe { self.commit_page(index, new_phys, alloc) }
    }

    /// Ensure page `index` is committed in `self`'s OWN radix tree, breaking
    /// copy-on-write if it currently resolves from an ancestor, and return its
    /// private phys for an in-place write (e.g. `MO_WRITE`).
    ///
    /// * Page already local to `self` → returned directly (no break).
    /// * Page resolving only from an ancestor (CoW child) → a fresh private
    ///   frame is allocated, the ancestor's content copied in, and the frame
    ///   committed locally, so the write mutates `self`'s own copy instead of
    ///   the shared / frozen ancestor frame.
    /// * Page absent everywhere → `None` (the caller stops, as the pre-CoW
    ///   `resolve_page` path did). `None` is also returned on OOM.
    ///
    /// After a break, present CoW mappings of the page are reconverged onto the
    /// private frame so reads through them observe the written content.
    ///
    /// # Safety
    /// `self` must be a live MemoryObject; the caller holds this MO's per-tree
    /// serialization lock (so the chain walk needs no hand-over-hand pins) and
    /// no `commit_lock`.
    pub unsafe fn cow_break_for_write(&mut self, index: usize) -> Option<u64> {
        if index >= self.page_count as usize {
            return None;
        }
        let self_ptr = self as *mut MemoryObject;
        // Fast path: already local to `self`.
        {
            self.commit_lock.lock();
            let entry = self.pages.get(index);
            self.commit_lock.unlock();
            if entry != 0 && entry & PHYS_TAG_BUSY == 0 && entry & PHYS_TAG_PAGER_FAILED == 0 {
                return Some(entry & !PHYS_TAG_MASK);
            }
        }
        // Not local — resolve the content source from the CoW chain. Absent
        // everywhere → nothing to write (preserves the pre-CoW behaviour).
        let src_phys = unsafe { self.resolve_page_depth_locked(index) }.map(|(p, _, _)| p)?;
        if src_phys == 0 {
            return None;
        }
        // Break: private frame + copy of the ancestor's content.
        let owner = crate::mm::frame::FrameOwner::MoData {
            mo: self_ptr,
            page_idx: index as u32,
        };
        let new_phys = crate::mm::pmm_alloc(&owner)?;
        unsafe {
            let src = crate::mm::phys_to_virt(src_phys) as *const u8;
            let dst = crate::mm::phys_to_virt(new_phys) as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, crate::mm::PAGE_SIZE);
        }
        let mut alloc = crate::mm::node_alloc::PmmNodeAllocator {
            owner: crate::mm::frame::FrameOwner::MoMeta {
                mo: self_ptr,
                subkind: crate::mm::frame::MoMetaKind::Radix,
            },
            use_reserve: false,
        };
        self.commit_lock.lock();
        // A concurrent writer may have broken the page first.
        let existing = self.pages.get(index);
        if existing != 0 && existing & PHYS_TAG_BUSY == 0 {
            self.commit_lock.unlock();
            crate::mm::pmm_free(new_phys, &owner);
            return Some(existing & !PHYS_TAG_MASK);
        }
        let committed = unsafe { self.commit_page(index, new_phys, &mut alloc) };
        self.commit_lock.unlock();
        if !committed {
            crate::mm::pmm_free(new_phys, &owner);
            return None;
        }
        // Keep present CoW mappings coherent with the new private frame.
        unsafe { self.converge_sibling_mappings_to_owned(index, core::ptr::null_mut(), 0) };
        Some(new_phys)
    }

    /// Link `self` as a COW child of `parent`: a locally-uncommitted page
    /// `i` of `self` resolves to page `i + offset_pages` of `parent`.
    ///
    /// Takes one keep-alive `increment_refcount` on `parent` (paired with
    /// the `release_object` in `destroy` / lazy-collapse) so the hidden
    /// parent cannot be reaped while this child still maps its frames, and
    /// splices `self` into `parent.first_child` under `parent.commit_lock`.
    ///
    /// # Safety
    /// `self` must be unlinked (`cow_parent` null) and distinct from
    /// `parent`; `parent` must point at a live MO; the caller must not hold
    /// `parent`'s `commit_lock` (only `VSpace.lock`s, per the documented
    /// `VSpace.lock → commit_lock` order).
    pub unsafe fn attach_cow_parent(&mut self, parent: *mut MemoryObject, offset_pages: u32) {
        crate::kernel::bug::kassert!(
            self.cow_parent.is_null(),
            "attach_cow_parent: child already linked"
        );
        let self_ptr = self as *mut MemoryObject;
        crate::kernel::bug::kassert!(self_ptr != parent, "attach_cow_parent: self-parent cycle");
        // The caller's bind protocol must have published the same per-tree state
        // on both before attaching — attach takes only the parent keep-alive
        // ref, never a state ref.
        crate::kernel::bug::kassert!(
            self.hierarchy_state
                .load(core::sync::atomic::Ordering::Acquire)
                == unsafe {
                    (*parent)
                        .hierarchy_state
                        .load(core::sync::atomic::Ordering::Acquire)
                },
            "attach_cow_parent: child and parent must share one tree state"
        );
        self.kind = MoKind::CowChild;
        self.cow_parent = parent;
        self.cow_parent_offset = offset_pages;
        // SAFETY: `parent` is a live MO distinct from `self`; we hold no
        // other `commit_lock`, so taking `parent.commit_lock` respects the
        // `VSpace.lock → commit_lock` order. The keep-alive ref pairs with
        // the release in `destroy` / lazy-collapse.
        unsafe {
            crate::cap::increment_refcount(parent as *mut KernelObject);
            (*parent).commit_lock.lock();
            self.next_sibling = (*parent).first_child;
            (*parent).first_child = self_ptr;
            (*parent).commit_lock.unlock();
        }
    }

    /// Snapshot `self` by interposing the fresh hidden parent `h`: `self`'s
    /// committed *local* pages move into `h` (frozen) and `self` becomes a CoW
    /// child of `h`. Afterwards `self`'s pages resolve through `h` (frozen at
    /// snapshot time); an in-place write through a still-present writable
    /// mapping must be turned into a CoW fault by the caller
    /// (`downgrade_mappings_to_cow`) so it breaks against `h` rather than
    /// mutating the now-frozen frame.
    ///
    /// `h` inherits `self`'s [`MoKind`] so the per-MoKind frame accounting is
    /// preserved once the caller re-tags the moved frames' PMM owner to `h`.
    /// The radix tree is handed over by a single root-pointer move (O(1), no
    /// page copy), which is what makes the snapshot lazy for large objects.
    ///
    /// `self` need **not** be a CoW root. If `self` is already a child of a
    /// grandparent `g` at offset `pg`, `h` is spliced *between* them: `h` takes
    /// `self`'s slot in `g`'s child list with `cow_parent = g` /
    /// `cow_parent_offset = pg`, and `self` re-parents onto `h` at offset 0.
    /// Only `self`'s local pages (those it broke since becoming `g`'s child)
    /// move into `h`; inherited pages keep resolving `self -> h -> g` with the
    /// offset preserved, so the resolved content is identical to before the
    /// splice. This is the Zircon chained-hidden-parent insert, and is what
    /// lets the same object be snapshotted more than once.
    ///
    /// Lock order: the chained splice mutates `g`'s child list, so
    /// `g.commit_lock` is taken **before** `self.commit_lock` (parent before
    /// child — the same order `destroy`'s lazy-collapse uses; the fault walker
    /// never nests two `commit_lock`s, so this cannot invert). `g` is pinned
    /// across the unlock/relock dance and that pin becomes `h`'s `cow_parent`
    /// ref; `self`'s stale ref on `g` is released after the locks drop. A
    /// concurrent collapse that re-parents `self` is caught by re-validating
    /// `self.cow_parent == g` under `self.commit_lock` and retrying.
    ///
    /// Caller obligations, in order, after this returns (unchanged from the
    /// root case):
    ///   1. re-tag every moved frame's PMM owner from `self` to `h`
    ///      (walk `h.pages`, `pmm_set_owner(.., MoData { mo: h, .. })`);
    ///   2. link the snapshot child to `h` via [`attach_cow_parent`];
    ///   3. `self.downgrade_mappings_to_cow()`;
    ///   4. after dropping the per-tree lock, `release_object` the returned
    ///      grandparent ref (chained case; `None` for a root snapshot).
    ///
    /// Returns the now-stale grandparent reference the caller must drop once
    /// it has released the tree lock — `release_object` takes `REAPER_LOCK`,
    /// which must never nest under the tree lock; `None` in the root case.
    ///
    /// # Safety
    /// `h` must be a pristine, exclusively-owned MO (empty pages/rmap, no
    /// children, `cow_parent` null, live refcount) distinct from `self`.
    /// The caller holds the per-tree serialization lock (the bound tree's
    /// `VmHierarchyState.lock`, or the fresh state's lock with `self` / `h`'s
    /// `hierarchy_bind_lock` held during a first-snapshot bind) and no
    /// `commit_lock`.
    pub unsafe fn snapshot_page_move_into(
        &mut self,
        h: *mut MemoryObject,
    ) -> Option<*mut MemoryObject> {
        let self_ptr = self as *mut MemoryObject;
        crate::kernel::bug::kassert!(self_ptr != h, "snapshot_page_move_into: self-parent cycle");
        // The caller holds this tree's `VmHierarchyState` lock, which
        // serialises this insert against `destroy`'s lazy-collapse (the only
        // other CoW-topology mutator, now also under the tree lock) — so the
        // insert-vs-collapse race is impossible by construction, no validation
        // or retry. `commit_lock` still guards the radix swap / child-list
        // mutation against concurrent page-resolve readers.
        self.commit_lock.lock();
        let g = self.cow_parent;
        if g.is_null() {
            // Root snapshot: `h` becomes a fresh root and `self` its child.
            unsafe {
                let hm = &mut *h;
                // O(1) radix hand-over: the whole page tree moves to the frozen
                // parent; `self` is left empty and resolves up through `h`.
                hm.pages =
                    core::mem::replace(&mut self.pages, crate::mm::radix_tree::RadixTree::empty());
                hm.page_count = self.page_count;
                hm.kind = self.kind;
                hm.cow_parent = core::ptr::null_mut();
                hm.cow_parent_offset = 0;
                // `h` is exclusive (not yet referenced by any walker) — wire its
                // child list inline without taking `h.commit_lock`.
                hm.first_child = self_ptr;
                self.next_sibling = core::ptr::null_mut();
                // Keep-alive ref paired with the release in `destroy`.
                crate::cap::increment_refcount(h as *mut KernelObject);
                // Publish: `self` resolves through `h` from here.
                self.kind = MoKind::CowChild;
                self.cow_parent_offset = 0;
                self.cow_parent = h;
            }
            self.commit_lock.unlock();
            // Root snapshot: no grandparent ref to drop.
            return None;
        }

        // Chained snapshot: splice `h` between `self` and its parent `g`. The
        // caller's tree lock keeps `g` stable — no concurrent collapse can
        // re-parent `self` — so this is straight-line. Re-acquire in
        // parent->child order for the child-list mutation.
        self.commit_lock.unlock();
        unsafe {
            (*g).commit_lock.lock();
        }
        self.commit_lock.lock();
        crate::kernel::bug::kassert!(
            self.cow_parent == g,
            "snapshot insert: parent changed under tree lock"
        );
        let pg = self.cow_parent_offset;
        unsafe {
            let hm = &mut *h;
            // Move only `self`'s local pages into `h`; inherited pages keep
            // resolving through `h -> g` at the preserved offset.
            hm.pages =
                core::mem::replace(&mut self.pages, crate::mm::radix_tree::RadixTree::empty());
            hm.page_count = self.page_count;
            hm.kind = self.kind;
            hm.cow_parent = g;
            hm.cow_parent_offset = pg;
            // `h`'s keep-alive ref on `g` (paired with `self`'s stale ref drop
            // after the locks release) and `self`'s ref on `h`.
            crate::cap::increment_refcount(g as *mut KernelObject);
            crate::cap::increment_refcount(h as *mut KernelObject);
            // Replace `self` with `h` in `g`'s child list. Under the topology
            // lock `self` is stably `g`'s child, so the unlink always succeeds.
            let unlinked = Self::remove_from_child_list_locked(&mut *g, self_ptr);
            crate::kernel::bug::kassert!(
                unlinked,
                "snapshot insert: self missing from g's child list"
            );
            let _ = unlinked;
            hm.first_child = self_ptr;
            self.next_sibling = core::ptr::null_mut();
            hm.next_sibling = (*g).first_child;
            (*g).first_child = h;
            // Publish: `self` resolves through `h` from here.
            self.kind = MoKind::CowChild;
            self.cow_parent_offset = 0;
            self.cow_parent = h;
        }
        self.commit_lock.unlock();
        unsafe {
            (*g).commit_lock.unlock();
        }
        // Return `self`'s now-stale ref on `g` for the caller to drop AFTER it
        // releases the per-tree lock: `release_object` takes `REAPER_LOCK`,
        // which must never nest under the tree lock. `g`'s refcount nets zero
        // across the insert — `h` acquired a ref above; the caller drops this
        // stale one.
        Some(g)
    }

    /// Downgrade every currently-present, writable mapping of `self` to a
    /// read-only CoW PTE so a later write faults and breaks against the
    /// snapshot's hidden parent instead of mutating the now-frozen frame in
    /// place. Not-yet-faulted mappings need nothing: once `cow_parent` is set
    /// they demand-fault as CoW automatically.
    ///
    /// Respects the `VSpace.lock → rmap_lock` order by snapshotting rmap
    /// entries under `rmap_lock`, then downgrading PTEs per entry under that
    /// entry's `VSpace.lock` (never both locks at once). EVERY current mapping
    /// is downgraded — leaving any writable PTE behind would let that mapper
    /// keep writing into the frozen frames. The rmap is walked by stable
    /// structural position (inline slots, then each overflow page in
    /// `BATCH`-sized slot chunks): overflow pages are never freed mid-life and
    /// slots are never moved (non-compacting `remove`/`replace`), so the walk
    /// is robust to concurrent mutation — a mapping unmapped between snapshots
    /// just leaves a dead slot (skipped: its mapping is gone, nothing to
    /// downgrade) and a fault only adds a CoW slot (also nothing to downgrade).
    /// Every pre-existing writable mapping keeps its slot until unmapped, so it
    /// is reached and downgraded. There is no fixed mapping-count limit.
    ///
    /// # Safety
    /// Called during `MO_SNAPSHOT` after `snapshot_page_move_into`. Concurrent
    /// faults and unmaps on `self` are tolerated (see above); VSpace pointers
    /// are valid for the system lifetime, and a stale `(vspace, va)` whose
    /// mapping was just removed reads back absent and is skipped.
    pub unsafe fn downgrade_mappings_to_cow(&mut self) {
        // The owning tree state — its `rcl` accumulates the per-page CoW
        // write-protect shootdowns for a coalesced post-unlock flush by the
        // snapshot caller (keeping each local invlpg immediate). Non-null:
        // downgrade only ever runs on a bound P under its tree lock.
        let state = self
            .hierarchy_state
            .load(core::sync::atomic::Ordering::Acquire);
        const BATCH: usize = 64;
        let mut batch: [(*mut crate::mm::vspace::VSpace, u64, u32); BATCH] =
            [(core::ptr::null_mut(), 0, 0); BATCH];

        // Inline slots: RMAP_INLINE <= BATCH, so one snapshot covers them.
        let n = {
            let irq = self.rmap_enter();
            let mut n = 0usize;
            for s in self.reverse_maps.inline.iter() {
                if s.is_live() {
                    batch[n] = (s.vspace, s.va_start, s.page_count);
                    n += 1;
                }
            }
            self.rmap_leave(irq);
            n
        };
        Self::downgrade_cow_batch(state, &batch[..n]);

        // Overflow pages are scanned by stable slot position in `BATCH`-sized
        // chunks. `page` follows the chain captured at the start; pages
        // prepended by concurrent faults hold only CoW entries and need no
        // downgrade, so missing them is harmless.
        let mut page = {
            let irq = self.rmap_enter();
            let p = self.reverse_maps.overflow;
            self.rmap_leave(irq);
            p
        };
        while !page.is_null() {
            let mut off = 0usize;
            loop {
                let (n, end) = {
                    let irq = self.rmap_enter();
                    let mut n = 0usize;
                    let mut idx = off;
                    while idx < RMAP_OVERFLOW_ENTRIES && n < BATCH {
                        let s = unsafe { &(*page).entries[idx] };
                        if s.is_live() {
                            batch[n] = (s.vspace, s.va_start, s.page_count);
                            n += 1;
                        }
                        idx += 1;
                    }
                    self.rmap_leave(irq);
                    (n, idx)
                };
                Self::downgrade_cow_batch(state, &batch[..n]);
                off = end;
                if off >= RMAP_OVERFLOW_ENTRIES {
                    break;
                }
            }
            let next = {
                let irq = self.rmap_enter();
                let nx = unsafe { (*page).next };
                self.rmap_leave(irq);
                nx
            };
            page = next;
        }
    }

    /// Downgrade a captured batch of `(vspace, va_start, page_count)` mappings:
    /// each present, writable, non-CoW PTE becomes a read-only CoW PTE under
    /// the owning `VSpace.lock`. No `rmap_lock` is held here (it was released by
    /// the caller before this runs, honouring `VSpace.lock → rmap_lock`). A
    /// stale entry whose mapping was concurrently unmapped reads back absent and
    /// is skipped.
    fn downgrade_cow_batch(
        state: *mut VmHierarchyState,
        batch: &[(*mut crate::mm::vspace::VSpace, u64, u32)],
    ) {
        use crate::mm::vspace::{ENTRY_COW, ENTRY_PRESENT, ENTRY_WRITABLE};
        for &(vspace_ptr, va_start, pc) in batch {
            if vspace_ptr.is_null() {
                continue;
            }
            let vspace = unsafe { &mut *vspace_ptr };
            let vspace_irq = unsafe { crate::mm::vspace::save_irq_disable() };
            vspace.lock.lock();
            for k in 0..pc as u64 {
                let page_vaddr = va_start + k * crate::mm::PAGE_SIZE as u64;
                if let Some(pte) = vspace.read_entry(page_vaddr, 1) {
                    if pte & ENTRY_PRESENT != 0 && pte & ENTRY_WRITABLE != 0 && pte & ENTRY_COW == 0
                    {
                        let new_pte = (pte & !ENTRY_WRITABLE) | ENTRY_COW;
                        let _ = vspace.write_entry(page_vaddr, 1, new_pte);
                        crate::arch::paging::invlpg(page_vaddr);
                        // Defer the remote shootdown into the tree's rcl for a
                        // coalesced post-unlock flush by the snapshot caller;
                        // the local invlpg above stays immediate. Fall back to
                        // an immediate shootdown only if somehow unbound.
                        if state.is_null() {
                            vspace.tlb_shootdown(page_vaddr);
                        } else {
                            unsafe { (*state).rcl.record(vspace_ptr, page_vaddr) };
                        }
                    }
                }
            }
            vspace.lock.unlock();
            unsafe { crate::mm::vspace::restore_irq(vspace_irq) };
        }
    }

    /// True if this MO is freshly retyped and unbound — eligible to be bound
    /// into a COW tree as a hidden parent / snapshot child / fork shadow. It
    /// must be live (`ref_count != 0`), outside any COW tree (no parent /
    /// children / siblings, `hierarchy_state` still null), have no committed
    /// pages, no reverse mappings, and no attached pager. The snapshot / clone
    /// / fork bind protocols require this before publishing tree state onto it.
    pub fn is_pristine(&self) -> bool {
        self.header
            .ref_count
            .load(core::sync::atomic::Ordering::Acquire)
            != 0
            && self.cow_parent.is_null()
            && self.first_child.is_null()
            && self.next_sibling.is_null()
            && self.pages.is_empty()
            && self.rmap_is_all_empty()
            && self
                .hierarchy_state
                .load(core::sync::atomic::Ordering::Acquire)
                .is_null()
            && self.pager.is_null()
    }

    /// True if any live mapping of this MO overlaps the page range
    /// `[start, end)` in MO page-index space. `MO_RESIZE` shrink uses this
    /// to reject (busy) a truncation that would free a still-mapped tail
    /// page: freeing a frame that still has a live PTE leaves a non-zero
    /// `map_count` and panics the PMM (`free_internal`). The caller unmaps
    /// the tail first, then retries. Walks the rmap under `rmap_lock` only
    /// (no VSpace locks taken), honouring `VSpace.lock → rmap_lock`.
    ///
    /// # Safety
    /// VSpace pointers in the rmap are valid for the system lifetime; this
    /// only reads `(mo_offset, page_count)`, never dereferences them.
    pub unsafe fn range_has_live_mapping(&self, start: usize, end: usize) -> bool {
        if start >= end {
            return false;
        }
        fn overlaps(s: &ReverseMapEntry, start: usize, end: usize) -> bool {
            if !s.is_live() {
                return false;
            }
            let lo = s.mo_offset as usize;
            let hi = lo + s.page_count as usize;
            lo < end && hi > start
        }
        let irq = self.rmap_enter();
        let mut hit = false;
        for s in self.reverse_maps.inline.iter() {
            if overlaps(s, start, end) {
                hit = true;
                break;
            }
        }
        if !hit {
            let mut page = self.reverse_maps.overflow;
            'outer: while !page.is_null() {
                let entries = unsafe { &(*page).entries };
                for s in entries.iter() {
                    if overlaps(s, start, end) {
                        hit = true;
                        break 'outer;
                    }
                }
                page = unsafe { (*page).next };
            }
        }
        self.rmap_leave(irq);
        hit
    }

    /// After a CoW break installed a private frame for `mo_page_idx` into
    /// `self`, converge every OTHER present CoW mapping of that page onto the
    /// owned frame so the MO's shared mappings stay coherent (a write through
    /// one shared mapping must be visible through the others). The faulting
    /// mapping `(exclude_vspace, exclude_va)` is already up to date and is
    /// skipped.
    ///
    /// Cross-VSpace safe: snapshots the rmap under `rmap_lock`, then updates
    /// PTEs per entry under that entry's `VSpace.lock` (never both at once,
    /// honouring `VSpace.lock → rmap_lock`). Each converged PTE takes its
    /// writability from the mapping's recorded `perms`, so a read-only shared
    /// mapping stays read-only.
    ///
    /// # Safety
    /// Called from the CoW fault path after the faulting `VSpace.lock` has
    /// been released. VSpace pointers are valid for the system lifetime.
    pub unsafe fn converge_sibling_mappings_to_owned(
        &mut self,
        mo_page_idx: usize,
        exclude_vspace: *mut crate::mm::vspace::VSpace,
        exclude_va: u64,
    ) {
        use crate::mm::vspace::{ENTRY_ADDR_MASK, ENTRY_COW, ENTRY_PRESENT, ENTRY_WRITABLE};
        // Owning tree state for the post-unlock shootdown flush (the cow-break
        // caller drains + flushes it). Non-null: converge runs on a bound CoW MO.
        let cv_state = self
            .hierarchy_state
            .load(core::sync::atomic::Ordering::Acquire);
        // The private frame installed by the break we are following up.
        let owned = {
            self.commit_lock.lock();
            let e = self.pages.get(mo_page_idx);
            self.commit_lock.unlock();
            e
        };
        let owned_phys = owned & !PHYS_TAG_MASK;
        if owned & PHYS_TAG_BUSY != 0 || owned_phys == 0 {
            return;
        }
        const MAX: usize = 64;
        let mut batch: [(*mut crate::mm::vspace::VSpace, u64, u8); MAX] =
            [(core::ptr::null_mut(), 0, 0); MAX];
        let mut n = 0usize;
        {
            let irq = self.rmap_enter();
            'collect: {
                for s in self.reverse_maps.inline.iter() {
                    if s.is_live() {
                        let off = s.mo_offset as usize;
                        if mo_page_idx >= off && mo_page_idx < off + s.page_count as usize {
                            let va = s.va_start
                                + ((mo_page_idx - off) as u64) * crate::mm::PAGE_SIZE as u64;
                            if !(s.vspace == exclude_vspace && va == exclude_va) {
                                if n >= MAX {
                                    break 'collect;
                                }
                                batch[n] = (s.vspace, va, s.perms);
                                n += 1;
                            }
                        }
                    }
                }
                let mut page = self.reverse_maps.overflow;
                while !page.is_null() {
                    let p = unsafe { &*page };
                    for slot in p.entries.iter() {
                        if slot.is_live() {
                            let off = slot.mo_offset as usize;
                            if mo_page_idx >= off && mo_page_idx < off + slot.page_count as usize {
                                let va = slot.va_start
                                    + ((mo_page_idx - off) as u64) * crate::mm::PAGE_SIZE as u64;
                                if !(slot.vspace == exclude_vspace && va == exclude_va) {
                                    if n >= MAX {
                                        break 'collect;
                                    }
                                    batch[n] = (slot.vspace, va, slot.perms);
                                    n += 1;
                                }
                            }
                        }
                    }
                    page = unsafe { (*page).next };
                }
            }
            self.rmap_leave(irq);
        }
        for i in 0..n {
            let (vspace_ptr, va, perms) = batch[i];
            if vspace_ptr.is_null() {
                continue;
            }
            let vspace = unsafe { &mut *vspace_ptr };
            let irq = unsafe { crate::mm::vspace::save_irq_disable() };
            vspace.lock.lock();
            if let Some(pte) = vspace.read_entry(va, 1) {
                // Only converge a still-CoW mapping of this page; a sibling
                // that already broke or remapped is left untouched.
                if pte & ENTRY_PRESENT != 0 && pte & ENTRY_COW != 0 {
                    let old_phys = pte & ENTRY_ADDR_MASK;
                    if old_phys != owned_phys {
                        let writable = if perms & 0x01 != 0 { ENTRY_WRITABLE } else { 0 };
                        let new_pte = (pte & !ENTRY_ADDR_MASK & !ENTRY_COW & !ENTRY_WRITABLE)
                            | owned_phys
                            | writable;
                        let _ = vspace.write_entry(va, 1, new_pte);
                        crate::arch::paging::invlpg(va);
                        // Defer the remote shootdown into the tree's rcl for a
                        // post-unlock flush by the cow-break caller; the local
                        // invlpg above stays immediate. Fall back to an immediate
                        // shootdown only if somehow unbound.
                        if cv_state.is_null() {
                            vspace.tlb_shootdown(va);
                        } else {
                            unsafe { (*cv_state).rcl.record(vspace_ptr, va) };
                        }
                        crate::mm::pmm_retain_mapping(owned_phys);
                        crate::mm::pmm_release_mapping(old_phys);
                    }
                }
            }
            vspace.lock.unlock();
            unsafe { crate::mm::vspace::restore_irq(irq) };
        }
    }

    /// Walk `self`'s CoW-parent chain for the nearest pager-backed ancestor
    /// that should service a fault for `page_idx`, translating the index
    /// through the accumulated `cow_parent_offset`s. Returns
    /// `(ancestor, index_within_ancestor)`, or `None` for an anonymous / shm
    /// child with no pager ancestor (the caller zero-fills). No hand-over-hand
    /// pins: safe only under the per-tree `VmHierarchyState` lock (lazy-collapse
    /// excluded → the chain is stable), which the caller keeps held until done
    /// with the returned ancestor.
    ///
    /// # Safety
    /// The caller holds this MO's per-tree serialization lock.
    pub unsafe fn find_pager_source_locked(
        &self,
        page_idx: usize,
    ) -> Option<(*mut MemoryObject, usize)> {
        self.commit_lock.lock();
        let mut current = self.cow_parent;
        let mut idx = page_idx + self.cow_parent_offset as usize;
        self.commit_lock.unlock();
        while !current.is_null() {
            // SAFETY: the per-tree lock keeps the chain stable; no pin needed.
            let cur = unsafe { &*current };
            cur.commit_lock.lock();
            let has_pager = !cur.pager.is_null();
            let nxt = cur.cow_parent;
            let nxt_off = cur.cow_parent_offset as usize;
            cur.commit_lock.unlock();
            if has_pager {
                return Some((current, idx));
            }
            idx += nxt_off;
            current = nxt;
        }
        None
    }

    // -----------------------------------------------------------------------
    // Destroy
    // -----------------------------------------------------------------------

    /// Release all resources: unmap from all VSpaces, free pages, detach
    /// from COW parent.
    ///
    /// # Safety
    /// Must be called when refcount reaches 0, guaranteeing exclusive
    /// access — no other CPU holds a reference to this MO.
    ///
    /// ## Lock ordering (reverse-map teardown)
    ///
    /// The rmap walk uses **snapshot + re-validate** rather than in-place
    /// iteration:
    ///
    /// 1. Under `MO.rmap_lock`, copy up to 32 LIVE `(vspace, va_start,
    ///    page_count)` tuples into a stack batch. PENDING slots are
    ///    skipped — they belong to an in-flight mapper that will either
    ///    commit or `release_ticket`.
    /// 2. For each snapshot tuple, acquire `VSpace.lock` then
    ///    `MO.rmap_lock` (documented order) and **re-validate** that the
    ///    tuple's LIVE entry still exists. If a concurrent
    ///    `VSpace::cleanup` or partial unmap already removed it, skip.
    /// 3. If still LIVE, clear the slot under `MO.rmap_lock` (taking a
    ///    local copy of `page_count`), release `MO.rmap_lock`, then run
    ///    the PTE teardown under `VSpace.lock` only. Release `VSpace.lock`.
    /// 4. Repeat until `rmap_total() == 0`.
    ///
    /// ## Load-bearing assumption
    ///
    /// Snapshotting a raw `*mut VSpace` is sound because *kernel objects
    /// are never freed or reused during system lifetime* — see
    /// `docs/spec/memory-model-audit.md` §"Load-Bearing Assumptions".
    /// If that invariant is ever relaxed, this routine needs an explicit
    /// identity/generation check, not just pointer equality.
    ///
    /// The radix tree traversal (`pages.for_each`) is safe because
    /// refcount==0 guarantees no concurrent commit/resolve operations.
    pub unsafe fn destroy(&mut self) {
        // 0. Detach from pager (if any). Pending requests keyed on this
        // MO must already have been failed by the pager-revoke /
        // MM_DEREGISTER cascade — destroy reaching here implies
        // refcount == 0, which the pager teardown path guarantees only
        // after all pending requests for this MO have been resolved.
        if !self.pager.is_null() {
            let pager_ptr = self.pager;
            self.pager = core::ptr::null_mut();
            self.pager_mo_id = 0;
            self.pager_epoch = 0;
            let self_ptr: *mut MemoryObject = self;
            unsafe {
                let pager = &mut *pager_ptr;
                pager.detach_mo(self_ptr);
                crate::cap::release_object(
                    pager_ptr as *mut crate::cap::object::KernelObject,
                    crate::cap::ObjectType::Pager,
                );
            }
        }

        // Acquire this MO's per-tree serialization lock for the whole teardown:
        // the rmap teardown, page free, and the parent re-parent / lazy-collapse
        // all run under it (plan: destroy serialises against the tree). lock_tree
        // picks the bound tree lock or, for a standalone MO, its bind lock; at
        // refcount==0 the bound/standalone choice is stable. Every release_object
        // is deferred until after this lock drops (acyclicity: release_object
        // takes REAPER_LOCK, which must never nest under the tree lock).
        let destroy_tree_lock = unsafe { self.lock_tree() };
        // The bound tree state (null for a standalone MO held under its bind
        // lock): the teardown records its per-page shootdowns into this state's
        // rcl for a coalesced post-unlock flush below.
        let destroy_state = self
            .hierarchy_state
            .load(core::sync::atomic::Ordering::Acquire);
        let mut destroy_deferred: [(*mut KernelObject, ObjectType); 3] =
            [(core::ptr::null_mut(), ObjectType::MemoryObject); 3];
        let mut destroy_deferred_n = 0usize;

        // 1. Reverse-map walk — snapshot + re-validate + per-entry teardown.
        const RMAP_SNAP_BATCH: usize = 32;
        type RmapTuple = (
            *mut crate::mm::vspace::VSpace,
            u64, /* va_start */
            u32, /* page_count */
        );

        loop {
            // ---- Step 1: snapshot ----
            let mut batch: [RmapTuple; RMAP_SNAP_BATCH] =
                [(core::ptr::null_mut(), 0, 0); RMAP_SNAP_BATCH];
            let mut batch_len = 0usize;
            {
                let irq = self.rmap_enter();
                for s in self.reverse_maps.inline.iter() {
                    if batch_len >= RMAP_SNAP_BATCH {
                        break;
                    }
                    if s.is_live() {
                        batch[batch_len] = (s.vspace, s.va_start, s.page_count);
                        batch_len += 1;
                    }
                }
                if batch_len < RMAP_SNAP_BATCH {
                    let mut page = self.reverse_maps.overflow;
                    while !page.is_null() && batch_len < RMAP_SNAP_BATCH {
                        let p = unsafe { &*page };
                        for slot in p.entries.iter() {
                            if batch_len >= RMAP_SNAP_BATCH {
                                break;
                            }
                            if slot.is_live() {
                                batch[batch_len] = (slot.vspace, slot.va_start, slot.page_count);
                                batch_len += 1;
                            }
                        }
                        page = unsafe { (*page).next };
                    }
                }
                self.rmap_leave(irq);
            }

            if batch_len == 0 {
                // Snapshot collected no LIVE tuples. At destroy time this
                // must also mean no PENDING slots: PENDING is only created
                // by an in-flight `rmap_reserve_slot`, and the RevMapTicket
                // it hands out can only be held by a syscall with a valid
                // MO cap reference. For the MO to reach destroy, refcount
                // must be 0 — i.e. no such cap reference exists. Violation
                // of this invariant would leak PENDING into the upcoming
                // overflow-page free step (UAF). Debug-assert to surface it.
                crate::kernel::bug::kassert!(
                    self.reverse_maps.is_all_empty(),
                    "PENDING rmap slots survived into MemoryObject::destroy"
                );
                break;
            }

            // ---- Step 2/3: per-tuple re-validate + teardown ----
            for i in 0..batch_len {
                let (vspace_ptr, va_start, snap_page_count) = batch[i];
                if vspace_ptr.is_null() {
                    continue;
                }
                // SAFETY: VSpace pointers remain valid for system lifetime
                // (see §"Load-Bearing Assumptions" in the audit doc). The
                // snapshot cannot be a dangling pointer — it can at worst
                // refer to a VSpace whose own `cleanup` already removed
                // our rmap entry, which we detect via re-validation below.
                let vspace = unsafe { &mut *vspace_ptr };

                let vspace_irq = unsafe { crate::mm::vspace::save_irq_disable() };
                vspace.lock.lock();

                // Re-validate: take rmap_lock, confirm the LIVE entry is
                // still present, and — if so — clear it while holding the
                // lock. We copy page_count locally under the lock to avoid
                // reading freed/reused slot memory during PTE teardown.
                let live_page_count: u32;
                {
                    let rmap_irq = unsafe { crate::mm::vspace::save_irq_disable() };
                    self.rmap_lock.lock();

                    let mut matched: Option<u32> = None;
                    for s in self.reverse_maps.inline.iter_mut() {
                        if s.is_live() && s.vspace == vspace_ptr && s.va_start == va_start {
                            matched = Some(s.page_count);
                            *s = ReverseMapEntry::EMPTY;
                            break;
                        }
                    }
                    if matched.is_none() {
                        let mut page = self.reverse_maps.overflow;
                        'outer: while !page.is_null() {
                            let p = unsafe { &mut *page };
                            for slot in p.entries.iter_mut() {
                                if slot.is_live()
                                    && slot.vspace == vspace_ptr
                                    && slot.va_start == va_start
                                {
                                    matched = Some(slot.page_count);
                                    *slot = ReverseMapEntry::EMPTY;
                                    break 'outer;
                                }
                            }
                            page = p.next;
                        }
                    }

                    self.rmap_lock.unlock();
                    unsafe { crate::mm::vspace::restore_irq(rmap_irq) };

                    match matched {
                        Some(pc) => live_page_count = pc,
                        None => {
                            // Concurrently removed (e.g., VSpace::cleanup
                            // ran while we were collecting the snapshot).
                            vspace.lock.unlock();
                            unsafe { crate::mm::vspace::restore_irq(vspace_irq) };
                            continue;
                        }
                    }
                }

                // Defensive: the re-validated page_count should match the
                // snapshot; mismatch means the entry was replaced in-place
                // which we currently don't do. Fall back to snapshot value.
                let pc = if live_page_count > 0 {
                    live_page_count
                } else {
                    snap_page_count
                };

                for k in 0..pc as u64 {
                    let page_vaddr = va_start + k * crate::mm::PAGE_SIZE as u64;
                    if let Some(pte) = vspace.read_entry(page_vaddr, 1) {
                        if pte & crate::mm::vspace::ENTRY_PRESENT != 0 {
                            let phys = pte & crate::mm::vspace::ENTRY_ADDR_MASK;
                            let _ = vspace.write_entry(page_vaddr, 1, 0);
                            crate::arch::paging::invlpg(page_vaddr);
                            // Defer the remote shootdown into the tree's rcl for
                            // a coalesced post-unlock flush; local invlpg stays
                            // immediate. A standalone MO (no tree) shoots down
                            // immediately.
                            if destroy_state.is_null() {
                                vspace.tlb_shootdown(page_vaddr);
                            } else {
                                unsafe { (*destroy_state).rcl.record(vspace_ptr, page_vaddr) };
                            }
                            crate::mm::pmm_release_mapping(phys);
                        }
                    }
                }

                vspace.lock.unlock();
                unsafe { crate::mm::vspace::restore_irq(vspace_irq) };
            }

            // If this iteration cleared fewer entries than the batch could
            // hold AND rmap is now empty, we're done. Otherwise loop again
            // to pick up remaining entries (another batch's worth).
            if batch_len < RMAP_SNAP_BATCH && self.rmap_is_all_empty() {
                break;
            }
        }

        // 2. Free all pages in the radix tree. PMM-backed pages return to the
        // PMM; untyped-backed pages return to the exact source recorded in
        // PMM metadata. BUSY entries are skipped (should not exist at destroy
        // time since refcount==0 means no concurrent commit).
        let self_ptr = self as *mut MemoryObject;

        unsafe {
            self.pages.for_each(|idx, entry| {
                if entry == 0 || entry & PHYS_TAG_BUSY != 0 {
                    return;
                }
                release_resident_data_page(self_ptr, idx, entry);
            });
        }

        // 3. Free radix tree nodes
        let mut tree_alloc = crate::mm::node_alloc::PmmNodeAllocator {
            owner: crate::mm::frame::FrameOwner::MoMeta {
                mo: self_ptr,
                subkind: crate::mm::frame::MoMetaKind::Radix,
            },
            use_reserve: false,
        };
        unsafe {
            self.pages.destroy(&mut tree_alloc);
        }

        // 4. Free overflow rmap pages
        let mut rmap_page = self.reverse_maps.overflow;
        while !rmap_page.is_null() {
            let next = unsafe { (*rmap_page).next };
            let phys = crate::mm::virt_to_phys(rmap_page as u64);
            crate::mm::pmm_free(
                phys,
                &crate::mm::frame::FrameOwner::MoMeta {
                    mo: self_ptr,
                    subkind: crate::mm::frame::MoMetaKind::Rmap,
                },
            );
            rmap_page = next;
        }
        self.reverse_maps.overflow = core::ptr::null_mut();

        // 5. Drop our reference on the COW parent (if any) + lazy collapse.
        //    Parent destruction is reaper-driven: we only call release_object
        //    so the reaper can finalize parent in proper order. We never
        //    invoke parent.destroy() directly — that would re-enter destroy
        //    inside CAP_LOCK and bypass the deferred-cleanup boundary.
        if !self.cow_parent.is_null() {
            // SAFETY: cow_parent points at a live MO whose refcount we hold
            // (acquired in mo_clone). Steal the field so any reentrant path
            // through `self` cannot double-drop.
            let parent_ptr = self.cow_parent;
            self.cow_parent = core::ptr::null_mut();

            unsafe {
                let parent_mo = &mut *parent_ptr;

                // The re-parent / lazy-collapse runs under the outer
                // `destroy_tree_lock` already held above — it serialises this
                // against snapshot insert and faults on the same tree.

                // 5a. Remove self from parent's child list under
                //     parent.commit_lock — this is the lock that protects
                //     `first_child` / `next_sibling` topology mutations.
                parent_mo.commit_lock.lock();
                Self::remove_from_child_list_locked(parent_mo, self as *mut MemoryObject);

                // 5b. Decide whether parent should lazy-collapse based on
                //     the *post-removal* child list. After our removal,
                //     does parent have exactly one remaining child and
                //     zero local pages? If so, splice that child up to
                //     grandparent so the chain stays flat.
                let remaining = parent_mo.first_child;
                let single_remaining = !remaining.is_null() && (*remaining).next_sibling.is_null();

                let mut has_local_pages = false;
                if single_remaining {
                    parent_mo.pages.for_each(|_, phys| {
                        if phys != 0 {
                            has_local_pages = true;
                        }
                    });
                }

                let collapse = parent_mo.kind == MoKind::CowChild
                    && !parent_mo.cow_parent.is_null()
                    && single_remaining
                    && !has_local_pages;

                if collapse {
                    let new_grandparent = parent_mo.cow_parent;

                    // Pin grandparent before remaining grabs a ref on it,
                    // so the chain can't be reaped from under the splice.
                    crate::cap::increment_refcount(new_grandparent as *mut KernelObject);

                    // Mutate `remaining.cow_parent` under `remaining.commit_lock`
                    // so a concurrent `resolve_page_depth` walker on
                    // `remaining` observes either the pre- or post-collapse
                    // pointer atomically — never an in-flight half-rewire.
                    (*remaining).commit_lock.lock();
                    (*remaining).cow_parent = new_grandparent;
                    // Fold the collapsed intermediate's offset into the
                    // child: `remaining` page i was at offset R into
                    // `parent`, and `parent` at offset P into grandparent,
                    // so after the splice `remaining` page i sits at R + P
                    // into grandparent.
                    (*remaining).cow_parent_offset = (*remaining)
                        .cow_parent_offset
                        .wrapping_add(parent_mo.cow_parent_offset);
                    (*remaining).commit_lock.unlock();

                    // Detach `remaining` from parent's child list.
                    parent_mo.first_child = core::ptr::null_mut();
                    (*remaining).next_sibling = core::ptr::null_mut();

                    parent_mo.commit_lock.unlock();

                    // Splice `remaining` into grandparent's child list under
                    // grandparent's commit_lock.
                    let gp_mo = &mut *new_grandparent;
                    gp_mo.commit_lock.lock();
                    (*remaining).next_sibling = gp_mo.first_child;
                    gp_mo.first_child = remaining;
                    gp_mo.commit_lock.unlock();

                    // Defer both parent ref drops until after the outer tree
                    // lock releases (release_object takes REAPER_LOCK). The
                    // first cancels `remaining`'s old ref on parent; the second
                    // is self's ref, taking parent.refcount → 0 so the reaper
                    // finalizes parent (parent.destroy then releases grandparent,
                    // balancing the increment_refcount above — net grandparent
                    // delta 0). Two distinct drops; do NOT dedupe.
                    destroy_deferred[destroy_deferred_n] =
                        (parent_ptr as *mut KernelObject, ObjectType::MemoryObject);
                    destroy_deferred_n += 1;
                    destroy_deferred[destroy_deferred_n] =
                        (parent_ptr as *mut KernelObject, ObjectType::MemoryObject);
                    destroy_deferred_n += 1;
                } else {
                    parent_mo.commit_lock.unlock();

                    // No collapse — defer our single parent ref drop until
                    // after the outer tree lock releases (REAPER_LOCK). If this
                    // was parent's last live owner, the reaper finalizes it.
                    destroy_deferred[destroy_deferred_n] =
                        (parent_ptr as *mut KernelObject, ObjectType::MemoryObject);
                    destroy_deferred_n += 1;
                }
            }
        }

        // Clear this MO's reference to the shared per-tree state while STILL
        // holding the tree lock (plan: clear under the lock, then drop, then
        // release once). The release_object itself is deferred below. When the
        // tree's last MO drops this ref the state object is reaped.
        let hstate = self
            .hierarchy_state
            .swap(core::ptr::null_mut(), core::sync::atomic::Ordering::AcqRel);
        if !hstate.is_null() {
            destroy_deferred[destroy_deferred_n] =
                (hstate as *mut KernelObject, ObjectType::VmHierarchyState);
            destroy_deferred_n += 1;
        }

        // Drain the accumulated teardown shootdowns while STILL holding the
        // tree lock; they are flushed post-unlock below (the sync-shootdown
        // seam). `destroy_state == hstate` — the swap cleared self's pointer but
        // the state object (and its rcl) is alive until released below.
        let mut rcl_local = if destroy_state.is_null() {
            crate::mm::vspace::RangeChangeList::new()
        } else {
            unsafe { VmHierarchyState::drain_rcl(destroy_state) }
        };

        // Drop the per-tree lock, THEN flush the coalesced shootdowns and run
        // every deferred release_object: each takes REAPER_LOCK, which must
        // never nest under the tree lock.
        unsafe { (*destroy_tree_lock).unlock() };
        unsafe { rcl_local.flush() };
        for i in 0..destroy_deferred_n {
            unsafe {
                crate::cap::release_object(destroy_deferred[i].0, destroy_deferred[i].1);
            }
        }
    }

    /// Remove `child` from `parent`'s intrusive child linked list. Returns
    /// `true` if `child` was found and unlinked, `false` otherwise. Under the
    /// per-tree `VmHierarchyState` lock the snapshot insert and the
    /// lazy-collapse re-parent atomically, so both callers always pass a
    /// `child` that is genuinely in `parent`'s list — a `false` there is a bug
    /// (asserted at the call site).
    ///
    /// # Safety
    /// Caller must hold `parent.commit_lock` — that is the lock domain that
    /// protects `first_child` / `next_sibling` topology mutations.
    unsafe fn remove_from_child_list_locked(
        parent: &mut MemoryObject,
        child: *mut MemoryObject,
    ) -> bool {
        if parent.first_child == child {
            unsafe {
                parent.first_child = (*child).next_sibling;
                (*child).next_sibling = core::ptr::null_mut();
            }
            return true;
        }
        let mut prev = parent.first_child;
        while !prev.is_null() {
            unsafe {
                if (*prev).next_sibling == child {
                    (*prev).next_sibling = (*child).next_sibling;
                    (*child).next_sibling = core::ptr::null_mut();
                    return true;
                }
                prev = (*prev).next_sibling;
            }
        }
        false
    }
}
