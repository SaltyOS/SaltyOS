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
use crate::mm::radix_tree::RadixTree;
use crate::mm::SpinLock;

// ---------------------------------------------------------------------------
// Physical address tag bits (stored in radix tree leaf entries)
// ---------------------------------------------------------------------------

/// Bit 0: page is backed by an untyped source (not PMM).
pub const PHYS_TAG_UNTYPED: u64 = 1;

/// Bit 1: commit in-progress sentinel. A BUSY entry means a thread has
/// reserved this slot and is allocating a frame outside the commit_lock.
pub const PHYS_TAG_BUSY: u64 = 2;

/// Mask covering all tag bits (bits [11:0]). Physical addresses are always
/// page-aligned so the low 12 bits are available for tags.
pub const PHYS_TAG_MASK: u64 = 0xFFF;

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

impl ReverseMapEntry {
    pub const EMPTY: Self = Self {
        vspace: core::ptr::null_mut(),
        va_start: 0,
        page_count: 0,
        mo_offset: 0,
        perms: 0,
        _pad: [0; 7],
    };

    pub fn is_empty(&self) -> bool {
        self.vspace.is_null()
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
    pub inline_count: u8,
    pub overflow: *mut ReverseMapPage,
}

impl ReverseMaps {
    pub const fn new() -> Self {
        Self {
            inline: [ReverseMapEntry::EMPTY; RMAP_INLINE],
            inline_count: 0,
            overflow: core::ptr::null_mut(),
        }
    }

    pub fn add(&mut self, entry: ReverseMapEntry) -> bool {
        let count = self.inline_count as usize;
        if count < RMAP_INLINE {
            self.inline[count] = entry;
            self.inline_count += 1;
            return true;
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

    pub fn ensure_slot(&mut self, mo: *mut MemoryObject) -> bool {
        let count = self.inline_count as usize;
        if count < RMAP_INLINE {
            return true;
        }

        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &mut *page };
            for slot in p.entries.iter() {
                if slot.is_empty() {
                    return true;
                }
            }
            page = p.next;
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

    /// # Safety
    /// `page_ptr` must point to a zeroed PMM page.
    pub unsafe fn add_overflow_page(&mut self, page_ptr: *mut ReverseMapPage) {
        unsafe {
            (*page_ptr).next = self.overflow;
        }
        self.overflow = page_ptr;
    }

    pub fn remove(&mut self, vspace: *mut crate::mm::vspace::VSpace, va_start: u64) {
        for i in 0..self.inline_count as usize {
            if self.inline[i].vspace == vspace && self.inline[i].va_start == va_start {
                for j in i..RMAP_INLINE - 1 {
                    self.inline[j] = self.inline[j + 1];
                }
                self.inline[RMAP_INLINE - 1] = ReverseMapEntry::EMPTY;
                self.inline_count -= 1;
                return;
            }
        }
        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &mut *page };
            for slot in p.entries.iter_mut() {
                if slot.vspace == vspace && slot.va_start == va_start {
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
        for i in 0..self.inline_count as usize {
            if self.inline[i].vspace == vspace && self.inline[i].va_start == va_start {
                self.inline[i] = entry;
                return true;
            }
        }
        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &mut *page };
            for slot in p.entries.iter_mut() {
                if slot.vspace == vspace && slot.va_start == va_start {
                    *slot = entry;
                    return true;
                }
            }
            page = p.next;
        }
        false
    }

    pub fn for_each<F: FnMut(&ReverseMapEntry)>(&self, f: &mut F) {
        for i in 0..self.inline_count as usize {
            if !self.inline[i].is_empty() {
                f(&self.inline[i]);
            }
        }
        let mut page = self.overflow;
        while !page.is_null() {
            let p = unsafe { &*page };
            for entry in &p.entries {
                if !entry.is_empty() {
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
    /// 4-level radix tree: page_idx → PhysAddr.
    pub pages: RadixTree,
    /// Which VSpaces map this MO's pages.
    pub reverse_maps: ReverseMaps,
    /// COW parent capability slot (0 = none). Valid when kind == CowChild.
    /// The cap system manages refcount — clone increments parent ref_count,
    /// destroy decrements it.
    pub cow_parent: u64,
    /// Intrusive child list: head of children whose cow_parent points to this MO.
    pub first_child: *mut MemoryObject,
    /// Next sibling in parent's child list.
    pub next_sibling: *mut MemoryObject,
    /// Physical address of the untyped carve holding this struct.
    pub untyped_phys: u64,
    /// Protects MO state during commit/decommit: radix leaf reads/writes,
    /// page state transitions. Lock ordering: commit_lock → ut.alloc_lock.
    pub commit_lock: SpinLock,
}

impl MemoryObject {
    pub fn new(_phys: u64, page_count: u32) -> Self {
        Self {
            header: KernelObject::new(ObjectType::MemoryObject, 0),
            kind: MoKind::Anon,
            page_count,
            pages: RadixTree::empty(),
            reverse_maps: ReverseMaps::new(),
            cow_parent: 0,
            first_child: core::ptr::null_mut(),
            next_sibling: core::ptr::null_mut(),
            untyped_phys: _phys,
            commit_lock: SpinLock::new(),
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
    // Page resolution
    // -----------------------------------------------------------------------

    /// Resolve physical address for `index`.
    /// Returns `(phys, chain_depth)`. Depth 0 means the page is in this MO's
    /// own radix tree. Depth > 0 means it was resolved from an ancestor.
    /// Caller should flatten (cow_resolve_page) when depth > COW_FLATTEN_THRESHOLD.
    pub fn resolve_page_depth(&self, index: usize) -> Option<(u64, usize)> {
        if index >= self.page_count as usize {
            return None;
        }

        let entry = self.pages.get(index);
        if entry != 0 {
            // BUSY sentinel means commit in-progress — treat as uncommitted.
            if entry & PHYS_TAG_BUSY != 0 {
                return None;
            }
            let phys = entry & !PHYS_TAG_MASK;
            if phys != 0 {
                return Some((phys, 0));
            }
        }

        if self.cow_parent == 0 {
            return None;
        }

        let mut depth = 0usize;
        let mut parent_slot = self.cow_parent;
        while parent_slot != 0 {
            let parent_mo = Self::deref_cow_parent(parent_slot);
            if parent_mo.is_null() {
                break;
            }
            depth += 1;
            let parent = unsafe { &*parent_mo };
            let p = parent.pages.get(index);
            if p != 0 {
                if p & PHYS_TAG_BUSY != 0 {
                    // Parent page is mid-commit — skip.
                    parent_slot = parent.cow_parent;
                    continue;
                }
                let phys = p & !PHYS_TAG_MASK;
                if phys != 0 {
                    return Some((phys, depth));
                }
            }
            parent_slot = parent.cow_parent;
        }

        None
    }

    /// Convenience: resolve page ignoring depth.
    pub fn resolve_page(&self, index: usize) -> Option<u64> {
        self.resolve_page_depth(index).map(|(phys, _)| phys)
    }

    /// Check if a page is locally committed (exists in own radix tree).
    /// Returns false for BUSY entries (commit in-progress).
    pub fn is_local_committed(&self, index: usize) -> bool {
        let entry = self.pages.get(index);
        entry != 0 && (entry & PHYS_TAG_BUSY == 0)
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

    // -----------------------------------------------------------------------
    // COW parent resolution
    // -----------------------------------------------------------------------

    /// Dereference a cow_parent CapSlot to get the parent MO pointer.
    /// Returns null if the slot is invalid.
    ///
    /// Called without CAP_LOCK from resolve_page_depth() during fault
    /// handling. This is safe because:
    ///
    /// 1. `cow_parent` is a dedicated cap slot set during MO_CLONE and
    ///    freed only when this child MO is destroyed. While the child
    ///    exists, the slot is stable.
    /// 2. The parent MO's refcount is incremented at clone time. Even if
    ///    all other capabilities to the parent are deleted, the parent
    ///    object remains live (refcount > 0) until this child is destroyed.
    /// 3. Kernel objects are never freed — they are carved from untyped
    ///    memory and the backing memory persists for the system lifetime.
    ///    The pointer in the cap slot therefore remains valid for reads.
    /// 4. `get_cap()` reads a single aligned `Cap` struct from the slot
    ///    array, which is a word-aligned load (atomic on aarch64/x86_64).
    fn deref_cow_parent(cap_slot: u64) -> *const MemoryObject {
        if cap_slot == 0 {
            return core::ptr::null();
        }
        // SAFETY: See function-level safety documentation above.
        unsafe {
            let cap = crate::cap::get_cap(cap_slot as u32);
            if cap.obj_type != ObjectType::MemoryObject {
                return core::ptr::null();
            }
            cap.object as *const MemoryObject
        }
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
    /// ## Lock ordering
    /// This function acquires `VSpace.lock` per reverse-map entry to
    /// perform unmapping. It is called from `release_object()` after
    /// `CAP_LOCK` has been released, so no outer locks are held. This
    /// is consistent with the lock ordering hierarchy in `mm/mod.rs`.
    ///
    /// The radix tree traversal (`pages.for_each`) is safe because
    /// refcount==0 guarantees no concurrent commit/resolve operations.
    pub unsafe fn destroy(&mut self) {
        // 1. Walk reverse maps: unmap all PTEs in all still-live observing
        //    VSpaces. VSpace::cleanup() removes its observer entries before it
        //    drops VmArea MO refs, so stale reverse-map pointers must not remain
        //    here by the time an MO reaches destroy().
        unsafe {
            self.reverse_maps.for_each(&mut |entry| {
                if entry.vspace.is_null() {
                    return;
                }
                let vspace = &mut *entry.vspace;
                let irq = crate::mm::save_irq_disable();
                vspace.lock.lock();
                for i in 0..entry.page_count as u64 {
                    let page_vaddr = entry.va_start + i * crate::mm::PAGE_SIZE as u64;
                    if let Some(pte) = vspace.read_entry(page_vaddr, 1) {
                        if pte & crate::mm::vspace::ENTRY_PRESENT != 0 {
                            let phys = pte & crate::mm::vspace::ENTRY_ADDR_MASK;
                            let _ = vspace.write_entry(page_vaddr, 1, 0);
                            crate::arch::paging::invlpg(page_vaddr);
                            vspace.tlb_shootdown(page_vaddr);
                            crate::mm::pmm_release_mapping(phys);
                        }
                    }
                }
                vspace.lock.unlock();
                crate::mm::restore_irq(irq);
            });
        }

        // 2. Free all pages in the radix tree.
        // Pages tagged with PHYS_TAG_UNTYPED are returned to the source
        // untyped's free list. PMM-backed pages go through pmm_free.
        // BUSY entries are skipped (should not exist at destroy time since
        // refcount==0 means no concurrent commit).
        let self_ptr = self as *mut MemoryObject;

        // Batch-collect untyped-backed pages to avoid holding commit_lock
        // while acquiring ut.alloc_lock (lock ordering).
        // Use a fixed-size on-stack batch buffer. 128 entries = 1KB stack.
        const BATCH_SIZE: usize = 128;
        let mut ut_batch: [u64; BATCH_SIZE] = [0; BATCH_SIZE];
        let mut ut_batch_len: usize = 0;

        unsafe {
            self.pages.for_each(|idx, entry| {
                if entry == 0 || entry & PHYS_TAG_BUSY != 0 {
                    return;
                }
                let phys = entry & !PHYS_TAG_MASK;
                if phys == 0 {
                    return;
                }
                if entry & PHYS_TAG_UNTYPED != 0 {
                    if ut_batch_len < BATCH_SIZE {
                        ut_batch[ut_batch_len] = phys;
                        ut_batch_len += 1;
                    } else {
                        // Flush batch when full
                        for b in 0..BATCH_SIZE {
                            let p = ut_batch[b];
                            let ut = crate::init::find_untyped_for_phys(p);
                            if !ut.is_null() {
                                (*ut).alloc_lock.lock();
                                *(crate::mm::phys_to_virt(p) as *mut u64) = (*ut).free_list_head;
                                (*ut).free_list_head = p;
                                (*ut).free_list_count += 1;
                                (*ut).alloc_lock.unlock();
                            }
                        }
                        ut_batch_len = 0;
                        ut_batch[ut_batch_len] = phys;
                        ut_batch_len += 1;
                    }
                } else {
                    crate::mm::pmm_free(
                        phys,
                        &crate::mm::frame::FrameOwner::MoData {
                            mo: self_ptr,
                            page_idx: idx as u32,
                        },
                    );
                }
            });

            // Flush remaining batch
            for b in 0..ut_batch_len {
                let p = ut_batch[b];
                let ut = crate::init::find_untyped_for_phys(p);
                if !ut.is_null() {
                    (*ut).alloc_lock.lock();
                    *(crate::mm::phys_to_virt(p) as *mut u64) = (*ut).free_list_head;
                    (*ut).free_list_head = p;
                    (*ut).free_list_count += 1;
                    (*ut).alloc_lock.unlock();
                }
            }
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

        // 5. Remove self from parent's child list + lazy collapse
        if self.cow_parent != 0 {
            let parent_slot = self.cow_parent as u32;
            unsafe {
                let parent_cap = crate::cap::get_cap(parent_slot);
                if !parent_cap.object.is_null() {
                    let parent_mo = &mut *(parent_cap.object as *mut MemoryObject);

                    // Remove self from parent's child linked list
                    Self::remove_from_child_list(parent_mo, self as *mut MemoryObject);

                    // Decrement parent ref_count
                    let old_rc = parent_mo
                        .header
                        .ref_count
                        .fetch_sub(1, core::sync::atomic::Ordering::Release);

                    // Last reference gone — cascade parent destruction.
                    // This handles the case where mmsrv already deleted
                    // its cap and our cow_parent was the final reference.
                    if old_rc == 1 {
                        parent_mo.destroy();
                    }

                    // Lazy collapse: parent is CowChild, ref_count == 1
                    // (one child remains), no local pages → re-point
                    // remaining child to grandparent, destroy parent.
                    if old_rc == 2 // was 2, now 1 after fetch_sub
                        && parent_mo.kind == MoKind::CowChild
                        && parent_mo.cow_parent != 0
                    {
                        let mut has_local = false;
                        parent_mo.pages.for_each(|_, phys| {
                            if phys != 0 {
                                has_local = true;
                            }
                        });

                        if !has_local && !parent_mo.first_child.is_null() {
                            let remaining = parent_mo.first_child;

                            // Transfer grandparent cap to remaining child
                            let old_child_cap = (*remaining).cow_parent;
                            (*remaining).cow_parent = parent_mo.cow_parent;
                            parent_mo.cow_parent = 0; // prevent double-decrement

                            // Free remaining child's old cap (referenced parent)
                            if old_child_cap != 0 {
                                crate::cap::free_slot(old_child_cap as u32);
                            }

                            // Detach remaining from parent
                            parent_mo.first_child = core::ptr::null_mut();
                            (*remaining).next_sibling = core::ptr::null_mut();

                            // Add remaining to grandparent's child list
                            if (*remaining).cow_parent != 0 {
                                let gp_cap = crate::cap::get_cap((*remaining).cow_parent as u32);
                                if !gp_cap.object.is_null() {
                                    let gp_mo = &mut *(gp_cap.object as *mut MemoryObject);
                                    (*remaining).next_sibling = gp_mo.first_child;
                                    gp_mo.first_child = remaining;
                                }
                            }

                            // Destroy the empty intermediate parent
                            parent_mo.destroy();
                        }
                    }
                }
            }
            crate::cap::free_slot(parent_slot);
            self.cow_parent = 0;
        }
    }

    /// Remove `child` from `parent`'s intrusive child linked list.
    unsafe fn remove_from_child_list(parent: &mut MemoryObject, child: *mut MemoryObject) {
        if parent.first_child == child {
            unsafe {
                parent.first_child = (*child).next_sibling;
                (*child).next_sibling = core::ptr::null_mut();
            }
            return;
        }
        let mut prev = parent.first_child;
        while !prev.is_null() {
            unsafe {
                if (*prev).next_sibling == child {
                    (*prev).next_sibling = (*child).next_sibling;
                    (*child).next_sibling = core::ptr::null_mut();
                    return;
                }
                prev = (*prev).next_sibling;
            }
        }
    }
}
