//! Untyped Memory Management
//!
//! Untyped memory is the raw memory from which all kernel objects are created.
//! This module implements retyping (allocating objects) and untyping (freeing),
//! with proper parent-child tracking via CDT.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::slot::{CapSlot, free_slot, get_cap, write_capability};
use super::{
    CDT, CapError, Capability, ObjectType, increment_refcount, release_object,
    try_increment_refcount,
};
use crate::cap::cnode::effective_cnode_bits;
use crate::mm::{self, PAGE_SIZE, PhysAddr};
use core::mem::MaybeUninit;

/// Maximum number of distinct `obj_size` classes a single `UntypedMemory`
/// can host concurrently. Each new `obj_size` carved from a source registers
/// a `ClassBucket`; once the registry is full, further new-class carves
/// return `CapError::OutOfClasses` and the caller (rsrcsrv) tries the next
/// source. Same-class carves and freelist hits remain unaffected.
pub const MAX_CLASSES_PER_SOURCE: usize = 16;

/// Per-class freelist bucket inside an `UntypedMemory`. The bucket key is
/// `obj_size` (in bytes); same-size objects of different `ObjectType`
/// share a single bucket because the freelist node format is identical
/// and the next `init_object` call overwrites all object bytes anyway.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClassBucket {
    /// Byte size of objects on this freelist. 0 = unused slot.
    pub obj_size: u64,
    /// Physical address of the head node, 0 = empty list. Each node stores
    /// the next phys at its first 8 bytes.
    pub free_head: u64,
    /// Diagnostic counter — number of nodes currently on the freelist.
    pub free_count: u32,
    _pad: u32,
}

impl ClassBucket {
    pub const fn empty() -> Self {
        Self {
            obj_size: 0,
            free_head: 0,
            free_count: 0,
            _pad: 0,
        }
    }
}

/// Untyped memory region
///
/// Represents a contiguous region of physical memory that can be
/// retyped into kernel objects. Hosts up to `MAX_CLASSES_PER_SOURCE`
/// distinct `obj_size` freelists simultaneously (multi-class).
#[repr(C)]
pub struct UntypedMemory {
    /// Kernel object header (must be first for refcount access)
    pub header: super::object::KernelObject,

    /// Physical address of the region
    pub phys_addr: PhysAddr,

    /// Size as power of 2 (e.g., 20 = 1MB, 12 = 4KB)
    pub size_bits: u8,

    /// Watermark - high-water mark for fresh allocations (monotonic; only
    /// reset by `UntypedTracker::reset` when the source has zero children).
    /// Freed objects of any class go onto their `ClassBucket::free_head`
    /// list and are reused by `carve_block` before bumping the watermark.
    pub watermark: u64,

    /// Whether this is device memory (non-cacheable). Device untypeds
    /// bypass freelist (MMIO is not PMM-tracked and not safely
    /// dereferenceable as next-pointer storage).
    pub is_device: bool,

    /// Protects all allocator state below (watermark, class_buckets,
    /// class_count). Lock ordering: `mo.commit_lock | mo.rmap_lock →
    /// ut.alloc_lock → FRAME_LOCK` (see `mm/mod.rs` lock-ordering doc).
    pub alloc_lock: mm::SpinLock,

    /// Per-class freelist registry, indexed 0..class_count.
    pub class_buckets: [ClassBucket; MAX_CLASSES_PER_SOURCE],

    /// Number of bucket slots currently in use.
    pub class_count: u8,

    /// Page-sized MO data allocations currently carved from this untyped.
    ///
    /// These pages are not `KernelObject` children, but they are live typed
    /// allocations from this source. They pin the untyped object and block
    /// reset/reap until the owning MO releases them.
    pub mo_page_refs: u32,

    /// Head of the per-object children list (`hlist`-style).
    ///
    /// Anchors every kernel object carved from this untyped, regardless
    /// of how many caps refer to it. `add_child` / `remove_child`
    /// mutate under `alloc_lock`. `null` when no children are alive.
    pub child_head: *mut super::object::KernelObject,
}

impl UntypedMemory {
    pub const fn new(phys_addr: PhysAddr, size_bits: u8, is_device: bool) -> Self {
        Self {
            header: super::object::KernelObject::new(ObjectType::Untyped, size_bits),
            phys_addr,
            size_bits,
            watermark: 0,
            is_device,
            alloc_lock: mm::SpinLock::new(),
            class_buckets: [ClassBucket::empty(); MAX_CLASSES_PER_SOURCE],
            class_count: 0,
            mo_page_refs: 0,
            child_head: core::ptr::null_mut(),
        }
    }

    /// Carve a single typed-object block from this untyped under
    /// multi-class semantics: prefers a freelist hit on the matching
    /// `obj_size` bucket, falls back to bumping the watermark, registers
    /// a new bucket if `obj_size` is unseen and the registry has room.
    ///
    /// Holds `alloc_lock` for the duration. Returns the physical address
    /// of the carved region. Does NOT touch CDT, capability slots, PMM
    /// ownership, or initialise the carved memory — callers (`retype` /
    /// MO_COMMIT) handle those layers.
    pub fn carve_block(&mut self, obj_size: u64, align: usize) -> Result<PhysAddr, CapError> {
        if obj_size == 0 || align == 0 {
            return Err(CapError::InvalidArgument);
        }
        self.alloc_lock.lock();
        let result = if self.is_device {
            self.carve_watermark_locked(obj_size, align)
        } else {
            self.carve_block_locked(obj_size, align)
        };
        self.alloc_lock.unlock();
        result
    }

    fn carve_block_locked(&mut self, obj_size: u64, align: usize) -> Result<PhysAddr, CapError> {
        let class_count = self.class_count as usize;
        for i in 0..class_count {
            if self.class_buckets[i].obj_size == obj_size {
                if self.class_buckets[i].free_head != 0 {
                    let popped = self.class_buckets[i].free_head;
                    let next = unsafe { *(mm::phys_to_virt(popped) as *const u64) };
                    self.class_buckets[i].free_head = next;
                    self.class_buckets[i].free_count -= 1;
                    return Ok(popped);
                }
                return self.carve_watermark_locked(obj_size, align);
            }
        }
        if class_count >= MAX_CLASSES_PER_SOURCE {
            return Err(CapError::OutOfClasses);
        }
        let phys = self.carve_watermark_locked(obj_size, align)?;
        self.class_buckets[class_count] = ClassBucket {
            obj_size,
            free_head: 0,
            free_count: 0,
            _pad: 0,
        };
        self.class_count = (class_count + 1) as u8;
        Ok(phys)
    }

    fn carve_watermark_locked(
        &mut self,
        obj_size: u64,
        align: usize,
    ) -> Result<PhysAddr, CapError> {
        let watermark = self.watermark as usize;
        let rounded = watermark
            .checked_add(align - 1)
            .ok_or(CapError::InsufficientMemory)?;
        let aligned = (rounded / align) * align;
        let end = (aligned as u64)
            .checked_add(obj_size)
            .ok_or(CapError::InsufficientMemory)?;
        if end > self.size_bytes() as u64 {
            return Err(CapError::InsufficientMemory);
        }
        let phys = self.phys_addr + aligned as u64;
        self.watermark = end;
        Ok(phys)
    }

    /// Carve one MO data page from this untyped and record it as a live
    /// non-object allocation. The returned page is still PMM-tagged
    /// `UntypedReserved { ut: self }`; `MO_COMMIT` transfers it to `MoData`
    /// after the radix commit succeeds.
    pub fn carve_mo_page(&mut self) -> Result<PhysAddr, CapError> {
        if self.is_device {
            return Err(CapError::InvalidOperation);
        }
        let header = &raw mut self.header;
        if unsafe { !try_increment_refcount(header) } {
            return Err(CapError::InvalidOperation);
        }

        self.alloc_lock.lock();
        let result = if self.mo_page_refs == u32::MAX {
            Err(CapError::InsufficientMemory)
        } else {
            let carved = self.carve_block_locked(PAGE_SIZE as u64, PAGE_SIZE);
            if carved.is_ok() {
                self.mo_page_refs += 1;
            }
            carved
        };
        self.alloc_lock.unlock();

        if result.is_err() {
            unsafe { release_object(header, ObjectType::Untyped) };
        }
        result
    }

    /// Push a freed block back onto its `obj_size`-matched bucket.
    /// Caller is responsible for ensuring the cap was already revoked
    /// and the PMM ownership has been reclaimed via
    /// `reclaim_child_range`. No-op for device untypeds.
    pub fn release_block(&mut self, phys: PhysAddr, obj_size: u64) -> Result<(), CapError> {
        if obj_size == 0 {
            return Err(CapError::InvalidArgument);
        }
        let region_end = self.phys_addr.saturating_add(self.size_bytes() as u64);
        let block_end = phys
            .checked_add(obj_size)
            .ok_or(CapError::InvalidArgument)?;
        if phys < self.phys_addr || block_end > region_end {
            return Err(CapError::InvalidArgument);
        }
        if self.is_device {
            return Ok(());
        }
        self.alloc_lock.lock();
        let result = self.release_block_locked(phys, obj_size);
        self.alloc_lock.unlock();
        result
    }

    fn release_block_locked(&mut self, phys: PhysAddr, obj_size: u64) -> Result<(), CapError> {
        let class_count = self.class_count as usize;
        for i in 0..class_count {
            if self.class_buckets[i].obj_size == obj_size {
                let head = self.class_buckets[i].free_head;
                unsafe {
                    *(mm::phys_to_virt(phys) as *mut u64) = head;
                }
                self.class_buckets[i].free_head = phys;
                self.class_buckets[i].free_count += 1;
                return Ok(());
            }
        }
        Err(CapError::InvalidOperation)
    }

    /// Return an MO page carved by [`carve_mo_page`] to this untyped's
    /// page-size freelist. The caller must have already restored PMM ownership
    /// to `UntypedReserved { ut: self }` when the page had been committed.
    pub unsafe fn release_mo_page_block(&mut self, phys: PhysAddr) {
        let header = &raw mut self.header;
        self.alloc_lock.lock();
        crate::kernel::bug::kassert!(self.mo_page_refs > 0, "untyped MO page ref underflow");
        let result = self.release_block_locked(phys, PAGE_SIZE as u64);
        if result.is_ok() {
            self.mo_page_refs -= 1;
        }
        self.alloc_lock.unlock();

        crate::kernel::bug::kassert!(result.is_ok(), "untyped MO page release failed");
        unsafe { release_object(header, ObjectType::Untyped) };
    }

    /// Return a committed MO page to this untyped. The live PMM owner must be
    /// `MoData { mo, page_idx }`; this method restores `UntypedReserved` under
    /// the untyped allocator lock before publishing the page on the freelist.
    pub unsafe fn release_committed_mo_page(
        &mut self,
        phys: PhysAddr,
        mo: *mut crate::cap::memory_object::MemoryObject,
        page_idx: usize,
    ) {
        let header = &raw mut self.header;
        self.alloc_lock.lock();
        crate::kernel::bug::kassert!(self.mo_page_refs > 0, "untyped MO page ref underflow");
        crate::mm::pmm_transfer(
            phys,
            &crate::mm::frame::FrameOwner::MoData {
                mo,
                page_idx: page_idx as u32,
            },
            &crate::mm::frame::FrameOwner::UntypedReserved {
                ut: self as *const UntypedMemory,
            },
        );
        let result = self.release_block_locked(phys, PAGE_SIZE as u64);
        if result.is_ok() {
            self.mo_page_refs -= 1;
        }
        self.alloc_lock.unlock();

        crate::kernel::bug::kassert!(result.is_ok(), "untyped MO page release failed");
        unsafe { release_object(header, ObjectType::Untyped) };
    }

    /// Get size in bytes
    pub fn size_bytes(&self) -> usize {
        1usize << self.size_bits
    }

    /// Get available bytes
    pub fn available(&self) -> usize {
        self.size_bytes().saturating_sub(self.watermark as usize)
    }

    /// Whether this untyped has any live children carved from it.
    ///
    /// Reads `child_head` under `alloc_lock`. Sees the union of every
    /// child added via `add_child` regardless of which cap was used to
    /// retype — this is the structural fix for the cap-local
    /// `ut_first_child` split-brain bug.
    pub fn has_children(&self) -> bool {
        self.alloc_lock.lock();
        let result = !self.child_head.is_null() || self.mo_page_refs != 0;
        self.alloc_lock.unlock();
        result
    }

    /// Insert `child` at the head of this untyped's children list.
    /// Locks `alloc_lock` for the duration.
    ///
    /// # Safety
    /// `child` must point at a valid, fully-initialised `KernelObject`
    /// whose sibling/parent fields are all `null` (i.e. not currently
    /// a member of any other untyped's child list). After this call
    /// `(*child).parent_ut == self as *mut UntypedMemory`. The child also
    /// holds an internal refcount pin on this parent untyped until the reaper
    /// removes it from the child list.
    pub unsafe fn add_child(&mut self, child: *mut super::object::KernelObject) {
        self.alloc_lock.lock();
        unsafe { self.add_child_locked(child) };
        self.alloc_lock.unlock();
    }

    /// Variant of `add_child` for callers that already hold
    /// `alloc_lock` (none today, but keeps the linkage logic in one
    /// place if `retype` is later restructured to fold add_child into
    /// the same critical section as `carve_block`).
    ///
    /// # Safety
    /// Caller must hold `self.alloc_lock`. Otherwise identical
    /// preconditions to `add_child`.
    pub unsafe fn add_child_locked(&mut self, child: *mut super::object::KernelObject) {
        unsafe {
            // The child object's parent_ut pointer must stay valid even if the
            // last user-visible cap to this untyped is deleted while children
            // are still live. Pair with object/reaper.rs when the child is
            // removed from this list.
            increment_refcount(&raw mut self.header);
            (*child).parent_ut = self as *mut UntypedMemory;
            (*child).ut_sibling_next = self.child_head;
            (*child).ut_sibling_pprev = &raw mut self.child_head;
            if !self.child_head.is_null() {
                (*self.child_head).ut_sibling_pprev = &raw mut (*child).ut_sibling_next;
            }
            self.child_head = child;
        }
    }

    /// Unlink `child` from this untyped's children list. O(1) via the
    /// `pprev` back-link. Locks `alloc_lock` for the duration.
    ///
    /// # Safety
    /// `child` must currently be a member of `self`'s child list
    /// (`(*child).parent_ut == self`). After this call, `child`'s
    /// sibling/parent fields are all `null`.
    pub unsafe fn remove_child(&mut self, child: *mut super::object::KernelObject) {
        self.alloc_lock.lock();
        unsafe { self.remove_child_locked(child) };
        self.alloc_lock.unlock();
    }

    /// Variant of `remove_child` for callers that already hold
    /// `alloc_lock`.
    ///
    /// # Safety
    /// Caller must hold `self.alloc_lock`. Otherwise identical
    /// preconditions to `remove_child`.
    pub unsafe fn remove_child_locked(&mut self, child: *mut super::object::KernelObject) {
        unsafe {
            let next = (*child).ut_sibling_next;
            let pprev = (*child).ut_sibling_pprev;
            if !pprev.is_null() {
                *pprev = next;
            }
            if !next.is_null() {
                (*next).ut_sibling_pprev = pprev;
            }
            (*child).ut_sibling_next = core::ptr::null_mut();
            (*child).ut_sibling_pprev = core::ptr::null_mut();
            (*child).parent_ut = core::ptr::null_mut();
        }
    }

    /// Wipe the per-object allocator state — `watermark`, the per-class
    /// freelist registry, and `class_count` — so the whole region can
    /// be re-carved fresh. Refuses with `HasChildren` when any child
    /// is still alive in the object's children list. The check + write
    /// happen under `alloc_lock` so no concurrent retype can slip a
    /// new child in between the test and the reset.
    pub fn reset_state(&mut self) -> Result<(), CapError> {
        self.alloc_lock.lock();
        if !self.child_head.is_null() || self.mo_page_refs != 0 {
            self.alloc_lock.unlock();
            return Err(CapError::HasChildren);
        }
        self.watermark = 0;
        self.class_buckets = [ClassBucket::empty(); MAX_CLASSES_PER_SOURCE];
        self.class_count = 0;
        self.alloc_lock.unlock();
        Ok(())
    }

    /// Mark every 4 KiB page in this untyped's covered range as
    /// `UntypedReserved` in the PMM, with the back-pointer set to
    /// `ut_ptr` (must point at the stable static storage or
    /// retyped-slot storage holding `self`).
    ///
    /// Establishes the PMM ↔ untyped disjointness invariant at root
    /// untyped creation: frames leave the PMM free pool and become
    /// carvable only through `retype`. Device untypeds cover MMIO that
    /// is never entered into the PMM bitmap — skipped.
    pub fn reserve_range(&self, ut_ptr: *const UntypedMemory) {
        if self.is_device {
            return;
        }
        let start = self.phys_addr;
        let pages = self.size_bytes() / PAGE_SIZE;
        let owner = mm::frame::FrameOwner::UntypedReserved { ut: ut_ptr };
        for i in 0..pages {
            let addr = start + (i * PAGE_SIZE) as u64;
            mm::pmm_set_owner(addr, &owner);
        }
    }

    /// Reverse of `reserve_range`: return every covered frame to the
    /// PMM free pool. Called from the revoke path for root untypeds.
    /// No-op for device untypeds.
    pub fn release_reservation(&self) {
        if self.is_device {
            return;
        }
        let start = self.phys_addr;
        let pages = self.size_bytes() / PAGE_SIZE;
        let owner = mm::frame::FrameOwner::UntypedReserved {
            ut: self as *const _,
        };
        for i in 0..pages {
            let addr = start + (i * PAGE_SIZE) as u64;
            mm::pmm_free(addr, &owner);
        }
    }

    /// Transition a typed-object's backing frames from Typed ownership
    /// back to `UntypedReserved { ut: self }`. Called from the untype
    /// path on a typed child being destroyed. No-op for device untypeds
    /// (their coverage is not tracked in the PMM bitmap).
    pub fn reclaim_child_range(&self, obj_phys: PhysAddr, byte_size: usize) {
        if self.is_device {
            return;
        }
        let pages = (byte_size + PAGE_SIZE - 1) / PAGE_SIZE;
        let owner = mm::frame::FrameOwner::UntypedReserved {
            ut: self as *const _,
        };
        for i in 0..pages {
            let addr = obj_phys + (i * PAGE_SIZE) as u64;
            mm::pmm_set_owner(addr, &owner);
        }
    }
}

/// Single frame object (for Frame capabilities)
#[repr(C)]
pub struct FrameObject {
    /// Kernel object header (must be first for refcount access)
    pub header: super::object::KernelObject,
    pub phys_addr: PhysAddr,
    pub size_bits: u8,
}

impl FrameObject {
    pub const fn new(phys_addr: PhysAddr, size_bits: u8) -> Self {
        Self {
            header: super::object::KernelObject::new(ObjectType::Frame, size_bits),
            phys_addr,
            size_bits,
        }
    }

    pub fn size_bytes(&self) -> usize {
        1usize << self.size_bits
    }
}

/// A userland-provided 4 KiB hardware page table, installed via `VSPACE_MAP_PT`.
/// Distinct from `FrameObject` so the same page can never be data-mapped (which
/// would let userland forge PTEs). Like `FrameObject`, the header lives out of
/// band — the 4 KiB page holds 512 live PTEs — and the page itself is at
/// `phys_addr`. `mapped` is the single-map guard: a table already installed in a
/// VSpace is refused on re-install, which would otherwise zero a live table or
/// re-introduce cross-address-space aliasing (seL4 single-maps page tables).
#[repr(C)]
pub struct PageTableObject {
    /// Kernel object header (must be first for refcount access).
    pub header: super::object::KernelObject,
    pub phys_addr: PhysAddr,
    pub mapped: bool,
}

impl PageTableObject {
    pub const fn new(phys_addr: PhysAddr) -> Self {
        Self {
            header: super::object::KernelObject::new(ObjectType::PageTable, 12),
            phys_addr,
            mapped: false,
        }
    }
}

/// Dynamic metadata state (pointers to frame-allocated arrays)
struct MetadataState {
    frame_ptr: *mut MaybeUninit<FrameObject>,
    vspace_ptr: *mut MaybeUninit<crate::mm::VSpace>,
    untyped_ptr: *mut MaybeUninit<UntypedMemory>,
    page_table_ptr: *mut MaybeUninit<PageTableObject>,
}

// SAFETY: Pointers are only accessed under CAP_LOCK
unsafe impl Sync for MetadataState {}

static mut METADATA_STATE: MetadataState = MetadataState {
    frame_ptr: core::ptr::null_mut(),
    vspace_ptr: core::ptr::null_mut(),
    untyped_ptr: core::ptr::null_mut(),
    page_table_ptr: core::ptr::null_mut(),
};

/// Initialize dynamically-allocated metadata arrays.
///
/// # Safety
/// Must be called exactly once during boot, after paging::init().
pub unsafe fn init_metadata(num_slots: usize) {
    use crate::mm::PAGE_SIZE;

    let frame_bytes = num_slots * core::mem::size_of::<MaybeUninit<FrameObject>>();
    let frame_pages = (frame_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    let vspace_bytes = num_slots * core::mem::size_of::<MaybeUninit<crate::mm::VSpace>>();
    let vspace_pages = (vspace_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    let untyped_bytes = num_slots * core::mem::size_of::<MaybeUninit<UntypedMemory>>();
    let untyped_pages = (untyped_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    let page_table_bytes = num_slots * core::mem::size_of::<MaybeUninit<PageTableObject>>();
    let page_table_pages = (page_table_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    let meta_owner = mm::frame::FrameOwner::KernelPrivate {
        subkind: mm::frame::KernelMetaKind::General,
    };
    let frame_phys = mm::pmm_alloc_contiguous_owned(frame_pages, &meta_owner)
        .expect("[CAP] FRAME_METADATA allocation failed");
    let vspace_phys = mm::pmm_alloc_contiguous_owned(vspace_pages, &meta_owner)
        .expect("[CAP] VSPACE_METADATA allocation failed");
    let untyped_phys = mm::pmm_alloc_contiguous_owned(untyped_pages, &meta_owner)
        .expect("[CAP] UNTYPED_METADATA allocation failed");
    let page_table_phys = mm::pmm_alloc_contiguous_owned(page_table_pages, &meta_owner)
        .expect("[CAP] PAGE_TABLE_METADATA allocation failed");

    // SAFETY: Single-threaded init, direct map available
    unsafe {
        let state = &mut *(&raw mut METADATA_STATE);
        state.frame_ptr = mm::phys_to_virt(frame_phys) as *mut MaybeUninit<FrameObject>;
        state.vspace_ptr = mm::phys_to_virt(vspace_phys) as *mut MaybeUninit<crate::mm::VSpace>;
        state.untyped_ptr = mm::phys_to_virt(untyped_phys) as *mut MaybeUninit<UntypedMemory>;
        state.page_table_ptr =
            mm::phys_to_virt(page_table_phys) as *mut MaybeUninit<PageTableObject>;
    }

    {
        let s = crate::kernel::printk::SerialGuard::acquire();
        s.puts("[CAP] Metadata arrays: frame=");
        s.dec(frame_pages as u64);
        s.puts("p, vspace=");
        s.dec(vspace_pages as u64);
        s.puts("p, untyped=");
        s.dec(untyped_pages as u64);
        s.puts("p\n");
    }
}

/// Resolve a typed child capability to its backing physical range
/// `(obj_phys, byte_size)`. Used by the untype/revoke path to restore
/// `UntypedReserved` ownership of the frames the child was carved from
/// and by the reaper to push the bytes back onto the parent untyped's
/// `release_block` freelist.
///
/// **Critical**: `cap.object` is NOT necessarily the carved range —
/// for `Frame`, `Untyped`, and `VSpace`, the kernel keeps an
/// out-of-band header in `METADATA_STATE` arrays (frame_ptr /
/// untyped_ptr / vspace_ptr) and the actual carved phys is recorded
/// inside that header. Mapping those types through the generic
/// `virt_to_phys(cap.object)` fallback would point at the metadata
/// array, not the carved range — and reaper would then retag the
/// wrong PMM frames as `UntypedReserved`, corrupting whatever else
/// happened to live at that metadata address. Always go through the
/// type-specific accessor for those.
///
/// Returns `None` only for `ReplyContext` (which lives in a separate
/// per-task pool, not in any untyped's carve) and for `Null` (no
/// object). All other object types — including `IoPort` and
/// `IrqHandler` whose 24/48-byte headers are carved from untyped
/// memory by `carve_block` like every other object — return their
/// header phys range so retype and reaper stay symmetric.
pub(crate) fn child_phys_range(cap: &crate::cap::Capability) -> Option<(PhysAddr, usize)> {
    if cap.object.is_null() {
        return None;
    }
    let obj_type = cap.obj_type;
    let size_bits = unsafe { (*cap.object).size_bits };
    match obj_type {
        ObjectType::Frame => {
            // `cap.object` is in `METADATA_STATE.frame_ptr[]`; the carved
            // page is at `FrameObject.phys_addr` with `size_bytes()`.
            let fo = cap.object as *const FrameObject;
            let phys = unsafe { (*fo).phys_addr };
            let size = unsafe { (*fo).size_bytes() };
            Some((phys, size))
        }
        ObjectType::PageTable => {
            // `cap.object` is in `METADATA_STATE.page_table_ptr[]`; the carved
            // page is the 4 KiB hardware table at `PageTableObject.phys_addr`.
            let pto = cap.object as *const PageTableObject;
            let phys = unsafe { (*pto).phys_addr };
            Some((phys, crate::mm::PAGE_SIZE))
        }
        ObjectType::Untyped => {
            // `cap.object` is in `METADATA_STATE.untyped_ptr[]`; the
            // carved range is `phys_addr .. phys_addr + size_bytes()`.
            let ut = cap.object as *const UntypedMemory;
            let phys = unsafe { (*ut).phys_addr };
            let size = unsafe { (*ut).size_bytes() };
            Some((phys, size))
        }
        ObjectType::VSpace => {
            // `cap.object` is in `METADATA_STATE.vspace_ptr[]`; the
            // carved range is the PML4 page plus the embedded
            // `VSpaceTracking`, totalling `VSPACE_OBJECT_SIZE` bytes
            // starting at the PML4 phys.
            let vs = cap.object as *const crate::mm::VSpace;
            let pml4_phys = unsafe { (*vs).root() };
            Some((pml4_phys, crate::mm::vspace::VSPACE_OBJECT_SIZE))
        }
        ObjectType::Null => None,
        _ => {
            // For the remaining types (`Tcb`, `CNode`, `MemoryObject`,
            // `IrqHandler`, `IoPort`, `SchedContext`, `EventQueue`,
            // `Watch`, `MessagePipe`, `DataPipe`, `Timer`, system caps)
            // `init_object` writes the header directly into the carved
            // virt, so `virt_to_phys(cap.object)` IS the carved phys.
            let size = object_size(obj_type, size_bits).ok()?;
            if size == 0 {
                return None;
            }
            let virt = cap.object as u64;
            let phys = mm::virt_to_phys(virt);
            Some((phys, size))
        }
    }
}

/// Get object size in bytes for a given type.
///
/// Fixed-layout types delegate to `object_alloc_bytes`, which mirrors
/// the kernite UAPI byte constants. Edge object types (rings, watcher
/// state, system caps) carry a placeholder zero in the UAPI header
/// while their layouts iterate; the kernel resolves their carve size
/// directly from `size_of::<T>()` so retype hands back a region wide
/// enough for the live struct, page-rounded so the carve always
/// matches the PMM granule.
pub(crate) fn object_size(obj_type: ObjectType, size_bits: u8) -> Result<usize, CapError> {
    use crate::cap::ObjectSizeError;

    if matches!(obj_type, ObjectType::Null) {
        return Ok(0);
    }

    let obj_type_u: u64 = match obj_type {
        ObjectType::Untyped => uapi::KERNITE_OBJ_UNTYPED as u64,
        ObjectType::Tcb => uapi::KERNITE_OBJ_TCB as u64,
        ObjectType::CNode => uapi::KERNITE_OBJ_CNODE as u64,
        ObjectType::VSpace => uapi::KERNITE_OBJ_VSPACE as u64,
        ObjectType::Frame => uapi::KERNITE_OBJ_FRAME as u64,
        ObjectType::IrqHandler => uapi::KERNITE_OBJ_IRQ_HANDLER as u64,
        ObjectType::IoPort => uapi::KERNITE_OBJ_IO_PORT as u64,
        ObjectType::SchedContext => uapi::KERNITE_OBJ_SCHED_CONTEXT as u64,
        ObjectType::MemoryObject => uapi::KERNITE_OBJ_MEMORY_OBJECT as u64,
        ObjectType::EventQueue => uapi::KERNITE_OBJ_EVENT_QUEUE as u64,
        ObjectType::Watch => uapi::KERNITE_OBJ_WATCH as u64,
        ObjectType::MessagePipe => uapi::KERNITE_OBJ_MESSAGE_PIPE as u64,
        ObjectType::MessagePipeCore => uapi::KERNITE_OBJ_MESSAGE_PIPE_CORE as u64,
        ObjectType::DataPipe => uapi::KERNITE_OBJ_DATA_PIPE as u64,
        ObjectType::DataPipeCore => uapi::KERNITE_OBJ_DATA_PIPE_CORE as u64,
        ObjectType::Timer => uapi::KERNITE_OBJ_TIMER as u64,
        ObjectType::KernelRng => uapi::KERNITE_OBJ_KERNEL_RNG as u64,
        ObjectType::SystemControl => uapi::KERNITE_OBJ_SYSTEM_CONTROL as u64,
        ObjectType::Clock => uapi::KERNITE_OBJ_CLOCK as u64,
        ObjectType::SystemInfo => uapi::KERNITE_OBJ_SYSTEM_INFO as u64,
        ObjectType::KernelDebug => uapi::KERNITE_OBJ_KERNEL_DEBUG as u64,
        ObjectType::Pager => uapi::KERNITE_OBJ_PAGER as u64,
        ObjectType::DeviceControl => uapi::KERNITE_OBJ_DEVICE_CONTROL as u64,
        ObjectType::VmHierarchyState => uapi::KERNITE_OBJ_VM_HIERARCHY_STATE as u64,
        ObjectType::ExecAuthority => uapi::KERNITE_OBJ_EXEC_AUTHORITY as u64,
        ObjectType::PageTable => uapi::KERNITE_OBJ_PAGE_TABLE as u64,
        ObjectType::Null => return Err(CapError::InvalidOperation),
    };
    match crate::cap::object_alloc_bytes(obj_type_u, size_bits as u64) {
        Ok(bytes) => Ok(bytes as usize),
        Err(ObjectSizeError::InvalidSizeBits) | Err(ObjectSizeError::InvalidObjType) => {
            Err(CapError::InvalidArgument)
        }
    }
}

/// Initialize kernel object in memory
unsafe fn init_object(
    obj_type: ObjectType,
    phys_addr: PhysAddr,
    size_bits: u8,
) -> Result<*mut crate::cap::object::KernelObject, CapError> {
    use crate::cap::object::KernelObject;

    let virt_addr = mm::phys_to_virt(phys_addr) as *mut u8;

    unsafe {
        match obj_type {
            ObjectType::CNode => {
                let bits = effective_cnode_bits(size_bits)?;
                crate::cap::CNode::init_at(virt_addr, bits);
                Ok(virt_addr as *mut KernelObject)
            }

            ObjectType::Frame => Err(CapError::InvalidOperation),

            // Out-of-band metadata, like Frame: created by
            // `init_page_table_metadata` in the retype carve loop, not here.
            ObjectType::PageTable => Err(CapError::InvalidOperation),

            ObjectType::Untyped => Err(CapError::InvalidOperation),

            ObjectType::Tcb => {
                let tcb = virt_addr as *mut crate::sched::thread::Tcb;
                if !crate::sched::thread::Tcb::init_at(tcb) {
                    return Err(CapError::InsufficientMemory);
                }
                Ok(tcb as *mut KernelObject)
            }

            ObjectType::VSpace => Err(CapError::InvalidOperation),

            ObjectType::SchedContext => {
                let sc = virt_addr as *mut crate::sched::thread::SchedContext;
                sc.write(crate::sched::thread::SchedContext::new());
                Ok(sc as *mut KernelObject)
            }

            ObjectType::IrqHandler => {
                let irq = virt_addr as *mut crate::event::irq::IrqHandler;
                irq.write(crate::event::irq::IrqHandler::new(0));
                Ok(irq as *mut KernelObject)
            }

            ObjectType::IoPort => {
                let ioport = virt_addr as *mut crate::cap::IoPortRange;
                ioport.write(crate::cap::IoPortRange::new(0, 0));
                Ok(ioport as *mut KernelObject)
            }

            ObjectType::EventQueue => {
                let eq = virt_addr as *mut crate::event::event_queue::EventQueue;
                eq.write(crate::event::event_queue::EventQueue::new());
                Ok(eq as *mut KernelObject)
            }

            ObjectType::Watch => {
                let w = virt_addr as *mut crate::event::watch::Watch;
                w.write(crate::event::watch::Watch::new());
                Ok(w as *mut KernelObject)
            }

            ObjectType::Pager => {
                let p = virt_addr as *mut crate::cap::pager::Pager;
                p.write(crate::cap::pager::Pager::new());
                Ok(p as *mut KernelObject)
            }

            ObjectType::MessagePipe => {
                let mp = virt_addr as *mut crate::ipc::message_pipe::MessagePipe;
                mp.write(crate::ipc::message_pipe::MessagePipe::new());
                Ok(mp as *mut KernelObject)
            }

            ObjectType::DataPipe => {
                let dp = virt_addr as *mut crate::ipc::data_pipe::DataPipe;
                dp.write(crate::ipc::data_pipe::DataPipe::new());
                Ok(dp as *mut KernelObject)
            }

            ObjectType::Timer => {
                let t = virt_addr as *mut crate::event::timer::Timer;
                t.write(crate::event::timer::Timer::new());
                Ok(t as *mut KernelObject)
            }

            ObjectType::KernelRng => {
                let r = virt_addr as *mut crate::cap::system::KernelRng;
                r.write(crate::cap::system::KernelRng::new());
                Ok(r as *mut KernelObject)
            }

            ObjectType::SystemControl => {
                let s = virt_addr as *mut crate::cap::system::SystemControl;
                s.write(crate::cap::system::SystemControl::new());
                Ok(s as *mut KernelObject)
            }

            ObjectType::Clock => {
                let c = virt_addr as *mut crate::cap::system::Clock;
                c.write(crate::cap::system::Clock::new());
                Ok(c as *mut KernelObject)
            }

            ObjectType::SystemInfo => {
                let si = virt_addr as *mut crate::cap::system::SystemInfo;
                si.write(crate::cap::system::SystemInfo::new());
                Ok(si as *mut KernelObject)
            }

            ObjectType::KernelDebug => {
                let kd = virt_addr as *mut crate::cap::system::KernelDebug;
                kd.write(crate::cap::system::KernelDebug::new());
                Ok(kd as *mut KernelObject)
            }

            ObjectType::DeviceControl => {
                let dc = virt_addr as *mut crate::cap::system::DeviceControl;
                dc.write(crate::cap::system::DeviceControl::new());
                Ok(dc as *mut KernelObject)
            }

            ObjectType::MessagePipeCore => {
                let core = virt_addr as *mut crate::ipc::message_pipe::MessagePipeCore;
                core.write(crate::ipc::message_pipe::MessagePipeCore::new());
                Ok(core as *mut KernelObject)
            }

            ObjectType::VmHierarchyState => {
                let state = virt_addr as *mut crate::cap::memory_object::VmHierarchyState;
                state.write(crate::cap::memory_object::VmHierarchyState::new());
                Ok(state as *mut KernelObject)
            }

            ObjectType::DataPipeCore => {
                let core = virt_addr as *mut crate::ipc::data_pipe::DataPipeCore;
                core.write(crate::ipc::data_pipe::DataPipeCore::new());
                Ok(core as *mut KernelObject)
            }

            _ => Err(CapError::InvalidOperation),
        }
    }
}

/// Initialize frame metadata in dynamically-allocated storage.
unsafe fn init_frame_metadata(
    cap_slot: CapSlot,
    phys_addr: PhysAddr,
    size_bits: u8,
    zero_fill: bool,
) -> *mut crate::cap::object::KernelObject {
    let actual_bits = if size_bits < 12 { 12 } else { size_bits };
    if zero_fill {
        let frame_virt = mm::phys_to_virt(phys_addr) as *mut u8;
        // Security invariant: newly retyped RAM-backed frames must be zeroed
        // before exposure to userspace.
        unsafe {
            core::ptr::write_bytes(frame_virt, 0, 1usize << actual_bits);
        }
    }
    // Frame ownership managed by PMM FrameOwner tags, no separate refcount needed.
    // SAFETY: METADATA_STATE is initialized before any retype operations
    let frame_ptr = unsafe {
        (*(&raw const METADATA_STATE))
            .frame_ptr
            .add(cap_slot as usize)
    };
    let frame_ptr = unsafe { (*frame_ptr).as_mut_ptr() };
    unsafe {
        frame_ptr.write(FrameObject::new(phys_addr, actual_bits));
    }
    frame_ptr as *mut crate::cap::object::KernelObject
}

/// Initialize page-table metadata in out-of-band storage and zero the carved
/// 4 KiB page. Mirrors `init_frame_metadata`: the `PageTableObject` header lives
/// in `METADATA_STATE.page_table_ptr[]`, and the carved page (the hardware
/// table) is at `phys_addr`. `install_page_table` re-zeroes on install; zeroing
/// here keeps a freshly-retyped, not-yet-installed table benign.
unsafe fn init_page_table_metadata(
    cap_slot: CapSlot,
    phys_addr: PhysAddr,
) -> *mut crate::cap::object::KernelObject {
    let pt_virt = mm::phys_to_virt(phys_addr) as *mut u8;
    // SAFETY: newly carved RAM page, exclusively owned during retype.
    unsafe {
        core::ptr::write_bytes(pt_virt, 0, crate::mm::PAGE_SIZE);
    }
    // SAFETY: METADATA_STATE is initialized before any retype operations.
    let pt_ptr = unsafe {
        (*(&raw const METADATA_STATE))
            .page_table_ptr
            .add(cap_slot as usize)
    };
    let pt_ptr = unsafe { (*pt_ptr).as_mut_ptr() };
    unsafe {
        pt_ptr.write(PageTableObject::new(phys_addr));
    }
    pt_ptr as *mut crate::cap::object::KernelObject
}

/// Initialize VSpace metadata in dynamically-allocated storage and initialize
/// the provided physical page as a PML4 root.
///
/// The untyped allocation for VSpace is `VSPACE_OBJECT_SIZE` bytes:
///   [0..PAGE_SIZE)  = PML4 page table root
///   [PAGE_SIZE..)   = embedded VSpaceTracking (seL4-style)
unsafe fn init_vspace_metadata(
    cap_slot: CapSlot,
    pml4_phys: PhysAddr,
) -> *mut crate::cap::object::KernelObject {
    let pml4_virt = mm::phys_to_virt(pml4_phys) as *mut u64;
    unsafe {
        core::ptr::write_bytes(pml4_virt as *mut u8, 0, PAGE_SIZE);

        // Copy kernel upper-half entries so the kernel remains mapped after
        // switching into the new VSpace.
        let kernel_cr3 = crate::mm::vspace::kernel_vspace_root();
        let kernel_pml4 = mm::phys_to_virt(kernel_cr3) as *const u64;
        for i in 256..512 {
            pml4_virt.add(i).write(kernel_pml4.add(i).read());
        }

        crate::arch::publish_page_table_page(pml4_phys);

        // Initialize embedded VSpaceTracking at pml4_phys + PAGE_SIZE
        let tracking_ptr = crate::mm::vspace::tracking_from_vspace_phys(pml4_phys);
        core::ptr::write(tracking_ptr, crate::mm::VSpaceTracking::new(pml4_phys));

        // SAFETY: METADATA_STATE is initialized before any retype operations
        let vspace_ptr = (*(&raw const METADATA_STATE))
            .vspace_ptr
            .add(cap_slot as usize);
        let vspace_ptr = (*vspace_ptr).as_mut_ptr();
        vspace_ptr.write(crate::mm::VSpace::new(pml4_phys, tracking_ptr));
        crate::mm::vspace::register_live_vspace(vspace_ptr);
        vspace_ptr as *mut crate::cap::object::KernelObject
    }
}

/// Initialize sub-untyped metadata in dynamically-allocated storage.
///
/// # Safety
/// Caller must ensure `cap_slot` is a valid, exclusively-owned slot index.
unsafe fn init_untyped_metadata(
    cap_slot: CapSlot,
    phys_addr: PhysAddr,
    size_bits: u8,
    is_device: bool,
) -> *mut crate::cap::object::KernelObject {
    // SAFETY: METADATA_STATE is initialized before any retype operations
    let untyped_ptr = unsafe {
        (*(&raw const METADATA_STATE))
            .untyped_ptr
            .add(cap_slot as usize)
    };
    let untyped_ptr = unsafe { (*untyped_ptr).as_mut_ptr() };
    unsafe {
        untyped_ptr.write(UntypedMemory::new(phys_addr, size_bits, is_device));
    }
    untyped_ptr as *mut crate::cap::object::KernelObject
}

impl UntypedMemory {
    /// Retype untyped memory into typed objects
    ///
    /// Allocates objects from the untyped region and creates capabilities.
    /// Objects become children of the untyped in both CDT and ut_next list.
    pub fn retype(
        &mut self,
        untyped_slot: CapSlot,
        new_type: ObjectType,
        size_bits: u8,
        num_objects: usize,
        dest_cnode: &mut crate::cap::cnode::CNode,
        dest_offset: usize,
        create_kind: crate::cap::memory_object::MoKind,
    ) -> Result<(), CapError> {
        // Untyped retype is the resource-creation authority, not an
        // authority-creation one: authority / control object types (the system
        // caps, DeviceControl, IrqHandler, IoPort, ExecAuthority) are minted by
        // the kernel at boot and delegated by cnode_copy, or by DeviceControl —
        // never forgeable from a process's own untyped. This primitive is the
        // single enforcement point; the wire decode stays a pure translation.
        if !new_type.is_retypeable_from_untyped() {
            return Err(CapError::InvalidOperation);
        }

        // Device memory can only be retyped into Frame or Untyped (no zeroing)
        if self.is_device && !matches!(new_type, ObjectType::Frame | ObjectType::Untyped) {
            return Err(CapError::InvalidOperation);
        }

        let obj_size = object_size(new_type, size_bits)?;

        // Validate destination range before probing slot occupancy.
        // Without this, out-of-range indices look "not empty" and are
        // misreported as SlotOccupied.
        let end = dest_offset
            .checked_add(num_objects)
            .ok_or(CapError::InvalidSlot)?;
        if end > dest_cnode.num_slots() {
            return Err(CapError::InvalidSlot);
        }

        // Check destination slots are empty
        for i in 0..num_objects {
            if !dest_cnode.is_slot_empty(dest_offset + i) {
                return Err(CapError::SlotOccupied);
            }
        }

        // Per-type alignment. CNode needs struct alignment (8 bytes for u64
        // guard field), not full slot-array size, since CNodes are never
        // user-mapped. VSpace PML4 must be page-aligned; trailing tracking
        // doesn't need obj_size alignment.
        let align = if obj_size == 0 {
            // Zero-sized objects (IoPort, IrqHandler) don't carve from
            // untyped memory — handled below in the loop without carve_block.
            1
        } else if new_type == ObjectType::CNode {
            core::mem::align_of::<crate::cap::CNode>()
        } else if new_type == ObjectType::VSpace {
            PAGE_SIZE
        } else {
            obj_size
        };

        // Allocate objects. Each iteration consumes one block from the
        // shared multi-class allocator (carve_block handles bucket/
        // freelist/watermark + alloc_lock). Zero-sized object types
        // (IrqHandler, IoPort) skip carve_block. The per-iteration
        // ordering is rollback-friendly: every fallible step runs
        // BEFORE any side-effect that publishes the new object outside
        // this loop (CDT link, `add_child`). On any failure the carved
        // bytes return to the freelist via `release_block` and the
        // capability slot is freed.
        for i in 0..num_objects {
            let obj_addr = if obj_size == 0 {
                0
            } else {
                self.carve_block(obj_size as u64, align)?
            };

            // Allocate capability slot (fallible).
            let cap_slot = match crate::cap::slot::alloc_slot() {
                Some(s) => s,
                None => {
                    if obj_size > 0 {
                        let _ = self.release_block(obj_addr, obj_size as u64);
                    }
                    return Err(CapError::OutOfSlots);
                }
            };

            // Initialize object (fallible only on the `_` arm via
            // `init_object`; other arms are infallible).
            let object = unsafe {
                match new_type {
                    ObjectType::Frame => {
                        init_frame_metadata(cap_slot, obj_addr, size_bits, !self.is_device)
                    }
                    ObjectType::PageTable => init_page_table_metadata(cap_slot, obj_addr),
                    ObjectType::VSpace => init_vspace_metadata(cap_slot, obj_addr),
                    ObjectType::Untyped => {
                        init_untyped_metadata(cap_slot, obj_addr, size_bits, self.is_device)
                    }
                    ObjectType::MemoryObject => {
                        let page_count = if size_bits == 0 {
                            1u32
                        } else {
                            1u32 << (size_bits as u32)
                        };
                        // SAFETY: obj_addr points to a zeroed untyped region of obj_size bytes.
                        let mo_virt = mm::phys_to_virt(obj_addr) as *mut u8;
                        core::ptr::write_bytes(mo_virt, 0, obj_size);
                        let mo_ptr = mo_virt as *mut crate::cap::memory_object::MemoryObject;
                        // SAFETY: Region is zeroed and large enough for MemoryObject + arrays.
                        core::ptr::write(
                            mo_ptr,
                            crate::cap::memory_object::MemoryObject::new(
                                obj_addr,
                                page_count,
                                create_kind,
                            ),
                        );
                        mo_virt as *mut crate::cap::object::KernelObject
                    }
                    _ => match init_object(new_type, obj_addr, size_bits) {
                        Ok(obj) => obj,
                        Err(e) => {
                            free_slot(cap_slot);
                            if obj_size > 0 {
                                let _ = self.release_block(obj_addr, obj_size as u64);
                            }
                            return Err(e);
                        }
                    },
                }
            };

            // Write capability payload into the slot (in-memory only).
            // EXECUTE is never conferred at retype: a process
            // minting frames / MOs from its own untyped gets non-executable
            // memory. EXECUTE enters the system only via mo_mark_executable
            // (gated by the exec-authority cap). cnode_copy masks
            // dst = src & requested, so it cannot be re-added downstream.
            let mut cap = Capability::null();
            cap.object = object;
            cap.obj_type = new_type;
            cap.rights = crate::cap::CapRights::ALL.without(crate::cap::CapRights::EXECUTE);
            cap.depth = 0;
            cap.badge = 0;
            write_capability(cap_slot, cap);

            // Publish into the destination CNode (LAST fallible step).
            // On failure roll back the carved bytes and the slot, then
            // bail before any irreversible side-effect.
            if let Err(e) =
                dest_cnode.insert_ref(dest_offset + i, crate::cap::cnode::CapRef::new(cap_slot))
            {
                crate::cap::slot::nullify_capability(cap_slot);
                free_slot(cap_slot);
                if obj_size > 0 {
                    let _ = self.release_block(obj_addr, obj_size as u64);
                }
                return Err(e);
            }

            // Transition the PMM ownership of every 4 KiB page this
            // carve covers. Child untypeds re-point the back-pointer
            // to the new inner storage; every other target type moves
            // to `KernelPrivate { General }` and is later retagged by
            // whichever subsystem takes ownership (MO commit, kernel
            // stack allocation, page-table install, ...). Device
            // untypeds cover MMIO that was never added to the PMM
            // bitmap — no transition. Infallible.
            if !self.is_device {
                let new_owner = if new_type == ObjectType::Untyped {
                    mm::frame::FrameOwner::UntypedReserved {
                        ut: object as *const UntypedMemory,
                    }
                } else {
                    mm::frame::FrameOwner::KernelPrivate {
                        subkind: mm::frame::KernelMetaKind::General,
                    }
                };
                let page_count = (obj_size + PAGE_SIZE - 1) / PAGE_SIZE;
                for k in 0..page_count {
                    let page_addr = obj_addr + (k * PAGE_SIZE) as u64;
                    mm::pmm_set_owner(page_addr, &new_owner);
                }
            }

            // Cap-level CDT relationship (cap-to-cap, infallible).
            CDT::insert_child(untyped_slot, cap_slot);

            // Object-level membership in this untyped's children list.
            // LAST step — only published after every fallible op above
            // has succeeded. `add_child` takes `alloc_lock` internally.
            unsafe {
                self.add_child(object);
            }
        }

        // Watermark/freelist already advanced per-call in carve_block.
        Ok(())
    }

    /// Untype (free) an object
    ///
    /// Frees an object back to the untyped pool. After CDT revoke and
    /// PMM ownership reclaim, pushes the freed (phys, obj_size) onto
    /// the parent untyped's matching `ClassBucket` freelist via
    /// `release_block`, so subsequent `carve_block` calls can reuse it
    /// without bumping the watermark.
    ///
    /// Only allowed if:
    /// 1. Object has no derived capabilities
    /// 2. Object's refcount is 1 (only this cap references it)
    pub fn untype(&mut self, untyped_slot: CapSlot, cap_slot: CapSlot) -> Result<(), CapError> {
        let cap = get_cap(cap_slot);

        // SAFETY CHECK 1: Object's `parent_ut` must point at THIS
        // `UntypedMemory` instance. Object-level check works even
        // when multiple caps refer to the same parent untyped (via
        // cnode_copy) — both caps see `&self` as the parent. Replaces
        // the old cap-local `meta.ut_parent != untyped_slot` test
        // which only saw the birth cap's slot and missed peers.
        if cap.object.is_null() {
            return Err(CapError::NotAChild);
        }
        let child_obj = cap.object as *mut super::object::KernelObject;
        if unsafe { (*child_obj).parent_ut } != self as *mut UntypedMemory {
            return Err(CapError::NotAChild);
        }
        // `untyped_slot` retained for ABI; gating now uses `parent_ut`.
        let _ = untyped_slot;

        // SAFETY CHECK 2: No derived capabilities (CDT check)
        if CDT::has_children(cap_slot) {
            return Err(CapError::HasDerivedCaps);
        }

        // SAFETY CHECK 3: Refcount must be 1 (only this cap)
        let refcount = unsafe {
            (*cap.object)
                .ref_count
                .load(core::sync::atomic::Ordering::Acquire)
        };
        if refcount != 1 {
            return Err(CapError::ObjectInUse);
        }

        // CDT::revoke -> CDT::delete_capability already calls
        // `release_block` on the parent untyped when refcount drops to 0
        // (see `kernite/src/cap/cdt.rs::CDT::delete_capability`). This
        // explicit `untype` syscall is just the seL4-style "untype
        // exactly this child" entry point; the actual freelist push is
        // the shared CDT path so cnode_revoke / cnode_delete callers
        // get the same effect without going through this function.
        CDT::revoke(cap_slot);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_untyped_size() {
        let untyped = UntypedMemory::new(0x1000, 20, false);
        assert_eq!(untyped.size_bytes(), 1 << 20);
        assert_eq!(untyped.available(), 1 << 20);
    }

    #[test]
    fn test_watermark() {
        let mut untyped = UntypedMemory::new(0x1000, 12, false);
        assert_eq!(untyped.watermark, 0);
        assert_eq!(untyped.available(), 4096);

        untyped.watermark = 2048;
        assert_eq!(untyped.available(), 2048);
    }
}
