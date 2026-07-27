//! Physical Frame Allocator
//!
//! Dynamically-sized bitmap allocated from the first usable memory region
//! during boot. Supports identity mapping → direct physical map transition.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{PAGE_SIZE, PhysAddr};
use crate::cap::memory_object::MoKind;
use crate::init::bootinfo::{MemoryKind, ParsedBootInfo};

// ---------------------------------------------------------------------------
// FrameOwner — semantic type for PMM ownership tracking
// ---------------------------------------------------------------------------

/// Sub-kind for MO-internal metadata pages.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MoMetaKind {
    Radix = 0,
    Rmap = 1,
}

/// Sub-kind for kernel-private pages.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KernelMetaKind {
    PageTable = 0,
    KernelStack = 1,
    MapleNode = 2,
    General = 3,
    /// Frame donated by userland to a VSpace's COW scratch pool. Kernel
    /// holds the lifetime claim while the entry is live; on consumption
    /// the frame is retagged to `MoData`, and on VSpace teardown any
    /// un-consumed pool entries are `pmm_free`'d back to PMM.
    CowPool = 4,
}

/// Semantic ownership of a physical frame. Used in PMM APIs for
/// type-safe allocation, deallocation, and transfer.
///
/// The `mo` pointer in `MoData` and `MoMeta` variants is safe to store
/// as a raw pointer because kernel objects are never freed — they are
/// carved from untyped memory and the backing memory persists for the
/// system lifetime. Even when a MemoryObject is logically destroyed
/// (last capability deleted), the struct memory is not reclaimed.
///
/// The `ut` pointer in `UntypedReserved` is a back-reference to the
/// root untyped block whose range covers this frame. Kernel objects
/// (untypeds included) are never freed, so the pointer is stable for
/// the system lifetime.
#[derive(Clone, Copy, Debug)]
pub enum FrameOwner {
    Free,
    /// Frame is covered by a live (root) untyped block and carvable
    /// only via `UntypedMemory::retype`. `pmm_alloc` never returns a
    /// frame in this state.
    UntypedReserved {
        ut: *const crate::cap::UntypedMemory,
    },
    /// User-visible data page owned by an MO.
    MoData {
        mo: *mut crate::cap::memory_object::MemoryObject,
        page_idx: u32,
    },
    /// MO-internal metadata page (radix tree node, reverse map overflow).
    MoMeta {
        mo: *mut crate::cap::memory_object::MemoryObject,
        subkind: MoMetaKind,
    },
    /// Kernel-private page (page tables, kernel stacks, Maple tree nodes).
    KernelPrivate {
        subkind: KernelMetaKind,
    },
    /// File-backed page cache entry (future).
    PageCache,
    /// Reserved pool for fault-path metadata allocation.
    EmergencyReserve,
}

// ---------------------------------------------------------------------------
// FrameMeta — packed per-frame storage (32 bytes)
// ---------------------------------------------------------------------------

/// Owner tag discriminant (matches FrameOwner variants).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OwnerTag {
    Free = 0,
    MoData = 1,
    MoMeta = 2,
    KernelPrivate = 3,
    PageCache = 4,
    EmergencyReserve = 5,
    UntypedReserved = 6,
}

/// Number of OwnerTag variants (used as the length of per-tag counter arrays).
pub const OWNER_TAG_COUNT: usize = 7;

/// Number of KernelMetaKind variants.
pub const KMETA_SUBKIND_COUNT: usize = 5;

/// Number of MoMetaKind variants.
pub const MO_META_SUBKIND_COUNT: usize = 2;

/// Number of MoKind variants tracked on MoData frames (via the
/// `FrameMeta.subkind` overload for `OwnerTag::MoData`).
pub const MO_KIND_COUNT: usize = 4;

/// FrameMeta flags (bit field).
pub const FRAME_FLAG_DIRTY: u8 = 1 << 0;
pub const FRAME_FLAG_REFERENCED: u8 = 1 << 1;
pub const FRAME_FLAG_PINNED: u8 = 1 << 2;
pub const FRAME_FLAG_WRITEBACK: u8 = 1 << 3;
pub const FRAME_FLAG_ACTIVE: u8 = 1 << 4;

/// Result of trying to move a dirty file-backed frame into
/// writeback. This is a PMM-internal state transition; the pager
/// syscall maps it to the existing syscall errors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileWritebackBegin {
    Started,
    Clean,
    Busy,
}

/// Packed per-frame metadata. Stored in a contiguous array indexed by
/// frame number. Provides O(1) reverse lookup from phys addr to owner.
///
/// Layout is 32 bytes on 64-bit targets. `map_count` is `u32` so the
/// free-time invariant check in `free_internal` cannot be triggered by
/// legitimate sharing on heavily-threaded workloads.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FrameMeta {
    pub owner_tag: OwnerTag,
    pub subkind: u8,
    pub flags: u8,
    pub _pad0: u8,
    pub map_count: u32,
    pub owner_ptr: u64,
    /// Source untyped for `MoData` frames committed from an untyped cap.
    /// Live owner remains the MO; this records where the frame returns
    /// when the MO page is decommitted, evicted, resized away, or destroyed.
    pub source_ut: u64,
    pub page_idx: u32,
    pub _pad1: u32,
}

const _: () = assert!(core::mem::size_of::<FrameMeta>() == 32);

impl FrameMeta {
    pub const EMPTY: Self = Self {
        owner_tag: OwnerTag::Free,
        subkind: 0,
        flags: 0,
        _pad0: 0,
        map_count: 0,
        owner_ptr: 0,
        source_ut: 0,
        page_idx: 0,
        _pad1: 0,
    };

    /// Convert packed storage to semantic FrameOwner.
    pub fn to_owner(&self) -> FrameOwner {
        match self.owner_tag {
            OwnerTag::Free => FrameOwner::Free,
            OwnerTag::UntypedReserved => FrameOwner::UntypedReserved {
                ut: self.owner_ptr as *const crate::cap::UntypedMemory,
            },
            OwnerTag::MoData => FrameOwner::MoData {
                mo: self.owner_ptr as *mut crate::cap::memory_object::MemoryObject,
                page_idx: self.page_idx,
            },
            OwnerTag::MoMeta => FrameOwner::MoMeta {
                mo: self.owner_ptr as *mut crate::cap::memory_object::MemoryObject,
                subkind: if self.subkind == 1 {
                    MoMetaKind::Rmap
                } else {
                    MoMetaKind::Radix
                },
            },
            OwnerTag::KernelPrivate => FrameOwner::KernelPrivate {
                subkind: match self.subkind {
                    0 => KernelMetaKind::PageTable,
                    1 => KernelMetaKind::KernelStack,
                    2 => KernelMetaKind::MapleNode,
                    4 => KernelMetaKind::CowPool,
                    _ => KernelMetaKind::General,
                },
            },
            OwnerTag::PageCache => FrameOwner::PageCache,
            OwnerTag::EmergencyReserve => FrameOwner::EmergencyReserve,
        }
    }

    /// Set owner from semantic FrameOwner.
    pub fn set_owner(&mut self, owner: &FrameOwner) {
        match owner {
            FrameOwner::Free => {
                self.owner_tag = OwnerTag::Free;
                self.subkind = 0;
                self.page_idx = 0;
                self.owner_ptr = 0;
                self.source_ut = 0;
            }
            FrameOwner::UntypedReserved { ut } => {
                self.owner_tag = OwnerTag::UntypedReserved;
                self.subkind = 0;
                self.page_idx = 0;
                self.owner_ptr = *ut as u64;
                self.source_ut = 0;
            }
            FrameOwner::MoData { mo, page_idx } => {
                self.owner_tag = OwnerTag::MoData;
                // Overload `subkind` with the owning MO's kind so that
                // per-MoKind counters can be maintained without a
                // separate pointer chase at snapshot time. Reading
                // `(*mo).kind` here is safe: kernel objects are never
                // freed, and this is called under FRAME_LOCK while the
                // caller holds a live reference to the MO.
                let kind_byte = if mo.is_null() {
                    0u8
                } else {
                    unsafe { (**mo).kind as u8 }
                };
                self.subkind = kind_byte;
                self.page_idx = *page_idx;
                self.owner_ptr = *mo as u64;
            }
            FrameOwner::MoMeta { mo, subkind } => {
                self.owner_tag = OwnerTag::MoMeta;
                self.subkind = *subkind as u8;
                self.page_idx = 0;
                self.owner_ptr = *mo as u64;
                self.source_ut = 0;
            }
            FrameOwner::KernelPrivate { subkind } => {
                self.owner_tag = OwnerTag::KernelPrivate;
                self.subkind = *subkind as u8;
                self.page_idx = 0;
                self.owner_ptr = 0;
                self.source_ut = 0;
            }
            FrameOwner::PageCache => {
                self.owner_tag = OwnerTag::PageCache;
                self.subkind = 0;
                self.page_idx = 0;
                self.owner_ptr = 0;
                self.source_ut = 0;
            }
            FrameOwner::EmergencyReserve => {
                self.owner_tag = OwnerTag::EmergencyReserve;
                self.subkind = 0;
                self.page_idx = 0;
                self.owner_ptr = 0;
                self.source_ut = 0;
            }
        }
        // map_count and flags are NOT reset — they track VSpace state
    }

    /// Check if the current owner matches the expected owner for
    /// panic-on-mismatch verification in free/transfer.
    pub fn matches_owner(&self, expected: &FrameOwner) -> bool {
        match (self.owner_tag, expected) {
            (OwnerTag::Free, FrameOwner::Free) => true,
            (OwnerTag::UntypedReserved, FrameOwner::UntypedReserved { ut }) => {
                self.owner_ptr == *ut as u64
            }
            (OwnerTag::MoData, FrameOwner::MoData { mo, page_idx }) => {
                self.owner_ptr == *mo as u64 && self.page_idx == *page_idx
            }
            (OwnerTag::MoMeta, FrameOwner::MoMeta { mo, subkind }) => {
                self.owner_ptr == *mo as u64 && self.subkind == *subkind as u8
            }
            (OwnerTag::KernelPrivate, FrameOwner::KernelPrivate { subkind }) => {
                self.subkind == *subkind as u8
            }
            (OwnerTag::PageCache, FrameOwner::PageCache) => true,
            (OwnerTag::EmergencyReserve, FrameOwner::EmergencyReserve) => true,
            _ => false,
        }
    }
}

/// Tracks bitmap physical location for identity→direct map pointer swap.
struct BitmapState {
    /// Physical address of the bitmap allocation
    phys_addr: PhysAddr,
    /// Number of u64 words in the bitmap
    word_count: usize,
    /// Number of tracked frames (array length for refcounts)
    frame_count: usize,
}

/// Global bitmap state (set once during init, read during remap)
static mut BITMAP_STATE: BitmapState = BitmapState {
    phys_addr: 0,
    word_count: 0,
    frame_count: 0,
};

#[cfg(target_arch = "aarch64")]
const EARLY_BITMAP_WINDOW_BASE: u64 = 0x4000_0000;
#[cfg(target_arch = "aarch64")]
const EARLY_BITMAP_WINDOW_LIMIT: u64 = 0x8000_0000;

#[cfg(not(target_arch = "aarch64"))]
const EARLY_BITMAP_WINDOW_BASE: u64 = 0x10_0000;
#[cfg(not(target_arch = "aarch64"))]
const EARLY_BITMAP_WINDOW_LIMIT: u64 = 0x4000_0000;

/// Default emergency reserve size (pages). Used by fault-path
/// NodeAllocator when main pool is nearly exhausted.
const EMERGENCY_RESERVE_SIZE: usize = 32;

/// Frame allocator using bitmap
pub struct FrameAllocator {
    /// Bitmap of free frames (1 = free, 0 = used)
    bitmap: &'static mut [u64],
    /// First potentially free frame
    next_free: usize,
    /// Total frames (highest frame index + 1)
    total: usize,
    /// Free frames count
    free: usize,
    /// Per-frame metadata (ownership, map_count, flags) — 24 bytes each.
    meta: &'static mut [FrameMeta],
    /// Per-OwnerTag population counts. Tracks how many frames currently
    /// carry each tag. Invariant: `sum(by_tag) == total` once per-frame
    /// metadata is populated (Phase 2). Until Phase 2 all counters are
    /// zero and only `free` is authoritative.
    by_tag: [usize; OWNER_TAG_COUNT],
    /// Per-KernelMetaKind sub-counts for frames tagged KernelPrivate.
    /// Invariant: `sum(by_kmeta) == by_tag[KernelPrivate]`.
    by_kmeta: [usize; KMETA_SUBKIND_COUNT],
    /// Per-MoMetaKind sub-counts for frames tagged MoMeta.
    /// Invariant: `sum(by_mo_meta) == by_tag[MoMeta]`.
    by_mo_meta: [usize; MO_META_SUBKIND_COUNT],
    /// Per-MoKind sub-counts for frames tagged MoData. Derived from
    /// the owning MO's `kind` at set_owner time, stashed in
    /// `FrameMeta.subkind`. Invariant: `sum(by_mo_kind) == by_tag[MoData]`.
    by_mo_kind: [usize; MO_KIND_COUNT],
    /// File-backed data frames carrying `FRAME_FLAG_DIRTY`.
    dirty_file_pages: usize,
    /// File-backed data frames carrying `FRAME_FLAG_WRITEBACK`.
    writeback_file_pages: usize,
    /// LRU-eligible pages currently in the active set.
    active_lru_pages: usize,
    /// LRU-eligible pages currently in the inactive set.
    inactive_lru_pages: usize,
    /// Emergency reserve pool: pre-allocated frame PhysAddrs.
    /// Used only by fault-path NodeAllocator when main pool is low.
    reserve: [u64; EMERGENCY_RESERVE_SIZE],
    reserve_count: usize,
}

impl FrameAllocator {
    /// Create a new frame allocator from boot info.
    ///
    /// Dynamically allocates the bitmap from the first usable memory region
    /// inside the early boot identity-mapped window. On x86_64 this is the
    /// traditional low-memory area below 1GB; on aarch64 QEMU virt this is
    /// the guest RAM window starting at 0x4000_0000. The bitmap is initially
    /// accessed via the bootloader's identity mapping; after `paging::init()`,
    /// call `remap_bitmap()` to switch to the direct physical map.
    pub fn new(boot_info: &ParsedBootInfo) -> Self {
        let entries = &boot_info.memory_map[..boot_info.memory_map_len];

        // Find highest usable physical address to determine bitmap size
        let mut max_phys: u64 = 0;
        for entry in entries {
            if entry.kind == MemoryKind::Usable {
                let top = entry.base + entry.length;
                if top > max_phys {
                    max_phys = top;
                }
            }
        }

        let max_frames = (max_phys as usize) / PAGE_SIZE;
        let word_count = (max_frames + 63) / 64;
        let bitmap_bytes = word_count * 8;
        let bitmap_pages = (bitmap_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

        // Phase 1: Place only the bitmap below 1GB (identity-mapped).
        // Per-frame arrays are allocated in Phase 2 after the direct map.
        let mut bitmap_phys: PhysAddr = 0;
        let mut found = false;

        for entry in entries {
            if entry.kind != MemoryKind::Usable {
                continue;
            }
            let region_start = core::cmp::max(entry.base, EARLY_BITMAP_WINDOW_BASE);
            let region_end = core::cmp::min(entry.base + entry.length, EARLY_BITMAP_WINDOW_LIMIT);
            if region_start >= region_end {
                continue;
            }
            let needed = (bitmap_pages * PAGE_SIZE) as u64;

            let mut candidate = (region_start + (PAGE_SIZE as u64) - 1) & !((PAGE_SIZE as u64) - 1);

            loop {
                if candidate + needed > region_end {
                    break;
                }
                let mut advanced = false;
                for other in entries {
                    if other.kind == MemoryKind::Usable {
                        continue;
                    }
                    let other_end = other.base + other.length;
                    if other.base < candidate + needed && other_end > candidate {
                        candidate =
                            (other_end + (PAGE_SIZE as u64) - 1) & !((PAGE_SIZE as u64) - 1);
                        advanced = true;
                        break;
                    }
                }
                if !advanced {
                    bitmap_phys = candidate;
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }

        if !found {
            crate::kernel::printk::serial_puts_raw("[FRAME] FATAL: no usable region for bitmap\n");
            loop {
                crate::arch::halt();
            }
        }

        // Access via identity mapping (phys == virt during early boot)
        let bitmap_ptr = bitmap_phys as *mut u64;

        // Zero the bitmap only (per-frame arrays allocated in Phase 2)
        // SAFETY: bitmap_phys points to usable memory accessible via identity map
        unsafe {
            core::ptr::write_bytes(bitmap_ptr, 0, word_count);
        }

        // SAFETY: Single-threaded init, identity mapping valid
        let bitmap: &'static mut [u64] =
            unsafe { core::slice::from_raw_parts_mut(bitmap_ptr, word_count) };

        // Per-frame meta array starts empty; populated in Phase 2
        // SAFETY: Zero-length slice from NonNull::dangling() is valid
        let meta: &'static mut [FrameMeta] =
            unsafe { core::slice::from_raw_parts_mut(core::ptr::NonNull::dangling().as_ptr(), 0) };

        // Save state for remap
        // SAFETY: Single-threaded init
        unsafe {
            let state = &mut *(&raw mut BITMAP_STATE);
            state.phys_addr = bitmap_phys;
            state.word_count = word_count;
            state.frame_count = max_frames;
        }

        let mut allocator = Self {
            bitmap,
            next_free: 0,
            total: 0,
            free: 0,
            meta,
            by_tag: [0usize; OWNER_TAG_COUNT],
            by_kmeta: [0usize; KMETA_SUBKIND_COUNT],
            by_mo_meta: [0usize; MO_META_SUBKIND_COUNT],
            by_mo_kind: [0usize; MO_KIND_COUNT],
            dirty_file_pages: 0,
            writeback_file_pages: 0,
            active_lru_pages: 0,
            inactive_lru_pages: 0,
            reserve: [0u64; EMERGENCY_RESERVE_SIZE],
            reserve_count: 0,
        };

        // First pass: mark usable memory regions as free
        for entry in entries {
            if entry.kind == MemoryKind::Usable {
                allocator.mark_region_free(entry.base, entry.length);
            }
        }

        // Second pass: carve out reserved/kernel/bootinfo/initrd regions
        // that overlap with usable regions
        for entry in entries {
            if entry.kind != MemoryKind::Usable {
                allocator.mark_region_used(entry.base, entry.length);
            }
        }

        // Mark bitmap pages themselves as used
        allocator.mark_region_used(bitmap_phys, (bitmap_pages * PAGE_SIZE) as u64);

        crate::kernel::printk::kinfo!(|_g| {
            _g.puts("[FRAME] Phase 1 bitmap: ");
            _g.dec(max_frames as u64);
            _g.puts(" frames, ");
            _g.dec(bitmap_pages as u64);
            _g.puts(" bitmap pages at ");
            _g.hex(bitmap_phys);
            _g.puts(", free=");
            _g.dec(allocator.free as u64);
            _g.putc(b'\n');
        });

        allocator
    }

    fn mark_region_used(&mut self, base: u64, length: u64) {
        let start_frame = (base as usize) / PAGE_SIZE;
        let end_frame = ((base + length) as usize + PAGE_SIZE - 1) / PAGE_SIZE;

        for frame in start_frame..end_frame {
            if frame < self.total {
                let idx = frame / 64;
                let bit = frame % 64;
                if self.bitmap[idx] & (1u64 << bit) != 0 {
                    // Frame was free, mark as used
                    self.bitmap[idx] &= !(1u64 << bit);
                    self.free = self.free.saturating_sub(1);
                }
            }
        }
    }

    fn mark_region_free(&mut self, base: u64, length: u64) {
        let start_frame = (base as usize) / PAGE_SIZE;
        let end_frame = ((base + length) as usize) / PAGE_SIZE;

        let word_count = self.bitmap.len();

        for frame in start_frame..end_frame {
            let idx = frame / 64;
            if idx < word_count {
                let bit = frame % 64;
                self.bitmap[idx] |= 1u64 << bit;

                self.free += 1;
                self.total = self.total.max(frame + 1);
            }
        }
    }

    #[inline]
    fn bit_range_mask(start_bit: usize, end_bit: usize) -> u64 {
        crate::kernel::bug::kassert!(start_bit <= end_bit);
        crate::kernel::bug::kassert!(end_bit <= 64);
        if start_bit == end_bit {
            return 0;
        }
        let high = if end_bit == 64 {
            u64::MAX
        } else {
            (1u64 << end_bit) - 1
        };
        let low = if start_bit == 0 {
            0
        } else {
            (1u64 << start_bit) - 1
        };
        high & !low
    }

    #[inline]
    fn tracking_ready(&self, frame: usize) -> bool {
        frame < self.meta.len()
    }

    #[inline]
    fn meta_counts_dirty_file(meta: &FrameMeta) -> bool {
        meta.owner_tag == OwnerTag::MoData
            && meta.subkind == MoKind::FileBacked as u8
            && (meta.flags & FRAME_FLAG_DIRTY) != 0
    }

    #[inline]
    fn meta_counts_writeback_file(meta: &FrameMeta) -> bool {
        meta.owner_tag == OwnerTag::MoData
            && meta.subkind == MoKind::FileBacked as u8
            && (meta.flags & FRAME_FLAG_WRITEBACK) != 0
    }

    #[inline]
    fn meta_counts_lru_eligible(meta: &FrameMeta) -> bool {
        matches!(meta.owner_tag, OwnerTag::MoData | OwnerTag::PageCache)
    }

    #[inline]
    fn meta_counts_active(meta: &FrameMeta) -> bool {
        Self::meta_counts_lru_eligible(meta) && (meta.flags & FRAME_FLAG_ACTIVE) != 0
    }

    #[inline]
    fn meta_counts_inactive(meta: &FrameMeta) -> bool {
        Self::meta_counts_lru_eligible(meta) && (meta.flags & FRAME_FLAG_ACTIVE) == 0
    }

    #[inline]
    fn note_flag_transition(&mut self, frame: usize, old_flags: u8, new_flags: u8) {
        let mut before = self.meta[frame];
        before.flags = old_flags;
        let mut after = before;
        after.flags = new_flags;

        match (
            Self::meta_counts_dirty_file(&before),
            Self::meta_counts_dirty_file(&after),
        ) {
            (true, false) => self.dirty_file_pages = self.dirty_file_pages.saturating_sub(1),
            (false, true) => self.dirty_file_pages += 1,
            _ => {}
        }
        match (
            Self::meta_counts_writeback_file(&before),
            Self::meta_counts_writeback_file(&after),
        ) {
            (true, false) => {
                self.writeback_file_pages = self.writeback_file_pages.saturating_sub(1)
            }
            (false, true) => self.writeback_file_pages += 1,
            _ => {}
        }
        match (
            Self::meta_counts_active(&before),
            Self::meta_counts_active(&after),
        ) {
            (true, false) => self.active_lru_pages = self.active_lru_pages.saturating_sub(1),
            (false, true) => self.active_lru_pages += 1,
            _ => {}
        }
        match (
            Self::meta_counts_inactive(&before),
            Self::meta_counts_inactive(&after),
        ) {
            (true, false) => self.inactive_lru_pages = self.inactive_lru_pages.saturating_sub(1),
            (false, true) => self.inactive_lru_pages += 1,
            _ => {}
        }
    }

    /// Decrement the per-tag / per-subkind counters for `frame`'s
    /// current meta. Caller must ensure `tracking_ready(frame)`.
    #[inline]
    fn dec_tag_counter(&mut self, frame: usize) {
        let tag = self.meta[frame].owner_tag;
        let subkind = self.meta[frame].subkind as usize;
        if Self::meta_counts_dirty_file(&self.meta[frame]) {
            self.dirty_file_pages = self.dirty_file_pages.saturating_sub(1);
        }
        if Self::meta_counts_writeback_file(&self.meta[frame]) {
            self.writeback_file_pages = self.writeback_file_pages.saturating_sub(1);
        }
        if Self::meta_counts_active(&self.meta[frame]) {
            self.active_lru_pages = self.active_lru_pages.saturating_sub(1);
        }
        if Self::meta_counts_inactive(&self.meta[frame]) {
            self.inactive_lru_pages = self.inactive_lru_pages.saturating_sub(1);
        }
        self.by_tag[tag as usize] = self.by_tag[tag as usize].saturating_sub(1);
        match tag {
            OwnerTag::KernelPrivate => {
                let k = subkind.min(KMETA_SUBKIND_COUNT - 1);
                self.by_kmeta[k] = self.by_kmeta[k].saturating_sub(1);
            }
            OwnerTag::MoMeta => {
                let k = subkind.min(MO_META_SUBKIND_COUNT - 1);
                self.by_mo_meta[k] = self.by_mo_meta[k].saturating_sub(1);
            }
            OwnerTag::MoData => {
                let k = subkind.min(MO_KIND_COUNT - 1);
                self.by_mo_kind[k] = self.by_mo_kind[k].saturating_sub(1);
            }
            _ => {}
        }
    }

    /// Increment the per-tag / per-subkind counters to reflect
    /// `frame`'s new meta. Caller must ensure `tracking_ready(frame)`.
    #[inline]
    fn inc_tag_counter(&mut self, frame: usize) {
        let tag = self.meta[frame].owner_tag;
        let subkind = self.meta[frame].subkind as usize;
        self.by_tag[tag as usize] += 1;
        if Self::meta_counts_dirty_file(&self.meta[frame]) {
            self.dirty_file_pages += 1;
        }
        if Self::meta_counts_writeback_file(&self.meta[frame]) {
            self.writeback_file_pages += 1;
        }
        if Self::meta_counts_active(&self.meta[frame]) {
            self.active_lru_pages += 1;
        }
        if Self::meta_counts_inactive(&self.meta[frame]) {
            self.inactive_lru_pages += 1;
        }
        match tag {
            OwnerTag::KernelPrivate => {
                let k = subkind.min(KMETA_SUBKIND_COUNT - 1);
                self.by_kmeta[k] += 1;
            }
            OwnerTag::MoMeta => {
                let k = subkind.min(MO_META_SUBKIND_COUNT - 1);
                self.by_mo_meta[k] += 1;
            }
            OwnerTag::MoData => {
                let k = subkind.min(MO_KIND_COUNT - 1);
                self.by_mo_kind[k] += 1;
            }
            _ => {}
        }
    }

    #[inline]
    fn reset_frame_tracking(&mut self, frame: usize) {
        if self.tracking_ready(frame) {
            self.dec_tag_counter(frame);
            self.meta[frame] = FrameMeta::EMPTY;
            self.inc_tag_counter(frame);
        }
    }

    #[inline]
    fn mark_frame_allocated(&mut self, frame: usize) {
        crate::kernel::bug::kassert!(
            !self.tracking_ready(frame) || self.meta[frame].owner_tag == OwnerTag::Free,
            "PMM invariant violated: free-pool frame is not tagged Free"
        );
        let idx = frame / 64;
        let bit = frame % 64;
        self.bitmap[idx] &= !(1u64 << bit);
        self.reset_frame_tracking(frame);
        self.free -= 1;
        self.next_free = frame + 1;
    }

    fn find_free_frame_in_range(&self, start: usize, end: usize) -> Option<usize> {
        if start >= end {
            return None;
        }
        let mut word_idx = start / 64;
        while word_idx < self.bitmap.len() {
            let word_base = word_idx * 64;
            if word_base >= end {
                break;
            }

            let start_bit = if word_idx == start / 64 {
                start % 64
            } else {
                0
            };
            let end_bit = if word_base + 64 > end {
                end - word_base
            } else {
                64
            };
            let mask = Self::bit_range_mask(start_bit, end_bit);
            let free_bits = self.bitmap[word_idx] & mask;
            if free_bits != 0 {
                let bit = free_bits.trailing_zeros() as usize;
                return Some(word_base + bit);
            }
            word_idx += 1;
        }
        None
    }

    fn find_contiguous_run_in_range(
        &self,
        start: usize,
        end: usize,
        count: usize,
    ) -> Option<usize> {
        if start >= end || count == 0 {
            return None;
        }

        let mut run_start = 0usize;
        let mut run_len = 0usize;
        let mut word_idx = start / 64;

        while word_idx < self.bitmap.len() {
            let word_base = word_idx * 64;
            if word_base >= end {
                break;
            }

            let start_bit = if word_idx == start / 64 {
                start % 64
            } else {
                0
            };
            let end_bit = if word_base + 64 > end {
                end - word_base
            } else {
                64
            };
            let valid_bits = end_bit.saturating_sub(start_bit);
            if valid_bits == 0 {
                word_idx += 1;
                continue;
            }

            let mask = Self::bit_range_mask(start_bit, end_bit);
            let mut bits = (self.bitmap[word_idx] & mask) >> start_bit;
            if bits == 0 {
                run_len = 0;
                word_idx += 1;
                continue;
            }

            let mut pos = 0usize;
            while pos < valid_bits {
                if bits == 0 {
                    run_len = 0;
                    break;
                }

                let zeros = bits.trailing_zeros() as usize;
                if zeros > 0 {
                    run_len = 0;
                    pos += zeros;
                    bits >>= zeros;
                    continue;
                }

                let ones = bits.trailing_ones() as usize;
                let take = core::cmp::min(ones, valid_bits - pos);
                if run_len == 0 {
                    run_start = word_base + start_bit + pos;
                }
                run_len += take;
                if run_len >= count {
                    return Some(run_start);
                }
                pos += take;
                bits >>= take;
            }

            word_idx += 1;
        }

        None
    }

    pub fn alloc(&mut self) -> Option<PhysAddr> {
        let split = self.next_free.min(self.total);

        // First pass: [next_free, total)
        if let Some(frame) = self.find_free_frame_in_range(split, self.total) {
            self.mark_frame_allocated(frame);
            return Some((frame * PAGE_SIZE) as PhysAddr);
        }

        // Second pass (wrap-around): [0, next_free)
        if let Some(frame) = self.find_free_frame_in_range(0, split) {
            self.mark_frame_allocated(frame);
            return Some((frame * PAGE_SIZE) as PhysAddr);
        }

        None
    }

    /// Allocate `count` contiguous physical frames.
    /// Returns the physical address of the first frame, or None if unavailable.
    pub fn alloc_contiguous(&mut self, count: usize) -> Option<PhysAddr> {
        if count == 0 {
            return None;
        }
        if count == 1 {
            return self.alloc();
        }

        let split = self.next_free.min(self.total);
        let run_start = self
            .find_contiguous_run_in_range(split, self.total, count)
            .or_else(|| self.find_contiguous_run_in_range(0, split, count))?;

        // Found a contiguous run, mark all as used
        for j in run_start..(run_start + count) {
            crate::kernel::bug::kassert!(
                !self.tracking_ready(j) || self.meta[j].owner_tag == OwnerTag::Free,
                "PMM invariant violated: contiguous free-pool frame is not tagged Free"
            );
            let jidx = j / 64;
            let jbit = j % 64;
            self.bitmap[jidx] &= !(1u64 << jbit);
            self.reset_frame_tracking(j);
        }
        self.free -= count;
        self.next_free = run_start + count;
        Some((run_start * PAGE_SIZE) as PhysAddr)
    }

    pub fn free_count(&self) -> usize {
        self.free
    }

    /// Total tracked frame count.
    pub fn total_count(&self) -> usize {
        self.total
    }

    /// Frame count carrying the given owner tag.
    pub fn tag_count(&self, tag: OwnerTag) -> usize {
        self.by_tag[tag as usize]
    }

    /// Frame count carrying `OwnerTag::KernelPrivate` with the given subkind.
    pub fn kmeta_count(&self, kind: KernelMetaKind) -> usize {
        self.by_kmeta[kind as usize]
    }

    /// Frame count carrying `OwnerTag::MoMeta` with the given subkind.
    pub fn mo_meta_count(&self, kind: MoMetaKind) -> usize {
        self.by_mo_meta[kind as usize]
    }

    /// Frame count carrying `OwnerTag::MoData` whose owning MO has
    /// the given `MoKind`. Updated on every set_owner / transfer that
    /// moves a frame into or out of the MoData tag.
    pub fn mo_kind_count(&self, kind: crate::cap::memory_object::MoKind) -> usize {
        self.by_mo_kind[kind as usize]
    }

    /// File-backed frames currently marked dirty.
    pub fn dirty_file_count(&self) -> usize {
        self.dirty_file_pages
    }

    /// File-backed frames currently marked writeback.
    pub fn writeback_file_count(&self) -> usize {
        self.writeback_file_pages
    }

    /// LRU-eligible pages currently in the active set.
    pub fn active_lru_count(&self) -> usize {
        self.active_lru_pages
    }

    /// LRU-eligible pages currently in the inactive set.
    pub fn inactive_lru_count(&self) -> usize {
        self.inactive_lru_pages
    }

    #[inline]
    fn frame_index(&self, addr: PhysAddr) -> Option<usize> {
        let idx = (addr as usize) / PAGE_SIZE;
        if idx < self.total { Some(idx) } else { None }
    }

    // -----------------------------------------------------------------------
    // FrameMeta-based ownership API
    // -----------------------------------------------------------------------

    /// Set a frame's owner. Called after bitmap allocation.
    pub fn set_owner(&mut self, addr: PhysAddr, owner: &FrameOwner) {
        if let Some(frame) = self.frame_index(addr) {
            if self.tracking_ready(frame) {
                self.dec_tag_counter(frame);
                self.meta[frame].set_owner(owner);
                self.inc_tag_counter(frame);
            }
        }
    }

    /// Reverse lookup: get the owner metadata for a physical address. O(1).
    pub fn lookup(&self, addr: PhysAddr) -> Option<&FrameMeta> {
        let frame = self.frame_index(addr)?;
        if self.tracking_ready(frame) {
            Some(&self.meta[frame])
        } else {
            None
        }
    }

    /// Free a frame with ownership verification. Panics on tag mismatch.
    pub fn free_owned(&mut self, addr: PhysAddr, expected: &FrameOwner) {
        if let Some(frame) = self.frame_index(addr) {
            if self.tracking_ready(frame) && !self.meta[frame].matches_owner(expected) {
                // Ownership mismatch — likely double-free or use-after-free
                crate::kernel::printk::kerror!(|_g| {
                    _g.puts("[FRAME] PANIC: free_owned mismatch at ");
                    _g.hex(addr);
                    _g.puts(" expected_tag=");
                    _g.dec(match expected {
                        FrameOwner::Free => 0,
                        FrameOwner::MoData { .. } => 1,
                        FrameOwner::MoMeta { .. } => 2,
                        FrameOwner::KernelPrivate { .. } => 3,
                        FrameOwner::PageCache => 4,
                        FrameOwner::EmergencyReserve => 5,
                        FrameOwner::UntypedReserved { .. } => 6,
                    });
                    _g.puts(" actual_tag=");
                    _g.dec(self.meta[frame].owner_tag as u64);
                    _g.puts("\n");
                });
                panic!("PMM free_owned: ownership mismatch");
            }
            self.free_internal(frame);
        }
    }

    /// Transfer ownership between non-Free states. Panics on tag mismatch.
    pub fn transfer(&mut self, addr: PhysAddr, old: &FrameOwner, new: &FrameOwner) {
        if let Some(frame) = self.frame_index(addr) {
            if self.tracking_ready(frame) {
                if !self.meta[frame].matches_owner(old) {
                    panic!("PMM transfer: old owner mismatch");
                }
                self.dec_tag_counter(frame);
                self.meta[frame].set_owner(new);
                self.inc_tag_counter(frame);
            }
        }
    }

    /// Transfer ownership and attach an untyped source pointer to the new
    /// `MoData` owner. Used when `MO_COMMIT` consumes a page from an untyped
    /// source: the live owner becomes the MO, while the source pointer records
    /// where the page returns.
    pub fn transfer_with_source(
        &mut self,
        addr: PhysAddr,
        old: &FrameOwner,
        new: &FrameOwner,
        source_ut: *const crate::cap::UntypedMemory,
    ) {
        if let Some(frame) = self.frame_index(addr) {
            if self.tracking_ready(frame) {
                if !self.meta[frame].matches_owner(old) {
                    panic!("PMM transfer_with_source: old owner mismatch");
                }
                self.dec_tag_counter(frame);
                self.meta[frame].set_owner(new);
                if matches!(new, FrameOwner::MoData { .. }) {
                    self.meta[frame].source_ut = source_ut as u64;
                }
                self.inc_tag_counter(frame);
            }
        }
    }

    /// Source untyped pointer attached to a `MoData` frame, if any.
    pub fn source_untyped(&self, addr: PhysAddr) -> *mut crate::cap::UntypedMemory {
        let Some(frame) = self.frame_index(addr) else {
            return core::ptr::null_mut();
        };
        if !self.tracking_ready(frame) {
            return core::ptr::null_mut();
        }
        self.meta[frame].source_ut as *mut crate::cap::UntypedMemory
    }

    /// Increment map_count when a PTE is installed for this frame.
    pub fn retain_mapping_ref(&mut self, addr: PhysAddr) {
        if let Some(frame) = self.frame_index(addr) {
            if self.tracking_ready(frame) {
                self.meta[frame].map_count = self.meta[frame].map_count.saturating_add(1);
            }
        }
    }

    /// Decrement map_count when a PTE is removed for this frame.
    pub fn release_mapping_ref(&mut self, addr: PhysAddr) {
        if let Some(frame) = self.frame_index(addr) {
            if self.tracking_ready(frame) {
                if self.meta[frame].map_count > 0 {
                    self.meta[frame].map_count -= 1;
                }
            }
        }
    }

    /// Update a tracked frame's flag word and return the previous value.
    pub fn update_flags(&mut self, addr: PhysAddr, set_mask: u8, clear_mask: u8) -> Option<u8> {
        let frame = self.frame_index(addr)?;
        if !self.tracking_ready(frame) {
            return None;
        }
        let old_flags = self.meta[frame].flags;
        let new_flags = (old_flags | set_mask) & !clear_mask;
        if new_flags != old_flags {
            self.note_flag_transition(frame, old_flags, new_flags);
            self.meta[frame].flags = new_flags;
        }
        Some(old_flags)
    }

    /// Start writeback iff this is a dirty file-backed MO data
    /// frame. On success DIRTY is cleared and WRITEBACK is set in
    /// one PMM-lock window; any later writer must re-dirty the page
    /// through a PTE dirty harvest.
    pub fn begin_file_writeback(&mut self, addr: PhysAddr) -> Option<FileWritebackBegin> {
        let frame = self.frame_index(addr)?;
        if !self.tracking_ready(frame) {
            return None;
        }
        let meta = self.meta[frame];
        if meta.owner_tag != OwnerTag::MoData || meta.subkind != MoKind::FileBacked as u8 {
            return None;
        }

        let old_flags = meta.flags;
        if old_flags & FRAME_FLAG_WRITEBACK != 0 {
            return Some(FileWritebackBegin::Busy);
        }
        if old_flags & FRAME_FLAG_DIRTY == 0 {
            return Some(FileWritebackBegin::Clean);
        }

        let new_flags = (old_flags | FRAME_FLAG_WRITEBACK) & !FRAME_FLAG_DIRTY;
        if new_flags != old_flags {
            self.note_flag_transition(frame, old_flags, new_flags);
            self.meta[frame].flags = new_flags;
        }
        Some(FileWritebackBegin::Started)
    }

    /// Finish a file-backed writeback and return the new flag word.
    /// Success clears WRITEBACK and leaves DIRTY set only if the page
    /// was re-dirtied while writeback was in flight. Failure clears
    /// WRITEBACK and forces DIRTY so the next sweep retries.
    pub fn finish_file_writeback(&mut self, addr: PhysAddr, ok: bool) -> Option<u8> {
        let frame = self.frame_index(addr)?;
        if !self.tracking_ready(frame) {
            return None;
        }
        let meta = self.meta[frame];
        if meta.owner_tag != OwnerTag::MoData || meta.subkind != MoKind::FileBacked as u8 {
            return None;
        }

        let old_flags = meta.flags;
        let new_flags = if ok {
            old_flags & !FRAME_FLAG_WRITEBACK
        } else {
            (old_flags | FRAME_FLAG_DIRTY) & !FRAME_FLAG_WRITEBACK
        };
        if new_flags != old_flags {
            self.note_flag_transition(frame, old_flags, new_flags);
            self.meta[frame].flags = new_flags;
        }
        Some(new_flags)
    }

    /// Age the active/inactive state by one epoch.
    ///
    /// Pages referenced since the last epoch stay/become active. Unreferenced
    /// pages demote to inactive. The referenced latch is then cleared.
    pub fn age_activity_epoch(&mut self) -> (usize, usize) {
        for frame in 0..self.meta.len() {
            if !self.tracking_ready(frame) {
                continue;
            }

            let meta = self.meta[frame];
            let mut new_flags = meta.flags & !FRAME_FLAG_REFERENCED;

            if Self::meta_counts_lru_eligible(&meta) {
                if meta.flags & FRAME_FLAG_REFERENCED != 0 {
                    new_flags |= FRAME_FLAG_ACTIVE;
                } else {
                    new_flags &= !FRAME_FLAG_ACTIVE;
                }
            } else {
                new_flags &= !FRAME_FLAG_ACTIVE;
            }

            if new_flags != meta.flags {
                self.note_flag_transition(frame, meta.flags, new_flags);
                self.meta[frame].flags = new_flags;
            }
        }

        (self.active_lru_pages, self.inactive_lru_pages)
    }

    /// Internal: actually return a frame to the free pool.
    ///
    /// Enforces the PMM-local safety invariant *"no present mapping points
    /// at a freed frame"* by refusing to return a frame whose `map_count`
    /// is non-zero. A violation indicates that a caller freed a frame
    /// without first draining every PTE that referenced it (missing
    /// `pmm_release_mapping`, stale reverse-map entry, etc.) — i.e. a
    /// latent use-after-free. Panic loudly with a diagnostic rather than
    /// silently return the frame to the pool.
    fn free_internal(&mut self, frame: usize) {
        if frame >= self.total {
            return;
        }
        if self.tracking_ready(frame) && self.meta[frame].map_count != 0 {
            let addr = (frame * PAGE_SIZE) as PhysAddr;
            let mc = self.meta[frame].map_count;
            let tag = self.meta[frame].owner_tag as u8;
            crate::kernel::printk::kerror!(|_g| {
                _g.puts("[FRAME] PANIC: free with non-zero map_count at ");
                _g.hex(addr);
                _g.puts(" frame=");
                _g.dec(frame as u64);
                _g.puts(" map_count=");
                _g.dec(mc as u64);
                _g.puts(" tag=");
                _g.dec(tag as u64);
                _g.puts("\n");
            });
            panic!("PMM free_internal: non-zero map_count");
        }
        let idx = frame / 64;
        let bit = frame % 64;
        if self.bitmap[idx] & (1u64 << bit) == 0 {
            self.bitmap[idx] |= 1u64 << bit;
            self.free += 1;
            if self.tracking_ready(frame) {
                self.dec_tag_counter(frame);
                self.meta[frame] = FrameMeta::EMPTY;
                self.inc_tag_counter(frame);
            }
            if frame < self.next_free {
                self.next_free = frame;
            }
        }
    }

    /// Switch bitmap pointer from identity mapping to direct physical map.
    ///
    /// Called after `paging::init()` creates the direct physical mapping.
    /// After this, the identity mapping (PML4[0]) can be safely removed.
    ///
    /// # Safety
    /// Must be called exactly once, after direct physical map is established.
    pub unsafe fn remap_bitmap(&mut self) {
        // SAFETY: BITMAP_STATE was set during new(), single-threaded context
        let state = unsafe { &*(&raw const BITMAP_STATE) };
        let new_virt = super::phys_to_virt(state.phys_addr) as *mut u64;
        // SAFETY: The direct physical map covers the bitmap's physical address.
        // The underlying memory is the same; we're just changing the pointer.
        self.bitmap = unsafe { core::slice::from_raw_parts_mut(new_virt, state.word_count) };
    }

    // -----------------------------------------------------------------------
    // Emergency reserve pool
    // -----------------------------------------------------------------------

    /// Allocate from the emergency reserve. Only for fault-path
    /// NodeAllocator when the main pool is critically low.
    pub fn alloc_reserve(&mut self) -> Option<PhysAddr> {
        if self.reserve_count == 0 {
            return None;
        }
        self.reserve_count -= 1;
        let phys = self.reserve[self.reserve_count];
        self.reserve[self.reserve_count] = 0;
        Some(phys)
    }

    /// Replenish the reserve pool from the main free pool.
    /// Called during idle or after mmsrv handles OOM.
    pub fn replenish_reserve(&mut self, count: usize) {
        let target = core::cmp::min(self.reserve_count + count, EMERGENCY_RESERVE_SIZE);
        while self.reserve_count < target {
            if let Some(phys) = self.alloc() {
                self.set_owner(phys, &FrameOwner::EmergencyReserve);
                self.reserve[self.reserve_count] = phys;
                self.reserve_count += 1;
            } else {
                break;
            }
        }
    }

    /// Current reserve level.
    pub fn reserve_level(&self) -> usize {
        self.reserve_count
    }

    /// Phase 2: Allocate per-frame tracking arrays after direct map is established.
    ///
    /// # Safety
    /// Must be called exactly once, after `paging::init()` and `remap_bitmap()`.
    pub unsafe fn init_per_frame_arrays(&mut self) {
        // SAFETY: BITMAP_STATE set during new(), single-threaded boot
        let frame_count = unsafe { (*(&raw const BITMAP_STATE)).frame_count };
        if frame_count == 0 {
            return;
        }

        // Allocate unified FrameMeta array.
        let meta_bytes = frame_count * core::mem::size_of::<FrameMeta>();
        let meta_pages = (meta_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
        let meta_phys = match self.alloc_contiguous(meta_pages) {
            Some(addr) => addr,
            None => {
                crate::kernel::printk::serial_puts_raw(
                    "[FRAME] FATAL: Phase 2 FrameMeta alloc failed\n",
                );
                loop {
                    crate::arch::halt();
                }
            }
        };
        let meta_virt = super::phys_to_virt(meta_phys) as *mut FrameMeta;
        // SAFETY: Freshly allocated contiguous memory via direct map
        unsafe {
            core::ptr::write_bytes(meta_virt, 0, frame_count);
        }
        self.meta = unsafe { core::slice::from_raw_parts_mut(meta_virt, frame_count) };

        // Populate per-tag counters from the current bitmap. Frames with
        // bit set (in free pool) count as `Free`; frames with bit clear
        // (kernel image, bootloader reservations, bitmap/meta pages just
        // carved) are tagged `KernelPrivate { General }`.
        self.by_tag = [0usize; OWNER_TAG_COUNT];
        self.by_kmeta = [0usize; KMETA_SUBKIND_COUNT];
        self.by_mo_meta = [0usize; MO_META_SUBKIND_COUNT];
        for frame in 0..self.total {
            let idx = frame / 64;
            let bit = frame % 64;
            if self.bitmap[idx] & (1u64 << bit) != 0 {
                self.by_tag[OwnerTag::Free as usize] += 1;
            } else {
                self.meta[frame].owner_tag = OwnerTag::KernelPrivate;
                self.meta[frame].subkind = KernelMetaKind::General as u8;
                self.meta[frame].page_idx = 0;
                self.meta[frame].owner_ptr = 0;
                self.by_tag[OwnerTag::KernelPrivate as usize] += 1;
                self.by_kmeta[KernelMetaKind::General as usize] += 1;
            }
        }

        // Replenish emergency reserve after meta array is ready
        self.replenish_reserve(EMERGENCY_RESERVE_SIZE);

        crate::kernel::printk::kinfo!(|_g| {
            _g.puts("[FRAME] Phase 2: per-frame arrays allocated (");
            _g.dec(frame_count as u64);
            _g.puts(" frames, ");
            _g.dec(meta_pages as u64);
            _g.puts(" pages, reserve=");
            _g.dec(self.reserve_count as u64);
            _g.puts(")\n");
        });
    }

    /// Get the maximum physical address tracked by the frame allocator.
    pub fn max_phys(&self) -> u64 {
        self.total as u64 * PAGE_SIZE as u64
    }
}
