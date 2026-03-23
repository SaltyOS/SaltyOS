//! Physical Frame Allocator
//!
//! Dynamically-sized bitmap allocated from the first usable memory region
//! during boot. Supports identity mapping → direct physical map transition.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{PhysAddr, PAGE_SIZE};
use crate::bootinfo::{MemoryKind, ParsedBootInfo};

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
}

/// Semantic ownership of a physical frame. Used in PMM APIs for
/// type-safe allocation, deallocation, and transfer.
#[derive(Clone, Copy, Debug)]
pub enum FrameOwner {
    Free,
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
// FrameMeta — packed per-frame storage (16 bytes)
// ---------------------------------------------------------------------------

/// Owner tag discriminant (matches FrameOwner variants).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OwnerTag {
    Free = 0,
    MoData = 1,
    MoMeta = 2,
    KernelPrivate = 3,
    PageCache = 4,
    EmergencyReserve = 5,
}

/// FrameMeta flags (bit field).
pub const FRAME_FLAG_DIRTY: u8 = 1 << 0;
pub const FRAME_FLAG_REFERENCED: u8 = 1 << 1;
pub const FRAME_FLAG_PINNED: u8 = 1 << 2;

/// Packed per-frame metadata. Stored in a contiguous array indexed by
/// frame number. Provides O(1) reverse lookup from phys addr to owner.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FrameMeta {
    pub owner_tag: OwnerTag,
    pub subkind: u8,
    pub map_count: u8,
    pub flags: u8,
    pub page_idx: u32,
    pub owner_ptr: u64,
}

impl FrameMeta {
    pub const EMPTY: Self = Self {
        owner_tag: OwnerTag::Free,
        subkind: 0,
        map_count: 0,
        flags: 0,
        page_idx: 0,
        owner_ptr: 0,
    };

    /// Convert packed storage to semantic FrameOwner.
    pub fn to_owner(&self) -> FrameOwner {
        match self.owner_tag {
            OwnerTag::Free => FrameOwner::Free,
            OwnerTag::MoData => FrameOwner::MoData {
                mo: self.owner_ptr as *mut crate::cap::memory_object::MemoryObject,
                page_idx: self.page_idx,
            },
            OwnerTag::MoMeta => FrameOwner::MoMeta {
                mo: self.owner_ptr as *mut crate::cap::memory_object::MemoryObject,
                subkind: if self.subkind == 1 { MoMetaKind::Rmap } else { MoMetaKind::Radix },
            },
            OwnerTag::KernelPrivate => FrameOwner::KernelPrivate {
                subkind: match self.subkind {
                    0 => KernelMetaKind::PageTable,
                    1 => KernelMetaKind::KernelStack,
                    2 => KernelMetaKind::MapleNode,
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
            }
            FrameOwner::MoData { mo, page_idx } => {
                self.owner_tag = OwnerTag::MoData;
                self.subkind = 0;
                self.page_idx = *page_idx;
                self.owner_ptr = *mo as u64;
            }
            FrameOwner::MoMeta { mo, subkind } => {
                self.owner_tag = OwnerTag::MoMeta;
                self.subkind = *subkind as u8;
                self.page_idx = 0;
                self.owner_ptr = *mo as u64;
            }
            FrameOwner::KernelPrivate { subkind } => {
                self.owner_tag = OwnerTag::KernelPrivate;
                self.subkind = *subkind as u8;
                self.page_idx = 0;
                self.owner_ptr = 0;
            }
            FrameOwner::PageCache => {
                self.owner_tag = OwnerTag::PageCache;
                self.subkind = 0;
                self.page_idx = 0;
                self.owner_ptr = 0;
            }
            FrameOwner::EmergencyReserve => {
                self.owner_tag = OwnerTag::EmergencyReserve;
                self.subkind = 0;
                self.page_idx = 0;
                self.owner_ptr = 0;
            }
        }
        // map_count and flags are NOT reset — they track VSpace state
    }

    /// Check if the current owner matches the expected owner for
    /// panic-on-mismatch verification in free/transfer.
    pub fn matches_owner(&self, expected: &FrameOwner) -> bool {
        match (self.owner_tag, expected) {
            (OwnerTag::Free, FrameOwner::Free) => true,
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
    /// Per-frame metadata (ownership, map_count, flags) — 16 bytes each.
    meta: &'static mut [FrameMeta],
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
                        candidate = (other_end + (PAGE_SIZE as u64) - 1) & !((PAGE_SIZE as u64) - 1);
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
            crate::serial_puts_raw("[FRAME] FATAL: no usable region for bitmap\n");
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

        {
            let s = crate::SerialGuard::acquire();
            s.puts("[FRAME] Phase 1 bitmap: ");
            s.dec(max_frames as u64);
            s.puts(" frames, ");
            s.dec(bitmap_pages as u64);
            s.puts(" bitmap pages at ");
            s.hex(bitmap_phys);
            s.puts(", free=");
            s.dec(allocator.free as u64);
            s.putc(b'\n');
        }

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
        debug_assert!(start_bit <= end_bit);
        debug_assert!(end_bit <= 64);
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
    fn reset_frame_tracking(&mut self, frame: usize) {
        if self.tracking_ready(frame) {
            self.meta[frame] = FrameMeta::EMPTY;
        }
    }

    #[inline]
    fn mark_frame_allocated(&mut self, frame: usize) {
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

            let start_bit = if word_idx == start / 64 { start % 64 } else { 0 };
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

    fn find_contiguous_run_in_range(&self, start: usize, end: usize, count: usize) -> Option<usize> {
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

            let start_bit = if word_idx == start / 64 { start % 64 } else { 0 };
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

    #[inline]
    fn frame_index(&self, addr: PhysAddr) -> Option<usize> {
        let idx = (addr as usize) / PAGE_SIZE;
        if idx < self.total {
            Some(idx)
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // FrameMeta-based ownership API
    // -----------------------------------------------------------------------

    /// Set a frame's owner. Called after bitmap allocation.
    pub fn set_owner(&mut self, addr: PhysAddr, owner: &FrameOwner) {
        if let Some(frame) = self.frame_index(addr) {
            if self.tracking_ready(frame) {
                self.meta[frame].set_owner(owner);
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
                let s = crate::SerialGuard::acquire();
                s.puts("[FRAME] PANIC: free_owned mismatch at ");
                s.hex(addr);
                s.puts(" expected_tag=");
                s.dec(match expected {
                    FrameOwner::Free => 0,
                    FrameOwner::MoData { .. } => 1,
                    FrameOwner::MoMeta { .. } => 2,
                    FrameOwner::KernelPrivate { .. } => 3,
                    FrameOwner::PageCache => 4,
                    FrameOwner::EmergencyReserve => 5,
                });
                s.puts(" actual_tag=");
                s.dec(self.meta[frame].owner_tag as u64);
                s.puts("\n");
                drop(s);
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
                self.meta[frame].set_owner(new);
            }
        }
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

    /// Internal: actually return a frame to the free pool.
    fn free_internal(&mut self, frame: usize) {
        if frame >= self.total {
            return;
        }
        let idx = frame / 64;
        let bit = frame % 64;
        if self.bitmap[idx] & (1u64 << bit) == 0 {
            self.bitmap[idx] |= 1u64 << bit;
            self.free += 1;
            if self.tracking_ready(frame) {
                self.meta[frame] = FrameMeta::EMPTY;
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

        // Allocate unified FrameMeta array (16 bytes per frame)
        let meta_bytes = frame_count * core::mem::size_of::<FrameMeta>();
        let meta_pages = (meta_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
        let meta_phys = match self.alloc_contiguous(meta_pages) {
            Some(addr) => addr,
            None => {
                crate::serial_puts_raw("[FRAME] FATAL: Phase 2 FrameMeta alloc failed\n");
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

        // Replenish emergency reserve after meta array is ready
        self.replenish_reserve(EMERGENCY_RESERVE_SIZE);

        {
            let s = crate::SerialGuard::acquire();
            s.puts("[FRAME] Phase 2: per-frame arrays allocated (");
            s.dec(frame_count as u64);
            s.puts(" frames, ");
            s.dec(meta_pages as u64);
            s.puts(" pages, reserve=");
            s.dec(self.reserve_count as u64);
            s.puts(")\n");
        }
    }

    /// Get the maximum physical address tracked by the frame allocator.
    pub fn max_phys(&self) -> u64 {
        self.total as u64 * PAGE_SIZE as u64
    }
}
