//! Physical Frame Allocator
//!
//! Dynamically-sized bitmap allocated from the first usable memory region
//! during boot. Supports identity mapping → direct physical map transition.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{PhysAddr, PAGE_SIZE};
use crate::bootinfo::{MemoryKind, ParsedBootInfo};

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
    /// Per-frame mapping refcounts (PTE mappings)
    map_refs: &'static mut [u16],
    /// Per-frame object refcounts (FrameObject ownership)
    obj_refs: &'static mut [u16],
    /// Per-frame reclaimability flag (1 = allocator-owned/reclaimable)
    reclaimable: &'static mut [u8],
    /// Per-frame page-table ownership flag (1 = used as page table, never reclaim)
    pt_owned: &'static mut [u8],
    /// Per-frame kernel-runtime flag (1 = allocated for kernel use, reject untyped exposure)
    kernel_rt: &'static mut [u8],
}

impl FrameAllocator {
    /// Create a new frame allocator from boot info.
    ///
    /// Dynamically allocates the bitmap from the first usable memory region
    /// below 1GB (accessible via bootloader identity mapping). The bitmap
    /// is initially accessed via identity mapping (phys==virt); after
    /// `paging::init()`, call `remap_bitmap()` to switch to the direct
    /// physical map.
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
            // Must be below 1GB for identity map access
            if entry.base >= 0x4000_0000 {
                continue;
            }
            // Skip first 1MB (BIOS/legacy area)
            let region_start = if entry.base < 0x10_0000 {
                0x10_0000u64
            } else {
                entry.base
            };
            let region_end = core::cmp::min(entry.base + entry.length, 0x4000_0000);
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

        // Per-frame arrays start as empty slices; populated in Phase 2
        // SAFETY: Zero-length slices from NonNull::dangling() are valid
        let map_refs: &'static mut [u16] =
            unsafe { core::slice::from_raw_parts_mut(core::ptr::NonNull::dangling().as_ptr(), 0) };
        let obj_refs: &'static mut [u16] =
            unsafe { core::slice::from_raw_parts_mut(core::ptr::NonNull::dangling().as_ptr(), 0) };
        let reclaimable: &'static mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(core::ptr::NonNull::dangling().as_ptr(), 0) };
        let pt_owned: &'static mut [u8] =
            unsafe { core::slice::from_raw_parts_mut(core::ptr::NonNull::dangling().as_ptr(), 0) };
        let kernel_rt: &'static mut [u8] =
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
            map_refs,
            obj_refs,
            reclaimable,
            pt_owned,
            kernel_rt,
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
        frame < self.map_refs.len()
            && frame < self.obj_refs.len()
            && frame < self.reclaimable.len()
            && frame < self.pt_owned.len()
            && frame < self.kernel_rt.len()
    }

    #[inline]
    fn reset_frame_tracking(&mut self, frame: usize, reclaimable: u8) {
        if !self.tracking_ready(frame) {
            return;
        }

        self.map_refs[frame] = 0;
        self.obj_refs[frame] = 0;
        self.reclaimable[frame] = reclaimable;
        self.pt_owned[frame] = 0;
        self.kernel_rt[frame] = 0;
    }

    #[inline]
    fn mark_frame_allocated(&mut self, frame: usize) {
        let idx = frame / 64;
        let bit = frame % 64;
        self.bitmap[idx] &= !(1u64 << bit);
        self.reset_frame_tracking(frame, 1);
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

    pub fn free(&mut self, addr: PhysAddr) {
        let frame = (addr as usize) / PAGE_SIZE;
        if frame < self.total {
            let idx = frame / 64;
            let bit = frame % 64;

            // Guard against double-free: if the bit is already set (frame already
            // free), skip the free. This prevents bitmap corruption when VSpace
            // cleanup incorrectly tries to free untyped-owned pages, or from actual
            // double-free bugs. Frame allocator uses 1=free, 0=used convention.
            if self.bitmap[idx] & (1u64 << bit) != 0 {
                #[cfg(debug_assertions)]
                crate::println!("[FRAME] WARNING: attempted to free already-free frame at {:#x}", addr);
                return;
            }

            self.bitmap[idx] |= 1u64 << bit;
            self.reset_frame_tracking(frame, 0);

            self.free += 1;
            if frame < self.next_free {
                self.next_free = frame;
            }
        }
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
            self.reset_frame_tracking(j, 1);
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

    fn try_release_frame(&mut self, frame: usize) {
        if frame >= self.total {
            return;
        }
        if !self.tracking_ready(frame) {
            return;
        }
        if self.reclaimable[frame] == 0 {
            return;
        }
        // Page-table frames are never reclaimed via refcount — only via explicit
        // VSpace teardown which calls clear_pt_owned() first.
        if self.pt_owned[frame] != 0 {
            return;
        }
        if self.map_refs[frame] != 0 || self.obj_refs[frame] != 0 {
            return;
        }
        let idx = frame / 64;
        let bit = frame % 64;
        if self.bitmap[idx] & (1u64 << bit) == 0 {
            self.bitmap[idx] |= 1u64 << bit;
            self.free += 1;
            self.reclaimable[frame] = 0;
            // Clear kernel-runtime flag when frame is returned to free pool
            self.kernel_rt[frame] = 0;
            if frame < self.next_free {
                self.next_free = frame;
            }
        }
    }

    /// Mark a frame as used for page tables (prevents refcount-driven reclamation).
    pub fn mark_pt_owned(&mut self, addr: PhysAddr) {
        if let Some(frame) = self.frame_index(addr) {
            if frame < self.pt_owned.len() {
                self.pt_owned[frame] = 1;
            }
        }
    }

    /// Clear the page-table ownership flag (called during VSpace teardown before release).
    pub fn clear_pt_owned(&mut self, addr: PhysAddr) {
        if let Some(frame) = self.frame_index(addr) {
            if frame < self.pt_owned.len() {
                self.pt_owned[frame] = 0;
            }
        }
    }

    /// Mark a frame as allocated for kernel runtime use (debug: reject untyped exposure).
    pub fn mark_kernel_runtime(&mut self, addr: PhysAddr) {
        if let Some(frame) = self.frame_index(addr) {
            if frame < self.kernel_rt.len() {
                self.kernel_rt[frame] = 1;
            }
        }
    }

    /// Clear the kernel-runtime flag (called during VSpace teardown alongside clear_pt_owned).
    pub fn clear_kernel_runtime(&mut self, addr: PhysAddr) {
        if let Some(frame) = self.frame_index(addr) {
            if frame < self.kernel_rt.len() {
                self.kernel_rt[frame] = 0;
            }
        }
    }

    pub fn retain_mapping_ref(&mut self, addr: PhysAddr) {
        if let Some(frame) = self.frame_index(addr) {
            if !self.tracking_ready(frame) {
                return;
            }
            if self.reclaimable[frame] == 0 {
                return;
            }
            self.map_refs[frame] = self.map_refs[frame].saturating_add(1);
        }
    }

    pub fn release_mapping_ref(&mut self, addr: PhysAddr) {
        if let Some(frame) = self.frame_index(addr) {
            if !self.tracking_ready(frame) {
                return;
            }
            if self.reclaimable[frame] == 0 {
                return;
            }
            if self.map_refs[frame] == 0 {
                // Underflow: caller released more than it retained.
                #[cfg(debug_assertions)]
                {
                    crate::serial_puts("[FRAME] WARNING: release_mapping_ref underflow at ");
                    crate::serial_hex(addr);
                    crate::serial_puts("\n");
                }
                return;
            }
            self.map_refs[frame] -= 1;
            self.try_release_frame(frame);
        }
    }

    pub fn retain_object_ref(&mut self, addr: PhysAddr, size_bits: u8) {
        let bits = if size_bits < 12 { 12 } else { size_bits };
        let pages = 1usize << (bits as usize - 12);
        let base = (addr as usize) / PAGE_SIZE;
        for i in 0..pages {
            let frame = base + i;
            if frame < self.total && self.tracking_ready(frame) {
                #[cfg(debug_assertions)]
                if self.kernel_rt[frame] != 0 {
                    let frame_addr = (frame * PAGE_SIZE) as PhysAddr;
                    crate::serial_puts("[FRAME] BUG: retain_object_ref on kernel-runtime frame ");
                    crate::serial_hex(frame_addr);
                    crate::serial_puts("\n");
                }
                self.reclaimable[frame] = 1;
                self.obj_refs[frame] = self.obj_refs[frame].saturating_add(1);
            }
        }
    }

    pub fn release_object_ref(&mut self, addr: PhysAddr, size_bits: u8) {
        let bits = if size_bits < 12 { 12 } else { size_bits };
        let pages = 1usize << (bits as usize - 12);
        let base = (addr as usize) / PAGE_SIZE;
        for i in 0..pages {
            let frame = base + i;
            if frame < self.total && self.tracking_ready(frame) {
                if self.obj_refs[frame] == 0 {
                    // Underflow: caller released more than it retained.
                    #[cfg(debug_assertions)]
                    {
                        let frame_addr = (frame * PAGE_SIZE) as PhysAddr;
                        crate::serial_puts("[FRAME] WARNING: release_object_ref underflow at ");
                        crate::serial_hex(frame_addr);
                        crate::serial_puts("\n");
                    }
                    continue;
                }
                self.obj_refs[frame] -= 1;
                self.try_release_frame(frame);
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

        // Allocate per-frame map_refs (u16 per frame)
        let map_ref_bytes = frame_count * core::mem::size_of::<u16>();
        let map_ref_pages = (map_ref_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
        let map_ref_phys = match self.alloc_contiguous(map_ref_pages) {
            Some(addr) => addr,
            None => {
                crate::serial_puts_raw("[FRAME] FATAL: Phase 2 map_refs alloc failed\n");
                loop {
                    crate::arch::halt();
                }
            }
        };
        let map_ref_virt = super::phys_to_virt(map_ref_phys) as *mut u16;
        // SAFETY: Freshly allocated memory via direct map
        unsafe { core::ptr::write_bytes(map_ref_virt, 0, frame_count); }
        self.map_refs = unsafe { core::slice::from_raw_parts_mut(map_ref_virt, frame_count) };

        // Allocate per-frame obj_refs (u16 per frame)
        let obj_ref_bytes = frame_count * core::mem::size_of::<u16>();
        let obj_ref_pages = (obj_ref_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
        let obj_ref_phys = match self.alloc_contiguous(obj_ref_pages) {
            Some(addr) => addr,
            None => {
                crate::serial_puts_raw("[FRAME] FATAL: Phase 2 obj_refs alloc failed\n");
                loop {
                    crate::arch::halt();
                }
            }
        };
        let obj_ref_virt = super::phys_to_virt(obj_ref_phys) as *mut u16;
        // SAFETY: Freshly allocated memory via direct map
        unsafe { core::ptr::write_bytes(obj_ref_virt, 0, frame_count); }
        self.obj_refs = unsafe { core::slice::from_raw_parts_mut(obj_ref_virt, frame_count) };

        // Allocate per-frame reclaimable flags (u8 per frame)
        let reclaimable_bytes = frame_count * core::mem::size_of::<u8>();
        let reclaimable_pages = (reclaimable_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
        let reclaimable_phys = match self.alloc_contiguous(reclaimable_pages) {
            Some(addr) => addr,
            None => {
                crate::serial_puts_raw("[FRAME] FATAL: Phase 2 reclaimable alloc failed\n");
                loop {
                    crate::arch::halt();
                }
            }
        };
        let reclaimable_virt = super::phys_to_virt(reclaimable_phys) as *mut u8;
        // SAFETY: Freshly allocated memory via direct map
        unsafe { core::ptr::write_bytes(reclaimable_virt, 0, frame_count); }
        self.reclaimable = unsafe { core::slice::from_raw_parts_mut(reclaimable_virt, frame_count) };

        // Allocate per-frame pt_owned flags (u8 per frame)
        let pt_owned_bytes = frame_count * core::mem::size_of::<u8>();
        let pt_owned_pages = (pt_owned_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
        let pt_owned_phys = match self.alloc_contiguous(pt_owned_pages) {
            Some(addr) => addr,
            None => {
                crate::serial_puts_raw("[FRAME] FATAL: Phase 2 pt_owned alloc failed\n");
                loop {
                    crate::arch::halt();
                }
            }
        };
        let pt_owned_virt = super::phys_to_virt(pt_owned_phys) as *mut u8;
        // SAFETY: Freshly allocated memory via direct map
        unsafe { core::ptr::write_bytes(pt_owned_virt, 0, frame_count); }
        self.pt_owned = unsafe { core::slice::from_raw_parts_mut(pt_owned_virt, frame_count) };

        // Allocate per-frame kernel_rt flags (u8 per frame)
        let kernel_rt_bytes = frame_count * core::mem::size_of::<u8>();
        let kernel_rt_pages = (kernel_rt_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
        let kernel_rt_phys = match self.alloc_contiguous(kernel_rt_pages) {
            Some(addr) => addr,
            None => {
                crate::serial_puts_raw("[FRAME] FATAL: Phase 2 kernel_rt alloc failed\n");
                loop {
                    crate::arch::halt();
                }
            }
        };
        let kernel_rt_virt = super::phys_to_virt(kernel_rt_phys) as *mut u8;
        // SAFETY: Freshly allocated memory via direct map
        unsafe { core::ptr::write_bytes(kernel_rt_virt, 0, frame_count); }
        self.kernel_rt = unsafe { core::slice::from_raw_parts_mut(kernel_rt_virt, frame_count) };

        let total_pages = map_ref_pages + obj_ref_pages + reclaimable_pages + pt_owned_pages + kernel_rt_pages;
        {
            let s = crate::SerialGuard::acquire();
            s.puts("[FRAME] Phase 2: per-frame arrays allocated (");
            s.dec(frame_count as u64);
            s.puts(" frames, ");
            s.dec(total_pages as u64);
            s.puts(" pages)\n");
        }
    }

    /// Get the maximum physical address tracked by the frame allocator.
    pub fn max_phys(&self) -> u64 {
        self.total as u64 * PAGE_SIZE as u64
    }
}
