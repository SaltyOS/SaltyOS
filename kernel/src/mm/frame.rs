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
}

/// Global bitmap state (set once during init, read during remap)
static mut BITMAP_STATE: BitmapState = BitmapState {
    phys_addr: 0,
    word_count: 0,
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

        // Find a usable region below 1GB large enough for the bitmap.
        // Must be below 1GB to be accessible via bootloader identity mapping.
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
            let region_end = entry.base + entry.length;
            // Align start to page boundary
            let aligned_start = (region_start + (PAGE_SIZE as u64) - 1) & !((PAGE_SIZE as u64) - 1);
            let needed = (bitmap_pages * PAGE_SIZE) as u64;
            if aligned_start + needed <= region_end && aligned_start + needed <= 0x4000_0000 {
                bitmap_phys = aligned_start;
                found = true;
                break;
            }
        }

        if !found {
            crate::serial_puts_raw("[FRAME] FATAL: no usable region for bitmap\n");
            loop {
                // SAFETY: hlt is safe
                unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
            }
        }

        // Access via identity mapping (phys == virt during early boot)
        let bitmap_ptr = bitmap_phys as *mut u64;

        // Zero the bitmap
        // SAFETY: bitmap_phys points to usable memory accessible via identity map
        unsafe {
            core::ptr::write_bytes(bitmap_ptr, 0, word_count);
        }

        // SAFETY: Single-threaded init, identity mapping valid
        let bitmap: &'static mut [u64] =
            unsafe { core::slice::from_raw_parts_mut(bitmap_ptr, word_count) };

        // Save state for remap
        // SAFETY: Single-threaded init
        unsafe {
            let state = &mut *(&raw mut BITMAP_STATE);
            state.phys_addr = bitmap_phys;
            state.word_count = word_count;
        }

        let mut allocator = Self {
            bitmap,
            next_free: 0,
            total: 0,
            free: 0,
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
            s.puts("[FRAME] Dynamic bitmap: ");
            s.dec(max_frames as u64);
            s.puts(" frames, ");
            s.dec(bitmap_pages as u64);
            s.puts(" pages at ");
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

    pub fn alloc(&mut self) -> Option<PhysAddr> {
        // Find first free frame starting from next_free
        for i in self.next_free..self.total {
            let idx = i / 64;
            let bit = i % 64;

            let word = self.bitmap[idx];
            if word & (1u64 << bit) != 0 {
                // Found free frame, mark as used
                self.bitmap[idx] &= !(1u64 << bit);

                self.free -= 1;
                self.next_free = i + 1;
                return Some((i * PAGE_SIZE) as PhysAddr);
            }
        }
        None
    }

    pub fn free(&mut self, addr: PhysAddr) {
        let frame = (addr as usize) / PAGE_SIZE;
        if frame < self.total {
            let idx = frame / 64;
            let bit = frame % 64;

            self.bitmap[idx] |= 1u64 << bit;

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

        let mut run_start = self.next_free;
        let mut run_len = 0usize;

        let mut i = self.next_free;
        while i < self.total {
            let idx = i / 64;
            let bit = i % 64;

            if self.bitmap[idx] & (1u64 << bit) != 0 {
                // Frame is free
                if run_len == 0 {
                    run_start = i;
                }
                run_len += 1;
                if run_len == count {
                    // Found a contiguous run, mark all as used
                    for j in run_start..(run_start + count) {
                        let jidx = j / 64;
                        let jbit = j % 64;
                        self.bitmap[jidx] &= !(1u64 << jbit);
                    }
                    self.free -= count;
                    return Some((run_start * PAGE_SIZE) as PhysAddr);
                }
            } else {
                // Frame is used, reset run
                run_len = 0;
            }
            i += 1;
        }

        None
    }

    pub fn free_count(&self) -> usize {
        self.free
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
}
