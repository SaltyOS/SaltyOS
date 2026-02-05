//! Physical Frame Allocator
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{PhysAddr, PAGE_SIZE};
use crate::bootinfo::{MemoryKind, ParsedBootInfo};

/// Maximum supported physical memory (4GB for now)
const MAX_FRAMES: usize = 1024 * 1024; // 4GB / 4KB

/// Static bitmap storage to avoid stack overflow
/// Size: 128KB (placed in .bss section, not stack)
static mut BITMAP_STORAGE: [u64; MAX_FRAMES / 64] = [0; MAX_FRAMES / 64];

/// Frame allocator using bitmap
pub struct FrameAllocator {
    /// Bitmap of free frames (1 = free, 0 = used)
    bitmap: &'static mut [u64],
    /// First potentially free frame
    next_free: usize,
    /// Total frames
    total: usize,
    /// Free frames count
    free: usize,
}

impl FrameAllocator {
    pub fn new(boot_info: &ParsedBootInfo) -> Self {
        let bitmap = unsafe { &mut *(&raw mut BITMAP_STORAGE) };

        let mut allocator = Self {
            bitmap,
            next_free: 0,
            total: 0,
            free: 0,
        };

        // Mark usable memory regions as free (all others stay as used/0)
        let entries = &boot_info.memory_map[..boot_info.memory_map_len];
        for entry in entries {
            if entry.kind == MemoryKind::Usable {
                allocator.mark_region_free(entry.base, entry.length);
            }
        }

        allocator
    }

    fn mark_region_free(&mut self, base: u64, length: u64) {
        let start_frame = (base as usize) / PAGE_SIZE;
        let end_frame = ((base + length) as usize) / PAGE_SIZE;

        for frame in start_frame..end_frame {
            if frame < MAX_FRAMES {
                let idx = frame / 64;
                let bit = frame % 64;
                // SAFETY: idx < MAX_FRAMES / 64 since frame < MAX_FRAMES
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
        if frame < MAX_FRAMES {
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
}