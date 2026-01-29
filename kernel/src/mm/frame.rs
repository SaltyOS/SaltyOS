//! Physical Frame Allocator
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{PhysAddr, PAGE_SIZE};
use crate::{BootInfo, MemoryKind};

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
    pub fn new(boot_info: &BootInfo) -> Self {
        let bitmap = unsafe { &mut *(&raw mut BITMAP_STORAGE) };
        
        // Ensure bitmap is clear (optional if .bss is zeroed, but safe)
        // for val in bitmap.iter_mut() { *val = 0; }

        let mut allocator = Self {
            bitmap,
            next_free: 0,
            total: 0,
            free: 0,
        };

        // Mark all frames as used initially
        // Then mark usable memory as free

        if !boot_info.memory_map.is_null() && boot_info.memory_map_len > 0 {
            let entries = unsafe {
                core::slice::from_raw_parts(boot_info.memory_map, boot_info.memory_map_len)
            };

            for entry in entries {
                if entry.kind == MemoryKind::Usable {
                    allocator.mark_region_free(entry.base, entry.length);
                }
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

    pub fn free_count(&self) -> usize {
        self.free
    }
}