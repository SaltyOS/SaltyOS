//! Physical Frame Allocator (Bitmap-based)
//!
//! Manages physical memory frames using a bitmap where 1 bit = 1 frame (4 KiB).
//! FrameNumber is the global physical address index (not base-relative).

#![no_std]

use core::slice;

use spin::Mutex;
use saltyos_ska::{
    BootInfo, BootFlags, ExtraHeader, PhysAddr, MemoryEntry, MemoryType, PAGE_SIZE,
    EXTRA_KIND_MEM_RESERVED,
};

use super::{KERNEL_PHYS_BASE, KERNEL_SIZE, KERNEL_VIRT_BASE, MAX_MANAGED_MEMORY};

/// Maximum number of frames we can manage (4 GiB)
const MAX_MANAGED_FRAMES: u64 = MAX_MANAGED_MEMORY / PAGE_SIZE;

/// Number of u64 words needed for bitmap
const BITMAP_WORDS: usize = (MAX_MANAGED_FRAMES / 64) as usize;

/// Bitmap storage (16,384 u64 = 128 KiB)
static mut BITMAP_STORAGE: [u64; BITMAP_WORDS] = [0; BITMAP_WORDS];

/// Global frame allocator
static FRAME_ALLOC: Mutex<Option<FrameAllocator>> = Mutex::new(None);

/// Frame number = physical_address / PAGE_SIZE (global, not base-relative)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FrameNumber(pub u64);

impl FrameNumber {
    /// Create from physical address
    pub fn from_phys_addr(addr: PhysAddr) -> Self {
        Self(addr.as_u64() / PAGE_SIZE)
    }

    /// Convert to physical address
    pub fn to_phys_addr(self) -> PhysAddr {
        PhysAddr::new(self.0 * PAGE_SIZE)
    }
}

/// A physical frame
#[derive(Clone, Copy, Debug)]
pub struct Frame {
    pub number: FrameNumber,
}

/// Frame statistics
#[derive(Clone, Copy, Debug)]
pub struct FrameStats {
    pub total_ram: u64,
    pub managed_ram: u64,
    pub managed_free: u64,
}

/// Bitmap-based frame allocator
struct FrameAllocator {
    bitmap: &'static mut [u64],
    bitmap_words: usize,
    total_frames: u64,
    managed_frames: u64,
    highest_frame: u64,
}

impl FrameAllocator {
    /// Mark a frame as free (set bit to 1)
    fn mark_free(&mut self, frame: FrameNumber) {
        let word_idx = (frame.0 / 64) as usize;
        let bit_idx = (frame.0 % 64) as u64;
        if word_idx < self.bitmap_words {
            unsafe {
                self.bitmap.get_unchecked_mut(word_idx)
                    .set_bit(bit_idx as usize, true);
            }
        }
    }

    /// Mark a frame as used (set bit to 0)
    fn mark_used(&mut self, frame: FrameNumber) {
        let word_idx = (frame.0 / 64) as usize;
        let bit_idx = (frame.0 % 64) as u64;
        if word_idx < self.bitmap_words {
            unsafe {
                self.bitmap.get_unchecked_mut(word_idx)
                    .set_bit(bit_idx as usize, false);
            }
        }
    }

    /// Check if a frame is free
    fn is_free(&self, frame: FrameNumber) -> bool {
        let word_idx = (frame.0 / 64) as usize;
        let bit_idx = (frame.0 % 64) as u64;
        if word_idx < self.bitmap_words {
            unsafe {
                self.bitmap.get_unchecked(word_idx)
                    .get_bit(bit_idx as usize)
            }
        } else {
            false
        }
    }

    /// Mark a range of frames as used
    fn mark_used_range(&mut self, base: PhysAddr, size: u64) {
        let start_frame = (base.as_u64() / PAGE_SIZE) as u64;
        let end_frame = ((base.as_u64() + size - 1) / PAGE_SIZE) as u64;

        for frame in start_frame..=end_frame {
            if frame < MAX_MANAGED_FRAMES {
                self.mark_used(FrameNumber(frame));
            }
        }
    }

    /// Allocate a single frame
    fn allocate_frame(&mut self) -> Option<Frame> {
        // Search from frame 0 to highest_frame
        for word_idx in 0..=((self.highest_frame / 64) as usize) {
            let word = unsafe { *self.bitmap.get_unchecked(word_idx) };
            if word != 0 {
                // Find first set bit
                let bit_idx = word.trailing_zeros() as u64;
                let frame_num = (word_idx as u64) * 64 + bit_idx;
                if frame_num <= self.highest_frame {
                    self.mark_used(FrameNumber(frame_num));
                    return Some(Frame { number: FrameNumber(frame_num) });
                }
            }
        }
        None
    }

    /// Deallocate a frame
    fn deallocate_frame(&mut self, frame: Frame) {
        if frame.number.0 < MAX_MANAGED_FRAMES {
            self.mark_free(frame.number);
        }
    }

    /// Get statistics
    fn stats(&self) -> FrameStats {
        let free_count: u64 = self.bitmap.iter()
            .take(self.bitmap_words)
            .map(|w| w.count_ones() as u64)
            .sum();

        FrameStats {
            total_ram: self.total_frames * PAGE_SIZE,
            managed_ram: self.managed_frames * PAGE_SIZE,
            managed_free: free_count * PAGE_SIZE,
        }
    }

    fn apply_reserved_extras(&mut self, bootinfo: &BootInfo) {
        let min_extra = core::mem::offset_of!(BootInfo, extra)
            + core::mem::size_of::<PhysAddr>()
            + core::mem::size_of::<u32>();
        if bootinfo.size != 0 && (bootinfo.size as usize) < min_extra {
            return;
        }
        let extra_ptr = bootinfo.extra.as_u64();
        let extra_len = bootinfo.extra_len as u64;
        if extra_ptr == 0 || extra_len < core::mem::size_of::<ExtraHeader>() as u64 {
            return;
        }

        let mut offset = 0u64;
        while offset + core::mem::size_of::<ExtraHeader>() as u64 <= extra_len {
            let hdr = unsafe {
                &*( (extra_ptr + offset) as *const ExtraHeader )
            };
            let entry_len = hdr.len as u64;
            let entry_base = extra_ptr + offset + core::mem::size_of::<ExtraHeader>() as u64;

            if hdr.kind == EXTRA_KIND_MEM_RESERVED {
                if entry_len >= 4 {
                    let count = unsafe { *(entry_base as *const u32) } as u64;
                    let mut cur = entry_base + 4;
                    for _ in 0..count {
                        if cur + 16 > entry_base + entry_len {
                            break;
                        }
                        let base = unsafe { *(cur as *const u64) };
                        let size = unsafe { *((cur + 8) as *const u64) };
                        if size != 0 {
                            self.mark_used_range(PhysAddr::new(base), size);
                        }
                        cur += 16;
                    }
                }
            }

            if entry_len == 0 {
                break;
            }
            offset += core::mem::size_of::<ExtraHeader>() as u64 + entry_len;
        }
    }
}

/// Initialize the physical frame allocator
///
/// # Safety
/// Must be called once during kernel initialization with a valid BootInfo pointer.
pub unsafe fn init(bootinfo: &BootInfo) {
    // Use raw pointer to avoid static_mut_refs lint
    let bitmap_raw = (&raw mut BITMAP_STORAGE) as *mut u64;
    let bitmap = core::slice::from_raw_parts_mut(bitmap_raw, BITMAP_WORDS);
    let bitmap_words = BITMAP_WORDS;

    let mut allocator = FrameAllocator {
        bitmap,
        bitmap_words,
        total_frames: 0,
        managed_frames: 0,
        highest_frame: 0,
    };

    // Step 1: Set ALL bits to 0 (all used initially)
    for word in allocator.bitmap.iter_mut() {
        *word = 0;
    }

    // Step 2: Parse memory map and mark usable frames as free (1)
    let entries = slice::from_raw_parts(
        bootinfo.memory_map.as_u64() as *const MemoryEntry,
        bootinfo.memory_map_entries as usize
    );

    for entry in entries.iter() {
        let entry_frames = entry.length / PAGE_SIZE;
        allocator.total_frames += entry_frames as u64;

        if entry.mem_type == MemoryType::Usable {
            let start_frame = (entry.base.as_u64() / PAGE_SIZE) as u64;
            let end_frame = ((entry.base.as_u64() + entry.length - 1) / PAGE_SIZE) as u64;

            if start_frame < MAX_MANAGED_FRAMES && end_frame >= start_frame {
                let clamped_end = core::cmp::min(end_frame, MAX_MANAGED_FRAMES - 1);
                for frame in start_frame..=clamped_end {
                    allocator.mark_free(FrameNumber(frame));
                    allocator.managed_frames += 1;
                    allocator.highest_frame = allocator.highest_frame.max(frame);
                }
            }
        }
    }

    // BIOS identity map currently covers only the low 4 GiB.
    // Avoid allocating frames above that until the direct map is ready.
    if bootinfo.flags.contains(BootFlags::BIOS) {
        let max_identity_frame = (0x1_0000_0000u64 / PAGE_SIZE) - 1;
        allocator.highest_frame = allocator.highest_frame.min(max_identity_frame);
    }

    // Step 3: Mark reserved regions as used (0)

    // Kernel region
    allocator.mark_used_range(
        PhysAddr::new(KERNEL_PHYS_BASE),
        KERNEL_SIZE,
    );

    // Bitmap storage itself (actual location in kernel image)
    // NOTE: This calculation assumes .bss is within the kernel image at offset
    // (virt - KERNEL_VIRT_BASE) = (phys - KERNEL_PHYS_BASE). The linker script
    // places .bss immediately after .data within the same PT_LOAD segment, so
    // this assumption holds for the current layout.
    let bitmap_virt = bitmap_raw as u64;
    let bitmap_phys = bitmap_virt
        .wrapping_sub(KERNEL_VIRT_BASE)
        .wrapping_add(KERNEL_PHYS_BASE);
    let bitmap_size = (BITMAP_WORDS * core::mem::size_of::<u64>()) as u64;
    allocator.mark_used_range(PhysAddr::new(bitmap_phys), bitmap_size);

    // Bootloader-provided page tables (BIOS uses fixed low memory)
    allocator.mark_used_range(PhysAddr::new(0x1000), 0x17000);

    // BIOS BootInfo + E820 buffers in low memory
    if bootinfo.flags.contains(BootFlags::BIOS) {
        allocator.mark_used_range(PhysAddr::new(0x6000), 0x2000);
        // Avoid allocating from low memory (<2 MiB) in BIOS mode.
        allocator.mark_used_range(PhysAddr::new(0), 0x200000);
    }

    // UEFI bootloader page tables live in 0x10000..0x100000 (bump allocator)
    if bootinfo.flags.contains(BootFlags::UEFI) {
        allocator.mark_used_range(PhysAddr::new(0x10000), 0xF0000);
    }

    // Framebuffer (if present)
    if let Some(fb) = bootinfo.framebuffer {
        let fb_size = fb.pitch as u64 * fb.height as u64;
        allocator.mark_used_range(fb.address, fb_size);
    }

    // Initrd (if present)
    if let Some(initrd) = bootinfo.initrd {
        allocator.mark_used_range(initrd.address, initrd.size);
    }

    // Extra reserved ranges
    allocator.apply_reserved_extras(bootinfo);

    *FRAME_ALLOC.lock() = Some(allocator);
}

/// Allocate a physical frame
pub fn allocate_frame() -> Option<Frame> {
    let mut alloc = FRAME_ALLOC.lock();
    alloc.as_mut()?.allocate_frame()
}

/// Deallocate a physical frame
pub fn deallocate_frame(frame: Frame) {
    let mut alloc = FRAME_ALLOC.lock();
    if let Some(alloc) = alloc.as_mut() {
        alloc.deallocate_frame(frame);
    }
}

/// Get frame allocator statistics
pub fn frame_stats() -> FrameStats {
    let alloc = FRAME_ALLOC.lock();
    alloc.as_ref()
        .map(|a| a.stats())
        .unwrap_or(FrameStats {
            total_ram: 0,
            managed_ram: 0,
            managed_free: 0,
        })
}

// Extension trait for bit manipulation on u64
trait BitExt {
    fn get_bit(&self, idx: usize) -> bool;
    fn set_bit(&mut self, idx: usize, value: bool);
}

impl BitExt for u64 {
    fn get_bit(&self, idx: usize) -> bool {
        (self & (1 << idx)) != 0
    }

    fn set_bit(&mut self, idx: usize, value: bool) {
        if value {
            *self |= 1 << idx;
        } else {
            *self &= !(1 << idx);
        }
    }
}
