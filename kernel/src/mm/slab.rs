//! Slab Allocator for kernel objects
//!
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! # Per-CPU Slab Allocator
//!
//! This allocator uses a per-CPU caching strategy to minimize lock contention:
//! - Each CPU has a local cache of objects for fast allocation
//! - When a CPU's cache is empty, it refills from shared slabs
//! - When a CPU's cache is full, it flushes back to shared slabs
//!
//! ## Synchronization
//!
//! - Per-CPU cache access is lock-free (only accessed by owning CPU)
//! - Shared slab list requires synchronization (interrupts disabled)
//!
//! ## Memory Layout
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SlabAllocator                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Per-CPU Caches (fast path, lock-free)                      │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
//! │  │  CPU 0   │ │  CPU 1   │ │  CPU 2   │ │  CPU N   │      │
//! │  │  cache   │ │  cache   │ │  cache   │ │  cache   │      │
//! │  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Shared Slab List (slow path, synchronized)                 │
//! │  ┌─────────┐ ┌─────────┐ ┌─────────┐                        │
//! │  │  Slab   │→│  Slab   │→│  Slab   │→ ...                   │
//! │  └─────────┘ └─────────┘ └─────────┘                        │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use super::{align_up, alloc_frame, PAGE_SIZE, PHYS_MAP_OFFSET};
use crate::arch::MAX_CPUS;

/// Pointer alignment for free list (8 bytes on x86_64)
const PTR_SIZE: usize = core::mem::size_of::<usize>();

/// Per-CPU batch size for refilling/flushing
/// When refilling, take this many objects from shared slab
/// When flushing, return half the cache to shared slab
const BATCH_SIZE: usize = 32;

/// Maximum objects to keep in per-CPU cache
const PER_CPU_LIMIT: usize = BATCH_SIZE * 2;

/// Slab header at start of each slab page
///
/// Each slab is a 4KB page containing:
/// - SlabHeader metadata
/// - Array of objects
#[repr(C)]
struct SlabHeader {
    /// Next slab in shared list
    next: *mut SlabHeader,
    /// Free list of objects in this slab
    free_list: *mut FreeObject,
    /// Number of objects currently allocated
    used_count: usize,
    /// Total number of objects in this slab
    total_count: usize,
}

/// Free object in slab
///
/// When an object is free, its memory is reused to store the next pointer
#[repr(C)]
struct FreeObject {
    next: *mut FreeObject,
}

/// Per-CPU object cache
///
/// Provides lock-fast allocation for the owning CPU
#[repr(C)]
#[derive(Clone, Copy)]
struct PerCpuCache {
    /// Free list of objects
    free_list: *mut FreeObject,
    /// Number of free objects in cache
    free_count: usize,
}

impl PerCpuCache {
    const fn new() -> Self {
        Self {
            free_list: core::ptr::null_mut(),
            free_count: 0,
        }
    }
}

/// Slab allocator for fixed-size kernel objects
///
/// Uses per-CPU caching for fast allocation and minimal contention
pub struct SlabAllocator {
    /// Object size (aligned)
    obj_size: usize,

    /// Number of objects per slab
    obj_per_slab: usize,

    /// Offset of first object within a slab page
    obj_offset: usize,

    /// Per-CPU caches (indexed by CPU ID)
    per_cpu: [PerCpuCache; MAX_CPUS],

    /// Shared slab list (all slabs with some free objects)
    /// Protected by interrupt disable
    slab_list: *mut SlabHeader,
}

impl SlabAllocator {
    /// Create a new slab allocator for the given object size
    pub const fn new(obj_size: usize) -> Self {
        Self {
            obj_size,
            obj_per_slab: 0, // Calculated during first grow
            obj_offset: 0,   // Calculated during first grow
            per_cpu: [PerCpuCache::new(); MAX_CPUS],
            slab_list: core::ptr::null_mut(),
        }
    }

    /// Allocate an object
    ///
    /// Fast path: allocate from per-CPU cache (lock-free)
    /// Slow path: refill cache from shared slab
    pub fn alloc(&mut self) -> Option<*mut u8> {
        let cpu_id = crate::arch::current_cpu() as usize;

        // Fast path: allocate from per-CPU cache
        let cache = &mut self.per_cpu[cpu_id];
        if cache.free_count > 0 {
            unsafe {
                let obj = cache.free_list;
                cache.free_list = (*obj).next;
                cache.free_count -= 1;
                return Some(obj as *mut u8);
            }
        }

        // Slow path: refill from shared slab
        self.refill_cache(cpu_id)?;

        // Try again from cache
        let cache = &mut self.per_cpu[cpu_id];
        unsafe {
            let obj = cache.free_list;
            cache.free_list = (*obj).next;
            cache.free_count -= 1;
            Some(obj as *mut u8)
        }
    }

    /// Free an object
    ///
    /// Fast path: return to per-CPU cache (lock-free)
    /// Slow path: flush cache to shared slab if full
    pub fn free(&mut self, ptr: *mut u8) {
        let cpu_id = crate::arch::current_cpu() as usize;
        let cache = &mut self.per_cpu[cpu_id];

        unsafe {
            let obj = ptr as *mut FreeObject;

            // Fast path: add to per-CPU cache
            (*obj).next = cache.free_list;
            cache.free_list = obj;
            cache.free_count += 1;

            // Flush if cache is too full
            if cache.free_count > PER_CPU_LIMIT {
                self.flush_cache(cpu_id);
            }
        }
    }

    /// Refill per-CPU cache from shared slab list
    ///
    /// Takes BATCH_SIZE objects from shared slabs and moves them to the per-CPU cache.
    /// Creates new slab if no free objects available.
    fn refill_cache(&mut self, cpu_id: usize) -> Option<()> {
        // Try to get BATCH_SIZE objects from shared slabs
        let mut count = 0;
        let mut head: *mut FreeObject = core::ptr::null_mut();
        let mut tail: *mut FreeObject = core::ptr::null_mut();

        while count < BATCH_SIZE {
            // Find a slab with free objects
            let slab = self.find_free_slab()?;

            unsafe {
                // Take one object from slab
                let obj = (*slab).free_list;
                if obj.is_null() {
                    // Try next slab
                    continue;
                }

                (*slab).free_list = (*obj).next;
                (*slab).used_count += 1;

                // Add to our batch
                if head.is_null() {
                    head = obj;
                } else {
                    (*tail).next = obj;
                }
                tail = obj;
                (*obj).next = core::ptr::null_mut();
                count += 1;

                // If slab is now full, it's no longer useful for refilling
                if (*slab).free_list.is_null() {
                    break;
                }
            }
        }

        // Add batch to per-CPU cache
        let cache = &mut self.per_cpu[cpu_id];
        unsafe {
            (*tail).next = cache.free_list;
            cache.free_list = head;
            cache.free_count += count;
        }

        Some(())
    }

    /// Flush per-CPU cache back to shared slab list
    ///
    /// Returns half of the cached objects to shared slabs.
    /// This frees memory when a CPU stops using objects.
    fn flush_cache(&mut self, cpu_id: usize) {
        // Return half of the cache to shared slabs
        let flush_count = self.per_cpu[cpu_id].free_count / 2;

        unsafe {
            for _ in 0..flush_count {
                let obj = self.per_cpu[cpu_id].free_list;
                if obj.is_null() {
                    break;
                }

                self.per_cpu[cpu_id].free_list = (*obj).next;
                self.per_cpu[cpu_id].free_count -= 1;

                // Find which slab this object belongs to
                self.return_to_slab(obj);
            }
        }
    }

    /// Return an object to its slab
    fn return_to_slab(&mut self, obj: *mut FreeObject) {
        let obj_addr = obj as usize;

        // Find the slab containing this object
        let mut slab = self.slab_list;
        while !slab.is_null() {
            unsafe {
                let slab_start = slab as usize;
                let slab_end = slab_start + PAGE_SIZE;

                if obj_addr >= slab_start && obj_addr < slab_end {
                    // Found the slab, return object to its free list
                    (*obj).next = (*slab).free_list;
                    (*slab).free_list = obj;
                    (*slab).used_count -= 1;
                    return;
                }

                slab = (*slab).next;
            }
        }

        // Object not found in any slab (shouldn't happen)
        // TODO: handle this error case
    }

    /// Find a slab with free objects
    ///
    /// Creates new slab if none exists with free objects.
    fn find_free_slab(&mut self) -> Option<*mut SlabHeader> {
        // Look for slab with free objects
        let mut slab = self.slab_list;
        while !slab.is_null() {
            unsafe {
                if !(*slab).free_list.is_null() && (*slab).used_count < (*slab).total_count {
                    return Some(slab);
                }
                slab = (*slab).next;
            }
        }

        // No slab with free objects, create new one
        self.grow()
    }

    /// Grow the allocator by allocating a new slab
    ///
    /// Allocates a new physical frame and initializes it as a slab.
    fn grow(&mut self) -> Option<*mut SlabHeader> {
        // First time: calculate object layout
        if self.obj_per_slab == 0 {
            let obj_size = align_up(self.obj_size, PTR_SIZE);
            let header_size = align_up(core::mem::size_of::<SlabHeader>(), PTR_SIZE);
            let available = PAGE_SIZE - header_size;
            let count = available / obj_size;

            if count == 0 {
                return None; // Object too large
            }

            // These are const now, but we need mutable self to write them
            // SAFETY: This only happens once during first allocation
            unsafe {
                let ptr = &raw mut self.obj_per_slab;
                ptr.write(count);
                let ptr = &raw mut self.obj_offset;
                ptr.write(header_size);
                let ptr = &raw mut self.obj_size;
                ptr.write(obj_size);
            }
        }

        // Allocate physical frame
        let phys = alloc_frame()?;
        let virt = phys + PHYS_MAP_OFFSET;
        let slab = virt as *mut SlabHeader;

        unsafe {
            // Initialize slab header
            (*slab).next = self.slab_list;
            (*slab).used_count = 0;
            (*slab).total_count = self.obj_per_slab;

            // Build free list
            let slab_start = slab as usize;
            let first_obj = slab_start + self.obj_offset;

            for i in 0..self.obj_per_slab {
                let obj = (first_obj + i * self.obj_size) as *mut FreeObject;
                (*obj).next = if i == self.obj_per_slab - 1 {
                    core::ptr::null_mut()
                } else {
                    (first_obj + (i + 1) * self.obj_size) as *mut FreeObject
                };
            }

            (*slab).free_list = first_obj as *mut FreeObject;
        }

        // Add to front of slab list
        self.slab_list = slab;

        Some(slab)
    }

    /// Get statistics about the allocator
    pub fn stats(&self) -> SlabStats {
        let mut total_slabs = 0;
        let mut total_free = 0;
        let mut total_used = 0;

        let mut slab = self.slab_list;
        while !slab.is_null() {
            unsafe {
                total_slabs += 1;
                total_used += (*slab).used_count;
                let free_count = (*slab).total_count - (*slab).used_count;
                total_free += free_count;
                slab = (*slab).next;
            }
        }

        let mut per_cpu_free = 0;
        for cache in &self.per_cpu {
            per_cpu_free += cache.free_count;
        }

        SlabStats {
            slab_count: total_slabs,
            total_objects: total_used + total_free,
            used_objects: total_used,
            free_in_slabs: total_free,
            free_in_cache: per_cpu_free,
        }
    }
}

/// Slab allocator statistics
#[derive(Debug, Clone, Copy)]
pub struct SlabStats {
    /// Number of slab pages allocated
    pub slab_count: usize,

    /// Total object capacity
    pub total_objects: usize,

    /// Objects currently in use
    pub used_objects: usize,

    /// Free objects in shared slabs
    pub free_in_slabs: usize,

    /// Free objects in per-CPU caches
    pub free_in_cache: usize,
}

impl SlabStats {
    /// Total free objects (slabs + caches)
    pub fn total_free(&self) -> usize {
        self.free_in_slabs + self.free_in_cache
    }

    /// Utilization percentage
    pub fn utilization(&self) -> f64 {
        if self.total_objects == 0 {
            0.0
        } else {
            (self.used_objects as f64 / self.total_objects as f64) * 100.0
        }
    }
}
