//! Memory Management
//!
//! Physical frame allocator and virtual address spaces.
//!
//! SPDX-License-Identifier: GPL-2.0-only

pub mod frame;
pub mod vspace;
pub mod node_alloc;
pub mod radix_tree;
pub mod maple_tree;

pub use frame::FrameAllocator;
pub use vspace::{
    advance_quiescent_gen, current_vspace_tracking, kernel_vspace_root, kernel_vspace_tracking,
    process_deferred_free, restore_irq, save_irq_disable, set_current_vspace_tracking,
    set_online_cpu_count, set_pending_deactivate, take_pending_deactivate, DeactivateResult,
    PageFaultInfo, VSpace, VSpaceTracking,
};

use crate::ParsedBootInfo;
use core::sync::atomic::{AtomicU8, Ordering};

/// Page size (4KB)
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SHIFT: usize = 12;

/// Direct physical mapping offset
/// Physical memory is mapped at this virtual address
pub const PHYS_MAP_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Physical address type
pub type PhysAddr = u64;

/// Virtual address type
pub type VirtAddr = u64;

/// Simple spinlock for SMP-safe access to shared kernel structures.
///
/// Uses test-and-set with TTAS (test-and-test-and-set) optimization.
/// Debug builds include deadlock detection via spin count limit.
pub struct SpinLock {
    locked: AtomicU8,
}

impl SpinLock {
    pub const fn new() -> Self {
        Self {
            locked: AtomicU8::new(0),
        }
    }

    #[inline]
    pub fn lock(&self) {
        // Fast path: uncontended acquire
        if self
            .locked
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }

        // Slow path: bounded exponential backoff to reduce cache-line thrashing
        let mut backoff: u32 = 0;
        #[cfg(debug_assertions)]
        let mut _total_spins: u32 = 0;
        loop {
            // Spin with exponential backoff (cap at 64 PAUSE iterations)
            let spins = 1u32 << backoff.min(6);
            for _ in 0..spins {
                core::hint::spin_loop();
            }
            #[cfg(debug_assertions)]
            {
                _total_spins += spins;
                if _total_spins > 10_000_000 {
                    crate::serial_puts_raw("[SPINLOCK] possible deadlock detected\n");
                    _total_spins = 0;
                }
            }

            // Try acquire after backoff
            if self.locked.load(Ordering::Relaxed) == 0
                && self
                    .locked
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return;
            }

            if backoff < 6 {
                backoff += 1;
            }
        }
    }

    #[inline]
    pub fn unlock(&self) {
        self.locked.store(0, Ordering::Release);
    }
}

/// Subsystem lock: protects capability slot array, CDT operations, CNode ops,
/// untyped child tracking, and capability lookup.
///
/// Lock ordering (outermost → innermost):
///   CAP_LOCK → endpoint.lock / ntfn.lock / tcb.lock / sc.lock → SLEEP_LOCK / FUTEX_LOCK / IRQ_LOCK → sched.lock_cpu → VSpace.lock → ASID_LOCK → FRAME_LOCK → SERIAL_LOCK
///
/// MemoryObject::destroy() runs after refcount reaches 0 (no concurrent
/// accessors). It acquires VSpace.lock per reverse-map entry without
/// holding CAP_LOCK (released before release_object), which is safe
/// because no outer locks are held at that point.
///
/// Subsystem locks (SLEEP_LOCK, FUTEX_LOCK, IRQ_LOCK) are independent of each other
/// and of per-object locks. They protect their own global data structures.
pub static CAP_LOCK: SpinLock = SpinLock::new();

/// Global frame allocator
static mut FRAME_ALLOCATOR: Option<FrameAllocator> = None;

/// Spinlock protecting FRAME_ALLOCATOR for SMP safety (MM_LOCK)
static FRAME_LOCK: SpinLock = SpinLock::new();

/// Initialize memory management from boot info
pub fn init(boot_info: &ParsedBootInfo) {
    // SAFETY: Single-threaded initialization
    unsafe {
        (*(&raw mut FRAME_ALLOCATOR)) = Some(FrameAllocator::new(boot_info));
    }
}

// ---------------------------------------------------------------------------
// PMM public API (SMP-safe)
// ---------------------------------------------------------------------------

/// Allocate a physical frame with mandatory ownership declaration.
pub fn pmm_alloc(owner: &frame::FrameOwner) -> Option<PhysAddr> {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        if let Some(a) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            if let Some(phys) = a.alloc() {
                a.set_owner(phys, owner);
                Some(phys)
            } else {
                None
            }
        } else {
            None
        }
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Allocate contiguous physical frames. Caller must tag each frame via `pmm_set_owner`.
pub fn pmm_alloc_contiguous(count: usize) -> Option<PhysAddr> {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe { (*(&raw mut FRAME_ALLOCATOR)).as_mut()?.alloc_contiguous(count) };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Free a physical frame with ownership verification. Panics on mismatch.
pub fn pmm_free(addr: PhysAddr, expected: &frame::FrameOwner) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(a) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            a.free_owned(addr, expected);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Set/change the owner tag on an already-allocated frame.
/// Used after `pmm_alloc_contiguous` or when re-tagging during COW.
pub fn pmm_set_owner(addr: PhysAddr, owner: &frame::FrameOwner) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(a) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            a.set_owner(addr, owner);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Transfer ownership between non-Free states. Panics on old tag mismatch.
pub fn pmm_transfer(addr: PhysAddr, old: &frame::FrameOwner, new: &frame::FrameOwner) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(a) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            a.transfer(addr, old, new);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Reverse lookup: get owner metadata for a physical address. O(1).
pub fn pmm_lookup(addr: PhysAddr) -> Option<frame::FrameMeta> {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        (*(&raw mut FRAME_ALLOCATOR))
            .as_ref()
            .and_then(|a| a.lookup(addr).copied())
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Increment map_count when a PTE is installed for this phys frame.
pub fn pmm_retain_mapping(addr: PhysAddr) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(a) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            a.retain_mapping_ref(addr);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Decrement map_count when a PTE is removed.
pub fn pmm_release_mapping(addr: PhysAddr) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(a) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            a.release_mapping_ref(addr);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Allocate from the emergency reserve (fault-path only).
/// Allocate from the emergency reserve. Only callable during fault handling.
/// Panics if called outside a fault context (checked via current TCB state).
pub fn pmm_alloc_reserve() -> Option<PhysAddr> {
    // Verify fault context: current thread must be in FaultBlocked or
    // we must be inside an exception handler (IRQs disabled + on kernel stack).
    // In practice, this is called from the COW fast-path inside exception
    // handlers where IRQs are already disabled. The check is that we're
    // not in normal syscall context.
    #[cfg(debug_assertions)]
    {
        let scheduler = unsafe { crate::sched::scheduler::scheduler() };
        let current = scheduler.current();
        if !current.is_null() {
            // If the thread is Running (not in fault handler), this is misuse.
            // Fault handlers set state to FaultBlocked before IPC, but the
            // kernel fast-path runs before that transition. We check that
            // IRQs are disabled as a proxy for "we're in exception context."
            if !vspace::irqs_disabled() {
                panic!("pmm_alloc_reserve called outside fault context");
            }
        }
    }

    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        (*(&raw mut FRAME_ALLOCATOR))
            .as_mut()
            .and_then(|a| a.alloc_reserve())
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Replenish the emergency reserve pool (up to `count` frames).
pub fn pmm_replenish_reserve(count: usize) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(a) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            a.replenish_reserve(count);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Get free frame count.
pub fn pmm_free_count() -> usize {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        (*(&raw mut FRAME_ALLOCATOR))
            .as_ref()
            .map(|a| a.free_count())
            .unwrap_or(0)
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Align value up to alignment boundary
#[inline]
pub const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// Align value down to alignment boundary
#[inline]
pub const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

/// Check if value is aligned to alignment boundary
#[inline]
pub const fn is_aligned(value: usize, align: usize) -> bool {
    value & (align - 1) == 0
}

/// Convert physical address to virtual address (direct mapping)
#[inline]
pub const fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
    phys + PHYS_MAP_OFFSET
}

/// Convert virtual address to physical address (direct mapping)
#[inline]
pub const fn virt_to_phys(virt: VirtAddr) -> PhysAddr {
    virt - PHYS_MAP_OFFSET
}

/// Switch frame bitmap pointer from identity mapping to direct physical map.
///
/// Must be called exactly once, after `paging::init()` establishes the
/// direct physical mapping and before the identity mapping is removed.
pub fn remap_frame_bitmap() {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    // SAFETY: Called once during single-CPU boot, after direct map is valid
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.remap_bitmap();
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    crate::serial_puts("[MM] Frame bitmap remapped to direct physical map\n");
}

/// Initialize per-frame tracking arrays (Phase 2).
/// Must be called after paging::init() and remap_frame_bitmap().
pub fn init_per_frame_arrays() {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    // SAFETY: Called once during single-CPU boot, direct map available
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.init_per_frame_arrays();
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Get the maximum physical address tracked by the frame allocator.
pub fn max_phys() -> u64 {
    // SAFETY: Reading from FRAME_ALLOCATOR; no lock needed for this read-only
    // query during single-threaded boot, but we take the lock for correctness.
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        match (*(&raw const FRAME_ALLOCATOR)).as_ref() {
            Some(allocator) => allocator.max_phys(),
            None => 0,
        }
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

