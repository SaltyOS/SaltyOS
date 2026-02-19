//! Memory Management
//!
//! Physical frame allocator and virtual address spaces.
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod frame;
pub mod vspace;

pub use frame::FrameAllocator;
pub use vspace::{
    advance_quiescent_gen, current_vspace_tracking, kernel_vspace_root, kernel_vspace_tracking,
    process_deferred_free, restore_irq, save_irq_disable, set_current_vspace_tracking,
    set_pending_deactivate, take_pending_deactivate, DeactivateResult, VSpace, VSpaceTracking,
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
        let mut _spins: u32 = 0;
        while self
            .locked
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) != 0 {
                core::hint::spin_loop();
                _spins += 1;
                #[cfg(debug_assertions)]
                if _spins > 10_000_000 {
                    crate::serial_puts_raw("[SPINLOCK] possible deadlock detected\n");
                    _spins = 0;
                }
            }
        }
    }

    #[inline]
    pub fn unlock(&self) {
        self.locked.store(0, Ordering::Release);
    }
}

/// Subsystem lock: protects scheduler queues, endpoint/notification state,
/// TCB state transitions, sleep queue, VSpace waiter queues.
///
/// Lock ordering (outermost → innermost):
///   CAP_LOCK → SCHED_IPC_LOCK → scheduler.lock_state → VSpace.lock → MM_LOCK (FRAME_LOCK) → SERIAL_LOCK
///
/// Nesting patterns:
///   - Slowpath syscalls: CAP_LOCK (cap lookup) → release → SCHED_IPC_LOCK (IPC)
///   - IPC cap transfer (transfer_message): releases SCHED_IPC_LOCK → CAP_LOCK (slot copy) → releases CAP_LOCK → re-acquires SCHED_IPC_LOCK
///   - Fastpath: CAP_LOCK (cap copy-to-stack) → release → SCHED_IPC_LOCK → scheduler.lock_state
///   - Timer/IPI: SCHED_IPC_LOCK (assembly stub) → scheduler.lock_state
///   - do_context_switch: releases SCHED_IPC_LOCK before switch, reacquires on resume
pub static SCHED_IPC_LOCK: SpinLock = SpinLock::new();

/// Subsystem lock: protects capability slot array, CDT operations, CNode ops,
/// untyped child tracking, and capability lookup.
///
/// Lock ordering: CAP_LOCK → SCHED_IPC_LOCK → scheduler.lock_state → VSpace.lock → MM_LOCK → SERIAL_LOCK
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

/// Allocate a physical frame (SMP-safe)
pub fn alloc_frame() -> Option<PhysAddr> {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe { (*(&raw mut FRAME_ALLOCATOR)).as_mut()?.alloc() };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Allocate contiguous physical frames (SMP-safe)
pub fn alloc_contiguous_frames(count: usize) -> Option<PhysAddr> {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe { (*(&raw mut FRAME_ALLOCATOR)).as_mut()?.alloc_contiguous(count) };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Free a physical frame (SMP-safe)
pub fn free_frame(addr: PhysAddr) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.free(addr);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Retain one mapping reference for a physical page (SMP-safe).
pub fn retain_frame_mapping(addr: PhysAddr) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.retain_mapping_ref(addr);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Release one mapping reference for a physical page (SMP-safe).
pub fn release_frame_mapping(addr: PhysAddr) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.release_mapping_ref(addr);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Retain frame-object ownership references for a frame range (SMP-safe).
pub fn retain_frame_object(addr: PhysAddr, size_bits: u8) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.retain_object_ref(addr, size_bits);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Release frame-object ownership references for a frame range (SMP-safe).
pub fn release_frame_object(addr: PhysAddr, size_bits: u8) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.release_object_ref(addr, size_bits);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Mark a frame as used for page tables — prevents refcount-driven reclamation (SMP-safe).
pub fn mark_frame_pt_owned(addr: PhysAddr) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.mark_pt_owned(addr);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Clear the page-table ownership flag for a frame (SMP-safe).
/// Call this before release_frame_mapping() during VSpace teardown.
pub fn clear_frame_pt_owned(addr: PhysAddr) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.clear_pt_owned(addr);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Mark a frame as allocated for kernel runtime use (SMP-safe).
pub fn mark_frame_kernel_runtime(addr: PhysAddr) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.mark_kernel_runtime(addr);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Clear the kernel-runtime flag for a frame (SMP-safe).
/// Call before release_frame_mapping() for kernel-runtime frames during teardown.
pub fn clear_frame_kernel_runtime(addr: PhysAddr) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(allocator) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            allocator.clear_kernel_runtime(addr);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Free multiple contiguous frames
pub fn free_frames(addr: PhysAddr, size_bytes: usize) {
    let num_frames = (size_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    for i in 0..num_frames {
        free_frame(addr + (i * PAGE_SIZE) as u64);
    }
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

/// Query diagnostic state for a physical frame (SMP-safe).
///
/// Returns `(is_free, map_refs, obj_refs, reclaimable)`.
pub fn query_frame_debug(addr: PhysAddr) -> (bool, u16, u16, u8) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        match (*(&raw const FRAME_ALLOCATOR)).as_ref() {
            Some(a) => a.query_debug(addr),
            None => (true, 0, 0, 0),
        }
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Get the number of free physical frames (SMP-safe)
pub fn free_frame_count() -> usize {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let count = unsafe {
        match (*(&raw mut FRAME_ALLOCATOR)).as_ref() {
            Some(allocator) => allocator.free_count(),
            None => 0,
        }
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    count
}
