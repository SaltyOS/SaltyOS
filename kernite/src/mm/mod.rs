// SPDX-License-Identifier: GPL-2.0-only
//! Memory Management
//!
//! Physical frame allocator and virtual address spaces.

pub mod accounting;
pub mod frame;
pub mod maple_tree;
pub mod node_alloc;
pub mod radix_tree;
pub mod vspace;

pub use frame::FrameAllocator;
pub use vspace::{
    DeactivateResult, PageFaultInfo, VSpace, VSpaceTracking, advance_quiescent_gen,
    process_deferred_free, restore_irq, save_irq_disable, set_online_cpu_count,
    take_pending_deactivate,
};
#[cfg(target_arch = "x86_64")]
pub use vspace::{
    current_vspace_tracking, kernel_vspace_root, kernel_vspace_tracking,
    set_current_vspace_tracking, set_pending_deactivate,
};

use crate::init::bootinfo::ParsedBootInfo;
use core::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};

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
    /// Address of the `core::panic::Location` of the last successful `lock()`,
    /// captured via `#[track_caller]`. Printed by the hard-timeout dump so a
    /// hang names the holder's call site as well as the spinning site.
    acquired_loc: AtomicUsize,
    owner_cpu: AtomicUsize,
    owner_tid: AtomicU64,
    acquired_ns: AtomicU64,
    last_contender_cpu: AtomicUsize,
    last_contender_tid: AtomicU64,
    contender_since_ns: AtomicU64,
}

impl SpinLock {
    pub const fn new() -> Self {
        Self {
            locked: AtomicU8::new(0),
            acquired_loc: AtomicUsize::new(0),
            owner_cpu: AtomicUsize::new(usize::MAX),
            owner_tid: AtomicU64::new(u64::MAX),
            acquired_ns: AtomicU64::new(0),
            last_contender_cpu: AtomicUsize::new(usize::MAX),
            last_contender_tid: AtomicU64::new(u64::MAX),
            contender_since_ns: AtomicU64::new(0),
        }
    }

    #[inline]
    #[track_caller]
    pub fn lock(&self) {
        let loc = core::panic::Location::caller();
        if self
            .locked
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.set_acquired(loc);
            return;
        }
        self.lock_contended(loc);
    }

    #[inline]
    fn set_acquired(&self, loc: &'static core::panic::Location<'static>) {
        let cpu = crate::arch::diagnostic_current_cpu();
        let tid = current_tid();
        let now = crate::arch::now_ns();
        self.acquired_loc
            .store(loc as *const _ as usize, Ordering::Relaxed);
        let lock_addr = self as *const _ as usize;
        self.owner_cpu.store(cpu, Ordering::Release);
        self.owner_tid.store(tid, Ordering::Release);
        self.acquired_ns.store(now, Ordering::Release);
        self.last_contender_cpu.store(usize::MAX, Ordering::Release);
        self.last_contender_tid.store(u64::MAX, Ordering::Release);
        self.contender_since_ns.store(0, Ordering::Release);
        push_held_lock(lock_addr, loc as *const _ as usize, now, cpu, tid);
    }

    #[inline(never)]
    #[cold]
    fn lock_contended(&self, loc: &'static core::panic::Location<'static>) {
        let mut backoff: u32 = 0;
        let mut total_spins: u64 = 0;
        let contender_since = crate::arch::now_ns();
        let lock_addr = self as *const _ as usize;
        self.last_contender_cpu
            .store(crate::arch::diagnostic_current_cpu(), Ordering::Release);
        self.last_contender_tid
            .store(current_tid(), Ordering::Release);
        self.contender_since_ns
            .store(contender_since, Ordering::Release);
        loop {
            let spins = 1u32 << backoff.min(6);
            for _ in 0..spins {
                core::hint::spin_loop();
            }
            total_spins = total_spins.saturating_add(spins as u64);
            if total_spins > SPINLOCK_HARD_TIMEOUT_SPINS {
                spinlock_hard_timeout_panic(
                    "SpinLock",
                    lock_addr,
                    loc,
                    self.acquired_loc.load(Ordering::Relaxed),
                    self.owner_cpu.load(Ordering::Acquire) as u64,
                    self.owner_tid.load(Ordering::Acquire),
                    crate::arch::now_ns().saturating_sub(contender_since),
                );
            }

            if self.locked.load(Ordering::Relaxed) == 0
                && self
                    .locked
                    .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                self.set_acquired(loc);
                return;
            }

            if backoff < 6 {
                backoff += 1;
            }
        }
    }

    #[inline]
    pub fn unlock(&self) {
        let lock_addr = self as *const _ as usize;
        remove_held_lock(lock_addr);
        self.owner_cpu.store(usize::MAX, Ordering::Release);
        self.owner_tid.store(u64::MAX, Ordering::Release);
        self.acquired_ns.store(0, Ordering::Release);
        self.last_contender_cpu.store(usize::MAX, Ordering::Release);
        self.last_contender_tid.store(u64::MAX, Ordering::Release);
        self.contender_since_ns.store(0, Ordering::Release);
        self.locked.store(0, Ordering::Release);
    }
}

const HELD_LOCK_CAP: usize = 16;

struct HeldLockSlot {
    lock_addr: AtomicUsize,
    loc_addr: AtomicUsize,
    acquired_ns: AtomicU64,
    owner_cpu: AtomicUsize,
    owner_tid: AtomicU64,
}

impl HeldLockSlot {
    const fn new() -> Self {
        Self {
            lock_addr: AtomicUsize::new(0),
            loc_addr: AtomicUsize::new(0),
            acquired_ns: AtomicU64::new(0),
            owner_cpu: AtomicUsize::new(usize::MAX),
            owner_tid: AtomicU64::new(u64::MAX),
        }
    }
}

struct HeldLockCpuStack {
    slots: [HeldLockSlot; HELD_LOCK_CAP],
    overflow: AtomicU64,
}

impl HeldLockCpuStack {
    const fn new() -> Self {
        Self {
            slots: [const { HeldLockSlot::new() }; HELD_LOCK_CAP],
            overflow: AtomicU64::new(0),
        }
    }
}

static HELD_LOCKS: [HeldLockCpuStack; crate::arch::MAX_CPUS] =
    [const { HeldLockCpuStack::new() }; crate::arch::MAX_CPUS];

fn current_tid() -> u64 {
    if !crate::arch::per_cpu_ready() {
        return u64::MAX;
    }
    let current = crate::sched::scheduler::scheduler().current();
    if current.is_null() {
        u64::MAX
    } else {
        unsafe { (*current).trace_id() }
    }
}

fn push_held_lock(lock_addr: usize, loc_addr: usize, acquired_ns: u64, owner_cpu: usize, tid: u64) {
    let cpu = owner_cpu.min(crate::arch::MAX_CPUS - 1);
    let stack = &HELD_LOCKS[cpu];
    for slot in &stack.slots {
        if slot
            .lock_addr
            .compare_exchange(0, lock_addr, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            slot.loc_addr.store(loc_addr, Ordering::Release);
            slot.acquired_ns.store(acquired_ns, Ordering::Release);
            slot.owner_cpu.store(owner_cpu, Ordering::Release);
            slot.owner_tid.store(tid, Ordering::Release);
            return;
        }
    }
    stack.overflow.fetch_add(1, Ordering::AcqRel);
}

fn remove_held_lock(lock_addr: usize) {
    let cpu = crate::arch::diagnostic_current_cpu().min(crate::arch::MAX_CPUS - 1);
    let stack = &HELD_LOCKS[cpu];
    for slot in &stack.slots {
        if slot.lock_addr.load(Ordering::Acquire) == lock_addr {
            slot.owner_tid.store(u64::MAX, Ordering::Release);
            slot.owner_cpu.store(usize::MAX, Ordering::Release);
            slot.acquired_ns.store(0, Ordering::Release);
            slot.loc_addr.store(0, Ordering::Release);
            slot.lock_addr.store(0, Ordering::Release);
            return;
        }
    }
}

pub(crate) fn print_lock_diagnostics() {
    use crate::kernel::printk::{serial_dec_raw, serial_hex_raw, serial_putc_hw, serial_puts_raw};

    serial_puts_raw("-- lock diagnostics ----------------------------------------\n");
    let now = crate::arch::now_ns();
    let mut any = false;
    let mut cpu = 0usize;
    while cpu < crate::arch::MAX_CPUS {
        let stack = &HELD_LOCKS[cpu];
        for slot in &stack.slots {
            let lock_addr = slot.lock_addr.load(Ordering::Acquire);
            if lock_addr == 0 {
                continue;
            }
            any = true;
            let loc_addr = slot.loc_addr.load(Ordering::Acquire);
            let acquired_ns = slot.acquired_ns.load(Ordering::Acquire);
            serial_puts_raw("held_lock: addr=");
            serial_hex_raw(lock_addr as u64);
            serial_puts_raw(" symbol=");
            crate::kernel::kallsyms::print_symbol(lock_addr, false);
            serial_puts_raw(" class=SpinLock owner_cpu=");
            serial_dec_raw(slot.owner_cpu.load(Ordering::Acquire) as u64);
            serial_puts_raw(" owner_tid=");
            let tid = slot.owner_tid.load(Ordering::Acquire);
            if tid == u64::MAX {
                serial_puts_raw("<none>");
            } else {
                serial_dec_raw(tid);
            }
            serial_puts_raw(" held_ns=");
            serial_dec_raw(now.saturating_sub(acquired_ns));
            if loc_addr != 0 {
                // SAFETY: loc_addr is captured from a promoted &'static
                // core::panic::Location by SpinLock::lock.
                let loc = unsafe { &*(loc_addr as *const core::panic::Location<'static>) };
                serial_puts_raw(" acquired_at=");
                serial_puts_raw(loc.file());
                serial_putc_hw(b':');
                serial_dec_raw(loc.line() as u64);
            }
            serial_putc_hw(b'\n');

            // SAFETY: held-lock slots are populated only from live SpinLock
            // addresses during lock acquisition and cleared on unlock.
            let lock = unsafe { &*(lock_addr as *const SpinLock) };
            let contender_since = lock.contender_since_ns.load(Ordering::Acquire);
            if contender_since != 0 {
                any = true;
                serial_puts_raw("contender: lock=");
                serial_hex_raw(lock_addr as u64);
                serial_puts_raw(" symbol=");
                crate::kernel::kallsyms::print_symbol(lock_addr, false);
                serial_puts_raw(" cpu=");
                serial_dec_raw(lock.last_contender_cpu.load(Ordering::Acquire) as u64);
                serial_puts_raw(" tid=");
                let tid = lock.last_contender_tid.load(Ordering::Acquire);
                if tid == u64::MAX {
                    serial_puts_raw("<none>");
                } else {
                    serial_dec_raw(tid);
                }
                serial_puts_raw(" waiting_ns=");
                serial_dec_raw(now.saturating_sub(contender_since));
                serial_putc_hw(b'\n');
            }
        }
        let overflow = stack.overflow.load(Ordering::Acquire);
        if overflow != 0 {
            any = true;
            serial_puts_raw("held_lock_overflow: cpu=");
            serial_dec_raw(cpu as u64);
            serial_puts_raw(" count=");
            serial_dec_raw(overflow);
            serial_putc_hw(b'\n');
        }
        cpu += 1;
    }
    if !any {
        serial_puts_raw("held_locks: <none>\n");
    }
}

/// Approximate spin count corresponding to ~100ms on modern x86. The
/// scheduler / IPC critical sections are in the microsecond range, so
/// crossing this threshold means the lock holder is wedged.
pub(crate) const SPINLOCK_HARD_TIMEOUT_SPINS: u64 = 50_000_000;

/// Route spinlock hard timeouts through the unified panic path.
#[inline(never)]
#[cold]
pub(crate) fn spinlock_hard_timeout_panic(
    what: &'static str,
    lock_addr: usize,
    contended_loc: &'static core::panic::Location<'static>,
    acquired_loc: usize,
    owner_cpu: u64,
    owner_tid: u64,
    waiting_ns: u64,
) -> ! {
    let location = crate::kernel::panic::PanicLocation::new(
        contended_loc.file(),
        contended_loc.line(),
        contended_loc.column(),
    );
    crate::kernel::panic::spinlock_timeout(
        what,
        lock_addr,
        location,
        acquired_loc,
        owner_cpu,
        owner_tid,
        waiting_ns,
    );
}

/// Subsystem lock: protects capability slot array, CDT operations, CNode ops,
/// untyped child tracking, and capability lookup.
///
/// Lock ordering (outermost → innermost):
///   CAP_LOCK → IRQ_LOCK → mp_core.lock / dp_core.lock / eq.lock / tcb_lock / sc.lock → SLEEP_LOCK / FUTEX_LOCK → sched.lock_cpu → VmHierarchyState.lock (per COW tree) → VSpace.lock → ASID_LOCK → MO.commit_lock | MO.rmap_lock → ut.alloc_lock → FRAME_LOCK → SERIAL_LOCK
///
/// Leaf locks — never nested under `CAP_LOCK`, always taken outside it. A leaf
/// that can be reached by the interrupt-entry prologue
/// (`sched_runtime_enter_kernel` → `flush_deferred_current_release` →
/// `drain_reaper` → `CAP_LOCK` → `VSpace::cleanup` → `unregister_live_vspace`)
/// must be held with IRQs disabled, or an IRQ-enabled section holding it
/// deadlocks when that prologue runs (this is how the original
/// `DEFERRED_FREE_LOCK` deadlock fired):
/// - `DEFERRED_FREE_LOCK` — deferred `VSpaceTracking` free list. Taken only by
///   `process_deferred_free` (BSP idle thread) and by `flush_pending_retire`
///   (after `CAP_LOCK` release in `drain_reaper`), both IRQ-disabled.
/// - `LIVE_VSPACE_LOCK` — the live-VSpace registry. In the activity sweep it is
///   held only for the brief pointer snapshot + refcount pin, under IRQ-disable;
///   it is NOT held across the page-table harvest.
/// - `ACTIVITY_SWEEP_LOCK` — serializes the activity sweep and owns its snapshot
///   buffer; taken outside `LIVE_VSPACE_LOCK` and held across the harvest with
///   IRQs enabled (the harvest holds no registry lock and masks IRQs itself
///   around the per-VSpace page-table lock).
/// Each pair is acyclic because no path takes `CAP_LOCK` while holding any leaf,
/// and the registry lock is never held across the IRQ-enabled harvest.
///
/// Interrupt delivery nests `IRQ_LOCK` outside the per-object locks:
/// `dispatch_irq` holds `IRQ_LOCK` across `IrqHandler::signal_fire`, which takes
/// `eq.lock` (via `EventQueue::link_irq`) to link the firing handler onto the
/// queue's priority interrupt lane; `irq_handler_bind_eq` / `irq_handler_unbind_eq`
/// and handler cleanup take `IRQ_LOCK → eq.lock` likewise. `eq.lock` is released
/// before the `EQ_WAIT` waiter wake, so it never nests `sched.lock_cpu`. No path
/// takes a per-object lock before `IRQ_LOCK`, so the order stays acyclic.
///
/// `release_object()` is called from `delete_capability()` with CAP_LOCK held.
/// When refcount reaches zero, final cleanup is queued onto the object reaper;
/// the reaper later reacquires CAP_LOCK before entering `destroy_object()`
/// and each type-specific cleanup function. `MemoryObject::destroy()` uses a
/// **snapshot + re-validate** pattern to traverse `reverse_maps` without
/// nesting `MO.rmap_lock` around `VSpace.lock` (which would invert the
/// documented order). See the comment on `MemoryObject::destroy` for the full
/// protocol.
///
/// `MO.rmap_lock` protects `MemoryObject::reverse_maps` across every writer
/// (register/unmap split/cleanup/destroy) and reader (`total()`, `for_each`)
/// path. `MO.commit_lock` protects `MemoryObject::pages` (the radix tree of
/// committed physical addresses) across every writer (commit_page /
/// cow_resolve_page / decommit / resize-shrink) and every reader
/// (`resolve_page_depth`, `is_local_committed`). The two MO locks sit at the
/// same level and are **disjoint** — holding both simultaneously is forbidden.
/// `ut.alloc_lock` may be nested inside either MO lock when a radix node
/// allocator walks into PMM.
///
/// `VmHierarchyState.lock` (the per-COW-tree serialization lock) nests OUTSIDE
/// `VSpace.lock` and serializes every page-identity / topology / rmap /
/// write-protect / fault operation across one COW tree, so snapshot-freeze vs
/// fault vs partial-unmap-split cannot interleave (closes the F2/F3 COW defects
/// by construction). A standalone (not-yet-bound) MO uses its own
/// `MO.hierarchy_bind_lock` instead, which nests outside `VmHierarchyState.lock`
/// (only during the standalone→tree bind). **Acyclicity invariant:** while
/// holding the tree lock or a bind lock, never take CAP_LOCK, never call
/// `release_object()` (it takes REAPER_LOCK), and never signal a notification /
/// wake a thread / enqueue an event — those are deferred until after the lock
/// drops (deferred-release lists; deferred pager emit/wake; the post-unlock
/// RangeChangeList TLB flush). This keeps CAP_LOCK → tree lock the only edge
/// into the tree lock and forbids tree lock → REAPER_LOCK, so the graph stays
/// acyclic.
///
/// SLEEP_LOCK and FUTEX_LOCK are independent of each other and of per-object
/// locks; they protect their own global data structures. IRQ_LOCK nests outside
/// the per-object locks on the interrupt-delivery path (see the lock ordering
/// above).
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
    let result = unsafe {
        (*(&raw mut FRAME_ALLOCATOR))
            .as_mut()?
            .alloc_contiguous(count)
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Allocate contiguous physical frames and tag every frame with `owner`
/// before releasing the PMM lock.
pub fn pmm_alloc_contiguous_owned(count: usize, owner: &frame::FrameOwner) -> Option<PhysAddr> {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        let allocator = (*(&raw mut FRAME_ALLOCATOR)).as_mut()?;
        let phys = allocator.alloc_contiguous(count)?;
        for i in 0..count {
            allocator.set_owner(phys + (i * PAGE_SIZE) as u64, owner);
        }
        Some(phys)
    };
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

/// Transfer ownership and remember the untyped source for a new `MoData` owner.
pub fn pmm_transfer_with_source(
    addr: PhysAddr,
    old: &frame::FrameOwner,
    new: &frame::FrameOwner,
    source_ut: *const crate::cap::UntypedMemory,
) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    unsafe {
        if let Some(a) = (*(&raw mut FRAME_ALLOCATOR)).as_mut() {
            a.transfer_with_source(addr, old, new, source_ut);
        }
    }
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
}

/// Return the untyped source attached to a live `MoData` frame, if any.
pub fn pmm_source_untyped(addr: PhysAddr) -> *mut crate::cap::UntypedMemory {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        (*(&raw mut FRAME_ALLOCATOR))
            .as_ref()
            .map(|a| a.source_untyped(addr))
            .unwrap_or(core::ptr::null_mut())
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
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

/// Update a tracked frame's flag word and return the previous value.
pub fn pmm_update_flags(addr: PhysAddr, set_mask: u8, clear_mask: u8) -> Option<u8> {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        (*(&raw mut FRAME_ALLOCATOR))
            .as_mut()
            .and_then(|a| a.update_flags(addr, set_mask, clear_mask))
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Transition a dirty file-backed MO data frame into WRITEBACK.
/// Returns Clean when there is no dirty work to issue and Busy when
/// another writeback already owns the frame.
pub fn pmm_begin_file_writeback(addr: PhysAddr) -> Option<frame::FileWritebackBegin> {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        (*(&raw mut FRAME_ALLOCATOR))
            .as_mut()
            .and_then(|a| a.begin_file_writeback(addr))
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Complete a file-backed MO data frame writeback. The return value
/// is the new frame flag word after WRITEBACK is cleared.
pub fn pmm_finish_file_writeback(addr: PhysAddr, ok: bool) -> Option<u8> {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        (*(&raw mut FRAME_ALLOCATOR))
            .as_mut()
            .and_then(|a| a.finish_file_writeback(addr, ok))
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Age the active/inactive model by one epoch and return the new page counts.
pub fn pmm_age_activity_epoch() -> (usize, usize) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        (*(&raw mut FRAME_ALLOCATOR))
            .as_mut()
            .map(|a| a.age_activity_epoch())
            .unwrap_or((0, 0))
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Read the current active/inactive page counters without aging.
pub fn pmm_activity_counts() -> (usize, usize) {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        (*(&raw const FRAME_ALLOCATOR))
            .as_ref()
            .map(|a| (a.active_lru_count(), a.inactive_lru_count()))
            .unwrap_or((0, 0))
    };
    FRAME_LOCK.unlock();
    unsafe { restore_irq(irq_flag) };
    result
}

/// Allocate from the emergency reserve and immediately retag the frame
/// for its consumer. Only callable during fault handling.
/// Panics if called outside a fault context.
pub fn pmm_alloc_reserve(owner: &frame::FrameOwner) -> Option<PhysAddr> {
    // Verify fault context: we must be inside an exception handler
    // (IRQs disabled + on kernel stack).
    // In practice, this is called from the COW fast-path inside exception
    // handlers where IRQs are already disabled. The check is that we're
    // not in normal syscall context.
    {
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();
        if !current.is_null() {
            // If the thread is Running in normal syscall context,
            // this is misuse. IRQs-disabled is the proxy for "we're
            // in exception context."
            crate::kernel::bug::kassert!(
                vspace::irqs_disabled(),
                "pmm_alloc_reserve called outside fault context"
            );
        }
    }

    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        (*(&raw mut FRAME_ALLOCATOR)).as_mut().and_then(|a| {
            let phys = a.alloc_reserve()?;
            a.set_owner(phys, owner);
            Some(phys)
        })
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

/// Snapshot the global PMM accounting counters into a plain struct.
///
/// Takes FRAME_LOCK briefly to read a coherent copy of every per-tag
/// and per-subkind counter, then returns. Safe to call from any context
/// where the frame lock is not already held.
pub fn pmm_memsnapshot() -> accounting::GlobalMemCounts {
    let irq_flag = unsafe { save_irq_disable() };
    FRAME_LOCK.lock();
    let result = unsafe {
        (*(&raw const FRAME_ALLOCATOR))
            .as_ref()
            .map(accounting::GlobalMemCounts::from_allocator)
            .unwrap_or_default()
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
    crate::kernel::printk::serial_puts("[MM] Frame bitmap remapped to direct physical map\n");
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
