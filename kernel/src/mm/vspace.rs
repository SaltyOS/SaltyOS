//! Virtual Address Space
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{alloc_frame, free_frame, phys_to_virt, PhysAddr, SpinLock, VirtAddr, PAGE_SIZE};
use crate::arch::x86_64::paging::PageTable;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

/// Page table entry flag bits
const ENTRY_PRESENT: u64 = 1 << 0;
const ENTRY_WRITABLE: u64 = 1 << 1;
const ENTRY_USER: u64 = 1 << 2;
const ENTRY_WRITE_THROUGH: u64 = 1 << 3;
const ENTRY_CACHE_DISABLE: u64 = 1 << 4;
const ENTRY_COW: u64 = 1 << 9;
const ENTRY_NO_EXECUTE: u64 = 1 << 63;

/// Physical address mask in page table entry
const ENTRY_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// User PML4 range: entries 0..255 (lower half)
const USER_PML4_MAX: usize = 256;

/// Maximum number of CPUs (from arch module)
use crate::arch::MAX_CPUS;

/// Maximum number of concurrent VSpaces (including kernel VSpace)
/// This is a hard limit - each process needs one VSpace
const MAX_VSPACES: usize = 256;

/// Maximum number of deferred free entries
const MAX_DEFERRED: usize = 256;
/// VSpaceTracking pool - static allocation, no heap
///
/// All VSpaceTracking objects are allocated from this pool.
/// Uses a free list for O(1) allocation/deallocation.
/// PROTECTED BY: TRACKING_POOL_LOCK
static mut TRACKING_POOL: [VSpaceTracking; MAX_VSPACES] =
    [const { VSpaceTracking::new(0) }; MAX_VSPACES];
static mut TRACKING_FREE_LIST: [*mut VSpaceTracking; MAX_VSPACES] =
    [core::ptr::null_mut(); MAX_VSPACES];
static mut TRACKING_FREE_COUNT: usize = MAX_VSPACES;
static mut TRACKING_POOL_LOCK: SpinLock = SpinLock::new();

/// Initialize VSpaceTracking pool (call during boot)
///
/// Sets up the free list with all available tracking objects.
fn init_tracking_pool() {
    unsafe {
        TRACKING_FREE_COUNT = MAX_VSPACES;
        for i in 0..MAX_VSPACES {
            TRACKING_FREE_LIST[i] = &raw mut TRACKING_POOL[i];
        }
    }
}

/// Allocate a VSpaceTracking from the pool
///
/// Returns None if pool is exhausted.
/// Must be called with IRQs disabled (or from single-threaded boot context).
fn alloc_tracking(root: PhysAddr) -> Option<*mut VSpaceTracking> {
    unsafe {
        let lock = &raw const TRACKING_POOL_LOCK;
        (*lock).lock();

        if TRACKING_FREE_COUNT == 0 {
            (*lock).unlock();
            return None;
        }

        TRACKING_FREE_COUNT -= 1;
        let tracking = TRACKING_FREE_LIST[TRACKING_FREE_COUNT];
        TRACKING_FREE_LIST[TRACKING_FREE_COUNT] = core::ptr::null_mut();

        (*lock).unlock();

        // Initialize the tracking object
        (*tracking) = VSpaceTracking::new(root);
        Some(tracking)
    }
}

/// Deallocate a VSpaceTracking back to the pool
///
/// # Safety
/// Must be called with IRQs disabled and TRACKING_POOL_LOCK held.
/// This is ONLY called from deferred free processing with lock already held.
unsafe fn dealloc_tracking_locked(tracking: *mut VSpaceTracking) {
    unsafe {
        if TRACKING_FREE_COUNT >= MAX_VSPACES {
            // Pool full - should never happen
            return;
        }

        TRACKING_FREE_LIST[TRACKING_FREE_COUNT] = tracking;
        TRACKING_FREE_COUNT += 1;
    }
}

/// VSpace lifecycle states
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VSpaceState {
    Active = 0,
    Dying = 1,
    Dead = 2,
}

/// Result of deactivate_nosched() operation
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeactivateResult {
    /// Wasn't active, no change
    NotActive = 0,
    /// Was active, still other cores active
    StillActive = 1,
    /// Was the last active core, VSpace became inactive
    /// Caller MUST call scheduler::finish_deactivate() with scheduler lock held!
    BecameInactive = 2,
}

/// Global kernel VSpace tracking pointer (set during boot)
static mut KERNEL_VSPACE_TRACKING: *const VSpaceTracking = core::ptr::null();

/// Kernel PML4 physical address (set during boot, never freed)
static mut KERNEL_PML4_PHYS: PhysAddr = 0;

/// Per-CPU current VSpace tracking pointer
///
/// SAFETY: Same-CPU access only. Access from other CPUs is data race.
/// Use current_cpu() to index into this array.
static mut CURRENT_VSPACE_TRACKING: [*const VSpaceTracking; MAX_CPUS] =
    [core::ptr::null(); MAX_CPUS];

/// Per-CPU pending deactivate pointer (set by IPI, processed by scheduler)
///
/// IMPORTANT: Same-CPU only!
/// - set_pending_deactivate(): called from IPI handler (IRQ already disabled)
/// - take_pending_deactivate(): must be called with IRQs disabled (scheduler lock context)
///
/// SAFETY: VSpaceTracking pointers stored here are NEVER freed until all pending
/// has been processed. See VSpaceTrackingPool for deferred free mechanism.
static mut PENDING_DEACTIVATE: [*const VSpaceTracking; MAX_CPUS] = [core::ptr::null(); MAX_CPUS];

/// Generation counter for deferred free mechanism
///
/// Each CPU has a generation that increments when it processes pending.
/// VSpaceTracking is freed only when all CPUs have processed pending
/// AFTER the VSpace was marked for deletion.
static mut PENDING_GENERATION: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Global retire generation counter - increments for each retired tracking
static mut GLOBAL_RETIRE_GEN: AtomicU64 = AtomicU64::new(0);

// SpinLock is imported from super (mm/mod.rs)

/// Deferred free list for VSpaceTracking
///
/// VSpaceTracking is moved here when VSpace is destroyed.
/// Freed when all CPUs have processed pending (quiescent state).
///
/// PROTECTED BY: DEFERRED_FREE_LOCK (must hold for any access)
static mut DEFERRED_FREE_LIST: [*mut VSpaceTracking; MAX_DEFERRED] =
    [core::ptr::null_mut(); MAX_DEFERRED];
static mut DEFERRED_FREE_COUNT: usize = 0;
static mut DEFERRED_FREE_LOCK: SpinLock = SpinLock::new();

/// VSpace lifecycle tracking for SMP-safe teardown
///
/// Memory management: VSpaceTracking is allocated from a static pool
/// (no heap allocation) to allow deferred free. VSpace contains *mut VSpaceTracking pointer.
///
/// # Safety Invariant for Sync
///
/// `waiter_head: UnsafeCell<*mut Tcb>` is ONLY accessed from scheduler module
/// with scheduler lock held AND IRQs disabled. This is enforced by:
/// - waiter_head_get_locked/set_locked are pub(crate) only
/// - Only scheduler.rs uses these functions
#[repr(C)]
pub struct VSpaceTracking {
    /// VSpace root address (for identification and comparison)
    root: PhysAddr,

    /// Current state
    state: AtomicU8,

    /// Number of cores with this VSpace loaded
    active_count: AtomicU32,

    /// For debugging: bitmap of active cores
    active_mask: [AtomicU32; (MAX_CPUS + 31) / 32],

    /// IPI has been sent flag (prevent duplicate IPIs)
    ipi_sent: AtomicU8,

    /// Retire generation - assigned when tracking is retired for deferred free
    retire_gen: AtomicU64,

    /// Per-CPU generation snapshot at retire time
    /// Free condition: all PENDING_GENERATION[cpu] > retire_snapshot[cpu]
    retire_snapshot: [AtomicU64; MAX_CPUS],

    /// Intrusive wait queue head (protected by scheduler lock)
    /// SAFETY: ONLY accessed via waiter_head_get/set_locked() from scheduler module
    /// with scheduler lock held AND IRQs disabled!
    waiter_head: UnsafeCell<*mut crate::sched::Tcb>,
}

// SAFETY: waiter_head is only accessed from scheduler module with scheduler lock + IRQs disabled
// Access is restricted via pub(crate) _locked() functions
unsafe impl Sync for VSpaceTracking {}

impl VSpaceTracking {
    pub const fn new(root: PhysAddr) -> Self {
        Self {
            root,
            state: AtomicU8::new(VSpaceState::Active as u8),
            active_count: AtomicU32::new(0),
            active_mask: [const { AtomicU32::new(0) }; (MAX_CPUS + 31) / 32],
            ipi_sent: AtomicU8::new(0),
            retire_gen: AtomicU64::new(0),
            retire_snapshot: [const { AtomicU64::new(0) }; MAX_CPUS],
            waiter_head: UnsafeCell::new(core::ptr::null_mut()),
        }
    }

    pub fn root(&self) -> PhysAddr {
        self.root
    }

    /// Get waiter head pointer (scheduler module ONLY, lock REQUIRED)
    ///
    /// # Safety
    /// MUST be called with scheduler lock held AND IRQs disabled!
    /// This is pub(crate) - only scheduler module should call this.
    #[inline(always)]
    pub(crate) unsafe fn waiter_head_get_locked(&self) -> *mut crate::sched::Tcb {
        unsafe { *self.waiter_head.get() }
    }

    /// Set waiter head pointer (scheduler module ONLY, lock REQUIRED)
    ///
    /// # Safety
    /// MUST be called with scheduler lock held AND IRQs disabled!
    /// This is pub(crate) - only scheduler module should call this.
    #[inline(always)]
    pub(crate) unsafe fn waiter_head_set_locked(&self, head: *mut crate::sched::Tcb) {
        unsafe {
            *self.waiter_head.get() = head;
        }
    }

    /// Try to activate - idempotent, returns false if dying/dead
    pub fn try_activate(&self, cpu_id: usize) -> bool {
        let state = self.state.load(Ordering::Acquire);
        if state != VSpaceState::Active as u8 {
            return false;
        }

        let word = cpu_id / 32;
        let bit = cpu_id % 32;

        let old_mask = self.active_mask[word].fetch_or(1 << bit, Ordering::AcqRel);
        if old_mask & (1 << bit) != 0 {
            return true; // Already active
        }

        self.active_count.fetch_add(1, Ordering::AcqRel);

        let state = self.state.load(Ordering::Acquire);
        if state != VSpaceState::Active as u8 {
            self.active_mask[word].fetch_and(!(1 << bit), Ordering::AcqRel);
            self.active_count.fetch_sub(1, Ordering::AcqRel);
            return false;
        }

        true
    }

    /// Deactivate without scheduler interaction - only atomic count/mask update
    ///
    /// Returns `DeactivateResult` indicating whether VSpace became inactive.
    /// If `BecameInactive` is returned, caller MUST call `scheduler::finish_deactivate()`
    /// with scheduler lock held to wake waiters.
    ///
    /// This structurally enforces the shared lock requirement: you cannot
    /// wake waiters without going through scheduler-locked code.
    pub fn deactivate_nosched(&self, cpu_id: usize) -> DeactivateResult {
        let word = cpu_id / 32;
        let bit = cpu_id % 32;

        let old_mask = self.active_mask[word].fetch_and(!(1 << bit), Ordering::AcqRel);
        if old_mask & (1 << bit) == 0 {
            return DeactivateResult::NotActive;
        }

        let old_count = self.active_count.fetch_sub(1, Ordering::AcqRel);
        if old_count == 1 {
            return DeactivateResult::BecameInactive;
        }

        DeactivateResult::StillActive
    }

    /// Mark as dying and send IPI
    pub fn mark_dying(&self, current_cpu: usize) {
        self.state
            .store(VSpaceState::Dying as u8, Ordering::Release);

        // Use 0/1 for AtomicU8, not false/true
        if self
            .ipi_sent
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.send_ipi_to_active_cores(current_cpu);
        }
    }

    pub fn mark_dead(&self) {
        self.state.store(VSpaceState::Dead as u8, Ordering::Release);
    }

    pub fn is_active(&self) -> bool {
        self.active_count.load(Ordering::Acquire) > 0
    }

    pub fn state(&self) -> VSpaceState {
        match self.state.load(Ordering::Acquire) {
            0 => VSpaceState::Active,
            1 => VSpaceState::Dying,
            _ => VSpaceState::Dead,
        }
    }

    /// Send IPI to active cores (skip current CPU)
    fn send_ipi_to_active_cores(&self, current_cpu: usize) {
        for word_idx in 0..self.active_mask.len() {
            let mask = self.active_mask[word_idx].load(Ordering::Acquire);
            if mask == 0 {
                continue;
            }

            for bit in 0..32 {
                if mask & (1 << bit) != 0 {
                    let cpu_id = word_idx * 32 + bit;
                    if cpu_id < MAX_CPUS && cpu_id != current_cpu {
                        unsafe {
                            crate::arch::send_ipi(cpu_id, crate::arch::IpiKind::VSpaceTeardown);
                        }
                    }
                }
            }
        }
    }
}

/// Get current VSpaceTracking pointer for this CPU
pub fn current_vspace_tracking() -> *const VSpaceTracking {
    unsafe {
        let cpu_id = crate::arch::current_cpu() as usize;
        CURRENT_VSPACE_TRACKING[cpu_id]
    }
}

/// Set current VSpaceTracking for this CPU
pub fn set_current_vspace_tracking(tracking: *const VSpaceTracking) {
    unsafe {
        let cpu_id = crate::arch::current_cpu() as usize;
        CURRENT_VSPACE_TRACKING[cpu_id] = tracking;
    }
}

/// Get kernel VSpaceTracking pointer
pub fn kernel_vspace_tracking() -> *const VSpaceTracking {
    unsafe { KERNEL_VSPACE_TRACKING }
}

/// Get kernel VSpace root address
pub fn kernel_vspace_root() -> PhysAddr {
    unsafe {
        let tracking = KERNEL_VSPACE_TRACKING;
        if tracking.is_null() {
            return 0;
        }
        (*tracking).root()
    }
}

/// Initialize kernel VSpace (called during boot)
pub fn init_kernel_vspace(kernel_pml4: PhysAddr) {
    // Initialize tracking pool first (single-threaded boot context)
    init_tracking_pool();

    unsafe {
        KERNEL_PML4_PHYS = kernel_pml4;
        // Allocate from pool for kernel VSpace (always succeeds during boot)
        let tracking =
            alloc_tracking(kernel_pml4).expect("Failed to allocate kernel VSpace tracking");
        KERNEL_VSPACE_TRACKING = tracking;
        let cpu_id = crate::arch::current_cpu() as usize;
        CURRENT_VSPACE_TRACKING[cpu_id] = tracking;
    }
}

/// Set kernel PML4 physical address
pub fn set_kernel_pml4(addr: PhysAddr) {
    unsafe {
        KERNEL_PML4_PHYS = addr;
    }
}

/// Check if tracking is kernel VSpace
pub fn is_kernel_vspace(tracking: *const VSpaceTracking) -> bool {
    unsafe { tracking == KERNEL_VSPACE_TRACKING }
}

/// Set pending deactivate for a CPU (called from IPI handler)
///
/// # Safety
/// Only call from IPI handler context (IRQ already disabled by hardware).
/// Same-CPU only: cpu_id MUST be the current CPU.
///
/// POLICY: "One pending per CPU at a time"
/// - Overwrite guard: if already pending, keep existing value
/// - Safe because: IPI switches to kernel VSpace
/// - After switching to kernel, won't receive another VSpace teardown IPI
/// - (VSpace teardown only happens when leaving a VSpace for kernel)
/// - This prevents active_count from permanently staying high
pub unsafe fn set_pending_deactivate(cpu_id: usize, tracking: *const VSpaceTracking) {
    // SAFETY CHECK: Same-CPU only (debug build)
    #[cfg(debug_assertions)]
    {
        debug_assert_eq!(
            cpu_id,
            crate::arch::current_cpu() as usize,
            "set_pending_deactivate: cpu_id mismatch - must be current CPU"
        );
        debug_assert!(
            irqs_disabled(),
            "set_pending_deactivate: IRQs must be disabled"
        );
    }

    // Only set if null - guard against overwrite
    // POLICY ENFORCEMENT: "One pending per CPU"
    unsafe {
        if PENDING_DEACTIVATE[cpu_id].is_null() {
            PENDING_DEACTIVATE[cpu_id] = tracking;
        }
    }
}

/// Get and clear pending deactivate for this CPU
///
/// Returns pending tracking if any, null otherwise.
/// Does NOT advance generation - use advance_quiescent_gen() separately.
///
/// # Safety
/// Same-CPU only: cpu_id MUST be the current CPU.
/// Must be called with IRQs disabled (scheduler lock context).
/// This is called from scheduler module only.
pub unsafe fn take_pending_deactivate(cpu_id: usize) -> *const VSpaceTracking {
    // SAFETY CHECK: Same-CPU only + IRQs disabled (debug build)
    #[cfg(debug_assertions)]
    {
        debug_assert_eq!(
            cpu_id,
            crate::arch::current_cpu() as usize,
            "take_pending_deactivate: cpu_id mismatch - must be current CPU"
        );
        debug_assert!(
            irqs_disabled(),
            "take_pending_deactivate: IRQs must be disabled"
        );
    }

    unsafe {
        let tracking = PENDING_DEACTIVATE[cpu_id];
        PENDING_DEACTIVATE[cpu_id] = core::ptr::null();
        tracking
    }
}

/// Advance quiescent generation for this CPU
///
/// Signals that this CPU has passed a safe point (processed pending, etc.).
/// Separated from take_pending_deactivate() to clarify intent:
/// - advance_quiescent_gen(): "I passed a safe point"
/// - take_pending_deactivate(): "Is there work to do?"
///
/// # Safety
/// Same-CPU only: cpu_id MUST be the current CPU.
pub fn advance_quiescent_gen(cpu_id: usize) {
    #[cfg(debug_assertions)]
    {
        debug_assert_eq!(
            cpu_id,
            crate::arch::current_cpu() as usize,
            "advance_quiescent_gen: cpu_id mismatch - must be current CPU"
        );
    }

    unsafe {
        PENDING_GENERATION[cpu_id].fetch_add(1, Ordering::AcqRel);
    }
}

/// Mark VSpaceTracking for deferred free
///
/// Called when VSpace is destroyed. The tracking is moved to deferred free list
/// and will be freed after all CPUs have processed pending (quiescent state).
///
/// Uses per-CPU snapshot mechanism to ensure quiescent state:
/// - Each tracking gets unique retire_gen
/// - retire_snapshot[cpu] stores PENDING_GENERATION[cpu] at retire time
/// - Free condition: all PENDING_GENERATION[cpu] > retire_snapshot[cpu]
///
/// # Safety
/// Must be called with scheduler lock held.
pub unsafe fn defer_free_tracking(tracking: *mut VSpaceTracking) {
    unsafe {
        // Assign unique retire generation
        let retire_gen_ptr = &raw const GLOBAL_RETIRE_GEN;
        let retire_gen = (*retire_gen_ptr).fetch_add(1, Ordering::AcqRel) + 1;
        (*tracking).retire_gen.store(retire_gen, Ordering::Release);

        // Take snapshot of each CPU's generation at retire time
        for cpu in 0..MAX_CPUS {
            let cpu_gen = PENDING_GENERATION[cpu].load(Ordering::Acquire);
            (*tracking).retire_snapshot[cpu].store(cpu_gen, Ordering::Release);
        }

        // Add to deferred free list (protected by lock)
        let lock = &raw const DEFERRED_FREE_LOCK;
        (*lock).lock();
        debug_assert!(
            DEFERRED_FREE_COUNT < MAX_DEFERRED,
            "deferred free list overflow"
        );
        DEFERRED_FREE_LIST[DEFERRED_FREE_COUNT] = tracking;
        DEFERRED_FREE_COUNT += 1;
        (*lock).unlock();
    }
}

/// Process deferred free list (call periodically, e.g., from BSP idle loop)
///
/// Frees any tracking objects that have reached quiescent state.
/// Should only be called by BSP to avoid concurrent free list manipulation.
///
/// Free conditions for each tracking:
/// 1. All CPUs: PENDING_GENERATION[cpu] > tracking.retire_snapshot[cpu]
/// 2. tracking.active_count == 0
/// 3. tracking.state == Dead
/// 4. tracking.ipi_sent == 1 (teardown complete)
///
/// IMPORTANT: Collects pointers to free while holding lock, but actual
/// deallocation happens after releasing lock to avoid reentrancy issues.
pub fn process_deferred_free() {
    let mut to_free: [*mut VSpaceTracking; MAX_DEFERRED] = [core::ptr::null_mut(); MAX_DEFERRED];
    let mut to_free_count = 0;

    unsafe {
        let lock = &raw const DEFERRED_FREE_LOCK;
        (*lock).lock();

        // Scan for entries that can be freed
        let mut write_idx = 0;
        for read_idx in 0..DEFERRED_FREE_COUNT {
            let tracking = DEFERRED_FREE_LIST[read_idx];
            if tracking.is_null() {
                continue;
            }

            // Check quiescent state conditions
            let mut can_free = true;

            // Condition 1: All CPUs passed their snapshot
            for cpu in 0..MAX_CPUS {
                let cpu_gen = PENDING_GENERATION[cpu].load(Ordering::Acquire);
                let snapshot = (*tracking).retire_snapshot[cpu].load(Ordering::Acquire);
                if cpu_gen <= snapshot {
                    can_free = false;
                    break;
                }
            }

            // Conditions 2-4: Teardown complete
            if can_free {
                can_free = (*tracking).active_count.load(Ordering::Acquire) == 0
                    && (*tracking).state.load(Ordering::Acquire) == VSpaceState::Dead as u8
                    && (*tracking).ipi_sent.load(Ordering::Acquire) == 1;
            }

            if can_free {
                // Mark for freeing (outside lock)
                debug_assert!(to_free_count < MAX_DEFERRED, "to_free overflow");
                to_free[to_free_count] = tracking;
                to_free_count += 1;

                // Clear from list
                DEFERRED_FREE_LIST[read_idx] = core::ptr::null_mut();
            } else {
                // Keep for next time - compact the list
                if read_idx != write_idx {
                    DEFERRED_FREE_LIST[write_idx] = DEFERRED_FREE_LIST[read_idx];
                    DEFERRED_FREE_LIST[read_idx] = core::ptr::null_mut();
                }
                write_idx += 1;
            }
        }
        DEFERRED_FREE_COUNT = write_idx;

        (*lock).unlock();
    }

    // Actual deallocation happens OUTSIDE the lock
    // This prevents reentrancy issues with allocator
    for i in 0..to_free_count {
        unsafe {
            // Take lock for pool deallocation
            let lock = &raw const TRACKING_POOL_LOCK;
            (*lock).lock();
            dealloc_tracking_locked(to_free[i]);
            (*lock).unlock();
        }
    }
}

/// Deallocate VSpaceTracking (internal)
///
/// VSpaceTracking is allocated from the tracking pool.
/// This must be called with TRACKING_POOL_LOCK held.
unsafe fn dealloc_tracking(tracking: *mut VSpaceTracking) {
    unsafe {
        let lock = &raw const TRACKING_POOL_LOCK;
        (*lock).lock();
        dealloc_tracking_locked(tracking);
        (*lock).unlock();
    }
}

/// Check if IRQs are disabled
#[inline]
fn irqs_disabled() -> bool {
    let rflags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq; pop {}",
            out(reg) rflags,
            options(nomem, nostack)
        );
    }
    (rflags & (1 << 9)) == 0
}

/// Virtual address space (wraps page table root)
#[repr(C)]
pub struct VSpace {
    /// Kernel object header (must be first for refcount access)
    pub header: crate::cap::KernelObject,
    /// Physical address of PML4
    root: PhysAddr,
    /// VSpaceTracking is allocated from static pool for deferred free support
    /// Pool allocation allows tracking to outlive VSpace
    tracking: *mut VSpaceTracking,
    /// Per-VSpace lock for page table modifications (map/unmap/install_page_table)
    lock: SpinLock,
}

impl VSpace {
    pub fn new(pml4_addr: PhysAddr) -> Self {
        // Allocate tracking from pool - allows deferred free without heap
        let tracking = alloc_tracking(pml4_addr).expect("VSpace tracking pool exhausted");

        Self {
            header: crate::cap::KernelObject::new(
                crate::cap::ObjectType::VSpace,
                0,
            ),
            root: pml4_addr,
            tracking,
            lock: SpinLock::new(),
        }
    }

    pub fn root(&self) -> PhysAddr {
        self.root
    }

    pub fn tracking(&self) -> &VSpaceTracking {
        unsafe { &*self.tracking }
    }

    /// Extract PML4 index from virtual address
    #[inline]
    fn pml4_index(vaddr: VirtAddr) -> usize {
        ((vaddr >> 39) & 0x1FF) as usize
    }

    /// Extract PDPT index from virtual address
    #[inline]
    fn pdpt_index(vaddr: VirtAddr) -> usize {
        ((vaddr >> 30) & 0x1FF) as usize
    }

    /// Extract PD index from virtual address
    #[inline]
    fn pd_index(vaddr: VirtAddr) -> usize {
        ((vaddr >> 21) & 0x1FF) as usize
    }

    /// Extract PT index from virtual address
    #[inline]
    fn pt_index(vaddr: VirtAddr) -> usize {
        ((vaddr >> 12) & 0x1FF) as usize
    }

    /// Get PML4 table (root) as mutable reference
    fn pml4(&self) -> *mut PageTable {
        phys_to_virt(self.root) as *mut PageTable
    }

    /// Read page table entry at specified level
    /// level: 1=PT, 2=PD, 3=PDPT, 4=PML4
    /// Returns None if entry or table doesn't exist
    fn read_entry(&self, vaddr: VirtAddr, level: usize) -> Option<u64> {
        let pml4 = unsafe { &*self.pml4() };

        match level {
            4 => Some(pml4.entry(Self::pml4_index(vaddr))),
            3 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return None;
                }
                let pdpt = unsafe { &*(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *const PageTable) };
                Some(pdpt.entry(Self::pdpt_index(vaddr)))
            }
            2 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return None;
                }
                let pdpt = unsafe { &*(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *const PageTable) };
                let pdpte = pdpt.entry(Self::pdpt_index(vaddr));
                if pdpte & ENTRY_PRESENT == 0 {
                    return None;
                }
                let pd = unsafe { &*(phys_to_virt(pdpte & ENTRY_ADDR_MASK) as *const PageTable) };
                Some(pd.entry(Self::pd_index(vaddr)))
            }
            1 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return None;
                }
                let pdpt = unsafe { &*(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *const PageTable) };
                let pdpte = pdpt.entry(Self::pdpt_index(vaddr));
                if pdpte & ENTRY_PRESENT == 0 {
                    return None;
                }
                let pd = unsafe { &*(phys_to_virt(pdpte & ENTRY_ADDR_MASK) as *const PageTable) };
                let pde = pd.entry(Self::pd_index(vaddr));
                if pde & ENTRY_PRESENT == 0 {
                    return None;
                }
                // 2MB huge page — there is no level-1 page table
                if pde & (1 << 7) != 0 {
                    return None;
                }
                let pt = unsafe { &*(phys_to_virt(pde & ENTRY_ADDR_MASK) as *const PageTable) };
                Some(pt.entry(Self::pt_index(vaddr)))
            }
            _ => None,
        }
    }

    /// Resolve a user virtual address to its physical address.
    /// Returns None if the page is not mapped.
    pub fn resolve_page(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        let pte = self.read_entry(vaddr, 1)?;
        if pte & ENTRY_PRESENT == 0 {
            return None;
        }
        Some(pte & ENTRY_ADDR_MASK)
    }

    /// Ensure page table exists at specified level, creating if needed
    /// level: 1=PT, 2=PD, 3=PDPT
    /// Returns physical address of the page table
    fn ensure_table(
        &mut self,
        vaddr: VirtAddr,
        level: usize,
        is_user: bool,
    ) -> Result<PhysAddr, VSpaceError> {
        let user_flag = if is_user { ENTRY_USER } else { 0 };
        let table_flags = ENTRY_PRESENT | ENTRY_WRITABLE | user_flag;

        // Walk from PML4 down to target level
        let mut current_table: PhysAddr = self.root;
        let mut current_level = 4;

        while current_level > level {
            let table = unsafe { &mut *(phys_to_virt(current_table) as *mut PageTable) };
            let idx = match current_level {
                4 => Self::pml4_index(vaddr),
                3 => Self::pdpt_index(vaddr),
                2 => Self::pd_index(vaddr),
                _ => return Err(VSpaceError::NotMapped),
            };

            let entry = table.entry(idx);

            // If entry doesn't exist, create a new page table
            if entry & ENTRY_PRESENT == 0 {
                let new_frame = alloc_frame().ok_or(VSpaceError::OutOfMemory)?;
                let new_table_virt = phys_to_virt(new_frame) as *mut PageTable;

                // Zero the new page table
                unsafe {
                    core::ptr::write_bytes(new_table_virt, 0, 1);
                }

                // Set the entry
                table.set_entry(idx, new_frame | table_flags);

                current_table = new_frame;
            } else {
                // Huge page (PS bit set) at this level means we cannot
                // descend further — the entry covers a large page, not a table pointer.
                if current_level <= 3 && entry & (1 << 7) != 0 {
                    return Err(VSpaceError::AlreadyMapped);
                }
                current_table = entry & ENTRY_ADDR_MASK;
            }

            current_level -= 1;
        }

        Ok(current_table)
    }

    /// Write page table entry at specified level
    /// level: 1=PT, 2=PD, 3=PDPT, 4=PML4
    fn write_entry(
        &mut self,
        vaddr: VirtAddr,
        level: usize,
        value: u64,
    ) -> Result<(), VSpaceError> {
        let pml4 = unsafe { &mut *self.pml4() };

        match level {
            4 => {
                pml4.set_entry(Self::pml4_index(vaddr), value);
                Ok(())
            }
            3 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pdpt =
                    unsafe { &mut *(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *mut PageTable) };
                pdpt.set_entry(Self::pdpt_index(vaddr), value);
                Ok(())
            }
            2 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pdpt =
                    unsafe { &mut *(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *mut PageTable) };
                let pdpte = pdpt.entry(Self::pdpt_index(vaddr));
                if pdpte & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pd = unsafe { &mut *(phys_to_virt(pdpte & ENTRY_ADDR_MASK) as *mut PageTable) };
                pd.set_entry(Self::pd_index(vaddr), value);
                Ok(())
            }
            1 => {
                let pml4e = pml4.entry(Self::pml4_index(vaddr));
                if pml4e & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pdpt =
                    unsafe { &mut *(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *mut PageTable) };
                let pdpte = pdpt.entry(Self::pdpt_index(vaddr));
                if pdpte & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pd = unsafe { &mut *(phys_to_virt(pdpte & ENTRY_ADDR_MASK) as *mut PageTable) };
                let pde = pd.entry(Self::pd_index(vaddr));
                if pde & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                let pt = unsafe { &mut *(phys_to_virt(pde & ENTRY_ADDR_MASK) as *mut PageTable) };
                pt.set_entry(Self::pt_index(vaddr), value);
                Ok(())
            }
            _ => Err(VSpaceError::NotMapped),
        }
    }

    /// Convert PageFlags to page table entry flags
    fn flags_to_entry_flags(flags: PageFlags) -> u64 {
        let mut entry = ENTRY_PRESENT;

        if flags.writable {
            entry |= ENTRY_WRITABLE;
        }

        if flags.user {
            entry |= ENTRY_USER;
        }

        if !flags.executable {
            entry |= ENTRY_NO_EXECUTE;
        }

        if flags.cache_disable {
            entry |= ENTRY_CACHE_DISABLE;
        }

        if flags.write_through {
            entry |= ENTRY_WRITE_THROUGH;
        }

        if flags.cow {
            // COW mappings are intentionally read-only until fault resolution.
            entry &= !ENTRY_WRITABLE;
            entry |= ENTRY_COW;
        }

        entry
    }

    /// Send TLB shootdown IPI to all remote CPUs that have this VSpace loaded
    fn tlb_shootdown(&self, vaddr: VirtAddr) {
        if self.tracking.is_null() {
            return;
        }
        let cpu_id = crate::arch::current_cpu() as usize;
        let tracking = unsafe { &*self.tracking };

        for word_idx in 0..tracking.active_mask.len() {
            let mask = tracking.active_mask[word_idx].load(Ordering::Acquire);
            if mask == 0 {
                continue;
            }
            for bit in 0..32 {
                if mask & (1 << bit) != 0 {
                    let target = word_idx * 32 + bit;
                    if target < MAX_CPUS && target != cpu_id {
                        crate::arch::set_tlb_shootdown_addr(target, vaddr);
                        unsafe {
                            crate::arch::send_ipi(target, crate::arch::IpiKind::TlbShootdown);
                        }
                    }
                }
            }
        }
    }

    /// Map a page
    pub fn map(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), VSpaceError> {
        // Check alignment (no lock needed)
        if virt & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        if phys & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        // Acquire per-VSpace lock
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        // Ensure all intermediate page tables exist (may alloc frames — MM_LOCK is inner)
        let result = (|| {
            self.ensure_table(virt, 1, flags.user)?;

            // Check if already mapped
            if let Some(entry) = self.read_entry(virt, 1) {
                if entry & ENTRY_PRESENT != 0 {
                    return Err(VSpaceError::AlreadyMapped);
                }
            }

            // Create the mapping
            let entry_flags = Self::flags_to_entry_flags(flags);
            self.write_entry(virt, 1, phys | entry_flags)?;
            super::retain_frame_mapping(phys);

            // Local TLB flush
            crate::arch::x86_64::paging::invlpg(virt);

            // Remote TLB shootdown
            self.tlb_shootdown(virt);

            Ok(())
        })();

        self.lock.unlock();
        unsafe { restore_irq(irq) };

        result
    }

    /// Install a page table at a specific level
    ///
    /// Installs a pre-allocated page table frame into the page table hierarchy.
    /// level: 1=PT, 2=PD, 3=PDPT
    pub fn install_page_table(
        &mut self,
        vaddr: VirtAddr,
        pt_phys: PhysAddr,
        level: usize,
    ) -> Result<(), VSpaceError> {
        if level < 1 || level > 3 {
            return Err(VSpaceError::Alignment);
        }

        // Check alignment of the page table frame
        if pt_phys & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        // Zero the new page table
        unsafe {
            let pt_virt = phys_to_virt(pt_phys) as *mut u8;
            core::ptr::write_bytes(pt_virt, 0, PAGE_SIZE);
        }

        // Acquire per-VSpace lock
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let result = (|| {
            // Walk from PML4 down to the parent level
            let parent_level = level + 1;

            let user_flag = ENTRY_USER; // Page tables for user mappings
            let table_flags = ENTRY_PRESENT | ENTRY_WRITABLE | user_flag;

            let mut current_table: PhysAddr = self.root;
            let mut cur = 4;

            while cur > parent_level {
                let table = unsafe { &mut *(phys_to_virt(current_table) as *mut PageTable) };
                let idx = match cur {
                    4 => Self::pml4_index(vaddr),
                    3 => Self::pdpt_index(vaddr),
                    2 => Self::pd_index(vaddr),
                    _ => return Err(VSpaceError::NotMapped),
                };

                let entry = table.entry(idx);
                if entry & ENTRY_PRESENT == 0 {
                    return Err(VSpaceError::NotMapped);
                }
                current_table = entry & ENTRY_ADDR_MASK;
                cur -= 1;
            }

            // Now install at the parent level
            let parent_table = unsafe { &mut *(phys_to_virt(current_table) as *mut PageTable) };
            let idx = match parent_level {
                4 => Self::pml4_index(vaddr),
                3 => Self::pdpt_index(vaddr),
                2 => Self::pd_index(vaddr),
                _ => return Err(VSpaceError::NotMapped),
            };

            let existing = parent_table.entry(idx);
            if existing & ENTRY_PRESENT != 0 {
                return Err(VSpaceError::AlreadyMapped);
            }

            parent_table.set_entry(idx, pt_phys | table_flags);
            // No TLB shootdown needed — new empty table has no cached entries
            Ok(())
        })();

        self.lock.unlock();
        unsafe { restore_irq(irq) };

        result
    }

    /// Unmap a page
    pub fn unmap(&mut self, virt: VirtAddr) -> Result<(), VSpaceError> {
        // Check alignment (no lock needed)
        if virt & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        // Acquire per-VSpace lock
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let result = (|| {
            // Check if mapped
            let entry = self.read_entry(virt, 1).ok_or(VSpaceError::NotMapped)?;
            if entry & ENTRY_PRESENT == 0 {
                return Err(VSpaceError::NotMapped);
            }
            let phys = entry & ENTRY_ADDR_MASK;

            // Clear the entry
            self.write_entry(virt, 1, 0)?;

            // TLB invalidation BEFORE refcount release: remote CPUs may still
            // cache the stale entry. Flush first so no CPU can access the frame
            // via stale TLB after we drop the mapping reference.
            crate::arch::x86_64::paging::invlpg(virt);
            self.tlb_shootdown(virt);

            super::release_frame_mapping(phys);

            Ok(())
        })();

        self.lock.unlock();
        unsafe { restore_irq(irq) };

        result
    }

    /// Clone one source page into destination VSpace using COW semantics.
    ///
    /// - Read-only pages are shared directly.
    /// - Writable pages are write-protected in source and mapped COW in destination.
    pub fn clone_page_cow_to(
        &mut self,
        src_vaddr: VirtAddr,
        dst: &mut VSpace,
        dst_vaddr: VirtAddr,
    ) -> Result<(), VSpaceError> {
        if src_vaddr & (PAGE_SIZE as u64 - 1) != 0 || dst_vaddr & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        let irq = unsafe { save_irq_disable() };

        let same_vspace = core::ptr::eq(self, dst);
        let self_first = (self as *const VSpace as usize) <= (dst as *const VSpace as usize);

        if self_first {
            self.lock.lock();
            if !same_vspace {
                dst.lock.lock();
            }
        } else {
            dst.lock.lock();
            self.lock.lock();
        }

        let result = (|| {
            let src_entry = self.read_entry(src_vaddr, 1).ok_or(VSpaceError::NotMapped)?;
            if src_entry & ENTRY_PRESENT == 0 {
                return Err(VSpaceError::NotMapped);
            }

            let phys = src_entry & ENTRY_ADDR_MASK;
            let mut shared_flags = src_entry & !ENTRY_ADDR_MASK;

            if src_entry & ENTRY_WRITABLE != 0 {
                shared_flags = (shared_flags & !ENTRY_WRITABLE) | ENTRY_COW;
                self.write_entry(src_vaddr, 1, phys | shared_flags)?;
                crate::arch::x86_64::paging::invlpg(src_vaddr);
                self.tlb_shootdown(src_vaddr);
            }

            let is_user = (shared_flags & ENTRY_USER) != 0;
            dst.ensure_table(dst_vaddr, 1, is_user)?;
            if let Some(entry) = dst.read_entry(dst_vaddr, 1) {
                if entry & ENTRY_PRESENT != 0 {
                    return Err(VSpaceError::AlreadyMapped);
                }
            }

            dst.write_entry(dst_vaddr, 1, phys | shared_flags)?;
            super::retain_frame_mapping(phys);
            crate::arch::x86_64::paging::invlpg(dst_vaddr);
            dst.tlb_shootdown(dst_vaddr);

            Ok(())
        })();

        if self_first {
            if !same_vspace {
                dst.lock.unlock();
            }
            self.lock.unlock();
        } else {
            self.lock.unlock();
            dst.lock.unlock();
        }

        unsafe { restore_irq(irq) };
        result
    }

    /// Resolve a user-mode write fault on a COW page.
    ///
    /// Returns Ok(true) if the fault was handled and execution can resume.
    /// Returns Ok(false) if this was not a COW fault.
    pub fn handle_cow_fault(
        &mut self,
        fault_addr: VirtAddr,
        error_code: u64,
    ) -> Result<bool, VSpaceError> {
        // Need a present + write + user page fault.
        if (error_code & 0x7) != 0x7 {
            return Ok(false);
        }

        let page_vaddr = fault_addr & !((PAGE_SIZE as u64) - 1);

        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let result = (|| {
            let entry = self.read_entry(page_vaddr, 1).ok_or(VSpaceError::NotMapped)?;
            if entry & ENTRY_PRESENT == 0 || entry & ENTRY_COW == 0 {
                return Ok(false);
            }

            let old_phys = entry & ENTRY_ADDR_MASK;
            let new_phys = alloc_frame().ok_or(VSpaceError::OutOfMemory)?;

            unsafe {
                let src = phys_to_virt(old_phys) as *const u8;
                let dst = phys_to_virt(new_phys) as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE);
            }

            let mut new_flags = entry & !ENTRY_ADDR_MASK;
            new_flags |= ENTRY_WRITABLE;
            new_flags &= !ENTRY_COW;

            if self.write_entry(page_vaddr, 1, new_phys | new_flags).is_err() {
                super::free_frame(new_phys);
                return Err(VSpaceError::NotMapped);
            }

            // TLB invalidation BEFORE refcount release: remote CPUs may still
            // cache the stale read-only entry pointing to old_phys.
            crate::arch::x86_64::paging::invlpg(page_vaddr);
            self.tlb_shootdown(page_vaddr);

            super::retain_frame_mapping(new_phys);
            super::release_frame_mapping(old_phys);

            Ok(true)
        })();

        self.lock.unlock();
        unsafe { restore_irq(irq) };
        result
    }

    /// Resolve a user-mode non-present write fault by growing the user stack.
    ///
    /// Returns Ok(true) if one new stack page was mapped and execution can resume.
    /// Returns Ok(false) if this fault does not qualify as stack growth.
    pub fn handle_stack_growth_fault(
        &mut self,
        fault_addr: VirtAddr,
        error_code: u64,
        user_rsp: VirtAddr,
        stack_top: VirtAddr,
        stack_min: VirtAddr,
    ) -> Result<bool, VSpaceError> {
        // Need a user-mode, write, non-present fault.
        if (error_code & 0x7) != 0x6 {
            return Ok(false);
        }
        if stack_top == 0 || stack_min == 0 || stack_min >= stack_top {
            return Ok(false);
        }
        if user_rsp < stack_min || user_rsp >= stack_top {
            return Ok(false);
        }

        let page_vaddr = fault_addr & !((PAGE_SIZE as u64) - 1);
        if page_vaddr < stack_min || page_vaddr >= stack_top {
            return Ok(false);
        }

        // Keep growth close to the faulting stack pointer.
        // This avoids mapping unrelated holes far below the current stack.
        let rsp_page = user_rsp & !((PAGE_SIZE as u64) - 1);
        let page_size = PAGE_SIZE as u64;
        if page_vaddr + page_size < rsp_page.saturating_sub(page_size) {
            return Ok(false);
        }

        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let result = (|| {
            // Already present => not a stack-growth miss.
            if let Some(entry) = self.read_entry(page_vaddr, 1) {
                if entry & ENTRY_PRESENT != 0 {
                    return Ok(false);
                }
            }

            let new_phys = alloc_frame().ok_or(VSpaceError::OutOfMemory)?;
            unsafe {
                core::ptr::write_bytes(phys_to_virt(new_phys) as *mut u8, 0, PAGE_SIZE);
            }

            if let Err(e) = self.ensure_table(page_vaddr, 1, true) {
                super::free_frame(new_phys);
                return Err(e);
            }

            // Re-check after table creation to avoid racing with any concurrent mapper.
            if let Some(entry) = self.read_entry(page_vaddr, 1) {
                if entry & ENTRY_PRESENT != 0 {
                    super::free_frame(new_phys);
                    return Ok(false);
                }
            }

            let entry_flags = Self::flags_to_entry_flags(PageFlags::USER_RW);
            if self.write_entry(page_vaddr, 1, new_phys | entry_flags).is_err() {
                super::free_frame(new_phys);
                return Err(VSpaceError::NotMapped);
            }

            super::retain_frame_mapping(new_phys);
            crate::arch::x86_64::paging::invlpg(page_vaddr);
            self.tlb_shootdown(page_vaddr);
            Ok(true)
        })();

        self.lock.unlock();
        unsafe { restore_irq(irq) };
        result
    }

    /// Atomically switch to this VSpace (non-blocking)
    ///
    /// Uses deactivate_nosched() and centralized finish_deactivate() for
    /// BecameInactive case. Does NOT block.
    ///
    /// CRITICAL: CR3 write + CURRENT_VSPACE_TRACKING update must be atomic
    /// relative to IPI. We disable IRQs to prevent IPI from seeing torn state.
    pub fn switch_to(&self) -> bool {
        let cpu_id = crate::arch::current_cpu() as usize;
        let kernel_tracking = kernel_vspace_tracking();

        // Try to activate new VSpace
        unsafe {
            if !(*self.tracking).try_activate(cpu_id) {
                return false;
            }
        }

        // CRITICAL: Make CR3 + tracking update atomic with respect to IPI
        let irq_flag = unsafe { save_irq_disable() };

        // Load CR3
        unsafe {
            crate::arch::x86_64::paging::write_cr3(self.root);
        }

        // Compiler fence to prevent reordering
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // Update per-CPU tracking (must be after CR3 for IPI to see consistent state)
        let old_tracking = current_vspace_tracking();
        set_current_vspace_tracking(self.tracking);

        unsafe { restore_irq(irq_flag) };

        // Deactivate old VSpace (safe to do outside critical section)
        if !old_tracking.is_null() && old_tracking != self.tracking {
            if old_tracking != kernel_tracking {
                unsafe {
                    use crate::mm::vspace::DeactivateResult;
                    match (*old_tracking).deactivate_nosched(cpu_id) {
                        DeactivateResult::BecameInactive => {
                            // Use with_lock for non-blocking wakeup
                            crate::sched::scheduler::scheduler().with_lock(|s| {
                                s.finish_deactivate(&*old_tracking);
                            });
                        }
                        _ => {}
                    }
                }
            }
        }

        true
    }

    /// Cleanup when VSpace is destroyed (non-blocking)
    ///
    /// IMPORTANT: This function does NOT block. Blocking (wait_inactive) should
    /// happen in the syscall handler before calling cleanup().
    ///
    /// VSpaceTracking is moved to deferred free list - will be freed after
    /// all CPUs have processed pending deactivate (prevents UAF).
    ///
    /// # Preconditions
    /// - active_count MUST be 0 (inactive)
    /// - Should be called after block_current_on_vspace() returns
    pub fn cleanup(&mut self) {
        // Guard: Never free kernel VSpace
        if self.root == unsafe { KERNEL_PML4_PHYS } {
            return;
        }

        // SAFETY CHECK: Verify inactive (defensive, future-proofing)
        #[cfg(debug_assertions)]
        {
            unsafe {
                debug_assert!(
                    (*self.tracking).active_count.load(Ordering::Acquire) == 0,
                    "cleanup(): VSpace still active (active_count > 0)"
                );
            }
        }

        let cpu_id = crate::arch::current_cpu() as usize;

        // Guard: If current CPU is using this VSpace, switch away first
        let current_tracking = current_vspace_tracking();
        if current_tracking == self.tracking {
            // CRITICAL: Make CR3 + tracking update atomic with respect to IPI
            let irq_flag = unsafe { save_irq_disable() };

            // Switch to kernel VSpace FIRST
            let kernel_tracking = kernel_vspace_tracking();
            let kernel_root = kernel_vspace_root();

            unsafe {
                crate::arch::x86_64::paging::write_cr3(kernel_root);
            }

            // Compiler fence to prevent reordering
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

            // Update per-CPU tracking AFTER CR3 switch
            set_current_vspace_tracking(kernel_tracking);

            unsafe { restore_irq(irq_flag) };

            // Use deactivate_nosched + centralized finish_deactivate
            unsafe {
                use crate::mm::vspace::DeactivateResult;
                match (*self.tracking).deactivate_nosched(cpu_id) {
                    DeactivateResult::BecameInactive => {
                        // Use with_lock for non-blocking wakeup
                        crate::sched::scheduler::scheduler().with_lock(|s| {
                            s.finish_deactivate(&*self.tracking);
                        });
                    }
                    _ => {}
                }
            }
        }

        // Mark as dying (sends IPI to active cores)
        unsafe {
            (*self.tracking).mark_dying(cpu_id);
        }

        // Free page tables
        unsafe {
            self.free_page_tables_recursive(self.root);
        }

        // Mark as dead
        unsafe {
            (*self.tracking).mark_dead();
        }

        // CRITICAL: Move tracking to deferred free list
        // This prevents UAF from pending deactivate processing
        unsafe {
            defer_free_tracking(self.tracking);
        }

        // Clear tracking pointer to prevent double-free
        self.tracking = core::ptr::null_mut();
    }

    unsafe fn free_page_tables_recursive(&mut self, pml4_addr: PhysAddr) {
        unsafe {
            if pml4_addr == KERNEL_PML4_PHYS {
                return;
            }

            let pml4_virt = phys_to_virt(pml4_addr) as *const PageTable;
            let pml4 = &*pml4_virt;

            for i in 0..USER_PML4_MAX {
                let pml4e = pml4.entry(i);
                if pml4e & ENTRY_PRESENT == 0 {
                    continue;
                }
                let pdpt_addr = pml4e & ENTRY_ADDR_MASK;
                self.free_pdpt_recursive(pdpt_addr);
            }

            free_frame(pml4_addr);
        }
    }

    unsafe fn free_pdpt_recursive(&mut self, pdpt_addr: PhysAddr) {
        unsafe {
            let pdpt_virt = phys_to_virt(pdpt_addr) as *const PageTable;
            let pdpt = &*pdpt_virt;

            for i in 0..512 {
                let pdpte = pdpt.entry(i);
                if pdpte & ENTRY_PRESENT == 0 {
                    continue;
                }
                if pdpte & (1 << 7) != 0 {
                    continue; // 1GB page (data)
                }
                let pd_addr = pdpte & ENTRY_ADDR_MASK;
                self.free_pd_recursive(pd_addr);
            }

            free_frame(pdpt_addr);
        }
    }

    unsafe fn free_pd_recursive(&mut self, pd_addr: PhysAddr) {
        unsafe {
            let pd_virt = phys_to_virt(pd_addr) as *const PageTable;
            let pd = &*pd_virt;

            for i in 0..512 {
                let pde = pd.entry(i);
                if pde & ENTRY_PRESENT == 0 {
                    continue;
                }
                if pde & (1 << 7) != 0 {
                    continue; // 2MB page (data)
                }
                let pt_addr = pde & ENTRY_ADDR_MASK;
                let pt_virt = phys_to_virt(pt_addr) as *const PageTable;
                let pt = &*pt_virt;
                for j in 0..512 {
                    let pte = pt.entry(j);
                    if pte & ENTRY_PRESENT == 0 {
                        continue;
                    }
                    super::release_frame_mapping(pte & ENTRY_ADDR_MASK);
                }
                free_frame(pt_addr);
            }

            free_frame(pd_addr);
        }
    }

    /// Walk user-half page tables starting from `start_vaddr`.
    /// Returns up to `max_entries` mapped pages as (vaddr, phys, flags) tuples.
    /// `next_vaddr` is set to the next address to continue scanning (0 if done).
    pub fn walk_pages(
        &self,
        start_vaddr: VirtAddr,
        max_entries: usize,
    ) -> (usize, VirtAddr, [(VirtAddr, PhysAddr, u64); 6]) {
        let mut results = [(0u64, 0u64, 0u64); 6];
        let max = if max_entries > 6 { 6 } else { max_entries };
        let mut count = 0usize;
        let mut vaddr = start_vaddr & !0xFFF; // Align to page

        let pml4 = unsafe { &*self.pml4() };

        // Only walk user half (PML4 entries 0..255)
        let start_pml4 = Self::pml4_index(vaddr);

        for pml4_idx in start_pml4..USER_PML4_MAX {
            let pml4e = pml4.entry(pml4_idx);
            if pml4e & ENTRY_PRESENT == 0 {
                // Skip to next PML4 region
                vaddr = ((pml4_idx + 1) as u64) << 39;
                continue;
            }
            let pdpt = unsafe { &*(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *const PageTable) };

            let start_pdpt = if pml4_idx == start_pml4 { Self::pdpt_index(vaddr) } else { 0 };

            for pdpt_idx in start_pdpt..512 {
                let pdpte = pdpt.entry(pdpt_idx);
                if pdpte & ENTRY_PRESENT == 0 {
                    vaddr = ((pml4_idx as u64) << 39) | ((pdpt_idx + 1) as u64) << 30;
                    continue;
                }
                // Skip 1GB huge pages
                if pdpte & (1 << 7) != 0 {
                    vaddr = ((pml4_idx as u64) << 39) | ((pdpt_idx + 1) as u64) << 30;
                    continue;
                }
                let pd = unsafe { &*(phys_to_virt(pdpte & ENTRY_ADDR_MASK) as *const PageTable) };

                let start_pd = if pml4_idx == start_pml4 && pdpt_idx == start_pdpt {
                    Self::pd_index(vaddr)
                } else { 0 };

                for pd_idx in start_pd..512 {
                    let pde = pd.entry(pd_idx);
                    if pde & ENTRY_PRESENT == 0 {
                        vaddr = ((pml4_idx as u64) << 39) | ((pdpt_idx as u64) << 30) |
                                ((pd_idx + 1) as u64) << 21;
                        continue;
                    }
                    // Skip 2MB huge pages
                    if pde & (1 << 7) != 0 {
                        vaddr = ((pml4_idx as u64) << 39) | ((pdpt_idx as u64) << 30) |
                                ((pd_idx + 1) as u64) << 21;
                        continue;
                    }
                    let pt = unsafe { &*(phys_to_virt(pde & ENTRY_ADDR_MASK) as *const PageTable) };

                    let start_pt = if pml4_idx == start_pml4 && pdpt_idx == start_pdpt &&
                                      pd_idx == start_pd {
                        Self::pt_index(vaddr)
                    } else { 0 };

                    for pt_idx in start_pt..512 {
                        let pte = pt.entry(pt_idx);
                        if pte & ENTRY_PRESENT == 0 {
                            continue;
                        }

                        let page_vaddr = ((pml4_idx as u64) << 39) |
                                          ((pdpt_idx as u64) << 30) |
                                          ((pd_idx as u64) << 21) |
                                          ((pt_idx as u64) << 12);
                        let page_phys = pte & ENTRY_ADDR_MASK;
                        let page_flags = pte & !ENTRY_ADDR_MASK;

                        results[count] = (page_vaddr, page_phys, page_flags);
                        count += 1;

                        if count >= max {
                            // Set next_vaddr to the page after this one
                            let next = page_vaddr + PAGE_SIZE as u64;
                            return (count, next, results);
                        }
                    }
                }
            }
        }

        // Done scanning
        (count, 0, results)
    }
}

impl Drop for VSpace {
    fn drop(&mut self) {
        // VSpace being dropped - tracking is NOT freed here
        // It was already moved to deferred free list in cleanup()
        // If cleanup() wasn't called, this is a leak (by design for safety)
    }
}

/// Page mapping flags
#[derive(Clone, Copy)]
pub struct PageFlags {
    pub writable: bool,
    pub user: bool,
    pub executable: bool,
    pub cache_disable: bool,
    pub write_through: bool,
    pub cow: bool,
}

impl PageFlags {
    pub const KERNEL_RO: Self = Self {
        writable: false,
        user: false,
        executable: false,
        cache_disable: false,
        write_through: false,
        cow: false,
    };

    pub const KERNEL_RW: Self = Self {
        writable: true,
        user: false,
        executable: false,
        cache_disable: false,
        write_through: false,
        cow: false,
    };

    pub const KERNEL_RX: Self = Self {
        writable: false,
        user: false,
        executable: true,
        cache_disable: false,
        write_through: false,
        cow: false,
    };

    pub const USER_RO: Self = Self {
        writable: false,
        user: true,
        executable: false,
        cache_disable: false,
        write_through: false,
        cow: false,
    };

    pub const USER_RW: Self = Self {
        writable: true,
        user: true,
        executable: false,
        cache_disable: false,
        write_through: false,
        cow: false,
    };

    pub const USER_RX: Self = Self {
        writable: false,
        user: true,
        executable: true,
        cache_disable: false,
        write_through: false,
        cow: false,
    };
}

#[derive(Debug)]
pub enum VSpaceError {
    Alignment,
    AlreadyMapped,
    NotMapped,
    OutOfMemory,
}

impl core::fmt::Display for VSpaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VSpaceError::Alignment => write!(f, "Address not aligned to page boundary"),
            VSpaceError::AlreadyMapped => write!(f, "Page is already mapped"),
            VSpaceError::NotMapped => write!(f, "Page is not mapped"),
            VSpaceError::OutOfMemory => write!(f, "Out of memory for page table allocation"),
        }
    }
}

/// Save interrupt flag and disable IRQs
#[inline(always)]
pub unsafe fn save_irq_disable() -> u64 {
    unsafe {
        let mut rflags: u64;
        core::arch::asm!(
            "pushfq; pop {}",
            out(reg) rflags,
            options(nomem, nostack)
        );
        core::arch::asm!("cli", options(nomem, nostack));
        rflags
    }
}

/// Restore interrupt flag
#[inline(always)]
pub unsafe fn restore_irq(rflags: u64) {
    unsafe {
        if rflags & (1 << 9) != 0 {
            core::arch::asm!("sti", options(nomem, nostack));
        }
    }
}
