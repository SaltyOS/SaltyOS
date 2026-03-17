//! Virtual Address Space
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{alloc_frame, phys_to_virt, PhysAddr, SpinLock, VirtAddr, PAGE_SIZE};
use crate::arch::x86_64::paging::PageTable;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

/// Page table entry flag bits
const ENTRY_PRESENT: u64 = 1 << 0;
const ENTRY_WRITABLE: u64 = 1 << 1;
const ENTRY_USER: u64 = 1 << 2;
const ENTRY_WRITE_THROUGH: u64 = 1 << 3;
const ENTRY_CACHE_DISABLE: u64 = 1 << 4;
const ENTRY_COW: u64 = 1 << 9;
/// Demand page marker: PTE with PRESENT=0, DEMAND=1 triggers kernel fast-path
/// allocation on #PF instead of IPC to mmsrv. Bit 10 is OS-available when PRESENT=0.
const ENTRY_DEMAND: u64 = 1 << 10;
const ENTRY_NO_EXECUTE: u64 = 1 << 63;

/// Physical address mask in page table entry
const ENTRY_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// User PML4 range: entries 0..255 (lower half)
const USER_PML4_MAX: usize = 256;

/// Maximum number of entries returned by one `walk_pages` call.
const WALK_MAX_RESULTS: usize = 48;

/// Maximum number of CPUs (from arch module)
use crate::arch::MAX_CPUS;

/// Maximum number of deferred free entries
const MAX_DEFERRED: usize = 256;

/// Number of mapped pages at/above which range mapping uses one-shot full TLB
/// flush instead of per-page invalidation.
const RANGE_TLB_GLOBAL_THRESHOLD: usize = 8;

/// Static VSpaceTracking storage for the kernel VSpace (never destroyed).
///
/// User VSpaces have their tracking embedded in the untyped allocation
/// (seL4-style: all kernel object metadata lives in untyped memory).
static mut KERNEL_VSPACE_TRACKING_STORAGE: VSpaceTracking = VSpaceTracking::new(0);

/// Byte offset of VSpaceTracking within a VSpace untyped allocation.
///
/// VSpace layout in untyped memory:
///   [0 .. PAGE_SIZE)       = PML4 page table root (4KB, page-aligned)
///   [PAGE_SIZE .. PAGE_SIZE + TRACKING_SIZE) = VSpaceTracking
pub const VSPACE_TRACKING_OFFSET: usize = PAGE_SIZE;

/// Size of VSpaceTracking rounded up to 64-byte alignment.
pub const VSPACE_TRACKING_SIZE: usize = {
    let raw = core::mem::size_of::<VSpaceTracking>();
    (raw + 63) & !63
};

/// Total untyped allocation size for a VSpace object (PML4 + embedded tracking).
pub const VSPACE_OBJECT_SIZE: usize = PAGE_SIZE + VSPACE_TRACKING_SIZE;

/// Derive VSpaceTracking pointer from a VSpace's PML4 physical address.
///
/// # Safety
/// The PML4 must have been allocated with `VSPACE_OBJECT_SIZE` bytes from untyped,
/// so that the tracking area at `pml4_phys + PAGE_SIZE` is valid memory.
#[inline]
pub unsafe fn tracking_from_vspace_phys(pml4_phys: PhysAddr) -> *mut VSpaceTracking {
    phys_to_virt(pml4_phys + VSPACE_TRACKING_OFFSET as u64) as *mut VSpaceTracking
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

/// Number of CPUs currently online (updated by scheduler init)
static ONLINE_CPU_COUNT: AtomicU32 = AtomicU32::new(1);

/// Set the online CPU count (called from scheduler init/init_cpu)
pub fn set_online_cpu_count(count: u32) {
    ONLINE_CPU_COUNT.store(count, Ordering::Release);
}

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
/// Memory management: VSpaceTracking is embedded in the VSpace's untyped
/// allocation at offset PAGE_SIZE from the PML4 root (seL4-style: all kernel
/// object metadata lives in untyped memory). The kernel VSpace uses static
/// storage instead. Deferred free ensures no CPU references tracking after
/// removal from the deferred list.
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

    /// Number of online CPUs when this tracking was retired.
    /// Only iterate this many CPUs when checking quiescent state.
    retire_online_cpus: AtomicU32,

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
            retire_online_cpus: AtomicU32::new(0),
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
    unsafe {
        KERNEL_PML4_PHYS = kernel_pml4;
        // Initialize kernel VSpaceTracking in static storage (not from untyped)
        let storage = &raw mut KERNEL_VSPACE_TRACKING_STORAGE;
        (*storage) = VSpaceTracking::new(kernel_pml4);
        KERNEL_VSPACE_TRACKING = storage as *const VSpaceTracking;
        let cpu_id = crate::arch::current_cpu() as usize;
        CURRENT_VSPACE_TRACKING[cpu_id] = storage as *const VSpaceTracking;
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

        // Snapshot only online CPUs — non-existent CPUs never advance generation
        let online = ONLINE_CPU_COUNT.load(Ordering::Acquire) as usize;
        (*tracking).retire_online_cpus.store(online as u32, Ordering::Release);
        for cpu in 0..online {
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
    unsafe {
        let lock = &raw const DEFERRED_FREE_LOCK;
        (*lock).lock();

        // Scan for entries that have reached quiescent state
        let mut write_idx = 0;
        for read_idx in 0..DEFERRED_FREE_COUNT {
            let tracking = DEFERRED_FREE_LIST[read_idx];
            if tracking.is_null() {
                continue;
            }

            // Check quiescent state conditions
            let mut can_free = true;

            // Condition 1: All CPUs (online at retire time) passed their snapshot
            let online_at_retire = (*tracking).retire_online_cpus.load(Ordering::Acquire) as usize;
            for cpu in 0..online_at_retire {
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
                // Remove from deferred list. No pool deallocation needed:
                // tracking memory is embedded in the VSpace's untyped
                // allocation (seL4-style). Memory reclaimed when untyped
                // parent is revoked.
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
}

/// Check if IRQs are disabled
#[inline]
fn irqs_disabled() -> bool {
    let rflags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq; pop {}",
            out(reg) rflags,
            // pushfq/pop touches the current stack, so this asm must not use
            // `nostack` (and it does access memory via the stack).
            options(preserves_flags)
        );
    }
    (rflags & (1 << 9)) == 0
}

/// Lock-free SPSC ring: mmsrv produces pre-allocated frames, kernel consumes during COW fast-path.
/// Fits in a single 4K page.
#[repr(C)]
pub struct CowPool {
    /// Next entry for kernel to consume
    pub head: AtomicU16,
    /// Entries filled up to here by mmsrv
    pub tail: AtomicU16,
    _pad: [u8; 4],
    /// Pre-allocated frame physical addresses
    pub entries: [CowPoolEntry; 510],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CowPoolEntry {
    pub phys_addr: u64,
}

/// Kernel produces -> mmsrv consumes: records which pool entries were used and for what vaddr.
/// Fits in a single 4K page.
#[repr(C)]
pub struct CowNotifRing {
    /// Next entry for kernel to write
    pub head: AtomicU32,
    /// Next entry for mmsrv to read
    pub tail: AtomicU32,
    /// Notification entries
    pub entries: [CowNotifEntry; 510],
    /// Set by kernel when notification ring is full and an entry was skipped.
    /// mmsrv reads and clears this to trigger reconciliation.
    pub overflow: AtomicU8,
    _pad2: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CowNotifEntry {
    /// Virtual address >> 12 (supports 44-bit address space)
    pub vaddr_page: u32,
    /// Which pool entry was consumed
    pub pool_idx: u16,
    _pad: u16,
}

/// Virtual address space (wraps page table root)
#[repr(C)]
pub struct VSpace {
    /// Kernel object header (must be first for refcount access)
    pub header: crate::cap::KernelObject,
    /// Physical address of PML4
    root: PhysAddr,
    /// VSpaceTracking pointer — embedded in untyped allocation at root + PAGE_SIZE
    /// (seL4-style: all kernel object metadata lives in untyped memory).
    /// For kernel VSpace, points to static storage.
    tracking: *mut VSpaceTracking,
    /// Per-VSpace lock for page table modifications (map/unmap/install_page_table)
    lock: SpinLock,
    /// Physical address of CowPool page (0 = pool disabled)
    cow_pool_phys: PhysAddr,
    /// Physical address of CowNotifRing page
    cow_notif_phys: PhysAddr,
    /// Notification object to signal mmsrv after pool consumption
    cow_notif_ntfn: *mut crate::ipc::Notification,
}

impl VSpace {
    /// Create a new VSpace with an externally-provided VSpaceTracking pointer.
    ///
    /// For user VSpaces, `tracking` points to the embedded tracking area
    /// within the untyped allocation (at `pml4_addr + PAGE_SIZE`).
    /// For the kernel VSpace, `tracking` points to static storage.
    ///
    /// # Safety
    /// The tracking pointer must be valid and initialized with `VSpaceTracking::new()`.
    pub fn new(pml4_addr: PhysAddr, tracking: *mut VSpaceTracking) -> Self {
        Self {
            header: crate::cap::KernelObject::new(
                crate::cap::ObjectType::VSpace,
                0,
            ),
            root: pml4_addr,
            tracking,
            lock: SpinLock::new(),
            cow_pool_phys: 0,
            cow_notif_phys: 0,
            cow_notif_ntfn: core::ptr::null_mut(),
        }
    }

    pub fn root(&self) -> PhysAddr {
        self.root
    }

    pub fn tracking(&self) -> &VSpaceTracking {
        unsafe { &*self.tracking }
    }

    /// Get the COW pool physical address (0 if not configured).
    pub fn cow_pool_phys(&self) -> PhysAddr {
        self.cow_pool_phys
    }

    /// Get the COW pool physical address under VSpace.lock.
    ///
    /// Use this from contexts that do not already hold the lock.
    pub fn cow_pool_phys_locked(&self) -> PhysAddr {
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();
        let phys = self.cow_pool_phys;
        self.lock.unlock();
        unsafe { restore_irq(irq) };
        phys
    }

    /// Set the COW pool physical address.
    ///
    /// Acquires VSpace.lock to synchronize with the fault handler.
    pub fn set_cow_pool_phys(&mut self, phys: PhysAddr) {
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();
        self.cow_pool_phys = phys;
        self.lock.unlock();
        unsafe { restore_irq(irq) };
    }

    /// Configure the COW notification ring and notification object.
    ///
    /// Acquires VSpace.lock to synchronize with the fault handler.
    pub fn set_cow_notif(
        &mut self,
        ring_phys: PhysAddr,
        ntfn: *mut crate::ipc::Notification,
    ) {
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();
        self.cow_notif_phys = ring_phys;
        self.cow_notif_ntfn = ntfn;
        self.lock.unlock();
        unsafe { restore_irq(irq) };
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

                // SAFETY: retain before the PDE is visible so the frame cannot
                // be reclaimed between alloc_frame() and the PDE write.
                super::retain_frame_mapping(new_frame);
                // Mark as page-table frame and kernel-runtime: prevents accidental
                // reclamation via refcount bugs and exposure via untyped retype.
                super::mark_frame_pt_owned(new_frame);
                super::mark_frame_kernel_runtime(new_frame);
                crate::ktrace!({
                    _g.puts("[PT_ALLOC] seq=");
                    _g.hex(crate::arch::current_invoke_seq());
                    _g.puts(" vaddr=");
                    _g.hex(vaddr);
                    _g.puts(" level=");
                    _g.hex(current_level as u64);
                    _g.puts(" frame=");
                    _g.hex(new_frame);
                    _g.putc(b'\n');
                });
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

    /// Send full TLB flush IPI to all remote CPUs that have this VSpace loaded.
    fn tlb_shootdown_all(&self) {
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
                        unsafe {
                            crate::arch::send_ipi(target, crate::arch::IpiKind::TlbShootdownAll);
                        }
                    }
                }
            }
        }
    }

    /// Check whether this VSpace is currently active on the calling CPU.
    #[inline]
    fn active_on_current_cpu(&self) -> bool {
        if self.tracking.is_null() {
            return false;
        }
        let cpu_id = crate::arch::current_cpu() as usize;
        let word = cpu_id / 32;
        let bit = cpu_id % 32;
        let tracking = unsafe { &*self.tracking };
        if word >= tracking.active_mask.len() {
            return false;
        }
        (tracking.active_mask[word].load(Ordering::Acquire) & (1 << bit)) != 0
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

    /// Map a contiguous page range and return how many pages were mapped.
    ///
    /// Stops on the first mapping failure and returns the count mapped so far.
    /// This mirrors the partial-success contract used by VSPACE_MAP_DEVICE_RANGE.
    pub fn map_range_partial(
        &mut self,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        count: usize,
        flags: PageFlags,
    ) -> Result<usize, VSpaceError> {
        if count == 0 {
            return Ok(0);
        }
        if virt_start & (PAGE_SIZE as u64 - 1) != 0 || phys_start & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        let page_size = PAGE_SIZE as u64;
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let mut mapped = 0usize;
        let entry_flags = Self::flags_to_entry_flags(flags);
        let mut virt = virt_start;
        let mut phys = phys_start;

        for _ in 0..count {
            if self.ensure_table(virt, 1, flags.user).is_err() {
                break;
            }
            if let Some(entry) = self.read_entry(virt, 1) {
                if entry & ENTRY_PRESENT != 0 {
                    break;
                }
            }
            if self.write_entry(virt, 1, phys | entry_flags).is_err() {
                break;
            }
            super::retain_frame_mapping(phys);
            mapped += 1;

            virt = match virt.checked_add(page_size) {
                Some(v) => v,
                None => break,
            };
            phys = match phys.checked_add(page_size) {
                Some(p) => p,
                None => break,
            };
        }

        if mapped > RANGE_TLB_GLOBAL_THRESHOLD {
            if self.active_on_current_cpu() {
                let cr3 = crate::arch::x86_64::paging::read_cr3();
                unsafe {
                    crate::arch::x86_64::paging::write_cr3(cr3);
                }
            }
            self.tlb_shootdown_all();
        } else if mapped > 0 {
            let do_local_flush = self.active_on_current_cpu();
            let mut flush_virt = virt_start;
            for i in 0..mapped {
                if do_local_flush {
                    crate::arch::x86_64::paging::invlpg(flush_virt);
                }
                self.tlb_shootdown(flush_virt);
                if i + 1 < mapped {
                    flush_virt = match flush_virt.checked_add(page_size) {
                        Some(v) => v,
                        None => break,
                    };
                }
            }
        }

        self.lock.unlock();
        unsafe { restore_irq(irq) };
        Ok(mapped)
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
            // Protect the installed PT frame from premature reclamation if the
            // user-held Frame capability is later deleted (release_frame_object).
            super::retain_frame_mapping(pt_phys);
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

            // Demand PTE (PRESENT=0, DEMAND=1): no frame to release, just clear
            if entry & ENTRY_PRESENT == 0 && entry & ENTRY_DEMAND != 0 {
                self.write_entry(virt, 1, 0)?;
                return Ok(());
            }

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

    /// Change the protection flags on an already-mapped page.
    ///
    /// The physical frame stays the same; only PTE flag bits are updated.
    /// Issues local `invlpg` + TLB shootdown to remote CPUs.
    pub fn protect(&mut self, virt: VirtAddr, flags: PageFlags) -> Result<(), VSpaceError> {
        if virt & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let result = (|| {
            let entry = self.read_entry(virt, 1).ok_or(VSpaceError::NotMapped)?;

            // Demand PTE (PRESENT=0, DEMAND=1): update stored flags
            if entry & ENTRY_PRESENT == 0 && entry & ENTRY_DEMAND != 0 {
                let entry_flags = Self::flags_to_entry_flags(flags);
                let new_demand = (entry_flags & !ENTRY_PRESENT) | ENTRY_DEMAND;
                self.write_entry(virt, 1, new_demand)?;
                return Ok(());
            }

            if entry & ENTRY_PRESENT == 0 {
                return Err(VSpaceError::NotMapped);
            }
            let phys = entry & ENTRY_ADDR_MASK;
            let new_entry = phys | Self::flags_to_entry_flags(flags);
            self.write_entry(virt, 1, new_entry)?;

            // TLB invalidation inside lock scope to prevent race where another
            // CPU modifies the PTE between our unlock and shootdown, causing
            // the newer mapping to be incorrectly flushed.
            crate::arch::x86_64::paging::invlpg(virt);
            self.tlb_shootdown(virt);
            Ok(())
        })();

        self.lock.unlock();
        unsafe { restore_irq(irq) };

        result
    }

    /// Change the protection flags on a contiguous range of already-mapped pages.
    ///
    /// Acquires the VSpace lock once for the entire range. After all PTEs are
    /// updated, flushes TLB entries using the adaptive threshold strategy:
    /// large ranges (>8 pages) get a full TLB flush, small ranges get per-page
    /// `invlpg` + remote shootdown.  Pages that are not mapped (or not yet
    /// present) are silently skipped.
    ///
    /// Returns the number of pages whose flags were successfully updated.
    pub fn protect_range(
        &mut self,
        virt: VirtAddr,
        count: usize,
        flags: PageFlags,
    ) -> Result<usize, VSpaceError> {
        if virt & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let mut protected = 0usize;
        for i in 0..count {
            let addr = virt + (i as u64) * PAGE_SIZE as u64;
            let entry = match self.read_entry(addr, 1) {
                Some(e) => e,
                None => continue,
            };

            if entry & ENTRY_PRESENT == 0 && entry & ENTRY_DEMAND != 0 {
                let entry_flags = Self::flags_to_entry_flags(flags);
                let new_demand = (entry_flags & !ENTRY_PRESENT) | ENTRY_DEMAND;
                if self.write_entry(addr, 1, new_demand).is_ok() {
                    protected += 1;
                }
                continue;
            }

            if entry & ENTRY_PRESENT == 0 {
                continue;
            }

            let phys = entry & ENTRY_ADDR_MASK;
            let new_entry = phys | Self::flags_to_entry_flags(flags);
            if self.write_entry(addr, 1, new_entry).is_ok() {
                protected += 1;
            }
        }

        // Adaptive TLB flush: full flush for large ranges, per-page for small.
        if protected > RANGE_TLB_GLOBAL_THRESHOLD {
            if self.active_on_current_cpu() {
                let cr3 = crate::arch::x86_64::paging::read_cr3();
                unsafe {
                    crate::arch::x86_64::paging::write_cr3(cr3);
                }
            }
            self.tlb_shootdown_all();
        } else if protected > 0 {
            let do_local_flush = self.active_on_current_cpu();
            let page_size = PAGE_SIZE as u64;
            for i in 0..count {
                let addr = virt + (i as u64) * page_size;
                if do_local_flush {
                    crate::arch::x86_64::paging::invlpg(addr);
                }
                self.tlb_shootdown(addr);
            }
        }

        self.lock.unlock();
        unsafe { restore_irq(irq) };

        Ok(protected)
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

            // Demand PTE (PRESENT=0, DEMAND=1): copy to child as-is (no frame sharing)
            if src_entry & ENTRY_PRESENT == 0 && src_entry & ENTRY_DEMAND != 0 {
                let is_user = (src_entry & ENTRY_USER) != 0;
                dst.ensure_table(dst_vaddr, 1, is_user)?;
                if let Some(entry) = dst.read_entry(dst_vaddr, 1) {
                    if entry & ENTRY_PRESENT != 0 || entry & ENTRY_DEMAND != 0 {
                        return Err(VSpaceError::AlreadyMapped);
                    }
                }
                dst.write_entry(dst_vaddr, 1, src_entry)?;
                return Ok(());
            }

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

            // Mark as kernel-runtime: this frame was allocated by the kernel for a
            // COW copy and should not be exposed via untyped retype while in use.
            super::mark_frame_kernel_runtime(new_phys);

            unsafe {
                let src = phys_to_virt(old_phys) as *const u8;
                let dst = phys_to_virt(new_phys) as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE);
            }

            let mut new_flags = entry & !ENTRY_ADDR_MASK;
            new_flags |= ENTRY_WRITABLE;
            new_flags &= !ENTRY_COW;

            if self.write_entry(page_vaddr, 1, new_phys | new_flags).is_err() {
                super::clear_frame_kernel_runtime(new_phys);
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

    /// Resolve a COW fault using a caller-provided physical frame.
    ///
    /// Called by mmsrv via VSPACE_COW_RESOLVE invoke. The physical frame
    /// comes from a Frame capability (untyped-owned), so lifetime is
    /// managed by the capability system, not the kernel frame allocator.
    ///
    /// Returns:
    /// - `Ok(())` on success (COW resolved, old content copied to new_phys)
    /// - `Err(NotMapped)` if page is not present
    /// - `Err(AlreadyMapped)` if page is present but NOT COW (already resolved)
    /// - `Err(OutOfMemory)` if write_entry fails
    pub fn resolve_cow_with_frame(
        &mut self,
        vaddr: VirtAddr,
        new_phys: PhysAddr,
        _flags: PageFlags,
    ) -> Result<(), VSpaceError> {
        let page_vaddr = vaddr & !((PAGE_SIZE as u64) - 1);

        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let result = (|| {
            let entry = self.read_entry(page_vaddr, 1).ok_or(VSpaceError::NotMapped)?;

            // Not present -> NotMapped
            if entry & ENTRY_PRESENT == 0 {
                return Err(VSpaceError::NotMapped);
            }

            // Present but not COW — distinguish race from genuine RO
            if entry & ENTRY_COW == 0 {
                if entry & ENTRY_WRITABLE != 0 {
                    // Race: another CPU already resolved this COW page
                    return Err(VSpaceError::AlreadyMapped);
                } else {
                    // Not COW, genuinely read-only (e.g. mprotect PROT_READ)
                    return Err(VSpaceError::NotCow);
                }
            }

            let old_phys = entry & ENTRY_ADDR_MASK;

            // Copy 4K page content from old to new frame
            unsafe {
                // SAFETY: Both physical addresses are valid page-aligned frames.
                // old_phys is the existing mapped frame, new_phys comes from a
                // validated Frame capability. phys_to_virt returns the direct-map
                // virtual address for kernel access.
                let src = phys_to_virt(old_phys) as *const u8;
                let dst = phys_to_virt(new_phys) as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE);
            }

            // Build new PTE: set WRITABLE, clear COW, use new physical address
            let mut new_flags = entry & !ENTRY_ADDR_MASK;
            new_flags |= ENTRY_WRITABLE;
            new_flags &= !ENTRY_COW;

            if self.write_entry(page_vaddr, 1, new_phys | new_flags).is_err() {
                return Err(VSpaceError::NotMapped);
            }

            // TLB invalidation BEFORE refcount changes
            crate::arch::x86_64::paging::invlpg(page_vaddr);
            self.tlb_shootdown(page_vaddr);

            // Update frame mapping refcounts
            super::retain_frame_mapping(new_phys);
            super::release_frame_mapping(old_phys);

            Ok(())
        })();

        self.lock.unlock();
        unsafe { restore_irq(irq) };
        result
    }

    /// Fast-path COW resolution using a pre-allocated frame pool.
    ///
    /// Returns:
    /// - `Ok(true)` -- COW resolved via pool (fast path)
    /// - `Ok(false)` -- pool not configured or empty (fall through to mmsrv IPC)
    /// - `Err(...)` -- fault is not a COW fault
    pub fn handle_cow_fault_pooled(
        &mut self,
        fault_addr: VirtAddr,
        error_code: u64,
    ) -> Result<bool, VSpaceError> {
        // Must be a present + write + user page fault
        if (error_code & 0x7) != 0x7 {
            return Ok(false);
        }

        let page_vaddr = fault_addr & !((PAGE_SIZE as u64) - 1);

        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        // Pool not configured -- fall through to mmsrv IPC.
        // Check inside VSpace.lock to synchronize with set_cow_pool_phys().
        // Require both pool AND notif — if notif is missing, the kernel would
        // consume pool entries without writing notifications, so mmsrv never
        // learns about consumed frames.
        if self.cow_pool_phys == 0 || self.cow_notif_phys == 0 {
            self.lock.unlock();
            unsafe { restore_irq(irq) };
            return Ok(false);
        }

        // Captured outside the lock critical section to avoid
        // lock ordering violation: signal() → enqueue() → sched.lock_cpu,
        // but VSpace.lock must nest INSIDE sched.lock_cpu.
        let mut signal_ntfn: *mut crate::ipc::Notification = core::ptr::null_mut();

        let result = (|| {
            let entry = self.read_entry(page_vaddr, 1).ok_or(VSpaceError::NotMapped)?;
            if entry & ENTRY_PRESENT == 0 || entry & ENTRY_COW == 0 {
                return Ok(false);
            }

            // Read pool state
            unsafe {
                // SAFETY: cow_pool_phys was set via validated Frame cap in VSPACE_SET_COW_POOL.
                // The page remains valid for the lifetime of the VSpace.
                let pool = phys_to_virt(self.cow_pool_phys) as *const CowPool;
                let head = (*pool).head.load(Ordering::Acquire);
                let tail = (*pool).tail.load(Ordering::Acquire);

                if head == tail {
                    // Pool empty -- fall through to mmsrv IPC
                    return Ok(false);
                }

                // Pre-check: notification ring must have space before we
                // consume a pool entry. If full, fall back to mmsrv IPC
                // which will drain the ring. VSpace.lock serializes, so
                // the space check is still valid at write time.
                if self.cow_notif_phys != 0 {
                    // SAFETY: cow_notif_phys was set via validated Frame cap.
                    let ring = phys_to_virt(self.cow_notif_phys) as *mut CowNotifRing;
                    let ring_head = (*ring).head.load(Ordering::Relaxed);
                    let ring_tail = (*ring).tail.load(Ordering::Acquire);
                    if ring_head.wrapping_sub(ring_tail) >= 510 {
                        return Ok(false);
                    }
                }

                let idx = (head % 510) as usize;
                let new_phys = (*pool).entries[idx].phys_addr;

                // Advance head (kernel is sole consumer, VSpace lock serializes)
                // SAFETY: pool is valid and kernel is sole writer of head.
                (*(pool as *mut CowPool)).head.store(head.wrapping_add(1), Ordering::Release);

                let old_phys = entry & ENTRY_ADDR_MASK;

                // SAFETY: Both frames are valid physical pages accessible via direct map.
                let src = phys_to_virt(old_phys) as *const u8;
                let dst = phys_to_virt(new_phys) as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE);

                // Update PTE
                let mut new_flags = entry & !ENTRY_ADDR_MASK;
                new_flags |= ENTRY_WRITABLE;
                new_flags &= !ENTRY_COW;

                if self.write_entry(page_vaddr, 1, new_phys | new_flags).is_err() {
                    return Err(VSpaceError::NotMapped);
                }

                crate::arch::x86_64::paging::invlpg(page_vaddr);
                self.tlb_shootdown(page_vaddr);

                super::retain_frame_mapping(new_phys);
                super::release_frame_mapping(old_phys);

                // Write notification ring entry
                if self.cow_notif_phys != 0 {
                    // SAFETY: cow_notif_phys was set via validated Frame cap.
                    let ring = phys_to_virt(self.cow_notif_phys) as *mut CowNotifRing;
                    let ring_head = (*ring).head.load(Ordering::Relaxed);

                    // Ring space is guaranteed by the pre-check above.
                    let ring_idx = (ring_head % 510) as usize;
                    (*ring).entries[ring_idx] = CowNotifEntry {
                        vaddr_page: (page_vaddr >> 12) as u32,
                        pool_idx: head,
                        _pad: 0,
                    };
                    (*ring).head.store(ring_head.wrapping_add(1), Ordering::Release);

                    // Capture notification pointer; signal after lock release.
                    if !self.cow_notif_ntfn.is_null() {
                        signal_ntfn = self.cow_notif_ntfn;
                    }
                }
            }

            Ok(true)
        })();

        self.lock.unlock();

        // Signal mmsrv outside VSpace.lock to maintain lock ordering:
        // signal() may acquire sched.lock_cpu which must not nest
        // inside VSpace.lock.
        if !signal_ntfn.is_null() {
            if let Ok(true) = result {
                // SAFETY: cow_notif_ntfn was set via validated Notification cap
                // and remains valid for the lifetime of the VSpace.
                unsafe { (*signal_ntfn).signal(1) };
            }
        }

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

    /// Install a demand-page PTE: PRESENT=0, ENTRY_DEMAND=1, flags stored.
    ///
    /// On first user access, #PF → `handle_demand_fault` allocates a zero-fill
    /// frame and makes the page PRESENT, avoiding IPC to mmsrv.
    pub fn map_demand(
        &mut self,
        virt: VirtAddr,
        flags: PageFlags,
    ) -> Result<(), VSpaceError> {
        if virt & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let result = (|| {
            self.ensure_table(virt, 1, flags.user)?;

            // Check if already mapped (present or demand)
            if let Some(entry) = self.read_entry(virt, 1) {
                if entry & ENTRY_PRESENT != 0 || entry & ENTRY_DEMAND != 0 {
                    return Err(VSpaceError::AlreadyMapped);
                }
            }

            // Build demand PTE: NOT present, DEMAND bit set, flags stored
            let entry_flags = Self::flags_to_entry_flags(flags);
            // Strip PRESENT so the PTE triggers #PF; keep all other flags.
            let demand_entry = (entry_flags & !ENTRY_PRESENT) | ENTRY_DEMAND;
            self.write_entry(virt, 1, demand_entry)?;

            Ok(())
        })();

        self.lock.unlock();
        unsafe { restore_irq(irq) };
        result
    }

    /// Install demand-page PTEs for a contiguous range.
    ///
    /// Returns the number of pages successfully set up.
    pub fn map_demand_range(
        &mut self,
        virt_start: VirtAddr,
        count: usize,
        flags: PageFlags,
    ) -> Result<usize, VSpaceError> {
        if count == 0 {
            return Ok(0);
        }
        if virt_start & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        let page_size = PAGE_SIZE as u64;
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let entry_flags = Self::flags_to_entry_flags(flags);
        let demand_entry = (entry_flags & !ENTRY_PRESENT) | ENTRY_DEMAND;

        let mut mapped = 0usize;
        let mut virt = virt_start;

        for _ in 0..count {
            if self.ensure_table(virt, 1, flags.user).is_err() {
                break;
            }
            if let Some(entry) = self.read_entry(virt, 1) {
                if entry & ENTRY_PRESENT != 0 || entry & ENTRY_DEMAND != 0 {
                    break;
                }
            }
            if self.write_entry(virt, 1, demand_entry).is_err() {
                break;
            }
            mapped += 1;
            virt = match virt.checked_add(page_size) {
                Some(v) => v,
                None => break,
            };
        }

        self.lock.unlock();
        unsafe { restore_irq(irq) };
        Ok(mapped)
    }

    /// Handle a demand-page fault: allocate a zero-fill frame and make
    /// the PTE PRESENT.
    ///
    /// Returns `Ok(true)` if the fault was handled (demand PTE found and resolved).
    /// Returns `Ok(false)` if the PTE is not a demand page (caller should try
    /// other fault handlers or IPC fallback).
    ///
    /// Lock ordering: VSpace.lock → MM_LOCK (alloc_frame) — matches existing ordering.
    pub fn handle_demand_fault(
        &mut self,
        fault_addr: VirtAddr,
        _error_code: u64,
    ) -> Result<bool, VSpaceError> {
        let page_vaddr = fault_addr & !((PAGE_SIZE as u64) - 1);

        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let result = (|| {
            let entry = match self.read_entry(page_vaddr, 1) {
                Some(e) => e,
                None => return Ok(false),
            };

            // Already present — another CPU resolved this demand fault concurrently
            if entry & ENTRY_PRESENT != 0 {
                return Ok(false);
            }
            // Not a demand page — let other fault handlers deal with it
            if entry & ENTRY_DEMAND == 0 {
                return Ok(false);
            }

            // Allocate a zero-fill frame
            let new_phys = match alloc_frame() {
                Some(p) => p,
                None => {
                    crate::serial_puts_raw("[MM] demand fault OOM at vaddr=0x");
                    crate::serial_hex_raw(page_vaddr);
                    crate::serial_puts_raw("\n");
                    return Err(VSpaceError::OutOfMemory);
                }
            };
            // SAFETY: phys_to_virt returns kernel-mapped address for the frame
            unsafe {
                core::ptr::write_bytes(phys_to_virt(new_phys) as *mut u8, 0, PAGE_SIZE);
            }
            super::mark_frame_kernel_runtime(new_phys);

            // Build final PTE: restore original flags, add PRESENT, clear DEMAND
            let new_entry = (entry & !ENTRY_DEMAND) | ENTRY_PRESENT | new_phys;
            if self.write_entry(page_vaddr, 1, new_entry).is_err() {
                super::clear_frame_kernel_runtime(new_phys);
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

            // Do NOT free the PML4 frame — it was carved from untyped memory
            // (init_vspace_metadata in untyped.rs:377), not allocated from the
            // frame allocator. Its lifetime is managed by the parent untyped's
            // watermark. Freeing it would corrupt the frame allocator bitmap.
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

            // Clear PT-ownership flags before releasing — these flags were set in
            // ensure_table() to prevent accidental refcount-driven reclamation.
            super::clear_frame_pt_owned(pdpt_addr);
            super::clear_frame_kernel_runtime(pdpt_addr);
            super::release_frame_mapping(pdpt_addr);
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
                // Clear PT-ownership flags before releasing PT frame.
                super::clear_frame_pt_owned(pt_addr);
                super::clear_frame_kernel_runtime(pt_addr);
                super::release_frame_mapping(pt_addr);
            }

            // Clear PT-ownership flags before releasing PD frame.
            super::clear_frame_pt_owned(pd_addr);
            super::clear_frame_kernel_runtime(pd_addr);
            super::release_frame_mapping(pd_addr);
        }
    }

    /// Walk user-half page tables starting from `start_vaddr`.
    /// Returns up to `max_entries` mapped pages as (vaddr, phys, flags) tuples.
    /// `next_vaddr` is set to the next address to continue scanning (0 if done).
    pub fn walk_pages(
        &self,
        start_vaddr: VirtAddr,
        max_entries: usize,
    ) -> (usize, VirtAddr, [(VirtAddr, PhysAddr, u64); WALK_MAX_RESULTS]) {
        let mut results = [(0u64, 0u64, 0u64); WALK_MAX_RESULTS];
        let max = if max_entries > WALK_MAX_RESULTS {
            WALK_MAX_RESULTS
        } else {
            max_entries
        };
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
    NotCow,
}

impl core::fmt::Display for VSpaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VSpaceError::Alignment => write!(f, "Address not aligned to page boundary"),
            VSpaceError::AlreadyMapped => write!(f, "Page is already mapped"),
            VSpaceError::NotMapped => write!(f, "Page is not mapped"),
            VSpaceError::OutOfMemory => write!(f, "Out of memory for page table allocation"),
            VSpaceError::NotCow => write!(f, "Page is not COW"),
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
            // pushfq/pop touches the current stack, so this asm must not use
            // `nostack` (and it does access memory via the stack).
            options(preserves_flags)
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
