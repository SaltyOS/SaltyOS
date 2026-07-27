//! Virtual Address Space
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{PAGE_SIZE, PhysAddr, SpinLock, VirtAddr, phys_to_virt, pmm_alloc};
use crate::arch::paging::PageTable;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};

/// Architecture-neutral page fault descriptor.
///
/// Each architecture constructs this from its native fault register
/// (x86: PF error_code, AArch64: ESR_EL1) so that VSpace fault handlers
/// remain architecture-independent.
pub struct PageFaultInfo {
    /// The faulting page was present (permission violation, not unmapped).
    pub present: bool,
    /// The fault was caused by a write access.
    pub write: bool,
    /// The fault occurred in user mode.
    pub user: bool,
}

impl PageFaultInfo {
    /// Encode to the canonical VMFault IPC error_code format.
    ///
    /// Both architectures construct `PageFaultInfo` from their native fault
    /// registers, then use this method to produce a uniform error_code for
    /// the VMFault IPC message consumed by mmsrv.
    ///
    /// Bit layout:
    ///   \[0\] Present — 1 if permission fault, 0 if translation/not-present
    ///   \[1\] Write   — 1 if write access caused the fault
    ///   \[2\] User    — 1 if fault originated in user mode
    ///   \[4\] I/D     — 1 if instruction fetch
    pub fn to_ipc_error_code(&self, is_instr: bool) -> u64 {
        let mut code: u64 = 0;
        if self.present {
            code |= 1;
        }
        if self.write {
            code |= 2;
        }
        if self.user {
            code |= 4;
        }
        if is_instr {
            code |= 16;
        }
        code
    }
}

/// Page table entry flag bits
pub(crate) const ENTRY_PRESENT: u64 = 1 << 0;
pub(crate) const ENTRY_WRITABLE: u64 = 1 << 1;
pub(crate) const ENTRY_USER: u64 = 1 << 2;
const ENTRY_WRITE_THROUGH: u64 = 1 << 3;
const ENTRY_CACHE_DISABLE: u64 = 1 << 4;
pub(crate) const ENTRY_ACCESSED: u64 = 1 << 5;
pub(crate) const ENTRY_DIRTY: u64 = 1 << 6;
pub(crate) const ENTRY_COW: u64 = 1 << 9;
/// Demand page marker: PTE with PRESENT=0, DEMAND=1 triggers kernel fast-path
/// allocation on #PF instead of IPC to mmsrv. Bit 10 is OS-available when PRESENT=0.
const ENTRY_DEMAND: u64 = 1 << 10;
pub(crate) const ENTRY_NO_EXECUTE: u64 = 1 << 63;

/// Physical address mask in page table entry
pub(crate) const ENTRY_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

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

/// Capacity of the per-tree TLB range-change accumulator. Overflow flushes the
/// current batch mid-walk (fire-and-forget) and continues.
const RCL_CAP: usize = 16;

#[derive(Clone, Copy)]
struct RclEntry {
    vspace: *mut VSpace,
    va: u64,
}

/// Bounded per-tree TLB range-change accumulator, carried in `VmHierarchyState`
/// and touched only while the tree lock is held. Multi-page, tree-lock-held
/// operations (`downgrade_mappings_to_cow`, `destroy`'s rmap teardown, the
/// `unmap` split, `converge_sibling_mappings_to_owned`) record their
/// `(vspace, va)` PTE changes here instead of issuing a per-page remote
/// `tlb_shootdown` inside their loop; the local `invlpg` stays immediate at the
/// mutation site. The batch is flushed coalesced — one full flush per VSpace
/// whose changed-page count exceeds `RANGE_TLB_GLOBAL_THRESHOLD`, else per page
/// — AFTER the tree + VSpace locks drop (the sync-TLB integration seam, see the
/// `project_sync_tlb_shootdown` note): the caller `core::mem::replace`s the list
/// into a stack local under the lock, releases the locks, then `flush()`es the
/// local. Shootdowns are fire-and-forget, so an overflow mid-walk flush is
/// deadlock-free under the lock.
pub struct RangeChangeList {
    entries: [RclEntry; RCL_CAP],
    count: usize,
}

impl RangeChangeList {
    pub const fn new() -> Self {
        Self {
            entries: [RclEntry {
                vspace: core::ptr::null_mut(),
                va: 0,
            }; RCL_CAP],
            count: 0,
        }
    }

    /// Record a `(vspace, va)` PTE change. If the batch is full, flush it
    /// (fire-and-forget) and continue.
    ///
    /// # Safety
    /// Caller holds the owning tree's lock; `vspace` is live.
    pub unsafe fn record(&mut self, vspace: *mut VSpace, va: u64) {
        if self.count == RCL_CAP {
            unsafe { self.flush() };
        }
        self.entries[self.count] = RclEntry { vspace, va };
        self.count += 1;
    }

    /// Issue the accumulated remote shootdowns, coalesced per VSpace, then
    /// reset. Fire-and-forget; safe to call after the tree / VSpace locks drop.
    ///
    /// # Safety
    /// Every recorded `vspace` is still live.
    pub unsafe fn flush(&mut self) {
        let n = self.count;
        let mut i = 0;
        while i < n {
            let vs = self.entries[i].vspace;
            if vs.is_null() {
                i += 1;
                continue;
            }
            let mut cnt = 0usize;
            for j in i..n {
                if self.entries[j].vspace == vs {
                    cnt += 1;
                }
            }
            if cnt > RANGE_TLB_GLOBAL_THRESHOLD {
                unsafe { (*vs).tlb_shootdown_all() };
                for j in i..n {
                    if self.entries[j].vspace == vs {
                        self.entries[j].vspace = core::ptr::null_mut();
                    }
                }
            } else {
                for j in i..n {
                    if self.entries[j].vspace == vs {
                        unsafe { (*vs).tlb_shootdown(self.entries[j].va) };
                        self.entries[j].vspace = core::ptr::null_mut();
                    }
                }
            }
            i += 1;
        }
        self.count = 0;
    }
}

/// Maximum number of live user VSpaces tracked for global activity sweeps.
const MAX_LIVE_VSPACES: usize = 512;
/// Minimum interval between full active/inactive aging sweeps.
const ACTIVITY_CACHE_INTERVAL_NS: u64 = 1_000_000_000;
static NEXT_VSPACE_TRACE_ID: AtomicU64 = AtomicU64::new(1);

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
    /// Caller MUST run the two-phase wake: call
    /// `scheduler().finish_deactivate_drain(tracking)` with the
    /// scheduler lock held to drain the waiter list, then
    /// `scheduler().wake_drained_vspace_waiters(head)` after releasing
    /// the scheduler lock to safely acquire each waiter's `tcb_lock`.
    BecameInactive = 2,
}

/// Global kernel VSpace tracking pointer (set during boot)
static mut KERNEL_VSPACE_TRACKING: *const VSpaceTracking = core::ptr::null();

/// Kernel PML4 physical address (set during boot, never freed)
static mut KERNEL_PML4_PHYS: PhysAddr = 0;
/// Live user VSpace registry for global activity sweeps.
static LIVE_VSPACE_LOCK: SpinLock = SpinLock::new();
static mut LIVE_VSPACES: [*mut VSpace; MAX_LIVE_VSPACES] =
    [core::ptr::null_mut(); MAX_LIVE_VSPACES];
static mut LIVE_VSPACE_COUNT: usize = 0;

/// Scratch snapshot of the live-VSpace set, filled under `LIVE_VSPACE_LOCK`
/// and consumed during the activity sweep. Protected by `ACTIVITY_SWEEP_LOCK`
/// (the sweep is serialized), which avoids a 4 KiB stack array in
/// `force_global_activity_snapshot`.
static mut SWEEP_SNAPSHOT: [*mut VSpace; MAX_LIVE_VSPACES] =
    [core::ptr::null_mut(); MAX_LIVE_VSPACES];
/// Rate-limits global activity harvesting/aging epochs.
static ACTIVITY_SWEEP_LOCK: SpinLock = SpinLock::new();
static ACTIVITY_CACHE_NS: AtomicU64 = AtomicU64::new(0);

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

/// Per-CPU bridge from `retire_tracking` (under CAP_LOCK in `VSpace::cleanup`)
/// to the deferred-free list insert in `flush_pending_retire` (run by
/// `drain_reaper` after CAP_LOCK is released). Written and drained by the same
/// CPU within a single `drain_reaper` iteration — `drain_reaper` is
/// CAS-guarded (one drainer system-wide) and IRQ-disabled — so the slot is
/// single-writer/single-reader per CPU and needs no atomic.
static mut PENDING_RETIRE: [*mut VSpaceTracking; MAX_CPUS] = [core::ptr::null_mut(); MAX_CPUS];

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
/// Virtual memory area — a VSpace's view of one mapped region.
///
/// Defined here (not in maple_tree.rs) because it's a VSpace domain
/// concept. The maple tree stores `MapleTree<VmArea>` without knowing
/// what VmArea is.
///
/// `obj` is the strong-ref backing pointer — a `MemoryObject` for
/// `obj_type == MemoryObject` (page_count pages of MO offset
/// `mo_offset`), a `FrameObject` for `obj_type == Frame`
/// (page_count == 1, mo_offset == 0). Each live VmArea holds one
/// strong ref on `obj` for as long as the mapping metadata exists, so
/// the reaper cannot reclaim the PTE's backing phys under a live page
/// table. `release_object` dispatches on the typed destructor via the
/// stored `obj_type`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmArea {
    /// Strong-ref pointer to the backing kernel object. `*mut
    /// KernelObject` for type-erased storage; type-specific code
    /// re-casts via `obj_type`.
    pub obj: *mut crate::cap::KernelObject,
    /// Page offset within the MO for this region's start. Always 0
    /// for `Frame` backings.
    pub mo_offset: u32,
    /// Number of pages in this region.
    pub page_count: u32,
    /// Permissions (RWX packed).
    pub perms: u8,
    /// Classification of this region for per-process accounting
    /// (heap, mmap, stack, image text/data/bss, shared library, ...).
    /// Set at map time by mmsrv; zero means "unclassified / generic".
    pub region_kind: u8,
    /// `crate::cap::ObjectType` discriminant. Drives `release_object`
    /// dispatch on teardown and lets MO-only call sites
    /// (`rmap_*` / page lookup) gate on `MemoryObject`.
    pub obj_type: u8,
    /// Protection ceiling: the maximum permissions `protect` / `mprotect`
    /// may raise this region's PTEs to, captured at map time from the
    /// backing cap's rights. READ is always implied; bits gate WRITE
    /// (`MAX_PROT_WRITE`) and EXECUTE (`MAX_PROT_EXEC`). `0` means
    /// read-only — no W or X may be added. Frame mappings carry full
    /// `W|X` (page tables / COW pool / IPC buffers have no W^X policy);
    /// MO mappings carry exactly the rights of the cap that mapped them,
    /// so e.g. a `READ|EXECUTE` exec text region can never be made
    /// writable via `mprotect`, even by directly invoking the VSpace cap.
    pub max_prot: u8,
    pub _pad: [u8; 4],
}
// 8 + 4 + 4 + 1 + 1 + 1 + 1 + 4 = 24 bytes

impl VmArea {
    /// `max_prot` bit: WRITE may be added by `protect` / `mprotect`.
    pub const MAX_PROT_WRITE: u8 = 0x1;
    /// `max_prot` bit: EXECUTE may be added by `protect` / `mprotect`.
    pub const MAX_PROT_EXEC: u8 = 0x2;

    pub const EMPTY: Self = Self {
        obj: core::ptr::null_mut(),
        mo_offset: 0,
        page_count: 0,
        perms: 0,
        region_kind: 0,
        obj_type: crate::cap::ObjectType::Null as u8,
        max_prot: 0,
        _pad: [0; 4],
    };

    /// Convenience: typed pointer to the MO backing this VmArea.
    /// Returns null when `obj_type != MemoryObject` (frame mapping or
    /// empty). Call sites that need `rmap_*` / `page_at` / commit
    /// gate on the result being non-null.
    #[inline]
    pub fn mo(&self) -> *mut crate::cap::memory_object::MemoryObject {
        if self.obj_type == crate::cap::ObjectType::MemoryObject as u8 {
            self.obj as *mut crate::cap::memory_object::MemoryObject
        } else {
            core::ptr::null_mut()
        }
    }

    /// Increment the backing object's refcount. No-op when `obj` is
    /// null.
    #[inline]
    pub unsafe fn retain_obj_ref(&self) {
        if !self.obj.is_null() {
            unsafe {
                crate::cap::increment_refcount(self.obj);
            }
        }
    }

    /// Release the strong ref this VmArea holds. Dispatches the
    /// typed destructor through `obj_type`.
    #[inline]
    pub unsafe fn release_obj_ref(&self) {
        if self.obj.is_null() {
            return;
        }
        // Map the stored `obj_type` byte back to a strict `ObjectType`
        // value. VmAreas may own MemoryObject pages, Frame mappings, or
        // device Untyped mappings. Anything else means a new backing type
        // was added without updating this match; fall back to the live
        // header so production builds still release the reference.
        let ty = match self.obj_type {
            x if x == crate::cap::ObjectType::MemoryObject as u8 => {
                crate::cap::ObjectType::MemoryObject
            }
            x if x == crate::cap::ObjectType::Frame as u8 => crate::cap::ObjectType::Frame,
            x if x == crate::cap::ObjectType::Untyped as u8 => crate::cap::ObjectType::Untyped,
            _ => {
                crate::kernel::bug::kassert!(
                    false,
                    "VmArea.release_obj_ref: unexpected obj_type — fall back to header"
                );
                unsafe { (*self.obj).obj_type }
            }
        };
        unsafe {
            crate::cap::release_object(self.obj, ty);
        }
    }
}

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

    /// Intrusive wait queue head.
    ///
    /// PROTECTED BY: `waiter_lock` (below). IRQs must be disabled across
    /// the critical section. Access via `waiter_head_get_locked` /
    /// `waiter_head_set_locked` helpers, which assume the lock is held.
    waiter_head: UnsafeCell<*mut crate::sched::Tcb>,
    /// Dedicated spinlock serializing `waiter_head` mutation / splice
    /// and the `is_active()` recheck that gates `block_current_on_vspace`
    /// enqueue. Ordering: `CAP_LOCK → SCHED → waiter_lock → VSpace.lock
    /// → MM_LOCK`. Holding this lock does not prevent scheduler ops on
    /// other CPUs, but guarantees that waiter-list mutation and the
    /// last-deactivate wakeup snapshot happen in a single serialized
    /// section — closing both list-corruption and lost-wake races.
    waiter_lock: super::SpinLock,

    /// AArch64 ASID assigned to this VSpace (0 = not yet allocated).
    /// On x86_64 this field is unused (CR3 writes implicitly flush TLB).
    pub asid: AtomicU16,

    /// Generation when the ASID was allocated. If the global generation has
    /// advanced past this value, the ASID is stale and must be re-allocated.
    pub asid_generation: AtomicU64,

    /// Maple tree of VmArea entries: VA range → (MO, offset, perms).
    /// VSpace owns the lifetime of mapped MOs through per-VmArea refs.
    /// Protected by VSpace.lock.
    pub mappings: super::maple_tree::MapleTree<VmArea>,

    /// Page-table frames installed by `install_page_table` from a
    /// user-held Frame capability. Each entry holds a strong ref on
    /// the Frame `KernelObject` so the reaper cannot reclaim the phys
    /// out from under live page-table walks. Keyed by the PT phys;
    /// value is the Frame object pointer. Cleared by the user-PT
    /// branch of the page-table teardown walk in `VSpace::cleanup`,
    /// which `release_object`s the strong ref instead of `pmm_free`-
    /// ing the page as a kernel-owned `PageTable`.
    /// Protected by VSpace.lock.
    pub pt_mappings: super::maple_tree::MapleTree<*mut crate::cap::KernelObject>,

    /// Frames with `ENTRY_PRESENT` set in this VSpace's page tables.
    /// Incremented when a PTE transitions 0/Demand → Present; decremented
    /// when Present → 0/Demand. Read via `VSPACE_GET_MEM_STATS`.
    pub vm_resident_pages: AtomicU64,
    /// PTEs carrying `ENTRY_DEMAND` without `ENTRY_PRESENT` (lazy
    /// reservations). Bumped at demand-PTE install, dropped when the
    /// fault resolves or the range is unmapped.
    pub vm_demand_pages: AtomicU64,
    /// Total reserved virtual bytes described by live `VmArea` entries.
    pub vm_reserved_bytes: AtomicU64,
    /// High-water mark of `vm_reserved_bytes`.
    pub vm_peak_reserved_bytes: AtomicU64,
    /// PTEs with `ENTRY_COW` set.
    pub vm_cow_pages: AtomicU64,
    /// Page-table pages (PML4 / PDPT / PD / PT) owned by this VSpace's
    /// paging-structure tree. Bumped when a new page-table page is
    /// allocated, dropped when one is torn down.
    pub vm_pt_pages: AtomicU64,
    /// Pages charged to this VSpace's TCBs' kernel stacks.
    pub vm_kstack_pages: AtomicU64,
    /// Resident pages whose backing MO is `MoKind::Anon` or `CowChild`.
    pub resident_anon: AtomicU64,
    /// Resident pages whose backing MO is `MoKind::FileBacked`.
    pub resident_file: AtomicU64,
    /// Resident pages whose backing MO is `MoKind::Shm`.
    pub resident_shm: AtomicU64,
    /// High-water mark of `vm_resident_pages`.
    pub vm_peak_resident_pages: AtomicU64,
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
            waiter_lock: super::SpinLock::new(),
            asid: AtomicU16::new(0),
            asid_generation: AtomicU64::new(0),
            mappings: super::maple_tree::MapleTree::<VmArea>::empty(),
            pt_mappings: super::maple_tree::MapleTree::<*mut crate::cap::KernelObject>::empty(),
            vm_resident_pages: AtomicU64::new(0),
            vm_demand_pages: AtomicU64::new(0),
            vm_reserved_bytes: AtomicU64::new(0),
            vm_peak_reserved_bytes: AtomicU64::new(0),
            vm_cow_pages: AtomicU64::new(0),
            vm_pt_pages: AtomicU64::new(0),
            vm_kstack_pages: AtomicU64::new(0),
            resident_anon: AtomicU64::new(0),
            resident_file: AtomicU64::new(0),
            resident_shm: AtomicU64::new(0),
            vm_peak_resident_pages: AtomicU64::new(0),
        }
    }

    pub fn root(&self) -> PhysAddr {
        self.root
    }

    /// Observe a leaf-PTE transition and adjust per-VSpace counters.
    /// Called from `VSpace::write_entry` after the write has landed.
    /// `old`/`new` are raw PTE values.
    pub fn note_leaf_transition(&self, old: u64, new: u64) {
        let old_present = old & ENTRY_PRESENT != 0;
        let new_present = new & ENTRY_PRESENT != 0;
        let old_demand = old & ENTRY_DEMAND != 0 && !old_present;
        let new_demand = new & ENTRY_DEMAND != 0 && !new_present;
        let old_cow = old & ENTRY_COW != 0;
        let new_cow = new & ENTRY_COW != 0;

        if new_present && !old_present {
            let current = self.vm_resident_pages.fetch_add(1, Ordering::Relaxed) + 1;
            self.bump_peak(&self.vm_peak_resident_pages, current);
            self.adjust_resident_mokind(new & ENTRY_ADDR_MASK, 1);
        } else if old_present && !new_present {
            self.vm_resident_pages.fetch_sub(1, Ordering::Relaxed);
            self.adjust_resident_mokind(old & ENTRY_ADDR_MASK, -1);
        }
        if old_present != new_present {
            invalidate_activity_cache();
        }

        if new_demand && !old_demand {
            self.vm_demand_pages.fetch_add(1, Ordering::Relaxed);
        } else if old_demand && !new_demand {
            self.vm_demand_pages.fetch_sub(1, Ordering::Relaxed);
        }

        if new_cow && !old_cow {
            self.vm_cow_pages.fetch_add(1, Ordering::Relaxed);
        } else if old_cow && !new_cow {
            self.vm_cow_pages.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[inline]
    fn vma_bytes(vma: &VmArea) -> u64 {
        (vma.page_count as u64).saturating_mul(PAGE_SIZE as u64)
    }

    #[inline]
    fn bump_peak(&self, peak: &AtomicU64, candidate: u64) {
        let mut prev = peak.load(Ordering::Relaxed);
        while candidate > prev {
            match peak.compare_exchange_weak(prev, candidate, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(actual) => prev = actual,
            }
        }
    }

    #[inline]
    pub fn note_vma_added(&self, vma: &VmArea) {
        let bytes = Self::vma_bytes(vma);
        if bytes == 0 {
            return;
        }
        let current = self.vm_reserved_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        self.bump_peak(&self.vm_peak_reserved_bytes, current);
    }

    #[inline]
    pub fn note_vma_removed(&self, vma: &VmArea) {
        let bytes = Self::vma_bytes(vma);
        if bytes == 0 {
            return;
        }
        self.vm_reserved_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn note_vma_replaced(&self, old: &VmArea, new: &VmArea) {
        let old_bytes = Self::vma_bytes(old);
        let new_bytes = Self::vma_bytes(new);
        if new_bytes >= old_bytes {
            let delta = new_bytes - old_bytes;
            if delta != 0 {
                let current = self.vm_reserved_bytes.fetch_add(delta, Ordering::Relaxed) + delta;
                self.bump_peak(&self.vm_peak_reserved_bytes, current);
            }
        } else {
            self.vm_reserved_bytes
                .fetch_sub(old_bytes - new_bytes, Ordering::Relaxed);
        }
    }

    /// Adjust per-MoKind resident-page sub-counters. `delta` is ±1.
    /// Reads `FrameMeta.subkind` for the backing frame, which for
    /// `OwnerTag::MoData` encodes the owning MO's `MoKind` (set at
    /// `FrameMeta::set_owner` time). Frames that are not MoData
    /// (e.g. device-mapped MMIO, kernel-visible data pages) do not
    /// contribute to any sub-counter.
    fn adjust_resident_mokind(&self, phys: super::PhysAddr, delta: i64) {
        let Some(meta) = super::pmm_lookup(phys) else {
            return;
        };
        if meta.owner_tag != super::frame::OwnerTag::MoData {
            return;
        }
        let counter = match meta.subkind {
            0 | 1 => &self.resident_anon, // Anon / CowChild
            2 => &self.resident_file,
            3 => &self.resident_shm,
            _ => return,
        };
        if delta >= 0 {
            counter.fetch_add(delta as u64, Ordering::Relaxed);
        } else {
            counter.fetch_sub((-delta) as u64, Ordering::Relaxed);
        }
    }

    /// Get waiter head pointer (scheduler module ONLY, lock REQUIRED)
    ///
    /// # Safety
    /// MUST be called with `waiter_lock` held AND IRQs disabled.
    #[inline(always)]
    pub(crate) unsafe fn waiter_head_get_locked(&self) -> *mut crate::sched::Tcb {
        unsafe { *self.waiter_head.get() }
    }

    /// Set waiter head pointer.
    ///
    /// # Safety
    /// MUST be called with `waiter_lock` held AND IRQs disabled.
    #[inline(always)]
    pub(crate) unsafe fn waiter_head_set_locked(&self, head: *mut crate::sched::Tcb) {
        unsafe {
            *self.waiter_head.get() = head;
        }
    }

    /// Acquire the waiter-list spinlock. Caller must have IRQs disabled.
    #[inline(always)]
    pub(crate) fn waiter_lock_acquire(&self) {
        self.waiter_lock.lock();
    }

    /// Release the waiter-list spinlock.
    #[inline(always)]
    pub(crate) fn waiter_lock_release(&self) {
        self.waiter_lock.unlock();
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
    /// If `BecameInactive` is returned, caller MUST run the two-phase
    /// wake: `scheduler().finish_deactivate_drain(tracking)` with the
    /// scheduler lock held to drain the waiter list, then
    /// `scheduler().wake_drained_vspace_waiters(head)` after releasing
    /// the scheduler lock so each waiter's `tcb_lock` can be taken
    /// without violating the `tcb_lock > scheduler.lock_state` ordering.
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

#[derive(Clone, Copy, Debug, Default)]
pub struct ActivitySnapshot {
    pub pages_active: usize,
    pub pages_inactive: usize,
}

#[inline]
fn invalidate_activity_cache() {
    ACTIVITY_CACHE_NS.store(0, Ordering::Release);
}

pub fn register_live_vspace(vspace: *mut VSpace) {
    if vspace.is_null() {
        return;
    }

    LIVE_VSPACE_LOCK.lock();
    unsafe {
        for i in 0..LIVE_VSPACE_COUNT {
            if LIVE_VSPACES[i] == vspace {
                LIVE_VSPACE_LOCK.unlock();
                return;
            }
        }
        if LIVE_VSPACE_COUNT < MAX_LIVE_VSPACES {
            LIVE_VSPACES[LIVE_VSPACE_COUNT] = vspace;
            LIVE_VSPACE_COUNT += 1;
        } else {
            crate::kernel::printk::kerror!(|_g| {
                _g.puts("[VSPACE] live registry full, dropping activity tracking for ");
                _g.hex(vspace as u64);
                _g.puts("\n");
            });
        }
    }
    LIVE_VSPACE_LOCK.unlock();
    invalidate_activity_cache();
}

pub fn unregister_live_vspace(vspace: *mut VSpace) {
    if vspace.is_null() {
        return;
    }

    LIVE_VSPACE_LOCK.lock();
    unsafe {
        let mut idx = 0usize;
        while idx < LIVE_VSPACE_COUNT {
            if LIVE_VSPACES[idx] == vspace {
                LIVE_VSPACE_COUNT -= 1;
                LIVE_VSPACES[idx] = LIVE_VSPACES[LIVE_VSPACE_COUNT];
                LIVE_VSPACES[LIVE_VSPACE_COUNT] = core::ptr::null_mut();
                break;
            }
            idx += 1;
        }
    }
    LIVE_VSPACE_LOCK.unlock();
    invalidate_activity_cache();
}

pub fn global_activity_snapshot() -> ActivitySnapshot {
    let now = crate::arch::now_ns();
    let cached_ns = ACTIVITY_CACHE_NS.load(Ordering::Acquire);
    if cached_ns != 0 && now.saturating_sub(cached_ns) < ACTIVITY_CACHE_INTERVAL_NS {
        let (pages_active, pages_inactive) = super::pmm_activity_counts();
        return ActivitySnapshot {
            pages_active,
            pages_inactive,
        };
    }

    force_global_activity_snapshot()
}

pub fn force_global_activity_snapshot() -> ActivitySnapshot {
    // Serialize concurrent sweeps and own the snapshot buffer.
    ACTIVITY_SWEEP_LOCK.lock();
    let now = crate::arch::now_ns();

    // Snapshot the live-VSpace set under the registry lock and pin each
    // VSpace's refcount so a concurrent `unregister_live_vspace` (which
    // swap-removes from `LIVE_VSPACES` under this lock) followed by reaper
    // finalization cannot free the object once the registry lock is dropped.
    // The registry lock is held only for this brief snapshot — it is NOT held
    // across the harvest below. Holding it across harvest was what previously
    // forced IRQ-disable over the whole sweep (to avoid a CAP_LOCK <->
    // LIVE_VSPACE_LOCK cycle via the interrupt-entry prologue's drain_reaper).
    let count;
    // IRQ-disable only around the registry hold: an interrupt here runs the
    // entry prologue to drain_reaper -> CAP_LOCK -> VSpace::cleanup ->
    // unregister_live_vspace -> LIVE_VSPACE_LOCK, which would deadlock against
    // this hold. (The harvest walk below holds no registry lock and needs no
    // IRQ-disable — `harvest_activity_epoch` masks IRQs itself around the
    // per-VSpace page-table lock.) `save_irq_disable` is taken outside
    // `LIVE_VSPACE_LOCK` so the restore pairs with it on this CPU.
    let irq = unsafe { save_irq_disable() };
    LIVE_VSPACE_LOCK.lock();
    unsafe {
        count = LIVE_VSPACE_COUNT;
        for i in 0..count {
            let v = LIVE_VSPACES[i];
            // Conditional pin (inc-if-positive): pin only VSpaces that are
            // alive (refcount > 0). A VSpace at refcount 0 is already enqueued
            // for reap — zero is terminal, and drain_reaper finalizes without
            // re-checking refcount, so pinning it would not stop its free and
            // would race finalization. LIVE_VSPACE_LOCK blocks the reaper's
            // unregister (which precedes free), keeping the storage live for
            // the try_increment_refcount call; a concurrent cap-drop that
            // drives the refcount to zero mid-call makes the CAS fail and the
            // retry returns false, so that VSpace is simply skipped.
            if !v.is_null()
                && crate::cap::try_increment_refcount(v as *mut crate::cap::KernelObject)
            {
                SWEEP_SNAPSHOT[i] = v;
            } else {
                SWEEP_SNAPSHOT[i] = core::ptr::null_mut();
            }
        }
    }
    LIVE_VSPACE_LOCK.unlock();
    unsafe { restore_irq(irq) };

    // Walk the pinned snapshot with IRQs enabled. `harvest_activity_epoch`
    // takes the per-VSpace page-table lock under its own short IRQ-disable and
    // `flush_activity_tlb` issues fire-and-forget TLB-shootdown IPIs, so
    // neither requires the caller to mask IRQs; and with `LIVE_VSPACE_LOCK`
    // released an interrupt reaching CAP_LOCK cannot form a cycle. IRQs stay
    // enabled between VSpaces so the timer tick is not starved.
    unsafe {
        for i in 0..count {
            let v = SWEEP_SNAPSHOT[i];
            if !v.is_null() {
                (*v).harvest_activity_epoch();
            }
        }
    }

    let (pages_active, pages_inactive) = super::pmm_age_activity_epoch();
    ACTIVITY_CACHE_NS.store(now, Ordering::Release);

    // Drop the pins while still holding ACTIVITY_SWEEP_LOCK — it owns
    // SWEEP_SNAPSHOT, so a concurrent sweep cannot overwrite the slots we are
    // releasing. `release_object` -> `enqueue_reap` takes only REAPER_LOCK
    // (never CAP_LOCK), so nesting it under this leaf lock is order-safe; the
    // reaped VSpaces are finalized by the next syscall-boundary drain_reaper.
    unsafe {
        for i in 0..count {
            let v = SWEEP_SNAPSHOT[i];
            if !v.is_null() {
                SWEEP_SNAPSHOT[i] = core::ptr::null_mut();
                crate::cap::release_object(
                    v as *mut crate::cap::KernelObject,
                    crate::cap::ObjectType::VSpace,
                );
            }
        }
    }

    ACTIVITY_SWEEP_LOCK.unlock();

    ActivitySnapshot {
        pages_active,
        pages_inactive,
    }
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
    crate::kernel::bug::kassert_eq!(
        cpu_id,
        crate::arch::current_cpu() as usize,
        "set_pending_deactivate: cpu_id mismatch - must be current CPU"
    );
    crate::kernel::bug::kassert!(
        irqs_disabled(),
        "set_pending_deactivate: IRQs must be disabled"
    );

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
    crate::kernel::bug::kassert_eq!(
        cpu_id,
        crate::arch::current_cpu() as usize,
        "take_pending_deactivate: cpu_id mismatch - must be current CPU"
    );
    crate::kernel::bug::kassert!(
        irqs_disabled(),
        "take_pending_deactivate: IRQs must be disabled"
    );

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
    crate::kernel::bug::kassert_eq!(
        cpu_id,
        crate::arch::current_cpu() as usize,
        "advance_quiescent_gen: cpu_id mismatch - must be current CPU"
    );

    unsafe {
        PENDING_GENERATION[cpu_id].fetch_add(1, Ordering::AcqRel);
    }
}

/// Mark VSpaceTracking for deferred free
///
/// Called when a VSpace is destroyed (from `VSpace::cleanup` under CAP_LOCK).
/// Stages the tracking for deferred free; `flush_pending_retire` inserts it
/// into the list later, and it is freed once all CPUs reach quiescent state.
///
/// Uses per-CPU snapshot mechanism to ensure quiescent state:
/// - Each tracking gets unique retire_gen
/// - retire_snapshot[cpu] stores PENDING_GENERATION[cpu] at retire time
/// - Free condition: all PENDING_GENERATION[cpu] > retire_snapshot[cpu]
///
/// # Safety
/// `tracking` must be valid. Called under CAP_LOCK with IRQs disabled
/// (drain_reaper context); stages into the caller CPU's `PENDING_RETIRE` slot.
/// Retire a VSpace's tracking: assign its quiescent generation and snapshot the
/// online CPUs' current generations, then stage the pointer in this CPU's
/// `PENDING_RETIRE` slot. No `DEFERRED_FREE_LOCK` is taken here — this runs
/// under CAP_LOCK (via `VSpace::cleanup` in `drain_reaper`); the list insert is
/// deferred to `flush_pending_retire`, which `drain_reaper` runs after releasing
/// CAP_LOCK. That keeps `DEFERRED_FREE_LOCK` a strict leaf, never nested under
/// CAP_LOCK (the CAP_LOCK -> DEFERRED_FREE_LOCK edge of the SMP deadlock).
pub unsafe fn retire_tracking(tracking: *mut VSpaceTracking) {
    unsafe {
        // Assign unique retire generation
        let retire_gen_ptr = &raw const GLOBAL_RETIRE_GEN;
        let retire_gen = (*retire_gen_ptr).fetch_add(1, Ordering::AcqRel) + 1;
        (*tracking).retire_gen.store(retire_gen, Ordering::Release);

        // Snapshot only online CPUs — non-existent CPUs never advance generation
        let online = ONLINE_CPU_COUNT.load(Ordering::Acquire) as usize;
        (*tracking)
            .retire_online_cpus
            .store(online as u32, Ordering::Release);
        for cpu in 0..online {
            let cpu_gen = PENDING_GENERATION[cpu].load(Ordering::Acquire);
            (*tracking).retire_snapshot[cpu].store(cpu_gen, Ordering::Release);
        }

        // Stage for deferred list insertion after CAP_LOCK release.
        let cpu = crate::arch::current_cpu() as usize;
        PENDING_RETIRE[cpu] = tracking;
    }
}

/// Drain this CPU's staged retire (if any) into the deferred-free list under
/// `DEFERRED_FREE_LOCK`. Called by `drain_reaper` after `CAP_LOCK.unlock()`,
/// with IRQs still disabled. IRQ-disabled + same-CPU as the matching
/// `retire_tracking`, so the per-CPU slot needs no atomic.
///
/// Together with `process_deferred_free` (also IRQ-disabled), this makes every
/// `DEFERRED_FREE_LOCK` acquisition IRQ-disabled and never under CAP_LOCK.
pub unsafe fn flush_pending_retire() {
    unsafe {
        let cpu = crate::arch::current_cpu() as usize;
        let tracking = PENDING_RETIRE[cpu];
        if tracking.is_null() {
            return;
        }
        PENDING_RETIRE[cpu] = core::ptr::null_mut();

        let lock = &raw const DEFERRED_FREE_LOCK;
        (*lock).lock();
        crate::kernel::bug::kassert!(
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
        // IRQ-disabled across the whole scan. This runs on the BSP idle thread
        // with IRQs enabled, and the interrupt-entry prologue
        // (sched_runtime_enter_kernel -> flush_deferred_current_release ->
        // drain_reaper -> CAP_LOCK) can reach CAP_LOCK. Holding
        // DEFERRED_FREE_LOCK across an IRQ would create the
        // DEFERRED_FREE_LOCK -> CAP_LOCK edge of the CAP_LOCK cycle.
        let irq = save_irq_disable();
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
        restore_irq(irq);
    }
}

/// Check if IRQs are disabled
#[inline]
pub fn irqs_disabled() -> bool {
    crate::arch::irqs_disabled()
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

#[derive(Clone, Copy, Debug, Default)]
pub struct RangeMemStats {
    pub present_pages: u64,
    pub referenced_pages: u64,
    pub shared_pages: u64,
    pub shared_dirty_pages: u64,
    pub private_dirty_pages: u64,
    pub writeback_pages: u64,
    pub pss_bytes: u64,
}

impl RangeMemStats {
    pub const fn zeroed() -> Self {
        Self {
            present_pages: 0,
            referenced_pages: 0,
            shared_pages: 0,
            shared_dirty_pages: 0,
            private_dirty_pages: 0,
            writeback_pages: 0,
            pss_bytes: 0,
        }
    }
}

/// Virtual address space (wraps page table root)
#[repr(C)]
pub struct VSpace {
    /// Kernel object header (must be first for refcount access)
    pub header: crate::cap::KernelObject,
    /// Stable scheduler-trace VSpace id. Immutable after construction.
    trace_id: u64,
    /// Physical address of PML4
    root: PhysAddr,
    /// VSpaceTracking pointer — embedded in untyped allocation at root + PAGE_SIZE
    /// (seL4-style: all kernel object metadata lives in untyped memory).
    /// For kernel VSpace, points to static storage.
    pub(crate) tracking: *mut VSpaceTracking,
    /// Per-VSpace lock for page table modifications (map/unmap/install_page_table)
    pub(crate) lock: SpinLock,
    /// Physical address of CowPool page (0 = pool disabled)
    cow_pool_phys: PhysAddr,
    /// Physical address of CowNotifRing page
    cow_notif_phys: PhysAddr,
}

/// Outcome of the fault-path lock discovery (drop-revalidate dance step 1).
/// The named object is PINNED (one extra refcount) so its lock survives the
/// window between releasing `VSpace.lock` in discovery and re-acquiring it
/// after the outer lock is taken; drop the pin via [`FaultLock::release_pin`]
/// AFTER releasing every tree / VSpace lock (`release_object` takes
/// `REAPER_LOCK`, which must never nest under the tree lock).
#[derive(Clone, Copy)]
enum FaultLock {
    /// MO is bound to a COW tree — take `(*0).lock`; the pin is on the state.
    Bound(*mut crate::cap::memory_object::VmHierarchyState),
    /// MO is standalone — take `(*0).hierarchy_bind_lock`; the pin is on the MO.
    Standalone(*mut crate::cap::memory_object::MemoryObject),
}

impl FaultLock {
    /// Drop the discovery pin. Call only after every tree / VSpace lock is
    /// released, since `release_object` takes `REAPER_LOCK`.
    #[inline]
    unsafe fn release_pin(&self) {
        match *self {
            FaultLock::Bound(state) => unsafe {
                crate::cap::release_object(
                    state as *mut crate::cap::object::KernelObject,
                    crate::cap::ObjectType::VmHierarchyState,
                )
            },
            FaultLock::Standalone(mo) => unsafe {
                crate::cap::release_object(
                    mo as *mut crate::cap::object::KernelObject,
                    crate::cap::ObjectType::MemoryObject,
                )
            },
        }
    }
}

/// Outcome of [`pager_request_park`] — what the caller does after the tree +
/// VSpace locks drop. Shared by the demand-fault path and the
/// `MO_READ`/`MO_WRITE`/`MO_COMMIT` pager-driving helper. RFC-0002 acyclicity:
/// the wake/reschedule runs only after every lock is released.
enum PagerParkOutcome {
    /// The MO has no attached pager — re-resolve (anon zero-fill on demand).
    NoPager,
    /// Pager detached out from under us (epoch race) — re-resolve. The pager
    /// ref must be released after every lock drops.
    Retry(*mut crate::cap::pager::Pager),
    /// The page cannot be supplied (request already `Failed`, or the pager has
    /// no bound `EventQueue`) — permanent for this page. Release the pager ref
    /// after every lock drops.
    Failed(*mut crate::cap::pager::Pager),
    /// The pending-request slab is exhausted. Release the pager after unlock.
    Oom(*mut crate::cap::pager::Pager),
    /// The current thread parked on the pager request. After releasing every
    /// lock the caller MUST emit `record` to `eq_ptr` when `emit_event`, then
    /// `reschedule()`. The pager ref is handed off to that path.
    Parked {
        record: crate::event::record::EventRecord,
        eq_ptr: *mut crate::event::event_queue::EventQueue,
        pager_ptr: *mut crate::cap::pager::Pager,
        emit_event: bool,
    },
}

/// Pin the pager backing `pager_mo`, allocate-or-join a pending pager request
/// for `(pager_mo.pager_mo_id, pager_idx)`, and park the current TCB on it.
///
/// Shared by [`VSpace::handle_demand_fault`] and the `MemoryObject`
/// pager-driving syscalls (`MO_READ`/`MO_WRITE`/`MO_COMMIT`). The caller holds
/// the COW tree lock; this never reschedules — the caller emits the event and
/// reschedules after releasing every lock (RFC-0002: no wake/reschedule under
/// the tree lock). Returns a [`PagerParkOutcome`] the caller maps to its own
/// control flow.
///
/// # Safety
/// `pager_mo` is valid and the caller holds the tree lock for its COW tree.
unsafe fn pager_request_park(
    pager_mo: *mut crate::cap::memory_object::MemoryObject,
    pager_idx: usize,
    writable: bool,
) -> PagerParkOutcome {
    // Snapshot the pager pointer AND pin it under `commit_lock`, so a concurrent
    // `PAGER_DETACH` (which clears + releases the pager under that same lock)
    // cannot drop the last ref between the read and our use.
    let pager_attached = unsafe {
        let mo = &mut *pager_mo;
        mo.commit_lock.lock();
        let pager_ptr = mo.pager;
        let mo_id = mo.pager_mo_id;
        let pager_epoch = mo.pager_epoch;
        if !pager_ptr.is_null() {
            crate::cap::increment_refcount(pager_ptr as *mut crate::cap::object::KernelObject);
        }
        mo.commit_lock.unlock();
        if pager_ptr.is_null() {
            None
        } else {
            Some((pager_ptr, mo_id, pager_epoch))
        }
    };
    let Some((pager_ptr, mo_id, pager_epoch)) = pager_attached else {
        return PagerParkOutcome::NoPager;
    };

    let access_flags: u8 = if writable { 2 } else { 1 };

    unsafe {
        let pager = &mut *pager_ptr;
        pager.lock.lock();

        // Re-validate the pager generation UNDER pager.lock — detach bumps
        // `cancel_epoch` under this lock, so checking only before would let a
        // stale fault link a request after detach.
        if pager
            .cancel_epoch
            .load(core::sync::atomic::Ordering::Acquire)
            != pager_epoch
        {
            pager.lock.unlock();
            return PagerParkOutcome::Retry(pager_ptr);
        }

        // Bail before allocating/linking anything if we cannot block (no current
        // TCB) — avoids leaking a pending-request slot.
        let current_tcb = crate::sched::scheduler::scheduler().current();
        if current_tcb.is_null() {
            pager.lock.unlock();
            return PagerParkOutcome::Retry(pager_ptr);
        }

        let mut req: *mut crate::cap::pager::PendingPagerRequest = pager.pending_head;
        let mut found = core::ptr::null_mut();
        while !req.is_null() {
            if (*req).mo_id == mo_id && (*req).page_idx == pager_idx as u32 {
                found = req;
                break;
            }
            req = (*req).pager_next;
        }

        if !found.is_null() && (*found).state == crate::cap::pager::PendingState::Failed as u8 {
            pager.lock.unlock();
            return PagerParkOutcome::Failed(pager_ptr);
        }

        let mut emit_event = false;
        let req = if !found.is_null() {
            found
        } else {
            let eq_ptr = pager.bound_eq;
            if eq_ptr.is_null() {
                pager.lock.unlock();
                return PagerParkOutcome::Failed(pager_ptr);
            }

            let slot_idx = match crate::cap::pager::pending_alloc_slot() {
                Some(idx) => idx,
                None => {
                    pager.lock.unlock();
                    return PagerParkOutcome::Oom(pager_ptr);
                }
            };
            let new_req = crate::cap::pager::pending_get(slot_idx)
                .expect("freshly allocated pager request slot");
            (*new_req).pager = pager_ptr;
            (*new_req).mo = pager_mo;
            (*new_req).mo_id = mo_id;
            (*new_req).page_idx = pager_idx as u32;
            (*new_req).access_flags = access_flags;
            (*new_req).state = crate::cap::pager::PendingState::Pending as u8;
            (*new_req).request_epoch = pager_epoch;
            (*new_req).waiter_head = core::ptr::null_mut();
            pager.link_pending(new_req);
            emit_event = true;
            new_req
        };

        let eq_ptr = if emit_event {
            pager.bound_eq
        } else {
            core::ptr::null_mut()
        };
        let cookie = pager.cookie;
        if emit_event {
            crate::cap::increment_refcount(eq_ptr as *mut crate::cap::object::KernelObject);
        }

        (*current_tcb).sched_ref_inc();
        (*current_tcb).tcb_lock();
        (*current_tcb).wait_object = req as *mut core::ffi::c_void;
        crate::task::wait::prepare_blocked_reason_locked(
            &mut *current_tcb,
            crate::sched::thread::BlockedReason::PagerFaultBlocked,
        );
        (*current_tcb).tcb_unlock();
        (*current_tcb).eq_wait_next = (*req).waiter_head;
        (*req).waiter_head = current_tcb;

        pager.lock.unlock();

        let mut record = crate::event::record::EventRecord::empty();
        if emit_event {
            record.kind = uapi::KERNITE_EVENT_TYPE_PAGER_REQUEST;
            record.status = uapi::KERNITE_EVENT_STATUS_OK;
            record.cookie = cookie;
            record.object_id = mo_id;
            record.state_set = access_flags as u64;
            record.payload0 = pager_idx as u64;
            record.payload1 = PAGE_SIZE as u64;
            record.payload2 = (*current_tcb).trace_id;
        }

        PagerParkOutcome::Parked {
            record,
            eq_ptr,
            pager_ptr,
            emit_event,
        }
    }
}

/// Failure mode of [`populate_page_blocking`].
pub(crate) enum CommitErr {
    /// The page's effective source permanently failed (pager I/O failure, or a
    /// gone external source), or the system is out of memory.
    Io,
}

/// Outcome of one non-blocking [`populate_page_locked`] attempt under the COW
/// tree lock. Deferred pager references (which `release_object` must not drop
/// under the tree lock — RFC-0002 acyclicity) are threaded out for the caller to
/// release after every lock drops.
enum PopulateLocked {
    /// The page is resident: it already resolved, or `Zero` was just
    /// zero-committed. `depth` / `untyped_backed` carry the COW-mapping info the
    /// fault path and `VSPACE_MAP_MO` need.
    Done {
        phys: u64,
        depth: usize,
        untyped_backed: bool,
    },
    /// Parked on a pager request. After releasing every lock the caller emits
    /// `record` to `eq_ptr` when `emit_event`, reschedules, then releases
    /// `pager_ptr`.
    Parked {
        record: crate::event::record::EventRecord,
        eq_ptr: *mut crate::event::event_queue::EventQueue,
        pager_ptr: *mut crate::cap::pager::Pager,
        emit_event: bool,
    },
    /// Transient (pager epoch race / detached mid-classify): release `pager_ptr`
    /// if non-null after unlock, then re-classify.
    Retry {
        pager_ptr: *mut crate::cap::pager::Pager,
    },
    /// The effective source failed or is gone (pager-failed tombstone, or a
    /// file-backed source with no pager): release `pager_ptr` if non-null; the
    /// caller faults the thread (SIGBUS) or returns `IoError`.
    Failed {
        pager_ptr: *mut crate::cap::pager::Pager,
    },
    /// Out of memory committing the page or queuing the pager request: release
    /// `pager_ptr` if non-null.
    Oom {
        pager_ptr: *mut crate::cap::pager::Pager,
    },
}

/// Zero-fill and commit a fresh anonymous page into `mo`'s radix tree — the
/// anonymous-source half of [`populate_page_locked`].
///
/// # Safety
/// `mo` is valid and the caller holds its COW tree lock.
unsafe fn zero_commit_page(
    mo: *mut crate::cap::memory_object::MemoryObject,
    page_idx: usize,
) -> Option<u64> {
    let owner = super::frame::FrameOwner::MoData {
        mo,
        page_idx: page_idx as u32,
    };
    let new_phys = pmm_alloc(&owner)?;
    unsafe {
        core::ptr::write_bytes(phys_to_virt(new_phys) as *mut u8, 0, PAGE_SIZE);
    }
    let mut node_alloc = super::node_alloc::PmmNodeAllocator {
        owner: super::frame::FrameOwner::MoMeta {
            mo,
            subkind: super::frame::MoMetaKind::Radix,
        },
        use_reserve: true,
    };
    let mo_ref = unsafe { &mut *mo };
    mo_ref.commit_lock.lock();
    let ok = unsafe { mo_ref.commit_page(page_idx, new_phys, &mut node_alloc) };
    mo_ref.commit_lock.unlock();
    if !ok {
        super::pmm_free(new_phys, &owner);
        return None;
    }
    Some(new_phys)
}

/// Make `(mo, page_idx)`'s logical content resident — the single, non-blocking
/// populate step every VM operation shares. Classifies the effective source
/// ([`MemoryObject::effective_page_source_locked`]) and acts: `Resident` →
/// `Done`; `Zero` → zero-commit → `Done`; `Pager` → park on the pager request;
/// `Failed` → `Failed`. Never blocks, reschedules, or releases objects — it only
/// reads/commits under the held tree lock and hands deferred work back to the
/// caller (see [`PopulateLocked`]).
///
/// # Safety
/// `mo` is valid and the caller holds its COW tree lock for the whole
/// classify-then-act sequence. The fault path may also hold `VSpace.lock`.
unsafe fn populate_page_locked(
    mo: *mut crate::cap::memory_object::MemoryObject,
    page_idx: usize,
    writable: bool,
) -> PopulateLocked {
    match unsafe { (*mo).effective_page_source_locked(page_idx) } {
        crate::cap::memory_object::PageSource::Resident {
            phys,
            depth,
            untyped_backed,
            // Borrowed initrd frames map read-only like any resident page; the
            // fault path never stamps PMM ownership, so no special handling here.
            borrowed: _,
        } => PopulateLocked::Done {
            phys,
            depth,
            untyped_backed,
        },
        crate::cap::memory_object::PageSource::Zero => {
            match unsafe { zero_commit_page(mo, page_idx) } {
                Some(phys) => PopulateLocked::Done {
                    phys,
                    depth: 0,
                    untyped_backed: false,
                },
                None => PopulateLocked::Oom {
                    pager_ptr: core::ptr::null_mut(),
                },
            }
        }
        crate::cap::memory_object::PageSource::Pager {
            pager_mo,
            pager_idx,
        } => match unsafe { pager_request_park(pager_mo, pager_idx, writable) } {
            PagerParkOutcome::NoPager => PopulateLocked::Retry {
                pager_ptr: core::ptr::null_mut(),
            },
            PagerParkOutcome::Retry(p) => PopulateLocked::Retry { pager_ptr: p },
            PagerParkOutcome::Failed(p) => PopulateLocked::Failed { pager_ptr: p },
            PagerParkOutcome::Oom(p) => PopulateLocked::Oom { pager_ptr: p },
            PagerParkOutcome::Parked {
                record,
                eq_ptr,
                pager_ptr,
                emit_event,
            } => PopulateLocked::Parked {
                record,
                eq_ptr,
                pager_ptr,
                emit_event,
            },
        },
        crate::cap::memory_object::PageSource::Failed => PopulateLocked::Failed {
            pager_ptr: core::ptr::null_mut(),
        },
    }
}

/// Blocking wrapper over [`populate_page_locked`]: loop until `(mo, page_idx)`
/// is resident or its source permanently fails, driving the pager (park +
/// reschedule + retry) across lock drops. The `MemoryObject` analog of
/// `zx_vmo_read`/`zx_vmo_write`'s pager commit; `MO_WRITE`/`MO_COMMIT` and the
/// pager arm of `MO_READ` call this.
///
/// # Safety
/// `mo` is valid. MUST NOT be called with any COW tree / VSpace / cap lock held
/// (it takes the tree lock and reschedules). MUST NOT be called from the fault
/// path, which cannot drop `VSpace.lock` mid-fault — that path calls
/// [`populate_page_locked`] directly and defers its own reschedule.
pub(crate) unsafe fn populate_page_blocking(
    mo: *mut crate::cap::memory_object::MemoryObject,
    page_idx: usize,
    writable: bool,
) -> Result<(), CommitErr> {
    // Pin the target MO across the (possibly blocking) pager rounds: below we
    // drop the tree lock and `reschedule()`, so a concurrent last-cap drop would
    // otherwise free `mo` out from under the re-classify on wake (the syscall
    // holds no mapping ref, unlike the fault path's `FaultLock` pin). The COW
    // chain keeps `cow_parent` ancestors — including the pager source — alive via
    // each child's keep-alive ref on its parent, so pinning the leaf suffices.
    unsafe {
        crate::cap::increment_refcount(mo as *mut crate::cap::object::KernelObject);
    }

    let result = loop {
        let irq = unsafe { save_irq_disable() };
        let tl = unsafe { (*mo).lock_tree() };
        let outcome = unsafe { populate_page_locked(mo, page_idx, writable) };
        unsafe {
            (*tl).unlock();
            restore_irq(irq);
        }

        match outcome {
            PopulateLocked::Done { .. } => break Ok(()),
            PopulateLocked::Retry { pager_ptr } => {
                if !pager_ptr.is_null() {
                    unsafe {
                        crate::cap::release_object(
                            pager_ptr as *mut crate::cap::object::KernelObject,
                            crate::cap::ObjectType::Pager,
                        );
                    }
                }
                continue;
            }
            PopulateLocked::Failed { pager_ptr } | PopulateLocked::Oom { pager_ptr } => {
                if !pager_ptr.is_null() {
                    unsafe {
                        crate::cap::release_object(
                            pager_ptr as *mut crate::cap::object::KernelObject,
                            crate::cap::ObjectType::Pager,
                        );
                    }
                }
                break Err(CommitErr::Io);
            }
            PopulateLocked::Parked {
                record,
                eq_ptr,
                pager_ptr,
                emit_event,
            } => {
                unsafe {
                    if emit_event {
                        let _ = (*eq_ptr).enqueue(record);
                        crate::cap::release_object(
                            eq_ptr as *mut crate::cap::object::KernelObject,
                            crate::cap::ObjectType::EventQueue,
                        );
                    }
                    crate::sched::scheduler::scheduler().reschedule();
                    crate::cap::release_object(
                        pager_ptr as *mut crate::cap::object::KernelObject,
                        crate::cap::ObjectType::Pager,
                    );
                }
                continue;
            }
        }
    };

    unsafe {
        crate::cap::release_object(
            mo as *mut crate::cap::object::KernelObject,
            crate::cap::ObjectType::MemoryObject,
        );
    }
    result
}

impl VSpace {
    #[inline]
    fn alloc_trace_id() -> u64 {
        NEXT_VSPACE_TRACE_ID.fetch_add(1, Ordering::Relaxed)
    }

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
            header: crate::cap::KernelObject::new(crate::cap::ObjectType::VSpace, 0),
            trace_id: Self::alloc_trace_id(),
            root: pml4_addr,
            tracking,
            lock: SpinLock::new(),
            cow_pool_phys: 0,
            cow_notif_phys: 0,
        }
    }

    #[inline]
    pub fn trace_id(&self) -> u64 {
        self.trace_id
    }

    pub fn root(&self) -> PhysAddr {
        self.root
    }

    /// Ensure this VSpace has a valid ASID and return it shifted into the
    /// active host TTBR0[63:48] position. Allocates lazily on first call and
    /// re-allocates if the global generation has rolled over.
    ///
    /// Must be called with IRQs disabled (satisfied by `switch_to`).
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn ensure_asid(&self) -> u64 {
        let tracking = unsafe { &*self.tracking };
        let mut asid = tracking.asid.load(Ordering::Relaxed);
        let asid_gen = tracking.asid_generation.load(Ordering::Relaxed);
        let global_gen = unsafe { *(&raw const crate::arch::paging::ASID_GENERATION) };

        if asid == 0 || asid_gen != global_gen {
            let (new_asid, new_gen) = unsafe { crate::arch::paging::asid_alloc() };
            if asid != 0 && asid_gen == new_gen {
                unsafe { crate::arch::paging::asid_free(asid) };
            }
            tracking.asid.store(new_asid, Ordering::Relaxed);
            tracking.asid_generation.store(new_gen, Ordering::Relaxed);
            asid = new_asid;
        }

        (asid as u64) << 48
    }

    /// Return the fully encoded active host TTBR0 value for this VSpace.
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn host_ttbr0(&self) -> u64 {
        self.ensure_asid() | self.root
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
    pub(crate) fn read_entry(&self, vaddr: VirtAddr, level: usize) -> Option<u64> {
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

    /// Check if the PTE at `vaddr` is present and writable (not COW).
    /// Returns `true` if the page can be safely written by the kernel.
    pub fn is_page_writable(&self, vaddr: VirtAddr) -> bool {
        if let Some(pte) = self.read_entry(vaddr, 1) {
            pte & ENTRY_PRESENT != 0 && pte & ENTRY_WRITABLE != 0 && pte & ENTRY_COW == 0
        } else {
            false
        }
    }

    /// Ensure page exists and is writable, resolving COW if necessary.
    ///
    /// Returns `true` if the page is writable after the call.
    /// Intended for kernel writes to user pages (e.g. IPC buffer).
    pub fn ensure_writable(&mut self, vaddr: VirtAddr) -> bool {
        let pte = match self.read_entry(vaddr, 1) {
            Some(e) => e,
            None => return false,
        };
        if pte & ENTRY_PRESENT == 0 {
            return false;
        }
        if pte & ENTRY_WRITABLE != 0 && pte & ENTRY_COW == 0 {
            return true;
        }
        // Page is COW — synthesize a write fault to resolve it.
        let fault = super::PageFaultInfo {
            present: true,
            write: true,
            user: true,
        };
        match self.handle_cow_fault(vaddr, &fault) {
            Ok(true) => true,
            _ => false,
        }
    }

    /// Ensure page table exists at specified level, creating if needed
    /// level: 1=PT, 2=PD, 3=PDPT
    /// Returns physical address of the page table
    pub(crate) fn ensure_table(
        &mut self,
        vaddr: VirtAddr,
        level: usize,
        is_user: bool,
    ) -> Result<PhysAddr, VSpaceError> {
        self.ensure_table_inner(vaddr, level, is_user, None)
    }

    /// Variant of `ensure_table` that records every newly-allocated
    /// page-table page in `tracker`. See `EnsureTablesGuard` for the
    /// rollback semantics.
    pub(crate) fn ensure_table_tracked(
        &mut self,
        vaddr: VirtAddr,
        level: usize,
        is_user: bool,
        tracker: &mut EnsureTablesGuard,
    ) -> Result<PhysAddr, VSpaceError> {
        self.ensure_table_inner(vaddr, level, is_user, Some(tracker))
    }

    fn ensure_table_inner(
        &mut self,
        vaddr: VirtAddr,
        level: usize,
        is_user: bool,
        mut tracker: Option<&mut EnsureTablesGuard>,
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
                let new_frame = pmm_alloc(&super::frame::FrameOwner::KernelPrivate {
                    subkind: super::frame::KernelMetaKind::PageTable,
                })
                .ok_or(VSpaceError::OutOfMemory)?;

                // SAFETY: retain before the PDE is visible so the frame cannot
                // be reclaimed between pmm_alloc() and the PDE write.
                super::pmm_retain_mapping(new_frame);
                // Mark as page-table frame and kernel-runtime: prevents accidental
                // reclamation via refcount bugs and exposure via untyped retype.
                super::pmm_set_owner(
                    new_frame,
                    &super::frame::FrameOwner::KernelPrivate {
                        subkind: super::frame::KernelMetaKind::PageTable,
                    },
                );
                crate::kernel::printk::ktrace!(mm, |_g| {
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
                    core::ptr::write_bytes(new_table_virt as *mut u8, 0, PAGE_SIZE);
                }
                crate::arch::publish_page_table_page(new_frame);

                // Set the entry
                table.set_entry(idx, new_frame | table_flags);
                crate::arch::publish_page_table_page(current_table);

                if !self.tracking.is_null() {
                    unsafe {
                        (*self.tracking).vm_pt_pages.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Track the allocation so a downstream rollback can
                // unlink and free it. Overflow is a capacity-bound
                // logic bug; recover by undoing the publish we just
                // did and freeing the frame, so the guard's
                // invariant ("every tracked alloc is reachable") is
                // not violated and we don't leak the latest frame.
                if let Some(t) = tracker.as_deref_mut() {
                    if !t.push(PtAlloc {
                        parent_table_phys: current_table,
                        idx_in_parent: idx as u16,
                        child_phys: new_frame,
                        level: (current_level - 1) as u8,
                    }) {
                        // Roll back the publish we just performed so
                        // the parent slot stays at zero and the new
                        // frame can be freed cleanly.
                        table.set_entry(idx, 0);
                        crate::arch::publish_page_table_page(current_table);
                        if !self.tracking.is_null() {
                            unsafe {
                                (*self.tracking).vm_pt_pages.fetch_sub(1, Ordering::Relaxed);
                            }
                        }
                        super::pmm_release_mapping(new_frame);
                        super::pmm_free(
                            new_frame,
                            &super::frame::FrameOwner::KernelPrivate {
                                subkind: super::frame::KernelMetaKind::PageTable,
                            },
                        );
                        return Err(VSpaceError::OutOfMemory);
                    }
                }

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
    pub(crate) fn write_entry(
        &mut self,
        vaddr: VirtAddr,
        level: usize,
        value: u64,
    ) -> Result<(), VSpaceError> {
        let pml4 = unsafe { &mut *self.pml4() };

        match level {
            4 => {
                pml4.set_entry(Self::pml4_index(vaddr), value);
                crate::arch::publish_page_table_page(self.root);
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
                crate::arch::publish_page_table_page(pml4e & ENTRY_ADDR_MASK);
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
                crate::arch::publish_page_table_page(pdpte & ENTRY_ADDR_MASK);
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
                let pt_idx = Self::pt_index(vaddr);
                let old_leaf = pt.entry(pt_idx);
                pt.set_entry(pt_idx, value);
                crate::arch::publish_page_table_page(pde & ENTRY_ADDR_MASK);
                if !self.tracking.is_null() {
                    unsafe { (*self.tracking).note_leaf_transition(old_leaf, value) };
                }
                Ok(())
            }
            _ => Err(VSpaceError::NotMapped),
        }
    }

    /// Atomically demote a present leaf (level-1) PTE that maps
    /// `expected_phys` to a **demand** PTE: it clears PRESENT / DIRTY /
    /// ACCESSED and the physical address, preserves the permission and cache
    /// flags, and sets `ENTRY_DEMAND`. A later access then re-faults through
    /// the pager fast path (a zero PTE would instead fall through to a user
    /// fault and SIGSEGV). The read-and-replace is a single atomic swap, so a
    /// concurrent hardware write that set the Dirty bit is captured in the
    /// returned value instead of being lost.
    ///
    /// Returns the prior leaf value (logical), or `None` if the path is not
    /// fully mapped, the leaf is not present, or it maps a different frame.
    /// Used by page eviction under the owning MO's `rmap_lock` (never
    /// `VSpace.lock`), mirroring `MemoryObject::rmap_harvest_page_dirty`: the
    /// rmap lock keeps the page-table page live for the duration.
    pub(crate) fn demote_leaf_to_demand(
        &mut self,
        vaddr: VirtAddr,
        expected_phys: u64,
    ) -> Option<u64> {
        let pml4 = unsafe { &mut *self.pml4() };
        let pml4e = pml4.entry(Self::pml4_index(vaddr));
        if pml4e & ENTRY_PRESENT == 0 {
            return None;
        }
        let pdpt = unsafe { &mut *(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *mut PageTable) };
        let pdpte = pdpt.entry(Self::pdpt_index(vaddr));
        if pdpte & ENTRY_PRESENT == 0 {
            return None;
        }
        let pd = unsafe { &mut *(phys_to_virt(pdpte & ENTRY_ADDR_MASK) as *mut PageTable) };
        let pde = pd.entry(Self::pd_index(vaddr));
        if pde & ENTRY_PRESENT == 0 {
            return None;
        }
        let pt = unsafe { &mut *(phys_to_virt(pde & ENTRY_ADDR_MASK) as *mut PageTable) };
        let pt_idx = Self::pt_index(vaddr);
        let old = pt.entry(pt_idx);
        if old & ENTRY_PRESENT == 0 || old & ENTRY_ADDR_MASK != expected_phys {
            return None;
        }
        let demand = (old & !(ENTRY_ADDR_MASK | ENTRY_PRESENT | ENTRY_DIRTY | ENTRY_ACCESSED))
            | ENTRY_DEMAND;
        let old_leaf = pt.swap_entry(pt_idx, demand);
        crate::arch::publish_page_table_page(pde & ENTRY_ADDR_MASK);
        if !self.tracking.is_null() {
            unsafe { (*self.tracking).note_leaf_transition(old_leaf, demand) };
        }
        Some(old_leaf)
    }

    /// Convert PageFlags to page table entry flags
    /// Convert raw PTE entry back to arch-neutral PageFlags.
    pub(crate) fn entry_flags_to_page_flags(entry: u64) -> PageFlags {
        PageFlags {
            writable: entry & ENTRY_WRITABLE != 0,
            user: entry & ENTRY_USER != 0,
            executable: entry & ENTRY_NO_EXECUTE == 0,
            cache_disable: entry & ENTRY_CACHE_DISABLE != 0,
            write_through: entry & ENTRY_WRITE_THROUGH != 0,
            cow: entry & ENTRY_COW != 0,
        }
    }

    fn flags_to_entry_flags(flags: PageFlags) -> u64 {
        let mut entry = ENTRY_PRESENT;

        if !flags.user {
            entry |= ENTRY_ACCESSED;
        }

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
    pub(crate) fn tlb_shootdown(&self, vaddr: VirtAddr) {
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

    fn flush_activity_tlb(&self) {
        if self.active_on_current_cpu() {
            #[cfg(target_arch = "x86_64")]
            {
                let cr3 = crate::arch::paging::read_cr3();
                unsafe {
                    crate::arch::paging::write_cr3(cr3);
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                crate::arch::paging::flush_tlb_all();
            }
        }
        self.tlb_shootdown_all();
    }

    fn harvest_activity_epoch(&mut self) {
        if self.root == unsafe { KERNEL_PML4_PHYS } {
            return;
        }

        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let mut cleared_accessed = false;
        let pml4 = unsafe { &mut *self.pml4() };

        for pml4_idx in 0..USER_PML4_MAX {
            let pml4e = pml4.entry(pml4_idx);
            if pml4e & ENTRY_PRESENT == 0 {
                continue;
            }
            let pdpt = unsafe { &mut *(phys_to_virt(pml4e & ENTRY_ADDR_MASK) as *mut PageTable) };

            for pdpt_idx in 0..512 {
                let pdpte = pdpt.entry(pdpt_idx);
                if pdpte & ENTRY_PRESENT == 0 || pdpte & (1 << 7) != 0 {
                    continue;
                }
                let pd = unsafe { &mut *(phys_to_virt(pdpte & ENTRY_ADDR_MASK) as *mut PageTable) };

                for pd_idx in 0..512 {
                    let pde = pd.entry(pd_idx);
                    if pde & ENTRY_PRESENT == 0 || pde & (1 << 7) != 0 {
                        continue;
                    }
                    let pt_phys = pde & ENTRY_ADDR_MASK;
                    let pt = unsafe { &mut *(phys_to_virt(pt_phys) as *mut PageTable) };
                    let mut pt_modified = false;

                    for pt_idx in 0..512 {
                        let entry = pt.entry(pt_idx);
                        if entry & ENTRY_PRESENT == 0 {
                            continue;
                        }

                        let phys = entry & ENTRY_ADDR_MASK;
                        if entry & ENTRY_ACCESSED != 0 {
                            let _ = super::pmm_update_flags(
                                phys,
                                super::frame::FRAME_FLAG_REFERENCED
                                    | super::frame::FRAME_FLAG_ACTIVE,
                                0,
                            );
                        }

                        if entry & ENTRY_ACCESSED != 0 {
                            pt.set_entry(pt_idx, entry & !ENTRY_ACCESSED);
                            pt_modified = true;
                            cleared_accessed = true;
                        }
                    }

                    if pt_modified {
                        crate::arch::publish_page_table_page(pt_phys);
                    }
                }
            }
        }

        self.lock.unlock();
        unsafe { restore_irq(irq) };

        if cleared_accessed {
            self.flush_activity_tlb();
        }
    }

    /// Map a page
    pub fn map(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), VSpaceError> {
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();
        let result = unsafe { self.map_locked(virt, phys, flags) };
        self.lock.unlock();
        unsafe { restore_irq(irq) };
        result
    }

    /// Map a page. Caller must hold `self.lock` and have IRQs disabled.
    ///
    /// # Safety
    /// - `self.lock` must be held.
    /// - IRQs must be disabled (matching `map` wrapper).
    /// - Violating these lets concurrent mutators corrupt page tables.
    pub(crate) unsafe fn map_locked(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), VSpaceError> {
        if virt & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }
        if phys & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        self.ensure_table(virt, 1, flags.user)?;

        // Check if already mapped
        if let Some(entry) = self.read_entry(virt, 1) {
            if entry & ENTRY_PRESENT != 0 {
                return Err(VSpaceError::AlreadyMapped);
            }
        }

        let entry_flags = Self::flags_to_entry_flags(flags);
        self.write_entry(virt, 1, phys | entry_flags)?;

        super::pmm_retain_mapping(phys);

        // Local TLB flush
        crate::arch::paging::invlpg(virt);

        // Remote TLB shootdown
        self.tlb_shootdown(virt);

        // Executable mapping requires I-cache coherence (no-op on x86_64).
        // Clean D-cache to PoU first so the I-cache refill path sees data
        // written via any VA (e.g. RTLD scratch mappings).
        if flags.executable {
            crate::arch::paging::flush_dcache_pou_page(phys_to_virt(phys) as u64);
            crate::arch::paging::flush_icache_all();
        }

        Ok(())
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
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();
        let result = unsafe { self.map_range_partial_locked(virt_start, phys_start, count, flags) };
        self.lock.unlock();
        unsafe { restore_irq(irq) };
        result
    }

    /// Map a contiguous page range while `self.lock` is already held.
    /// Existing leaf PTEs, including demand placeholders, stop the range.
    ///
    /// # Safety
    /// - `self.lock` must be held.
    /// - IRQs must be disabled.
    pub(crate) unsafe fn map_range_partial_locked(
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

        let mut mapped = 0usize;
        let entry_flags = Self::flags_to_entry_flags(flags);
        let mut virt = virt_start;
        let mut phys = phys_start;

        for _ in 0..count {
            if self.ensure_table(virt, 1, flags.user).is_err() {
                break;
            }
            if let Some(entry) = self.read_entry(virt, 1) {
                if entry != 0 {
                    break;
                }
            }
            if self.write_entry(virt, 1, phys | entry_flags).is_err() {
                break;
            }
            super::pmm_retain_mapping(phys);
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
                #[cfg(target_arch = "x86_64")]
                {
                    let cr3 = crate::arch::paging::read_cr3();
                    unsafe {
                        crate::arch::paging::write_cr3(cr3);
                    }
                }
                #[cfg(target_arch = "aarch64")]
                {
                    crate::arch::paging::flush_tlb_all();
                }
            }
            self.tlb_shootdown_all();
        } else if mapped > 0 {
            let do_local_flush = self.active_on_current_cpu();
            let mut flush_virt = virt_start;
            for i in 0..mapped {
                if do_local_flush {
                    crate::arch::paging::invlpg(flush_virt);
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

        Ok(mapped)
    }

    /// Install a page table at a specific level.
    ///
    /// `frame_obj` is the strong-ref backing pointer for the PT page.
    /// When non-null, the call site is `syscall_vspace_map_pt`, the
    /// PT page is owned by a user-held Frame capability, and we must
    /// keep the Frame alive for as long as the parent PTE points at
    /// `pt_phys` — otherwise `cnode_delete(frame_cap)` triggers the
    /// reaper, the freelist returns the bytes, and the next retype
    /// zeroes the PT under the live walker. We satisfy that by
    /// reserving a slot in `pt_mappings` BEFORE the parent PTE write,
    /// then bumping the Frame's refcount and committing the
    /// reservation on success. `cleanup` walks the registry and
    /// `release_object`s these frames instead of `pmm_free`-ing them
    /// as kernel-owned `PageTable`s.
    ///
    /// Pure kernel-allocated PT installs pass `null` for `frame_obj`
    /// and skip the `pt_mappings` machinery entirely. level: 1=PT,
    /// 2=PD, 3=PDPT.
    pub fn install_page_table(
        &mut self,
        vaddr: VirtAddr,
        pt_phys: PhysAddr,
        level: usize,
        frame_obj: *mut crate::cap::KernelObject,
    ) -> Result<(), VSpaceError> {
        if level < 1 || level > 3 {
            return Err(VSpaceError::Alignment);
        }

        // Check alignment of the page table frame
        if pt_phys & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

        // Single-map (seL4): refuse a PageTable already installed in a VSpace —
        // a second install would zero a live table or alias it across address
        // spaces. `frame_obj` is the typed PageTable object (see VSPACE_MAP_PT).
        if !frame_obj.is_null() {
            let pto = frame_obj as *mut crate::cap::PageTableObject;
            if unsafe { (*pto).mapped } {
                return Err(VSpaceError::AlreadyMapped);
            }
        }

        // Zero the new page table
        unsafe {
            let pt_virt = phys_to_virt(pt_phys) as *mut u8;
            core::ptr::write_bytes(pt_virt, 0, PAGE_SIZE);
        }

        // Acquire per-VSpace lock
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let mut tree_alloc = super::node_alloc::PmmNodeAllocator {
            owner: super::frame::FrameOwner::KernelPrivate {
                subkind: super::frame::KernelMetaKind::MapleNode,
            },
            use_reserve: false,
        };
        let resv = if !frame_obj.is_null() && !self.tracking.is_null() {
            let t = unsafe { &mut *self.tracking };
            match t.pt_mappings.reserve_for_insert(&mut tree_alloc) {
                Ok(r) => Some(r),
                Err(_) => {
                    self.lock.unlock();
                    unsafe { restore_irq(irq) };
                    return Err(VSpaceError::OutOfMemory);
                }
            }
        } else {
            None
        };

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
            crate::arch::publish_page_table_page(current_table);
            // Protect the installed PT frame from premature reclamation if the
            // user-held Frame capability is later deleted (pmm_free).
            super::pmm_retain_mapping(pt_phys);
            // No TLB shootdown needed — new empty table has no cached entries
            Ok(())
        })();

        match (result, resv) {
            (Ok(()), Some(mut r)) => {
                // Commit: bump the PageTable's refcount and stash the
                // strong-ref pointer in `pt_mappings` so cleanup can
                // dispatch `release_object(.., PageTable)` instead of
                // freeing the page as a kernel-owned `PageTable`.
                unsafe {
                    crate::cap::increment_refcount(frame_obj);
                    // Single-map: mark the table installed (see the guard above).
                    (*(frame_obj as *mut crate::cap::PageTableObject)).mapped = true;
                    let t = &mut *self.tracking;
                    t.pt_mappings.insert_reserved(pt_phys, frame_obj, &mut r);
                    r.release(&mut tree_alloc);
                }
                self.lock.unlock();
                unsafe { restore_irq(irq) };
                Ok(())
            }
            (Ok(()), None) => {
                self.lock.unlock();
                unsafe { restore_irq(irq) };
                Ok(())
            }
            (Err(e), Some(r)) => {
                r.release(&mut tree_alloc);
                self.lock.unlock();
                unsafe { restore_irq(irq) };
                Err(e)
            }
            (Err(e), None) => {
                self.lock.unlock();
                unsafe { restore_irq(irq) };
                Err(e)
            }
        }
    }

    /// Tear down a page-table page during `cleanup`.
    ///
    /// Drops the self-mapping `pmm_retain_mapping` ref and the
    /// `vm_pt_pages` accounting, then dispatches:
    /// - User-Frame backed (`pt_mappings` hit): remove the registry
    ///   entry and `release_object(frame_obj, Frame)`. The reaper
    ///   handles the actual phys reclamation through `release_block`.
    /// - Kernel-allocated `PageTable`: `pmm_free` as before.
    ///
    /// Caller must hold `self.lock` (cleanup runs single-threaded
    /// during VSpace teardown but the registry mutations still take
    /// the lock for ordering consistency with the `install` side).
    unsafe fn release_pt_frame(&mut self, pt_phys: PhysAddr) {
        super::pmm_release_mapping(pt_phys);
        if !self.tracking.is_null() {
            unsafe { (*self.tracking).vm_pt_pages.fetch_sub(1, Ordering::Relaxed) };
        }
        let user_frame = if !self.tracking.is_null() {
            unsafe {
                let t = &mut *self.tracking;
                let res = t.pt_mappings.lookup(pt_phys).map(|(_, &v)| v);
                if res.is_some() {
                    let mut tree_alloc = super::node_alloc::PmmNodeAllocator {
                        owner: super::frame::FrameOwner::KernelPrivate {
                            subkind: super::frame::KernelMetaKind::MapleNode,
                        },
                        use_reserve: false,
                    };
                    t.pt_mappings.remove(pt_phys, &mut tree_alloc);
                }
                res
            }
        } else {
            None
        };
        match user_frame {
            Some(frame_obj) => unsafe {
                // Clear the single-map flag so the (still cap-held) PageTable can
                // be installed again now that it is unmapped here.
                (*(frame_obj as *mut crate::cap::PageTableObject)).mapped = false;
                crate::cap::release_object(frame_obj, crate::cap::ObjectType::PageTable);
            },
            None => {
                super::pmm_free(
                    pt_phys,
                    &super::frame::FrameOwner::KernelPrivate {
                        subkind: super::frame::KernelMetaKind::PageTable,
                    },
                );
            }
        }
    }

    /// Unmap a page.
    ///
    /// If the page belongs to a tracked VmArea, this also shrinks or removes
    /// the VmArea and reverse-map metadata so MO-backed mappings cannot leak
    /// refs when callers use the general single-page unmap path.
    pub fn unmap(&mut self, virt: VirtAddr) -> Result<(), VSpaceError> {
        // Check alignment (no lock needed)
        if virt & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }
        // Retry only if the VMA is remapped to a different tree during the dance.
        loop {
            if let Some(r) = unsafe { self.unmap_once(virt) } {
                return r;
            }
        }
    }

    /// One unmap attempt: take the backing MO's per-tree lock (bound) / bind
    /// lock (standalone) OUTSIDE `VSpace.lock` so the VMA split serialises
    /// against downgrade on the same tree (F2), revalidate the VMA still maps
    /// that tree, then split / clear. Returns `None` to request a retry when
    /// the VMA was remapped to a different tree while `VSpace.lock` was dropped.
    ///
    /// # Safety
    /// `self` is a live VSpace; `virt` is page-aligned.
    unsafe fn unmap_once(&mut self, virt: VirtAddr) -> Option<Result<(), VSpaceError>> {
        let self_ptr = self as *mut VSpace;
        let fault_lock = unsafe { self.discover_fault_lock(virt) };
        let outer_lock_ptr: Option<*const SpinLock> = fault_lock.map(|fl| unsafe {
            match fl {
                FaultLock::Bound(state) => &(*state).lock as *const SpinLock,
                FaultLock::Standalone(mo) => &(*mo).hierarchy_bind_lock as *const SpinLock,
            }
        });

        let irq = unsafe { save_irq_disable() };
        if let Some(p) = outer_lock_ptr {
            unsafe { (*p).lock() };
        }
        self.lock.lock();

        // Revalidate the VMA still maps the tree we locked; if it was remapped
        // (or (dis)appeared) while VSpace.lock was dropped for the dance, retry.
        let cur_state: Option<*mut crate::cap::memory_object::VmHierarchyState> =
            if self.tracking.is_null() {
                None
            } else {
                let t = unsafe { &*self.tracking };
                match t.mappings.lookup(virt) {
                    Some((_s, vma)) if !vma.mo().is_null() => Some(unsafe {
                        (*vma.mo())
                            .hierarchy_state
                            .load(core::sync::atomic::Ordering::Acquire)
                    }),
                    _ => None,
                }
            };
        let retry = match (fault_lock, cur_state) {
            (Some(FaultLock::Bound(s)), Some(c)) => c != s,
            (Some(FaultLock::Standalone(_)), Some(c)) => !c.is_null(),
            (Some(_), None) => true,
            (None, Some(_)) => true,
            (None, None) => false,
        };
        if retry {
            self.lock.unlock();
            if let Some(p) = outer_lock_ptr {
                unsafe { (*p).unlock() };
            }
            unsafe { restore_irq(irq) };
            if let Some(fl) = fault_lock {
                unsafe { fl.release_pin() };
            }
            return None;
        }

        let mut mo_ref_delta: i8 = 0;
        let mut mo_ref_vma = VmArea::EMPTY;

        // Post-unlock TLB-shootdown seam: the bound tree's state (null if the MO
        // is standalone). The unmap shootdown is recorded into its rcl and
        // flushed after the locks drop (matches downgrade / destroy / converge).
        let unmap_state: *mut crate::cap::memory_object::VmHierarchyState =
            if let Some(FaultLock::Bound(s)) = fault_lock {
                s
            } else {
                core::ptr::null_mut()
            };

        let result = (|| {
            let entry = self.read_entry(virt, 1).ok_or(VSpaceError::NotMapped)?;
            let page_size = PAGE_SIZE as u64;
            let is_demand = entry & ENTRY_PRESENT == 0 && entry & ENTRY_DEMAND != 0;
            if !is_demand && entry & ENTRY_PRESENT == 0 {
                return Err(VSpaceError::NotMapped);
            }

            if !self.tracking.is_null() {
                let t = unsafe { &mut *self.tracking };
                if let Some((tracked_start, tracked_vma_ref)) = t.mappings.lookup(virt) {
                    let tracked_vma = *tracked_vma_ref;
                    let tracked_len = u64::from(tracked_vma.page_count)
                        .checked_mul(page_size)
                        .ok_or(VSpaceError::InvalidArgument)?;
                    let tracked_end = tracked_start
                        .checked_add(tracked_len)
                        .ok_or(VSpaceError::InvalidArgument)?;
                    if tracked_vma.page_count != 0 && virt >= tracked_start && virt < tracked_end {
                        let page_index = ((virt - tracked_start) / page_size) as u32;
                        let left_pages = page_index;
                        let right_pages = tracked_vma
                            .page_count
                            .checked_sub(page_index + 1)
                            .ok_or(VSpaceError::InvalidArgument)?;
                        let has_mo = !tracked_vma.mo().is_null();
                        let mut tree_alloc = super::node_alloc::PmmNodeAllocator {
                            owner: super::frame::FrameOwner::KernelPrivate {
                                subkind: super::frame::KernelMetaKind::MapleNode,
                            },
                            use_reserve: false,
                        };

                        let make_vma =
                            |start: u64,
                             mo_offset: u32,
                             page_count: u32|
                             -> Result<(u64, VmArea), VSpaceError> {
                                Ok((
                                    start,
                                    VmArea {
                                        obj: tracked_vma.obj,
                                        mo_offset,
                                        page_count,
                                        perms: tracked_vma.perms,
                                        region_kind: tracked_vma.region_kind,
                                        obj_type: tracked_vma.obj_type,
                                        max_prot: tracked_vma.max_prot,
                                        _pad: [0; 4],
                                    },
                                ))
                            };
                        let make_rmap = |start: u64, mo_offset: u32, page_count: u32| {
                            crate::cap::memory_object::ReverseMapEntry {
                                vspace: self_ptr,
                                va_start: start,
                                page_count,
                                mo_offset,
                                perms: tracked_vma.perms,
                                _pad: [0; 7],
                            }
                        };

                        // ---- Reserve phase (no metadata mutation yet) ----
                        //
                        // At most one Maple `InsertReservation` (for `(0,_)`
                        // and `(_,_)` arms) and one rmap ticket (only for
                        // the `(_,_)` arm that materializes a fresh
                        // `right` VmArea). All other arms are pure
                        // replace/remove and need no pre-allocation.
                        // `(0, rp>0)` needs an insert of the new right-shifted
                        // VmArea. `(lp>0, rp>0)` needs an insert of the right
                        // VmArea (left uses in-place replace). The other two
                        // arms only remove/replace → no new tree node.
                        let need_maple = matches!(
                            (left_pages, right_pages),
                            (0, rp) if rp != 0
                        ) || (left_pages != 0 && right_pages != 0);
                        let need_rmap_ticket = has_mo && left_pages != 0 && right_pages != 0;

                        // Precompute interior-split geometry BEFORE reserving,
                        // so the reserve -> commit path is infallible: no rmap
                        // ticket can drop while still PENDING on a fallible `?`
                        // between reserve and `rmap_add_reserved`.
                        let interior_geom: Option<(u64, u32, VmArea, VmArea)> =
                            if left_pages != 0 && right_pages != 0 {
                                let right_start = virt
                                    .checked_add(page_size)
                                    .ok_or(VSpaceError::InvalidArgument)?;
                                let right_mo_offset = tracked_vma
                                    .mo_offset
                                    .checked_add(page_index + 1)
                                    .ok_or(VSpaceError::InvalidArgument)?;
                                let (_, left_vma) =
                                    make_vma(tracked_start, tracked_vma.mo_offset, left_pages)?;
                                let (_, right_vma) =
                                    make_vma(right_start, right_mo_offset, right_pages)?;
                                Some((right_start, right_mo_offset, left_vma, right_vma))
                            } else {
                                None
                            };

                        let maple_resv = if need_maple {
                            match t.mappings.reserve_for_insert(&mut tree_alloc) {
                                Ok(r) => Some(r),
                                Err(_) => return Err(VSpaceError::OutOfMemory),
                            }
                        } else {
                            None
                        };
                        let rmap_ticket = if need_rmap_ticket {
                            match unsafe { (*tracked_vma.mo()).rmap_reserve_slot() } {
                                Ok(tk) => Some(tk),
                                Err(_) => {
                                    if let Some(r) = maple_resv {
                                        r.release(&mut tree_alloc);
                                    }
                                    return Err(VSpaceError::OutOfMemory);
                                }
                            }
                        } else {
                            None
                        };

                        // ---- Commit phase (infallible given reservation) ----
                        match (left_pages, right_pages) {
                            (0, 0) => {
                                crate::kernel::bug::kassert!(
                                    maple_resv.is_none() && rmap_ticket.is_none()
                                );
                                unsafe { t.mappings.remove(tracked_start, &mut tree_alloc) };
                                t.note_vma_removed(&tracked_vma);
                                if has_mo {
                                    unsafe {
                                        (*tracked_vma.mo()).rmap_remove(self_ptr, tracked_start);
                                    }
                                }
                                // Schedule the strong-ref release.
                                // `release_obj_ref` dispatches on
                                // `obj_type`, so this covers both MO
                                // backings (MemoryObject typed
                                // destructor) and Frame mappings (Frame
                                // typed destructor) — frame mappings
                                // reach this arm with `has_mo == false`
                                // but still need their Frame object's
                                // refcount dropped or the carved phys
                                // leaks until process exit.
                                if !tracked_vma.obj.is_null() {
                                    mo_ref_delta = -1;
                                    mo_ref_vma = tracked_vma;
                                }
                            }
                            (0, _) => {
                                let mut maple_resv = maple_resv.expect("maple reserve required");
                                crate::kernel::bug::kassert!(rmap_ticket.is_none());
                                let new_start = virt
                                    .checked_add(page_size)
                                    .ok_or(VSpaceError::InvalidArgument)?;
                                let new_mo_offset = tracked_vma
                                    .mo_offset
                                    .checked_add(1)
                                    .ok_or(VSpaceError::InvalidArgument)?;
                                let (_, new_vma) = make_vma(new_start, new_mo_offset, right_pages)?;

                                unsafe {
                                    t.mappings
                                        .insert_reserved(new_start, new_vma, &mut maple_resv);
                                }
                                t.note_vma_added(&new_vma);

                                if has_mo {
                                    let new_rmap = make_rmap(new_start, new_mo_offset, right_pages);
                                    let replaced = unsafe {
                                        (*tracked_vma.mo()).rmap_replace(
                                            self_ptr,
                                            tracked_start,
                                            new_rmap,
                                        )
                                    };
                                    crate::kernel::bug::kassert!(
                                        replaced,
                                        "rmap replace must succeed on looked-up entry"
                                    );
                                }
                                unsafe {
                                    t.mappings.remove(tracked_start, &mut tree_alloc);
                                }
                                t.note_vma_removed(&tracked_vma);
                                maple_resv.release(&mut tree_alloc);
                            }
                            (_, 0) => {
                                crate::kernel::bug::kassert!(
                                    maple_resv.is_none() && rmap_ticket.is_none()
                                );
                                let (_, new_vma) =
                                    make_vma(tracked_start, tracked_vma.mo_offset, left_pages)?;
                                let ok = unsafe { t.mappings.replace(tracked_start, new_vma) };
                                crate::kernel::bug::kassert!(
                                    ok,
                                    "maple replace must succeed on looked-up entry"
                                );
                                t.note_vma_replaced(&tracked_vma, &new_vma);
                                if has_mo {
                                    let replaced = unsafe {
                                        (*tracked_vma.mo()).rmap_replace(
                                            self_ptr,
                                            tracked_start,
                                            make_rmap(
                                                tracked_start,
                                                tracked_vma.mo_offset,
                                                left_pages,
                                            ),
                                        )
                                    };
                                    crate::kernel::bug::kassert!(
                                        replaced,
                                        "rmap replace must succeed on looked-up entry"
                                    );
                                }
                            }
                            _ => {
                                let mut maple_resv = maple_resv.expect("maple reserve required");
                                let ticket = rmap_ticket.expect("rmap ticket required");
                                // Geometry was precomputed before the reserve, so
                                // nothing below this point can fail — the ticket
                                // is always consumed by `rmap_add_reserved`.
                                let (right_start, right_mo_offset, left_vma, right_vma) =
                                    interior_geom.expect("interior geometry precomputed");

                                // Commit right VmArea via reservation, then
                                // update left in place. No failure edges.
                                unsafe {
                                    t.mappings.insert_reserved(
                                        right_start,
                                        right_vma,
                                        &mut maple_resv,
                                    );
                                }
                                t.note_vma_added(&right_vma);

                                let ok = unsafe { t.mappings.replace(tracked_start, left_vma) };
                                crate::kernel::bug::kassert!(
                                    ok,
                                    "left replace must succeed on looked-up entry"
                                );
                                t.note_vma_replaced(&tracked_vma, &left_vma);

                                if has_mo {
                                    unsafe {
                                        (*tracked_vma.mo()).rmap_add_reserved(
                                            ticket,
                                            make_rmap(right_start, right_mo_offset, right_pages),
                                        );
                                        let replaced = (*tracked_vma.mo()).rmap_replace(
                                            self_ptr,
                                            tracked_start,
                                            make_rmap(
                                                tracked_start,
                                                tracked_vma.mo_offset,
                                                left_pages,
                                            ),
                                        );
                                        crate::kernel::bug::kassert!(
                                            replaced,
                                            "left rmap replace must succeed"
                                        );
                                    }
                                    mo_ref_delta = 1;
                                    mo_ref_vma = tracked_vma;
                                }
                                maple_resv.release(&mut tree_alloc);
                            }
                        }
                    }
                }
            }

            // Demand PTE (PRESENT=0, DEMAND=1): no frame to release, just clear
            if is_demand {
                self.write_entry(virt, 1, 0)?;
                return Ok(());
            }

            let phys = entry & ENTRY_ADDR_MASK;
            if entry & ENTRY_DIRTY != 0 {
                let _ = super::pmm_update_flags(phys, super::frame::FRAME_FLAG_DIRTY, 0);
            }

            // Clear the entry
            self.write_entry(virt, 1, 0)?;

            // Local invlpg is immediate; the remote shootdown is recorded into
            // the tree's rcl for a coalesced post-unlock flush. With the deferred
            // flush the remote TLB is invalidated AFTER the pmm_release_mapping
            // below — the pre-existing fire-and-forget shootdown already had that
            // window; the future sync-shootdown protocol closes it via frame
            // quarantine (the freed frame is released only once the post-unlock
            // flush ACKs). A standalone MO (no tree) keeps an immediate shootdown.
            crate::arch::paging::invlpg(virt);
            if unmap_state.is_null() {
                self.tlb_shootdown(virt);
            } else {
                unsafe { (*unmap_state).rcl.record(self as *mut VSpace, virt) };
            }

            super::pmm_release_mapping(phys);

            Ok(())
        })();

        // Drain the unmap shootdown recorded above (if bound) while the tree
        // lock is still held; flush it post-unlock below (the sync-shootdown
        // seam, matching downgrade / destroy / converge).
        let mut rcl_local = if unmap_state.is_null() {
            RangeChangeList::new()
        } else {
            unsafe { crate::cap::memory_object::VmHierarchyState::drain_rcl(unmap_state) }
        };

        self.lock.unlock();
        if let Some(p) = outer_lock_ptr {
            unsafe { (*p).unlock() };
        }
        unsafe { restore_irq(irq) };
        unsafe { rcl_local.flush() };

        if result.is_ok() {
            match mo_ref_delta {
                -1 => unsafe { mo_ref_vma.release_obj_ref() },
                1 => unsafe { mo_ref_vma.retain_obj_ref() },
                _ => {}
            }
        }

        if let Some(fl) = fault_lock {
            unsafe { fl.release_pin() };
        }
        Some(result)
    }

    /// Reject if raising `[virt, virt + count*PAGE)` to `flags` would
    /// exceed any covering VmArea's `max_prot` ceiling. Present or demand
    /// pages with no tracked VmArea default-deny W/X elevation because the
    /// kernel recorded no backing-cap ceiling for them; absent holes are left
    /// to the normal not-mapped path. Lowering (no W and no X requested) is
    /// always allowed. The caller must hold `self.lock`; this only reads the
    /// mapping tree, so the scan is a pure pre-flight that leaves PTEs
    /// untouched on rejection — giving `mprotect` POSIX all-or-nothing
    /// atomicity and acting as the kernel backstop against a process raising
    /// perms past its backing cap's rights by invoking its VSpace cap directly.
    fn check_protect_ceiling_locked(
        &self,
        virt: VirtAddr,
        count: usize,
        flags: PageFlags,
    ) -> Result<(), VSpaceError> {
        if self.tracking.is_null() || (!flags.writable && !flags.executable) {
            return Ok(());
        }
        let tracking = unsafe { &*self.tracking };
        for i in 0..count {
            let addr = virt + (i as u64) * PAGE_SIZE as u64;
            let covered = match tracking.mappings.lookup(addr) {
                Some((start, vma)) if addr < start + (vma.page_count as u64) * PAGE_SIZE as u64 => {
                    if flags.writable && (vma.max_prot & VmArea::MAX_PROT_WRITE) == 0 {
                        return Err(VSpaceError::PermissionDenied);
                    }
                    if flags.executable && (vma.max_prot & VmArea::MAX_PROT_EXEC) == 0 {
                        return Err(VSpaceError::PermissionDenied);
                    }
                    true
                }
                _ => false,
            };
            if !covered {
                // Present-but-untracked: the kernel recorded no `max_prot` for
                // this page, so it cannot prove a W/X elevation stays within a
                // backing cap's rights — default-deny it. An absent page (no
                // PRESENT/DEMAND bit — including a huge PDE that `read_entry`
                // reports as `None`) is left to the normal not-mapped path;
                // `protect` cannot widen a huge page today, so 4 KiB leaves are
                // gated exactly.
                let present_or_demand = self
                    .read_entry(addr, 1)
                    .map(|e| e & (ENTRY_PRESENT | ENTRY_DEMAND) != 0)
                    .unwrap_or(false);
                if present_or_demand {
                    return Err(VSpaceError::PermissionDenied);
                }
            }
        }
        Ok(())
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
            self.check_protect_ceiling_locked(virt, 1, flags)?;
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
            crate::arch::paging::invlpg(virt);
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

        if let Err(e) = self.check_protect_ceiling_locked(virt, count, flags) {
            self.lock.unlock();
            unsafe { restore_irq(irq) };
            return Err(e);
        }

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
                #[cfg(target_arch = "x86_64")]
                {
                    let cr3 = crate::arch::paging::read_cr3();
                    unsafe {
                        crate::arch::paging::write_cr3(cr3);
                    }
                }
                #[cfg(target_arch = "aarch64")]
                {
                    crate::arch::paging::flush_tlb_all();
                }
            }
            self.tlb_shootdown_all();
        } else if protected > 0 {
            let do_local_flush = self.active_on_current_cpu();
            let page_size = PAGE_SIZE as u64;
            for i in 0..count {
                let addr = virt + (i as u64) * page_size;
                if do_local_flush {
                    crate::arch::paging::invlpg(addr);
                }
                self.tlb_shootdown(addr);
            }
        }

        // Pages transitioning to executable need D-cache clean + I-cache
        // invalidation (no-op on x86_64; required on aarch64 where I/D
        // caches are split).
        if flags.executable && protected > 0 {
            let page_size = PAGE_SIZE as u64;
            for i in 0..count {
                let addr = virt + (i as u64) * page_size;
                if let Some(entry) = self.read_entry(addr, 1) {
                    if entry & ENTRY_PRESENT != 0 {
                        let phys = entry & ENTRY_ADDR_MASK;
                        crate::arch::paging::flush_dcache_pou_page(phys_to_virt(phys) as u64);
                    }
                }
            }
            crate::arch::paging::flush_icache_all();
        }

        self.lock.unlock();
        unsafe { restore_irq(irq) };

        Ok(protected)
    }

    /// Share a read-only page from self into dst VSpace.
    ///
    /// Copies the PTE only when it is present **and** read-only.
    /// Writable or absent pages return an error — the source VSpace is
    /// never modified (no COW marking, no TLB flush on src).
    pub fn share_ro_page_to(
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
            let src_entry = self
                .read_entry(src_vaddr, 1)
                .ok_or(VSpaceError::NotMapped)?;

            if src_entry & ENTRY_PRESENT == 0 {
                return Err(VSpaceError::NotMapped);
            }

            // Reject writable pages — share_ro only shares read-only
            // mappings; writable/COW sharing goes through MO clone.
            if src_entry & ENTRY_WRITABLE != 0 {
                return Err(VSpaceError::InvalidArgument);
            }

            let phys = src_entry & ENTRY_ADDR_MASK;
            let flags = src_entry & !ENTRY_ADDR_MASK;

            let is_user = (flags & ENTRY_USER) != 0;
            dst.ensure_table(dst_vaddr, 1, is_user)?;
            if let Some(entry) = dst.read_entry(dst_vaddr, 1) {
                if entry & ENTRY_PRESENT != 0 {
                    return Err(VSpaceError::AlreadyMapped);
                }
            }

            dst.write_entry(dst_vaddr, 1, phys | flags)?;
            super::pmm_retain_mapping(phys);
            crate::arch::paging::invlpg(dst_vaddr);
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

    /// Per-page fork install. Caller must already hold both `self.lock`
    /// (parent) and `dst.lock` (child) with IRQs disabled. Returns the number
    /// of pages successfully installed into the child (holes are possible —
    /// the loop `continue`s on any per-page failure).
    ///
    /// # Safety
    /// - Both `self.lock` and `dst.lock` must be held, IRQs disabled.
    /// - Locks must have been acquired in canonical pointer order.
    /// Pre-reserve every leaf page-table node `dst` will need for a
    /// fork over `[va_start, va_start + page_count * PAGE_SIZE)` while
    /// recording the newly-allocated page-table pages in an
    /// `EnsureTablesGuard`. Caller commits the guard with `forget()`
    /// on success or `rollback(dst)` on a downstream reservation
    /// failure (rmap ticket / maple-tree slot OOM); the guard then
    /// unlinks the new PT pages from their parents and returns the
    /// frames to PMM, so a fork that aborts before commit leaves no
    /// half-built page-table tree behind.
    ///
    /// # Safety
    /// Caller must hold `dst.lock` (the destination VSpace lock).
    pub(crate) unsafe fn ensure_tables_for_range(
        dst: &mut VSpace,
        va_start: VirtAddr,
        page_count: usize,
    ) -> Result<EnsureTablesGuard, VSpaceError> {
        let mut guard = EnsureTablesGuard::new();
        for i in 0..page_count {
            let vaddr = va_start + (i as u64) * PAGE_SIZE as u64;
            if let Err(e) = dst.ensure_table_inner(vaddr, 1, true, Some(&mut guard)) {
                unsafe { guard.rollback(dst) };
                return Err(e);
            }
        }
        Ok(guard)
    }

    /// Fork a contiguous chunk of parent's address space into `dst`.
    ///
    /// **All-or-nothing.** Caller pre-reserves child PT nodes via
    /// `ensure_tables_for_range`. After that, every per-page step is
    /// guaranteed to succeed (any `write_entry` failure is a kernel
    /// invariant break, asserted in debug builds).
    ///
    /// Return value semantics:
    ///   * `0`    — pre-condition failed (currently only `va_start`
    ///              alignment); caller must rollback metadata
    ///              reservation.
    ///   * `page_count` — execute phase completed without invariant
    ///              break. Parent holes (no PT, level-2 huge page,
    ///              non-present + non-demand leaf) are silently
    ///              skipped without changing parent state and without
    ///              setting bitmap bits, but they DO NOT reduce the
    ///              return value: a chunk that finds parent fully
    ///              unmapped is still a successful no-op transaction.
    ///
    /// Returning the `forked` page tally would force callers to
    /// re-litigate the "did the chunk transactionally commit?"
    /// question on every chunk in a sequential fork, and conflate
    /// failure with legitimate parent unmapping. Return value is
    /// strictly `0` or `page_count`.
    ///
    /// `bitmap` (length `(page_count + 7) / 8` bytes, zero-initialized
    /// by caller) is updated by this function: bit `i` is set iff the
    /// parent PTE at `va_start + i*PAGE_SIZE` was flipped from
    /// "writable, !cow" to "!writable, cow" by this call. The bitmap
    /// is the only state `vspace_undo_fork_range` needs to restore the
    /// parent side precisely without re-deriving which PTEs were
    /// authored vs. inherited COW.
    pub(crate) unsafe fn fork_range_locked(
        &mut self,
        dst: &mut VSpace,
        va_start: VirtAddr,
        page_count: usize,
        bitmap: &mut [u8],
    ) -> usize {
        if va_start & (PAGE_SIZE as u64 - 1) != 0 {
            return 0;
        }

        for i in 0..page_count {
            let vaddr = va_start + (i as u64) * PAGE_SIZE as u64;

            // Parent has no PT covering this vaddr (or it's a 2 MiB
            // huge mapping that read_entry refuses to descend into).
            // Treat as a hole — child stays unmapped, bitmap untouched.
            let parent_entry = match self.read_entry(vaddr, 1) {
                Some(e) => e,
                None => continue,
            };

            if parent_entry & ENTRY_PRESENT == 0 {
                if parent_entry & ENTRY_DEMAND != 0 {
                    // Demand entry: copy parent's encoding to child verbatim
                    // (no PTE flip on parent side, no bitmap mark). Tables
                    // are pre-reserved.
                    let r = dst.write_entry(vaddr, 1, parent_entry);
                    crate::kernel::bug::kassert!(
                        r.is_ok(),
                        "write_entry failed after ensure_tables_for_range pre-reserve"
                    );
                }
                // Non-present + non-demand leaf == hole; skip silently.
                continue;
            }

            let phys = parent_entry & ENTRY_ADDR_MASK;
            let mut flags = Self::entry_flags_to_page_flags(parent_entry);
            let (cow_eligible, vma_writable) = if !self.tracking.is_null() {
                let tracking = unsafe { &*self.tracking };
                match tracking.mappings.lookup(vaddr) {
                    Some((_start, vma)) if !vma.mo().is_null() => (true, vma.perms & 0x01 != 0),
                    Some((_start, _vma)) => (false, false),
                    None => (true, flags.writable || flags.cow),
                }
            } else {
                (true, flags.writable || flags.cow)
            };

            // MO-backed private mappings follow the logical writability of
            // the VMA, not just the transient hardware writability of the
            // current parent PTE. Non-MO mappings (device/frame mappings)
            // are shared as mappings and must not be converted into COW.
            if cow_eligible && (flags.writable || flags.cow || vma_writable) {
                let was_writable_only = flags.writable && !flags.cow;
                flags.writable = false;
                flags.cow = true;

                let new_parent = (parent_entry & !ENTRY_WRITABLE) | ENTRY_COW;
                if new_parent != parent_entry {
                    let r = self.write_entry(vaddr, 1, new_parent);
                    crate::kernel::bug::kassert!(
                        r.is_ok(),
                        "write_entry failed after ensure_tables_for_range pre-reserve"
                    );
                    // Use ASID-specific TLB invalidation for the parent VSpace
                    // to avoid flushing unrelated VSpaces (e.g. mmsrv's IPC
                    // buffer at the same VA).
                    #[cfg(target_arch = "aarch64")]
                    {
                        let parent_asid = if !self.tracking.is_null() {
                            unsafe {
                                (*self.tracking)
                                    .asid
                                    .load(core::sync::atomic::Ordering::Relaxed)
                            }
                        } else {
                            0
                        };
                        crate::arch::paging::invlpg_asid(vaddr, parent_asid);
                    }
                    #[cfg(not(target_arch = "aarch64"))]
                    {
                        crate::arch::paging::invlpg(vaddr);
                    }
                    self.tlb_shootdown(vaddr);

                    // Bitmap records pages this call transitioned writable→COW.
                    // Pages already COW pre-fork (was_writable_only==false)
                    // are not recorded — undo must not unset COW on those.
                    if was_writable_only {
                        let byte_idx = i / 8;
                        let bit = 1u8 << (i & 7);
                        if byte_idx < bitmap.len() {
                            bitmap[byte_idx] |= bit;
                        }
                    }
                }
            }

            // Map in child with same flags (COW if was writable). Tables are
            // pre-reserved; write_entry cannot fail with NotMapped.
            let child_entry = phys | Self::flags_to_entry_flags(flags);
            let r = dst.write_entry(vaddr, 1, child_entry);
            crate::kernel::bug::kassert!(
                r.is_ok(),
                "write_entry failed after ensure_tables_for_range pre-reserve"
            );

            super::pmm_retain_mapping(phys);
        }

        // All-or-nothing: pre-reserve already covered the only failure
        // mode; the loop above is infallible.
        page_count
    }

    /// Reverse of `fork_range_locked` for a previously-committed chunk.
    ///
    /// `bitmap` carries the same bit pattern that `fork_range_locked`
    /// wrote on commit: bit `i` set ⇔ this chunk flipped parent's PTE
    /// at page `i` from writable → COW, so undo restores writable on
    /// exactly those pages and TLB-shoots them down. Pages with bit
    /// clear were either non-present, demand, or already COW pre-fork
    /// — undo leaves them as-is.
    ///
    /// Child PTEs in the chunk range are unconditionally cleared (the
    /// chunk installed them; undo removes them). PMM map-counts are
    /// released for every present child PTE.
    ///
    /// # Safety
    /// Caller must hold both `self.lock` and `dst.lock`.
    pub(crate) unsafe fn undo_fork_range_locked(
        &mut self,
        dst: &mut VSpace,
        va_start: VirtAddr,
        page_count: usize,
        bitmap: &[u8],
    ) {
        if va_start & (PAGE_SIZE as u64 - 1) != 0 {
            return;
        }

        for i in 0..page_count {
            let vaddr = va_start + (i as u64) * PAGE_SIZE as u64;

            // 1. Restore parent PTE writable for pages we marked.
            let byte_idx = i / 8;
            let bit = 1u8 << (i & 7);
            let we_set_cow = byte_idx < bitmap.len() && (bitmap[byte_idx] & bit) != 0;
            if we_set_cow {
                if let Some(parent_entry) = self.read_entry(vaddr, 1) {
                    if parent_entry & ENTRY_PRESENT != 0 {
                        let restored = (parent_entry | ENTRY_WRITABLE) & !ENTRY_COW;
                        let _ = self.write_entry(vaddr, 1, restored);
                        #[cfg(target_arch = "aarch64")]
                        {
                            let parent_asid = if !self.tracking.is_null() {
                                unsafe {
                                    (*self.tracking)
                                        .asid
                                        .load(core::sync::atomic::Ordering::Relaxed)
                                }
                            } else {
                                0
                            };
                            crate::arch::paging::invlpg_asid(vaddr, parent_asid);
                        }
                        #[cfg(not(target_arch = "aarch64"))]
                        {
                            crate::arch::paging::invlpg(vaddr);
                        }
                        self.tlb_shootdown(vaddr);
                    }
                }
            }
        }

        // 2. Clear the forked child's chunk PTEs and release their PMM
        //    map-counts (demand entries are cleared too).
        unsafe { dst.release_child_range_locked(va_start, page_count) };
    }

    /// Clear this VSpace's PTEs over `[va_start, va_start + page_count)`
    /// and release each present mapping's PMM map-count; demand entries
    /// are cleared too. Shared by `undo_fork_range_locked` (child-side
    /// teardown) and the idempotent `CHUNK_SPLIT_KIND_NONE` undo arm,
    /// which previously dropped the child VMA/rmap but leaked the PTE
    /// map-counts.
    ///
    /// # Safety
    /// Caller must hold `self.lock`.
    pub(crate) unsafe fn release_child_range_locked(
        &mut self,
        va_start: VirtAddr,
        page_count: usize,
    ) {
        if va_start & (PAGE_SIZE as u64 - 1) != 0 {
            return;
        }
        for i in 0..page_count {
            let vaddr = va_start + (i as u64) * PAGE_SIZE as u64;
            if let Some(child_entry) = self.read_entry(vaddr, 1) {
                if child_entry & ENTRY_PRESENT != 0 {
                    let phys = child_entry & ENTRY_ADDR_MASK;
                    let _ = self.write_entry(vaddr, 1, 0);
                    #[cfg(target_arch = "aarch64")]
                    {
                        let child_asid = if !self.tracking.is_null() {
                            unsafe {
                                (*self.tracking)
                                    .asid
                                    .load(core::sync::atomic::Ordering::Relaxed)
                            }
                        } else {
                            0
                        };
                        crate::arch::paging::invlpg_asid(vaddr, child_asid);
                    }
                    #[cfg(not(target_arch = "aarch64"))]
                    {
                        crate::arch::paging::invlpg(vaddr);
                    }
                    self.tlb_shootdown(vaddr);
                    super::pmm_release_mapping(phys);
                } else if child_entry & ENTRY_DEMAND != 0 {
                    let _ = self.write_entry(vaddr, 1, 0);
                }
            }
        }
    }

    /// Transactional COW installation: publish a new child-MO backing
    /// frame atomically across (PTE, MO radix tree, PMM owner).
    ///
    /// Caller contract:
    /// - `VSpace.lock` is held.
    /// - `new_phys` has PMM owner `*retag_from` (e.g., `KernelPrivate{General}`
    ///   for ad-hoc alloc, `KernelPrivate{CowPool}` for pool-consumed,
    ///   `KernelPrivate{CowPool}` for syscall donation).
    /// - `new_flags` contains the final PTE flag bits (writable, no-COW,
    ///   etc.) without the physical-address portion.
    /// - `child_mo` points to the MO whose radix tree should hold the
    ///   new phys at `mo_page_idx`.
    /// - `old_phys` is the old PTE's physical-address portion (for
    ///   mapping-ref accounting).
    ///
    /// Protocol (all under `child_mo.commit_lock`):
    /// 1. Reserve radix slot with `PHYS_TAG_BUSY`.
    /// 2. Publish: `write_entry` → TLB flush → pmm_retain/release.
    /// 3. Finalize: radix slot `BUSY → new_phys`.
    /// 4. Commit point: `pmm_set_owner(new_phys, MoData{...})`.
    ///
    /// Any failure before the commit point rolls back to pre-call state
    /// across all three domains. External observers (commit_lock not held)
    /// see only pre-call or post-call `(PTE, radix, PMM owner)` tuples.
    ///
    /// Returns:
    /// - `Ok(())` — transaction committed.
    /// - `Err(RaceLost)` — another CPU already resolved or is resolving.
    /// - `Err(OutOfMemory)` — radix intermediate node allocation failed.
    /// - `Err(NotMapped)` — `write_entry` failed (PTE path broken).
    ///
    /// # Safety
    /// - `child_mo` must point to a live `MemoryObject`.
    /// - `page_vaddr` must be page-aligned and within this VSpace.
    /// - `retag_from` must match the current PMM owner of `new_phys`.
    pub unsafe fn cow_install_atomic(
        &mut self,
        child_mo: *mut crate::cap::memory_object::MemoryObject,
        mo_page_idx: usize,
        page_vaddr: VirtAddr,
        new_phys: PhysAddr,
        new_flags: u64,
        old_phys: PhysAddr,
    ) -> Result<(), VSpaceError> {
        use crate::cap::memory_object::PHYS_TAG_BUSY;

        let mo = unsafe { &mut *child_mo };
        let mut node_alloc = super::node_alloc::PmmNodeAllocator {
            owner: super::frame::FrameOwner::MoMeta {
                mo: child_mo,
                subkind: super::frame::MoMetaKind::Radix,
            },
            use_reserve: true,
        };

        mo.commit_lock.lock();

        // 1. Reserve slot with BUSY sentinel.
        let reserved = unsafe {
            mo.pages
                .reserve_slot(mo_page_idx, PHYS_TAG_BUSY, &mut node_alloc)
        };
        match reserved {
            Ok(true) => {}
            Ok(false) => {
                mo.commit_lock.unlock();
                return Err(VSpaceError::RaceLost);
            }
            Err(()) => {
                mo.commit_lock.unlock();
                return Err(VSpaceError::OutOfMemory);
            }
        }

        // 2a. Publish new PTE. On failure, roll back the reservation.
        if self
            .write_entry(page_vaddr, 1, new_phys | new_flags)
            .is_err()
        {
            mo.pages.remove(mo_page_idx);
            mo.commit_lock.unlock();
            return Err(VSpaceError::NotMapped);
        }

        // 2b. TLB invalidation before mapping-ref release so remote CPUs
        // cannot observe a stale PTE pointing at the old frame after its
        // map_count dropped.
        crate::arch::paging::invlpg(page_vaddr);
        self.tlb_shootdown(page_vaddr);

        // 2c. Mapping-ref accounting.
        super::pmm_retain_mapping(new_phys);
        super::pmm_release_mapping(old_phys);
        let _ = super::pmm_update_flags(
            new_phys,
            super::frame::FRAME_FLAG_REFERENCED | super::frame::FRAME_FLAG_ACTIVE,
            0,
        );

        // 2d. I-cache coherence for executable COW pages.
        if new_flags & ENTRY_NO_EXECUTE == 0 {
            crate::arch::paging::flush_dcache_pou_page(phys_to_virt(new_phys) as u64);
            crate::arch::paging::flush_icache_all();
        }

        // 3. Finalize: rewrite BUSY → new_phys. Intermediate nodes are
        // already present (Reserve grew them), so the leaf overwrite is
        // infallible.
        let _ = unsafe { mo.pages.insert(mo_page_idx, new_phys, &mut node_alloc) };

        // 4. Commit point: flip PMM owner to the child MO. Prior to this
        // line external observers see radix=new_phys, PMM=retag_from
        // (a transient state allowed only under commit_lock). After this
        // line the 3-way tuple is fully post-call.
        super::pmm_set_owner(
            new_phys,
            &super::frame::FrameOwner::MoData {
                mo: child_mo,
                page_idx: mo_page_idx as u32,
            },
        );

        mo.commit_lock.unlock();
        Ok(())
    }

    /// Resolve the source physical address the COW break for page
    /// `mo_page_idx` of `child_mo` should byte-copy from, or `None` if the
    /// source cannot be safely touched.
    ///
    /// This is the **single source of truth** for the COW-break source: both
    /// the gate decision (some sources cannot be copied) and the copy's
    /// source address come from one chain walk under the tree lock, so the
    /// caller never compares an out-of-band PTE-derived `phys` against a
    /// fresh chain-derived one.
    ///
    /// Borrowed-frames MOs are valid `MO_CLONE_RANGE` parents: their pages
    /// live in the immortal initrd device-untyped and are never
    /// owned/committed/evicted/freed by the MO
    /// (`cap/memory_object.rs:1026-1071`, evict path early-returns for
    /// `BorrowedFrames` at line 907, destroy skips at line 2233). When the
    /// chain resolves a child MO's page to a borrowed source, byte-copying
    /// the borrowed frame into the child's new MoData frame is safe: the
    /// source stays in place (its `PHYS_TAG_BORROWED` is preserved), and the
    /// kernel never frees it.
    ///
    /// For non-borrowed resident sources a legacy phys-based filter applies:
    /// a true device-MEM frame (MMIO, non-borrowed) must not be touched,
    /// so `MoData` owner or non-device untyped is required.
    ///
    /// `Pager` (lazy pager-backed — no committed frame yet), `Zero`
    /// (logical zero — caller fills a zero page), and `Failed` (pager
    /// tombstone — fault propagates as SIGBUS) return `None`: there is no
    /// resident frame to copy from, and the caller must let the fault fall
    /// through to the pager / mmsrv IPC rather than attempt a break.
    ///
    /// # Safety
    /// Caller holds `child_mo`'s per-tree serialization lock so the chain
    /// walk in `effective_page_source_locked` needs no hand-over-hand pins.
    #[inline]
    unsafe fn cow_break_source_locked(
        child_mo: *mut crate::cap::memory_object::MemoryObject,
        mo_page_idx: usize,
    ) -> Option<u64> {
        use crate::cap::memory_object::PageSource;
        // SAFETY: tree lock held; `effective_page_source_locked` requires it.
        match unsafe { (*child_mo).effective_page_source_locked(mo_page_idx) } {
            PageSource::Resident {
                phys,
                borrowed: true,
                ..
            } => Some(phys),
            PageSource::Resident {
                phys,
                borrowed: false,
                ..
            } => Self::phys_is_touchable_data_page(phys).then_some(phys),
            PageSource::Pager { .. } | PageSource::Zero | PageSource::Failed => None,
        }
    }

    /// `true` iff `phys` names a frame the kernel may byte-copy into a
    /// MoData-owned frame on COW break. Excludes true device-MEM frames
    /// (MMIO, non-borrowed): the kernel must never read from or write to
    /// them. PMM-tracked `MoData` frames pass; non-device `UntypedReserved`
    /// frames pass; everything else (PAGER-backed, KernelPrivate, etc.)
    /// fails.
    #[inline]
    fn phys_is_touchable_data_page(phys: PhysAddr) -> bool {
        match super::pmm_lookup(phys) {
            Some(meta) => match meta.owner_tag {
                super::frame::OwnerTag::MoData => true,
                super::frame::OwnerTag::UntypedReserved => match meta.to_owner() {
                    super::frame::FrameOwner::UntypedReserved { ut } => {
                        !ut.is_null() && unsafe { !(*ut).is_device }
                    }
                    _ => false,
                },
                _ => false,
            },
            None => {
                let ut = crate::init::main::find_untyped_for_phys(phys);
                !ut.is_null() && unsafe { !(*ut).is_device }
            }
        }
    }

    /// On a lost CoW-break race, converge the faulting PTE at `page_vaddr`
    /// onto the private frame `child_mo` already owns for `mo_page_idx` (the
    /// winning sibling installed it), rather than re-copying. Returns `true`
    /// if it converged. Caller holds `self.lock`; this takes
    /// `child_mo.commit_lock` (respecting `VSpace.lock → commit_lock`).
    ///
    /// # Safety
    /// `child_mo` must point at a live MemoryObject.
    unsafe fn cow_converge_to_owned(
        &mut self,
        child_mo: *mut crate::cap::memory_object::MemoryObject,
        mo_page_idx: usize,
        page_vaddr: VirtAddr,
        old_phys: PhysAddr,
    ) -> bool {
        use crate::cap::memory_object::{PHYS_TAG_BUSY, PHYS_TAG_MASK};
        let owned = unsafe {
            let mo = &*child_mo;
            mo.commit_lock.lock();
            let e = mo.pages.get(mo_page_idx);
            mo.commit_lock.unlock();
            e
        };
        if owned & PHYS_TAG_BUSY != 0 {
            return false;
        }
        let owned_phys = owned & !PHYS_TAG_MASK;
        if owned == 0 || owned_phys == 0 || owned_phys == old_phys {
            return false;
        }
        let entry = match self.read_entry(page_vaddr, 1) {
            Some(e) => e,
            None => return false,
        };
        if entry & ENTRY_PRESENT == 0 || entry & ENTRY_COW == 0 {
            return false;
        }
        let new_pte = (entry & !ENTRY_ADDR_MASK & !ENTRY_COW) | owned_phys | ENTRY_WRITABLE;
        if self.write_entry(page_vaddr, 1, new_pte).is_err() {
            return false;
        }
        crate::arch::paging::invlpg(page_vaddr);
        self.tlb_shootdown(page_vaddr);
        super::pmm_retain_mapping(owned_phys);
        super::pmm_release_mapping(old_phys);
        true
    }

    /// Drop-revalidate dance step 1: under `VSpace.lock`, find the lock that
    /// serializes the COW tree of the MO backing `page_vaddr`, PIN it (one
    /// extra refcount so it survives the window after `VSpace.lock` is dropped
    /// and before the outer lock is taken), then release `VSpace.lock`. Returns
    /// `None` if `page_vaddr` is not mapped to an MO. The caller drops the pin
    /// via [`FaultLock::release_pin`] after releasing every tree / VSpace lock.
    ///
    /// # Safety
    /// `self` is a live VSpace.
    unsafe fn discover_fault_lock(&mut self, page_vaddr: VirtAddr) -> Option<FaultLock> {
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();
        let out = if self.tracking.is_null() {
            None
        } else {
            let t = unsafe { &*self.tracking };
            match t.mappings.lookup(page_vaddr) {
                Some((_start, vma)) if !vma.mo().is_null() => {
                    let mo = vma.mo();
                    let state = unsafe {
                        (*mo)
                            .hierarchy_state
                            .load(core::sync::atomic::Ordering::Acquire)
                    };
                    if state.is_null() {
                        unsafe {
                            crate::cap::increment_refcount(
                                mo as *mut crate::cap::object::KernelObject,
                            )
                        };
                        Some(FaultLock::Standalone(mo))
                    } else {
                        unsafe {
                            crate::cap::increment_refcount(
                                state as *mut crate::cap::object::KernelObject,
                            )
                        };
                        Some(FaultLock::Bound(state))
                    }
                }
                _ => None,
            }
        };
        self.lock.unlock();
        unsafe { restore_irq(irq) };
        out
    }

    pub fn handle_cow_fault(
        &mut self,
        fault_addr: VirtAddr,
        fault: &PageFaultInfo,
    ) -> Result<bool, VSpaceError> {
        // Need a present + write + user page fault.
        if !(fault.present && fault.write && fault.user) {
            return Ok(false);
        }

        let page_vaddr = fault_addr & !((PAGE_SIZE as u64) - 1);

        // Drop-revalidate dance: a COW PTE implies a bound MO, so its per-tree
        // `VmHierarchyState` lock must be taken OUTSIDE `VSpace.lock`. Discover
        // (and pin) it under `VSpace.lock`, drop that lock, take the tree lock,
        // then re-take `VSpace.lock` and revalidate everything from live state.
        let fault_lock = match unsafe { self.discover_fault_lock(page_vaddr) } {
            Some(fl) => fl,
            None => return Ok(false),
        };
        let tree_state = match fault_lock {
            FaultLock::Bound(state) => state,
            // A standalone MO cannot carry a COW PTE — stale fault.
            FaultLock::Standalone(_) => {
                unsafe { fault_lock.release_pin() };
                return Ok(false);
            }
        };

        // Set when a CoW break installs a fresh private frame; drives the
        // post-break sibling convergence so the MO's other mappings of this
        // page stay coherent.
        let mut broke: Option<(*mut crate::cap::memory_object::MemoryObject, usize)> = None;

        let irq = unsafe { save_irq_disable() };
        unsafe { (*tree_state).lock.lock() };
        self.lock.lock();

        let result = (|| {
            let entry = self
                .read_entry(page_vaddr, 1)
                .ok_or(VSpaceError::NotMapped)?;
            if entry & ENTRY_PRESENT == 0 || entry & ENTRY_COW == 0 {
                return Ok(false);
            }

            // Resolve the child MO + page index FIRST. Without a backing
            // MO the atomic transaction cannot close (no radix tree to
            // commit into), so bail before allocating.
            let (child_mo, mo_page_idx) = {
                if self.tracking.is_null() {
                    return Err(VSpaceError::NotMapped);
                }
                let t = unsafe { &*self.tracking };
                match t.mappings.lookup(page_vaddr) {
                    Some((start, vma)) if !vma.mo().is_null() => {
                        let idx = vma.mo_offset as usize
                            + ((page_vaddr - start) / PAGE_SIZE as u64) as usize;
                        (vma.mo(), idx)
                    }
                    _ => return Err(VSpaceError::NotMapped),
                }
            };

            // Revalidate the MO still belongs to the tree we locked; if the VMA
            // was remapped while VSpace.lock was dropped for the dance, re-fault.
            if unsafe {
                (*child_mo)
                    .hierarchy_state
                    .load(core::sync::atomic::Ordering::Acquire)
            } != tree_state
            {
                return Ok(false);
            }

            // Resolve the COW-break source under the tree lock — single source
            // of truth for both the gate (can we copy?) and the copy source.
            // SAFETY: tree lock held (see `discover_fault_lock` dance above).
            let src_phys = match unsafe { Self::cow_break_source_locked(child_mo, mo_page_idx) } {
                Some(p) => p,
                None => return Err(VSpaceError::NotCow),
            };
            let scratch_owner = super::frame::FrameOwner::KernelPrivate {
                subkind: super::frame::KernelMetaKind::General,
            };
            let new_phys = pmm_alloc(&scratch_owner).ok_or(VSpaceError::OutOfMemory)?;

            unsafe {
                let src = phys_to_virt(src_phys) as *const u8;
                let dst = phys_to_virt(new_phys) as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE);
            }

            let mut new_flags = entry & !ENTRY_ADDR_MASK;
            new_flags |= ENTRY_WRITABLE;
            new_flags &= !ENTRY_COW;

            match unsafe {
                self.cow_install_atomic(
                    child_mo,
                    mo_page_idx,
                    page_vaddr,
                    new_phys,
                    new_flags,
                    src_phys,
                )
            } {
                Ok(()) => {
                    broke = Some((child_mo, mo_page_idx));
                    Ok(true)
                }
                Err(VSpaceError::RaceLost) => {
                    // Rollback: scratch frame never reached the commit point.
                    super::pmm_free(new_phys, &scratch_owner);
                    // Another mapping of this MO won the break and now owns a
                    // private frame for the page. Converge this PTE onto it so
                    // the shared mappings stay coherent without re-copying.
                    if unsafe {
                        self.cow_converge_to_owned(child_mo, mo_page_idx, page_vaddr, src_phys)
                    } {
                        return Ok(true);
                    }
                    // Otherwise re-read the PTE: a concurrent break must have
                    // left it RW=1 && !COW. If it is still COW, this is a
                    // structural bug and silently returning Ok(true) would spin
                    // the instruction.
                    let re_entry = self
                        .read_entry(page_vaddr, 1)
                        .ok_or(VSpaceError::RaceLost)?;
                    if re_entry & ENTRY_PRESENT != 0
                        && re_entry & ENTRY_WRITABLE != 0
                        && re_entry & ENTRY_COW == 0
                    {
                        Ok(true)
                    } else {
                        crate::kernel::printk::serial_puts(
                            "[COW_FAULT] RaceLost with PTE still COW — propagating fault\n",
                        );
                        Err(VSpaceError::RaceLost)
                    }
                }
                Err(e) => {
                    // Rollback: scratch frame is still `KernelPrivate{General}`
                    // (commit point never reached), so returning it to PMM is
                    // the full recovery.
                    super::pmm_free(new_phys, &scratch_owner);
                    Err(e)
                }
            }
        })();

        // Release the faulting VSpace.lock but keep the tree lock so the
        // sibling convergence is serialized against concurrent downgrade /
        // faults on the same tree. Convergence takes each sibling VSpace.lock
        // independently (the tree lock is OUTER to every VSpace.lock).
        self.lock.unlock();
        if matches!(result, Ok(true)) {
            if let Some((child_mo, idx)) = broke {
                unsafe {
                    (*child_mo).converge_sibling_mappings_to_owned(
                        idx,
                        self as *mut VSpace,
                        page_vaddr,
                    );
                }
            }
        }
        // Drain converge's recorded sibling shootdowns under the tree lock;
        // flush them post-unlock (the sync-shootdown seam). The faulting page's
        // own shootdown already fired immediately inside the locked section.
        let mut rcl_local =
            unsafe { crate::cap::memory_object::VmHierarchyState::drain_rcl(tree_state) };
        unsafe { (*tree_state).lock.unlock() };
        unsafe { restore_irq(irq) };
        unsafe { rcl_local.flush() };
        // Drop the discovery pin only after every lock is released —
        // `release_object` takes `REAPER_LOCK`.
        unsafe { fault_lock.release_pin() };
        result
    }

    pub fn handle_accessed_fault(
        &mut self,
        fault_addr: VirtAddr,
        fault: &PageFaultInfo,
    ) -> Result<bool, VSpaceError> {
        if !fault.user {
            return Ok(false);
        }

        let page_vaddr = fault_addr & !((PAGE_SIZE as u64) - 1);

        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let result = (|| {
            let entry = match self.read_entry(page_vaddr, 1) {
                Some(entry) => entry,
                None => return Ok(false),
            };
            if entry & ENTRY_PRESENT == 0 || entry & ENTRY_ACCESSED != 0 {
                return Ok(false);
            }

            self.write_entry(page_vaddr, 1, entry | ENTRY_ACCESSED)?;
            crate::arch::paging::invlpg(page_vaddr);
            self.tlb_shootdown(page_vaddr);

            let phys = entry & ENTRY_ADDR_MASK;
            let _ = super::pmm_update_flags(
                phys,
                super::frame::FRAME_FLAG_REFERENCED | super::frame::FRAME_FLAG_ACTIVE,
                0,
            );
            Ok(true)
        })();

        self.lock.unlock();
        unsafe { restore_irq(irq) };
        result
    }

    pub fn note_present_fault_activity(
        &mut self,
        fault_addr: VirtAddr,
    ) -> Result<bool, VSpaceError> {
        let page_vaddr = fault_addr & !((PAGE_SIZE as u64) - 1);

        let irq = unsafe { save_irq_disable() };
        self.lock.lock();

        let result = (|| {
            let entry = match self.read_entry(page_vaddr, 1) {
                Some(entry) => entry,
                None => return Ok(false),
            };
            if entry & ENTRY_PRESENT == 0 {
                return Ok(false);
            }

            let phys = entry & ENTRY_ADDR_MASK;
            let _ = super::pmm_update_flags(
                phys,
                super::frame::FRAME_FLAG_REFERENCED | super::frame::FRAME_FLAG_ACTIVE,
                0,
            );
            Ok(true)
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
        fault: &PageFaultInfo,
    ) -> Result<bool, VSpaceError> {
        // Must be a present + write + user page fault
        if !(fault.present && fault.write && fault.user) {
            return Ok(false);
        }

        let page_vaddr = fault_addr & !((PAGE_SIZE as u64) - 1);

        // Drop-revalidate dance: a COW PTE implies a bound MO, so take its
        // per-tree lock OUTSIDE `VSpace.lock` (see `handle_cow_fault`).
        let fault_lock = match unsafe { self.discover_fault_lock(page_vaddr) } {
            Some(fl) => fl,
            None => return Ok(false),
        };
        let tree_state = match fault_lock {
            FaultLock::Bound(state) => state,
            FaultLock::Standalone(_) => {
                unsafe { fault_lock.release_pin() };
                return Ok(false);
            }
        };

        let irq = unsafe { save_irq_disable() };
        unsafe { (*tree_state).lock.lock() };
        self.lock.lock();

        let result = (|| {
            // Pool not configured -- fall through to mmsrv IPC. Checked inside
            // VSpace.lock to synchronize with set_cow_pool_phys(). Require both
            // pool AND notif — without notif the kernel would consume pool
            // entries without telling mmsrv about them.
            if self.cow_pool_phys == 0 || self.cow_notif_phys == 0 {
                return Ok(false);
            }

            let entry = self
                .read_entry(page_vaddr, 1)
                .ok_or(VSpaceError::NotMapped)?;
            if entry & ENTRY_PRESENT == 0 || entry & ENTRY_COW == 0 {
                return Ok(false);
            }

            // Resolve the child MO BEFORE consuming a pool entry. If we
            // cannot identify the backing MO, the atomic commit would
            // have nowhere to land — fall back to mmsrv IPC without
            // touching pool state.
            let (child_mo, mo_page_idx) = {
                if self.tracking.is_null() {
                    return Ok(false);
                }
                let t = unsafe { &*self.tracking };
                match t.mappings.lookup(page_vaddr) {
                    Some((start, vma)) if !vma.mo().is_null() => {
                        let idx = vma.mo_offset as usize
                            + ((page_vaddr - start) / PAGE_SIZE as u64) as usize;
                        (vma.mo(), idx)
                    }
                    _ => return Ok(false),
                }
            };

            // Revalidate the MO still belongs to the tree we locked; if the VMA
            // was remapped while VSpace.lock was dropped for the dance, re-fault.
            if unsafe {
                (*child_mo)
                    .hierarchy_state
                    .load(core::sync::atomic::Ordering::Acquire)
            } != tree_state
            {
                return Ok(false);
            }

            // Read pool state + notification-ring space check. On failure
            // of either precondition we fall back without consuming.
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
                // Resolve the COW-break source under the tree lock — single
                // source of truth for both the gate and the copy source.
                // SAFETY: tree lock held (see `discover_fault_lock` dance above).
                let src_phys = match Self::cow_break_source_locked(child_mo, mo_page_idx) {
                    Some(p) => p,
                    None => return Err(VSpaceError::NotCow),
                };

                // Consume: advance head (kernel is sole consumer, VSpace
                // lock serializes). The pool entry is now owned by this
                // call — success or failure, it will not return to the pool.
                (*(pool as *mut CowPool))
                    .head
                    .store(head.wrapping_add(1), Ordering::Release);

                // Copy content from the source frame into the pool frame.
                // SAFETY: Both frames are valid physical pages accessible via direct map.
                let src = phys_to_virt(src_phys) as *const u8;
                let dst = phys_to_virt(new_phys) as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE);

                // Build new PTE flags: writable + not-COW.
                let mut new_flags = entry & !ENTRY_ADDR_MASK;
                new_flags |= ENTRY_WRITABLE;
                new_flags &= !ENTRY_COW;

                match self.cow_install_atomic(
                    child_mo,
                    mo_page_idx,
                    page_vaddr,
                    new_phys,
                    new_flags,
                    src_phys,
                ) {
                    Ok(()) => {}
                    Err(VSpaceError::RaceLost) => {
                        // Pool entry already owned by kernel as CowPool;
                        // no commit occurred, so release back to PMM with
                        // the CowPool owner tag still in place.
                        super::pmm_free(
                            new_phys,
                            &super::frame::FrameOwner::KernelPrivate {
                                subkind: super::frame::KernelMetaKind::CowPool,
                            },
                        );
                        // Verify another CPU actually resolved the COW.
                        // If the PTE is still COW, this is a structural
                        // bug (e.g. parent VmArea on original MO with no
                        // shadow MO destination); silently returning
                        // Ok(true) would loop forever on retry.
                        let re_entry = self
                            .read_entry(page_vaddr, 1)
                            .ok_or(VSpaceError::RaceLost)?;
                        if re_entry & ENTRY_PRESENT != 0
                            && re_entry & ENTRY_WRITABLE != 0
                            && re_entry & ENTRY_COW == 0
                        {
                            return Ok(true);
                        }
                        crate::kernel::printk::serial_puts(
                            "[COW_FAULT_POOLED] RaceLost with PTE still COW — propagating fault\n",
                        );
                        return Err(VSpaceError::RaceLost);
                    }
                    Err(e) => {
                        super::pmm_free(
                            new_phys,
                            &super::frame::FrameOwner::KernelPrivate {
                                subkind: super::frame::KernelMetaKind::CowPool,
                            },
                        );
                        return Err(e);
                    }
                }

                // Write notification ring entry so mmsrv can replenish.
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
                    (*ring)
                        .head
                        .store(ring_head.wrapping_add(1), Ordering::Release);
                }
            }

            Ok(true)
        })();

        self.lock.unlock();
        unsafe { (*tree_state).lock.unlock() };
        unsafe { restore_irq(irq) };
        unsafe { fault_lock.release_pin() };
        result
    }

    /// Install a demand-page PTE: PRESENT=0, ENTRY_DEMAND=1, flags stored.
    ///
    /// On first user access, #PF → `handle_demand_fault` allocates a zero-fill
    /// frame and makes the page PRESENT, avoiding IPC to mmsrv.
    pub fn map_demand(&mut self, virt: VirtAddr, flags: PageFlags) -> Result<(), VSpaceError> {
        let irq = unsafe { save_irq_disable() };
        self.lock.lock();
        let result = unsafe { self.map_demand_locked(virt, flags) };
        self.lock.unlock();
        unsafe { restore_irq(irq) };
        result
    }

    /// Install a demand-page PTE. Caller must hold `self.lock` and have IRQs
    /// disabled.
    ///
    /// # Safety
    /// Same requirements as `map_locked`.
    pub(crate) unsafe fn map_demand_locked(
        &mut self,
        virt: VirtAddr,
        flags: PageFlags,
    ) -> Result<(), VSpaceError> {
        if virt & (PAGE_SIZE as u64 - 1) != 0 {
            return Err(VSpaceError::Alignment);
        }

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
    /// Lock ordering: VSpace.lock → MM_LOCK (pmm_alloc) — matches existing ordering.
    pub fn handle_demand_fault(
        &mut self,
        fault_addr: VirtAddr,
        _fault: &PageFaultInfo,
    ) -> Result<bool, VSpaceError> {
        let page_vaddr = fault_addr & !((PAGE_SIZE as u64) - 1);

        // Drop-revalidate dance: take the backing MO's per-tree lock (bound)
        // or per-MO `hierarchy_bind_lock` (standalone) OUTSIDE `VSpace.lock`.
        // discover_fault_lock pins the locked object so it survives the gap.
        let fault_lock = match unsafe { self.discover_fault_lock(page_vaddr) } {
            Some(fl) => fl,
            None => return Ok(false),
        };
        let outer_lock_ptr: *const SpinLock = unsafe {
            match fault_lock {
                FaultLock::Bound(state) => &(*state).lock,
                FaultLock::Standalone(mo) => &(*mo).hierarchy_bind_lock,
            }
        };

        // Captures the pager-emit plan computed inside the closure when the
        // fault routes to a kernel-attached pager. Consumed AFTER the outer
        // + VSpace locks release (EQ enqueue + reschedule must not run under
        // the tree lock). Fields: (event, bound_eq, pager, emit_event).
        let mut pager_emit: Option<(
            crate::event::record::EventRecord,
            *mut crate::event::event_queue::EventQueue,
            *mut crate::cap::pager::Pager,
            bool,
        )> = None;
        // Error-path pager reference to release AFTER the locks drop —
        // `release_object` takes `REAPER_LOCK`, never under the tree lock.
        let mut deferred_pager: *mut crate::cap::pager::Pager = core::ptr::null_mut();

        let irq = unsafe { save_irq_disable() };
        unsafe { (*outer_lock_ptr).lock() };
        self.lock.lock();

        let result = (|| {
            let entry = match self.read_entry(page_vaddr, 1) {
                Some(e) => e,
                None => return Ok(false),
            };

            // Already present — another CPU resolved this demand fault. Treat
            // it as handled so the fault path does not deliver a user fault for
            // a now-accessible page.
            if entry & ENTRY_PRESENT != 0 {
                let phys = entry & ENTRY_ADDR_MASK;
                let _ = super::pmm_update_flags(
                    phys,
                    super::frame::FRAME_FLAG_REFERENCED | super::frame::FRAME_FLAG_ACTIVE,
                    0,
                );
                return Ok(true);
            }
            // Not a demand page — let other fault handlers deal with it.
            if entry & ENTRY_DEMAND == 0 {
                return Ok(false);
            }

            // Look up VmArea from the Maple tree to find the backing MO.
            let (mo_ptr, page_idx) = if !self.tracking.is_null() {
                let t = unsafe { &*self.tracking };
                match t.mappings.lookup(page_vaddr) {
                    Some((_start, vma)) if !vma.mo().is_null() => {
                        let idx = vma.mo_offset as usize
                            + ((page_vaddr - _start) / PAGE_SIZE as u64) as usize;
                        (vma.mo(), idx)
                    }
                    _ => return Ok(false),
                }
            } else {
                return Ok(false);
            };

            // Revalidate the MO still matches the lock we took during the
            // dance; if the VMA was remapped while VSpace.lock was dropped,
            // re-fault rather than operate under the wrong lock.
            let cur_state = unsafe {
                (*mo_ptr)
                    .hierarchy_state
                    .load(core::sync::atomic::Ordering::Acquire)
            };
            match fault_lock {
                FaultLock::Bound(state) => {
                    if cur_state != state {
                        return Ok(false);
                    }
                }
                FaultLock::Standalone(_) => {
                    // Bound while we waited on the bind lock — re-fault on the
                    // tree-lock path.
                    if !cur_state.is_null() {
                        return Ok(false);
                    }
                }
            }

            let requested = Self::entry_flags_to_page_flags(entry);
            // Single populate step: classify the page's effective source and
            // act on it. `populate_page_locked` runs under the tree + VSpace
            // lock we hold and never reschedules — the pager wake/reschedule is
            // deferred below, after both locks drop (RFC-0002 acyclicity).
            match unsafe { populate_page_locked(mo_ptr, page_idx, requested.writable) } {
                PopulateLocked::Done {
                    phys,
                    depth,
                    untyped_backed: _,
                } => {
                    // `depth > 0` means the page resolved from an ancestor; map
                    // it read-only CoW. A concurrent break reconverges this
                    // mapping via the rmap (`converge_sibling_mappings_to_owned`).
                    // A freshly zero-committed page is local (`depth == 0`) and
                    // maps with the requested flags.
                    let from_parent = depth > 0;
                    let effective = if unsafe { !(*mo_ptr).cow_parent.is_null() }
                        && requested.writable
                        && from_parent
                    {
                        PageFlags {
                            writable: false,
                            cow: true,
                            ..requested
                        }
                    } else {
                        requested
                    };

                    let new_entry = phys | Self::flags_to_entry_flags(effective);
                    if self.write_entry(page_vaddr, 1, new_entry).is_err() {
                        return Err(VSpaceError::NotMapped);
                    }

                    super::pmm_retain_mapping(phys);
                    let _ = super::pmm_update_flags(
                        phys,
                        super::frame::FRAME_FLAG_REFERENCED | super::frame::FRAME_FLAG_ACTIVE,
                        0,
                    );
                    crate::arch::paging::invlpg(page_vaddr);
                    self.tlb_shootdown(page_vaddr);

                    // Demand-faulted executable page: ensure I-cache coherence.
                    if new_entry & ENTRY_NO_EXECUTE == 0 {
                        crate::arch::paging::flush_dcache_pou_page(phys_to_virt(phys) as u64);
                        crate::arch::paging::flush_icache_all();
                    }

                    Ok(true)
                }
                // Parked on the pager request: emit the event + reschedule after
                // the tree + VSpace locks drop (RFC-0002 acyclicity).
                PopulateLocked::Parked {
                    record,
                    eq_ptr,
                    pager_ptr,
                    emit_event,
                } => {
                    pager_emit = Some((record, eq_ptr, pager_ptr, emit_event));
                    Ok(true)
                }
                // Pager epoch race / detached, or a permanent failure (pager I/O,
                // or a gone external source): release the pager ref after unlock
                // and report unhandled. A `Failed` page reaches the faulting
                // thread as SIGBUS via the caller's user-fault path.
                PopulateLocked::Retry { pager_ptr } | PopulateLocked::Failed { pager_ptr } => {
                    deferred_pager = pager_ptr;
                    Ok(false)
                }
                PopulateLocked::Oom { pager_ptr } => {
                    deferred_pager = pager_ptr;
                    Err(VSpaceError::OutOfMemory)
                }
            }
        })();

        self.lock.unlock();
        unsafe { (*outer_lock_ptr).unlock() };
        unsafe { restore_irq(irq) };

        // Deferred release of the error-path pager ref (REAPER_LOCK), now that
        // the tree / bind lock and VSpace.lock are both dropped.
        if !deferred_pager.is_null() {
            unsafe {
                crate::cap::release_object(
                    deferred_pager as *mut crate::cap::object::KernelObject,
                    crate::cap::ObjectType::Pager,
                );
            }
        }

        if let Some((record, eq_ptr, pager_ptr, emit_event)) = pager_emit {
            unsafe {
                if emit_event {
                    let _ = (*eq_ptr).enqueue(record);
                    crate::cap::release_object(
                        eq_ptr as *mut crate::cap::object::KernelObject,
                        crate::cap::ObjectType::EventQueue,
                    );
                }
                crate::sched::scheduler::scheduler().reschedule();
                crate::cap::release_object(
                    pager_ptr as *mut crate::cap::object::KernelObject,
                    crate::cap::ObjectType::Pager,
                );
            }
        }

        // Drop the discovery pin after every lock is released.
        unsafe { fault_lock.release_pin() };
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
            #[cfg(target_arch = "aarch64")]
            let cr3 = self.host_ttbr0();
            #[cfg(not(target_arch = "aarch64"))]
            let cr3 = self.root;
            crate::arch::paging::write_cr3(cr3);
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
                            // Chunked drain+wake runs with no scheduler
                            // lock held; each waiter's `tcb_lock` is
                            // ordered above `scheduler.lock_state`.
                            crate::sched::scheduler::scheduler()
                                .finish_deactivate_wake(&*old_tracking);
                        }
                        _ => {}
                    }
                }
            }
        }

        true
    }

    fn detach_current_cpu_if_active(&self) {
        if self.tracking.is_null() {
            return;
        }

        let cpu_id = crate::arch::current_cpu() as usize;
        let current_tracking = current_vspace_tracking();
        if current_tracking != self.tracking {
            return;
        }

        // CRITICAL: Make CR3 + tracking update atomic with respect to IPI.
        let irq_flag = unsafe { save_irq_disable() };

        let kernel_tracking = kernel_vspace_tracking();
        let kernel_root = kernel_vspace_root();

        unsafe {
            crate::arch::paging::write_cr3(kernel_root);
        }

        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        set_current_vspace_tracking(kernel_tracking);

        unsafe { restore_irq(irq_flag) };

        unsafe {
            use crate::mm::vspace::DeactivateResult;
            match (*self.tracking).deactivate_nosched(cpu_id) {
                DeactivateResult::BecameInactive => {
                    crate::sched::scheduler::scheduler().finish_deactivate_wake(&*self.tracking);
                }
                _ => {}
            }
        }
    }

    /// Prepare this VSpace for reaping.
    ///
    /// Reaper finalization cannot free page tables while any CPU still
    /// advertises this address space in `active_count`. This helper starts the
    /// teardown protocol (`Dying` + VSpace-teardown IPIs), switches the current
    /// CPU away if it is the last local user, and reports whether deep cleanup
    /// may run in this drain pass.
    pub fn prepare_reap(&mut self) -> bool {
        if self.root == unsafe { KERNEL_PML4_PHYS } || self.tracking.is_null() {
            return true;
        }

        self.detach_current_cpu_if_active();

        unsafe {
            (*self.tracking).mark_dying(crate::arch::current_cpu() as usize);
            (*self.tracking).active_count.load(Ordering::Acquire) == 0
        }
    }

    /// Cleanup when VSpace is destroyed (non-blocking).
    ///
    /// VSpaceTracking is moved to the deferred-free list and released only
    /// after all CPUs have processed pending deactivate state.
    ///
    /// # Preconditions
    /// - `prepare_reap()` returned true for this VSpace in the current reaper
    ///   pass.
    pub fn cleanup(&mut self) {
        // Guard: Never free kernel VSpace
        if self.root == unsafe { KERNEL_PML4_PHYS } {
            return;
        }

        unregister_live_vspace(self as *mut VSpace);

        self.detach_current_cpu_if_active();

        unsafe {
            (*self.tracking).mark_dying(crate::arch::current_cpu() as usize);
            crate::kernel::bug::kassert!(
                (*self.tracking).active_count.load(Ordering::Acquire) == 0,
                "cleanup(): VSpace still active (active_count > 0)"
            );
        }

        // Free ASID and flush its TLB entries before tearing down page tables
        #[cfg(target_arch = "aarch64")]
        unsafe {
            let asid = (*self.tracking).asid.load(Ordering::Relaxed);
            if asid != 0 {
                crate::arch::paging::asid_free(asid);
                (*self.tracking).asid.store(0, Ordering::Relaxed);
            }
        }

        // Drain any un-consumed COW pool entries back to PMM. Each live
        // entry is a kernel-owned frame tagged `KernelPrivate{CowPool}`;
        // on VSpace teardown the kernel is the only holder, so they are
        // freed directly. Done before page-table teardown so the pool
        // page (still mapped in the user VSpace) is still readable via
        // its direct-map kernel VA.
        unsafe {
            if self.cow_pool_phys != 0 {
                let pool = phys_to_virt(self.cow_pool_phys) as *const CowPool;
                let head = (*pool).head.load(Ordering::Acquire);
                let tail = (*pool).tail.load(Ordering::Acquire);
                let mut idx = head;
                while idx != tail {
                    let slot = (idx % 510) as usize;
                    let phys = (*pool).entries[slot].phys_addr;
                    if phys != 0 {
                        super::pmm_free(
                            phys,
                            &super::frame::FrameOwner::KernelPrivate {
                                subkind: super::frame::KernelMetaKind::CowPool,
                            },
                        );
                    }
                    idx = idx.wrapping_add(1);
                }
                self.cow_pool_phys = 0;
            }
        }

        // Free page tables. Drain every leaf PTE's map_count FIRST (via
        // `free_page_tables_recursive` -> `pmm_release_mapping`) before dropping
        // any VmArea's MO backing ref below. `release_obj_ref()` may drop the
        // last ref to a MemoryObject, whose `destroy` frees its MoData pages
        // directly once no rmap entry remains; if a leaf PTE still mapped such a
        // page the PMM would see a non-zero map_count at free time and panic.
        // Tearing the page tables down first guarantees map_count has reached
        // zero before any MO can be destroyed.
        unsafe {
            self.free_page_tables_recursive(self.root);
            if !self.tracking.is_null() {
                let t = &mut *self.tracking;
                let self_ptr = self as *mut VSpace;
                t.mappings.for_each(&mut |start, vma| {
                    let mo = vma.mo();
                    if !mo.is_null() {
                        // Serialise rmap_remove against snapshot / downgrade on
                        // this MO's tree via its per-tree lock (bound) or bind
                        // lock (standalone). Re-check the choice under the lock
                        // against a concurrent first-snapshot bind. The lock is
                        // dropped before release_obj_ref (REAPER_LOCK).
                        loop {
                            let state = (*mo)
                                .hierarchy_state
                                .load(core::sync::atomic::Ordering::Acquire);
                            if state.is_null() {
                                (*mo).hierarchy_bind_lock.lock();
                                if (*mo)
                                    .hierarchy_state
                                    .load(core::sync::atomic::Ordering::Acquire)
                                    .is_null()
                                {
                                    (*mo).rmap_remove(self_ptr, start);
                                    (*mo).hierarchy_bind_lock.unlock();
                                    break;
                                }
                                (*mo).hierarchy_bind_lock.unlock();
                            } else {
                                (*state).lock.lock();
                                if (*mo)
                                    .hierarchy_state
                                    .load(core::sync::atomic::Ordering::Acquire)
                                    == state
                                {
                                    (*mo).rmap_remove(self_ptr, start);
                                    (*state).lock.unlock();
                                    break;
                                }
                                (*state).lock.unlock();
                            }
                        }
                    }
                    vma.release_obj_ref();
                });
                let mut tree_alloc = crate::mm::node_alloc::PmmNodeAllocator {
                    owner: crate::mm::frame::FrameOwner::KernelPrivate {
                        subkind: crate::mm::frame::KernelMetaKind::MapleNode,
                    },
                    use_reserve: false,
                };
                t.mappings.destroy(&mut tree_alloc);
            }
        }

        // Mark as dead
        unsafe {
            (*self.tracking).mark_dead();
        }

        // Stage tracking for deferred free. The retire bookkeeping (generation
        // snapshot) runs here under CAP_LOCK; the actual deferred-free list
        // insert is deferred to flush_pending_retire(), which drain_reaper runs
        // after releasing CAP_LOCK — keeping DEFERRED_FREE_LOCK a strict leaf,
        // never nested under CAP_LOCK.
        unsafe {
            retire_tracking(self.tracking);
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

            // Tear down the PDPT frame. `release_pt_frame` dispatches
            // user-Frame backed PTs (registered in `pt_mappings` by
            // `install_page_table`) to `release_object(.., Frame)` so
            // the reaper handles their phys reclamation; pure
            // kernel-allocated `PageTable` frames go through `pmm_free`
            // as before.
            self.release_pt_frame(pdpt_addr);
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
                    super::pmm_release_mapping(pte & ENTRY_ADDR_MASK);
                }
                // Release the PT frame via the user-Frame-aware helper.
                self.release_pt_frame(pt_addr);
            }

            // Same release → free protocol for the PD frame itself.
            self.release_pt_frame(pd_addr);
        }
    }

    pub fn range_mem_stats(&self, start_vaddr: VirtAddr, page_count: usize) -> RangeMemStats {
        let mut stats = RangeMemStats::zeroed();
        let mut vaddr = start_vaddr & !0xFFF;

        for _ in 0..page_count {
            let Some(pte) = self.read_entry(vaddr, 1) else {
                vaddr = vaddr.saturating_add(PAGE_SIZE as u64);
                continue;
            };
            if pte & ENTRY_PRESENT == 0 {
                vaddr = vaddr.saturating_add(PAGE_SIZE as u64);
                continue;
            }

            stats.present_pages += 1;

            let phys = pte & ENTRY_ADDR_MASK;
            let meta = super::pmm_lookup(phys);
            let share_count = meta
                .as_ref()
                .map(|m| core::cmp::max(1, m.map_count as u64))
                .unwrap_or(1);
            let mut frame_flags = meta.map(|m| m.flags).unwrap_or(0);
            let mut observed_flags = 0u8;

            if pte & ENTRY_ACCESSED != 0 {
                observed_flags |=
                    super::frame::FRAME_FLAG_REFERENCED | super::frame::FRAME_FLAG_ACTIVE;
            }
            if pte & ENTRY_DIRTY != 0 {
                observed_flags |= super::frame::FRAME_FLAG_DIRTY;
            }
            if observed_flags != 0 {
                if let Some(old_flags) = super::pmm_update_flags(phys, observed_flags, 0) {
                    frame_flags = old_flags | observed_flags;
                } else {
                    frame_flags |= observed_flags;
                }
            }

            if frame_flags & (super::frame::FRAME_FLAG_REFERENCED | super::frame::FRAME_FLAG_ACTIVE)
                != 0
            {
                stats.referenced_pages += 1;
            }

            if share_count > 1 {
                stats.shared_pages += 1;
            }
            stats.pss_bytes = stats
                .pss_bytes
                .saturating_add((PAGE_SIZE as u64) / share_count);

            if frame_flags & super::frame::FRAME_FLAG_DIRTY != 0 {
                if share_count > 1 {
                    stats.shared_dirty_pages += 1;
                } else {
                    stats.private_dirty_pages += 1;
                }
            }
            if frame_flags & super::frame::FRAME_FLAG_WRITEBACK != 0 {
                stats.writeback_pages += 1;
            }

            vaddr = vaddr.saturating_add(PAGE_SIZE as u64);
        }

        stats
    }

    /// Walk user-half page tables starting from `start_vaddr`.
    /// Returns up to `max_entries` mapped pages as (vaddr, phys, flags) tuples.
    /// `next_vaddr` is set to the next address to continue scanning (0 if done).
    pub fn walk_pages(
        &self,
        start_vaddr: VirtAddr,
        max_entries: usize,
    ) -> (
        usize,
        VirtAddr,
        [(VirtAddr, PhysAddr, u64); WALK_MAX_RESULTS],
    ) {
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

            let start_pdpt = if pml4_idx == start_pml4 {
                Self::pdpt_index(vaddr)
            } else {
                0
            };

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
                } else {
                    0
                };

                for pd_idx in start_pd..512 {
                    let pde = pd.entry(pd_idx);
                    if pde & ENTRY_PRESENT == 0 {
                        vaddr = ((pml4_idx as u64) << 39)
                            | ((pdpt_idx as u64) << 30)
                            | ((pd_idx + 1) as u64) << 21;
                        continue;
                    }
                    // Skip 2MB huge pages
                    if pde & (1 << 7) != 0 {
                        vaddr = ((pml4_idx as u64) << 39)
                            | ((pdpt_idx as u64) << 30)
                            | ((pd_idx + 1) as u64) << 21;
                        continue;
                    }
                    let pt = unsafe { &*(phys_to_virt(pde & ENTRY_ADDR_MASK) as *const PageTable) };

                    let start_pt =
                        if pml4_idx == start_pml4 && pdpt_idx == start_pdpt && pd_idx == start_pd {
                            Self::pt_index(vaddr)
                        } else {
                            0
                        };

                    for pt_idx in start_pt..512 {
                        let pte = pt.entry(pt_idx);
                        if pte & ENTRY_PRESENT == 0 {
                            continue;
                        }

                        let page_vaddr = ((pml4_idx as u64) << 39)
                            | ((pdpt_idx as u64) << 30)
                            | ((pd_idx as u64) << 21)
                            | ((pt_idx as u64) << 12);
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
    InvalidArgument,
    /// Another CPU is already resolving this COW page (radix entry is
    /// BUSY or already committed). Used by `cow_install_atomic`.
    RaceLost,
    /// `protect` would raise a region's PTEs past the `max_prot` ceiling
    /// captured from the backing cap's rights at map time.
    PermissionDenied,
}

/// One newly-allocated page-table page tracked by `EnsureTablesGuard`.
///
/// `parent_table_phys` + `idx_in_parent` identifies the slot in the
/// upper-level table that points at `child_phys`. Rollback walks each
/// entry in reverse-allocation order, clears the parent slot, and
/// returns the child frame to the PMM.
#[derive(Clone, Copy)]
struct PtAlloc {
    parent_table_phys: PhysAddr,
    idx_in_parent: u16,
    child_phys: PhysAddr,
    /// Level the child sits at: 1 = PT, 2 = PD, 3 = PDPT.
    level: u8,
}

const ENSURE_TABLES_GUARD_CAPACITY: usize = 32;

const _PT_ALLOC_ZERO: PtAlloc = PtAlloc {
    parent_table_phys: 0,
    idx_in_parent: 0,
    child_phys: 0,
    level: 0,
};

/// Records page-table pages newly allocated by `ensure_table_tracked` /
/// `ensure_tables_for_range`. The caller commits with [`forget`] on
/// success or [`rollback`] on a downstream reservation failure.
///
/// Capacity (32 entries) is sized for the largest fork chunk
/// (`MAX_FORK_PAGES = 8192` pages → ≤ 16 PT pages + 1 PD + 1 PDPT +
/// 1 PML4 = 19 worst-case allocations); overflow returns
/// `OutOfMemory` from `ensure_table_inner` rather than silently
/// losing track of an allocation.
///
/// [`forget`]: Self::forget
/// [`rollback`]: Self::rollback
pub(crate) struct EnsureTablesGuard {
    allocs: [PtAlloc; ENSURE_TABLES_GUARD_CAPACITY],
    len: usize,
}

impl EnsureTablesGuard {
    pub(crate) fn new() -> Self {
        Self {
            allocs: [_PT_ALLOC_ZERO; ENSURE_TABLES_GUARD_CAPACITY],
            len: 0,
        }
    }

    fn push(&mut self, alloc: PtAlloc) -> bool {
        if self.len >= self.allocs.len() {
            return false;
        }
        self.allocs[self.len] = alloc;
        self.len += 1;
        true
    }

    /// Caller succeeded — drop the tracker without unlinking. The
    /// page-table pages remain live and reachable through their
    /// parent entries.
    pub(crate) fn forget(self) {
        // Destructor is a no-op; explicitly consume to make the
        // success path visible at call sites.
        drop(self);
    }

    /// Caller failed — unlink each tracked PT page from its parent
    /// table, return the frame to the PMM, and decrement the
    /// VSpace's `vm_pt_pages` counter. Reverse-order so deeper levels
    /// are unlinked before their parents (so the parent table is
    /// still alive when its child entry is cleared).
    ///
    /// Frame teardown delegates to `VSpace::release_pt_frame`, which
    /// handles the `pmm_release_mapping` + `vm_pt_pages--` +
    /// `pmm_free(... PageTable)` triple. Invoking only
    /// `pmm_release_mapping` here would leave the frame's `map_count`
    /// at zero but never return it to the free pool, so a fork that
    /// fails after `ensure_tables_for_range` allocates fresh PTs
    /// would silently leak those frames.
    ///
    /// # Safety
    /// `dst` must be the same VSpace whose `ensure_table_inner`
    /// pushed the tracked entries. Caller holds `dst.lock`.
    pub(crate) unsafe fn rollback(mut self, dst: &mut VSpace) {
        for i in (0..self.len).rev() {
            let alloc = self.allocs[i];
            let parent_table =
                unsafe { &mut *(phys_to_virt(alloc.parent_table_phys) as *mut PageTable) };
            parent_table.set_entry(alloc.idx_in_parent as usize, 0);
            crate::arch::publish_page_table_page(alloc.parent_table_phys);
            // `release_pt_frame` does pmm_release_mapping +
            // vm_pt_pages.fetch_sub(1) + pmm_free internally; calling
            // those directly here would double-decrement.
            unsafe { dst.release_pt_frame(alloc.child_phys) };
        }
        self.len = 0;
    }
}

impl core::fmt::Display for VSpaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VSpaceError::Alignment => write!(f, "Address not aligned to page boundary"),
            VSpaceError::AlreadyMapped => write!(f, "Page is already mapped"),
            VSpaceError::NotMapped => write!(f, "Page is not mapped"),
            VSpaceError::OutOfMemory => write!(f, "Out of memory for page table allocation"),
            VSpaceError::NotCow => write!(f, "Page is not COW"),
            VSpaceError::InvalidArgument => write!(f, "Invalid argument"),
            VSpaceError::RaceLost => write!(f, "Lost race on COW page resolution"),
            VSpaceError::PermissionDenied => {
                write!(f, "Protection exceeds the mapping's max_prot ceiling")
            }
        }
    }
}

/// Save interrupt flag and disable IRQs
#[inline(always)]
pub unsafe fn save_irq_disable() -> u64 {
    crate::arch::save_irq_disable()
}

/// Restore interrupt flag
#[inline(always)]
pub unsafe fn restore_irq(saved: u64) {
    // SAFETY: Caller forwards a saved interrupt state obtained from save_irq_disable().
    unsafe {
        crate::arch::restore_irq(saved);
    }
}
