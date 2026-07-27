// SPDX-License-Identifier: GPL-2.0-only

use super::{MAX_CPUS, Tcb};

#[inline]
pub(super) fn is_canonical_addr(addr: u64) -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        return (addr >> 48) == 0xFFFF;
    }

    #[cfg(target_arch = "x86_64")]
    {
        let sign = (addr >> 47) & 1;
        let upper = addr >> 48;
        return if sign == 0 {
            upper == 0
        } else {
            upper == 0xFFFF
        };
    }
}

#[inline]
pub(super) fn is_kernel_addr(addr: u64) -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        let kernel_base = core::ptr::addr_of!(super::_text_start) as u64;
        is_canonical_addr(addr) && addr >= kernel_base
    }

    #[cfg(target_arch = "x86_64")]
    {
        is_canonical_addr(addr) && addr >= crate::mm::PHYS_MAP_OFFSET
    }
}

#[inline]
pub(super) fn is_aligned_to<T>(addr: u64) -> bool {
    let align = core::mem::align_of::<T>() as u64;
    addr & (align - 1) == 0
}

#[inline]
pub(super) fn checked_cpu_id(site: &'static str) -> usize {
    let cpu_id = crate::arch::current_cpu() as usize;
    if cpu_id >= MAX_CPUS {
        panic!(
            "[SCHED] {}: invalid current_cpu={} (max={})",
            site, cpu_id, MAX_CPUS
        );
    }
    cpu_id
}

#[inline]
pub(super) fn is_bootstrap_tcb(tcb: *mut Tcb) -> bool {
    if tcb.is_null() {
        return false;
    }
    core::ptr::eq(tcb, &raw mut super::super::BOOTSTRAP_TCB)
}

/// Intrusive stack of TCBs awaiting a `sched_ref` decrement.
///
/// Every scheduler-lock critical section that could observe
/// `sched_ref` transitioning past zero (stale ready-queue skips,
/// `pending_enqueue` displacements / cancels, ready-queue exits)
/// pushes the affected TCB onto a stack-local `DeferredReleaseList`,
/// then hands the list back to the top-level caller. The caller
/// drains it via [`crate::sched::scheduler::Scheduler::drain_release`]
/// *after* releasing the per-CPU scheduler lock — this is the only
/// ordering that respects `CAP_LOCK → scheduler.lock_cpu`, because
/// actually firing final cleanup through the reaper still requires
/// `CAP_LOCK` to be taken as an outer lock.
///
/// The list uses the owner CPU's `Tcb.deferred_release_next[cpu]` and
/// `deferred_release_count[cpu]` slots, so enqueue is O(1) and needs no
/// dynamic allocation. CPU-indexed links are required on SMP: a migrating
/// TCB can be staged for release by two CPUs at the same time, and a single
/// global intrusive link would splice one stack-local list into another.
pub(crate) struct DeferredReleaseList {
    pub(super) head: *mut Tcb,
    pub(super) owner_cpu: usize,
}

impl DeferredReleaseList {
    pub(crate) fn new() -> Self {
        Self {
            head: core::ptr::null_mut(),
            owner_cpu: crate::arch::diagnostic_current_cpu().min(MAX_CPUS - 1),
        }
    }

    /// Push `tcb` onto the list for deferred `sched_ref` release. Safe
    /// no-op on null. Must only be called from a scheduler-lock-held
    /// critical section on the owning CPU.
    ///
    /// A single scheduler API call can legitimately need more than one
    /// deferred release on the same TCB — e.g., `process_pending_enqueue`
    /// stages the pending-slot release and a subsequent `schedule_unlocked`
    /// stale dequeue may stage another when state has since flipped
    /// Inactive. The per-CPU intrusive link only supports one physical
    /// membership per owner CPU, so multiplicity is tracked in
    /// `deferred_release_count[owner_cpu]`.
    ///
    /// # Safety
    /// `tcb` must be a valid TCB pointer. Pushing a TCB that is already
    /// on *this* list is legal (count is incremented). By construction
    /// no two scheduler APIs on the same CPU hold concurrent lists (the
    /// per-CPU lock serialises them), so "on a different active list"
    /// cannot occur.
    pub(crate) unsafe fn push(&mut self, tcb: *mut Tcb) {
        if tcb.is_null() {
            return;
        }
        unsafe {
            let owner = self.owner_cpu;
            if (*tcb).deferred_release_count[owner] == 0 {
                // Not yet on any list — link in.
                (*tcb).deferred_release_next[owner] = self.head;
                self.head = tcb;
            }
            crate::kernel::bug::kassert!(
                (*tcb).deferred_release_count[owner] < u32::MAX,
                "DeferredReleaseList::push: release count about to saturate"
            );
            (*tcb).deferred_release_count[owner] =
                (*tcb).deferred_release_count[owner].saturating_add(1);
        }
    }

    /// Returns true when the list is empty.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.head.is_null()
    }
}

/// Capacity of one VSpace-waiter drain batch (see
/// `drain_vspace_waiters_batch_locked`). Larger lists are handled by
/// re-draining in a loop across `waiter_lock` release windows.
pub(super) const DRAIN_BATCH_CAP: usize = 64;

/// Stack-local snapshot of up to `DRAIN_BATCH_CAP` VSpace waiters.
/// Used to carry drained pointers from the `waiter_lock`-held drain
/// phase to the lock-free wake phase without relying on the
/// `vspace_wait_next` intrusive link (which is reused as a Fair tree
/// parent pointer once a TCB is re-enqueued).
pub(super) struct VSpaceWaiterBatch {
    pub(super) tcbs: [*mut Tcb; DRAIN_BATCH_CAP],
    pub(super) count: usize,
}

impl VSpaceWaiterBatch {
    pub(super) const fn new() -> Self {
        Self {
            tcbs: [core::ptr::null_mut(); DRAIN_BATCH_CAP],
            count: 0,
        }
    }
}
