// SPDX-License-Identifier: GPL-2.0-only

use super::support::{DRAIN_BATCH_CAP, VSpaceWaiterBatch};
use super::{BlockedReason, DeferredReleaseList, Scheduler};
use crate::task::state::ThreadState;

impl Scheduler {
    /// Splice all threads from a VSpace's waiter list and enqueue them.
    ///
    /// The list is drained atomically under `tracking.waiter_lock`, and
    /// each node's `blocked_vspace_tracking` / `vspace_wait_next` are
    /// cleared under the same lock so a concurrent
    /// `detach_thread_wait_queues` cannot see a half-dismantled node.
    /// After the lock is released, each waiter is transitioned to
    /// `Ready` and enqueued with `enqueue_unlocked`.
    ///
    /// Must be called with scheduler lock held and IRQs disabled.
    /// Drain up to `DRAIN_BATCH_CAP` waiters from a deactivated VSpace's
    /// waiter list into `batch`, returning whether more waiters remain.
    ///
    /// The intrusive `vspace_wait_next` field aliases the Fair tree's
    /// parent link when a TCB is later re-enqueued (see `Scheduler`
    /// field doc on `fair_heads`). So we cannot carry the waiter list
    /// across the `waiter_lock` / wake boundary using that pointer —
    /// a concurrent `TCB_START` between drain and wake would clobber
    /// it. Instead we copy each node pointer into a caller-owned array
    /// under `waiter_lock`, null its `vspace_wait_next`, null its
    /// `blocked_vspace_tracking` (so `detach_thread_wait_queues` skips
    /// the VSpace branch), and bump its cap refcount (so the pointer
    /// stays live across the wake window).
    ///
    /// Caller MUST hold the scheduler lock.
    fn drain_vspace_waiters_batch_locked(
        &mut self,
        tracking: &crate::mm::VSpaceTracking,
        batch: &mut VSpaceWaiterBatch,
    ) -> bool {
        batch.count = 0;
        unsafe {
            tracking.waiter_lock_acquire();
            let mut node = tracking.waiter_head_get_locked();
            while !node.is_null() && batch.count < DRAIN_BATCH_CAP {
                let next = (*node).vspace_wait_next;
                batch.tcbs[batch.count] = node;
                batch.count += 1;
                (*node).blocked_vspace_tracking = core::ptr::null_mut();
                (*node).vspace_wait_next = core::ptr::null_mut();
                // No cap-refcount pin needed: each waiter already holds
                // a `sched_ref` for its waiter-list slot (added by
                // `block_current_on_vspace`). That pin defers any
                // concurrent last-cap-drop `release_object` from firing
                // `destroy_object`; we release the pin per-waiter in
                // `wake_drained_batch` via `sched_ref_release_may_destroy`
                // after the thread has either been enqueued (transferring
                // ownership to the ready-queue slot) or definitively
                // refused by state (Inactive / already Ready).
                node = next;
            }
            tracking.waiter_head_set_locked(node);
            let more = !node.is_null();
            tracking.waiter_lock_release();
            more
        }
    }

    /// Wake one drained waiter batch.
    ///
    /// Must be called with the scheduler lock NOT held. Each waiter is
    /// transitioned under its own `tcb_lock` so the Blocked→Ready
    /// transition is serialized against `TCB_STOP` / `TCB_START`
    /// (same lock), preventing resurrection of threads SUSPEND already
    /// marked Inactive and double-enqueue against threads RESUME
    /// already moved to Ready/Running. Drops the cap refcount pin taken
    /// in the drain phase after processing each node.
    ///
    /// # Safety
    /// `batch` must be the result of a matching
    /// `drain_vspace_waiters_batch_locked` call; each entry's cap
    /// refcount pin is owned by this function.
    unsafe fn wake_drained_batch(&mut self, batch: &VSpaceWaiterBatch) {
        unsafe {
            for i in 0..batch.count {
                let cur = batch.tcbs[i];
                // Re-check under tcb_lock: only wake waiters still in
                // Blocked state. RESUME (Ready/Running) or SUSPEND
                // (Inactive) already claimed the state transition AND
                // already released this TCB's waiter-slot `sched_ref`
                // via their own `detach_thread_wait_queues` + explicit
                // release path — so here we release only if we still
                // own the waiter slot.
                let owns_waiter_slot = crate::sched::control::execute_wake_plan(
                    crate::sched::control::vspace_wait_wake_plan(cur),
                );

                // Release the waiter-slot `sched_ref` added by
                // `block_current_on_vspace`. If we no longer own the slot
                // (concurrent detach) this is a no-op at the refcount
                // level — the concurrent path already decremented. If we
                // did own it, the decrement either:
                //  - drops to the ready-queue slot's count (enqueue was
                //    called above), or
                //  - drops to zero and, if `pending_destroy` is set,
                //    queues reaper final cleanup — correct, the
                //    scheduler no longer holds any pointer to this TCB.
                if owns_waiter_slot {
                    self.sched_ref_release_may_destroy(cur);
                }
            }
        }
    }

    /// Wake every waiter on a deactivated VSpace's list.
    ///
    /// Runs chunked drain + wake in a loop (re-acquiring `waiter_lock`
    /// for each batch) so unbounded waiter lists are handled without a
    /// fixed cap. Must be called with the scheduler lock NOT held.
    ///
    /// # Safety
    /// `tracking` must outlive the call; typically the caller already
    /// observed `BecameInactive` and owns the tracking for teardown.
    pub(crate) unsafe fn finish_deactivate_wake(&mut self, tracking: &crate::mm::VSpaceTracking) {
        loop {
            let mut batch = VSpaceWaiterBatch::new();
            let more = self.drain_vspace_waiters_batch_locked(tracking, &mut batch);
            if batch.count == 0 {
                break;
            }
            unsafe { self.wake_drained_batch(&batch) };
            if !more {
                break;
            }
        }
    }

    /// Block current thread on VSpace teardown (MAY switch, manages IRQ state internally)
    ///
    /// `waiter_lock` serializes the enqueue with the last-deactivate
    /// wakeup snapshot in `wakeup_vspace_waiters_locked`, and the
    /// `is_active()` recheck inside the locked section guarantees we
    /// never leave a waiter parked on a VSpace that already became
    /// inactive (which would otherwise never be woken).
    pub fn block_current_on_vspace(&mut self, tracking: &crate::mm::VSpaceTracking) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        let mut releases = DeferredReleaseList::new();
        self.lock();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];

            // Fast path before taking waiter_lock.
            if !tracking.is_active() {
                self.unlock();
                self.drain_release(&mut releases);
                crate::mm::restore_irq(irq_flag);
                return;
            }

            tracking.waiter_lock_acquire();

            // Recheck under waiter_lock: a concurrent
            // `wakeup_vspace_waiters_locked` drains the list inside
            // the same lock, so if we observe `is_active` true here
            // our insertion will be visible to any future drain.
            if !tracking.is_active() {
                tracking.waiter_lock_release();
                self.unlock();
                self.drain_release(&mut releases);
                crate::mm::restore_irq(irq_flag);
                return;
            }

            // Mark as blocked
            crate::task::wait::mark_blocked_locked(current);
            (*current).blocked_reason = Some(BlockedReason::VSpaceWait);
            (*current).blocked_vspace_tracking = tracking as *const _ as *mut _;

            // Pin the TCB via `sched_ref` for the waiter-list slot BEFORE
            // publishing the pointer into the list. This closes the
            // refcount race where a concurrent last-cap-drop would
            // otherwise observe `sched_ref == 0` (the thread no longer
            // occupies current[], isn't in a ready queue, and isn't in
            // pending_enqueue) and fire `destroy_object` while the
            // scheduler-owned `waiter_head` still points at this TCB.
            // The release happens in `wake_drained_batch` (drain path)
            // or in the detach-caller (TCB_START / TCB_STOP /
            // thread_exit) — see callers of `detach_thread_wait_queues`.
            (*current).sched_ref_inc();

            // Add to VSpace's intrusive wait queue under waiter_lock.
            (*current).vspace_wait_next = tracking.waiter_head_get_locked();
            tracking.waiter_head_set_locked(current);
            tracking.waiter_lock_release();

            // Make schedule decision and publish current[] while still
            // holding the lock so remote observers (find_running_cpu,
            // CURRENT_ON_CPU broadcast, quiesce scans) never see the
            // old/new transition as a split between lock release and
            // set_current.
            let new_tcb = self.schedule_unlocked(current, &mut releases);
            let old_tcb = current;
            if self.switch_if_changed_locked(old_tcb, new_tcb, irq_flag, &mut releases) {
                return;
            }

            // Release scheduler lock before performing the actual context
            // switch (register save/restore must not run under the lock).
            self.unlock();
            // Drain before the switch so any queued final cleanup fires
            // serially on this stack rather than after resume.
            self.drain_release(&mut releases);

            crate::mm::restore_irq(irq_flag);
        }
    }

    /// Drain every waiter linked through `eq_wait_next` from a
    /// `PendingPagerRequest` and transition each Blocked→Runnable. Caller
    /// holds the request's `Pager.lock` while detaching the chain so a
    /// concurrent fault cannot re-add to the same request after
    /// terminator state.
    ///
    /// # Safety
    /// `head` is the saved waiter list head taken under `Pager.lock`; the
    /// caller has already written `null` into the request's
    /// `waiter_head` so no fresh additions appear.
    pub unsafe fn wake_pager_request_waiters(&mut self, mut head: *mut crate::sched::thread::Tcb) {
        unsafe {
            while !head.is_null() {
                let next = (*head).eq_wait_next;
                (*head).eq_wait_next = core::ptr::null_mut();
                (*head).wait_object = core::ptr::null_mut();
                let _ = crate::sched::control::execute_wake_plan(
                    crate::sched::control::pipe_wait_wake_plan(head),
                );
                self.sched_ref_release_may_destroy(head);
                head = next;
            }
        }
    }

    /// Block current thread for a futex timed wait.
    ///
    /// The caller has already set the thread's state to Blocked and
    /// blocked_reason to FutexTimedBlocked, and inserted it into the
    /// futex hash table. This method inserts the thread into the sleep
    /// queue and performs a context switch.
    ///
    /// # Preconditions
    /// - Thread state and futex fields already configured by caller.
    /// - No IPC core locks should be held across this call.
    pub fn block_current_futex_timed(&mut self, wakeup_ns: u64) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        let mut releases = DeferredReleaseList::new();
        self.lock();

        unsafe {
            let cpu_id = crate::arch::current_cpu() as usize;
            let current = self.current[cpu_id];
            if current.is_null() {
                self.unlock();
                self.drain_release(&mut releases);
                crate::mm::restore_irq(irq_flag);
                return;
            }

            let still_timed_blocked = match (*current).blocked_reason {
                Some(BlockedReason::FutexTimedBlocked) => {
                    (*current).state() == ThreadState::Blocked && !(*current).futex_vspace.is_null()
                }
                _ => false,
            };

            if !still_timed_blocked {
                // A wake may have raced in after the caller dropped its
                // futex / IPC core lock but before we could publish the
                // sleep queue entry. In that case this thread never
                // actually blocked.
                self.restore_current_running_after_pending_cancel_unlocked(
                    cpu_id,
                    current,
                    &mut releases,
                );
                self.unlock();
                self.drain_release(&mut releases);
                crate::mm::restore_irq(irq_flag);
                return;
            }

            // Set timer wakeup and insert into deadline queue
            (*current).timer_wakeup_ns = wakeup_ns;
            crate::sched::deadline_queue::arm_thread_futex_timed(current, wakeup_ns);

            let new_tcb = self.schedule_unlocked(current, &mut releases);
            let old_tcb = current;
            if self.switch_if_changed_locked(old_tcb, new_tcb, irq_flag, &mut releases) {
                return;
            }
        }

        self.unlock();
        unsafe {
            self.drain_release(&mut releases);
            crate::mm::restore_irq(irq_flag);
        }
    }
}
