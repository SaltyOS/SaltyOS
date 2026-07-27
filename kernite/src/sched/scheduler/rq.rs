// SPDX-License-Identifier: GPL-2.0-only

use super::support::{checked_cpu_id, is_bootstrap_tcb};
use super::{
    DeferredReleaseList, MAX_CPUS, SCHED_CLASS_DEADLINE, SCHED_CLASS_FAIR, SCHED_CLASS_IDLE,
    SCHED_CLASS_RT_FIFO, Scheduler, Tcb, global::current_on_cpu,
};
use crate::task::state::ThreadState;
use core::sync::atomic::Ordering;

impl Scheduler {
    /// Select which CPU's ready queue a thread should be enqueued on.
    ///
    /// - Specific affinity: use that CPU if it is online, otherwise fall back
    ///   to the current CPU so we never queue onto an offline target.
    /// - Any-affinity: prefer an idle CPU other than `last_cpu` to spread
    ///   runnable work, otherwise fall back to `last_cpu` for cache affinity.
    ///
    /// Caller MUST hold the local CPU scheduler lock. Remote CPU load is
    /// considered only through lock-free placement hints; the target CPU's
    /// ready queue is touched later under that CPU's lock.
    pub(super) fn select_target_cpu(&self, tcb: *mut Tcb) -> usize {
        unsafe {
            let online = self.online_cpus as usize;
            let current_cpu = crate::arch::current_cpu() as usize;
            if online == 0 {
                return current_cpu;
            }

            let affinity = (*tcb).cpu_affinity;
            if affinity != 0xFFFF_FFFF {
                let target = affinity as usize;
                if target < online {
                    return target;
                }
                return current_cpu.min(online - 1);
            }

            let last = (*tcb).placement.last_cpu as usize;
            if online > 1 {
                let start = if last < online {
                    (last + 1) % online
                } else {
                    current_cpu % online
                };
                for offset in 0..online {
                    let cpu = (start + offset) % online;
                    if cpu == last {
                        continue;
                    }
                    if self.cpu_is_idle_hint(cpu) {
                        return cpu;
                    }
                }
            }

            if last < online {
                return last;
            }

            for offset in 0..online {
                let cpu = (current_cpu + offset) % online;
                if self.cpu_is_idle_hint(cpu) {
                    return cpu;
                }
            }

            current_cpu.min(online - 1)
        }
    }

    #[inline]
    fn cpu_is_idle_hint(&self, cpu: usize) -> bool {
        // This is only a placement hint. Ready queues are protected by each
        // CPU's scheduler lock, so target selection uses the atomic current
        // mirror and pending slot only; the actual enqueue revalidates under
        // the target CPU lock.
        cpu < self.online_cpus as usize
            && current_on_cpu(cpu) == self.idle[cpu] as usize
            && self.pending_enqueue[cpu]
                .load(core::sync::atomic::Ordering::Acquire)
                .is_null()
    }

    /// Insert a thread into a specific CPU's ready queue, sorted by class-local
    /// scheduling key.
    ///
    /// Sets `ready_queued` and `queued_cpu` on the TCB.
    /// Does NOT send IPIs — caller handles that.
    ///
    /// Caller MUST hold the scheduler lock.
    unsafe fn queue_head_mut(&mut self, cpu: usize, class: u8) -> &mut *mut Tcb {
        match class {
            SCHED_CLASS_DEADLINE => &mut self.deadline_heads[cpu],
            SCHED_CLASS_RT_FIFO => &mut self.rt_fifo_heads[cpu],
            SCHED_CLASS_IDLE => panic!("[SCHED] idle thread must not enter a ready queue"),
            _ => &mut self.fair_heads[cpu],
        }
    }

    #[inline]
    fn queue_head(&self, cpu: usize, class: u8) -> *mut Tcb {
        match class {
            SCHED_CLASS_DEADLINE => self.deadline_heads[cpu],
            SCHED_CLASS_RT_FIFO => self.rt_fifo_heads[cpu],
            SCHED_CLASS_IDLE => core::ptr::null_mut(),
            _ => self.fair_heads[cpu],
        }
    }

    #[inline]
    fn class_rank(class: u8) -> u8 {
        match class {
            SCHED_CLASS_DEADLINE => 0,
            SCHED_CLASS_RT_FIFO => 1,
            SCHED_CLASS_FAIR => 2,
            SCHED_CLASS_IDLE => 3,
            _ => 2,
        }
    }

    #[inline]
    unsafe fn sort_key(&self, tcb: *mut Tcb) -> u64 {
        unsafe {
            match (*tcb).effective_sched_class() {
                SCHED_CLASS_DEADLINE | SCHED_CLASS_RT_FIFO => (*tcb).priority,
                SCHED_CLASS_FAIR => (*tcb).fair_virtual_deadline(),
                _ => u64::MAX,
            }
        }
    }

    #[inline]
    unsafe fn fair_entity_precedes(&self, candidate: *mut Tcb, incumbent: *mut Tcb) -> bool {
        unsafe {
            if candidate.is_null() || incumbent.is_null() {
                return false;
            }
            let candidate_deadline = (*candidate).fair_virtual_deadline();
            let incumbent_deadline = (*incumbent).fair_virtual_deadline();
            if candidate_deadline != incumbent_deadline {
                return candidate_deadline < incumbent_deadline;
            }
            let candidate_vruntime = (*candidate).fair_vruntime();
            let incumbent_vruntime = (*incumbent).fair_vruntime();
            if candidate_vruntime != incumbent_vruntime {
                return candidate_vruntime < incumbent_vruntime;
            }
            (candidate as usize) < (incumbent as usize)
        }
    }

    #[inline]
    unsafe fn ready_queue_precedes(&self, candidate: *mut Tcb, incumbent: *mut Tcb) -> bool {
        unsafe {
            if candidate.is_null() || incumbent.is_null() {
                return false;
            }
            let candidate_class = (*candidate).effective_sched_class();
            let incumbent_class = (*incumbent).effective_sched_class();
            let candidate_rank = Self::class_rank(candidate_class);
            let incumbent_rank = Self::class_rank(incumbent_class);
            if candidate_rank != incumbent_rank {
                return candidate_rank < incumbent_rank;
            }
            if candidate_class == SCHED_CLASS_FAIR {
                return self.fair_entity_precedes(candidate, incumbent);
            }
            let candidate_key = self.sort_key(candidate);
            let incumbent_key = self.sort_key(incumbent);
            if candidate_key != incumbent_key {
                return candidate_key < incumbent_key;
            }
            (candidate as usize) < (incumbent as usize)
        }
    }

    #[inline]
    unsafe fn fair_tree_left(tcb: *mut Tcb) -> *mut Tcb {
        unsafe {
            if tcb.is_null() {
                core::ptr::null_mut()
            } else {
                (*tcb).fair_left
            }
        }
    }

    #[inline]
    unsafe fn fair_tree_right(tcb: *mut Tcb) -> *mut Tcb {
        unsafe {
            if tcb.is_null() {
                core::ptr::null_mut()
            } else {
                (*tcb).fair_right
            }
        }
    }

    #[inline]
    unsafe fn fair_tree_parent(tcb: *mut Tcb) -> *mut Tcb {
        unsafe {
            if tcb.is_null() {
                core::ptr::null_mut()
            } else {
                (*tcb).fair_parent
            }
        }
    }

    #[inline]
    unsafe fn fair_tree_subtree_min_vruntime(tcb: *mut Tcb) -> u64 {
        unsafe {
            if tcb.is_null() {
                u64::MAX
            } else {
                (*tcb).fair_subtree_min
            }
        }
    }

    #[inline]
    unsafe fn fair_tree_subtree_has_stealable(tcb: *mut Tcb) -> bool {
        unsafe { !tcb.is_null() && (*tcb).fair_subtree_stealable }
    }

    #[inline]
    unsafe fn fair_tree_set_subtree_has_stealable(tcb: *mut Tcb, has_stealable: bool) {
        unsafe {
            (*tcb).fair_subtree_stealable = has_stealable;
        }
    }

    #[inline]
    unsafe fn fair_tree_set_left(parent: *mut Tcb, child: *mut Tcb) {
        unsafe {
            (*parent).fair_left = child;
            if !child.is_null() {
                (*child).fair_parent = parent;
            }
        }
    }

    #[inline]
    unsafe fn fair_tree_set_right(parent: *mut Tcb, child: *mut Tcb) {
        unsafe {
            (*parent).fair_right = child;
            if !child.is_null() {
                (*child).fair_parent = parent;
            }
        }
    }

    #[inline]
    unsafe fn fair_tree_reset_node(tcb: *mut Tcb) {
        unsafe {
            (*tcb).fair_left = core::ptr::null_mut();
            (*tcb).fair_right = core::ptr::null_mut();
            (*tcb).fair_parent = core::ptr::null_mut();
            (*tcb).fair_subtree_min = (*tcb).fair_vruntime();
            Self::fair_tree_set_subtree_has_stealable(tcb, (*tcb).cpu_affinity == 0xFFFF_FFFF);
        }
    }

    #[inline]
    unsafe fn fair_tree_recalc_node(tcb: *mut Tcb) {
        unsafe {
            let mut subtree_min = (*tcb).fair_vruntime();
            let mut subtree_has_stealable = (*tcb).cpu_affinity == 0xFFFF_FFFF;
            let left = Self::fair_tree_left(tcb);
            if !left.is_null() {
                subtree_min = subtree_min.min(Self::fair_tree_subtree_min_vruntime(left));
                subtree_has_stealable |= Self::fair_tree_subtree_has_stealable(left);
            }
            let right = Self::fair_tree_right(tcb);
            if !right.is_null() {
                subtree_min = subtree_min.min(Self::fair_tree_subtree_min_vruntime(right));
                subtree_has_stealable |= Self::fair_tree_subtree_has_stealable(right);
            }
            (*tcb).fair_subtree_min = subtree_min;
            Self::fair_tree_set_subtree_has_stealable(tcb, subtree_has_stealable);
        }
    }

    #[inline]
    unsafe fn fair_tree_recalc_upwards(&self, mut tcb: *mut Tcb) {
        unsafe {
            while !tcb.is_null() {
                Self::fair_tree_recalc_node(tcb);
                tcb = Self::fair_tree_parent(tcb);
            }
        }
    }

    #[inline]
    fn fair_tree_heap_key(tcb: *mut Tcb) -> u64 {
        let mut x = tcb as usize as u64;
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        x ^ (x >> 33)
    }

    #[inline]
    fn fair_tree_heap_precedes(a: *mut Tcb, b: *mut Tcb) -> bool {
        let a_key = Self::fair_tree_heap_key(a);
        let b_key = Self::fair_tree_heap_key(b);
        if a_key != b_key {
            a_key < b_key
        } else {
            (a as usize) < (b as usize)
        }
    }

    unsafe fn fair_tree_rotate_left(&mut self, cpu: usize, pivot: *mut Tcb) {
        unsafe {
            let new_root = Self::fair_tree_right(pivot);
            let moved = Self::fair_tree_left(new_root);
            let parent = Self::fair_tree_parent(pivot);

            Self::fair_tree_set_right(pivot, moved);

            (*new_root).fair_parent = parent;
            if parent.is_null() {
                self.fair_heads[cpu] = new_root;
            } else if Self::fair_tree_left(parent) == pivot {
                (*parent).fair_left = new_root;
            } else {
                (*parent).fair_right = new_root;
            }

            Self::fair_tree_set_left(new_root, pivot);

            Self::fair_tree_recalc_node(pivot);
            Self::fair_tree_recalc_node(new_root);
        }
    }

    unsafe fn fair_tree_rotate_right(&mut self, cpu: usize, pivot: *mut Tcb) {
        unsafe {
            let new_root = Self::fair_tree_left(pivot);
            let moved = Self::fair_tree_right(new_root);
            let parent = Self::fair_tree_parent(pivot);

            Self::fair_tree_set_left(pivot, moved);

            (*new_root).fair_parent = parent;
            if parent.is_null() {
                self.fair_heads[cpu] = new_root;
            } else if Self::fair_tree_left(parent) == pivot {
                (*parent).fair_left = new_root;
            } else {
                (*parent).fair_right = new_root;
            }

            Self::fair_tree_set_right(new_root, pivot);

            Self::fair_tree_recalc_node(pivot);
            Self::fair_tree_recalc_node(new_root);
        }
    }

    #[inline]
    unsafe fn fair_account_enqueue_unlocked(&mut self, cpu: usize, tcb: *mut Tcb) {
        unsafe {
            let weight = (*tcb).fair_weight() as u64;
            self.fair_weight_sum[cpu] = self.fair_weight_sum[cpu].saturating_add(weight);
            self.fair_weighted_vruntime_sum[cpu] = self.fair_weighted_vruntime_sum[cpu]
                .saturating_add(((*tcb).fair_vruntime() as u128).saturating_mul(weight as u128));
        }
    }

    #[inline]
    unsafe fn fair_account_dequeue_unlocked(&mut self, cpu: usize, tcb: *mut Tcb) {
        unsafe {
            let weight = (*tcb).fair_weight() as u64;
            self.fair_weight_sum[cpu] = self.fair_weight_sum[cpu].saturating_sub(weight);
            self.fair_weighted_vruntime_sum[cpu] = self.fair_weighted_vruntime_sum[cpu]
                .saturating_sub(((*tcb).fair_vruntime() as u128).saturating_mul(weight as u128));
        }
    }

    #[inline]
    pub(super) unsafe fn fair_refresh_min_vruntime_unlocked(&mut self, cpu: usize) {
        unsafe {
            let mut candidate = u64::MAX;
            let queued_root = self.fair_heads[cpu];
            if !queued_root.is_null() {
                candidate = candidate.min(Self::fair_tree_subtree_min_vruntime(queued_root));
            }

            let current = self.current[cpu];
            if !current.is_null()
                && (*current).state() == ThreadState::Runnable
                && (*current).effective_sched_class() == SCHED_CLASS_FAIR
            {
                candidate = candidate.min((*current).fair_vruntime());
            }

            if candidate != u64::MAX && candidate > self.fair_min_vruntime[cpu] {
                self.fair_min_vruntime[cpu] = candidate;
            }
        }
    }

    unsafe fn fair_insert_unlocked(&mut self, cpu: usize, tcb: *mut Tcb) {
        unsafe {
            crate::kernel::bug::kassert!(
                (*tcb).sleep_next.is_null()
                    && (*tcb).futex_next.is_null()
                    && (*tcb).vspace_wait_next.is_null(),
                "fair_insert_unlocked: blocking-queue residue present on TCB entering Fair tree"
            );
            crate::kernel::bug::kassert!(
                (*tcb).blocked_reason.is_none(),
                "fair_insert_unlocked: TCB still marked Blocked on entry"
            );
            crate::kernel::bug::kassert!(
                (*tcb).blocked_vspace_tracking.is_null(),
                "fair_insert_unlocked: blocked_vspace_tracking not cleared before Fair insert"
            );

            Self::fair_tree_reset_node(tcb);

            let root = self.fair_heads[cpu];
            if root.is_null() {
                self.fair_heads[cpu] = tcb;
                self.fair_account_enqueue_unlocked(cpu, tcb);
                self.fair_refresh_min_vruntime_unlocked(cpu);
                return;
            }

            let mut parent = core::ptr::null_mut();
            let mut current = root;
            while !current.is_null() {
                parent = current;
                current = if self.fair_entity_precedes(tcb, current) {
                    Self::fair_tree_left(current)
                } else {
                    Self::fair_tree_right(current)
                };
            }

            (*tcb).fair_parent = parent;
            if self.fair_entity_precedes(tcb, parent) {
                Self::fair_tree_set_left(parent, tcb);
            } else {
                Self::fair_tree_set_right(parent, tcb);
            }

            self.fair_tree_recalc_upwards(parent);

            while !Self::fair_tree_parent(tcb).is_null()
                && Self::fair_tree_heap_precedes(tcb, Self::fair_tree_parent(tcb))
            {
                let parent = Self::fair_tree_parent(tcb);
                if Self::fair_tree_left(parent) == tcb {
                    self.fair_tree_rotate_right(cpu, parent);
                } else {
                    self.fair_tree_rotate_left(cpu, parent);
                }
            }

            self.fair_tree_recalc_upwards(tcb);
            self.fair_account_enqueue_unlocked(cpu, tcb);
            self.fair_refresh_min_vruntime_unlocked(cpu);
        }
    }

    unsafe fn fair_remove_unlocked(&mut self, cpu: usize, tcb: *mut Tcb) {
        unsafe {
            while !Self::fair_tree_left(tcb).is_null() || !Self::fair_tree_right(tcb).is_null() {
                let left = Self::fair_tree_left(tcb);
                let right = Self::fair_tree_right(tcb);
                if left.is_null() {
                    self.fair_tree_rotate_left(cpu, tcb);
                } else if right.is_null() {
                    self.fair_tree_rotate_right(cpu, tcb);
                } else if Self::fair_tree_heap_precedes(left, right) {
                    self.fair_tree_rotate_right(cpu, tcb);
                } else {
                    self.fair_tree_rotate_left(cpu, tcb);
                }
            }

            let parent = Self::fair_tree_parent(tcb);
            if parent.is_null() {
                self.fair_heads[cpu] = core::ptr::null_mut();
            } else if Self::fair_tree_left(parent) == tcb {
                (*parent).fair_left = core::ptr::null_mut();
            } else {
                (*parent).fair_right = core::ptr::null_mut();
            }

            self.fair_account_dequeue_unlocked(cpu, tcb);
            self.fair_tree_recalc_upwards(parent);
            Self::fair_tree_reset_node(tcb);
            self.fair_refresh_min_vruntime_unlocked(cpu);

            crate::kernel::bug::kassert!(
                (*tcb).fair_left.is_null()
                    && (*tcb).fair_right.is_null()
                    && (*tcb).fair_parent.is_null(),
                "fair_remove_unlocked: reset_node failed to clear tree links"
            );
        }
    }

    #[inline]
    unsafe fn fair_leftmost_unlocked(&self, cpu: usize) -> *mut Tcb {
        unsafe {
            let mut current = self.fair_heads[cpu];
            while !current.is_null() && !Self::fair_tree_left(current).is_null() {
                current = Self::fair_tree_left(current);
            }
            current
        }
    }

    unsafe fn fair_first_eligible_from_unlocked(
        &self,
        tcb: *mut Tcb,
        avg_vruntime: u64,
    ) -> *mut Tcb {
        unsafe {
            if tcb.is_null() || Self::fair_tree_subtree_min_vruntime(tcb) > avg_vruntime {
                return core::ptr::null_mut();
            }

            let left = Self::fair_tree_left(tcb);
            let left_match = self.fair_first_eligible_from_unlocked(left, avg_vruntime);
            if !left_match.is_null() {
                return left_match;
            }

            if (*tcb).fair_vruntime() <= avg_vruntime {
                return tcb;
            }

            self.fair_first_eligible_from_unlocked(Self::fair_tree_right(tcb), avg_vruntime)
        }
    }

    unsafe fn fair_find_stealable_from_unlocked(&self, tcb: *mut Tcb) -> *mut Tcb {
        unsafe {
            if tcb.is_null() || !Self::fair_tree_subtree_has_stealable(tcb) {
                return core::ptr::null_mut();
            }

            let left_child = Self::fair_tree_left(tcb);
            let left = self.fair_find_stealable_from_unlocked(left_child);
            if !left.is_null() {
                return left;
            }

            if (*tcb).state() == ThreadState::Runnable && (*tcb).cpu_affinity == 0xFFFF_FFFF {
                return tcb;
            }

            self.fair_find_stealable_from_unlocked(Self::fair_tree_right(tcb))
        }
    }

    #[inline]
    unsafe fn fair_avg_vruntime_unlocked(&self, cpu: usize, running_fair: *mut Tcb) -> Option<u64> {
        unsafe {
            let mut total_vruntime = self.fair_weighted_vruntime_sum[cpu];
            let mut total_weight = self.fair_weight_sum[cpu] as u128;

            if !running_fair.is_null()
                && (*running_fair).state() == ThreadState::Runnable
                && (*running_fair).effective_sched_class() == SCHED_CLASS_FAIR
            {
                let weight = (*running_fair).fair_weight() as u128;
                total_vruntime = total_vruntime.saturating_add(
                    ((*running_fair).fair_vruntime() as u128).saturating_mul(weight),
                );
                total_weight = total_weight.saturating_add(weight);
            }

            if total_weight == 0 {
                None
            } else {
                Some((total_vruntime / total_weight) as u64)
            }
        }
    }

    #[inline]
    unsafe fn fair_avg_or_min_unlocked(&self, cpu: usize, running_fair: *mut Tcb) -> u64 {
        unsafe {
            self.fair_avg_vruntime_unlocked(cpu, running_fair)
                .unwrap_or(self.fair_min_vruntime[cpu])
        }
    }

    #[inline]
    unsafe fn fair_avg_for_entity_unlocked(
        &self,
        cpu: usize,
        running_fair: *mut Tcb,
        tcb: *mut Tcb,
    ) -> u64 {
        unsafe {
            let mut total_vruntime = self.fair_weighted_vruntime_sum[cpu];
            let mut total_weight = self.fair_weight_sum[cpu] as u128;
            let mut entity_accounted = false;

            if !running_fair.is_null()
                && (*running_fair).effective_sched_class() == SCHED_CLASS_FAIR
                && self.current[cpu] == running_fair
                && (*running_fair).state() == ThreadState::Runnable
            {
                let weight = (*running_fair).fair_weight() as u128;
                total_vruntime = total_vruntime.saturating_add(
                    ((*running_fair).fair_vruntime() as u128).saturating_mul(weight),
                );
                total_weight = total_weight.saturating_add(weight);
                entity_accounted = running_fair == tcb;
            }

            if !tcb.is_null()
                && !entity_accounted
                && (*tcb).effective_sched_class() == SCHED_CLASS_FAIR
                && self.current[cpu] == tcb
                && !(*tcb).placement.ready_queued
            {
                let weight = (*tcb).fair_weight() as u128;
                total_vruntime = total_vruntime
                    .saturating_add(((*tcb).fair_vruntime() as u128).saturating_mul(weight));
                total_weight = total_weight.saturating_add(weight);
            }

            if total_weight == 0 {
                if tcb.is_null() {
                    self.fair_min_vruntime[cpu]
                } else {
                    (*tcb).fair_vruntime()
                }
            } else {
                (total_vruntime / total_weight) as u64
            }
        }
    }

    #[inline]
    pub(super) unsafe fn fair_snapshot_lag_unlocked(
        &self,
        cpu: usize,
        tcb: *mut Tcb,
        running_fair: *mut Tcb,
    ) {
        unsafe {
            let avg_vruntime = self.fair_avg_for_entity_unlocked(cpu, running_fair, tcb);
            (*tcb).snapshot_fair_lag(avg_vruntime);
        }
    }

    #[inline]
    unsafe fn restore_fair_lag_for_entity_unlocked(
        &self,
        cpu: usize,
        running_fair: *mut Tcb,
        tcb: *mut Tcb,
    ) -> bool {
        unsafe {
            let avg_vruntime = self.fair_avg_for_entity_unlocked(cpu, running_fair, tcb);
            (*tcb).restore_fair_lag_or_seed(avg_vruntime)
        }
    }

    #[inline]
    unsafe fn fair_is_eligible(&self, avg_vruntime: u64, tcb: *mut Tcb) -> bool {
        unsafe { (*tcb).fair_vruntime() <= avg_vruntime }
    }

    #[inline]
    unsafe fn fair_is_eligible_for_cpu_unlocked(
        &self,
        cpu: usize,
        running_fair: *mut Tcb,
        tcb: *mut Tcb,
    ) -> bool {
        unsafe { self.fair_is_eligible(self.fair_avg_or_min_unlocked(cpu, running_fair), tcb) }
    }

    #[inline]
    unsafe fn fair_should_preempt_for_cpu_unlocked(
        &self,
        cpu: usize,
        current: *mut Tcb,
        candidate: *mut Tcb,
    ) -> bool {
        unsafe {
            let avg_vruntime = self.fair_avg_or_min_unlocked(cpu, current);
            if !self.fair_is_eligible_for_cpu_unlocked(cpu, current, candidate) {
                return false;
            }
            if !self.fair_is_eligible(avg_vruntime, current) {
                return true;
            }
            self.fair_entity_precedes(candidate, current)
        }
    }

    #[inline]
    unsafe fn reweight_running_fair_thread_unlocked(
        &mut self,
        owner_cpu: usize,
        tcb: *mut Tcb,
        new_weight: u16,
    ) {
        unsafe {
            let now_ns = crate::arch::now_ns();
            self.account_current_runtime_unlocked(owner_cpu, now_ns);
            let avg_vruntime = self.fair_avg_for_entity_unlocked(owner_cpu, tcb, tcb);
            (*tcb).snapshot_fair_lag(avg_vruntime);
            (*tcb).reweight_fair_entity_from_snapshot(avg_vruntime, new_weight);
        }
    }

    #[inline]
    unsafe fn reweight_detached_fair_thread_unlocked(&mut self, tcb: *mut Tcb, new_weight: u16) {
        unsafe {
            (*tcb).reweight_fair_entity_detached(new_weight);
        }
    }

    #[inline]
    unsafe fn reweight_queued_fair_thread_unlocked(
        &mut self,
        cpu: usize,
        tcb: *mut Tcb,
        new_weight: u16,
    ) {
        unsafe {
            let removed = self.remove_from_ready_queue_unlocked(tcb);
            if removed {
                (*tcb).set_fair_weight(new_weight);
                self.prepare_enqueue_unlocked(cpu, tcb);
                self.insert_sorted(cpu, tcb);

                let target_current = self.current[cpu];
                let current_cpu = crate::arch::current_cpu() as usize;
                let should_ipi = if target_current == self.idle[cpu] {
                    true
                } else if !target_current.is_null() {
                    self.should_preempt_tcb(cpu, tcb, target_current)
                } else {
                    false
                };
                if cpu != current_cpu && cpu < self.online_cpus as usize && should_ipi {
                    crate::arch::send_ipi(cpu, crate::arch::IpiKind::Reschedule);
                }
            } else {
                self.reweight_detached_fair_thread_unlocked(tcb, new_weight);
            }
        }
    }

    unsafe fn find_best_fair_unlocked(&self, cpu: usize, running_fair: *mut Tcb) -> *mut Tcb {
        unsafe {
            let avg_vruntime = self.fair_avg_or_min_unlocked(cpu, running_fair);
            let best_eligible =
                self.fair_first_eligible_from_unlocked(self.fair_heads[cpu], avg_vruntime);
            if !best_eligible.is_null() {
                best_eligible
            } else {
                self.fair_leftmost_unlocked(cpu)
            }
        }
    }

    #[inline]
    pub(crate) unsafe fn should_preempt_tcb(
        &self,
        cpu: usize,
        candidate: *mut Tcb,
        current: *mut Tcb,
    ) -> bool {
        unsafe {
            if candidate.is_null() || current.is_null() {
                return false;
            }
            let candidate_class = (*candidate).effective_sched_class();
            let current_class = (*current).effective_sched_class();
            let candidate_rank = Self::class_rank(candidate_class);
            let current_rank = Self::class_rank(current_class);
            if candidate_rank != current_rank {
                return candidate_rank < current_rank;
            }
            if candidate_class == SCHED_CLASS_FAIR {
                return self.fair_should_preempt_for_cpu_unlocked(cpu, current, candidate);
            }
            self.sort_key(candidate) < self.sort_key(current)
        }
    }

    #[inline]
    unsafe fn should_ipi_after_enqueue_locked(&self, cpu: usize, tcb: *mut Tcb) -> bool {
        unsafe {
            if cpu >= self.online_cpus as usize || self.idle[cpu].is_null() {
                return false;
            }

            let target_current = self.current[cpu];
            if target_current == self.idle[cpu] {
                true
            } else if !target_current.is_null() {
                if (*target_current).state() != ThreadState::Runnable {
                    true
                } else {
                    self.should_preempt_tcb(cpu, tcb, target_current)
                }
            } else {
                false
            }
        }
    }

    /// Return whether `tcb` is still safe to mutate for ready-queue insertion
    /// under CPU `cpu`'s scheduler lock.
    #[inline]
    unsafe fn ready_insert_claimable_unlocked(&self, cpu: usize, tcb: *mut Tcb) -> bool {
        unsafe {
            self.live_owner_cpu(tcb, "ready_insert_claimable_unlocked", cpu)
                .is_none()
                && self.find_running_cpu(tcb).is_none()
                && !(*tcb).placement.ready_queued
                && !self.is_pending_on_any_cpu(tcb)
        }
    }

    /// Insert `tcb` into CPU `cpu`'s ready queue, sorted by the class-local
    /// scheduling key. Caller MUST hold `lock_cpu(cpu)`.
    ///
    /// Re-validates scheduler ownership under that same lock so the "not
    /// already owned" decision and the tree mutation are atomic with respect
    /// to any other CPU inserting into this CPU's tree. Returns `false` when
    /// another scheduler slot claimed the TCB first; the caller then drops its
    /// speculative ready-queue reference.
    unsafe fn insert_sorted(&mut self, cpu: usize, tcb: *mut Tcb) -> bool {
        unsafe {
            if !self.ready_insert_claimable_unlocked(cpu, tcb) {
                return false;
            }

            let class = (*tcb).effective_sched_class();
            (*tcb).placement.ready_queued = true;
            (*tcb).placement.queued_cpu = cpu as u32;
            (*tcb).queued_class = class;
            (*tcb).next = core::ptr::null_mut();

            if class == SCHED_CLASS_FAIR {
                self.fair_insert_unlocked(cpu, tcb);
                return true;
            }

            let head_ptr = self.queue_head(cpu, class);
            if head_ptr.is_null() {
                *self.queue_head_mut(cpu, class) = tcb;
                return true;
            }

            if self.ready_queue_precedes(tcb, head_ptr) {
                (*tcb).next = head_ptr;
                *self.queue_head_mut(cpu, class) = tcb;
            } else {
                let mut current = head_ptr;
                while !(*current).next.is_null() && !self.ready_queue_precedes(tcb, (*current).next)
                {
                    current = (*current).next;
                }
                (*tcb).next = (*current).next;
                (*current).next = tcb;
            }
            true
        }
    }

    #[inline]
    unsafe fn clear_ready_placement_unlocked(tcb: *mut Tcb) {
        unsafe {
            (*tcb).next = core::ptr::null_mut();
            (*tcb).placement.ready_queued = false;
            (*tcb).placement.queued_cpu = 0xFFFF_FFFF;
            (*tcb).queued_class = SCHED_CLASS_IDLE;
        }
    }

    unsafe fn pop_head_for_class_unlocked(
        &mut self,
        cpu: usize,
        class: u8,
        claim_cpu: usize,
        releases: &mut DeferredReleaseList,
    ) -> Option<*mut Tcb> {
        unsafe {
            loop {
                let head = *self.queue_head_mut(cpu, class);
                if head.is_null() {
                    return None;
                }

                let claimed = (*head).try_claim_run_owner_cpu(claim_cpu);
                let queue_head = self.queue_head_mut(cpu, class);
                *queue_head = (*head).next;
                Self::clear_ready_placement_unlocked(head);

                if claimed {
                    return Some(head);
                }

                // The entry was already scheduler-owned while still linked
                // in this ready queue. Drop only this stale ready-slot ref;
                // the live owner keeps its current/switch-save ownership.
                releases.push(head);
            }
        }
    }

    unsafe fn peek_best_fair_unlocked(&self, cpu: usize, running_fair: *mut Tcb) -> *mut Tcb {
        unsafe { self.find_best_fair_unlocked(cpu, running_fair) }
    }

    unsafe fn pop_best_fair_unlocked(
        &mut self,
        cpu: usize,
        claim_cpu: usize,
        releases: &mut DeferredReleaseList,
    ) -> Option<*mut Tcb> {
        unsafe {
            loop {
                let target = self.find_best_fair_unlocked(cpu, core::ptr::null_mut());
                if target.is_null() {
                    return None;
                }

                let claimed = (*target).try_claim_run_owner_cpu(claim_cpu);
                self.fair_remove_unlocked(cpu, target);
                (*target).clear_fair_saved_lag();
                Self::clear_ready_placement_unlocked(target);

                if claimed {
                    if crate::sched::scheduler::debug_reply_wake_once(target, 1) {
                        crate::kernel::printk::ktrace!(sched, |_g| {
                            _g.puts("[FORK_WAKE_DEQ] cpu=");
                            _g.dec(cpu as u64);
                            _g.puts(" tcb=");
                            _g.hex(target as u64);
                            _g.puts(" vr=");
                            _g.hex((*target).fair_vruntime());
                            _g.puts(" key=");
                            _g.hex((*target).priority);
                            _g.puts("\n");
                        });
                    }
                    return Some(target);
                }

                // See the non-fair path above: an owned fair entity linked in
                // the tree is a stale ready-slot, not a runnable candidate.
                releases.push(target);
            }
        }
    }

    #[inline]
    pub(super) unsafe fn peek_best_ready_unlocked(
        &self,
        cpu: usize,
        running: *mut Tcb,
    ) -> *mut Tcb {
        unsafe {
            if !self.deadline_heads[cpu].is_null() {
                self.deadline_heads[cpu]
            } else if !self.rt_fifo_heads[cpu].is_null() {
                self.rt_fifo_heads[cpu]
            } else {
                self.peek_best_fair_unlocked(cpu, running)
            }
        }
    }

    unsafe fn prepare_enqueue_unlocked(&mut self, cpu: usize, tcb: *mut Tcb) {
        unsafe {
            match (*tcb).sched_class {
                SCHED_CLASS_FAIR => {
                    self.prepare_fair_entity_for_cpu_unlocked(cpu, tcb);
                }
                SCHED_CLASS_IDLE => self.prepare_nonfair_entity_for_enqueue_unlocked(tcb),
                SCHED_CLASS_RT_FIFO | SCHED_CLASS_DEADLINE => {
                    self.prepare_nonfair_entity_for_enqueue_unlocked(tcb);
                }
                _ => {
                    (*tcb).sched_class = SCHED_CLASS_FAIR;
                    self.prepare_fair_entity_for_cpu_unlocked(cpu, tcb);
                }
            }
        }
    }

    #[inline]
    unsafe fn prepare_nonfair_entity_for_enqueue_unlocked(&mut self, tcb: *mut Tcb) {
        unsafe {
            if (*tcb).sched_class == SCHED_CLASS_DEADLINE {
                self.prepare_deadline_entity_for_enqueue_unlocked(tcb);
            } else {
                (*tcb).recompute_sched_key();
            }
        }
    }

    #[inline]
    unsafe fn prepare_deadline_entity_for_enqueue_unlocked(&mut self, tcb: *mut Tcb) {
        unsafe {
            if (*tcb).deadline_entity_needs_replenish() {
                self.replenish_budget_unlocked(tcb);
            }
            (*tcb).recompute_sched_key();
        }
    }

    #[inline]
    unsafe fn prepare_fair_entity_for_cpu_unlocked(&mut self, cpu: usize, tcb: *mut Tcb) {
        unsafe {
            let src_min_vruntime =
                if (*tcb).fair_entity_needs_vruntime_translation(cpu, self.online_cpus as usize) {
                    let last_cpu = (*tcb).placement.last_cpu as usize;
                    Some(self.fair_min_vruntime[last_cpu])
                } else {
                    None
                };
            let avg_vruntime = self.fair_avg_or_min_unlocked(cpu, self.current[cpu]);
            (*tcb).prepare_fair_entity_for_cpu(
                src_min_vruntime,
                self.fair_min_vruntime[cpu],
                avg_vruntime,
            );
        }
    }

    pub fn enqueue_unlocked(&mut self, tcb: *mut Tcb, releases: &mut DeferredReleaseList) {
        unsafe {
            let cpu_id = checked_cpu_id("enqueue_unlocked");
            self.validate_tcb_ptr(tcb, "enqueue_unlocked", cpu_id);

            if is_bootstrap_tcb(tcb) {
                crate::task::stop::mark_stopped_locked(tcb);
                return;
            }

            let live_owner = self.live_owner_cpu(tcb, "enqueue_unlocked", cpu_id);

            if let Some(running_cpu) = self.find_running_cpu(tcb) {
                if crate::sched::scheduler::debug_reply_wake_once(tcb, 0) {
                    crate::kernel::printk::ktrace!(sched, |_g| {
                        _g.puts("[FORK_WAKE_ENQ] running_cpu=");
                        _g.dec(running_cpu as u64);
                        _g.puts(" state=");
                        crate::sched::thread::ktrace_thread_state(&_g, (*tcb).state());
                        _g.puts("\n");
                    });
                }
                if (*tcb).state() != ThreadState::Runnable {
                    self.set_pending_enqueue(running_cpu, tcb, releases);
                    if running_cpu != cpu_id && running_cpu < self.online_cpus as usize {
                        crate::arch::send_ipi(running_cpu, crate::arch::IpiKind::Reschedule);
                    }
                }
                return;
            }

            if let Some(owner_cpu) = live_owner {
                if let Some(pending_cpu) = self.pending_cpu_for(tcb) {
                    if (*tcb).state() == ThreadState::Runnable
                        && pending_cpu < self.online_cpus as usize
                    {
                        crate::arch::send_ipi(pending_cpu, crate::arch::IpiKind::Reschedule);
                    }
                    return;
                }
                if owner_cpu != cpu_id {
                    crate::arch::send_ipi(owner_cpu, crate::arch::IpiKind::Reschedule);
                }
                return;
            }

            if (*tcb).placement.ready_queued {
                if crate::sched::scheduler::debug_reply_wake_once(tcb, 0) {
                    crate::kernel::printk::ktrace!(sched, |_g| {
                        _g.puts("[FORK_WAKE_ENQ] already_queued cpu=");
                        _g.dec((*tcb).placement.queued_cpu as u64);
                        _g.puts("\n");
                    });
                }
                crate::task::wait::mark_runnable_locked(tcb);
                return;
            }

            if self.is_pending_on_any_cpu(tcb) {
                if let Some(pending_cpu) = self.pending_cpu_for(tcb) {
                    if crate::sched::scheduler::debug_reply_wake_once(tcb, 0) {
                        crate::kernel::printk::ktrace!(sched, |_g| {
                            _g.puts("[FORK_WAKE_ENQ] pending_cpu=");
                            _g.dec(pending_cpu as u64);
                            _g.puts(" current_cpu=");
                            _g.dec(cpu_id as u64);
                            _g.puts("\n");
                        });
                    }
                    if pending_cpu == cpu_id {
                        if self.pending_enqueue[pending_cpu]
                            .compare_exchange(
                                tcb,
                                core::ptr::null_mut(),
                                Ordering::AcqRel,
                                Ordering::Relaxed,
                            )
                            .is_ok()
                        {
                            releases.push(tcb);
                        } else {
                            crate::task::wait::mark_runnable_locked(tcb);
                            return;
                        }
                    } else {
                        crate::task::wait::mark_runnable_locked(tcb);
                        if pending_cpu < self.online_cpus as usize {
                            crate::arch::send_ipi(pending_cpu, crate::arch::IpiKind::Reschedule);
                        }
                        return;
                    }
                } else {
                    crate::task::wait::mark_runnable_locked(tcb);
                    return;
                }
            }

            crate::task::wait::mark_runnable_locked(tcb);
            (*tcb).sched_ref_inc();

            let target = self.select_target_cpu(tcb);
            let this_cpu = crate::arch::current_cpu() as usize;

            let (_target_current_for_trace, should_ipi_target, inserted) = if target == this_cpu {
                let inserted = if self.ready_insert_claimable_unlocked(target, tcb) {
                    self.prepare_enqueue_unlocked(target, tcb);
                    self.insert_sorted(target, tcb)
                } else {
                    false
                };
                (self.current[target], false, inserted)
            } else if target > this_cpu {
                self.lock_cpu(target);
                let inserted = if self.ready_insert_claimable_unlocked(target, tcb) {
                    self.prepare_enqueue_unlocked(target, tcb);
                    self.insert_sorted(target, tcb)
                } else {
                    false
                };
                let target_current = self.current[target];
                let should_ipi = if inserted {
                    self.should_ipi_after_enqueue_locked(target, tcb)
                } else {
                    false
                };
                self.unlock_cpu(target);
                (target_current, should_ipi, inserted)
            } else {
                self.unlock_cpu(this_cpu);
                self.lock_cpu(target);
                let inserted = if self.ready_insert_claimable_unlocked(target, tcb) {
                    self.prepare_enqueue_unlocked(target, tcb);
                    self.insert_sorted(target, tcb)
                } else {
                    false
                };
                let target_current = self.current[target];
                let should_ipi = if inserted {
                    self.should_ipi_after_enqueue_locked(target, tcb)
                } else {
                    false
                };
                self.unlock_cpu(target);
                self.lock_cpu(this_cpu);
                (target_current, should_ipi, inserted)
            };

            if crate::sched::scheduler::debug_reply_wake_once(tcb, 0) {
                crate::kernel::printk::ktrace!(sched, |_g| {
                    _g.puts("[FORK_WAKE_ENQ] this_cpu=");
                    _g.dec(this_cpu as u64);
                    _g.puts(" target=");
                    _g.dec(target as u64);
                    _g.puts(" tcb=");
                    _g.hex(tcb as u64);
                    _g.puts(" state=");
                    crate::sched::thread::ktrace_thread_state(&_g, (*tcb).state());
                    _g.puts(" queued=");
                    _g.dec((*tcb).placement.ready_queued as u64);
                    _g.puts(" vr=");
                    _g.hex((*tcb).fair_vruntime());
                    _g.puts(" key=");
                    _g.hex((*tcb).priority);
                    _g.puts(" current=");
                    _g.hex(_target_current_for_trace as u64);
                    _g.puts("\n");
                });
            }

            if !inserted {
                // A concurrent scheduler transition claimed this TCB
                // (running / ready-queued / pending) under the destination
                // lock, so we did not insert it. Release the would-be
                // ready-slot `sched_ref` taken above so ownership
                // accounting stays balanced; the TCB's current owner
                // holds the queue slot.
                releases.push(tcb);
            } else if should_ipi_target {
                crate::arch::send_ipi(target, crate::arch::IpiKind::Reschedule);
            }
        }
    }

    pub fn dequeue_unlocked(&mut self, releases: &mut DeferredReleaseList) -> Option<*mut Tcb> {
        let cpu_id = crate::arch::current_cpu() as usize;
        self.dequeue_for_cpu_unlocked(cpu_id, releases)
    }

    pub fn dequeue_for_cpu_unlocked(
        &mut self,
        cpu_id: usize,
        releases: &mut DeferredReleaseList,
    ) -> Option<*mut Tcb> {
        unsafe {
            if let Some(tcb) =
                self.pop_head_for_class_unlocked(cpu_id, SCHED_CLASS_DEADLINE, cpu_id, releases)
            {
                return Some(tcb);
            }
            if let Some(tcb) =
                self.pop_head_for_class_unlocked(cpu_id, SCHED_CLASS_RT_FIFO, cpu_id, releases)
            {
                return Some(tcb);
            }
            self.pop_best_fair_unlocked(cpu_id, cpu_id, releases)
        }
    }

    pub fn remove_from_ready_queue_unlocked(&mut self, tcb: *mut Tcb) -> bool {
        unsafe {
            if !(*tcb).placement.ready_queued {
                return false;
            }
            let cpu = (*tcb).placement.queued_cpu as usize;
            if cpu >= MAX_CPUS {
                return false;
            }

            let class = (*tcb).queued_class;
            if class == SCHED_CLASS_FAIR {
                self.fair_snapshot_lag_unlocked(cpu, tcb, self.current[cpu]);
                self.fair_remove_unlocked(cpu, tcb);
                (*tcb).next = core::ptr::null_mut();
                (*tcb).placement.ready_queued = false;
                (*tcb).placement.queued_cpu = 0xFFFF_FFFF;
                (*tcb).queued_class = SCHED_CLASS_IDLE;
                return true;
            }

            let mut prev: *mut Tcb = core::ptr::null_mut();
            let head = self.queue_head_mut(cpu, class);
            let mut current = *head;
            while !current.is_null() {
                if current == tcb {
                    if prev.is_null() {
                        *head = (*current).next;
                    } else {
                        (*prev).next = (*current).next;
                    }
                    (*current).next = core::ptr::null_mut();
                    (*tcb).placement.ready_queued = false;
                    (*tcb).placement.queued_cpu = 0xFFFF_FFFF;
                    (*tcb).queued_class = SCHED_CLASS_IDLE;
                    return true;
                }
                prev = current;
                current = (*current).next;
            }
            false
        }
    }

    fn is_ready_queued_unlocked(&self, tcb: *mut Tcb) -> bool {
        unsafe { (*tcb).placement.ready_queued }
    }

    pub fn enqueue_with_releases_locked(
        &mut self,
        tcb: *mut Tcb,
        releases: &mut DeferredReleaseList,
    ) {
        self.lock();
        self.enqueue_unlocked(tcb, releases);
        self.unlock();
    }

    pub fn remove_from_ready_queue_with_releases_locked(
        &mut self,
        tcb: *mut Tcb,
        releases: &mut DeferredReleaseList,
    ) -> bool {
        unsafe {
            if !(*tcb).placement.ready_queued {
                return false;
            }
            let cpu = (*tcb).placement.queued_cpu as usize;
            if cpu >= MAX_CPUS {
                return false;
            }
            self.lock_cpu(cpu);
            // Re-validate under the lock: ready_queued / queued_cpu are
            // invariant only under the queued CPU's scheduler lock. Between
            // the unlocked reads above and here the TCB may have been
            // dequeued and re-queued on a different CPU; if the queued CPU
            // no longer matches the lock we hold, mutating its tree would
            // race the current owner — leave it instead.
            let result =
                if (*tcb).placement.ready_queued && (*tcb).placement.queued_cpu as usize == cpu {
                    self.remove_from_ready_queue_unlocked(tcb)
                } else {
                    false
                };
            if result {
                releases.push(tcb);
            }
            self.unlock_cpu(cpu);
            result
        }
    }

    pub fn requeue_thread_with_releases_locked(
        &mut self,
        tcb: *mut Tcb,
        releases: &mut DeferredReleaseList,
    ) {
        let _ = self.remove_from_ready_queue_with_releases_locked(tcb, releases);
        self.enqueue_with_releases_locked(tcb, releases);
    }

    pub fn enqueue(&mut self, tcb: *mut Tcb) {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        let mut releases = DeferredReleaseList::new();
        self.enqueue_with_releases_locked(tcb, &mut releases);
        unsafe {
            self.drain_release(&mut releases);
            crate::mm::restore_irq(irq_flag);
        }
    }

    pub fn dequeue(&mut self) -> Option<*mut Tcb> {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        let mut releases = DeferredReleaseList::new();
        self.lock();
        let result = self.dequeue_unlocked(&mut releases);
        self.unlock();
        unsafe {
            self.drain_release(&mut releases);
            crate::mm::restore_irq(irq_flag);
        }
        result
    }

    pub fn dequeue_for_cpu(&mut self, cpu_id: usize) -> Option<*mut Tcb> {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        let mut releases = DeferredReleaseList::new();
        self.lock_cpu(cpu_id);
        let result = self.dequeue_for_cpu_unlocked(cpu_id, &mut releases);
        self.unlock_cpu(cpu_id);
        unsafe {
            self.drain_release(&mut releases);
            crate::mm::restore_irq(irq_flag);
        }
        result
    }

    pub fn remove_from_ready_queue(&mut self, tcb: *mut Tcb) -> bool {
        let irq_flag = unsafe { crate::mm::save_irq_disable() };
        let mut releases = DeferredReleaseList::new();
        let result = self.remove_from_ready_queue_with_releases_locked(tcb, &mut releases);
        unsafe {
            self.drain_release(&mut releases);
            crate::mm::restore_irq(irq_flag);
        }
        result
    }

    pub fn resort_ready_thread(&mut self, tcb: *mut Tcb) {
        unsafe {
            if !(*tcb).placement.ready_queued {
                return;
            }
            let cpu = (*tcb).placement.queued_cpu as usize;
            if cpu >= MAX_CPUS {
                return;
            }
            self.lock_cpu(cpu);
            if self.remove_from_ready_queue_unlocked(tcb) {
                self.insert_sorted(cpu, tcb);
            }
            self.unlock_cpu(cpu);
        }
    }

    pub(crate) unsafe fn reweight_fair_thread_locked(&mut self, tcb: *mut Tcb, new_weight: u16) {
        unsafe {
            if (*tcb).sched_class != SCHED_CLASS_FAIR {
                return;
            }

            if (*tcb).placement.ready_queued {
                let cpu = (*tcb).placement.queued_cpu as usize;
                if cpu < MAX_CPUS {
                    self.lock_cpu(cpu);
                    self.reweight_queued_fair_thread_unlocked(cpu, tcb, new_weight);
                    self.unlock_cpu(cpu);
                    return;
                }
            }

            if let Some(owner_cpu) = (*tcb).run_owner() {
                if owner_cpu < self.online_cpus as usize {
                    self.lock_cpu(owner_cpu);
                    if self.current[owner_cpu] == tcb {
                        self.reweight_running_fair_thread_unlocked(owner_cpu, tcb, new_weight);
                        self.unlock_cpu(owner_cpu);

                        let current_cpu = crate::arch::current_cpu() as usize;
                        if owner_cpu != current_cpu {
                            crate::arch::send_ipi(owner_cpu, crate::arch::IpiKind::Reschedule);
                        }
                        return;
                    }
                    self.unlock_cpu(owner_cpu);
                }
            }

            self.reweight_detached_fair_thread_unlocked(tcb, new_weight);
        }
    }

    pub(super) fn schedule_unlocked(
        &mut self,
        publish_old: *mut Tcb,
        releases: &mut DeferredReleaseList,
    ) -> *mut Tcb {
        let cpu_id = crate::arch::current_cpu() as usize;

        while let Some(tcb) = self.dequeue_for_cpu_unlocked(cpu_id, releases) {
            unsafe {
                if (*tcb).run_owner() != Some(cpu_id) {
                    panic!(
                        "[SCHED] schedule_unlocked: dequeued tcb=0x{:x} was not claimed by cpu={}",
                        tcb as u64, cpu_id
                    );
                }
                if let Some(running_cpu) = self.find_running_cpu(tcb) {
                    panic!(
                        "[SCHED] schedule_unlocked: dequeued tcb=0x{:x} is current on cpu={} on cpu={}",
                        tcb as u64, running_cpu, cpu_id
                    );
                }
                if (*tcb).state() != ThreadState::Runnable || self.is_pending_on_any_cpu(tcb) {
                    (*tcb).clear_run_owner_cpu();
                    releases.push(tcb);
                    continue;
                }
            }
            unsafe {
                self.publish_switch_target_locked(cpu_id, publish_old, tcb, releases);
            }
            unsafe {
                (*tcb)
                    .sched_ref
                    .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
                self.fair_refresh_min_vruntime_unlocked(cpu_id);
            }
            return tcb;
        }

        self.unlock_cpu(cpu_id);

        let online = self.online_cpus as usize;
        for victim in 0..online {
            if victim == cpu_id {
                continue;
            }
            self.lock_cpu(victim);
            if let Some(tcb) = self.steal_from_unlocked(victim, cpu_id, releases) {
                self.unlock_cpu(victim);
                self.lock_cpu(cpu_id);
                unsafe {
                    if (*tcb).run_owner() != Some(cpu_id) {
                        panic!(
                            "[SCHED] schedule_unlocked: stole tcb=0x{:x} but cpu={} did not own it",
                            tcb as u64, cpu_id
                        );
                    }
                    if let Some(running_cpu) = self.find_running_cpu(tcb) {
                        panic!(
                            "[SCHED] schedule_unlocked: stole tcb=0x{:x} is current on cpu={} from cpu={}",
                            tcb as u64, running_cpu, victim
                        );
                    }
                    if (*tcb).state() != ThreadState::Runnable || self.is_pending_on_any_cpu(tcb) {
                        (*tcb).clear_run_owner_cpu();
                        releases.push(tcb);
                        self.unlock_cpu(cpu_id);
                        continue;
                    }
                    if (*tcb).sched_class == SCHED_CLASS_FAIR {
                        self.prepare_fair_entity_for_cpu_unlocked(cpu_id, tcb);
                    }
                }
                unsafe {
                    self.publish_switch_target_locked(cpu_id, publish_old, tcb, releases);
                    (*tcb)
                        .sched_ref
                        .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
                    self.fair_refresh_min_vruntime_unlocked(cpu_id);
                }
                return tcb;
            }
            self.unlock_cpu(victim);
        }

        self.lock_cpu(cpu_id);
        if !publish_old.is_null() {
            unsafe {
                self.publish_outgoing_before_current_flip_locked(cpu_id, publish_old, releases);
            }
        }
        self.idle[cpu_id]
    }

    fn steal_from_unlocked(
        &mut self,
        victim: usize,
        claim_cpu: usize,
        releases: &mut DeferredReleaseList,
    ) -> Option<*mut Tcb> {
        unsafe {
            for class in [SCHED_CLASS_DEADLINE, SCHED_CLASS_RT_FIFO] {
                let head = self.queue_head_mut(victim, class);
                let mut prev: *mut Tcb = core::ptr::null_mut();
                let mut current = *head;

                while !current.is_null() {
                    let next = (*current).next;
                    let affinity = (*current).cpu_affinity;
                    if affinity == 0xFFFF_FFFF && (*current).state() == ThreadState::Runnable {
                        let claimed = (*current).try_claim_run_owner_cpu(claim_cpu);
                        if prev.is_null() {
                            *head = next;
                        } else {
                            (*prev).next = next;
                        }
                        Self::clear_ready_placement_unlocked(current);
                        if claimed {
                            return Some(current);
                        }
                        releases.push(current);
                        current = next;
                        continue;
                    }
                    prev = current;
                    current = next;
                }
            }

            loop {
                let fair_target = self.fair_find_stealable_from_unlocked(self.fair_heads[victim]);
                if fair_target.is_null() {
                    break;
                }
                let claimed = (*fair_target).try_claim_run_owner_cpu(claim_cpu);
                self.fair_snapshot_lag_unlocked(victim, fair_target, self.current[victim]);
                self.fair_remove_unlocked(victim, fair_target);
                Self::clear_ready_placement_unlocked(fair_target);
                if claimed {
                    return Some(fair_target);
                }
                releases.push(fair_target);
            }
            None
        }
    }

    pub fn needs_reschedule(&self) -> bool {
        let cpu_id = crate::arch::current_cpu() as usize;
        let current = self.current[cpu_id];
        let head = unsafe { self.peek_best_ready_unlocked(cpu_id, current) };
        if head.is_null() || current.is_null() {
            return false;
        }
        unsafe { self.should_preempt_tcb(cpu_id, head, current) }
    }
}
