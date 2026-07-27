// SPDX-License-Identifier: GPL-2.0-only
//! Reference Counting for Kernel Objects
//!
//! Inline reference counting in KernelObject for proper lifecycle management.
//! When refcount reaches zero, object-specific cleanup is performed.

use super::object::{KernelObject, ObjectType};
use core::sync::atomic::Ordering;

/// Release object (called by delete_capability)
///
/// Decrements reference count and queues final cleanup if it reaches zero.
///
/// For TCB objects, destruction is deferred if the scheduler still holds
/// a reference (`sched_ref > 0`).  In that case, `pending_destroy` is set
/// and the scheduler will trigger destruction when its reference drops.
///
/// # Safety
/// obj must be a valid pointer to a KernelObject.
pub unsafe fn release_object(obj: *mut KernelObject, obj_type: ObjectType) {
    if obj.is_null() {
        return;
    }

    unsafe {
        // Decrement refcount
        let old_count = (*obj).ref_count.fetch_sub(1, Ordering::AcqRel);

        if old_count == 1 {
            // Last capability reference gone.
            // For TCBs: if the scheduler still references this TCB
            // (it is current[] on some CPU), defer destruction.
            // The scheduler will trigger it when sched_ref drops to 0.
            if obj_type == ObjectType::Tcb {
                let tcb = obj as *mut crate::sched::thread::Tcb;
                if (*tcb).sched_ref.load(Ordering::Acquire) > 0 {
                    (*tcb).pending_destroy.store(true, Ordering::Release);
                    return;
                }
            }
            crate::object::enqueue_reap(obj, obj_type);
        }
    }
}

/// Run final object destruction once the reaper decides cleanup may proceed.
///
/// The caller must hold `CAP_LOCK`.
///
/// # Safety
/// obj must be a valid pointer to a KernelObject.  CAP_LOCK must be held.
pub(crate) unsafe fn destroy_object_final(obj: *mut KernelObject, obj_type: ObjectType) {
    unsafe {
        destroy_object(obj, obj_type);
    }
}

#[inline]
unsafe fn with_cap_lock_released(f: impl FnOnce()) {
    // Some finalizers publish watch events or wake pipe/EQ waiters.
    // Those wake paths can drop the last scheduler reference on a
    // TCB and re-enter the object reaper, which takes CAP_LOCK.
    // Mirror TCB cleanup's discipline: release CAP_LOCK around the
    // wake-capable part, then reacquire it so the reaper can finish
    // the final untyped freelist publication under the normal lock.
    crate::mm::CAP_LOCK.unlock();
    f();
    crate::mm::CAP_LOCK.lock();
}

/// Increment object reference count. The object MUST already have a positive
/// refcount — this is a strong pin (an extra reference taken while already
/// holding one, or while holding a lock that blocks finalization). Zero is
/// terminal: once `release_object` drives the refcount to zero the object is
/// enqueued for reap and MUST NOT be resurrected with this call, because
/// `drain_reaper` finalizes without re-checking the refcount. For weak
/// walkers / registries that may race teardown, use `try_increment_refcount`.
///
/// # Safety
/// `obj` must be a valid pointer to a live `KernelObject` with refcount > 0.
pub unsafe fn increment_refcount(obj: *mut KernelObject) -> u32 {
    if obj.is_null() {
        return 0;
    }
    unsafe { (*obj).ref_count.fetch_add(1, Ordering::AcqRel) + 1 }
}

/// Conditionally increment the reference count — pins the object only if it is
/// currently alive (refcount > 0). Returns `false` without touching the count
/// when the refcount is zero, so a zero-ref object that is enqueued for
/// reaping is left to finalize: zero is terminal, never resurrected (matching
/// prior art such as Linux's `mmget_not_zero` / `atomic_inc_not_zero`). Use
/// this from weak-pointer registries / walkers (e.g. a global sweep over a
/// live set) that can race a concurrent `release_object` driving the refcount
/// to zero, where a plain `increment_refcount` would resurrect a dying object
/// that `drain_reaper` then frees regardless of the bump.
///
/// The CAS loop is race-free: between observing refcount > 0 and the successful
/// add, a concurrent drop to zero makes the `compare_exchange` fail and the
/// retry observes zero and returns `false`.
///
/// # Safety
/// `obj` must be a valid pointer to a `KernelObject` whose storage is live for
/// the duration of the call — the caller must hold a lock or other guarantee
/// that blocks `destroy_object_final` (in SaltyOS this means blocking the
/// reaper path that unregisters/frees the object, e.g. `LIVE_VSPACE_LOCK`).
pub unsafe fn try_increment_refcount(obj: *mut KernelObject) -> bool {
    if obj.is_null() {
        return false;
    }
    unsafe {
        loop {
            let cur = (*obj).ref_count.load(Ordering::Acquire);
            if cur == 0 {
                return false;
            }
            if (*obj)
                .ref_count
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }
}

/// RAII pin: holds an extra refcount on a `KernelObject` for the
/// duration of a syscall slow/fast path that must release CAP_LOCK
/// between snapshot and use. Without the pin a sibling thread's
/// `delete_capability` could drive the master's refcount to zero and
/// reap the object before we re-validate it under CAP_LOCK; with
/// the pin our reference keeps the object alive even if the
/// user-visible cap slot is freed and reused under us.
pub struct ObjectPin {
    obj: *mut KernelObject,
    obj_type: ObjectType,
}

impl ObjectPin {
    /// # Safety
    /// `obj` must currently have at least one outstanding reference
    /// (e.g. via the cap slot the caller just resolved), and the
    /// caller must hold whatever lock (typically CAP_LOCK) keeps
    /// that pre-existing reference stable for the duration of this
    /// constructor. After construction the pin owns a fresh +1
    /// independent of the originating cap slot.
    pub unsafe fn new(obj: *mut KernelObject, obj_type: ObjectType) -> Self {
        unsafe { increment_refcount(obj) };
        Self { obj, obj_type }
    }

    /// Drop the pin without releasing — used when ownership of the
    /// underlying refcount has been transferred to a long-lived
    /// holder (e.g. installed into a TCB field).
    pub fn forget(self) {
        core::mem::forget(self);
    }

    pub fn obj(&self) -> *mut KernelObject {
        self.obj
    }
}

impl Drop for ObjectPin {
    fn drop(&mut self) {
        if !self.obj.is_null() {
            // SAFETY: `new()` paired the +1 with this -1; the
            // contract is upheld unless the holder explicitly opted
            // out via `forget()`.
            unsafe { release_object(self.obj, self.obj_type) };
        }
    }
}

/// Get current reference count
///
/// # Safety
/// obj must be a valid pointer to a KernelObject.
pub unsafe fn get_refcount(obj: *mut KernelObject) -> u32 {
    if obj.is_null() {
        return 0;
    }
    unsafe { (*obj).ref_count.load(Ordering::Acquire) }
}

/// Destroy object when refcount reaches zero
///
/// # Safety
/// obj must be a valid pointer to a KernelObject with no remaining references.
unsafe fn destroy_object(obj: *mut KernelObject, obj_type: ObjectType) {
    unsafe {
        match obj_type {
            ObjectType::Untyped => {
                // Backing-frame ownership and root-reservation
                // transitions are performed by the reaper's
                // final-death path before this destructor runs (see
                // `object/reaper.rs::drain_reaper` steps 2 + 3).
                // Verify the children list is empty — a non-empty
                // list at this point means the reaper unlinked the
                // wrong object or `add_child` / `remove_child` raced.
                let ut = obj as *const crate::cap::UntypedMemory;
                crate::kernel::bug::kassert!(
                    (*ut).child_head.is_null() && (*ut).mo_page_refs == 0,
                    "Untyped destroyed with live children or MO pages — invariant violation"
                );
            }

            ObjectType::Frame => {
                // Backing-frame ownership is restored to the parent untyped by
                // the CDT delete path before destroy_object() runs.
            }

            // Same as Frame: the carved page returns to the parent untyped via
            // the CDT delete path (`child_phys_range`) before destroy runs.
            ObjectType::PageTable => {}

            ObjectType::MemoryObject => {
                // SAFETY: obj was validated as MemoryObject type above.
                let mo = &mut *(obj as *mut super::memory_object::MemoryObject);
                mo.destroy();
            }

            ObjectType::CNode => {
                // CNode cleanup: delete all capabilities stored in slots
                let cnode = &mut *(obj as *mut super::cnode::CNode);
                let num_slots = cnode.num_slots();

                crate::kernel::printk::kdebug!(cap, |_g| {
                    _g.puts("[REFCOUNT] CNode destroy: cleaning up ");
                    _g.dec(num_slots as u64);
                    _g.puts(" slots\n");
                });

                // Iterate all slots and delete any non-null capabilities.
                // delete_capability is idempotent (checks SlotState::Free) and
                // safe to call recursively (bounded by MAX_RESOLVE_DEPTH).
                for i in 0..num_slots {
                    // SAFETY: slot_ptr is within bounds (i < num_slots)
                    let cap_ref = *cnode.slot_ptr(i);
                    // Only tear down a live reference. A stale entry (slot
                    // freed + reused since written) points at an unrelated
                    // cap owned by whoever allocated the slot — deleting it
                    // would corrupt another CSpace. The transit-pin gate in
                    // delete_capability separately protects in-flight caps.
                    if let Some((slot, _)) = cap_ref.get_live() {
                        super::cdt::CDT::delete_capability(slot);
                    }
                }

                crate::kernel::printk::kdebug!(cap, |_g| {
                    _g.puts("[REFCOUNT] CNode destroy: cleanup complete\n");
                });
            }

            ObjectType::VSpace => {
                // Page table cleanup
                let vspace = &mut *(obj as *mut crate::mm::VSpace);

                crate::kernel::printk::kdebug!(cap, |_g| {
                    _g.puts("[REFCOUNT] VSpace destroy: cleaning up page tables\n");
                });

                vspace.cleanup();

                crate::kernel::printk::kdebug!(cap, |_g| {
                    _g.puts("[REFCOUNT] VSpace destroy: cleanup complete\n");
                });
            }

            ObjectType::Tcb => {
                // Thread cleanup
                let tcb = &mut *(obj as *mut crate::sched::thread::Tcb);
                tcb.cleanup();
            }

            ObjectType::IrqHandler => {
                let irq = &mut *(obj as *mut crate::event::irq::IrqHandler);
                with_cap_lock_released(|| irq.cleanup());
            }

            ObjectType::IoPort => {
                // I/O port capability - no cleanup needed
            }

            ObjectType::SchedContext => {
                // Scheduling context cleanup
                let sc = &mut *(obj as *mut crate::sched::thread::SchedContext);
                sc.cleanup();
            }

            ObjectType::EventQueue => {
                let eq = &mut *(obj as *mut crate::event::event_queue::EventQueue);
                with_cap_lock_released(|| {
                    eq.signal_closed();
                    eq.watcher_list.drain_closed();
                });
            }

            ObjectType::Watch => {
                let watch = &mut *(obj as *mut crate::event::watch::Watch);
                watch.disarm();
                let watched = watch.watched_object;
                if !watched.is_null() {
                    let watched_obj_type = (*watched).obj_type;
                    let list_ptr = crate::event::source::watcher_list_for_obj_type(
                        watched_obj_type,
                        watched as *mut core::ffi::c_void,
                    );
                    if !list_ptr.is_null() {
                        let _ = (*list_ptr).remove(watch as *mut crate::event::watch::Watch);
                    }
                }
                let eq = watch.event_queue;
                if !eq.is_null() {
                    watch.event_queue = core::ptr::null_mut();
                    crate::cap::release_object(
                        eq as *mut crate::cap::KernelObject,
                        ObjectType::EventQueue,
                    );
                }
            }

            ObjectType::MessagePipe => {
                let mp = &mut *(obj as *mut crate::ipc::message_pipe::MessagePipe);
                with_cap_lock_released(|| mp.cleanup());
            }

            ObjectType::DataPipe => {
                let dp = &mut *(obj as *mut crate::ipc::data_pipe::DataPipe);
                with_cap_lock_released(|| dp.cleanup());
            }

            ObjectType::MessagePipeCore => {
                // Side destructors call `mp.cleanup()`, which closes the side
                // (propagating PEER_CLOSED + draining waiters under the core
                // lock) and then drops one core refcount. By the time the
                // core itself reaches refcount 0 every waiter list is
                // drained and every state bit settled — but the rings may
                // still hold in-flight carrier slots that `close` left
                // behind (carrier teardown needs CAP_LOCK, which `close`
                // can't take under the core lock). Drain them now,
                // CAP_LOCK held, via the canonical `CDT::delete_capability`
                // path.
                let core = &mut *(obj as *mut crate::ipc::message_pipe::MessagePipeCore);
                core.drain_all_carriers();
            }

            ObjectType::DataPipeCore => {
                // No carriers — DataPipe is a byte stream; the byte
                // ring is plain memory inside the core and is freed
                // along with the object's storage.
            }

            ObjectType::Timer => {
                let timer = &mut *(obj as *mut crate::event::timer::Timer);
                // `cancel` disarms the wheel entry and releases the
                // bound EQ refcount; nothing else to drop here.
                with_cap_lock_released(|| {
                    timer.cancel();
                    timer.watcher_list.drain_closed();
                });
            }

            ObjectType::KernelRng
            | ObjectType::SystemControl
            | ObjectType::Clock
            | ObjectType::SystemInfo
            | ObjectType::KernelDebug
            | ObjectType::DeviceControl
            | ObjectType::ExecAuthority => {
                // Pure cap-token types — no per-instance state beyond
                // the KernelObject header, nothing to tear down.
            }

            ObjectType::Pager => {
                // Pager cleanup can wake TCBs and release sched_refs, so
                // `object::drain_reaper` runs it before taking CAP_LOCK.
                // The in-lock type destructor is intentionally a no-op.
            }

            ObjectType::VmHierarchyState => {
                // One-shot per-COW-tree lock object. By the time its
                // refcount reaches zero every bound MO has dropped its
                // internal reference (in `MemoryObject::destroy`, after
                // releasing the tree lock) and the user cap is gone, so the
                // tree is empty and nothing references the lock. No
                // per-instance state to tear down beyond the header.
            }

            ObjectType::Null => {
                // Nothing to do
            }
        }
    }
}

/// Extension trait for cleanup operations
pub trait Cleanup {
    /// Cleanup resources when object is destroyed
    fn cleanup(&mut self);
}

// Watcher-list dispatch lives in `crate::event::source` —
// `watcher_list_for_obj_type` returns `null_mut()` for non-watchable
// types as well as for the pipe-side `core == null` finalize race.
// The `Watch` finalize arm above goes through that helper directly.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refcount_increment() {
        let obj = KernelObject::new(ObjectType::MessagePipe, 4);

        assert_eq!(obj.ref_count.load(Ordering::Acquire), 1);
        unsafe {
            increment_refcount(&obj as *const _ as *mut _);
        }
        assert_eq!(obj.ref_count.load(Ordering::Acquire), 2);
    }
}
