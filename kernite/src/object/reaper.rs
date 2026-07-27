// SPDX-License-Identifier: GPL-2.0-only
//! Deferred object finalization queue.
//!
//! The queue establishes a hard boundary between "reference reached zero" and
//! "run deep cleanup now". `release_object()` is allowed to enqueue from a wide
//! range of contexts, including paths that currently hold `CAP_LOCK`; actual
//! final cleanup is serialized later by `drain_reaper()` under `CAP_LOCK`.

use crate::cap::{KernelObject, ObjectType};
use crate::mm::SpinLock;
use core::sync::atomic::{AtomicU8, Ordering};

const REAPER_QUEUED_BIT: u64 = 1;
const REAPER_NEXT_MASK: u64 = !REAPER_QUEUED_BIT;

static REAPER_LOCK: SpinLock = SpinLock::new();
static REAPER_DRAINING: AtomicU8 = AtomicU8::new(0);

static mut REAPER_HEAD: *mut KernelObject = core::ptr::null_mut();
static mut REAPER_TAIL: *mut KernelObject = core::ptr::null_mut();

#[inline]
unsafe fn reaper_link_is_queued(obj: *mut KernelObject) -> bool {
    unsafe { ((*obj).reaper_link & REAPER_QUEUED_BIT) != 0 }
}

#[inline]
unsafe fn reaper_link_next(obj: *mut KernelObject) -> *mut KernelObject {
    unsafe { (((*obj).reaper_link & REAPER_NEXT_MASK) as usize) as *mut KernelObject }
}

#[inline]
unsafe fn set_reaper_link(obj: *mut KernelObject, next: *mut KernelObject, queued: bool) {
    crate::kernel::bug::kassert_eq!((next as usize) & (REAPER_QUEUED_BIT as usize), 0);
    unsafe {
        (*obj).reaper_link = (next as usize as u64) | if queued { REAPER_QUEUED_BIT } else { 0 };
    }
}

#[inline]
unsafe fn reaper_pop() -> Option<*mut KernelObject> {
    unsafe {
        let irq = crate::mm::save_irq_disable();
        REAPER_LOCK.lock();
        let result = if REAPER_HEAD.is_null() {
            None
        } else {
            let obj = REAPER_HEAD;
            REAPER_HEAD = reaper_link_next(obj);
            if REAPER_HEAD.is_null() {
                REAPER_TAIL = core::ptr::null_mut();
            }
            set_reaper_link(obj, core::ptr::null_mut(), false);
            Some(obj)
        };
        REAPER_LOCK.unlock();
        crate::mm::restore_irq(irq);
        result
    }
}

#[inline]
unsafe fn reaper_is_empty() -> bool {
    unsafe {
        let irq = crate::mm::save_irq_disable();
        REAPER_LOCK.lock();
        let empty = REAPER_HEAD.is_null();
        REAPER_LOCK.unlock();
        crate::mm::restore_irq(irq);
        empty
    }
}

/// Enqueue a kernel object for deferred final cleanup.
///
/// # Safety
/// `obj` must point to a live kernel object whose capability refcount has
/// already reached zero. Every retype-able kernel object follows the
/// standard one-shot `0 -> enqueue -> finalize` transition; no kernel
/// object now needs special reuse handling. The already-queued check
/// below is kept as defense-in-depth for any future
/// path that double-enqueues — type-specific finalizers are still
/// expected to be idempotent under spurious re-entry.
pub(crate) unsafe fn enqueue_reap(obj: *mut KernelObject, obj_type: ObjectType) {
    if obj.is_null() || obj_type == ObjectType::Null {
        return;
    }

    unsafe {
        let irq = crate::mm::save_irq_disable();
        REAPER_LOCK.lock();
        if reaper_link_is_queued(obj) {
            // Already queued — pending drain will pick it up
            // exactly once. Type-specific finalizer is responsible
            // for handling the (rare, inline-storage-only) case
            // where the object was re-bound between enqueues.
            REAPER_LOCK.unlock();
            crate::mm::restore_irq(irq);
            return;
        }
        set_reaper_link(obj, core::ptr::null_mut(), true);
        if REAPER_TAIL.is_null() {
            REAPER_HEAD = obj;
        } else {
            set_reaper_link(REAPER_TAIL, obj, true);
        }
        REAPER_TAIL = obj;

        REAPER_LOCK.unlock();
        crate::mm::restore_irq(irq);
    }
}

/// Drain every pending reaper item.
///
/// Final cleanup always runs under `CAP_LOCK` to preserve the existing cleanup
/// assumptions in capability, TCB, and MM code. The queue lock is never held
/// across final cleanup, so nested `release_object()` calls inside cleanup may
/// enqueue more work without deadlocking.
pub(crate) fn drain_reaper() {
    if REAPER_DRAINING
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    loop {
        match unsafe { reaper_pop() } {
            Some(obj) => unsafe {
                // Pager cleanup may wake TCBs and release waiter-slot
                // sched_refs; do that before CAP_LOCK so a last sched_ref
                // drop cannot recursively enter the reaper while CAP_LOCK is
                // already held. The type finalizer below calls cleanup again,
                // but Pager::cleanup is idempotent after this drain.
                if (*obj).obj_type == crate::cap::ObjectType::Pager {
                    let pager = &mut *(obj as *mut crate::cap::pager::Pager);
                    let (prev_eq, drained) = pager.cleanup();
                    if !prev_eq.is_null() {
                        crate::cap::release_object(
                            prev_eq as *mut crate::cap::KernelObject,
                            crate::cap::ObjectType::EventQueue,
                        );
                    }
                    crate::cap::pager::wake_and_free_drained_requests(drained);
                }

                let irq = crate::mm::save_irq_disable();
                crate::mm::CAP_LOCK.lock();

                if (*obj).obj_type == crate::cap::ObjectType::VSpace {
                    let vspace = &mut *(obj as *mut crate::mm::VSpace);
                    if !vspace.prepare_reap() {
                        enqueue_reap(obj, crate::cap::ObjectType::VSpace);
                        crate::mm::CAP_LOCK.unlock();
                        crate::mm::restore_irq(irq);
                        REAPER_DRAINING.store(0, Ordering::Release);
                        break;
                    }
                }

                // Trusted parent_ut is on the object header itself
                // (set in retype's terminal `add_child`, cleared in
                // `remove_child`). PMM owner backpointer is only a
                // debug-time consistency check.
                let parent_ut: *mut crate::cap::UntypedMemory = (*obj).parent_ut;

                let mut tmp_cap = crate::cap::Capability::null();
                tmp_cap.object = obj;
                tmp_cap.obj_type = (*obj).obj_type;
                let phys_range = crate::cap::child_phys_range(&tmp_cap);

                if let Some((phys, _)) = phys_range {
                    if let Some(meta) = crate::mm::pmm_lookup(phys) {
                        if let crate::mm::frame::FrameOwner::UntypedReserved { ut } =
                            meta.to_owner()
                        {
                            let pmm_parent = ut as *mut crate::cap::UntypedMemory;
                            let expected_ut = if (*obj).obj_type == crate::cap::ObjectType::Untyped
                            {
                                obj as *mut crate::cap::UntypedMemory
                            } else {
                                parent_ut
                            };
                            crate::kernel::bug::kassert!(
                                expected_ut.is_null() || pmm_parent == expected_ut,
                                "reaper: object header/PMM untyped owner disagreement"
                            );
                        }
                    }
                }

                // 1. Unlink from parent untyped's object-level children
                //    list. After this `has_children` (and therefore
                //    `untyped_reset`) sees one fewer child.
                if !parent_ut.is_null() {
                    (*parent_ut).remove_child(obj);
                }

                // 2. Reclaim the carved phys range to
                //    `UntypedReserved { ut: parent_ut }` BEFORE the
                //    destructor wipes the child's inner storage —
                //    PMM owner must not point at soon-to-be-dead bytes.
                //
                // Exception: a `Frame` whose PMM ownership has already
                // been transferred to an MO (`FrameOwner::MoData`) by
                // `PAGER_SUPPLY_PAGE` must not be reclaimed here —
                // the underlying physical page now belongs to the MO,
                // not the parent untyped. The reaper still drops the
                // `FrameObject` metadata (step 4 below is a no-op for
                // Frame), and the MO owns the page until its own
                // destroy/decommit.
                let skip_phys_reclaim = if (*obj).obj_type == crate::cap::ObjectType::Frame {
                    if let Some((phys, _)) = phys_range {
                        if let Some(meta) = crate::mm::pmm_lookup(phys) {
                            matches!(meta.to_owner(), crate::mm::frame::FrameOwner::MoData { .. })
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                if let Some((phys, byte_size)) = phys_range {
                    if !skip_phys_reclaim && !parent_ut.is_null() {
                        (*parent_ut).reclaim_child_range(phys, byte_size);
                    }
                }

                // 3. Root untyped (no parent_ut) returns its covered
                //    frames to the PMM free pool.
                if (*obj).obj_type == crate::cap::ObjectType::Untyped && parent_ut.is_null() {
                    let ut = &*(obj as *const crate::cap::UntypedMemory);
                    ut.release_reservation();
                }

                // 4. Type-specific destructor.
                crate::cap::destroy_object_final(obj, (*obj).obj_type);

                // 5. Push the freed (phys, byte_size) onto the parent
                //    untyped's matching `ClassBucket` freelist. POST
                //    destroy so the destructor can't race a concurrent
                //    retype reading the freelist node header.
                //    `CAP_LOCK` serializes the publication.
                //
                // Mirrors the step-2 exception: a Frame transferred to
                // `FrameOwner::MoData` is owned by the MO, not the
                // untyped's freelist.
                if let Some((phys, byte_size)) = phys_range {
                    if !skip_phys_reclaim && !parent_ut.is_null() {
                        let _ = (*parent_ut).release_block(phys, byte_size as u64);
                    }
                }

                // Drop the internal child-list pin acquired by
                // UntypedMemory::add_child_locked. This is deliberately after
                // every use of parent_ut above; if the last user-visible cap to
                // the untyped was already deleted, this release may enqueue the
                // parent untyped itself for reaping.
                if !parent_ut.is_null() {
                    crate::cap::release_object(
                        parent_ut as *mut crate::cap::KernelObject,
                        crate::cap::ObjectType::Untyped,
                    );
                }
                crate::mm::CAP_LOCK.unlock();
                // Insert any tracking retired by VSpace::cleanup above into the
                // deferred-free list now that CAP_LOCK is released, keeping
                // DEFERRED_FREE_LOCK a leaf never nested under CAP_LOCK. IRQs
                // are still disabled (restored on the next line).
                crate::mm::vspace::flush_pending_retire();
                crate::mm::restore_irq(irq);
            },
            None => {
                REAPER_DRAINING.store(0, Ordering::Release);
                let empty = unsafe { reaper_is_empty() };
                if empty
                    || REAPER_DRAINING
                        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                {
                    break;
                }
            }
        }
    }
}
