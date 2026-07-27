// SPDX-License-Identifier: GPL-2.0-only
//! Pager-related syscall handlers.
//!
//! `PAGER_BIND_EQ` / `PAGER_SUPPLY_PAGE` / `PAGER_FAIL` / `PAGER_DETACH` /
//! `PAGER_BEGIN_WRITEBACK` / `PAGER_WRITEBACK_DONE`.

use super::{
    CapRights, Capability, ObjectType, SyscallError, SyscallResult, lookup_typed_cap_locked,
    validate_capability,
};
use crate::cap::pager::{PendingPagerRequest, PendingState};

pub(super) fn syscall_pager_bind_eq(
    cap: &Capability,
    eq_cap_ptr: u64,
    cookie: u64,
    _flags: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Pager, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let eq_cap =
        match lookup_typed_cap_locked(eq_cap_ptr, ObjectType::EventQueue, CapRights::SIGNAL) {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };

    unsafe {
        let pager = &mut *(cap.object as *mut crate::cap::pager::Pager);
        let eq_ptr = eq_cap.object as *mut crate::event::event_queue::EventQueue;
        crate::cap::increment_refcount(eq_ptr as *mut crate::cap::object::KernelObject);
        let prev = pager.bind_eq(eq_ptr, cookie);
        if !prev.is_null() {
            crate::cap::release_object(
                prev as *mut crate::cap::object::KernelObject,
                ObjectType::EventQueue,
            );
        }
    }
    SyscallResult::ok(0)
}

pub(super) fn syscall_pager_supply_page(
    cap: &Capability,
    mo_id: u64,
    page_idx: u64,
    frame_cap_ptr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Pager, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let pager_ptr = cap.object as *mut crate::cap::pager::Pager;
    let (req_ptr, mo_ptr) = unsafe {
        let pager = &mut *pager_ptr;
        pager.lock.lock();

        let mut req: *mut PendingPagerRequest = pager.pending_head;
        let mut found: *mut PendingPagerRequest = core::ptr::null_mut();
        while !req.is_null() {
            if (*req).mo_id == mo_id && (*req).page_idx == page_idx as u32 {
                found = req;
                break;
            }
            req = (*req).pager_next;
        }

        if found.is_null() {
            pager.lock.unlock();
            return SyscallResult::err(SyscallError::NotFound);
        }

        let mo_ptr = (*found).mo;
        if mo_ptr.is_null() {
            pager.unlink_pending_locked(found);
            (*found).pager_next = core::ptr::null_mut();
            (*found).state = PendingState::Reclaimed as u8;
            pager.lock.unlock();
            crate::cap::pager::wake_and_free_drained_requests(found);
            return SyscallResult::err(SyscallError::NotFound);
        }

        if (*found).state == PendingState::Supplied as u8 {
            pager.lock.unlock();
            return SyscallResult::err(SyscallError::Busy);
        }
        if (*found).state == PendingState::Failed as u8
            || (*found).state == PendingState::Reclaimed as u8
        {
            pager.lock.unlock();
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        (*found).state = PendingState::Supplied as u8;
        pager.lock.unlock();
        (found, mo_ptr)
    };

    let supply_result = super::cspace::consume_current_root_typed_cap_with_locked(
        frame_cap_ptr,
        ObjectType::Frame,
        CapRights::READ,
        |frame_cap| {
            let frame_obj = frame_cap.object as *mut crate::cap::FrameObject;
            let phys = unsafe { (*frame_obj).phys_addr };
            if phys == 0 {
                return Ok(Err(SyscallError::InvalidCapability));
            }

            let committed = unsafe {
                let mo = &mut *mo_ptr;
                // Commit serialises against decommit / evict / resize on this
                // tree. CAP_LOCK is held by the cap-consume around this closure,
                // so the order is CAP_LOCK -> tree lock -> commit_lock.
                let irq = crate::mm::vspace::save_irq_disable();
                let tl = mo.lock_tree();
                mo.commit_lock.lock();

                let existing = mo.pages.get(page_idx as usize);
                if existing != 0
                    && existing & crate::cap::memory_object::PHYS_TAG_BUSY == 0
                    && existing & crate::cap::memory_object::PHYS_TAG_PAGER_FAILED == 0
                {
                    mo.commit_lock.unlock();
                    (*tl).unlock();
                    crate::mm::vspace::restore_irq(irq);
                    return Ok(Ok(()));
                }

                let mut node_alloc = crate::mm::node_alloc::PmmNodeAllocator {
                    owner: crate::mm::frame::FrameOwner::MoMeta {
                        mo: mo_ptr,
                        subkind: crate::mm::frame::MoMetaKind::Radix,
                    },
                    use_reserve: true,
                };
                let committed = mo.commit_page(page_idx as usize, phys, &mut node_alloc);

                mo.commit_lock.unlock();
                (*tl).unlock();
                crate::mm::vspace::restore_irq(irq);
                committed
            };

            if !committed {
                return Ok(Err(SyscallError::OutOfMemory));
            }

            crate::mm::pmm_set_owner(
                phys,
                &crate::mm::frame::FrameOwner::MoData {
                    mo: mo_ptr,
                    page_idx: page_idx as u32,
                },
            );
            Ok(Ok(()))
        },
    );

    match supply_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            unsafe {
                let pager = &mut *pager_ptr;
                pager.lock.lock();
                if (*req_ptr).state == PendingState::Supplied as u8 {
                    (*req_ptr).state = PendingState::Failed as u8;
                    let waiters = (*req_ptr).waiter_head;
                    (*req_ptr).waiter_head = core::ptr::null_mut();
                    pager.lock.unlock();
                    crate::sched::scheduler::scheduler().wake_pager_request_waiters(waiters);
                } else {
                    pager.lock.unlock();
                }
            }
            return SyscallResult::err(e);
        }
        Err(e) => {
            unsafe {
                let pager = &mut *pager_ptr;
                pager.lock.lock();
                if (*req_ptr).state == PendingState::Supplied as u8 {
                    (*req_ptr).state = PendingState::Pending as u8;
                }
                pager.lock.unlock();
            }
            return SyscallResult::err(e);
        }
    }

    let drained = unsafe {
        let pager = &mut *pager_ptr;
        pager.lock.lock();
        if (*req_ptr).state == PendingState::Supplied as u8 {
            pager.unlink_pending_locked(req_ptr);
            (*req_ptr).pager_next = core::ptr::null_mut();
            pager.lock.unlock();
            req_ptr
        } else {
            pager.lock.unlock();
            core::ptr::null_mut()
        }
    };
    unsafe {
        crate::cap::pager::wake_and_free_drained_requests(drained);
    }
    SyscallResult::ok(0)
}

/// `PAGER_SUPPLY_COPY(pager, mo_id, page_idx, src_va, bytes_read)` —
/// page-cache supply. Unlike [`syscall_pager_supply_page`] the pager
/// donates no `Frame` cap: the kernel sources the page from the global
/// PMM (the anonymous demand-fault model), zero-fills it, copies
/// `bytes_read` bytes from the pager's `src_va`, and commits it into the
/// MO at `(mo_id, page_idx)` as untagged `MoData`. The page is therefore
/// kernel-owned page-cache memory — it never charges the pager's untyped
/// quota and returns to the global PMM on MO release/decommit. Bytes past
/// `bytes_read` stay zero (POSIX partial-page mmap semantics). I-cache
/// coherence for executable pages is handled by the faulter's resolve-map
/// path in `VSpace::handle_demand_fault`, so no extra sync is needed here.
///
/// On any failure the page is freed and the pending request is marked
/// `Failed` with its waiters woken, mirroring the failure epilogue of
/// `syscall_pager_supply_page` so the faulter retry surfaces SIGBUS.
pub(super) fn syscall_pager_supply_copy(
    cap: &Capability,
    mo_id: u64,
    page_idx: u64,
    src_va: u64,
    bytes_read: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Pager, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let pager_ptr = cap.object as *mut crate::cap::pager::Pager;
    // SAFETY: `pager_ptr` names the live Pager behind the validated cap; the
    // pending-request list is walked under `pager.lock`.
    let (req_ptr, mo_ptr) = unsafe {
        let pager = &mut *pager_ptr;
        pager.lock.lock();

        let mut req: *mut PendingPagerRequest = pager.pending_head;
        let mut found: *mut PendingPagerRequest = core::ptr::null_mut();
        while !req.is_null() {
            if (*req).mo_id == mo_id && (*req).page_idx == page_idx as u32 {
                found = req;
                break;
            }
            req = (*req).pager_next;
        }

        if found.is_null() {
            pager.lock.unlock();
            return SyscallResult::err(SyscallError::NotFound);
        }

        let mo_ptr = (*found).mo;
        if mo_ptr.is_null() {
            pager.unlink_pending_locked(found);
            (*found).pager_next = core::ptr::null_mut();
            (*found).state = PendingState::Reclaimed as u8;
            pager.lock.unlock();
            crate::cap::pager::wake_and_free_drained_requests(found);
            return SyscallResult::err(SyscallError::NotFound);
        }

        if (*found).state == PendingState::Supplied as u8 {
            pager.lock.unlock();
            return SyscallResult::err(SyscallError::Busy);
        }
        if (*found).state == PendingState::Failed as u8
            || (*found).state == PendingState::Reclaimed as u8
        {
            pager.lock.unlock();
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        (*found).state = PendingState::Supplied as u8;
        pager.lock.unlock();
        (found, mo_ptr)
    };

    let supply_result: Result<(), SyscallError> = (|| {
        let owner = crate::mm::frame::FrameOwner::MoData {
            mo: mo_ptr,
            page_idx: page_idx as u32,
        };
        let phys = match crate::mm::pmm_alloc(&owner) {
            Some(p) => p,
            None => return Err(SyscallError::OutOfMemory),
        };

        // SAFETY: `phys` is a fresh PMM page owned by this MO; the kernel
        // direct map gives a unique writable alias for the zero-fill + copy.
        // `copy_from_user_bytes` validates `src_va` in the caller's address
        // space and reports a fault by returning `false`.
        unsafe {
            let kva = crate::mm::phys_to_virt(phys) as *mut u8;
            core::ptr::write_bytes(kva, 0, crate::mm::PAGE_SIZE);
            let copy_len = core::cmp::min(bytes_read as usize, crate::mm::PAGE_SIZE);
            if copy_len > 0 && !crate::arch::uaccess::copy_from_user_bytes(src_va, kva, copy_len) {
                crate::mm::pmm_free(phys, &owner);
                return Err(SyscallError::InvalidArgument);
            }
        }

        // SAFETY: `mo_ptr` is the live MO captured from the pending request;
        // the radix commit runs under its `commit_lock`.
        let committed = unsafe {
            let mo = &mut *mo_ptr;
            // Commit serialises against decommit / evict / resize on this tree.
            // The user copy above already completed outside the lock.
            let irq = crate::mm::vspace::save_irq_disable();
            let tl = mo.lock_tree();
            mo.commit_lock.lock();

            let existing = mo.pages.get(page_idx as usize);
            if existing != 0
                && existing & crate::cap::memory_object::PHYS_TAG_BUSY == 0
                && existing & crate::cap::memory_object::PHYS_TAG_PAGER_FAILED == 0
            {
                // A concurrent supply already committed this page; drop ours.
                mo.commit_lock.unlock();
                (*tl).unlock();
                crate::mm::vspace::restore_irq(irq);
                crate::mm::pmm_free(phys, &owner);
                return Ok(());
            }

            let mut node_alloc = crate::mm::node_alloc::PmmNodeAllocator {
                owner: crate::mm::frame::FrameOwner::MoMeta {
                    mo: mo_ptr,
                    subkind: crate::mm::frame::MoMetaKind::Radix,
                },
                use_reserve: true,
            };
            let committed = mo.commit_page(page_idx as usize, phys, &mut node_alloc);
            mo.commit_lock.unlock();
            (*tl).unlock();
            crate::mm::vspace::restore_irq(irq);
            committed
        };

        if !committed {
            crate::mm::pmm_free(phys, &owner);
            return Err(SyscallError::OutOfMemory);
        }

        Ok(())
    })();

    if let Err(e) = supply_result {
        // SAFETY: `req_ptr` is the request we transitioned to `Supplied`;
        // flip it to `Failed` and wake its waiters so the faulter retry
        // surfaces SIGBUS.
        unsafe {
            let pager = &mut *pager_ptr;
            pager.lock.lock();
            if (*req_ptr).state == PendingState::Supplied as u8 {
                (*req_ptr).state = PendingState::Failed as u8;
                let waiters = (*req_ptr).waiter_head;
                (*req_ptr).waiter_head = core::ptr::null_mut();
                pager.lock.unlock();
                crate::sched::scheduler::scheduler().wake_pager_request_waiters(waiters);
            } else {
                pager.lock.unlock();
            }
        }
        return SyscallResult::err(e);
    }

    // SAFETY: success — unlink the satisfied request and wake every blocked
    // faulter; `wake_and_free_drained_requests` consumes the detached node.
    let drained = unsafe {
        let pager = &mut *pager_ptr;
        pager.lock.lock();
        if (*req_ptr).state == PendingState::Supplied as u8 {
            pager.unlink_pending_locked(req_ptr);
            (*req_ptr).pager_next = core::ptr::null_mut();
            pager.lock.unlock();
            req_ptr
        } else {
            pager.lock.unlock();
            core::ptr::null_mut()
        }
    };
    unsafe {
        crate::cap::pager::wake_and_free_drained_requests(drained);
    }
    SyscallResult::ok(0)
}

pub(super) fn syscall_pager_fail(
    cap: &Capability,
    mo_id: u64,
    page_idx: u64,
    _errno: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Pager, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let pager_ptr = cap.object as *mut crate::cap::pager::Pager;
    let mo_ptr = unsafe {
        let pager = &mut *pager_ptr;
        pager.lock.lock();

        let mut req: *mut PendingPagerRequest = pager.pending_head;
        let mut found: *mut PendingPagerRequest = core::ptr::null_mut();
        while !req.is_null() {
            if (*req).mo_id == mo_id && (*req).page_idx == page_idx as u32 {
                found = req;
                break;
            }
            req = (*req).pager_next;
        }

        if found.is_null() {
            pager.lock.unlock();
            return SyscallResult::err(SyscallError::NotFound);
        }

        if (*found).state == PendingState::Supplied as u8 {
            pager.lock.unlock();
            return SyscallResult::err(SyscallError::Busy);
        }

        let mo_ptr = (*found).mo;
        (*found).state = PendingState::Failed as u8;
        pager.lock.unlock();
        mo_ptr
    };

    if mo_ptr.is_null() {
        let drained = unsafe {
            let pager = &mut *pager_ptr;
            pager.lock.lock();
            let mut req = pager.pending_head;
            let mut found = core::ptr::null_mut();
            while !req.is_null() {
                if (*req).mo_id == mo_id && (*req).page_idx == page_idx as u32 {
                    found = req;
                    break;
                }
                req = (*req).pager_next;
            }
            if found.is_null() || (*found).state != PendingState::Failed as u8 {
                pager.lock.unlock();
                core::ptr::null_mut()
            } else {
                pager.unlink_pending_locked(found);
                (*found).pager_next = core::ptr::null_mut();
                pager.lock.unlock();
                found
            }
        };
        unsafe {
            crate::cap::pager::wake_and_free_drained_requests(drained);
        }
        return SyscallResult::err(SyscallError::NotFound);
    }

    let tombstone_ok = unsafe {
        let mo = &mut *mo_ptr;
        // The PAGER_FAILED tombstone is a page-identity write; serialise it
        // against commit / decommit / evict / resize on this tree.
        let irq = crate::mm::vspace::save_irq_disable();
        let tl = mo.lock_tree();
        mo.commit_lock.lock();
        let mut node_alloc = crate::mm::node_alloc::PmmNodeAllocator {
            owner: crate::mm::frame::FrameOwner::MoMeta {
                mo: mo_ptr,
                subkind: crate::mm::frame::MoMetaKind::Radix,
            },
            use_reserve: true,
        };
        let existing = mo.pages.get(page_idx as usize);
        let ok = if existing & crate::cap::memory_object::PHYS_TAG_PAGER_FAILED != 0 {
            true
        } else if existing != 0 {
            existing & crate::cap::memory_object::PHYS_TAG_BUSY == 0
        } else {
            mo.commit_page(
                page_idx as usize,
                crate::cap::memory_object::PHYS_TAG_PAGER_FAILED,
                &mut node_alloc,
            )
        };
        mo.commit_lock.unlock();
        (*tl).unlock();
        crate::mm::vspace::restore_irq(irq);
        ok
    };

    if !tombstone_ok {
        let waiter_head = unsafe {
            let pager = &mut *pager_ptr;
            pager.lock.lock();
            let mut req = pager.pending_head;
            let mut found = core::ptr::null_mut();
            while !req.is_null() {
                if (*req).mo_id == mo_id && (*req).page_idx == page_idx as u32 {
                    found = req;
                    break;
                }
                req = (*req).pager_next;
            }
            if found.is_null() || (*found).state != PendingState::Failed as u8 {
                pager.lock.unlock();
                core::ptr::null_mut()
            } else {
                let head = (*found).waiter_head;
                (*found).waiter_head = core::ptr::null_mut();
                pager.lock.unlock();
                head
            }
        };
        unsafe {
            crate::sched::scheduler::scheduler().wake_pager_request_waiters(waiter_head);
        }
        return SyscallResult::err(SyscallError::OutOfMemory);
    }

    let drained = unsafe {
        let pager = &mut *pager_ptr;
        pager.lock.lock();
        let mut req = pager.pending_head;
        let mut found = core::ptr::null_mut();
        while !req.is_null() {
            if (*req).mo_id == mo_id && (*req).page_idx == page_idx as u32 {
                found = req;
                break;
            }
            req = (*req).pager_next;
        }
        if found.is_null() || (*found).state != PendingState::Failed as u8 {
            pager.lock.unlock();
            core::ptr::null_mut()
        } else {
            pager.unlink_pending_locked(found);
            (*found).pager_next = core::ptr::null_mut();
            pager.lock.unlock();
            found
        }
    };

    unsafe {
        crate::cap::pager::wake_and_free_drained_requests(drained);
    }
    SyscallResult::ok(0)
}

pub(super) fn syscall_pager_detach(cap: &Capability, mo_id: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Pager, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let pager_ptr = cap.object as *mut crate::cap::pager::Pager;
    let drained = unsafe {
        let pager = &mut *pager_ptr;
        pager.lock.lock();

        let mut mo: *mut crate::cap::memory_object::MemoryObject = pager.attached_mo_head;
        while !mo.is_null() {
            if (*mo).pager_mo_id == mo_id {
                break;
            }
            mo = (*mo).pager_next;
        }
        pager.lock.unlock();

        if mo.is_null() {
            return SyscallResult::err(SyscallError::NotFound);
        }

        let mo_ref = &mut *mo;
        mo_ref.commit_lock.lock();
        let was_attached = mo_ref.pager == pager_ptr && mo_ref.pager_mo_id == mo_id;
        if was_attached {
            mo_ref.pager = core::ptr::null_mut();
            mo_ref.pager_mo_id = 0;
            mo_ref.pager_epoch = 0;
        }
        mo_ref.commit_lock.unlock();

        if was_attached {
            pager.lock.lock();
            pager
                .cancel_epoch
                .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            let mut cursor: *mut *mut crate::cap::memory_object::MemoryObject =
                &mut pager.attached_mo_head;
            while !(*cursor).is_null() {
                if *cursor == mo {
                    *cursor = (*mo).pager_next;
                    (*mo).pager_next = core::ptr::null_mut();
                    break;
                }
                cursor = &mut (**cursor).pager_next;
            }
            let drained = pager.drain_pending_locked(Some(mo_id));
            pager.lock.unlock();
            crate::cap::release_object(
                pager_ptr as *mut crate::cap::object::KernelObject,
                ObjectType::Pager,
            );
            drained
        } else {
            core::ptr::null_mut()
        }
    };
    unsafe {
        crate::cap::pager::wake_and_free_drained_requests(drained);
    }
    SyscallResult::ok(0)
}

pub(super) fn syscall_pager_begin_writeback(
    cap: &Capability,
    mo_id: u64,
    page_idx: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Pager, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let pager_ptr = cap.object as *mut crate::cap::pager::Pager;
    unsafe {
        let pager = &mut *pager_ptr;
        pager.lock.lock();

        let mut mo: *mut crate::cap::memory_object::MemoryObject = pager.attached_mo_head;
        while !mo.is_null() {
            if (*mo).pager_mo_id == mo_id {
                break;
            }
            mo = (*mo).pager_next;
        }
        pager.lock.unlock();

        if mo.is_null() {
            return SyscallResult::err(SyscallError::NotFound);
        }

        let mo_ref = &*mo;
        // Resolve + harvest + begin writeback under the tree lock (the chain
        // walk needs it; there is no user copy here, so holding the lock across
        // the harvest / frame-state update is fine).
        let irq = crate::mm::vspace::save_irq_disable();
        let tl = mo_ref.lock_tree();
        let phys = match mo_ref
            .resolve_page_depth_locked(page_idx as usize)
            .map(|(p, _, _)| p)
        {
            Some(p) => p,
            None => {
                (*tl).unlock();
                crate::mm::vspace::restore_irq(irq);
                return SyscallResult::err(SyscallError::NotFound);
            }
        };
        mo_ref.rmap_harvest_page_dirty(page_idx as usize, phys, true);
        let begin = crate::mm::pmm_begin_file_writeback(phys);
        (*tl).unlock();
        crate::mm::vspace::restore_irq(irq);
        match begin {
            Some(crate::mm::frame::FileWritebackBegin::Started) => {
                let epoch = pager
                    .cancel_epoch
                    .load(core::sync::atomic::Ordering::Acquire);
                SyscallResult::ok(epoch)
            }
            Some(crate::mm::frame::FileWritebackBegin::Clean) => {
                SyscallResult::err(SyscallError::WouldBlock)
            }
            Some(crate::mm::frame::FileWritebackBegin::Busy) => {
                SyscallResult::err(SyscallError::Busy)
            }
            None => SyscallResult::err(SyscallError::InvalidOperation),
        }
    }
}

pub(super) fn syscall_pager_evict_page(
    cap: &Capability,
    mo_id: u64,
    page_idx: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Pager, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let pager_ptr = cap.object as *mut crate::cap::pager::Pager;
    unsafe {
        let pager = &mut *pager_ptr;
        pager.lock.lock();

        let mut mo: *mut crate::cap::memory_object::MemoryObject = pager.attached_mo_head;
        while !mo.is_null() {
            if (*mo).pager_mo_id == mo_id {
                break;
            }
            mo = (*mo).pager_next;
        }
        pager.lock.unlock();

        if mo.is_null() {
            return SyscallResult::err(SyscallError::NotFound);
        }

        // Evict frees a clean page (page-identity mutation); serialise against
        // commit / decommit / resize / fault on this tree.
        let irq = crate::mm::vspace::save_irq_disable();
        let tl = (*mo).lock_tree();
        let result = (*mo).evict_clean_page(page_idx as usize);
        (*tl).unlock();
        crate::mm::vspace::restore_irq(irq);
        match result {
            crate::cap::memory_object::EvictResult::Evicted => SyscallResult::ok(0),
            crate::cap::memory_object::EvictResult::Dirty => SyscallResult::err(SyscallError::Busy),
            crate::cap::memory_object::EvictResult::NotResident => {
                SyscallResult::err(SyscallError::NotFound)
            }
        }
    }
}

pub(super) fn syscall_pager_writeback_done(
    cap: &Capability,
    mo_id: u64,
    page_idx: u64,
    epoch: u64,
    status: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Pager, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let pager_ptr = cap.object as *mut crate::cap::pager::Pager;
    unsafe {
        let pager = &mut *pager_ptr;
        let current_epoch = pager
            .cancel_epoch
            .load(core::sync::atomic::Ordering::Acquire);
        if epoch != current_epoch {
            return SyscallResult::err(SyscallError::Cancelled);
        }

        pager.lock.lock();

        let mut mo: *mut crate::cap::memory_object::MemoryObject = pager.attached_mo_head;
        while !mo.is_null() {
            if (*mo).pager_mo_id == mo_id {
                break;
            }
            mo = (*mo).pager_next;
        }
        pager.lock.unlock();

        if mo.is_null() {
            return SyscallResult::err(SyscallError::NotFound);
        }

        let mo_ref = &*mo;
        // Resolve + harvest + finish writeback under the tree lock.
        let irq = crate::mm::vspace::save_irq_disable();
        let tl = mo_ref.lock_tree();
        let phys = match mo_ref
            .resolve_page_depth_locked(page_idx as usize)
            .map(|(p, _, _)| p)
        {
            Some(p) => p,
            None => {
                (*tl).unlock();
                crate::mm::vspace::restore_irq(irq);
                return SyscallResult::err(SyscallError::NotFound);
            }
        };
        mo_ref.rmap_harvest_page_dirty(page_idx as usize, phys, true);
        let finish = crate::mm::pmm_finish_file_writeback(phys, status == 0);
        (*tl).unlock();
        crate::mm::vspace::restore_irq(irq);
        let Some(new_flags) = finish else {
            return SyscallResult::err(SyscallError::InvalidOperation);
        };
        let dirty_pending = if new_flags & crate::mm::frame::FRAME_FLAG_DIRTY != 0 {
            1
        } else {
            0
        };
        return SyscallResult::ok(dirty_pending);
    }
}
