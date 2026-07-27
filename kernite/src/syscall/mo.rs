// SPDX-License-Identifier: GPL-2.0-only
//! MemoryObject-related syscall handlers.

use super::{
    CapRights, Capability, ObjectType, SyscallError, SyscallResult, current_ipc_buffer_base,
    lookup_typed_cap_locked, validate_capability,
};

pub(super) fn syscall_mo_attach_pager(
    cap: &Capability,
    pager_cap_ptr: u64,
    _flags: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }
    let pager_cap =
        match lookup_typed_cap_locked(pager_cap_ptr, ObjectType::Pager, CapRights::WRITE) {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };

    let mo_ptr = cap.object as *mut crate::cap::memory_object::MemoryObject;
    let pager_ptr = pager_cap.object as *mut crate::cap::pager::Pager;

    unsafe {
        let mo = &mut *mo_ptr;
        // Borrowed-frames MOs are immutable and have no pager source to attach.
        if mo.kind == crate::cap::memory_object::MoKind::BorrowedFrames {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        // Serialise pager attach with the COW bind protocol: take this MO's
        // hierarchy_bind_lock (its standalone domain) and reject an MO already
        // bound into a tree. snapshot / clone / fork take this same lock and
        // read `pager.is_null()` as part of their pristine check, so a pager
        // can never be attached underneath a concurrent bind (or a bind run on
        // a concurrently-pager-attached MO) — they serialise by construction.
        // IRQs off while the bind lock is held, matching the bind protocol.
        let irq = crate::mm::vspace::save_irq_disable();
        mo.hierarchy_bind_lock.lock();
        if !mo
            .hierarchy_state
            .load(core::sync::atomic::Ordering::Acquire)
            .is_null()
        {
            mo.hierarchy_bind_lock.unlock();
            crate::mm::vspace::restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        mo.commit_lock.lock();
        if !mo.pager.is_null() {
            mo.commit_lock.unlock();
            mo.hierarchy_bind_lock.unlock();
            crate::mm::vspace::restore_irq(irq);
            return SyscallResult::err(SyscallError::AlreadyExists);
        }
        let pager = &mut *pager_ptr;
        let mo_id = pager.alloc_mo_id();
        let pager_epoch = pager
            .cancel_epoch
            .load(core::sync::atomic::Ordering::Acquire);

        crate::cap::increment_refcount(pager_ptr as *mut crate::cap::object::KernelObject);
        mo.pager = pager_ptr;
        mo.pager_mo_id = mo_id;
        mo.pager_epoch = pager_epoch;
        mo.commit_lock.unlock();
        mo.hierarchy_bind_lock.unlock();
        crate::mm::vspace::restore_irq(irq);

        pager.attach_mo(mo_ptr);
        SyscallResult::ok(mo_id)
    }
}

/// `mo_populate_borrowed(mo_cap, initrd_device_untyped_cap, device_offset, page_count)`.
///
/// Initialize a pristine MemoryObject (CONFIGURE) as a borrowed-frames view over
/// a contiguous run of the immortal initrd device-untyped (READ). The
/// device-untyped MUST be the initrd — pointer-identity via
/// `initrd_device_limit_for`, not an arbitrary MMIO device-untyped a driver
/// could hold — and the run must be page-aligned and within the initrd's
/// exposed limit. See `MemoryObject::populate_borrowed` for the page-path
/// invariants (frames are never PMM-owned, freed, or evicted).
pub(super) fn syscall_mo_populate_borrowed(
    cap: &Capability,
    device_ut_cap_ptr: u64,
    device_offset: u64,
    page_count: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }
    // Resolve the device-untyped cap (takes CAP_LOCK) before touching the MO.
    let dev_ut =
        match lookup_typed_cap_locked(device_ut_cap_ptr, ObjectType::Untyped, CapRights::READ) {
            Ok(c) => c.object as *mut crate::cap::UntypedMemory,
            Err(e) => return SyscallResult::err(e),
        };
    // Authority boundary: only the immortal initrd may be borrowed.
    let limit = match crate::init::main::initrd_device_limit_for(dev_ut) {
        Some(l) => l,
        None => return SyscallResult::err(SyscallError::InvalidCapability),
    };
    let page = crate::mm::PAGE_SIZE as u64;
    if device_offset & (page - 1) != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if page_count == 0 || page_count > u32::MAX as u64 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    let span = match page_count.checked_mul(page) {
        Some(s) => s,
        None => return SyscallResult::err(SyscallError::OutOfRange),
    };
    let end = match device_offset.checked_add(span) {
        Some(e) => e,
        None => return SyscallResult::err(SyscallError::OutOfRange),
    };
    if end > limit {
        return SyscallResult::err(SyscallError::OutOfRange);
    }
    unsafe {
        let mo_ptr = cap.object as *mut crate::cap::memory_object::MemoryObject;
        let base_phys = (*dev_ut).phys_addr + device_offset;
        let mut alloc = crate::mm::node_alloc::PmmNodeAllocator {
            owner: crate::mm::frame::FrameOwner::MoMeta {
                mo: mo_ptr,
                subkind: crate::mm::frame::MoMetaKind::Radix,
            },
            use_reserve: false,
        };
        match (*mo_ptr).populate_borrowed(base_phys, page_count as usize, &mut alloc) {
            Ok(()) => SyscallResult::ok(0),
            Err(()) => SyscallResult::err(SyscallError::InvalidOperation),
        }
    }
}

pub(super) fn syscall_mo_commit(
    cap: &Capability,
    offset: u64,
    count: u64,
    ut_cap_ptr: u64,
) -> SyscallResult {
    use crate::cap::memory_object::{PHYS_TAG_BUSY, PHYS_TAG_UNTYPED};

    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let mo_ptr = cap.object as *mut crate::cap::memory_object::MemoryObject;
        // Borrowed-frames MOs are immutable: never commit into one.
        if (*mo_ptr).kind == crate::cap::memory_object::MoKind::BorrowedFrames {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let start = offset as usize;
        let cnt = count as usize;

        if start.checked_add(cnt).is_none() || start + cnt > (*mo_ptr).page_count as usize {
            return SyscallResult::err(SyscallError::OutOfRange);
        }

        // Resolve the untyped cap (which takes CAP_LOCK) BEFORE the tree lock —
        // no capability lookup may run under the tree lock.
        let ut: *mut crate::cap::UntypedMemory = if ut_cap_ptr == 0 {
            core::ptr::null_mut()
        } else {
            let ut_cap =
                match lookup_typed_cap_locked(ut_cap_ptr, ObjectType::Untyped, CapRights::READ) {
                    Ok(c) => c,
                    Err(e) => return SyscallResult::err(e),
                };
            let ut = ut_cap.object as *mut crate::cap::UntypedMemory;
            if (*ut).is_device {
                return SyscallResult::err(SyscallError::InvalidCapability);
            }
            ut
        };

        // Guard: pin the MO across the whole syscall. The anonymous/pager path
        // below drops the tree lock per page (`populate_page_blocking`), so
        // without an outer pin a concurrent last-cap drop could free `mo`
        // between pages and `destroy` (which takes the tree lock) would race the
        // next round. (The untyped path holds the tree lock across its loop and
        // is independently safe, but the pin is uniform and harmless there.)
        crate::cap::increment_refcount(mo_ptr as *mut crate::cap::object::KernelObject);

        let result = if ut.is_null() {
            // Anonymous / pager-backed: populate each page through the shared
            // primitive (zero-commit for anon, pager-drive for file-backed).
            // Per-page and non-atomic vs a concurrent snapshot/fork — the
            // canonical model (Zircon `zx_vmo_op_range` commit, Linux
            // `__mm_populate`). Status-only: no count, no rollback.
            let mut err: Option<SyscallError> = None;
            for i in 0..cnt {
                match crate::mm::vspace::populate_page_blocking(mo_ptr, start + i, false) {
                    Ok(()) => {}
                    Err(crate::mm::vspace::CommitErr::Io) => {
                        err = Some(SyscallError::IoError);
                        break;
                    }
                }
            }
            match err {
                Some(e) => SyscallResult::err(e),
                None => SyscallResult::ok(0),
            }
        } else {
            // Untyped carve: classify each page under the tree lock and carve a
            // zeroed untyped block ONLY for a genuinely anonymous-zero page. A
            // page with a real source (pager) must not be zero-carved over —
            // that is the commit footgun in another form. The whole loop runs
            // under one continuous tree-lock hold, so the per-page reserve /
            // carve / commit (and its BUSY marker) is never exposed across a
            // lock drop (a snapshot could otherwise move a BUSY entry).
            let ut = &mut *ut;
            let mut alloc = crate::mm::node_alloc::PmmNodeAllocator {
                owner: crate::mm::frame::FrameOwner::MoMeta {
                    mo: mo_ptr,
                    subkind: crate::mm::frame::MoMetaKind::Radix,
                },
                use_reserve: false,
            };
            let irq = crate::mm::vspace::save_irq_disable();
            let tl = (*mo_ptr).lock_tree();
            let mut err: Option<SyscallError> = None;
            for i in 0..cnt {
                let page_idx = start + i;
                match (*mo_ptr).effective_page_source_locked(page_idx) {
                    // Already resolved (resident anywhere on the chain) — done.
                    crate::cap::memory_object::PageSource::Resident { .. } => continue,
                    // Anonymous-zero — carve a zeroed untyped block and commit.
                    crate::cap::memory_object::PageSource::Zero => {
                        (*mo_ptr).commit_lock.lock();
                        let reserve =
                            (*mo_ptr)
                                .pages
                                .reserve_slot(page_idx, PHYS_TAG_BUSY, &mut alloc);
                        (*mo_ptr).commit_lock.unlock();
                        match reserve {
                            Ok(false) => continue,
                            Err(()) => {
                                err = Some(SyscallError::OutOfMemory);
                                break;
                            }
                            Ok(true) => {}
                        }
                        let phys = match ut.carve_mo_page() {
                            Ok(p) => p,
                            Err(_) => {
                                (*mo_ptr).commit_lock.lock();
                                (*mo_ptr).pages.remove(page_idx);
                                (*mo_ptr).commit_lock.unlock();
                                err = Some(SyscallError::OutOfMemory);
                                break;
                            }
                        };
                        let frame_ptr = crate::mm::phys_to_virt(phys) as *mut u8;
                        core::ptr::write_bytes(frame_ptr, 0, crate::mm::PAGE_SIZE);
                        (*mo_ptr).commit_lock.lock();
                        let ok =
                            (*mo_ptr).commit_page(page_idx, phys | PHYS_TAG_UNTYPED, &mut alloc);
                        (*mo_ptr).commit_lock.unlock();
                        if !ok {
                            ut.release_mo_page_block(phys);
                            err = Some(SyscallError::OutOfMemory);
                            break;
                        }
                        crate::mm::pmm_transfer_with_source(
                            phys,
                            &crate::mm::frame::FrameOwner::UntypedReserved {
                                ut: ut as *const crate::cap::UntypedMemory,
                            },
                            &crate::mm::frame::FrameOwner::MoData {
                                mo: mo_ptr,
                                page_idx: page_idx as u32,
                            },
                            ut as *const crate::cap::UntypedMemory,
                        );
                    }
                    // A real external source — reject untyped-carving over it.
                    crate::cap::memory_object::PageSource::Pager { .. } => {
                        err = Some(SyscallError::InvalidArgument);
                        break;
                    }
                    crate::cap::memory_object::PageSource::Failed => {
                        err = Some(SyscallError::IoError);
                        break;
                    }
                }
            }
            (*tl).unlock();
            crate::mm::vspace::restore_irq(irq);
            match err {
                Some(e) => SyscallResult::err(e),
                None => SyscallResult::ok(0),
            }
        };

        crate::cap::release_object(
            mo_ptr as *mut crate::cap::object::KernelObject,
            crate::cap::ObjectType::MemoryObject,
        );
        result
    }
}

pub(super) fn syscall_mo_decommit(cap: &Capability, offset: u64, count: u64) -> SyscallResult {
    use crate::cap::memory_object::PHYS_TAG_BUSY;

    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let mo = &mut *(cap.object as *mut crate::cap::memory_object::MemoryObject);
        // Borrowed-frames MOs are immutable and never own their frames; a
        // decommit free path would hand an initrd frame to `pmm_free`.
        if mo.kind == crate::cap::memory_object::MoKind::BorrowedFrames {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let start = offset as usize;
        let cnt = count as usize;

        if start.checked_add(cnt).is_none() || start + cnt > mo.page_count as usize {
            return SyscallResult::err(SyscallError::OutOfRange);
        }

        let mo_ptr = cap.object as *mut crate::cap::memory_object::MemoryObject;

        // Decommit frees frames; serialise against snapshot / fault on this
        // tree, and (like MO_RESIZE shrink) reject if any page in the range
        // still has a live mapping — `pmm_free` panics on `map_count != 0`.
        let irq = crate::mm::vspace::save_irq_disable();
        let tl = mo.lock_tree();
        if mo.range_has_live_mapping(start, start + cnt) {
            (*tl).unlock();
            crate::mm::vspace::restore_irq(irq);
            return SyscallResult::err(SyscallError::Busy);
        }

        let mut decommitted = 0u64;
        for i in 0..cnt {
            let page_idx = start + i;

            mo.commit_lock.lock();
            let entry = mo.pages.get(page_idx);
            if entry == 0 || entry & PHYS_TAG_BUSY != 0 {
                mo.commit_lock.unlock();
                continue;
            }
            mo.pages.remove(page_idx);
            mo.commit_lock.unlock();

            crate::cap::memory_object::release_resident_data_page(mo_ptr, page_idx, entry);
            decommitted += 1;
        }

        (*tl).unlock();
        crate::mm::vspace::restore_irq(irq);
        SyscallResult::ok(decommitted)
    }
}

pub(super) fn syscall_mo_get_size(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::READ) {
        return SyscallResult::err(e);
    }
    unsafe {
        let mo = &*(cap.object as *const crate::cap::memory_object::MemoryObject);
        SyscallResult::ok(mo.page_count as u64)
    }
}

pub(super) fn syscall_mo_clone(
    cap: &Capability,
    child_mo_cap_ptr: u64,
    _flags: u64,
    s_cap_ptr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let child_cap =
        match lookup_typed_cap_locked(child_mo_cap_ptr, ObjectType::MemoryObject, CapRights::WRITE)
        {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };
    // `S` is provided only when the parent is standalone (this clone creates the
    // tree); a clone of an already-bound parent reuses its tree state and passes
    // a null slot.
    let s_obj: *mut crate::cap::memory_object::VmHierarchyState = if s_cap_ptr != 0 {
        match lookup_typed_cap_locked(s_cap_ptr, ObjectType::VmHierarchyState, CapRights::WRITE) {
            Ok(c) => c.object as *mut crate::cap::memory_object::VmHierarchyState,
            Err(e) => return SyscallResult::err(e),
        }
    } else {
        core::ptr::null_mut()
    };

    unsafe {
        let parent_ptr = cap.object as *mut crate::cap::memory_object::MemoryObject;
        let child_mo_ptr = child_cap.object as *mut crate::cap::memory_object::MemoryObject;
        if child_mo_ptr.is_null() || child_mo_ptr == parent_ptr {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }
        let child_mo = &*child_mo_ptr;

        let child_refcount = child_mo
            .header
            .ref_count
            .load(core::sync::atomic::Ordering::Acquire);
        let child_is_pristine = child_refcount != 0
            && child_mo.cow_parent.is_null()
            && child_mo.first_child.is_null()
            && child_mo.next_sibling.is_null()
            && child_mo.pages.is_empty()
            && child_mo.rmap_is_all_empty();
        if !child_is_pristine {
            return SyscallResult::err(SyscallError::Busy);
        }

        clone_under_tree_lock(parent_ptr, child_mo_ptr, s_obj, 0, (*parent_ptr).page_count)
    }
}

/// Initialize a pristine `child` MO as a CoW clone of the page window
/// `[offset_pages, offset_pages + child_page_count)` of the parent (`cap`).
/// Unlike `MO_CLONE` (whole-MO 1:1), this clones a sub-range: the child's
/// pages resolve through the parent's pager at the parent-relative offset, so
/// a writable child mapping COW-breaks only the touched pages while the
/// untouched tail stays shared with the file-backed parent. Used by mmsrv to
/// stage a writable data segment over an exec image's file MO.
///
/// arg0 = child MO cap (WRITE), arg1 = offset_pages, arg2 = child_page_count,
/// arg3 = VmHierarchyState cap (WRITE; required only when the parent is
/// standalone, adopt-and-ignored otherwise).
pub(super) fn syscall_mo_clone_range(
    cap: &Capability,
    child_mo_cap_ptr: u64,
    offset_pages: u64,
    child_page_count: u64,
    s_cap_ptr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::READ) {
        return SyscallResult::err(e);
    }
    if child_page_count == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let child_cap =
        match lookup_typed_cap_locked(child_mo_cap_ptr, ObjectType::MemoryObject, CapRights::WRITE)
        {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };
    let s_obj: *mut crate::cap::memory_object::VmHierarchyState = if s_cap_ptr != 0 {
        match lookup_typed_cap_locked(s_cap_ptr, ObjectType::VmHierarchyState, CapRights::WRITE) {
            Ok(c) => c.object as *mut crate::cap::memory_object::VmHierarchyState,
            Err(e) => return SyscallResult::err(e),
        }
    } else {
        core::ptr::null_mut()
    };

    unsafe {
        let parent_ptr = cap.object as *mut crate::cap::memory_object::MemoryObject;
        let child_mo_ptr = child_cap.object as *mut crate::cap::memory_object::MemoryObject;
        if child_mo_ptr.is_null() || child_mo_ptr == parent_ptr {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }
        // The window must lie wholly within the parent MO.
        let parent_pages = (*parent_ptr).page_count as u64;
        match offset_pages.checked_add(child_page_count) {
            Some(end) if end <= parent_pages => {}
            _ => return SyscallResult::err(SyscallError::OutOfRange),
        }

        let child_mo = &*child_mo_ptr;
        let child_refcount = child_mo
            .header
            .ref_count
            .load(core::sync::atomic::Ordering::Acquire);
        let child_is_pristine = child_refcount != 0
            && child_mo.cow_parent.is_null()
            && child_mo.first_child.is_null()
            && child_mo.next_sibling.is_null()
            && child_mo.pages.is_empty()
            && child_mo.rmap_is_all_empty();
        if !child_is_pristine {
            return SyscallResult::err(SyscallError::Busy);
        }

        clone_under_tree_lock(
            parent_ptr,
            child_mo_ptr,
            s_obj,
            offset_pages as u32,
            child_page_count as u32,
        )
    }
}

/// Bind `child` as a CoW child of `parent` covering the page window
/// `[offset_pages, offset_pages + child_page_count)`, creating a fresh tree
/// (using `s_obj`) when `parent` is standalone or adopting `parent`'s existing
/// tree state otherwise. `offset_pages = 0`, `child_page_count =
/// parent.page_count` is the whole-MO 1:1 clone. Mirrors the snapshot bind
/// protocol: bind locks in pointer order → publish `hierarchy_state` + one
/// state ref per newly-bound MO → attach under the tree lock. `s_obj` must be
/// non-null iff `parent` is standalone.
///
/// # Safety
/// `parent` / `child` are live, distinct MOs; `child` is pristine. `s_obj`, if
/// non-null, is a live `VmHierarchyState`. The window lies within the parent
/// (bounds-checked by the caller).
unsafe fn clone_under_tree_lock(
    parent: *mut crate::cap::memory_object::MemoryObject,
    child: *mut crate::cap::memory_object::MemoryObject,
    s_obj: *mut crate::cap::memory_object::VmHierarchyState,
    offset_pages: u32,
    child_page_count: u32,
) -> SyscallResult {
    use core::sync::atomic::Ordering;
    let irq = unsafe { crate::mm::vspace::save_irq_disable() };
    loop {
        let p_state = unsafe { (*parent).hierarchy_state.load(Ordering::Acquire) };
        if p_state.is_null() {
            // First clone of a standalone parent: bind a fresh tree using S.
            if s_obj.is_null() {
                unsafe { crate::mm::vspace::restore_irq(irq) };
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            let mut order = [parent, child];
            order.sort_unstable_by_key(|&m| m as usize);
            for &m in &order {
                unsafe { (*m).hierarchy_bind_lock.lock() };
            }
            // Re-read under the bind locks: if the parent was bound while we
            // waited, restart on the adopt path.
            if !unsafe { (*parent).hierarchy_state.load(Ordering::Acquire) }.is_null() {
                for &m in order.iter().rev() {
                    unsafe { (*m).hierarchy_bind_lock.unlock() };
                }
                continue;
            }
            // Revalidate the child is still pristine under its bind lock — a
            // concurrent binder could have consumed it between the pre-check
            // and taking the locks (the bind protocol must re-check, per plan).
            if !unsafe { mo_is_pristine(child) } {
                for &m in order.iter().rev() {
                    unsafe { (*m).hierarchy_bind_lock.unlock() };
                }
                unsafe { crate::mm::vspace::restore_irq(irq) };
                return SyscallResult::err(SyscallError::Busy);
            }
            unsafe { (*s_obj).lock.lock() };
            // One-shot: a state object can bind exactly one tree.
            if unsafe { (*s_obj).bound.swap(true, Ordering::AcqRel) } {
                unsafe { (*s_obj).lock.unlock() };
                for &m in order.iter().rev() {
                    unsafe { (*m).hierarchy_bind_lock.unlock() };
                }
                unsafe { crate::mm::vspace::restore_irq(irq) };
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            for &m in &[parent, child] {
                unsafe {
                    (*m).hierarchy_state.store(s_obj, Ordering::Release);
                    crate::cap::increment_refcount(s_obj as *mut crate::cap::object::KernelObject);
                }
            }
            unsafe { clone_attach_range_locked(parent, child, offset_pages, child_page_count) };
            unsafe { (*s_obj).lock.unlock() };
            for &m in order.iter().rev() {
                unsafe { (*m).hierarchy_bind_lock.unlock() };
            }
            unsafe { crate::mm::vspace::restore_irq(irq) };
            return SyscallResult::ok(0);
        } else {
            // Clone of an already-bound parent: the child adopts the parent's
            // existing tree state. A non-null `s_obj` is simply unused here (the
            // caller can't cheaply know the parent was already bound) and is
            // reaped by the caller — adopt-and-ignore rather than reject, so the
            // caller can uniformly provision S for every clone.
            unsafe { (*child).hierarchy_bind_lock.lock() };
            unsafe { (*p_state).lock.lock() };
            if unsafe { (*parent).hierarchy_state.load(Ordering::Acquire) } != p_state {
                unsafe { (*p_state).lock.unlock() };
                unsafe { (*child).hierarchy_bind_lock.unlock() };
                continue;
            }
            // Revalidate child pristine under its bind lock before adopting the
            // parent's tree state (per plan: H/C pristine re-check under locks).
            if !unsafe { mo_is_pristine(child) } {
                unsafe { (*p_state).lock.unlock() };
                unsafe { (*child).hierarchy_bind_lock.unlock() };
                unsafe { crate::mm::vspace::restore_irq(irq) };
                return SyscallResult::err(SyscallError::Busy);
            }
            unsafe {
                (*child).hierarchy_state.store(p_state, Ordering::Release);
                crate::cap::increment_refcount(p_state as *mut crate::cap::object::KernelObject);
            }
            unsafe { clone_attach_range_locked(parent, child, offset_pages, child_page_count) };
            unsafe { (*p_state).lock.unlock() };
            unsafe { (*child).hierarchy_bind_lock.unlock() };
            unsafe { crate::mm::vspace::restore_irq(irq) };
            return SyscallResult::ok(0);
        }
    }
}

/// Reset the pristine `child`'s per-MO fields and splice it as a CoW child of
/// `parent` covering `child_page_count` pages starting `offset_pages` into the
/// parent. `offset_pages = 0`, `child_page_count = parent.page_count` is the
/// whole-MO 1:1 clone; any narrower window is a sub-range clone whose pages
/// resolve through the parent's pager at `page_idx + offset_pages`. Runs under
/// the tree lock with `parent` / `child` already bound to the same state by
/// `clone_under_tree_lock`.
///
/// # Safety
/// Caller holds the tree lock; `child` is pristine and bound to `parent`'s tree.
/// `offset_pages + child_page_count <= parent.page_count` (bounds-checked by the
/// caller).
unsafe fn clone_attach_range_locked(
    parent: *mut crate::cap::memory_object::MemoryObject,
    child: *mut crate::cap::memory_object::MemoryObject,
    offset_pages: u32,
    child_page_count: u32,
) {
    let child_mo = unsafe { &mut *child };
    // Reset only the `MemoryObject`-proper fields; the `KernelObject` header,
    // `parent_ut`, `ut_sibling_*`, `obj_type`, and `ref_count` are owned by
    // `cap::retype` / `untyped::add_child` and must survive a clone-into.
    // `commit_lock` / `rmap_lock` were observed quiescent (pristine check), so
    // leaving them untouched does not disturb any unlock-ordering spinner.
    child_mo.kind = crate::cap::memory_object::MoKind::CowChild;
    child_mo.page_count = child_page_count;
    child_mo.pages = crate::mm::radix_tree::RadixTree::empty();
    child_mo.reverse_maps = crate::cap::memory_object::ReverseMaps::new();
    child_mo.first_child = core::ptr::null_mut();
    child_mo.next_sibling = core::ptr::null_mut();
    // Take the keep-alive ref on parent and splice `child` into its child list
    // under `parent.commit_lock`, recording the parent-relative page offset.
    unsafe { child_mo.attach_cow_parent(parent, offset_pages) };
}

/// Is `mo` a pristine, freshly-retyped MO suitable to become a hidden parent
/// or snapshot child — live refcount, no CoW links, no children, empty pages,
/// empty rmap.
///
/// # Safety
/// `mo` must point at a live MemoryObject.
unsafe fn mo_is_pristine(mo: *mut crate::cap::memory_object::MemoryObject) -> bool {
    // Single source of truth: also rejects an already-bound (`hierarchy_state`)
    // or pager-attached MO, which a fresh hidden-parent / child must never be.
    unsafe { (*mo).is_pristine() }
}

/// `MO_SNAPSHOT(cap = source/live MO P; arg0 = hidden parent H; arg1 =
/// snapshot child C; arg2 = per-tree state S)` — realise a Zircon-style strict
/// snapshot of `P`.
///
/// `H`, `C`, and `S` are fresh objects the caller (mmsrv) retyped from untyped
/// — the kernel has no heap and cannot allocate them. The handler binds `P`,
/// `H`, and `C` into one COW tree sharing the per-tree [`VmHierarchyState`]
/// serialization lock, then — holding that lock — moves `P`'s committed pages
/// into `H` (frozen), re-parents both `P` (live) and `C` (snapshot) as CoW
/// children of `H`, and downgrades `P`'s present writable mappings to CoW so
/// concurrent shared writers break against `H` rather than mutating the frozen
/// frames. Holding the tree lock across the whole sequence closes the
/// freeze-window race (F3) by construction: no fault on `P` or `C` can
/// interleave between the page move and the downgrade.
///
/// `S` is supplied only for the **first** snapshot of a standalone `P`; a
/// chained snapshot of an already-bound `P` reuses `P`'s existing tree state
/// and must pass a null `arg2`. `C` reads `H`'s frozen pages and breaks
/// privately on write. `H` is kept alive by the `cow_parent` refs of `P` and
/// `C`; the caller may drop its `H` / `S` caps immediately after this returns.
pub(super) fn syscall_mo_snapshot(
    cap: &Capability,
    h_cap_ptr: u64,
    c_cap_ptr: u64,
    s_cap_ptr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let h_cap = match lookup_typed_cap_locked(h_cap_ptr, ObjectType::MemoryObject, CapRights::WRITE)
    {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    let c_cap = match lookup_typed_cap_locked(c_cap_ptr, ObjectType::MemoryObject, CapRights::WRITE)
    {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    // `S` is provided only for a first snapshot of a standalone source; a
    // chained snapshot of an already-bound source reuses the existing tree
    // state and passes a null slot.
    let s_obj: *mut crate::cap::memory_object::VmHierarchyState = if s_cap_ptr != 0 {
        match lookup_typed_cap_locked(s_cap_ptr, ObjectType::VmHierarchyState, CapRights::WRITE) {
            Ok(c) => c.object as *mut crate::cap::memory_object::VmHierarchyState,
            Err(e) => return SyscallResult::err(e),
        }
    } else {
        core::ptr::null_mut()
    };

    unsafe {
        let p_ptr = cap.object as *mut crate::cap::memory_object::MemoryObject;
        let h_ptr = h_cap.object as *mut crate::cap::memory_object::MemoryObject;
        let c_ptr = c_cap.object as *mut crate::cap::memory_object::MemoryObject;
        if h_ptr.is_null() || c_ptr.is_null() || h_ptr == p_ptr || c_ptr == p_ptr || h_ptr == c_ptr
        {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }
        if !mo_is_pristine(h_ptr) || !mo_is_pristine(c_ptr) {
            return SyscallResult::err(SyscallError::Busy);
        }
        // MO_SNAPSHOT is the strict-snapshot (freeze) *mechanism*. Freezing
        // moves the source's committed pages into a pager-less hidden parent,
        // which would sever a pager-backed object's child from its page
        // supply — so the mechanism is valid only for a non-pager-backed
        // source, and the kernel enforces that precondition here. The
        // freeze-vs-lazy *policy* (shm → snapshot, file → lazy) lives in the
        // caller: lazy private clones of pager-backed objects use MO_CLONE,
        // whose child resolves uncommitted pages via the ancestor's pager.
        if !(*p_ptr).pager.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        snapshot_under_tree_lock(p_ptr, h_ptr, c_ptr, s_obj)
    }
}

/// Bind `p` / `h` / `c` into one COW tree and perform the freeze under that
/// tree's serialization lock, then drop deferred references after the lock is
/// released. `s_obj` is the fresh per-tree state for a standalone `p` (first
/// snapshot) and must be null when `p` is already bound (chained snapshot,
/// which reuses `p`'s existing tree state).
///
/// # Safety
/// `p` / `h` / `c` are live, distinct MOs; `h` / `c` are pristine; `p` is not
/// pager-backed. `s_obj`, if non-null, is a live `VmHierarchyState`.
unsafe fn snapshot_under_tree_lock(
    p: *mut crate::cap::memory_object::MemoryObject,
    h: *mut crate::cap::memory_object::MemoryObject,
    c: *mut crate::cap::memory_object::MemoryObject,
    s_obj: *mut crate::cap::memory_object::VmHierarchyState,
) -> SyscallResult {
    use core::sync::atomic::Ordering;
    // The tree lock and bind locks are spinlocks held across the whole freeze;
    // disable IRQs so a timer preemption cannot deschedule the holder and wedge
    // another CPU spinning on the same lock. TLB shootdowns issued inside are
    // fire-and-forget (no ACK wait), so the long IRQ-off window cannot deadlock.
    let irq = unsafe { crate::mm::vspace::save_irq_disable() };
    loop {
        let p_state = unsafe { (*p).hierarchy_state.load(Ordering::Acquire) };
        if p_state.is_null() {
            // ---- First snapshot: bind a fresh tree using the provided S. ----
            if s_obj.is_null() {
                unsafe { crate::mm::vspace::restore_irq(irq) };
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            let mut order = [p, h, c];
            order.sort_unstable_by_key(|&m| m as usize);
            for &m in &order {
                unsafe { (*m).hierarchy_bind_lock.lock() };
            }
            // Re-read under the bind locks: if P was bound while we waited,
            // restart on the chained path.
            if !unsafe { (*p).hierarchy_state.load(Ordering::Acquire) }.is_null() {
                for &m in order.iter().rev() {
                    unsafe { (*m).hierarchy_bind_lock.unlock() };
                }
                continue;
            }
            // Re-check the source P is still not pager-backed under its bind
            // lock — attach_pager takes this same lock, so this serialises the
            // freeze against a concurrent pager attach on P (freezing a
            // pager-backed source would sever its child from its page supply).
            if !unsafe { (*p).pager.is_null() } {
                for &m in order.iter().rev() {
                    unsafe { (*m).hierarchy_bind_lock.unlock() };
                }
                unsafe { crate::mm::vspace::restore_irq(irq) };
                return SyscallResult::err(SyscallError::InvalidOperation);
            }
            // Revalidate H and C are still pristine under their bind locks
            // before consuming S / publishing (per plan: H/C pristine re-check).
            if !unsafe { mo_is_pristine(h) } || !unsafe { mo_is_pristine(c) } {
                for &m in order.iter().rev() {
                    unsafe { (*m).hierarchy_bind_lock.unlock() };
                }
                unsafe { crate::mm::vspace::restore_irq(irq) };
                return SyscallResult::err(SyscallError::Busy);
            }
            unsafe { (*s_obj).lock.lock() };
            // One-shot: a state object can bind exactly one tree.
            if unsafe { (*s_obj).bound.swap(true, Ordering::AcqRel) } {
                unsafe { (*s_obj).lock.unlock() };
                for &m in order.iter().rev() {
                    unsafe { (*m).hierarchy_bind_lock.unlock() };
                }
                unsafe { crate::mm::vspace::restore_irq(irq) };
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            for &m in &[p, h, c] {
                unsafe {
                    (*m).hierarchy_state.store(s_obj, Ordering::Release);
                    crate::cap::increment_refcount(s_obj as *mut crate::cap::object::KernelObject);
                }
            }
            let deferred_g = unsafe { snapshot_freeze_locked(p, h, c) };
            // Drain the downgrade's recorded CoW shootdowns under S.lock; flush
            // them after the locks drop (the post-unlock sync-shootdown seam).
            let mut rcl_local =
                unsafe { crate::cap::memory_object::VmHierarchyState::drain_rcl(s_obj) };
            unsafe { (*s_obj).lock.unlock() };
            for &m in order.iter().rev() {
                unsafe { (*m).hierarchy_bind_lock.unlock() };
            }
            unsafe { crate::mm::vspace::restore_irq(irq) };
            unsafe { rcl_local.flush() };
            if let Some(g) = deferred_g {
                unsafe {
                    crate::cap::release_object(
                        g as *mut crate::cap::object::KernelObject,
                        ObjectType::MemoryObject,
                    )
                };
            }
            return SyscallResult::ok(0);
        } else {
            // ---- Chained snapshot: reuse P's existing tree state. A non-null
            // `s_obj` is unused here (the caller can't cheaply know P was already
            // bound) and is reaped by the caller — adopt-and-ignore rather than
            // reject, so the caller can uniformly provision S for every snapshot.
            let mut order = [h, c];
            order.sort_unstable_by_key(|&m| m as usize);
            for &m in &order {
                unsafe { (*m).hierarchy_bind_lock.lock() };
            }
            unsafe { (*p_state).lock.lock() };
            // P's state is one-shot, so this should hold; re-validate defensively.
            if unsafe { (*p).hierarchy_state.load(Ordering::Acquire) } != p_state {
                unsafe { (*p_state).lock.unlock() };
                for &m in order.iter().rev() {
                    unsafe { (*m).hierarchy_bind_lock.unlock() };
                }
                continue;
            }
            // Revalidate H and C pristine under their bind locks before
            // publishing into P's existing tree (per plan: H/C pristine re-check).
            if !unsafe { mo_is_pristine(h) } || !unsafe { mo_is_pristine(c) } {
                unsafe { (*p_state).lock.unlock() };
                for &m in order.iter().rev() {
                    unsafe { (*m).hierarchy_bind_lock.unlock() };
                }
                unsafe { crate::mm::vspace::restore_irq(irq) };
                return SyscallResult::err(SyscallError::Busy);
            }
            for &m in &[h, c] {
                unsafe {
                    (*m).hierarchy_state.store(p_state, Ordering::Release);
                    crate::cap::increment_refcount(
                        p_state as *mut crate::cap::object::KernelObject,
                    );
                }
            }
            let deferred_g = unsafe { snapshot_freeze_locked(p, h, c) };
            // Drain the downgrade's recorded CoW shootdowns under the tree lock;
            // flush after the locks drop (the post-unlock sync-shootdown seam).
            let mut rcl_local =
                unsafe { crate::cap::memory_object::VmHierarchyState::drain_rcl(p_state) };
            unsafe { (*p_state).lock.unlock() };
            for &m in order.iter().rev() {
                unsafe { (*m).hierarchy_bind_lock.unlock() };
            }
            unsafe { crate::mm::vspace::restore_irq(irq) };
            unsafe { rcl_local.flush() };
            if let Some(g) = deferred_g {
                unsafe {
                    crate::cap::release_object(
                        g as *mut crate::cap::object::KernelObject,
                        ObjectType::MemoryObject,
                    )
                };
            }
            return SyscallResult::ok(0);
        }
    }
}

/// Perform the freeze (move `p`'s pages into `h`, retag, downgrade `p`, then
/// attach `c`) with the per-tree lock held. Returns the deferred grandparent ref from
/// a chained insert for the caller to drop after releasing the tree lock.
///
/// # Safety
/// Caller holds the per-tree serialization lock and the relevant
/// `hierarchy_bind_lock`s; `p` / `h` / `c` are live and distinct, `h` / `c`
/// pristine.
unsafe fn snapshot_freeze_locked(
    p: *mut crate::cap::memory_object::MemoryObject,
    h: *mut crate::cap::memory_object::MemoryObject,
    c: *mut crate::cap::memory_object::MemoryObject,
) -> Option<*mut crate::cap::memory_object::MemoryObject> {
    let p_page_count = unsafe { (*p).page_count };
    // 1. Move P's local pages into H and re-parent P as a CoW child of H.
    let deferred_g = unsafe { (*p).snapshot_page_move_into(h) };
    // 2. Re-tag the moved frames' PMM owner P -> H. H's pages are frozen after
    //    the snapshot (never written again), so reading them needs no lock.
    unsafe {
        (*h).pages.for_each(|idx, entry| {
            let phys = entry & !crate::cap::memory_object::PHYS_TAG_MASK;
            if phys != 0 && entry & crate::cap::memory_object::PHYS_TAG_BUSY == 0 {
                crate::mm::pmm_set_owner(
                    phys,
                    &crate::mm::frame::FrameOwner::MoData {
                        mo: h,
                        page_idx: idx as u32,
                    },
                );
            }
        });
    }
    // 3. Downgrade P's present writable mappings FIRST. This must precede
    //    attaching C: until P's PTEs are read-only CoW, a concurrent P thread
    //    can write through a still-writable PTE (a hardware store takes no
    //    kernel lock, so the tree lock cannot block it) and mutate a frozen
    //    frame in place. If C is already linked to H, that write leaks into
    //    C's snapshot (F3). Downgrading first means any such write faults and
    //    breaks CoW against H before C ever observes the page.
    unsafe { (*p).downgrade_mappings_to_cow() };
    // 4. Now link the snapshot child C to H (lazy CoW over the frozen pages).
    //    P can no longer mutate those frames in place, so C sees a clean freeze.
    unsafe {
        (*c).page_count = p_page_count;
        (*c).cow_parent_offset = 0;
        (*c).attach_cow_parent(h, 0);
    }
    deferred_g
}

pub(super) fn syscall_mo_resize(cap: &Capability, new_page_count: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let new_pc = new_page_count as usize;
    if new_pc == 0 || new_pc > u32::MAX as usize {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let mo = &mut *(cap.object as *mut crate::cap::memory_object::MemoryObject);
        // Borrowed-frames MOs are immutable; a shrink would free initrd frames.
        if mo.kind == crate::cap::memory_object::MoKind::BorrowedFrames {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let old_pc = mo.page_count as usize;

        if new_pc == old_pc {
            return SyscallResult::ok(0);
        }

        // Resize mutates page_count and (on shrink) frees pages; serialise
        // against snapshot / fault on this tree.
        let irq = crate::mm::vspace::save_irq_disable();
        let tl = mo.lock_tree();

        if new_pc < old_pc {
            use crate::cap::memory_object::PHYS_TAG_BUSY;
            let mo_ptr = cap.object as *mut crate::cap::memory_object::MemoryObject;
            // A shrink must not free a page that still has a live mapping —
            // `pmm_free` panics on a frame whose `map_count != 0`. Reject the
            // truncation as busy so the caller unmaps the tail first and then
            // retries (POSIX `ftruncate`-shrink of a live-mapped region).
            if (*mo_ptr).range_has_live_mapping(new_pc, old_pc) {
                (*tl).unlock();
                crate::mm::vspace::restore_irq(irq);
                return SyscallResult::err(SyscallError::Busy);
            }
            for i in new_pc..old_pc {
                mo.commit_lock.lock();
                let entry = mo.pages.get(i);
                if entry == 0 || entry & PHYS_TAG_BUSY != 0 {
                    mo.commit_lock.unlock();
                    continue;
                }
                mo.pages.remove(i);
                mo.commit_lock.unlock();
                crate::cap::memory_object::release_resident_data_page(mo_ptr, i, entry);
            }
        }

        mo.page_count = new_pc as u32;

        (*tl).unlock();
        crate::mm::vspace::restore_irq(irq);
        SyscallResult::ok(0)
    }
}

pub(super) fn syscall_mo_read(cap: &Capability, offset: u64, count: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let byte_count = count as usize;
    if byte_count == 0 {
        return SyscallResult::ok(0);
    }
    if byte_count > core::mem::size_of::<crate::ipc::IpcBuffer>() {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let mo = &*(cap.object as *const crate::cap::memory_object::MemoryObject);
        let buf_addr = match current_ipc_buffer_base() {
            Ok(addr) => addr,
            Err(err) => return SyscallResult::err(err),
        };

        let mut bytes_read = 0usize;
        let mut src_off = offset as usize;

        while bytes_read < byte_count {
            let page_idx = src_off / crate::mm::PAGE_SIZE;
            let page_off = src_off % crate::mm::PAGE_SIZE;
            let chunk = core::cmp::min(crate::mm::PAGE_SIZE - page_off, byte_count - bytes_read);

            // Resolve + pin the frame under the tree lock, then copy WITHOUT
            // the lock held — copy_to_user can fault and re-enter COW handling,
            // so it must never run under the tree lock. The pin (mapping
            // refcount) keeps the frame alive across the copy against a
            // concurrent decommit / evict.
            let irq = crate::mm::vspace::save_irq_disable();
            let tl = mo.lock_tree();
            let resolved = mo.resolve_page_depth_locked(page_idx).map(|(p, _, _)| p);
            let phys = match resolved {
                Some(p) if p != 0 => {
                    crate::mm::pmm_retain_mapping(p);
                    p
                }
                _ => {
                    (*tl).unlock();
                    crate::mm::vspace::restore_irq(irq);
                    // Absent: make the page resident — a fresh zero-committed
                    // frame for anonymous memory, or a pager-driven page for a
                    // file-backed one — then retry the resolve. Commit-on-read
                    // matches the demand-fault path (which commits on a read
                    // fault); this kernel has no shared zero page.
                    match crate::mm::vspace::populate_page_blocking(
                        cap.object as *mut crate::cap::memory_object::MemoryObject,
                        page_idx,
                        false,
                    ) {
                        Ok(()) => continue,
                        Err(crate::mm::vspace::CommitErr::Io) => {
                            return SyscallResult::err(SyscallError::IoError);
                        }
                    }
                }
            };
            (*tl).unlock();
            crate::mm::vspace::restore_irq(irq);

            let src = (crate::mm::phys_to_virt(phys) as *const u8).add(page_off);
            let ok =
                crate::arch::uaccess::copy_to_user_bytes(buf_addr + bytes_read as u64, src, chunk);
            crate::mm::pmm_release_mapping(phys);
            if !ok {
                return SyscallResult::err(SyscallError::BadAddress);
            }

            bytes_read += chunk;
            src_off += chunk;
        }

        SyscallResult::ok(bytes_read as u64)
    }
}

pub(super) fn syscall_mo_write(cap: &Capability, offset: u64, count: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let byte_count = count as usize;
    if byte_count == 0 {
        return SyscallResult::ok(0);
    }
    if byte_count > core::mem::size_of::<crate::ipc::IpcBuffer>() {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let mo = &mut *(cap.object as *mut crate::cap::memory_object::MemoryObject);
        // Borrowed-frames MOs are immutable: a write would CoW-break the shared
        // initrd image, violating the read-only borrow.
        if mo.kind == crate::cap::memory_object::MoKind::BorrowedFrames {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let ipc_buf = match current_ipc_buffer_base() {
            Ok(addr) => addr,
            Err(err) => return SyscallResult::err(err),
        };

        let mut bytes_written = 0usize;
        let mut dst_off = offset as usize;

        while bytes_written < byte_count {
            let page_idx = dst_off / crate::mm::PAGE_SIZE;
            let page_off = dst_off % crate::mm::PAGE_SIZE;
            let chunk = core::cmp::min(crate::mm::PAGE_SIZE - page_off, byte_count - bytes_written);

            // Break CoW for inherited pages so the write lands on `self`'s own
            // private copy, never the shared / frozen ancestor frame. Break
            // under the tree lock (serialises with downgrade / snapshot on this
            // tree), pin the resulting private frame, then copy WITHOUT the lock
            // held — copy_from_user can fault and re-enter COW handling, which
            // must not run under the tree lock. The pin keeps the frame alive
            // across the copy.
            let irq = crate::mm::vspace::save_irq_disable();
            let tl = mo.lock_tree();
            let cv_state = mo
                .hierarchy_state
                .load(core::sync::atomic::Ordering::Acquire);
            let broke = mo.cow_break_for_write(page_idx);
            // Drain the sibling-convergence shootdowns converge recorded under
            // the tree lock; flush them post-unlock at each exit below (the
            // sync-shootdown seam). Standalone MO (no tree) records nothing.
            let mut rcl_local = if cv_state.is_null() {
                crate::mm::vspace::RangeChangeList::new()
            } else {
                crate::cap::memory_object::VmHierarchyState::drain_rcl(cv_state)
            };
            let phys = match broke {
                Some(p) if p != 0 => {
                    crate::mm::pmm_retain_mapping(p);
                    p
                }
                _ => {
                    (*tl).unlock();
                    crate::mm::vspace::restore_irq(irq);
                    rcl_local.flush();
                    // Absent after the COW break: make the page resident — a
                    // fresh zero-committed private page for anonymous memory, or
                    // a pager-driven page for a file-backed one — then retry the
                    // break + write.
                    match crate::mm::vspace::populate_page_blocking(
                        cap.object as *mut crate::cap::memory_object::MemoryObject,
                        page_idx,
                        true,
                    ) {
                        Ok(()) => continue,
                        Err(crate::mm::vspace::CommitErr::Io) => {
                            return SyscallResult::err(SyscallError::IoError);
                        }
                    }
                }
            };
            (*tl).unlock();
            crate::mm::vspace::restore_irq(irq);
            rcl_local.flush();

            let dst = (crate::mm::phys_to_virt(phys) as *mut u8).add(page_off);
            let ok = crate::arch::uaccess::copy_from_user_bytes(
                ipc_buf + bytes_written as u64,
                dst,
                chunk,
            );
            crate::mm::pmm_release_mapping(phys);
            if !ok {
                return SyscallResult::err(SyscallError::BadAddress);
            }

            bytes_written += chunk;
            dst_off += chunk;
        }

        SyscallResult::ok(bytes_written as u64)
    }
}

pub(super) fn syscall_mo_has_page(cap: &Capability, page_index: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let mo = &*(cap.object as *const crate::cap::memory_object::MemoryObject);
        let index = page_index as usize;
        if index >= mo.page_count as usize {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let irq = crate::mm::vspace::save_irq_disable();
        let tl = mo.lock_tree();
        let present = mo.resolve_page_depth_locked(index).is_some();
        (*tl).unlock();
        crate::mm::vspace::restore_irq(irq);
        SyscallResult::ok(if present { 1 } else { 0 })
    }
}

pub(super) fn syscall_mo_get_map_count(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let mo = &*(cap.object as *const crate::cap::memory_object::MemoryObject);
        SyscallResult::ok(mo.rmap_total() as u64)
    }
}

pub(super) fn syscall_mo_update_page_flags(
    cap: &Capability,
    page_index: u64,
    set_mask: u64,
    clear_mask: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let allowed =
        (crate::mm::frame::FRAME_FLAG_DIRTY | crate::mm::frame::FRAME_FLAG_WRITEBACK) as u64;
    if (set_mask | clear_mask) & !allowed != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let mo = &*(cap.object as *const crate::cap::memory_object::MemoryObject);
        // Borrowed-frames MOs are immutable; their pages carry no dirty/writeback
        // state to update.
        if mo.kind == crate::cap::memory_object::MoKind::BorrowedFrames {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let index = page_index as usize;
        if index >= mo.page_count as usize {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        // Resolve under the tree lock; pmm_update_flags only touches frame
        // metadata (no user copy), so it is safe to run with the lock held.
        let irq = crate::mm::vspace::save_irq_disable();
        let tl = mo.lock_tree();
        let resolved = mo.resolve_page_depth_locked(index).map(|(p, _, _)| p);
        let result = match resolved {
            Some(phys) => {
                match crate::mm::pmm_update_flags(phys, set_mask as u8, clear_mask as u8) {
                    Some(old) => SyscallResult::ok(old as u64),
                    None => SyscallResult::err(SyscallError::InvalidOperation),
                }
            }
            None => SyscallResult::err(SyscallError::NotFound),
        };
        (*tl).unlock();
        crate::mm::vspace::restore_irq(irq);
        result
    }
}
