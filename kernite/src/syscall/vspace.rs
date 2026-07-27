// SPDX-License-Identifier: GPL-2.0-only
//! VSpace-related syscall handlers.

use super::{
    CAP_LOCK, CapRights, Capability, FrameObject, ObjectType, SyscallError, SyscallResult,
    copy_to_current_ipc_words, lookup_cnode_root, lookup_typed_cap_locked, phys_to_virt,
    restore_irq, save_irq_disable, syscall_error_from_vspace_error, validate_capability,
    write_current_ipc_word,
};
use crate::cap::UntypedMemory;
use crate::mm::VSpace;
use crate::mm::vspace::{CowPool, PageFlags};
use core::sync::atomic::Ordering;
const REGION_KIND_NONE: u8 = uapi::KERNITE_REGION_KIND_NONE as u8;
const REGION_KIND_IMAGE_TEXT: u8 = uapi::KERNITE_REGION_KIND_IMAGE_TEXT as u8;
const REGION_KIND_IMAGE_DATA: u8 = uapi::KERNITE_REGION_KIND_IMAGE_DATA as u8;
const REGION_KIND_IMAGE_BSS: u8 = uapi::KERNITE_REGION_KIND_IMAGE_BSS as u8;
const REGION_KIND_HEAP: u8 = uapi::KERNITE_REGION_KIND_HEAP as u8;
const REGION_KIND_STACK: u8 = uapi::KERNITE_REGION_KIND_STACK as u8;
const REGION_KIND_MMAP: u8 = uapi::KERNITE_REGION_KIND_MMAP as u8;
const REGION_KIND_SHARED_LIB: u8 = uapi::KERNITE_REGION_KIND_SHARED_LIB as u8;

#[inline]
fn page_flags_from_bits(flags_bits: u64) -> PageFlags {
    // Decode against the KERNITE_PAGE_FLAG_* bit positions from uapi/vmem.h.
    // KERNITE_PAGE_FLAG_DEMAND is not a permission attribute: MO demand
    // mapping is requested via KERNITE_VSPACE_MAP_MO_FLAG_DEMAND and realized
    // as ENTRY_DEMAND, so it is intentionally not decoded here.
    PageFlags {
        writable: flags_bits & uapi::KERNITE_PAGE_FLAG_WRITABLE != 0,
        user: flags_bits & uapi::KERNITE_PAGE_FLAG_USER != 0,
        executable: flags_bits & uapi::KERNITE_PAGE_FLAG_EXECUTABLE != 0,
        cache_disable: flags_bits & uapi::KERNITE_PAGE_FLAG_NOCACHE != 0,
        write_through: flags_bits & uapi::KERNITE_PAGE_FLAG_WRITETHROUGH != 0,
        cow: flags_bits & uapi::KERNITE_PAGE_FLAG_COW != 0,
    }
}

#[inline]
fn phys_is_direct_mapped_ram(phys: u64) -> bool {
    if let Some(meta) = crate::mm::pmm_lookup(phys) {
        return meta.owner_tag != crate::mm::frame::OwnerTag::Free;
    }

    let ut = crate::init::main::find_untyped_for_phys(phys);
    !ut.is_null() && unsafe { !(*ut).is_device }
}

#[inline]
fn phys_is_mo_data_or_untyped_ram(phys: u64) -> bool {
    match crate::mm::pmm_lookup(phys) {
        Some(meta) => match meta.owner_tag {
            crate::mm::frame::OwnerTag::MoData => true,
            crate::mm::frame::OwnerTag::UntypedReserved => match meta.to_owner() {
                crate::mm::frame::FrameOwner::UntypedReserved { ut } => {
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

pub(super) fn syscall_vspace_map(
    cap: &Capability,
    frame_cap_ptr: u64,
    virt_addr: u64,
    flags_bits: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    let frame_cap = match lookup_typed_cap_locked(frame_cap_ptr, ObjectType::Frame, CapRights::READ)
    {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };

    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // Cap-derived initial-prot gate (mirrors the MAP_MO / device-range checks):
    // a writable mapping requires frame WRITE, an executable mapping requires
    // frame EXECUTE. Since retype mints no EXECUTE, an executable raw map of a
    // process's own frame is refused — executable memory enters only via the
    // exec-conferring path.
    if (flags_bits & 1) != 0 && !frame_cap.has_right(CapRights::WRITE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    if (flags_bits & 4) != 0 && !frame_cap.has_right(CapRights::EXECUTE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }

    unsafe {
        let frame = &*(frame_cap.object as *const FrameObject);
        let frame_phys = frame.phys_addr;
        let frame_obj = frame_cap.object as *mut crate::cap::KernelObject;
        let vspace = &mut *(cap.object as *mut VSpace);
        let flags = page_flags_from_bits(flags_bits);

        // Single-page Frame mapping needs a `VmArea` so the Frame
        // object's lifetime is tied to the live PTE. Without this the
        // child can `cnode_delete(frame_cap)` after `vspace_map` and
        // the reaper will free the backing phys out from under the
        // PTE. Order of ops:
        //   1. Reserve a maple-tree slot.
        //   2. Install the PTE under VSpace.lock.
        //   3. Bump the Frame object's refcount and commit the
        //      reservation (now infallible).
        //   4. Either release the reservation on failure or run the
        //      commit branch.
        // All maple-tree mutations and the PTE write happen under the
        // VSpace lock to match the existing `vspace_map_mo` ordering.
        let mut tree_alloc = crate::mm::node_alloc::PmmNodeAllocator {
            owner: crate::mm::frame::FrameOwner::KernelPrivate {
                subkind: crate::mm::frame::KernelMetaKind::MapleNode,
            },
            use_reserve: false,
        };

        let irq = crate::mm::save_irq_disable();
        vspace.lock.lock();

        let resv = if !vspace.tracking.is_null() {
            let t = &mut *vspace.tracking;
            match t.mappings.reserve_for_insert(&mut tree_alloc) {
                Ok(r) => Some(r),
                Err(_) => {
                    vspace.lock.unlock();
                    crate::mm::restore_irq(irq);
                    return SyscallResult::err(SyscallError::OutOfMemory);
                }
            }
        } else {
            None
        };

        let map_result = vspace.map_locked(virt_addr, frame_phys, flags);
        match map_result {
            Ok(()) => {
                if let Some(mut r) = resv {
                    crate::cap::increment_refcount(frame_obj);
                    let vma = crate::mm::vspace::VmArea {
                        obj: frame_obj,
                        mo_offset: 0,
                        page_count: 1,
                        perms: 0,
                        region_kind: 0,
                        obj_type: crate::cap::ObjectType::Frame as u8,
                        max_prot: max_prot_from_cap(&frame_cap),
                        _pad: [0; 4],
                    };
                    let t = &mut *vspace.tracking;
                    t.mappings.insert_reserved(virt_addr, vma, &mut r);
                    t.note_vma_added(&vma);
                    r.release(&mut tree_alloc);
                }
                vspace.lock.unlock();
                crate::mm::restore_irq(irq);
                SyscallResult::ok(0)
            }
            Err(e) => {
                if let Some(r) = resv {
                    r.release(&mut tree_alloc);
                }
                vspace.lock.unlock();
                crate::mm::restore_irq(irq);
                SyscallResult::err(syscall_error_from_vspace_error(e))
            }
        }
    }
}

pub(super) fn syscall_vspace_unmap(cap: &Capability, virt_addr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    unsafe {
        let current = crate::sched::scheduler::scheduler().current();
        if !current.is_null()
            && !(*current).vspace_root.is_null()
            && core::ptr::eq(
                cap.object as *const VSpace,
                (*current).vspace_root as *const VSpace,
            )
            && virt_addr < 0x0001_0000_0000_0000
        {
            crate::arch::sync_user_page_before_unmap(virt_addr);
        }

        let vspace = &mut *(cap.object as *mut VSpace);
        match vspace.unmap(virt_addr) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

pub(super) fn syscall_vspace_protect(
    cap: &Capability,
    virt_addr: u64,
    flags_bits: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let vspace = &mut *(cap.object as *mut VSpace);
        match vspace.protect(virt_addr, page_flags_from_bits(flags_bits)) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

pub(super) fn syscall_vspace_protect_range(
    cap: &Capability,
    virt_addr: u64,
    count: u64,
    flags_bits: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let vspace = &mut *(cap.object as *mut VSpace);
        match vspace.protect_range(virt_addr, count as usize, page_flags_from_bits(flags_bits)) {
            Ok(protected) => SyscallResult::ok(protected as u64),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

pub(super) fn syscall_vspace_map_demand(
    cap: &Capability,
    virt_addr: u64,
    flags_bits: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let vspace = &mut *(cap.object as *mut VSpace);
        let mut flags = page_flags_from_bits(flags_bits);
        flags.cow = false;
        // Cap-less demand maps are anonymous zero-fill: never executable.
        // Executable demand regions exist only via the MO-backed demand path,
        // bounded by the backing MO cap.
        flags.executable = false;
        match vspace.map_demand(virt_addr, flags) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

pub(super) fn syscall_vspace_map_demand_range(
    cap: &Capability,
    virt_addr: u64,
    count: u64,
    flags_bits: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let vspace = &mut *(cap.object as *mut VSpace);
        let mut flags = page_flags_from_bits(flags_bits);
        flags.cow = false;
        // Cap-less demand maps are anonymous zero-fill: never executable.
        flags.executable = false;
        match vspace.map_demand_range(virt_addr, count as usize, flags) {
            Ok(mapped) => SyscallResult::ok(mapped as u64),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

pub(super) fn syscall_vspace_set_cow_pool(
    cap: &Capability,
    pool_frame_cap_ptr: u64,
    src_cnode_cap_ptr: u64,
    count: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    if count > 510 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let pool_frame_cap =
        match lookup_typed_cap_locked(pool_frame_cap_ptr, ObjectType::Frame, CapRights::READ) {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };

    unsafe {
        let pool_frame = &*(pool_frame_cap.object as *const FrameObject);
        let pool_phys = pool_frame.phys_addr;
        if !phys_is_direct_mapped_ram(pool_phys) {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        let irq = save_irq_disable();
        CAP_LOCK.lock();

        let src_cnode = match lookup_cnode_root(src_cnode_cap_ptr, CapRights::READ) {
            Ok(cnode) => cnode,
            Err(e) => {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(e);
            }
        };
        let src_cnode = &mut *src_cnode;
        let pool = phys_to_virt(pool_phys) as *mut CowPool;

        for i in 0..count as usize {
            let frame_cap = match src_cnode.get(i) {
                Some(c) => c,
                None => {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(SyscallError::InvalidCapability);
                }
            };
            if frame_cap.obj_type != ObjectType::Frame || frame_cap.object.is_null() {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidCapability);
            }
            let frame_obj = &*(frame_cap.object as *const FrameObject);
            let phys = frame_obj.phys_addr;
            if !phys_is_direct_mapped_ram(phys) {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            (*pool).entries[i].phys_addr = phys;

            if src_cnode.revoke(i).is_err() {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidCapability);
            }

            crate::mm::pmm_set_owner(
                phys,
                &crate::mm::frame::FrameOwner::KernelPrivate {
                    subkind: crate::mm::frame::KernelMetaKind::CowPool,
                },
            );
        }

        (*pool).head.store(0, Ordering::Release);
        (*pool).tail.store(count as u16, Ordering::Release);

        CAP_LOCK.unlock();
        restore_irq(irq);

        let vspace = &mut *(cap.object as *mut VSpace);
        vspace.set_cow_pool_phys(pool_phys);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_vspace_replenish_cow_pool(
    cap: &Capability,
    src_cnode_cap_ptr: u64,
    start_slot: u64,
    count: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    if count > 510 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let vspace = &*(cap.object as *const VSpace);
        let pool_phys = vspace.cow_pool_phys_locked();
        if pool_phys == 0 {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        if !phys_is_direct_mapped_ram(pool_phys) {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        let irq = save_irq_disable();
        CAP_LOCK.lock();

        let src_cnode = match lookup_cnode_root(src_cnode_cap_ptr, CapRights::READ) {
            Ok(cnode) => cnode,
            Err(e) => {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(e);
            }
        };
        let src_cnode = &mut *src_cnode;
        let pool = phys_to_virt(pool_phys) as *mut CowPool;
        let current_tail = (*pool).tail.load(Ordering::Acquire);
        let current_head = (*pool).head.load(Ordering::Acquire);
        let used = current_tail.wrapping_sub(current_head) as u64;
        let available = 509u64.saturating_sub(used);
        if count > available {
            CAP_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        for i in 0..count as usize {
            let slot_idx = start_slot as usize + i;
            let frame_cap = match src_cnode.get(slot_idx) {
                Some(c) => c,
                None => {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(SyscallError::InvalidCapability);
                }
            };
            if frame_cap.obj_type != ObjectType::Frame || frame_cap.object.is_null() {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidCapability);
            }
            let frame_obj = &*(frame_cap.object as *const FrameObject);
            let phys = frame_obj.phys_addr;
            if !phys_is_direct_mapped_ram(phys) {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            let pool_idx = (current_tail.wrapping_add(i as u16) % 510) as usize;
            (*pool).entries[pool_idx].phys_addr = phys;

            if src_cnode.revoke(slot_idx).is_err() {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidCapability);
            }
            crate::mm::pmm_set_owner(
                phys,
                &crate::mm::frame::FrameOwner::KernelPrivate {
                    subkind: crate::mm::frame::KernelMetaKind::CowPool,
                },
            );
        }

        (*pool)
            .tail
            .store(current_tail.wrapping_add(count as u16), Ordering::Release);

        CAP_LOCK.unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_vspace_map_pt(
    cap: &Capability,
    frame_cap_ptr: u64,
    virt_addr: u64,
    level: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    if !(1..=3).contains(&level) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // A page table must be a typed PageTable object, never a Frame: a Frame can
    // also be data-mapped via VSPACE_MAP, which would let userland write forged
    // PTEs into a live table. Typing makes that alias impossible by construction.
    let pt_cap =
        match lookup_typed_cap_locked(frame_cap_ptr, ObjectType::PageTable, CapRights::READ) {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };

    unsafe {
        let pt = &*(pt_cap.object as *const crate::cap::PageTableObject);
        let pt_obj = pt_cap.object as *mut crate::cap::KernelObject;
        let vspace = &mut *(cap.object as *mut VSpace);
        match vspace.install_page_table(virt_addr, pt.phys_addr, level as usize, pt_obj) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

pub(super) fn syscall_vspace_walk(
    cap: &Capability,
    start_vaddr: u64,
    max_entries: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        const EXT_ENTRY_BASE_WORD: usize = 42;
        const WALK_MAGIC: u64 = 0x5357_4c4b_434f_4d50;

        let vspace = &*(cap.object as *const VSpace);
        let ipc_words_total =
            core::mem::size_of::<crate::ipc::IpcBuffer>() / core::mem::size_of::<u64>();
        let ext_capacity = (ipc_words_total - EXT_ENTRY_BASE_WORD) / 3;
        let requested = if max_entries > usize::MAX as u64 {
            usize::MAX
        } else {
            max_entries as usize
        };
        let max = core::cmp::min(requested, ext_capacity);
        let (count, next_vaddr, entries) = vspace.walk_pages(start_vaddr, max);

        if let Err(err) = write_current_ipc_word(0, count as u64) {
            return SyscallResult::err(err);
        }
        if let Err(err) = write_current_ipc_word(1, next_vaddr) {
            return SyscallResult::err(err);
        }
        if let Err(err) = write_current_ipc_word(ipc_words_total - 1, WALK_MAGIC) {
            return SyscallResult::err(err);
        }
        for i in 0..count {
            let out = EXT_ENTRY_BASE_WORD + i * 3;
            if let Err(err) =
                copy_to_current_ipc_words(out, &[entries[i].0, entries[i].1, entries[i].2])
            {
                return SyscallResult::err(err);
            }
        }
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_vspace_resolve_page(cap: &Capability, vaddr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let vspace = &*(cap.object as *const VSpace);
        match vspace.resolve_page(vaddr) {
            Some(page_phys) => SyscallResult::ok(page_phys + (vaddr & 0xFFF)),
            None => SyscallResult::err(SyscallError::NotFound),
        }
    }
}

pub(super) fn syscall_vspace_copy_page(
    cap: &Capability,
    src_vaddr: u64,
    dst_frame_cap_ptr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }
    if src_vaddr & 0xFFF != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let frame_cap =
        match lookup_typed_cap_locked(dst_frame_cap_ptr, ObjectType::Frame, CapRights::WRITE) {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };

    unsafe {
        let vspace = &*(cap.object as *const VSpace);
        let frame = &*(frame_cap.object as *const FrameObject);
        let src_phys = match vspace.resolve_page(src_vaddr) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::NotFound),
        };
        if !phys_is_direct_mapped_ram(src_phys) {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }
        if !phys_is_direct_mapped_ram(frame.phys_addr) {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        let src_ptr = crate::mm::phys_to_virt(src_phys) as *const u8;
        let dst_ptr = crate::mm::phys_to_virt(frame.phys_addr) as *mut u8;
        core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, crate::mm::PAGE_SIZE);
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_vspace_share_ro_page(
    cap: &Capability,
    src_vaddr: u64,
    dst_vspace_cap_ptr: u64,
    dst_vaddr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }
    if src_vaddr & 0xFFF != 0 || dst_vaddr & 0xFFF != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let dst_cap =
        match lookup_typed_cap_locked(dst_vspace_cap_ptr, ObjectType::VSpace, CapRights::MAP) {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };

    unsafe {
        let src_vs = &mut *(cap.object as *mut VSpace);
        let dst_vs = &mut *(dst_cap.object as *mut VSpace);
        match src_vs.share_ro_page_to(src_vaddr, dst_vs, dst_vaddr) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

pub(super) fn syscall_vspace_map_device(
    cap: &Capability,
    device_untyped_cap_ptr: u64,
    page_offset: u64,
    virt_addr: u64,
    flags_bits: u64,
) -> SyscallResult {
    let result = syscall_vspace_map_device_range(
        cap,
        device_untyped_cap_ptr,
        page_offset,
        virt_addr,
        (1u64 << 32) | (flags_bits & 0xFFFF_FFFF),
    );
    if result.error == 0 {
        if result.value == 1 {
            SyscallResult::ok(0)
        } else {
            SyscallResult::err(SyscallError::InvalidArgument)
        }
    } else {
        result
    }
}

pub(super) fn syscall_vspace_map_device_range(
    cap: &Capability,
    device_untyped_cap_ptr: u64,
    offset_start: u64,
    vaddr_start: u64,
    count_and_flags: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    let count = (count_and_flags >> 32) as u64;
    let flags_bits = count_and_flags & 0xFFFF_FFFF;

    if count == 0 {
        return SyscallResult::ok(0);
    }
    if count > 8192 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if offset_start & 0xFFF != 0 || vaddr_start & 0xFFF != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let dev_cap =
        match lookup_typed_cap_locked(device_untyped_cap_ptr, ObjectType::Untyped, CapRights::READ)
        {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };
    if (flags_bits & 1) != 0 && !dev_cap.has_right(CapRights::WRITE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    if (flags_bits & 4) != 0 && !dev_cap.has_right(CapRights::EXECUTE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let dev_ut = &*(dev_cap.object as *const UntypedMemory);
        if !dev_ut.is_device {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let map_limit = crate::init::main::initrd_device_limit_for(dev_ut as *const UntypedMemory)
            .or_else(|| crate::init::main::fb_device_limit_for(dev_ut as *const UntypedMemory))
            .unwrap_or(dev_ut.size_bytes() as u64);

        let total_bytes = match count.checked_mul(0x1000) {
            Some(v) => v,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        let end_offset = match offset_start.checked_add(total_bytes) {
            Some(v) => v,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        if end_offset > map_limit {
            return SyscallResult::err(SyscallError::OutOfRange);
        }

        let base_phys = dev_ut.phys_addr;
        let phys_start = match base_phys.checked_add(offset_start) {
            Some(v) => v,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        let offset_pages = offset_start / crate::mm::PAGE_SIZE as u64;
        if offset_pages > u32::MAX as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let offset_pages = offset_pages as u32;

        let vspace = &mut *(cap.object as *mut VSpace);
        let dev_obj = dev_cap.object;
        let mut tree_alloc = map_mo_tree_allocator();

        let irq = save_irq_disable();
        vspace.lock.lock();

        let meta_resv = if !vspace.tracking.is_null() {
            if vspace_map_mo_has_conflicting_metadata(vspace, vaddr_start, count as u32) {
                vspace.lock.unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidArgument);
            }

            let tracking = &mut *vspace.tracking;
            match tracking.mappings.reserve_for_insert(&mut tree_alloc) {
                Ok(r) => Some(r),
                Err(_) => {
                    vspace.lock.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(SyscallError::OutOfMemory);
                }
            }
        } else {
            None
        };

        let mapped_result = vspace.map_range_partial_locked(
            vaddr_start,
            phys_start,
            count as usize,
            page_flags_from_bits(flags_bits),
        );

        let result = match mapped_result {
            Ok(mapped) => {
                if let Some(mut r) = meta_resv {
                    if mapped > 0 {
                        let vma = crate::mm::vspace::VmArea {
                            obj: dev_obj,
                            mo_offset: offset_pages,
                            page_count: mapped as u32,
                            perms: vspace_map_mo_perms(flags_bits),
                            region_kind: REGION_KIND_MMAP,
                            obj_type: crate::cap::ObjectType::Untyped as u8,
                            max_prot: max_prot_from_cap(&dev_cap),
                            _pad: [0; 4],
                        };
                        crate::cap::increment_refcount(dev_obj);
                        let tracking = &mut *vspace.tracking;
                        tracking.mappings.insert_reserved(vaddr_start, vma, &mut r);
                        tracking.note_vma_added(&vma);
                    }
                    r.release(&mut tree_alloc);
                }
                SyscallResult::ok(mapped as u64)
            }
            Err(e) => {
                if let Some(r) = meta_resv {
                    r.release(&mut tree_alloc);
                }
                SyscallResult::err(syscall_error_from_vspace_error(e))
            }
        };

        vspace.lock.unlock();
        restore_irq(irq);
        result
    }
}

pub(super) fn syscall_vspace_get_mem_stats(cap: &Capability, out_ptr: u64) -> SyscallResult {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Out {
        vm_reserved_bytes: u64,
        vm_resident_pages: u64,
        vm_demand_pages: u64,
        vm_cow_pages: u64,
        vm_shared_pages: u64,
        vm_pt_pages: u64,
        vm_kstack_pages: u64,
        resident_anon: u64,
        resident_file: u64,
        resident_shm: u64,
        vm_stk_bytes: u64,
        vm_exe_bytes: u64,
        vm_data_bytes: u64,
        vm_lib_bytes: u64,
        vm_peak_reserved_bytes: u64,
        vm_peak_resident_pages: u64,
    }

    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }
    if out_ptr == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let vspace = unsafe { &*(cap.object as *const crate::mm::VSpace) };
    let tracking = vspace.tracking;
    if tracking.is_null() {
        return SyscallResult::err(SyscallError::InvalidOperation);
    }
    let t = unsafe { &*tracking };

    let mut vm_stk_bytes: u64 = 0;
    let mut vm_exe_bytes: u64 = 0;
    let mut vm_data_bytes: u64 = 0;
    let mut vm_lib_bytes: u64 = 0;
    let mut vm_shared_pages: u64 = 0;
    {
        let irq = unsafe { save_irq_disable() };
        vspace.lock.lock();
        t.mappings.for_each(&mut |start, vma| {
            let bytes = vma.page_count as u64 * 4096;
            match vma.region_kind {
                v if v == REGION_KIND_STACK => vm_stk_bytes += bytes,
                v if v == REGION_KIND_IMAGE_TEXT => vm_exe_bytes += bytes,
                v if v == REGION_KIND_SHARED_LIB => vm_lib_bytes += bytes,
                v if v == REGION_KIND_NONE
                    || v == REGION_KIND_HEAP
                    || v == REGION_KIND_MMAP
                    || v == REGION_KIND_IMAGE_DATA
                    || v == REGION_KIND_IMAGE_BSS =>
                {
                    vm_data_bytes += bytes
                }
                _ => {}
            }
            vm_shared_pages += vspace
                .range_mem_stats(start, vma.page_count as usize)
                .shared_pages;
        });
        vspace.lock.unlock();
        unsafe { restore_irq(irq) };
    }

    let out = Out {
        vm_reserved_bytes: t.vm_reserved_bytes.load(Ordering::Relaxed),
        vm_resident_pages: t.vm_resident_pages.load(Ordering::Relaxed),
        vm_demand_pages: t.vm_demand_pages.load(Ordering::Relaxed),
        vm_cow_pages: t.vm_cow_pages.load(Ordering::Relaxed),
        vm_shared_pages,
        vm_pt_pages: t.vm_pt_pages.load(Ordering::Relaxed),
        vm_kstack_pages: t.vm_kstack_pages.load(Ordering::Relaxed),
        resident_anon: t.resident_anon.load(Ordering::Relaxed),
        resident_file: t.resident_file.load(Ordering::Relaxed),
        resident_shm: t.resident_shm.load(Ordering::Relaxed),
        vm_stk_bytes,
        vm_exe_bytes,
        vm_data_bytes,
        vm_lib_bytes,
        vm_peak_reserved_bytes: t.vm_peak_reserved_bytes.load(Ordering::Relaxed),
        vm_peak_resident_pages: t.vm_peak_resident_pages.load(Ordering::Relaxed),
    };

    unsafe {
        if !crate::arch::uaccess::copy_to_user(out_ptr, &out) {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }
    }

    SyscallResult::ok(0)
}

pub(super) fn syscall_vspace_get_trace_id(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let vspace = unsafe { &*(cap.object as *const crate::mm::VSpace) };
    SyscallResult::ok(vspace.trace_id())
}

pub(super) fn syscall_vspace_get_range_stats(
    cap: &Capability,
    start_vaddr: u64,
    page_count: u64,
    out_ptr: u64,
) -> SyscallResult {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Out {
        present_pages: u64,
        referenced_pages: u64,
        shared_pages: u64,
        shared_dirty_pages: u64,
        private_dirty_pages: u64,
        writeback_pages: u64,
        pss_bytes: u64,
    }

    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }
    if out_ptr == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let vspace = unsafe { &*(cap.object as *const crate::mm::VSpace) };
    let pages = if page_count > usize::MAX as u64 {
        usize::MAX
    } else {
        page_count as usize
    };
    let stats = vspace.range_mem_stats(start_vaddr, pages);
    let out = Out {
        present_pages: stats.present_pages,
        referenced_pages: stats.referenced_pages,
        shared_pages: stats.shared_pages,
        shared_dirty_pages: stats.shared_dirty_pages,
        private_dirty_pages: stats.private_dirty_pages,
        writeback_pages: stats.writeback_pages,
        pss_bytes: stats.pss_bytes,
    };

    unsafe {
        if !crate::arch::uaccess::copy_to_user(out_ptr, &out) {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }
    }

    SyscallResult::ok(0)
}

const VSPACE_MAP_MO_FLAG_DEMAND: u64 = uapi::KERNITE_VSPACE_MAP_MO_FLAG_DEMAND as u64;
const VSPACE_MAP_MO_REGION_KIND_SHIFT: u64 = 24;
const VSPACE_MAP_MO_REGION_KIND_MASK: u64 = 0xFF << VSPACE_MAP_MO_REGION_KIND_SHIFT;

#[inline]
fn vspace_map_mo_mapping_flags(flags_bits: u64) -> u64 {
    flags_bits & !VSPACE_MAP_MO_FLAG_DEMAND
}

#[inline]
fn vspace_map_mo_perms(flags_bits: u64) -> u8 {
    (vspace_map_mo_mapping_flags(flags_bits) & 0xFF) as u8
}

/// Map a mapping-perms byte (bit0 = writable, bit2 = executable — the
/// `vspace_map_mo_mapping_flags` encoding) to a `VmArea::max_prot`
/// ceiling. Used for fork-child / split regions whose protection ceiling
/// tracks the region's own perms.
#[inline]
fn perms_to_max_prot(perms: u8) -> u8 {
    let mut m = 0u8;
    if perms & 1 != 0 {
        m |= crate::mm::vspace::VmArea::MAX_PROT_WRITE;
    }
    if perms & 4 != 0 {
        m |= crate::mm::vspace::VmArea::MAX_PROT_EXEC;
    }
    m
}

/// Derive a `VmArea::max_prot` ceiling from a backing cap's rights: a
/// region may be raised (via `protect` / `mprotect`) to WRITE only if the
/// cap carries WRITE, and to EXECUTE only if it carries EXECUTE. READ is
/// always implied.
#[inline]
fn max_prot_from_cap(cap: &crate::cap::Capability) -> u8 {
    let mut m = 0u8;
    if cap.has_right(CapRights::WRITE) {
        m |= crate::mm::vspace::VmArea::MAX_PROT_WRITE;
    }
    if cap.has_right(CapRights::EXECUTE) {
        m |= crate::mm::vspace::VmArea::MAX_PROT_EXEC;
    }
    m
}

#[inline]
fn vspace_map_mo_region_kind(flags_bits: u64) -> u8 {
    ((flags_bits & VSPACE_MAP_MO_REGION_KIND_MASK) >> VSPACE_MAP_MO_REGION_KIND_SHIFT) as u8
}

unsafe fn vspace_map_mo_has_covering_metadata(
    vspace: &VSpace,
    vaddr: u64,
    mapped_pages: u32,
    mo_ptr: *mut crate::cap::memory_object::MemoryObject,
    mo_offset: u32,
    perms: u8,
    region_kind: u8,
) -> bool {
    if mapped_pages == 0 || vspace.tracking.is_null() {
        return false;
    }

    let tracking = unsafe { &*vspace.tracking };
    let Some((start, existing)) = tracking.mappings.lookup(vaddr) else {
        return false;
    };
    if existing.mo() != mo_ptr || existing.perms != perms || existing.region_kind != region_kind {
        return false;
    }

    let delta_pages = match u32::try_from((vaddr - start) / crate::mm::PAGE_SIZE as u64) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if existing.mo_offset.checked_add(delta_pages) != Some(mo_offset) {
        return false;
    }

    let span_bytes = match (mapped_pages as u64).checked_mul(crate::mm::PAGE_SIZE as u64) {
        Some(v) => v,
        None => return false,
    };
    let end = match vaddr.checked_add(span_bytes) {
        Some(v) => v,
        None => return false,
    };
    let existing_span = match (existing.page_count as u64).checked_mul(crate::mm::PAGE_SIZE as u64)
    {
        Some(v) => v,
        None => return false,
    };
    let existing_end = match start.checked_add(existing_span) {
        Some(v) => v,
        None => return false,
    };

    end <= existing_end
}

unsafe fn vspace_map_mo_has_conflicting_metadata(
    vspace: &VSpace,
    vaddr: u64,
    mapped_pages: u32,
) -> bool {
    if mapped_pages == 0 || vspace.tracking.is_null() {
        return false;
    }
    let tracking = unsafe { &*vspace.tracking };
    let page_size = crate::mm::PAGE_SIZE as u64;
    let span = (mapped_pages as u64).saturating_mul(page_size);
    let end = match vaddr.checked_add(span) {
        Some(v) => v,
        None => return true,
    };

    if let Some((start, vma)) = tracking.mappings.lookup(vaddr) {
        let vma_span = (vma.page_count as u64).saturating_mul(page_size);
        if let Some(vma_end) = start.checked_add(vma_span) {
            if vma_end > vaddr {
                return true;
            }
        } else {
            return true;
        }
    }

    if tracking.mappings.first_in_range(vaddr, end).is_some() {
        return true;
    }

    false
}

enum MapMoMetaReservation {
    Covered,
    Pending {
        tree_resv: Option<crate::mm::maple_tree::InsertReservation>,
        ticket: crate::cap::memory_object::RevMapTicket,
    },
}

impl MapMoMetaReservation {
    #[inline]
    fn is_covered(&self) -> bool {
        matches!(self, MapMoMetaReservation::Covered)
    }
}

fn map_mo_tree_allocator() -> crate::mm::node_alloc::PmmNodeAllocator {
    crate::mm::node_alloc::PmmNodeAllocator {
        owner: crate::mm::frame::FrameOwner::KernelPrivate {
            subkind: crate::mm::frame::KernelMetaKind::MapleNode,
        },
        use_reserve: false,
    }
}

unsafe fn reserve_vspace_map_mo_metadata_locked(
    vspace: &mut VSpace,
    mo_ptr: *mut crate::cap::memory_object::MemoryObject,
    vaddr: u64,
    requested_pages: u32,
    mo_offset: u32,
    perms: u8,
    region_kind: u8,
) -> Result<MapMoMetaReservation, SyscallError> {
    if requested_pages == 0 {
        return Ok(MapMoMetaReservation::Covered);
    }

    if !vspace.tracking.is_null()
        && unsafe {
            vspace_map_mo_has_covering_metadata(
                vspace,
                vaddr,
                requested_pages,
                mo_ptr,
                mo_offset,
                perms,
                region_kind,
            )
        }
    {
        return Ok(MapMoMetaReservation::Covered);
    }

    if !vspace.tracking.is_null()
        && unsafe { vspace_map_mo_has_conflicting_metadata(vspace, vaddr, requested_pages) }
    {
        return Err(SyscallError::InvalidArgument);
    }

    if vspace.tracking.is_null() {
        let ticket = match unsafe { (*mo_ptr).rmap_reserve_slot() } {
            Ok(t) => t,
            Err(_) => return Err(SyscallError::OutOfMemory),
        };
        return Ok(MapMoMetaReservation::Pending {
            tree_resv: None,
            ticket,
        });
    }

    let tracking = unsafe { &mut *vspace.tracking };
    let mut tree_alloc = map_mo_tree_allocator();
    let tree_resv = match tracking.mappings.reserve_for_insert(&mut tree_alloc) {
        Ok(r) => r,
        Err(_) => return Err(SyscallError::OutOfMemory),
    };
    let ticket = match unsafe { (*mo_ptr).rmap_reserve_slot() } {
        Ok(t) => t,
        Err(_) => {
            tree_resv.release(&mut tree_alloc);
            return Err(SyscallError::OutOfMemory);
        }
    };
    Ok(MapMoMetaReservation::Pending {
        tree_resv: Some(tree_resv),
        ticket,
    })
}

/// Thin wrapper that derives the region's `max_prot` ceiling from its own
/// perms. Used by fork-range error/cleanup paths (which pass
/// `mapped_pages = 0`, so no VmArea is built and the ceiling is unused)
/// and any caller whose ceiling equals its perms. Callers needing a
/// cap-derived ceiling (the map-MO syscall, which may map fewer perms
/// than the cap allows so `mprotect` can later raise up to the cap's
/// rights) call `..._max_prot_locked` directly.
unsafe fn commit_or_release_vspace_map_mo_metadata_locked(
    resv: MapMoMetaReservation,
    vspace: &mut VSpace,
    mo_ptr: *mut crate::cap::memory_object::MemoryObject,
    vaddr: u64,
    mapped_pages: u32,
    mo_offset: u32,
    perms: u8,
    region_kind: u8,
) {
    unsafe {
        commit_or_release_vspace_map_mo_metadata_max_prot_locked(
            resv,
            vspace,
            mo_ptr,
            vaddr,
            mapped_pages,
            mo_offset,
            perms,
            region_kind,
            perms_to_max_prot(perms),
        )
    }
}

unsafe fn commit_or_release_vspace_map_mo_metadata_max_prot_locked(
    resv: MapMoMetaReservation,
    vspace: &mut VSpace,
    mo_ptr: *mut crate::cap::memory_object::MemoryObject,
    vaddr: u64,
    mapped_pages: u32,
    mo_offset: u32,
    perms: u8,
    region_kind: u8,
    max_prot: u8,
) {
    match resv {
        MapMoMetaReservation::Covered => {}
        MapMoMetaReservation::Pending { tree_resv, ticket } => {
            if mapped_pages == 0 {
                unsafe { (*mo_ptr).rmap_release_ticket(ticket) };
                if let Some(r) = tree_resv {
                    let mut tree_alloc = map_mo_tree_allocator();
                    r.release(&mut tree_alloc);
                }
                return;
            }

            let vma = crate::mm::vspace::VmArea {
                obj: mo_ptr as *mut crate::cap::KernelObject,
                mo_offset,
                page_count: mapped_pages,
                perms,
                region_kind,
                obj_type: crate::cap::ObjectType::MemoryObject as u8,
                max_prot,
                _pad: [0; 4],
            };

            unsafe {
                (*mo_ptr).rmap_add_reserved(
                    ticket,
                    crate::cap::memory_object::ReverseMapEntry {
                        vspace: vspace as *mut VSpace,
                        va_start: vaddr,
                        page_count: mapped_pages,
                        mo_offset,
                        perms,
                        _pad: [0; 7],
                    },
                );
            }

            if let Some(mut r) = tree_resv {
                let tracking = unsafe { &mut *vspace.tracking };
                unsafe { tracking.mappings.insert_reserved(vaddr, vma, &mut r) };
                let mut tree_alloc = map_mo_tree_allocator();
                r.release(&mut tree_alloc);
                tracking.note_vma_added(&vma);
            }
            unsafe { vma.retain_obj_ref() };
        }
    }
}

/// Plan for the parent VmArea swap performed at the end of a successful
/// forward fork. Distinguishes between the four ways the chunk's range
/// can sit inside the existing parent VmArea:
///   * `Exact`         — V == chunk; full owner swap.
///   * `LeftAligned`   — V.start == chunk.start, V.end >  chunk.end;
///                       split into V_chunk + V_right.
///   * `RightAligned`  — V.start <  chunk.start, V.end == chunk.end;
///                       split into V_left + V_chunk.
///   * `StrictInterior`— V.start <  chunk.start, V.end >  chunk.end;
///                       split into V_left + V_chunk + V_right.
enum ParentSwapPlan {
    None,
    Exact {
        ticket: crate::cap::memory_object::RevMapTicket,
        old_mo: *mut crate::cap::memory_object::MemoryObject,
        vma_start: u64,
        base_vma: crate::mm::vspace::VmArea,
    },
    LeftAligned {
        ps_ticket: crate::cap::memory_object::RevMapTicket,
        old_ticket: crate::cap::memory_object::RevMapTicket,
        old_mo: *mut crate::cap::memory_object::MemoryObject,
        vma_start: u64,
        base_vma: crate::mm::vspace::VmArea,
        v_right_start: u64,
        v_right_pages: u32,
        v_right_mo_offset: u32,
        tree_resv: crate::mm::maple_tree::InsertReservation,
    },
    RightAligned {
        ps_ticket: crate::cap::memory_object::RevMapTicket,
        old_ticket: crate::cap::memory_object::RevMapTicket,
        old_mo: *mut crate::cap::memory_object::MemoryObject,
        vma_start: u64,
        base_vma: crate::mm::vspace::VmArea,
        v_left_pages: u32,
        chunk_va: u64,
        chunk_mo_offset: u32,
        tree_resv: crate::mm::maple_tree::InsertReservation,
    },
    StrictInterior {
        ps_ticket: crate::cap::memory_object::RevMapTicket,
        old_ticket_left: crate::cap::memory_object::RevMapTicket,
        old_ticket_right: crate::cap::memory_object::RevMapTicket,
        old_mo: *mut crate::cap::memory_object::MemoryObject,
        vma_start: u64,
        base_vma: crate::mm::vspace::VmArea,
        v_left_pages: u32,
        chunk_va: u64,
        chunk_mo_offset: u32,
        v_right_start: u64,
        v_right_pages: u32,
        v_right_mo_offset: u32,
        tree_resv_left: crate::mm::maple_tree::InsertReservation,
        tree_resv_right: crate::mm::maple_tree::InsertReservation,
    },
}

/// Drop a fork's source-tree bind: the tree / `S` lock first, then the
/// `hierarchy_bind_lock`s in reverse acquisition order. No-op when `state` is
/// null and `locked` is empty (fork with no source MO to bind).
///
/// # Safety
/// `state` (if non-null) and every entry of `locked` are live and currently
/// locked by this CPU.
unsafe fn fork_bind_release(
    state: *mut crate::cap::memory_object::VmHierarchyState,
    locked: &[*mut crate::cap::memory_object::MemoryObject],
) {
    if !state.is_null() {
        unsafe { (*state).lock.unlock() };
    }
    for &m in locked.iter().rev() {
        unsafe { (*m).hierarchy_bind_lock.unlock() };
    }
}

/// RAII guard that drops a fork's source-tree bind on scope exit, so the many
/// fallible exits in `syscall_vspace_fork_range` / `..._undo_fork_range` need no
/// manual release. The bind locks (`hierarchy_bind_lock`, `VmHierarchyState.lock`)
/// are never taken by IRQ handlers, so releasing them in `Drop` — which on an
/// error path may run just after `restore_irq` — cannot self-deadlock. The
/// success path drops it explicitly *before* the post-commit user copy so that
/// copy runs outside the tree lock.
struct ForkBindGuard {
    state: *mut crate::cap::memory_object::VmHierarchyState,
    locked: [*mut crate::cap::memory_object::MemoryObject; 3],
    n: usize,
}

impl Drop for ForkBindGuard {
    fn drop(&mut self) {
        unsafe { fork_bind_release(self.state, &self.locked[..self.n]) };
    }
}

/// RAII guard releasing a single held spinlock (the per-tree / bind lock a
/// `MemoryObject::lock_tree` handed back) on scope exit, so the many fallible
/// exits in `syscall_vspace_undo_fork_range` need no manual unlock. Like
/// `ForkBindGuard`, the lock is never taken by IRQ handlers, so releasing it in
/// `Drop` (possibly just after `restore_irq`) is deadlock-free; the success /
/// idempotent paths drop it explicitly before any deferred `release_obj_ref`.
struct TreeLockGuard(*const crate::mm::SpinLock);

impl Drop for TreeLockGuard {
    fn drop(&mut self) {
        unsafe { (*self.0).unlock() };
    }
}

/// Publish `hierarchy_state` on every MO this fork newly binds and take one
/// state ref each. Called only after all fallible reservations succeed, so a
/// reservation failure never leaves published one-shot state. Standalone
/// source → the fresh `S` is bound (one-shot `bound` swap); already-bound
/// source → the child / shadow adopt its existing state (`to_bind` excludes the
/// source). Returns false only if the one-shot `S` was already consumed.
///
/// # Safety
/// Caller holds the bind locks + the tree / `S` lock from `fork_bind_release`'s
/// matching acquisition.
unsafe fn fork_bind_publish(
    state: *mut crate::cap::memory_object::VmHierarchyState,
    to_bind: &[*mut crate::cap::memory_object::MemoryObject],
    standalone: bool,
) -> bool {
    use core::sync::atomic::Ordering;
    if state.is_null() {
        return true;
    }
    if standalone && unsafe { (*state).bound.swap(true, Ordering::AcqRel) } {
        return false;
    }
    for &m in to_bind.iter() {
        unsafe {
            (*m).hierarchy_state.store(state, Ordering::Release);
            crate::cap::increment_refcount(state as *mut crate::cap::object::KernelObject);
        }
    }
    true
}

pub(super) fn syscall_vspace_fork_range(
    parent_cap: &Capability,
    child_vs_s_packed: u64,
    packed_mo_caps: u64,
    va_start: u64,
    rollback_buffer_uaddr: u64,
) -> SyscallResult {
    // MAP, not READ: this call mutates parent VmArea ownership and
    // flips parent PTEs writable→COW. READ would let an unprivileged
    // holder of a read-only VSpace cap mutate the address space.
    if let Err(e) = validate_capability(parent_cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    // arg0 packs the child VSpace cap slot (low 32) and the per-tree
    // `VmHierarchyState` cap slot (high 32): the invoke arg registers are full
    // and a cptr fits in 32 bits (same convention as `packed_mo_caps`), so the
    // S cap rides in the spare half of the child-VSpace arg. `s` is supplied
    // only when the source MO is standalone (this fork creates its tree); a
    // fork whose source is already in a tree passes a null S slot.
    let child_vs_cap_ptr = child_vs_s_packed & 0xFFFF_FFFF;
    let s_cap_ptr = child_vs_s_packed >> 32;

    let child_vs_cap =
        match lookup_typed_cap_locked(child_vs_cap_ptr, ObjectType::VSpace, CapRights::MAP) {
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

    // packed_mo_caps: high 32 = parent_shadow_mo, low 32 = child_mo.
    // parent_shadow_mo = 0 keeps parent VmArea on its existing MO (no swap).
    let parent_shadow_mo_cap_ptr = packed_mo_caps >> 32;
    let child_mo_cap_ptr = packed_mo_caps & 0xFFFF_FFFF;

    let child_mo_cap =
        match lookup_typed_cap_locked(child_mo_cap_ptr, ObjectType::MemoryObject, CapRights::WRITE)
        {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };

    let parent_shadow_mo: *mut crate::cap::memory_object::MemoryObject =
        if parent_shadow_mo_cap_ptr != 0 {
            match lookup_typed_cap_locked(
                parent_shadow_mo_cap_ptr,
                ObjectType::MemoryObject,
                CapRights::WRITE,
            ) {
                Ok(c) => c.object as *mut crate::cap::memory_object::MemoryObject,
                Err(e) => return SyscallResult::err(e),
            }
        } else {
            core::ptr::null_mut()
        };

    // Read rollback buffer header to get page_count and the offset
    // used by the fresh parent-shadow / child MOs. old_mo and
    // old_mo_offset are for the matching undo call; the forward path
    // resolves the current parent VmArea owner directly.
    let header: ChunkRollbackHeader = match unsafe {
        crate::arch::uaccess::copy_from_user::<ChunkRollbackHeader>(rollback_buffer_uaddr)
    } {
        Some(h) => h,
        None => return SyscallResult::err(SyscallError::InvalidArgument),
    };
    let page_count = header.page_count as usize;
    let fork_mo_offset = header.mo_offset as usize;

    if va_start & 0xFFF != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if page_count == 0 {
        return SyscallResult::ok(0);
    }
    if page_count > MAX_FORK_PAGES_USIZE {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let parent_vs = &mut *(parent_cap.object as *mut VSpace);
        let child_vs = &mut *(child_vs_cap.object as *mut VSpace);
        let child_mo = child_mo_cap.object as *mut crate::cap::memory_object::MemoryObject;

        let irq = save_irq_disable();
        let same = core::ptr::eq(parent_vs, child_vs);
        let parent_first =
            (parent_vs as *const VSpace as usize) <= (child_vs as *const VSpace as usize);

        // Drop-revalidate dance: discover the source MO under the VSpace locks,
        // then take its per-tree bind domain OUTSIDE those locks (canonical
        // order VmHierarchyState.lock → VSpace.lock), re-take the VSpace locks,
        // and revalidate. fork is a controlled op, so a revalidation mismatch
        // returns a retryable error rather than spinning.
        lock_fork_pair(parent_vs, child_vs, parent_first, same);
        let src_mo: *mut crate::cap::memory_object::MemoryObject = if parent_vs.tracking.is_null() {
            core::ptr::null_mut()
        } else {
            match (*parent_vs.tracking).mappings.lookup(va_start) {
                Some((_s, vma)) if !vma.mo().is_null() => vma.mo(),
                _ => core::ptr::null_mut(),
            }
        };
        unlock_fork_pair(parent_vs, child_vs, parent_first, same);

        // Reject aliased MO arguments before locking the bind domain: the
        // candidate list below is sorted and each entry's hierarchy_bind_lock is
        // locked in turn, so a duplicate pointer would lock the same spinlock
        // twice and self-deadlock. child / parent-shadow must be distinct from
        // the source and from each other.
        if !src_mo.is_null()
            && (child_mo == src_mo
                || parent_shadow_mo == src_mo
                || (!parent_shadow_mo.is_null() && parent_shadow_mo == child_mo))
        {
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        // Acquire the source tree's bind domain — locks only; publish (storing
        // `hierarchy_state` + refs) happens after every fallible reservation so
        // a failure never leaves published one-shot state. `bind_state` is the
        // tree / S lock to release; `bind_locked` the hierarchy_bind_locks;
        // `bind_to_publish` the MOs to bind (standalone: src+child+shadow;
        // bound: child+shadow only — src already holds its state ref).
        let mut bind_state: *mut crate::cap::memory_object::VmHierarchyState =
            core::ptr::null_mut();
        let mut bind_locked: [*mut crate::cap::memory_object::MemoryObject; 3] =
            [core::ptr::null_mut(); 3];
        let mut bind_locked_n = 0usize;
        let mut bind_to_publish: [*mut crate::cap::memory_object::MemoryObject; 3] =
            [core::ptr::null_mut(); 3];
        let mut bind_to_publish_n = 0usize;
        let mut bind_standalone = false;
        if !src_mo.is_null() {
            let src_state = (*src_mo)
                .hierarchy_state
                .load(core::sync::atomic::Ordering::Acquire);
            bind_standalone = src_state.is_null();
            let candidates: [*mut crate::cap::memory_object::MemoryObject; 3] = if bind_standalone {
                [src_mo, child_mo, parent_shadow_mo]
            } else {
                [child_mo, parent_shadow_mo, core::ptr::null_mut()]
            };
            for m in candidates {
                if !m.is_null() {
                    bind_locked[bind_locked_n] = m;
                    bind_locked_n += 1;
                }
            }
            bind_locked[..bind_locked_n].sort_unstable_by_key(|&m| m as usize);
            for &m in bind_locked[..bind_locked_n].iter() {
                (*m).hierarchy_bind_lock.lock();
            }
            bind_to_publish = bind_locked;
            bind_to_publish_n = bind_locked_n;
            bind_state = if bind_standalone { s_obj } else { src_state };
            if !bind_state.is_null() {
                (*bind_state).lock.lock();
            }
        }

        // The bind is now held; this guard releases it on every scope exit
        // (Drop), so the fallible reservations below need no manual release.
        let fork_bind = ForkBindGuard {
            state: bind_state,
            locked: bind_locked,
            n: bind_locked_n,
        };

        // Deferred release of the swapped-out source VMA ref; `release_obj_ref`
        // takes REAPER_LOCK and must not run under the tree lock, so it is
        // drained after every lock drops.
        let mut deferred_old: Option<crate::mm::vspace::VmArea> = None;

        lock_fork_pair(parent_vs, child_vs, parent_first, same);

        // Revalidate the source still backs the range under the re-taken locks.
        if !src_mo.is_null() {
            // A standalone source (this fork creates its tree) must supply S.
            if bind_standalone && s_obj.is_null() {
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            let cur = if parent_vs.tracking.is_null() {
                core::ptr::null_mut()
            } else {
                match (*parent_vs.tracking).mappings.lookup(va_start) {
                    Some((_s, vma)) if vma.mo() == src_mo => src_mo,
                    _ => core::ptr::null_mut(),
                }
            };
            let cur_state = (*src_mo)
                .hierarchy_state
                .load(core::sync::atomic::Ordering::Acquire);
            let state_ok = if bind_standalone {
                cur_state.is_null()
            } else {
                cur_state == bind_state
            };
            if cur != src_mo || !state_ok {
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                restore_irq(irq);
                return SyscallResult::err(SyscallError::Busy);
            }
            // A standalone fork must be handed an UNBOUND one-shot S. Verify it
            // here under S.lock (held via ForkBindGuard); the publish swap below
            // is then infallible because S.lock is held continuously until then.
            if bind_standalone
                && !bind_state.is_null()
                && (*bind_state)
                    .bound
                    .load(core::sync::atomic::Ordering::Acquire)
            {
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            // The child + parent-shadow MOs this fork binds into the tree must
            // be pristine. Their bind locks are held above, so their standalone
            // state stays stable through publish (plan: re-check pristine under
            // the bind locks).
            if (!child_mo.is_null() && !(*child_mo).is_pristine())
                || (!parent_shadow_mo.is_null() && !(*parent_shadow_mo).is_pristine())
            {
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                restore_irq(irq);
                return SyscallResult::err(SyscallError::Busy);
            }
        }

        // Pre-reserve every leaf page-table node `child_vs` will touch.
        // After this succeeds, `fork_range_locked` cannot fail with
        // `NotMapped` on any per-page write_entry, so the loop becomes
        // all-or-nothing relative to the chunk range. The returned
        // guard tracks every newly-allocated PT page so a later
        // reservation failure can roll the page-table tree back.
        let pt_guard = match VSpace::ensure_tables_for_range(child_vs, va_start, page_count) {
            Ok(g) => g,
            Err(e) => {
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                restore_irq(irq);
                return SyscallResult::err(syscall_error_from_vspace_error(e));
            }
        };

        let (perms, region_kind) = if parent_vs.tracking.is_null() {
            let mut sample: u64 = 0;
            for i in 0..page_count {
                let va = va_start + (i as u64) * crate::mm::PAGE_SIZE as u64;
                if let Some(e) = parent_vs.read_entry(va, 1) {
                    if e != 0 {
                        sample = e;
                        break;
                    }
                }
            }
            if sample == 0 {
                pt_guard.rollback(child_vs);
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            let ff = VSpace::entry_flags_to_page_flags(sample);
            let mut p: u8 = 0;
            if ff.writable || ff.cow {
                p |= 0x01;
            }
            if ff.user {
                p |= 0x02;
            }
            if ff.executable {
                p |= 0x04;
            }
            (p, 0u8)
        } else {
            let pt = &*parent_vs.tracking;
            match pt.mappings.lookup(va_start) {
                Some((_start, vma)) => (vma.perms, vma.region_kind),
                None => {
                    pt_guard.rollback(child_vs);
                    unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                    restore_irq(irq);
                    return SyscallResult::err(SyscallError::InvalidArgument);
                }
            }
        };

        let meta_resv = match reserve_vspace_map_mo_metadata_locked(
            child_vs,
            child_mo,
            va_start,
            page_count as u32,
            fork_mo_offset as u32,
            perms,
            region_kind,
        ) {
            Ok(r) => r,
            Err(e) => {
                pt_guard.rollback(child_vs);
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                restore_irq(irq);
                return SyscallResult::err(e);
            }
        };

        if meta_resv.is_covered() {
            pt_guard.forget();
            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
            restore_irq(irq);
            return SyscallResult::ok(page_count as u64);
        }

        // Plan parent VmArea swap. The chunk's range may exactly match
        // the parent VmArea (whole-VmArea swap) or be a left-aligned
        // sub-range (split V into V_chunk + V_right). mmsrv issues
        // chunks sequentially from a region's base, so right-aligned
        // and strict-interior cases are not produced by the policy
        // layer; they are rejected here as `InvalidArgument` so a
        // future caller cannot silently slip past split semantics.
        // The forked child region inherits the parent region's protection
        // ceiling — fork never widens rights. Sampled before the swap
        // below mutates the parent VmArea in place.
        let parent_max_prot = if parent_vs.tracking.is_null() {
            crate::mm::vspace::VmArea::MAX_PROT_WRITE | crate::mm::vspace::VmArea::MAX_PROT_EXEC
        } else {
            (*parent_vs.tracking)
                .mappings
                .lookup(va_start)
                .map(|(_, v)| v.max_prot)
                .unwrap_or(
                    crate::mm::vspace::VmArea::MAX_PROT_WRITE
                        | crate::mm::vspace::VmArea::MAX_PROT_EXEC,
                )
        };
        let parent_plan = if !parent_shadow_mo.is_null() {
            if parent_vs.tracking.is_null() {
                commit_or_release_vspace_map_mo_metadata_locked(
                    meta_resv,
                    child_vs,
                    child_mo,
                    va_start,
                    0,
                    fork_mo_offset as u32,
                    perms,
                    region_kind,
                );
                pt_guard.rollback(child_vs);
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            let pt = &*parent_vs.tracking;
            let lookup = pt.mappings.lookup(va_start);
            let chunk_bytes = (page_count as u64) * crate::mm::PAGE_SIZE as u64;
            let chunk_end = va_start + chunk_bytes;
            match lookup {
                Some((vma_start, vma)) if vma.mo() == parent_shadow_mo => {
                    // Already swapped (idempotent re-call); nothing to do.
                    let _ = vma_start;
                    ParentSwapPlan::None
                }
                Some((vma_start, vma))
                    if vma_start == va_start
                        && (vma.page_count as usize) == page_count
                        && !vma.mo().is_null() =>
                {
                    // Exact match: full-VmArea swap.
                    match (*parent_shadow_mo).rmap_reserve_slot() {
                        Ok(t) => ParentSwapPlan::Exact {
                            ticket: t,
                            old_mo: vma.mo(),
                            vma_start,
                            base_vma: *vma,
                        },
                        Err(_) => {
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    }
                }
                Some((vma_start, vma))
                    if vma_start == va_start
                        && (vma.page_count as usize) > page_count
                        && !vma.mo().is_null()
                        && vma.mo() != parent_shadow_mo =>
                {
                    // Left-aligned subset: split V → V_chunk (parent_shadow_mo,
                    // [va_start, chunk_end)) + V_right (old_mo, [chunk_end,
                    // V.end)). chunk_end becomes the new V_right key, replacing
                    // the existing entry's value via insert_reserved.
                    let v_right_pages = vma.page_count as u32 - page_count as u32;
                    let v_right_mo_offset = vma.mo_offset + page_count as u32;

                    let ps_ticket = match (*parent_shadow_mo).rmap_reserve_slot() {
                        Ok(t) => t,
                        Err(_) => {
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };

                    let old_mo = vma.mo();
                    let old_mo_obj = old_mo as *mut crate::cap::memory_object::MemoryObject;
                    let old_ticket = match (*old_mo_obj).rmap_reserve_slot() {
                        Ok(t) => t,
                        Err(_) => {
                            (*parent_shadow_mo).rmap_release_ticket(ps_ticket);
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };

                    let mut tree_alloc = map_mo_tree_allocator();
                    let tree_resv = match pt.mappings.reserve_for_insert(&mut tree_alloc) {
                        Ok(r) => r,
                        Err(_) => {
                            (*parent_shadow_mo).rmap_release_ticket(ps_ticket);
                            (*old_mo_obj).rmap_release_ticket(old_ticket);
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };

                    ParentSwapPlan::LeftAligned {
                        ps_ticket,
                        old_ticket,
                        old_mo,
                        vma_start,
                        base_vma: *vma,
                        v_right_start: chunk_end,
                        v_right_pages,
                        v_right_mo_offset,
                        tree_resv,
                    }
                }
                Some((vma_start, vma))
                    if vma_start < va_start
                        && !vma.mo().is_null()
                        && vma.mo() != parent_shadow_mo
                        && vma_start + (vma.page_count as u64) * crate::mm::PAGE_SIZE as u64
                            == chunk_end =>
                {
                    // Right-aligned subset: V starts strictly before
                    // the chunk and ends exactly at chunk_end. Split
                    // V → V_left (old_mo, [V.start, va_start)) +
                    // V_chunk (parent_shadow_mo, [va_start, chunk_end)).
                    let v_left_pages =
                        ((va_start - vma_start) / crate::mm::PAGE_SIZE as u64) as u32;
                    let chunk_mo_offset = fork_mo_offset as u32;

                    let ps_ticket = match (*parent_shadow_mo).rmap_reserve_slot() {
                        Ok(t) => t,
                        Err(_) => {
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };

                    let old_mo = vma.mo();
                    let old_mo_obj = old_mo as *mut crate::cap::memory_object::MemoryObject;
                    let old_ticket = match (*old_mo_obj).rmap_reserve_slot() {
                        Ok(t) => t,
                        Err(_) => {
                            (*parent_shadow_mo).rmap_release_ticket(ps_ticket);
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };

                    let mut tree_alloc = map_mo_tree_allocator();
                    let tree_resv = match pt.mappings.reserve_for_insert(&mut tree_alloc) {
                        Ok(r) => r,
                        Err(_) => {
                            (*parent_shadow_mo).rmap_release_ticket(ps_ticket);
                            (*old_mo_obj).rmap_release_ticket(old_ticket);
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };

                    ParentSwapPlan::RightAligned {
                        ps_ticket,
                        old_ticket,
                        old_mo,
                        vma_start,
                        base_vma: *vma,
                        v_left_pages,
                        chunk_va: va_start,
                        chunk_mo_offset,
                        tree_resv,
                    }
                }
                Some((vma_start, vma))
                    if vma_start < va_start
                        && !vma.mo().is_null()
                        && vma.mo() != parent_shadow_mo
                        && vma_start + (vma.page_count as u64) * crate::mm::PAGE_SIZE as u64
                            > chunk_end =>
                {
                    // Strict interior: V strictly contains the chunk.
                    // Split V → V_left + V_chunk + V_right (old_mo,
                    // parent_shadow_mo, old_mo respectively).
                    let v_left_pages =
                        ((va_start - vma_start) / crate::mm::PAGE_SIZE as u64) as u32;
                    let old_chunk_mo_offset = vma.mo_offset + v_left_pages;
                    let chunk_mo_offset = fork_mo_offset as u32;
                    let total_pages = vma.page_count as u32;
                    let v_right_pages = total_pages - v_left_pages - page_count as u32;
                    let v_right_mo_offset = old_chunk_mo_offset + page_count as u32;

                    let ps_ticket = match (*parent_shadow_mo).rmap_reserve_slot() {
                        Ok(t) => t,
                        Err(_) => {
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };

                    let old_mo = vma.mo();
                    let old_mo_obj = old_mo as *mut crate::cap::memory_object::MemoryObject;
                    let old_ticket_left = match (*old_mo_obj).rmap_reserve_slot() {
                        Ok(t) => t,
                        Err(_) => {
                            (*parent_shadow_mo).rmap_release_ticket(ps_ticket);
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };
                    let old_ticket_right = match (*old_mo_obj).rmap_reserve_slot() {
                        Ok(t) => t,
                        Err(_) => {
                            (*parent_shadow_mo).rmap_release_ticket(ps_ticket);
                            (*old_mo_obj).rmap_release_ticket(old_ticket_left);
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };

                    let mut tree_alloc = map_mo_tree_allocator();
                    let tree_resv_left = match pt.mappings.reserve_for_insert(&mut tree_alloc) {
                        Ok(r) => r,
                        Err(_) => {
                            (*parent_shadow_mo).rmap_release_ticket(ps_ticket);
                            (*old_mo_obj).rmap_release_ticket(old_ticket_left);
                            (*old_mo_obj).rmap_release_ticket(old_ticket_right);
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };
                    let tree_resv_right = match pt.mappings.reserve_for_insert(&mut tree_alloc) {
                        Ok(r) => r,
                        Err(_) => {
                            (*parent_shadow_mo).rmap_release_ticket(ps_ticket);
                            (*old_mo_obj).rmap_release_ticket(old_ticket_left);
                            (*old_mo_obj).rmap_release_ticket(old_ticket_right);
                            tree_resv_left.release(&mut tree_alloc);
                            commit_or_release_vspace_map_mo_metadata_locked(
                                meta_resv,
                                child_vs,
                                child_mo,
                                va_start,
                                0,
                                fork_mo_offset as u32,
                                perms,
                                region_kind,
                            );
                            pt_guard.rollback(child_vs);
                            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };

                    ParentSwapPlan::StrictInterior {
                        ps_ticket,
                        old_ticket_left,
                        old_ticket_right,
                        old_mo,
                        vma_start,
                        base_vma: *vma,
                        v_left_pages,
                        chunk_va: va_start,
                        chunk_mo_offset,
                        v_right_start: chunk_end,
                        v_right_pages,
                        v_right_mo_offset,
                        tree_resv_left,
                        tree_resv_right,
                    }
                }
                _ => {
                    commit_or_release_vspace_map_mo_metadata_locked(
                        meta_resv,
                        child_vs,
                        child_mo,
                        va_start,
                        0,
                        fork_mo_offset as u32,
                        perms,
                        region_kind,
                    );
                    pt_guard.rollback(child_vs);
                    unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                    restore_irq(irq);
                    return SyscallResult::err(SyscallError::InvalidArgument);
                }
            }
        } else {
            ParentSwapPlan::None
        };

        // Stack-allocated bitmap. MAX_FORK_PAGES = 8192 → 1024 bytes.
        // Sized to MAX so the array length is a constant; only the
        // first `(page_count + 7) / 8` bytes are valid for this call.
        let mut bitmap = [0u8; MAX_FORK_BITMAP_BYTES];
        let bitmap_len = (page_count + 7) / 8;
        let bitmap_slice = &mut bitmap[..bitmap_len];

        let forked = parent_vs.fork_range_locked(child_vs, va_start, page_count, bitmap_slice);

        commit_or_release_vspace_map_mo_metadata_max_prot_locked(
            meta_resv,
            child_vs,
            child_mo,
            va_start,
            if forked == 0 { 0 } else { page_count as u32 },
            fork_mo_offset as u32,
            perms,
            region_kind,
            parent_max_prot,
        );

        // Tracks the split form actually committed for this chunk so
        // it can be stamped into the rollback record's `split_kind`
        // for the matching undo. Initial value is the sentinel for
        // "this chunk made no parent-side state change" — each
        // `ParentSwapPlan` arm overwrites it on a successful commit.
        // Leaving it as `NONE` keeps a `forked > 0`, parent-untouched
        // call (idempotent re-fork) safely undoable without reverting
        // an earlier successful swap.
        let mut committed_split_kind: u32 = CHUNK_SPLIT_KIND_NONE;
        let parent_shadow_mo_offset = fork_mo_offset as u32;

        // Publish the source-tree binding now that every fallible reservation
        // has succeeded: store `hierarchy_state` on the newly-bound MOs and take
        // one state ref each. Past this point the commit is infallible.
        if forked > 0 {
            let published = fork_bind_publish(
                bind_state,
                &bind_to_publish[..bind_to_publish_n],
                bind_standalone,
            );
            // The one-shot S was verified unbound at the revalidate above and
            // S.lock has been held continuously since, so publish cannot fail.
            // A false here is a kernel invariant break after partial commit —
            // fail hard rather than silently binding into a consumed state.
            assert!(
                published,
                "fork: source tree state already bound after revalidate"
            );
        }

        // Build the Zircon-style hidden-parent COW hierarchy: link the
        // fresh shadow MOs as COW children of the parent VMA's current
        // source MO. The source then outlives both shadows — each child's
        // `destroy` rmap-walk releases the shared frames' `map_count`
        // before the source's own radix free — which is what keeps the
        // PMM `map_count == 0`-at-free invariant intact for fork-shared
        // frames. The parent VMA still names the source MO here; the swap
        // below moves it onto `parent_shadow_mo`. Idempotent across chunks
        // and idempotent re-calls via the `cow_parent` null guard.
        let child_needs_link = (*child_mo).cow_parent.is_null();
        let shadow_needs_link =
            !parent_shadow_mo.is_null() && (*parent_shadow_mo).cow_parent.is_null();
        if forked > 0 && (child_needs_link || shadow_needs_link) && !parent_vs.tracking.is_null() {
            let link = {
                let pt = &*parent_vs.tracking;
                pt.mappings.lookup(va_start).and_then(|(vma_start, vma)| {
                    let src_mo = vma.mo();
                    if src_mo.is_null() || src_mo == child_mo || src_mo == parent_shadow_mo {
                        None
                    } else {
                        // Page index of the chunk within the source MO,
                        // minus the shadows' own offset for the chunk: a
                        // shadow page `fork_mo_offset + j` resolves to
                        // source page `chunk_base + j`.
                        let chunk_base = vma.mo_offset as usize
                            + ((va_start - vma_start) / crate::mm::PAGE_SIZE as u64) as usize;
                        Some((src_mo, chunk_base.saturating_sub(fork_mo_offset) as u32))
                    }
                })
            };
            if let Some((src_mo, cow_off)) = link {
                if child_needs_link {
                    (*child_mo).attach_cow_parent(src_mo, cow_off);
                }
                if shadow_needs_link {
                    (*parent_shadow_mo).attach_cow_parent(src_mo, cow_off);
                }
            }
        }

        // Commit / rollback the parent VmArea swap.
        match parent_plan {
            ParentSwapPlan::None => {}
            ParentSwapPlan::Exact {
                ticket,
                old_mo,
                vma_start,
                base_vma,
            } => {
                if forked > 0 {
                    let mut new_vma = base_vma;
                    new_vma.obj = parent_shadow_mo as *mut crate::cap::KernelObject;
                    new_vma.mo_offset = parent_shadow_mo_offset;

                    let pt = &mut *parent_vs.tracking;
                    let replaced = pt.mappings.replace(vma_start, new_vma);

                    if replaced {
                        (*old_mo).rmap_remove(parent_vs as *mut VSpace, vma_start);
                        (*parent_shadow_mo).rmap_add_reserved(
                            ticket,
                            crate::cap::memory_object::ReverseMapEntry {
                                vspace: parent_vs as *mut VSpace,
                                va_start: vma_start,
                                page_count: new_vma.page_count,
                                mo_offset: new_vma.mo_offset,
                                perms: new_vma.perms,
                                _pad: [0; 7],
                            },
                        );

                        new_vma.retain_obj_ref();
                        let old_vma_ref = crate::mm::vspace::VmArea {
                            obj: old_mo as *mut crate::cap::KernelObject,
                            mo_offset: 0,
                            page_count: 0,
                            perms: 0,
                            region_kind: 0,
                            obj_type: crate::cap::ObjectType::MemoryObject as u8,
                            max_prot: 0,
                            _pad: [0; 4],
                        };
                        deferred_old = Some(old_vma_ref);
                        committed_split_kind = CHUNK_SPLIT_KIND_EXACT;
                    } else {
                        (*parent_shadow_mo).rmap_release_ticket(ticket);
                    }
                } else {
                    (*parent_shadow_mo).rmap_release_ticket(ticket);
                }
            }
            ParentSwapPlan::LeftAligned {
                ps_ticket,
                old_ticket,
                old_mo,
                vma_start,
                base_vma,
                v_right_start,
                v_right_pages,
                v_right_mo_offset,
                mut tree_resv,
            } => {
                let old_mo_obj = old_mo as *mut crate::cap::memory_object::MemoryObject;
                if forked > 0 {
                    // V_chunk replaces V at vma_start: same key, parent_shadow_mo
                    // owner, page_count = chunk pages.
                    let mut v_chunk = base_vma;
                    v_chunk.obj = parent_shadow_mo as *mut crate::cap::KernelObject;
                    v_chunk.page_count = page_count as u32;
                    v_chunk.mo_offset = parent_shadow_mo_offset;

                    // V_right is the leftover suffix: same owner old_mo, new
                    // start key = chunk_end.
                    let mut v_right = base_vma;
                    v_right.page_count = v_right_pages;
                    v_right.mo_offset = v_right_mo_offset;

                    let pt = &mut *parent_vs.tracking;
                    let replaced = pt.mappings.replace(vma_start, v_chunk);
                    crate::kernel::bug::kassert!(
                        replaced,
                        "LeftAligned VmArea split: replace at vma_start failed"
                    );
                    pt.mappings
                        .insert_reserved(v_right_start, v_right, &mut tree_resv);
                    let mut tree_alloc = map_mo_tree_allocator();
                    tree_resv.release(&mut tree_alloc);

                    // rmap surgery: drop old_mo's full-range entry, add
                    // old_mo's V_right entry, and add parent_shadow_mo's
                    // V_chunk entry.
                    (*old_mo_obj).rmap_remove(parent_vs as *mut VSpace, vma_start);
                    (*old_mo_obj).rmap_add_reserved(
                        old_ticket,
                        crate::cap::memory_object::ReverseMapEntry {
                            vspace: parent_vs as *mut VSpace,
                            va_start: v_right_start,
                            page_count: v_right_pages,
                            mo_offset: v_right_mo_offset,
                            perms: v_right.perms,
                            _pad: [0; 7],
                        },
                    );
                    (*parent_shadow_mo).rmap_add_reserved(
                        ps_ticket,
                        crate::cap::memory_object::ReverseMapEntry {
                            vspace: parent_vs as *mut VSpace,
                            va_start: vma_start,
                            page_count: page_count as u32,
                            mo_offset: v_chunk.mo_offset,
                            perms: v_chunk.perms,
                            _pad: [0; 7],
                        },
                    );

                    // Refcounting: V_chunk gains parent_shadow_mo ref; V_right
                    // gains a fresh old_mo ref; the original V's old_mo ref
                    // is dropped.
                    v_chunk.retain_obj_ref();
                    v_right.retain_obj_ref();
                    let old_vma_ref = crate::mm::vspace::VmArea {
                        obj: old_mo as *mut crate::cap::KernelObject,
                        mo_offset: 0,
                        page_count: 0,
                        perms: 0,
                        region_kind: 0,
                        obj_type: crate::cap::ObjectType::MemoryObject as u8,
                        max_prot: 0,
                        _pad: [0; 4],
                    };
                    deferred_old = Some(old_vma_ref);
                    committed_split_kind = CHUNK_SPLIT_KIND_LEFT;
                } else {
                    (*parent_shadow_mo).rmap_release_ticket(ps_ticket);
                    (*old_mo_obj).rmap_release_ticket(old_ticket);
                    let mut tree_alloc = map_mo_tree_allocator();
                    tree_resv.release(&mut tree_alloc);
                }
            }
            ParentSwapPlan::RightAligned {
                ps_ticket,
                old_ticket,
                old_mo,
                vma_start,
                base_vma,
                v_left_pages,
                chunk_va,
                chunk_mo_offset,
                mut tree_resv,
            } => {
                let old_mo_obj = old_mo as *mut crate::cap::memory_object::MemoryObject;
                if forked > 0 {
                    // V_left replaces V at vma_start (key unchanged):
                    // smaller page_count, same owner old_mo.
                    let mut v_left = base_vma;
                    v_left.page_count = v_left_pages;

                    // V_chunk inserts at chunk_va: parent_shadow_mo,
                    // page_count = chunk pages, mo_offset adjusted.
                    let mut v_chunk = base_vma;
                    v_chunk.obj = parent_shadow_mo as *mut crate::cap::KernelObject;
                    v_chunk.page_count = page_count as u32;
                    v_chunk.mo_offset = chunk_mo_offset;

                    let pt = &mut *parent_vs.tracking;
                    let replaced = pt.mappings.replace(vma_start, v_left);
                    crate::kernel::bug::kassert!(
                        replaced,
                        "RightAligned VmArea split: replace at vma_start failed"
                    );
                    pt.mappings
                        .insert_reserved(chunk_va, v_chunk, &mut tree_resv);
                    let mut tree_alloc = map_mo_tree_allocator();
                    tree_resv.release(&mut tree_alloc);

                    // rmap surgery: drop old_mo's full-range entry,
                    // re-add as V_left's narrower entry, add
                    // parent_shadow_mo's V_chunk entry.
                    (*old_mo_obj).rmap_remove(parent_vs as *mut VSpace, vma_start);
                    (*old_mo_obj).rmap_add_reserved(
                        old_ticket,
                        crate::cap::memory_object::ReverseMapEntry {
                            vspace: parent_vs as *mut VSpace,
                            va_start: vma_start,
                            page_count: v_left_pages,
                            mo_offset: v_left.mo_offset,
                            perms: v_left.perms,
                            _pad: [0; 7],
                        },
                    );
                    (*parent_shadow_mo).rmap_add_reserved(
                        ps_ticket,
                        crate::cap::memory_object::ReverseMapEntry {
                            vspace: parent_vs as *mut VSpace,
                            va_start: chunk_va,
                            page_count: page_count as u32,
                            mo_offset: v_chunk.mo_offset,
                            perms: v_chunk.perms,
                            _pad: [0; 7],
                        },
                    );

                    // Refcount: V_left + V_chunk replace V. old_mo: 0
                    // delta (V→V_left). parent_shadow_mo: +1 (V_chunk).
                    v_left.retain_obj_ref();
                    v_chunk.retain_obj_ref();
                    let old_vma_ref = crate::mm::vspace::VmArea {
                        obj: old_mo as *mut crate::cap::KernelObject,
                        mo_offset: 0,
                        page_count: 0,
                        perms: 0,
                        region_kind: 0,
                        obj_type: crate::cap::ObjectType::MemoryObject as u8,
                        max_prot: 0,
                        _pad: [0; 4],
                    };
                    deferred_old = Some(old_vma_ref);
                    committed_split_kind = CHUNK_SPLIT_KIND_RIGHT;
                } else {
                    (*parent_shadow_mo).rmap_release_ticket(ps_ticket);
                    (*old_mo_obj).rmap_release_ticket(old_ticket);
                    let mut tree_alloc = map_mo_tree_allocator();
                    tree_resv.release(&mut tree_alloc);
                }
            }
            ParentSwapPlan::StrictInterior {
                ps_ticket,
                old_ticket_left,
                old_ticket_right,
                old_mo,
                vma_start,
                base_vma,
                v_left_pages,
                chunk_va,
                chunk_mo_offset,
                v_right_start,
                v_right_pages,
                v_right_mo_offset,
                mut tree_resv_left,
                mut tree_resv_right,
            } => {
                let old_mo_obj = old_mo as *mut crate::cap::memory_object::MemoryObject;
                if forked > 0 {
                    // V_left replaces V at vma_start; V_chunk and
                    // V_right insert at chunk_va and chunk_end.
                    let mut v_left = base_vma;
                    v_left.page_count = v_left_pages;

                    let mut v_chunk = base_vma;
                    v_chunk.obj = parent_shadow_mo as *mut crate::cap::KernelObject;
                    v_chunk.page_count = page_count as u32;
                    v_chunk.mo_offset = chunk_mo_offset;

                    let mut v_right = base_vma;
                    v_right.page_count = v_right_pages;
                    v_right.mo_offset = v_right_mo_offset;

                    let pt = &mut *parent_vs.tracking;
                    let replaced = pt.mappings.replace(vma_start, v_left);
                    crate::kernel::bug::kassert!(
                        replaced,
                        "StrictInterior VmArea split: replace at vma_start failed"
                    );
                    pt.mappings
                        .insert_reserved(chunk_va, v_chunk, &mut tree_resv_left);
                    pt.mappings
                        .insert_reserved(v_right_start, v_right, &mut tree_resv_right);
                    let mut tree_alloc = map_mo_tree_allocator();
                    tree_resv_left.release(&mut tree_alloc);
                    tree_resv_right.release(&mut tree_alloc);

                    // rmap: drop V's old entry, add V_left, V_chunk,
                    // V_right entries.
                    (*old_mo_obj).rmap_remove(parent_vs as *mut VSpace, vma_start);
                    (*old_mo_obj).rmap_add_reserved(
                        old_ticket_left,
                        crate::cap::memory_object::ReverseMapEntry {
                            vspace: parent_vs as *mut VSpace,
                            va_start: vma_start,
                            page_count: v_left_pages,
                            mo_offset: v_left.mo_offset,
                            perms: v_left.perms,
                            _pad: [0; 7],
                        },
                    );
                    (*parent_shadow_mo).rmap_add_reserved(
                        ps_ticket,
                        crate::cap::memory_object::ReverseMapEntry {
                            vspace: parent_vs as *mut VSpace,
                            va_start: chunk_va,
                            page_count: page_count as u32,
                            mo_offset: v_chunk.mo_offset,
                            perms: v_chunk.perms,
                            _pad: [0; 7],
                        },
                    );
                    (*old_mo_obj).rmap_add_reserved(
                        old_ticket_right,
                        crate::cap::memory_object::ReverseMapEntry {
                            vspace: parent_vs as *mut VSpace,
                            va_start: v_right_start,
                            page_count: v_right_pages,
                            mo_offset: v_right_mo_offset,
                            perms: v_right.perms,
                            _pad: [0; 7],
                        },
                    );

                    // Refcount: 3 new VmAreas replace 1 V. old_mo gets
                    // +2 retains (V_left, V_right) - 1 release (V) =
                    // +1 net. parent_shadow_mo: +1 (V_chunk).
                    v_left.retain_obj_ref();
                    v_chunk.retain_obj_ref();
                    v_right.retain_obj_ref();
                    let old_vma_ref = crate::mm::vspace::VmArea {
                        obj: old_mo as *mut crate::cap::KernelObject,
                        mo_offset: 0,
                        page_count: 0,
                        perms: 0,
                        region_kind: 0,
                        obj_type: crate::cap::ObjectType::MemoryObject as u8,
                        max_prot: 0,
                        _pad: [0; 4],
                    };
                    deferred_old = Some(old_vma_ref);
                    committed_split_kind = CHUNK_SPLIT_KIND_INTERIOR;
                } else {
                    (*parent_shadow_mo).rmap_release_ticket(ps_ticket);
                    (*old_mo_obj).rmap_release_ticket(old_ticket_left);
                    (*old_mo_obj).rmap_release_ticket(old_ticket_right);
                    let mut tree_alloc = map_mo_tree_allocator();
                    tree_resv_left.release(&mut tree_alloc);
                    tree_resv_right.release(&mut tree_alloc);
                }
            }
        }

        // The child VmArea + parent VmArea swap (or split) all committed; the
        // freshly-allocated PT pages are now owned by the live page-table tree.
        pt_guard.forget();
        unlock_fork_pair(parent_vs, child_vs, parent_first, same);
        // Release the source-tree bind BEFORE the user copy + the deferred ref
        // drop: copy_to_user can fault and re-enter COW handling, and
        // release_obj_ref takes REAPER_LOCK — neither may run under the tree
        // lock. drop() consumes the guard so it is not re-released at return.
        drop(fork_bind);
        restore_irq(irq);

        // Publish the rollback bitmap + committed split form to mmsrv's user
        // buffer, now OUTSIDE every lock. The bitmap is appended to the rollback
        // header (the kernel reads it only on undo); `split_kind` is stamped so
        // undo dispatches purely on it (inferring the split form from
        // neighbouring VmArea state would misread an unrelated same-`old_mo`
        // mapping). Failure is a kernel-invariant break: the swap / PTE flips /
        // child VmArea install are all already committed and the buffer was read
        // back earlier in this same syscall, so a failure means the user mapping
        // was torn down behind our back — panic rather than leave a chunk that
        // cannot be rolled back.
        if forked > 0 {
            let bitmap_dst_uaddr =
                rollback_buffer_uaddr + core::mem::size_of::<ChunkRollbackHeader>() as u64;
            let ok = crate::arch::uaccess::copy_to_user_bytes(
                bitmap_dst_uaddr,
                bitmap_slice.as_ptr(),
                bitmap_slice.len(),
            );
            if !ok {
                panic!("vspace_fork_range: bitmap copy_to_user failed after commit");
            }
            let split_kind_uaddr = rollback_buffer_uaddr
                + core::mem::offset_of!(ChunkRollbackHeader, split_kind) as u64;
            let split_kind_bytes = committed_split_kind.to_ne_bytes();
            let ok = crate::arch::uaccess::copy_to_user_bytes(
                split_kind_uaddr,
                split_kind_bytes.as_ptr(),
                split_kind_bytes.len(),
            );
            if !ok {
                panic!("vspace_fork_range: split_kind copy_to_user failed after commit");
            }
        }

        // Drop the swapped-out source VMA's ref after every lock is released.
        if let Some(old) = deferred_old {
            old.release_obj_ref();
        }

        SyscallResult::ok(forked as u64)
    }
}

/// Reverse a previously committed `vspace_fork_range` chunk.
/// All-or-nothing: on success returns Ok(0), on failure returns the
/// VSpace error and the kernel state is unchanged from the pre-undo
/// state. Bitmap, `old_mo`, and `old_mo_offset` are read from the
/// same rollback buffer the matching forward fork wrote.
pub(super) fn syscall_vspace_undo_fork_range(
    parent_cap: &Capability,
    child_vs_cap_ptr: u64,
    packed_mo_caps: u64,
    va_start: u64,
    rollback_buffer_uaddr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(parent_cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }
    let child_vs_cap =
        match lookup_typed_cap_locked(child_vs_cap_ptr, ObjectType::VSpace, CapRights::MAP) {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };

    let parent_shadow_mo_cap_ptr = packed_mo_caps >> 32;
    let child_mo_cap_ptr = packed_mo_caps & 0xFFFF_FFFF;

    let child_mo_cap =
        match lookup_typed_cap_locked(child_mo_cap_ptr, ObjectType::MemoryObject, CapRights::WRITE)
        {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };
    let parent_shadow_mo_cap = match lookup_typed_cap_locked(
        parent_shadow_mo_cap_ptr,
        ObjectType::MemoryObject,
        CapRights::WRITE,
    ) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };

    let header: ChunkRollbackHeader = match unsafe {
        crate::arch::uaccess::copy_from_user::<ChunkRollbackHeader>(rollback_buffer_uaddr)
    } {
        Some(h) => h,
        None => return SyscallResult::err(SyscallError::InvalidArgument),
    };
    let page_count = header.page_count as usize;

    if va_start & 0xFFF != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if page_count == 0 {
        return SyscallResult::ok(0);
    }
    if page_count > MAX_FORK_PAGES_USIZE {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // Resolve old_mo by cap slot stored in the rollback record.
    let old_mo_cap_ptr = header.old_mo as u64;
    let old_mo_cap =
        match lookup_typed_cap_locked(old_mo_cap_ptr, ObjectType::MemoryObject, CapRights::WRITE) {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };

    // Read bitmap into a stack buffer.
    let bitmap_len = (page_count + 7) / 8;
    let mut bitmap = [0u8; MAX_FORK_BITMAP_BYTES];
    let bitmap_dst_uaddr =
        rollback_buffer_uaddr + core::mem::size_of::<ChunkRollbackHeader>() as u64;
    let ok = unsafe {
        crate::arch::uaccess::copy_from_user_bytes(
            bitmap_dst_uaddr,
            bitmap.as_mut_ptr(),
            bitmap_len,
        )
    };
    if !ok {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    let bitmap_slice = &bitmap[..bitmap_len];

    unsafe {
        let parent_vs = &mut *(parent_cap.object as *mut VSpace);
        let child_vs = &mut *(child_vs_cap.object as *mut VSpace);
        let parent_shadow_mo =
            parent_shadow_mo_cap.object as *mut crate::cap::memory_object::MemoryObject;
        let old_mo_obj = old_mo_cap.object as *mut crate::cap::memory_object::MemoryObject;
        let _child_mo = child_mo_cap.object as *mut crate::cap::memory_object::MemoryObject;

        let irq = save_irq_disable();
        let same = core::ptr::eq(parent_vs, child_vs);
        let parent_first =
            (parent_vs as *const VSpace as usize) <= (child_vs as *const VSpace as usize);

        // Take the affected tree's serialization lock OUTSIDE the VSpace locks
        // (canonical order). NONE rolls back only the child side, so it locks
        // the child MO's tree; every other shape mutates old_mo's rmap, so it
        // locks old_mo's tree. `lock_tree` handles the bound/standalone choice
        // and re-check; the MOs are cap-stable here, so no drop-revalidate dance
        // is needed. The guard releases the lock on every fallible exit (Drop).
        let mo_to_lock = if header.split_kind == CHUNK_SPLIT_KIND_NONE {
            child_mo_cap.object as *mut crate::cap::memory_object::MemoryObject
        } else {
            old_mo_obj
        };
        let tree_lock = TreeLockGuard((*mo_to_lock).lock_tree());

        // Deferred `release_obj_ref` of the per-shape VMA refs dropped during
        // rollback; `release_obj_ref` takes REAPER_LOCK, so it runs only after
        // the tree + VSpace locks drop.
        let mut deferred: [crate::mm::vspace::VmArea; 5] = [crate::mm::vspace::VmArea::EMPTY; 5];
        let mut deferred_n = 0usize;

        lock_fork_pair(parent_vs, child_vs, parent_first, same);

        if parent_vs.tracking.is_null() {
            unlock_fork_pair(parent_vs, child_vs, parent_first, same);
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        let chunk_bytes = (page_count as u64) * crate::mm::PAGE_SIZE as u64;
        let chunk_end = va_start + chunk_bytes;
        let split_kind = header.split_kind;
        let old_chunk_mo_offset = header.old_mo_offset;

        // Undo path mirrors the forward `LeftAligned` / `Exact` cases.
        // Look up V_chunk at va_start (must currently own parent_shadow_mo
        // and span exactly `page_count` pages — established by the matching
        // forward fork).
        let pt = &mut *parent_vs.tracking;
        let lookup = pt.mappings.lookup(va_start);
        let (vma_start, base_vma) = match lookup {
            Some((vs, vma))
                if vs == va_start
                    && vma.mo() == parent_shadow_mo
                    && vma.page_count as usize == page_count =>
            {
                (vs, *vma)
            }
            _ => {
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
        };

        // Forward fork stamped the committed split form into the
        // rollback header. Inferring it from neighbouring VmArea state
        // is unsafe because an unrelated mapping could place a
        // same-`old_mo` VmArea right after `V_chunk` and look identical
        // to the forward call's `V_right`. Trusting `split_kind` keeps
        // undo's behaviour symmetric with whatever forward actually did.
        //
        // For LEFT / RIGHT / INTERIOR cases we look up the relevant
        // neighbours and snapshot them; the actual merge runs after
        // PTE/rmap teardown below.
        let mut v_left_info: Option<(u64, crate::mm::vspace::VmArea)> = None;
        let mut v_right_info: Option<(u64, crate::mm::vspace::VmArea)> = None;
        match split_kind {
            CHUNK_SPLIT_KIND_NONE => {
                // Forward fork was idempotent (parent VmArea already
                // pointed at parent_shadow_mo); only the child side
                // needs cleanup. Skip ticket reservation, parent PTE
                // restore, and parent VmArea merge — fall through to
                // the child-cleanup tail at the end of the function.
                //
                // Clear the child's chunk PTEs and release their
                // map_count: the forward NONE case shared frames into the
                // child but left the parent untouched, so this is the only
                // teardown the child side needs. (Previously this arm
                // dropped the child VMA/rmap but leaked the PTE map_count.)
                child_vs.release_child_range_locked(va_start, page_count);
                let child_pt = if !child_vs.tracking.is_null() {
                    Some(&mut *child_vs.tracking)
                } else {
                    None
                };
                if let Some(child_pt) = child_pt {
                    let lookup_data = child_pt
                        .mappings
                        .lookup(va_start)
                        .map(|(cs, cvma)| (cs, *cvma));
                    if let Some((cs, cvma_copy)) = lookup_data {
                        let child_mo_ptr =
                            child_mo_cap.object as *mut crate::cap::memory_object::MemoryObject;
                        if cs == va_start
                            && cvma_copy.page_count as usize == page_count
                            && cvma_copy.mo() == child_mo_ptr
                        {
                            let mut tree_alloc = map_mo_tree_allocator();
                            let removed = child_pt.mappings.remove(cs, &mut tree_alloc);
                            if removed {
                                if !child_mo_ptr.is_null() {
                                    (*child_mo_ptr).rmap_remove(child_vs as *mut VSpace, cs);
                                }
                                deferred[deferred_n] = cvma_copy;
                                deferred_n += 1;
                                child_pt.note_vma_removed(&cvma_copy);
                            }
                        }
                    }
                }
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                drop(tree_lock);
                restore_irq(irq);
                for i in 0..deferred_n {
                    deferred[i].release_obj_ref();
                }
                return SyscallResult::ok(0);
            }
            CHUNK_SPLIT_KIND_EXACT => {}
            CHUNK_SPLIT_KIND_LEFT => {
                let lookup = pt.mappings.lookup(chunk_end);
                let candidate = match lookup {
                    Some((vs, vma))
                        if vs == chunk_end
                            && vma.mo()
                                == old_mo_obj as *mut crate::cap::memory_object::MemoryObject =>
                    {
                        Some((vs, *vma))
                    }
                    _ => None,
                };
                let validated = match candidate {
                    Some((vs, vma))
                        // V_right's `mo_offset` must continue exactly
                        // where this chunk ended in the original old MO.
                        // `base_vma.mo_offset` belongs to the fresh
                        // parent-shadow MO and can be 0 even when the
                        // original old-MO offset was non-zero.
                        if vma.mo_offset
                            == old_chunk_mo_offset + base_vma.page_count
                            && vma.perms == base_vma.perms
                            && vma.region_kind == base_vma.region_kind
                            && vma.obj_type == base_vma.obj_type =>
                    {
                        Some((vs, vma))
                    }
                    _ => None,
                };
                match validated {
                    Some((vs, vma)) => v_right_info = Some((vs, vma)),
                    None => {
                        unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                        restore_irq(irq);
                        return SyscallResult::err(SyscallError::InvalidArgument);
                    }
                }
            }
            CHUNK_SPLIT_KIND_RIGHT => {
                if va_start == 0 {
                    unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                    restore_irq(irq);
                    return SyscallResult::err(SyscallError::InvalidArgument);
                }
                let probe = va_start - 1;
                let lookup = pt.mappings.lookup(probe);
                let candidate = match lookup {
                    Some((vs, vma))
                        if vs < va_start
                            && vs + (vma.page_count as u64) * crate::mm::PAGE_SIZE as u64
                                == va_start
                            && vma.mo()
                                == old_mo_obj as *mut crate::cap::memory_object::MemoryObject =>
                    {
                        Some((vs, *vma))
                    }
                    _ => None,
                };
                let validated = match candidate {
                    Some((vs, vma))
                        // V_left's `mo_offset + page_count` must land
                        // exactly at this chunk's original old-MO
                        // offset so the merged V_orig has a contiguous
                        // offset map.
                        if vma.mo_offset + vma.page_count
                            == old_chunk_mo_offset
                            && vma.perms == base_vma.perms
                            && vma.region_kind == base_vma.region_kind
                            && vma.obj_type == base_vma.obj_type =>
                    {
                        Some((vs, vma))
                    }
                    _ => None,
                };
                match validated {
                    Some((vs, vma)) => v_left_info = Some((vs, vma)),
                    None => {
                        unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                        restore_irq(irq);
                        return SyscallResult::err(SyscallError::InvalidArgument);
                    }
                }
            }
            CHUNK_SPLIT_KIND_INTERIOR => {
                if va_start == 0 {
                    unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                    restore_irq(irq);
                    return SyscallResult::err(SyscallError::InvalidArgument);
                }
                let left_probe = va_start - 1;
                let left_lookup = pt.mappings.lookup(left_probe);
                let left_candidate = match left_lookup {
                    Some((vs, vma))
                        if vs < va_start
                            && vs + (vma.page_count as u64) * crate::mm::PAGE_SIZE as u64
                                == va_start
                            && vma.mo()
                                == old_mo_obj as *mut crate::cap::memory_object::MemoryObject =>
                    {
                        Some((vs, *vma))
                    }
                    _ => None,
                };
                let left_validated = match left_candidate {
                    Some((vs, vma))
                        if vma.mo_offset + vma.page_count == old_chunk_mo_offset
                            && vma.perms == base_vma.perms
                            && vma.region_kind == base_vma.region_kind
                            && vma.obj_type == base_vma.obj_type =>
                    {
                        Some((vs, vma))
                    }
                    _ => None,
                };
                match left_validated {
                    Some((vs, vma)) => v_left_info = Some((vs, vma)),
                    None => {
                        unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                        restore_irq(irq);
                        return SyscallResult::err(SyscallError::InvalidArgument);
                    }
                }
                let right_lookup = pt.mappings.lookup(chunk_end);
                let right_candidate = match right_lookup {
                    Some((vs, vma))
                        if vs == chunk_end
                            && vma.mo()
                                == old_mo_obj as *mut crate::cap::memory_object::MemoryObject =>
                    {
                        Some((vs, *vma))
                    }
                    _ => None,
                };
                let right_validated = match right_candidate {
                    Some((vs, vma))
                        if vma.mo_offset == old_chunk_mo_offset + base_vma.page_count
                            && vma.perms == base_vma.perms
                            && vma.region_kind == base_vma.region_kind
                            && vma.obj_type == base_vma.obj_type =>
                    {
                        Some((vs, vma))
                    }
                    _ => None,
                };
                match right_validated {
                    Some((vs, vma)) => v_right_info = Some((vs, vma)),
                    None => {
                        unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                        restore_irq(irq);
                        return SyscallResult::err(SyscallError::InvalidArgument);
                    }
                }
            }
            _ => {
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
        }

        // Reserve rmap ticket on old_mo for the restored V_orig.
        let old_ticket = match (*old_mo_obj).rmap_reserve_slot() {
            Ok(t) => t,
            Err(_) => {
                unlock_fork_pair(parent_vs, child_vs, parent_first, same);
                restore_irq(irq);
                return SyscallResult::err(SyscallError::OutOfMemory);
            }
        };

        // Clear parent COW marks + drop child PTEs from the chunk range.
        parent_vs.undo_fork_range_locked(child_vs, va_start, page_count, bitmap_slice);

        // Rebuild parent VmArea state. All four cases consolidate
        // V_chunk plus any V_left / V_right back into a single V_orig
        // owned by old_mo; only the keys / page-counts / inserts vary.
        let v_orig_start = match (v_left_info, split_kind) {
            (Some((ls, _)), CHUNK_SPLIT_KIND_RIGHT)
            | (Some((ls, _)), CHUNK_SPLIT_KIND_INTERIOR) => ls,
            _ => vma_start,
        };
        let v_orig_pages: u32 = base_vma.page_count
            + v_left_info.map(|(_, v)| v.page_count).unwrap_or(0)
            + v_right_info.map(|(_, v)| v.page_count).unwrap_or(0);
        let v_orig_mo_offset: u32 = match v_left_info {
            Some((_, v)) => v.mo_offset,
            None => match split_kind {
                CHUNK_SPLIT_KIND_LEFT => old_chunk_mo_offset,
                CHUNK_SPLIT_KIND_EXACT => old_chunk_mo_offset,
                _ => old_chunk_mo_offset,
            },
        };

        let mut v_orig = base_vma;
        v_orig.obj = old_mo_obj as *mut crate::cap::KernelObject;
        v_orig.page_count = v_orig_pages;
        v_orig.mo_offset = v_orig_mo_offset;

        match split_kind {
            CHUNK_SPLIT_KIND_EXACT => {
                let replaced = pt.mappings.replace(vma_start, v_orig);
                crate::kernel::bug::kassert!(replaced, "V_chunk vanished mid-undo (Exact)");
            }
            CHUNK_SPLIT_KIND_LEFT => {
                let mut tree_alloc = map_mo_tree_allocator();
                let (v_right_start, _) = v_right_info.expect("LEFT undo missing v_right");
                let removed = pt.mappings.remove(v_right_start, &mut tree_alloc);
                crate::kernel::bug::kassert!(removed, "V_right vanished mid-undo (Left)");
                let replaced = pt.mappings.replace(vma_start, v_orig);
                crate::kernel::bug::kassert!(replaced, "V_chunk vanished mid-undo (Left)");
            }
            CHUNK_SPLIT_KIND_RIGHT => {
                // V_chunk lives at va_start; V_left lives at v_orig_start
                // (which already has the right key). Replace V_left with
                // V_orig (page_count grown to cover full range), then
                // remove V_chunk's standalone entry at va_start.
                let mut tree_alloc = map_mo_tree_allocator();
                let removed = pt.mappings.remove(va_start, &mut tree_alloc);
                crate::kernel::bug::kassert!(removed, "V_chunk vanished mid-undo (Right)");
                let replaced = pt.mappings.replace(v_orig_start, v_orig);
                crate::kernel::bug::kassert!(replaced, "V_left vanished mid-undo (Right)");
            }
            CHUNK_SPLIT_KIND_INTERIOR => {
                let mut tree_alloc = map_mo_tree_allocator();
                let (v_right_start, _) = v_right_info.expect("INTERIOR undo missing v_right");
                let removed_right = pt.mappings.remove(v_right_start, &mut tree_alloc);
                crate::kernel::bug::kassert!(removed_right, "V_right vanished mid-undo (Interior)");
                let removed_chunk = pt.mappings.remove(va_start, &mut tree_alloc);
                crate::kernel::bug::kassert!(removed_chunk, "V_chunk vanished mid-undo (Interior)");
                let replaced = pt.mappings.replace(v_orig_start, v_orig);
                crate::kernel::bug::kassert!(replaced, "V_left vanished mid-undo (Interior)");
            }
            _ => unreachable!(),
        }

        // rmap surgery: drop every per-shape entry the forward fork
        // created, then publish a single old_mo entry covering the
        // merged V_orig.
        (*parent_shadow_mo).rmap_remove(parent_vs as *mut VSpace, va_start);
        if let Some((v_left_start, _)) = v_left_info {
            (*old_mo_obj).rmap_remove(parent_vs as *mut VSpace, v_left_start);
        }
        if let Some((v_right_start, _)) = v_right_info {
            (*old_mo_obj).rmap_remove(parent_vs as *mut VSpace, v_right_start);
        }
        (*old_mo_obj).rmap_add_reserved(
            old_ticket,
            crate::cap::memory_object::ReverseMapEntry {
                vspace: parent_vs as *mut VSpace,
                va_start: v_orig_start,
                page_count: v_orig.page_count,
                mo_offset: v_orig.mo_offset,
                perms: v_orig.perms,
                _pad: [0; 7],
            },
        );

        // Refcount surgery: V_orig retains old_mo (+1); each per-shape
        // VmArea releases its respective owner.
        v_orig.retain_obj_ref();
        let v_chunk_ref = crate::mm::vspace::VmArea {
            obj: parent_shadow_mo as *mut crate::cap::KernelObject,
            mo_offset: 0,
            page_count: 0,
            perms: 0,
            region_kind: 0,
            obj_type: crate::cap::ObjectType::MemoryObject as u8,
            max_prot: 0,
            _pad: [0; 4],
        };
        deferred[deferred_n] = v_chunk_ref;
        deferred_n += 1;
        if v_left_info.is_some() {
            let v_left_ref = crate::mm::vspace::VmArea {
                obj: old_mo_obj as *mut crate::cap::KernelObject,
                mo_offset: 0,
                page_count: 0,
                perms: 0,
                region_kind: 0,
                obj_type: crate::cap::ObjectType::MemoryObject as u8,
                max_prot: 0,
                _pad: [0; 4],
            };
            deferred[deferred_n] = v_left_ref;
            deferred_n += 1;
        }
        if v_right_info.is_some() {
            let v_right_ref = crate::mm::vspace::VmArea {
                obj: old_mo_obj as *mut crate::cap::KernelObject,
                mo_offset: 0,
                page_count: 0,
                perms: 0,
                region_kind: 0,
                obj_type: crate::cap::ObjectType::MemoryObject as u8,
                max_prot: 0,
                _pad: [0; 4],
            };
            deferred[deferred_n] = v_right_ref;
            deferred_n += 1;
        }

        // Drop child meta for the chunk range. The forward fork added a
        // child VmArea + rmap entry; undo removes both.
        //
        // Defensively verify the child VmArea is owned by the
        // `child_mo` cap the caller named: a bug in the journal or a
        // racing remap could otherwise have us tear down an unrelated
        // mapping that just happens to land at `va_start` with
        // matching page_count.
        let child_pt = if !child_vs.tracking.is_null() {
            Some(&mut *child_vs.tracking)
        } else {
            None
        };
        if let Some(child_pt) = child_pt {
            let lookup_data = child_pt
                .mappings
                .lookup(va_start)
                .map(|(cs, cvma)| (cs, *cvma));
            if let Some((cs, cvma_copy)) = lookup_data {
                let child_mo_ptr =
                    child_mo_cap.object as *mut crate::cap::memory_object::MemoryObject;
                if cs == va_start
                    && cvma_copy.page_count as usize == page_count
                    && cvma_copy.mo() == child_mo_ptr
                {
                    let mut tree_alloc = map_mo_tree_allocator();
                    let removed = child_pt.mappings.remove(cs, &mut tree_alloc);
                    if removed {
                        if !child_mo_ptr.is_null() {
                            (*child_mo_ptr).rmap_remove(child_vs as *mut VSpace, cs);
                        }
                        deferred[deferred_n] = cvma_copy;
                        deferred_n += 1;
                        child_pt.note_vma_removed(&cvma_copy);
                    }
                }
            }
        }

        unlock_fork_pair(parent_vs, child_vs, parent_first, same);
        // Release the tree lock before the deferred ref drops (REAPER_LOCK).
        drop(tree_lock);
        restore_irq(irq);
        for i in 0..deferred_n {
            deferred[i].release_obj_ref();
        }
        SyscallResult::ok(0)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ChunkRollbackHeader {
    old_mo: u32,
    page_count: u32,
    /// Offset, in pages, used by the fresh parent-shadow and child
    /// MOs installed by the forward fork. mmsrv normally passes zero
    /// because it allocates region-local fork MOs.
    mo_offset: u32,
    /// Forward fork writes the split form chosen for this chunk
    /// (see `CHUNK_SPLIT_KIND_*`). Undo reads it back to drive the
    /// matching reverse-VmArea path. mmsrv leaves it zero on input.
    split_kind: u32,
    /// Offset, in pages, of this chunk in the original parent old_mo.
    /// Undo cannot infer this from the parent-shadow VmArea because
    /// the shadow MO has its own offset domain.
    old_mo_offset: u32,
}

const CHUNK_SPLIT_KIND_EXACT: u32 = 0;
const CHUNK_SPLIT_KIND_LEFT: u32 = 1;
const CHUNK_SPLIT_KIND_RIGHT: u32 = 2;
const CHUNK_SPLIT_KIND_INTERIOR: u32 = 3;
/// Forward fork found the parent VmArea already pointed at
/// `parent_shadow_mo` (idempotent re-call) and made no parent-side
/// state change. Undo for such a chunk must be a no-op on the parent
/// VmArea — only the child mapping installed by this call (if any) is
/// torn down. Using a distinct code stops a duplicate forward call's
/// rollback from un-doing the *first* fork's parent swap.
const CHUNK_SPLIT_KIND_NONE: u32 = 4;

/// Mirror of `lib/trona/uapi/consts/kernel.rs::MAX_FORK_PAGES`. Constants
/// crossing the syscall ABI must be kept in sync manually (kept-in-sync
/// list lives in `CLAUDE.md`).
const MAX_FORK_PAGES_USIZE: usize = 8192;
const MAX_FORK_BITMAP_BYTES: usize = (MAX_FORK_PAGES_USIZE + 7) / 8;

#[inline]
unsafe fn lock_fork_pair(parent: &VSpace, child: &VSpace, parent_first: bool, same: bool) {
    if parent_first {
        parent.lock.lock();
        if !same {
            child.lock.lock();
        }
    } else {
        child.lock.lock();
        parent.lock.lock();
    }
}

unsafe fn unlock_fork_pair(parent: &VSpace, child: &VSpace, parent_first: bool, same: bool) {
    if parent_first {
        if !same {
            child.lock.unlock();
        }
        parent.lock.unlock();
    } else {
        parent.lock.unlock();
        child.lock.unlock();
    }
}

pub(super) fn syscall_vspace_map_mo(
    cap: &Capability,
    mo_cap_ptr: u64,
    vaddr: u64,
    mo_offset: u64,
    count_and_flags: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }
    if vaddr & 0xFFF != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let mo_cap =
        match lookup_typed_cap_locked(mo_cap_ptr, ObjectType::MemoryObject, CapRights::READ) {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };

    let count = (count_and_flags >> 32) as usize;
    let flags_bits = count_and_flags & 0xFFFF_FFFF;
    let mapping_flags_bits = vspace_map_mo_mapping_flags(flags_bits);
    let demand_only = (flags_bits & VSPACE_MAP_MO_FLAG_DEMAND) != 0;
    let perms = vspace_map_mo_perms(flags_bits);
    let region_kind = vspace_map_mo_region_kind(flags_bits);

    if (mapping_flags_bits & 1 != 0) && (mapping_flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // The mapping's permissions must be backed by the MO cap's rights: a
    // writable mapping requires WRITE, an executable mapping requires
    // EXECUTE (READ is already demanded by the lookup above). Mirrors the
    // device-range rights check, and is what makes a policy-issued cap's
    // rights load-bearing — a READ|EXECUTE exec MO cannot be mapped
    // writable, and only an EXECUTE-bearing MO can back a code mapping.
    if (mapping_flags_bits & 1) != 0 && !mo_cap.has_right(CapRights::WRITE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    if (mapping_flags_bits & 4) != 0 && !mo_cap.has_right(CapRights::EXECUTE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }

    unsafe {
        let mo_ptr = mo_cap.object as *mut crate::cap::memory_object::MemoryObject;
        let vspace = &mut *(cap.object as *mut VSpace);

        let flags = PageFlags {
            writable: mapping_flags_bits & 1 != 0,
            user: mapping_flags_bits & 2 != 0,
            executable: mapping_flags_bits & 4 != 0,
            cache_disable: mapping_flags_bits & 8 != 0,
            write_through: mapping_flags_bits & 16 != 0,
            cow: false,
        };

        let offset = mo_offset as usize;
        if count > 0 && offset + count > (*mo_ptr).page_count as usize {
            return SyscallResult::err(SyscallError::OutOfRange);
        }

        let mut alloc = crate::mm::node_alloc::PmmNodeAllocator {
            owner: crate::mm::frame::FrameOwner::MoMeta {
                mo: mo_ptr,
                subkind: crate::mm::frame::MoMetaKind::Radix,
            },
            use_reserve: false,
        };

        // Acquire the MO's per-tree serialization lock (bound) or per-MO bind
        // lock (standalone) OUTSIDE vspace.lock, so this map serializes against
        // snapshot / downgrade on the same tree. The MO cap keeps the MO — and
        // thus its hierarchy_state — alive, so no extra pin is needed; the
        // choice is re-validated under the lock against a concurrent first
        // snapshot binding the MO.
        let irq = save_irq_disable();
        let outer_lock_ptr: *const crate::mm::SpinLock = loop {
            let state = (*mo_ptr)
                .hierarchy_state
                .load(core::sync::atomic::Ordering::Acquire);
            if state.is_null() {
                (*mo_ptr).hierarchy_bind_lock.lock();
                if (*mo_ptr)
                    .hierarchy_state
                    .load(core::sync::atomic::Ordering::Acquire)
                    .is_null()
                {
                    break &(*mo_ptr).hierarchy_bind_lock as *const crate::mm::SpinLock;
                }
                (*mo_ptr).hierarchy_bind_lock.unlock();
            } else {
                (*state).lock.lock();
                if (*mo_ptr)
                    .hierarchy_state
                    .load(core::sync::atomic::Ordering::Acquire)
                    == state
                {
                    break &(*state).lock as *const crate::mm::SpinLock;
                }
                (*state).lock.unlock();
            }
        };
        vspace.lock.lock();

        let meta_resv = match reserve_vspace_map_mo_metadata_locked(
            vspace,
            mo_ptr,
            vaddr,
            count as u32,
            offset as u32,
            perms,
            region_kind,
        ) {
            Ok(r) => r,
            Err(e) => {
                vspace.lock.unlock();
                (*outer_lock_ptr).unlock();
                restore_irq(irq);
                return SyscallResult::err(e);
            }
        };

        if meta_resv.is_covered() {
            vspace.lock.unlock();
            (*outer_lock_ptr).unlock();
            restore_irq(irq);
            return SyscallResult::ok(count as u64);
        }

        // Read `is_cloned` UNDER the tree lock. `cow_parent` transitions
        // null→non-null only via snapshot / clone, which hold this same tree
        // lock; a read taken before the lock could go stale and let a
        // from-parent (inherited) page map writable. Re-reading here keeps
        // inherited pages CoW by construction.
        let is_cloned = !(*mo_ptr).cow_parent.is_null();

        let mut mapped = 0u64;
        let mut map_error = None;
        for i in 0..count {
            let page_vaddr = vaddr + (i as u64 * crate::mm::PAGE_SIZE as u64);

            if demand_only {
                match vspace.map_demand_locked(page_vaddr, flags) {
                    Ok(()) => {
                        mapped += 1;
                        continue;
                    }
                    Err(_) => break,
                }
            }

            // Eager map only a resident page; every non-resident source
            // (`Zero` anon/shm, `Pager` file-backed, or a `Failed` pager
            // tombstone) is demand-mapped, preserving the eager-resident /
            // demand-rest split. The classifier is the single source of truth.
            if let crate::cap::memory_object::PageSource::Resident {
                mut phys,
                depth,
                untyped_backed: _,
                borrowed,
            } = (*mo_ptr).effective_page_source_locked(offset + i)
            {
                let page_idx = offset + i;
                // Borrowed initrd frames are device memory (not PMM-tracked),
                // so the RAM-ownership check would reject them; they are
                // validated against the immortal device-untyped at populate time.
                if !borrowed && !phys_is_mo_data_or_untyped_ram(phys) {
                    map_error = Some(SyscallError::InvalidArgument);
                    break;
                }

                // Set when the flatten below replaces `phys` with a freshly
                // committed LOCAL frame: that page is then `self`'s own and must
                // map writable, not read-only CoW.
                let mut flattened = false;
                if depth > crate::cap::memory_object::COW_FLATTEN_THRESHOLD {
                    let flatten_owner = crate::mm::frame::FrameOwner::MoData {
                        mo: mo_ptr,
                        page_idx: page_idx as u32,
                    };
                    if let Some(new_phys) = crate::mm::pmm_alloc(&flatten_owner) {
                        let src = crate::mm::phys_to_virt(phys) as *const u8;
                        let dst = crate::mm::phys_to_virt(new_phys) as *mut u8;
                        core::ptr::copy_nonoverlapping(src, dst, crate::mm::PAGE_SIZE);
                        (*mo_ptr).commit_lock.lock();
                        let ok = (*mo_ptr).commit_page(page_idx, new_phys, &mut alloc);
                        (*mo_ptr).commit_lock.unlock();
                        if ok {
                            phys = new_phys;
                            flattened = true;
                        } else {
                            crate::mm::pmm_free(new_phys, &flatten_owner);
                        }
                    }
                }

                // `phys` is from a parent iff it resolved at depth > 0 AND we
                // did not just flatten it into a local frame. Using the local
                // `flattened` flag (not a racy `is_local_committed` re-read)
                // means a concurrent break can never trick this into mapping the
                // stale ancestor frame writable.
                let from_parent = depth > 0 && !flattened;
                let effective = if is_cloned && flags.writable && from_parent {
                    PageFlags {
                        writable: false,
                        cow: true,
                        ..flags
                    }
                } else {
                    flags
                };

                match vspace.map_locked(page_vaddr, phys, effective) {
                    Ok(()) => {
                        // Keep the local resident page's PMM owner aligned
                        // with the MO. Untyped-backed pages also carry their
                        // source untyped in FrameMeta::source_ut, so owner
                        // accuracy no longer conflicts with returning the
                        // page to the carving untyped on release.
                        // Borrowed frames are never PMM-owned: stamping `MoData`
                        // would hand an initrd frame to `pmm_free` on teardown.
                        if depth == 0 && !borrowed {
                            crate::mm::pmm_set_owner(
                                phys,
                                &crate::mm::frame::FrameOwner::MoData {
                                    mo: mo_cap.object
                                        as *mut crate::cap::memory_object::MemoryObject,
                                    page_idx: page_idx as u32,
                                },
                            );
                        }
                        mapped += 1;
                    }
                    Err(_) => break,
                }
            } else {
                match vspace.map_demand_locked(page_vaddr, flags) {
                    Ok(()) => mapped += 1,
                    Err(_) => break,
                }
            }
        }

        commit_or_release_vspace_map_mo_metadata_max_prot_locked(
            meta_resv,
            vspace,
            mo_ptr,
            vaddr,
            mapped as u32,
            offset as u32,
            perms,
            region_kind,
            max_prot_from_cap(&mo_cap),
        );

        vspace.lock.unlock();
        (*outer_lock_ptr).unlock();
        restore_irq(irq);
        if let Some(e) = map_error {
            return SyscallResult::err(e);
        }
        SyscallResult::ok(mapped)
    }
}
