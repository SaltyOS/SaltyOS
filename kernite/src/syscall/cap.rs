// SPDX-License-Identifier: GPL-2.0-only
//! Capability-object syscall handlers.

use super::cspace::with_cap_lock;
use super::{
    CNode, CapRights, Capability, ObjectType, SyscallError, SyscallResult,
    copy_to_current_ipc_words, resolve_cnode_copy_request, resolve_cnode_move_request,
    resolve_cnode_write_request, resolve_untyped_reset_request, resolve_untyped_retype_request,
    syscall_error_from_cap_error, validate_capability,
};

#[inline]
unsafe fn with_cap_lock_syscall(f: impl FnOnce() -> SyscallResult) -> SyscallResult {
    unsafe { with_cap_lock(f) }
}

pub(super) fn syscall_cnode_copy(
    cap: &Capability,
    src_slot: u64,
    dest_cnode_cap_ptr: u64,
    dest_slot: u64,
    rights_bits: u64,
) -> SyscallResult {
    unsafe {
        let src_root = &*(cap.object as *const CNode);
        with_cap_lock_syscall(|| {
            let request = match resolve_cnode_copy_request(
                src_root,
                src_slot,
                dest_cnode_cap_ptr,
                dest_slot,
                rights_bits,
            ) {
                Ok(v) => v,
                Err(e) => return SyscallResult::err(e),
            };
            match request.copy() {
                Ok(()) => SyscallResult::ok(0),
                Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
            }
        })
    }
}

pub(super) fn syscall_cnode_mint(
    cap: &Capability,
    src_slot: u64,
    dest_cnode_cap_ptr: u64,
    dest_slot: u64,
    badge: u64,
) -> SyscallResult {
    let minted_rights = (uapi::KERNITE_RIGHT_ALL & !uapi::KERNITE_RIGHT_GRANT) as u64;
    unsafe {
        let src_root = &*(cap.object as *const CNode);
        with_cap_lock_syscall(|| {
            let request = match resolve_cnode_copy_request(
                src_root,
                src_slot,
                dest_cnode_cap_ptr,
                dest_slot,
                minted_rights,
            ) {
                Ok(v) => v,
                Err(e) => return SyscallResult::err(e),
            };
            match request.mint(badge) {
                Ok(()) => SyscallResult::ok(0),
                Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
            }
        })
    }
}

pub(super) fn syscall_cnode_move(
    cap: &Capability,
    dest_slot: u64,
    src_cnode_cap_ptr: u64,
    src_slot: u64,
) -> SyscallResult {
    unsafe {
        let dest_root = &*(cap.object as *const CNode);
        with_cap_lock_syscall(|| {
            let request =
                match resolve_cnode_move_request(dest_root, dest_slot, src_cnode_cap_ptr, src_slot)
                {
                    Ok(v) => v,
                    Err(e) => return SyscallResult::err(e),
                };
            match request.move_slot() {
                Ok(()) => SyscallResult::ok(0),
                Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
            }
        })
    }
}

pub(super) fn syscall_cnode_mutate(
    cap: &Capability,
    dest_slot: u64,
    src_cnode_cap_ptr: u64,
    src_slot: u64,
    badge: u64,
) -> SyscallResult {
    unsafe {
        let dest_root = &*(cap.object as *const CNode);
        with_cap_lock_syscall(|| {
            let request =
                match resolve_cnode_move_request(dest_root, dest_slot, src_cnode_cap_ptr, src_slot)
                {
                    Ok(v) => v,
                    Err(e) => return SyscallResult::err(e),
                };
            match request.mutate(badge) {
                Ok(()) => SyscallResult::ok(0),
                Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
            }
        })
    }
}

pub(super) fn syscall_cnode_delete(cap: &Capability, slot: u64) -> SyscallResult {
    if !cap.has_right(CapRights::WRITE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    unsafe {
        let cnode_root = &*(cap.object as *const CNode);
        with_cap_lock_syscall(|| {
            let request = match resolve_cnode_write_request(cnode_root, slot) {
                Ok(v) => v,
                Err(e) => return SyscallResult::err(e),
            };
            match request.delete() {
                Ok(()) => SyscallResult::ok(0),
                Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
            }
        })
    }
}

pub(super) fn syscall_cnode_revoke(cap: &Capability, slot: u64) -> SyscallResult {
    if !cap.has_right(CapRights::WRITE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    unsafe {
        let cnode_root = &*(cap.object as *const CNode);
        with_cap_lock_syscall(|| {
            let request = match resolve_cnode_write_request(cnode_root, slot) {
                Ok(v) => v,
                Err(e) => return SyscallResult::err(e),
            };
            match request.revoke() {
                Ok(()) => SyscallResult::ok(0),
                Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
            }
        })
    }
}

pub(super) fn syscall_cnode_set_guard(
    cap: &Capability,
    guard: u64,
    guard_bits: u64,
) -> SyscallResult {
    if !cap.has_right(CapRights::WRITE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    if guard_bits > 64 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    unsafe {
        with_cap_lock_syscall(|| {
            let cnode = &mut *(cap.object as *mut CNode);
            let num_slots = cnode.num_slots();
            for i in 0..num_slots {
                if !cnode.is_slot_empty(i) {
                    return SyscallResult::err(SyscallError::InvalidOperation);
                }
            }
            cnode.guard = guard;
            cnode.guard_bits = guard_bits as u8;
            SyscallResult::ok(0)
        })
    }
}

pub(super) fn syscall_cnode_get_info(cap: &Capability) -> SyscallResult {
    if !cap.has_right(CapRights::READ) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    unsafe {
        let (guard, guard_bits, size_bits, num_slots) = with_cap_lock(|| {
            let cnode = &*(cap.object as *const CNode);
            (
                cnode.guard,
                cnode.guard_bits as u64,
                cnode.header.size_bits as u64,
                cnode.num_slots() as u64,
            )
        });
        if let Err(err) = copy_to_current_ipc_words(0, &[guard, guard_bits, size_bits, num_slots]) {
            return SyscallResult::err(err);
        }
        SyscallResult::ok(0)
    }
}

pub(super) fn syscall_untyped_retype(
    cap: &Capability,
    cap_ptr: u64,
    new_type_raw: u64,
    size_bits: u64,
    dest_offset: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Untyped, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // Type discriminants must match `kernite/include/uapi/object.h`
    // (KERNITE_OBJ_*) exactly — the userland retype call passes the
    // UAPI value verbatim. Adding a new object type here without
    // updating the C header (or vice versa) is an ABI break.
    let type_byte = new_type_raw & 0xFF;
    let new_type = match type_byte {
        1 => ObjectType::Untyped,
        2 => ObjectType::Tcb,
        3 => ObjectType::CNode,
        4 => ObjectType::VSpace,
        5 => ObjectType::Frame,
        6 => ObjectType::IrqHandler,
        7 => ObjectType::IoPort,
        8 => ObjectType::SchedContext,
        9 => ObjectType::MemoryObject,
        10 => ObjectType::EventQueue,
        11 => ObjectType::Watch,
        12 => ObjectType::MessagePipe,
        13 => ObjectType::DataPipe,
        14 => ObjectType::Timer,
        15 => ObjectType::KernelRng,
        16 => ObjectType::SystemControl,
        17 => ObjectType::Clock,
        18 => ObjectType::SystemInfo,
        19 => ObjectType::KernelDebug,
        20 => ObjectType::MessagePipeCore,
        21 => ObjectType::DataPipeCore,
        23 => ObjectType::Pager,
        24 => ObjectType::DeviceControl,
        25 => ObjectType::VmHierarchyState,
        26 => ObjectType::ExecAuthority,
        27 => ObjectType::PageTable,
        _ => return SyscallResult::err(SyscallError::InvalidArgument),
    };
    // This is a pure wire->ObjectType translation. Whether a type may actually
    // be created from untyped is the policy of `ObjectType::is_retypeable_from_untyped()`,
    // enforced at the `UntypedMemory::retype` primitive — authority types
    // (system caps, DeviceControl, IrqHandler, IoPort, ExecAuthority) decode
    // fine here but are rejected there, so they cannot be forged from untyped.
    let create_kind = match (new_type_raw >> 8) & 0xFF {
        0 => crate::cap::memory_object::MoKind::Anon,
        1 => crate::cap::memory_object::MoKind::CowChild,
        2 => crate::cap::memory_object::MoKind::FileBacked,
        3 => crate::cap::memory_object::MoKind::Shm,
        _ => return SyscallResult::err(SyscallError::InvalidArgument),
    };

    unsafe {
        with_cap_lock_syscall(|| {
            let current_tcb = crate::sched::scheduler::scheduler().current();
            if current_tcb.is_null() {
                return SyscallResult::err(SyscallError::InvalidOperation);
            }

            let request = match resolve_untyped_retype_request(current_tcb, cap_ptr, dest_offset) {
                Ok(request) => request,
                Err(e) => return SyscallResult::err(e),
            };

            match request.retype(new_type, size_bits as u8, create_kind) {
                Ok(()) => SyscallResult::ok(0),
                Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
            }
        })
    }
}

pub(super) fn syscall_untyped_reset(cap: &Capability, cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Untyped, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    unsafe {
        with_cap_lock_syscall(|| {
            let current_tcb = crate::sched::scheduler::scheduler().current();
            if current_tcb.is_null() {
                return SyscallResult::err(SyscallError::InvalidOperation);
            }

            let request = match resolve_untyped_reset_request(current_tcb, cap_ptr) {
                Ok(slot) => slot,
                Err(e) => return SyscallResult::err(e),
            };

            match request.reset() {
                Ok(()) => SyscallResult::ok(0),
                Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
            }
        })
    }
}
