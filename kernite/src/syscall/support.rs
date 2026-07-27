// SPDX-License-Identifier: GPL-2.0-only
//! Shared syscall helper routines.

use super::tcb;
use crate::cap::{CapError, CapRights, Capability, ObjectType};
use crate::mm::vspace::VSpaceError;
use crate::syscall::SyscallError;

pub(crate) fn validate_capability(
    cap: &Capability,
    expected_type: ObjectType,
    required_rights: CapRights,
) -> Result<(), SyscallError> {
    if cap.is_null() {
        return Err(SyscallError::InvalidCapability);
    }
    if expected_type != ObjectType::Null && cap.obj_type != expected_type {
        return Err(SyscallError::InvalidOperation);
    }
    if !cap.has_right(required_rights) {
        return Err(SyscallError::InsufficientRights);
    }
    Ok(())
}

// IPC buffer word-index map. Mirrors the `kernite_ipc_buffer` layout
// declared in `kernite/include/uapi/ipc.h` 1:1; any drift between the
// two forms an ABI break the kernel cannot detect at runtime.
//
// `msg[]` runs from word 0 to word IPC_MSG_WORDS - 1 with the layout
// `[label, length, regs[0..32]]`. Helpers that index into `regs[]`
// add `IPC_MSG_REGS_BASE_WORD` to the regs index to land on the
// matching raw IPC word offset.
pub(crate) const IPC_MSG_WORDS: usize = 34;
pub(crate) const IPC_MSG_REGS_BASE_WORD: usize = 2;
pub(crate) const IPC_BADGE_WORD: usize = IPC_MSG_WORDS;
pub(crate) const IPC_FLAGS_WORD: usize = IPC_BADGE_WORD + 1;
pub(crate) const IPC_CAPS_BASE_WORD: usize = IPC_FLAGS_WORD + 1;
pub(crate) const IPC_RECEIVE_CNODE_WORD: usize = IPC_CAPS_BASE_WORD + 4;
pub(crate) const IPC_RECEIVE_INDEX_WORD: usize = IPC_RECEIVE_CNODE_WORD + 1;
pub(crate) const IPC_RECEIVE_DEPTH_WORD: usize = IPC_RECEIVE_INDEX_WORD + 1;
/// MessagePipe call transaction id word between typed IPC header and reserved payload.
pub(crate) const IPC_MP_TXID_WORD: usize = IPC_RECEIVE_DEPTH_WORD + 1;
/// Reserved payload base after the typed IPC header and MP txid word.
pub(crate) const IPC_RESERVED_BASE_WORD: usize = IPC_MP_TXID_WORD + 1;
// Convention: `reserved[0]` carries the nested receive-slot depth for
// chained cap delivery. Distinct from `IPC_RECEIVE_DEPTH_WORD`, which
// is the per-call receive slot depth surfaced in the typed field.
pub(crate) const IPC_RECEIVE_SLOT_DEPTH_WORD: usize = IPC_RESERVED_BASE_WORD;
/// Word offset of the `received_cap_count` reserved slot. Mirrors
/// UAPI macro `KERNITE_IPC_RESERVED_RECEIVED_CAP_COUNT`
/// (= `reserved[1]`). On every inbound MP_READ / MP_CALL reply the
/// kernel writes the number of caps it installed into `caps[]` so
/// the receiver can locate user-supplied caps without scanning
/// sentinels.
pub(crate) const IPC_RECEIVED_CAP_COUNT_WORD: usize = IPC_RESERVED_BASE_WORD + 1;
/// Word offset of the well-known `kernite_event_record` slot inside
/// the IPC buffer's `reserved[]` area. Mirrors UAPI macro
/// `KERNITE_IPC_RESERVED_EVENT_RECORD_BASE` (= `reserved[2]`). The
/// kernel publishes one record here on every successful
/// `KERNITE_INV_EQ_WAIT` / `KERNITE_INV_EQ_POLL`. The record is 8
/// `u64` words wide.
pub(crate) const IPC_EVENT_RECORD_BASE_WORD: usize = IPC_RESERVED_BASE_WORD + 2;
pub(crate) const IPC_EVENT_RECORD_WORDS: usize = 8;
pub(crate) const IPC_EXT_BASE_WORD: usize = IPC_EVENT_RECORD_BASE_WORD + IPC_EVENT_RECORD_WORDS;
pub(crate) const IPC_TOTAL_WORDS: usize = IPC_RESERVED_BASE_WORD + 468;

pub(crate) unsafe fn current_ipc_buffer_base() -> Result<u64, SyscallError> {
    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if current.is_null() {
        return Err(SyscallError::InvalidOperation);
    }

    let buf = unsafe { (*current).ipc_buffer };
    if buf == 0 {
        return Err(SyscallError::BadAddress);
    }
    tcb::validate_ipc_buffer_addr(buf).map_err(|_| SyscallError::BadAddress)?;
    Ok(buf)
}

pub(crate) unsafe fn copy_from_current_ipc_words(
    base_word: usize,
    dst: &mut [u64],
) -> Result<(), SyscallError> {
    if dst.is_empty() {
        return Ok(());
    }
    if base_word > IPC_TOTAL_WORDS || dst.len() > IPC_TOTAL_WORDS - base_word {
        return Err(SyscallError::BadAddress);
    }

    let base = unsafe { current_ipc_buffer_base()? };
    let addr = base + (base_word as u64 * core::mem::size_of::<u64>() as u64);
    if unsafe {
        crate::arch::uaccess::copy_from_user_bytes(
            addr,
            dst.as_mut_ptr().cast::<u8>(),
            dst.len() * core::mem::size_of::<u64>(),
        )
    } {
        Ok(())
    } else {
        Err(SyscallError::BadAddress)
    }
}

pub(crate) unsafe fn copy_to_current_ipc_words(
    base_word: usize,
    src: &[u64],
) -> Result<(), SyscallError> {
    if src.is_empty() {
        return Ok(());
    }
    if base_word > IPC_TOTAL_WORDS || src.len() > IPC_TOTAL_WORDS - base_word {
        return Err(SyscallError::BadAddress);
    }

    let base = unsafe { current_ipc_buffer_base()? };
    let addr = base + (base_word as u64 * core::mem::size_of::<u64>() as u64);
    if unsafe {
        crate::arch::uaccess::copy_to_user_bytes(
            addr,
            src.as_ptr().cast::<u8>(),
            src.len() * core::mem::size_of::<u64>(),
        )
    } {
        Ok(())
    } else {
        Err(SyscallError::BadAddress)
    }
}

pub(crate) unsafe fn read_current_ipc_word(word: usize) -> Result<u64, SyscallError> {
    let mut value = [0u64; 1];
    unsafe {
        copy_from_current_ipc_words(word, &mut value)?;
    }
    Ok(value[0])
}

pub(crate) unsafe fn write_current_ipc_word(word: usize, value: u64) -> Result<(), SyscallError> {
    unsafe { copy_to_current_ipc_words(word, &[value]) }
}

pub(crate) fn syscall_error_from_vspace_error(err: VSpaceError) -> SyscallError {
    match err {
        VSpaceError::Alignment => SyscallError::InvalidArgument,
        VSpaceError::AlreadyMapped => SyscallError::AlreadyMapped,
        VSpaceError::NotMapped => SyscallError::NotFound,
        VSpaceError::OutOfMemory => SyscallError::OutOfMemory,
        VSpaceError::NotCow => SyscallError::InvalidOperation,
        VSpaceError::InvalidArgument => SyscallError::InvalidArgument,
        VSpaceError::RaceLost => SyscallError::InvalidOperation,
        VSpaceError::PermissionDenied => SyscallError::InsufficientRights,
    }
}

pub(crate) fn syscall_error_from_cap_error(err: CapError) -> SyscallError {
    match err {
        CapError::InvalidSlot | CapError::InvalidArgument => SyscallError::InvalidArgument,
        CapError::SlotEmpty => SyscallError::NotFound,
        CapError::InsufficientRights => SyscallError::InsufficientRights,
        CapError::InsufficientMemory | CapError::OutOfSlots => SyscallError::OutOfMemory,
        CapError::OutOfClasses => SyscallError::OutOfMemory,
        CapError::SlotOccupied => SyscallError::SlotOccupied,
        CapError::HasChildren => SyscallError::InvalidOperation,
        _ => SyscallError::InvalidOperation,
    }
}
