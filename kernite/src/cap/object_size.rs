// SPDX-License-Identifier: GPL-2.0-only
//! Kernel-side helpers for sizing untyped retype carves.
//!
//! Mirrors the per-object byte cost of every retype target. Inputs are
//! the UAPI `KERNITE_OBJ_*` discriminants and the caller-supplied
//! `size_bits` (only meaningful for `Untyped`, `Frame`, `CNode`,
//! `MemoryObject`); outputs are byte counts the retype path then
//! carves out of the parent untyped.
//!
//! With kernite UAPI authored as C headers (no Rust code in the
//! bindgen output) the alloc-bytes helper that used to live in
//! the shared UAPI crate is reimplemented here against the bindgen-
//! generated `KERNITE_*` constants. rsrcsrv reimplements the same
//! logic on its side when it needs quota accounting.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectSizeError {
    InvalidObjType,
    InvalidSizeBits,
}

#[inline]
const fn cnode_alloc_bytes(size_bits: u64) -> Result<u64, ObjectSizeError> {
    let bits = if size_bits == 0 {
        uapi::KERNITE_CNODE_DEFAULT_SIZE_BITS as u64
    } else {
        size_bits
    };
    if bits < uapi::KERNITE_CNODE_MIN_SIZE_BITS as u64
        || bits > uapi::KERNITE_CNODE_MAX_SIZE_BITS as u64
    {
        return Err(ObjectSizeError::InvalidSizeBits);
    }
    Ok(uapi::KERNITE_CNODE_HEADER_BYTES as u64
        + (uapi::KERNITE_CNODE_SLOT_BYTES as u64) * (1u64 << bits))
}

#[inline]
const fn memory_object_alloc_bytes(_size_bits: u64) -> Result<u64, ObjectSizeError> {
    let header = uapi::KERNITE_MO_HEADER_BYTES as u64;
    let page = uapi::KERNITE_PAGE_BYTES as u64;
    Ok((header + page - 1) & !(page - 1))
}

/// Total byte cost of carving a single object of `obj_type` from an
/// untyped, given the caller-supplied `size_bits`.
pub const fn object_alloc_bytes(obj_type: u64, size_bits: u64) -> Result<u64, ObjectSizeError> {
    match obj_type {
        v if v == uapi::KERNITE_OBJ_UNTYPED as u64 => {
            if size_bits < 12 || size_bits > 47 {
                return Err(ObjectSizeError::InvalidSizeBits);
            }
            Ok(1u64 << size_bits)
        }
        v if v == uapi::KERNITE_OBJ_FRAME as u64 => {
            let effective = if size_bits == 0 { 12 } else { size_bits };
            if effective < 12 || effective > 30 {
                return Err(ObjectSizeError::InvalidSizeBits);
            }
            Ok(1u64 << effective)
        }
        v if v == uapi::KERNITE_OBJ_TCB as u64 => Ok(uapi::KERNITE_TCB_BYTES as u64),
        v if v == uapi::KERNITE_OBJ_CNODE as u64 => cnode_alloc_bytes(size_bits),
        v if v == uapi::KERNITE_OBJ_VSPACE as u64 => Ok(uapi::KERNITE_VSPACE_BYTES as u64),
        v if v == uapi::KERNITE_OBJ_IRQ_HANDLER as u64 => {
            Ok(uapi::KERNITE_IRQ_HANDLER_BYTES as u64)
        }
        v if v == uapi::KERNITE_OBJ_IO_PORT as u64 => Ok(uapi::KERNITE_IO_PORT_BYTES as u64),
        v if v == uapi::KERNITE_OBJ_SCHED_CONTEXT as u64 => {
            Ok(uapi::KERNITE_SCHED_CONTEXT_BYTES as u64)
        }
        v if v == uapi::KERNITE_OBJ_MEMORY_OBJECT as u64 => memory_object_alloc_bytes(size_bits),
        // Edge object types — each carved at exactly its
        // `size_of::<T>()` from the parent untyped. The kernel-side
        // asserts in `cap/object_size_assert.rs` keep the header
        // constants and Rust struct sizes lock-stepped.
        v if v == uapi::KERNITE_OBJ_EVENT_QUEUE as u64 => {
            Ok(uapi::KERNITE_EVENT_QUEUE_BYTES as u64)
        }
        v if v == uapi::KERNITE_OBJ_WATCH as u64 => Ok(uapi::KERNITE_WATCH_BYTES as u64),
        v if v == uapi::KERNITE_OBJ_MESSAGE_PIPE as u64 => {
            Ok(uapi::KERNITE_MESSAGE_PIPE_BYTES as u64)
        }
        v if v == uapi::KERNITE_OBJ_MESSAGE_PIPE_CORE as u64 => {
            Ok(uapi::KERNITE_MESSAGE_PIPE_CORE_BYTES as u64)
        }
        v if v == uapi::KERNITE_OBJ_DATA_PIPE as u64 => Ok(uapi::KERNITE_DATA_PIPE_BYTES as u64),
        v if v == uapi::KERNITE_OBJ_DATA_PIPE_CORE as u64 => {
            Ok(uapi::KERNITE_DATA_PIPE_CORE_BYTES as u64)
        }
        v if v == uapi::KERNITE_OBJ_TIMER as u64 => Ok(uapi::KERNITE_TIMER_BYTES as u64),
        v if v == uapi::KERNITE_OBJ_KERNEL_RNG as u64 => Ok(uapi::KERNITE_KERNEL_RNG_BYTES as u64),
        v if v == uapi::KERNITE_OBJ_SYSTEM_CONTROL as u64 => {
            Ok(uapi::KERNITE_SYSTEM_CONTROL_BYTES as u64)
        }
        v if v == uapi::KERNITE_OBJ_CLOCK as u64 => Ok(uapi::KERNITE_CLOCK_BYTES as u64),
        v if v == uapi::KERNITE_OBJ_SYSTEM_INFO as u64 => {
            Ok(uapi::KERNITE_SYSTEM_INFO_BYTES as u64)
        }
        v if v == uapi::KERNITE_OBJ_KERNEL_DEBUG as u64 => {
            Ok(uapi::KERNITE_KERNEL_DEBUG_BYTES as u64)
        }
        v if v == uapi::KERNITE_OBJ_PAGER as u64 => Ok(uapi::KERNITE_PAGER_BYTES as u64),
        v if v == uapi::KERNITE_OBJ_DEVICE_CONTROL as u64 => {
            Ok(uapi::KERNITE_DEVICE_CONTROL_BYTES as u64)
        }
        v if v == uapi::KERNITE_OBJ_VM_HIERARCHY_STATE as u64 => {
            Ok(uapi::KERNITE_VM_HIERARCHY_STATE_BYTES as u64)
        }
        v if v == uapi::KERNITE_OBJ_EXEC_AUTHORITY as u64 => {
            Ok(uapi::KERNITE_EXEC_AUTHORITY_BYTES as u64)
        }
        // A page table is exactly one hardware page (512 PTEs); its metadata is
        // out-of-band (like Frame), so the carve is one page granule.
        v if v == uapi::KERNITE_OBJ_PAGE_TABLE as u64 => Ok(uapi::KERNITE_PAGE_TABLE_BYTES as u64),
        _ => Err(ObjectSizeError::InvalidObjType),
    }
}
