// SPDX-License-Identifier: GPL-2.0-only
//! Compile-time refinement: kernel struct sizes match the kernite UAPI
//! `KERNITE_*_BYTES` constants in `kernite/include/uapi/object.h`.
//!
//! Each assert below fires at compile time if a kernel struct's
//! `size_of::<T>()` (or a sizing helper) drifts from the C-header
//! constant. To fix a failure: read the live `size_of::<T>()` and
//! update the matching `KERNITE_*_BYTES` macro in the header.
//!
//! The new-edge object types (EventQueue / Watch / MessagePipe /
//! DataPipe / Timer / system caps) carry a placeholder zero in the
//! header until their layouts stabilise; their drift checks come back
//! online once those constants are set.

use crate::cap::IoPortRange;
use crate::cap::cnode::{
    CNODE_DEFAULT_SIZE_BITS, CNODE_MAX_SIZE_BITS, CNODE_MIN_SIZE_BITS, CNode, CapRef,
};
use crate::cap::memory_object::{MemoryObject, VmHierarchyState};
use crate::cap::pager::Pager;
use crate::cap::{ObjectSizeError, ObjectType, object_alloc_bytes};
use crate::event::irq::IrqHandler;
use crate::mm::PAGE_SIZE;
use crate::mm::vspace::{VSPACE_OBJECT_SIZE, VSPACE_TRACKING_SIZE};
use crate::sched::thread::{SchedContext, Tcb};

// ---------------------------------------------------------------------------
// ObjectType discriminants must match KERNITE_OBJ_* exactly. The enum
// declaration in `object.rs` already pins each variant to the UAPI
// value; these asserts catch any future hand-edit that drifts.
// ---------------------------------------------------------------------------

const _: () = assert!(
    ObjectType::Untyped as u8 as u64 == uapi::KERNITE_OBJ_UNTYPED as u64,
    "OBJ_UNTYPED literal drift"
);
const _: () = assert!(
    ObjectType::Tcb as u8 as u64 == uapi::KERNITE_OBJ_TCB as u64,
    "OBJ_TCB literal drift"
);
const _: () = assert!(
    ObjectType::CNode as u8 as u64 == uapi::KERNITE_OBJ_CNODE as u64,
    "OBJ_CNODE literal drift"
);
const _: () = assert!(
    ObjectType::VSpace as u8 as u64 == uapi::KERNITE_OBJ_VSPACE as u64,
    "OBJ_VSPACE literal drift"
);
const _: () = assert!(
    ObjectType::Frame as u8 as u64 == uapi::KERNITE_OBJ_FRAME as u64,
    "OBJ_FRAME literal drift"
);
const _: () = assert!(
    ObjectType::IrqHandler as u8 as u64 == uapi::KERNITE_OBJ_IRQ_HANDLER as u64,
    "OBJ_IRQ_HANDLER literal drift"
);
const _: () = assert!(
    ObjectType::IoPort as u8 as u64 == uapi::KERNITE_OBJ_IO_PORT as u64,
    "OBJ_IO_PORT literal drift"
);
const _: () = assert!(
    ObjectType::SchedContext as u8 as u64 == uapi::KERNITE_OBJ_SCHED_CONTEXT as u64,
    "OBJ_SCHED_CONTEXT literal drift"
);
const _: () = assert!(
    ObjectType::MemoryObject as u8 as u64 == uapi::KERNITE_OBJ_MEMORY_OBJECT as u64,
    "OBJ_MEMORY_OBJECT literal drift"
);
const _: () = assert!(
    ObjectType::Pager as u8 as u64 == uapi::KERNITE_OBJ_PAGER as u64,
    "OBJ_PAGER literal drift"
);
const _: () = assert!(
    ObjectType::DeviceControl as u8 as u64 == uapi::KERNITE_OBJ_DEVICE_CONTROL as u64,
    "OBJ_DEVICE_CONTROL literal drift"
);
const _: () = assert!(
    ObjectType::VmHierarchyState as u8 as u64 == uapi::KERNITE_OBJ_VM_HIERARCHY_STATE as u64,
    "OBJ_VM_HIERARCHY_STATE literal drift"
);
const _: () = assert!(
    ObjectType::ExecAuthority as u8 as u64 == uapi::KERNITE_OBJ_EXEC_AUTHORITY as u64,
    "OBJ_EXEC_AUTHORITY literal drift"
);
const _: () = assert!(
    ObjectType::PageTable as u8 as u64 == uapi::KERNITE_OBJ_PAGE_TABLE as u64,
    "OBJ_PAGE_TABLE literal drift"
);

// ---------------------------------------------------------------------------
// Page size — UAPI must mirror the kernel's PAGE_SIZE.
// ---------------------------------------------------------------------------

const _: () = assert!(
    PAGE_SIZE as u64 == uapi::KERNITE_PAGE_BYTES as u64,
    "KERNITE_PAGE_BYTES drift from kernite::mm::PAGE_SIZE"
);
const _: () = assert!(
    PAGE_SIZE as u64 == uapi::KERNITE_PAGE_TABLE_BYTES as u64,
    "KERNITE_PAGE_TABLE_BYTES drift from kernite::mm::PAGE_SIZE"
);

// ---------------------------------------------------------------------------
// CNode bounds.
// ---------------------------------------------------------------------------

const _: () = assert!(
    CNODE_DEFAULT_SIZE_BITS as u64 == uapi::KERNITE_CNODE_DEFAULT_SIZE_BITS as u64,
    "CNODE_DEFAULT_SIZE_BITS drift"
);
const _: () = assert!(
    CNODE_MIN_SIZE_BITS as u64 == uapi::KERNITE_CNODE_MIN_SIZE_BITS as u64,
    "CNODE_MIN_SIZE_BITS drift"
);
const _: () = assert!(
    CNODE_MAX_SIZE_BITS as u64 == uapi::KERNITE_CNODE_MAX_SIZE_BITS as u64,
    "CNODE_MAX_SIZE_BITS drift"
);

// ---------------------------------------------------------------------------
// Fixed-layout struct sizes.
//
// Encoded as `[(); EXPECTED] = [(); ACTUAL]`. When they disagree, rustc
// prints "expected an array with a fixed size of EXPECTED elements,
// found one with ACTUAL elements" — both numbers visible in the error
// so the fix is just "set KERNITE_TCB_BYTES = <ACTUAL>" in the header.
// ---------------------------------------------------------------------------

const _: [(); uapi::KERNITE_TCB_BYTES as usize] = [(); core::mem::size_of::<Tcb>()];
const _: [(); uapi::KERNITE_SCHED_CONTEXT_BYTES as usize] =
    [(); core::mem::size_of::<SchedContext>()];
const _: [(); uapi::KERNITE_IRQ_HANDLER_BYTES as usize] = [(); core::mem::size_of::<IrqHandler>()];
const _: [(); uapi::KERNITE_IO_PORT_BYTES as usize] = [(); core::mem::size_of::<IoPortRange>()];

// ---------------------------------------------------------------------------
// CNode header + slot.
// ---------------------------------------------------------------------------

const _: [(); uapi::KERNITE_CNODE_HEADER_BYTES as usize] = [(); core::mem::size_of::<CNode>()];
const _: [(); uapi::KERNITE_CNODE_SLOT_BYTES as usize] = [(); core::mem::size_of::<CapRef>()];

// ---------------------------------------------------------------------------
// VSpace — both the tracking-only constant and the composite.
// ---------------------------------------------------------------------------

const _: [(); uapi::KERNITE_VSPACE_TRACKING_BYTES as usize] = [(); VSPACE_TRACKING_SIZE];
const _: () = assert!(
    VSPACE_OBJECT_SIZE as u64 == uapi::KERNITE_VSPACE_BYTES as u64,
    "KERNITE_VSPACE_BYTES drift from VSPACE_OBJECT_SIZE"
);
const _: () = assert!(
    VSPACE_OBJECT_SIZE == PAGE_SIZE + VSPACE_TRACKING_SIZE,
    "VSPACE_OBJECT_SIZE != PAGE_SIZE + VSPACE_TRACKING_SIZE — kernel arithmetic drift"
);

// ---------------------------------------------------------------------------
// MemoryObject — header equality.
// ---------------------------------------------------------------------------

const _: [(); uapi::KERNITE_MO_HEADER_BYTES as usize] = [(); MemoryObject::required_bytes(0)];

// ---------------------------------------------------------------------------
// VmHierarchyState — per-COW-tree lock object, carved exactly.
// ---------------------------------------------------------------------------

const _: [(); uapi::KERNITE_VM_HIERARCHY_STATE_BYTES as usize] =
    [(); core::mem::size_of::<VmHierarchyState>()];

// ---------------------------------------------------------------------------
// Edge-object structs must fit within a page. `object_alloc_bytes`
// carves a `KERNITE_PAGE_BYTES`-sized chunk for each, so a struct
// that exceeds the page would either spill into the next object or
// panic the carve helper.
// ---------------------------------------------------------------------------

const _: [(); uapi::KERNITE_EVENT_QUEUE_BYTES as usize] =
    [(); core::mem::size_of::<crate::event::event_queue::EventQueue>()];
const _: [(); uapi::KERNITE_WATCH_BYTES as usize] =
    [(); core::mem::size_of::<crate::event::watch::Watch>()];
const _: [(); uapi::KERNITE_MESSAGE_PIPE_BYTES as usize] =
    [(); core::mem::size_of::<crate::ipc::message_pipe::MessagePipe>()];
const _: [(); uapi::KERNITE_MESSAGE_PIPE_CORE_BYTES as usize] =
    [(); core::mem::size_of::<crate::ipc::message_pipe::MessagePipeCore>()];
const _: [(); uapi::KERNITE_DATA_PIPE_BYTES as usize] =
    [(); core::mem::size_of::<crate::ipc::data_pipe::DataPipe>()];
const _: [(); uapi::KERNITE_DATA_PIPE_CORE_BYTES as usize] =
    [(); core::mem::size_of::<crate::ipc::data_pipe::DataPipeCore>()];
const _: [(); uapi::KERNITE_TIMER_BYTES as usize] =
    [(); core::mem::size_of::<crate::event::timer::Timer>()];
const _: [(); uapi::KERNITE_PAGER_BYTES as usize] = [(); core::mem::size_of::<Pager>()];
const _: [(); uapi::KERNITE_KERNEL_RNG_BYTES as usize] =
    [(); core::mem::size_of::<crate::cap::system::KernelRng>()];
const _: [(); uapi::KERNITE_SYSTEM_CONTROL_BYTES as usize] =
    [(); core::mem::size_of::<crate::cap::system::SystemControl>()];
const _: [(); uapi::KERNITE_CLOCK_BYTES as usize] =
    [(); core::mem::size_of::<crate::cap::system::Clock>()];
const _: [(); uapi::KERNITE_SYSTEM_INFO_BYTES as usize] =
    [(); core::mem::size_of::<crate::cap::system::SystemInfo>()];
const _: [(); uapi::KERNITE_KERNEL_DEBUG_BYTES as usize] =
    [(); core::mem::size_of::<crate::cap::system::KernelDebug>()];
const _: [(); uapi::KERNITE_DEVICE_CONTROL_BYTES as usize] =
    [(); core::mem::size_of::<crate::cap::system::DeviceControl>()];
const _: [(); uapi::KERNITE_EXEC_AUTHORITY_BYTES as usize] =
    [(); core::mem::size_of::<crate::cap::system::ExecAuthority>()];

// ---------------------------------------------------------------------------
// Round-trip: kernel `object_alloc_bytes` agrees with the UAPI
// constants for every accepted object type.
// ---------------------------------------------------------------------------

const fn unwrap_u64(r: Result<u64, ObjectSizeError>) -> u64 {
    match r {
        Ok(v) => v,
        Err(_) => {
            panic!("object_alloc_bytes returned Err for an input the assert expected to accept")
        }
    }
}

const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_VSPACE as u64, 0))
        == uapi::KERNITE_VSPACE_BYTES as u64,
    "object_alloc_bytes(OBJ_VSPACE, 0) != KERNITE_VSPACE_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_TCB as u64, 0))
        == uapi::KERNITE_TCB_BYTES as u64,
    "object_alloc_bytes(OBJ_TCB, 0) != KERNITE_TCB_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(
        uapi::KERNITE_OBJ_SCHED_CONTEXT as u64,
        0
    )) == uapi::KERNITE_SCHED_CONTEXT_BYTES as u64,
    "object_alloc_bytes(OBJ_SCHED_CONTEXT, 0) != KERNITE_SCHED_CONTEXT_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_IRQ_HANDLER as u64, 0))
        == uapi::KERNITE_IRQ_HANDLER_BYTES as u64,
    "object_alloc_bytes(OBJ_IRQ_HANDLER, 0) != KERNITE_IRQ_HANDLER_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_IO_PORT as u64, 0))
        == uapi::KERNITE_IO_PORT_BYTES as u64,
    "object_alloc_bytes(OBJ_IO_PORT, 0) != KERNITE_IO_PORT_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_FRAME as u64, 0))
        == uapi::KERNITE_PAGE_BYTES as u64,
    "object_alloc_bytes(OBJ_FRAME, 0) != KERNITE_PAGE_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_FRAME as u64, 21)) == (1u64 << 21),
    "object_alloc_bytes(OBJ_FRAME, 21) != 2 MiB"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_UNTYPED as u64, 20)) == (1u64 << 20),
    "object_alloc_bytes(OBJ_UNTYPED, 20) != 1 MiB"
);

// Edge object round-trips: same byte counts everywhere — UAPI
// header, `object_alloc_bytes`, and the retype-path
// `cap/untyped.rs::object_size` (which delegates to
// `object_alloc_bytes`).
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_EVENT_QUEUE as u64, 0))
        == uapi::KERNITE_EVENT_QUEUE_BYTES as u64,
    "object_alloc_bytes(OBJ_EVENT_QUEUE, 0) != KERNITE_EVENT_QUEUE_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_WATCH as u64, 0))
        == uapi::KERNITE_WATCH_BYTES as u64,
    "object_alloc_bytes(OBJ_WATCH, 0) != KERNITE_WATCH_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_MESSAGE_PIPE as u64, 0))
        == uapi::KERNITE_MESSAGE_PIPE_BYTES as u64,
    "object_alloc_bytes(OBJ_MESSAGE_PIPE, 0) != KERNITE_MESSAGE_PIPE_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(
        uapi::KERNITE_OBJ_MESSAGE_PIPE_CORE as u64,
        0
    )) == uapi::KERNITE_MESSAGE_PIPE_CORE_BYTES as u64,
    "object_alloc_bytes(OBJ_MESSAGE_PIPE_CORE, 0) != KERNITE_MESSAGE_PIPE_CORE_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_DATA_PIPE as u64, 0))
        == uapi::KERNITE_DATA_PIPE_BYTES as u64,
    "object_alloc_bytes(OBJ_DATA_PIPE, 0) != KERNITE_DATA_PIPE_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(
        uapi::KERNITE_OBJ_DATA_PIPE_CORE as u64,
        0
    )) == uapi::KERNITE_DATA_PIPE_CORE_BYTES as u64,
    "object_alloc_bytes(OBJ_DATA_PIPE_CORE, 0) != KERNITE_DATA_PIPE_CORE_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_TIMER as u64, 0))
        == uapi::KERNITE_TIMER_BYTES as u64,
    "object_alloc_bytes(OBJ_TIMER, 0) != KERNITE_TIMER_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_KERNEL_RNG as u64, 0))
        == uapi::KERNITE_KERNEL_RNG_BYTES as u64,
    "object_alloc_bytes(OBJ_KERNEL_RNG, 0) != KERNITE_KERNEL_RNG_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(
        uapi::KERNITE_OBJ_SYSTEM_CONTROL as u64,
        0
    )) == uapi::KERNITE_SYSTEM_CONTROL_BYTES as u64,
    "object_alloc_bytes(OBJ_SYSTEM_CONTROL, 0) != KERNITE_SYSTEM_CONTROL_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_CLOCK as u64, 0))
        == uapi::KERNITE_CLOCK_BYTES as u64,
    "object_alloc_bytes(OBJ_CLOCK, 0) != KERNITE_CLOCK_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_SYSTEM_INFO as u64, 0))
        == uapi::KERNITE_SYSTEM_INFO_BYTES as u64,
    "object_alloc_bytes(OBJ_SYSTEM_INFO, 0) != KERNITE_SYSTEM_INFO_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_KERNEL_DEBUG as u64, 0))
        == uapi::KERNITE_KERNEL_DEBUG_BYTES as u64,
    "object_alloc_bytes(OBJ_KERNEL_DEBUG, 0) != KERNITE_KERNEL_DEBUG_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_PAGER as u64, 0))
        == uapi::KERNITE_PAGER_BYTES as u64,
    "object_alloc_bytes(OBJ_PAGER, 0) != KERNITE_PAGER_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(
        uapi::KERNITE_OBJ_DEVICE_CONTROL as u64,
        0
    )) == uapi::KERNITE_DEVICE_CONTROL_BYTES as u64,
    "object_alloc_bytes(OBJ_DEVICE_CONTROL, 0) != KERNITE_DEVICE_CONTROL_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(
        uapi::KERNITE_OBJ_VM_HIERARCHY_STATE as u64,
        0
    )) == uapi::KERNITE_VM_HIERARCHY_STATE_BYTES as u64,
    "object_alloc_bytes(OBJ_VM_HIERARCHY_STATE, 0) != KERNITE_VM_HIERARCHY_STATE_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(
        uapi::KERNITE_OBJ_EXEC_AUTHORITY as u64,
        0
    )) == uapi::KERNITE_EXEC_AUTHORITY_BYTES as u64,
    "object_alloc_bytes(OBJ_EXEC_AUTHORITY, 0) != KERNITE_EXEC_AUTHORITY_BYTES"
);
const _: () = assert!(
    unwrap_u64(object_alloc_bytes(uapi::KERNITE_OBJ_PAGE_TABLE as u64, 0))
        == uapi::KERNITE_PAGE_TABLE_BYTES as u64,
    "object_alloc_bytes(OBJ_PAGE_TABLE, 0) != KERNITE_PAGE_TABLE_BYTES"
);
