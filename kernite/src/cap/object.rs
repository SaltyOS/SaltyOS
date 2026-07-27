// SPDX-License-Identifier: GPL-2.0-only
//! Kernel Objects

use core::sync::atomic::AtomicU32;

/// Kernel object types.
///
/// Discriminants are taken straight from the kernite UAPI
/// (`KERNITE_OBJ_*`) so the kernel-internal enum and the wire-visible
/// retype target value share a single integer.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjectType {
    Null = 0,
    Untyped = uapi::KERNITE_OBJ_UNTYPED as u8,
    Tcb = uapi::KERNITE_OBJ_TCB as u8,
    CNode = uapi::KERNITE_OBJ_CNODE as u8,
    VSpace = uapi::KERNITE_OBJ_VSPACE as u8,
    Frame = uapi::KERNITE_OBJ_FRAME as u8,
    IrqHandler = uapi::KERNITE_OBJ_IRQ_HANDLER as u8,
    IoPort = uapi::KERNITE_OBJ_IO_PORT as u8,
    SchedContext = uapi::KERNITE_OBJ_SCHED_CONTEXT as u8,
    MemoryObject = uapi::KERNITE_OBJ_MEMORY_OBJECT as u8,
    EventQueue = uapi::KERNITE_OBJ_EVENT_QUEUE as u8,
    Watch = uapi::KERNITE_OBJ_WATCH as u8,
    MessagePipe = uapi::KERNITE_OBJ_MESSAGE_PIPE as u8,
    DataPipe = uapi::KERNITE_OBJ_DATA_PIPE as u8,
    Timer = uapi::KERNITE_OBJ_TIMER as u8,
    KernelRng = uapi::KERNITE_OBJ_KERNEL_RNG as u8,
    SystemControl = uapi::KERNITE_OBJ_SYSTEM_CONTROL as u8,
    Clock = uapi::KERNITE_OBJ_CLOCK as u8,
    SystemInfo = uapi::KERNITE_OBJ_SYSTEM_INFO as u8,
    KernelDebug = uapi::KERNITE_OBJ_KERNEL_DEBUG as u8,
    MessagePipeCore = uapi::KERNITE_OBJ_MESSAGE_PIPE_CORE as u8,
    DataPipeCore = uapi::KERNITE_OBJ_DATA_PIPE_CORE as u8,
    Pager = uapi::KERNITE_OBJ_PAGER as u8,
    DeviceControl = uapi::KERNITE_OBJ_DEVICE_CONTROL as u8,
    VmHierarchyState = uapi::KERNITE_OBJ_VM_HIERARCHY_STATE as u8,
    /// Authority token: possession permits `mo_mark_executable`, which
    /// confers EXECUTE on a code MemoryObject. A bare `KernelObject` header.
    ExecAuthority = uapi::KERNITE_OBJ_EXEC_AUTHORITY as u8,
    /// A userland-provided hardware page table for `VSPACE_MAP_PT`. Distinct
    /// from `Frame` so it can never be data-mapped (which would let userland
    /// forge PTEs); its metadata is out-of-band like `FrameObject`.
    PageTable = uapi::KERNITE_OBJ_PAGE_TABLE as u8,
}

impl ObjectType {
    /// Whether `UntypedMemory::retype` may create this type from a process's
    /// own untyped. Resource / memory / IPC / per-binding-role objects are
    /// user-creatable; authority and control objects are NOT — they are
    /// kernel-minted at boot (delegated by `cnode_copy`) or minted by the
    /// `DeviceControl` authority, so possession of untyped can never forge
    /// them (system shutdown, device I/O, conferring EXECUTE).
    ///
    /// The match is intentionally exhaustive — no wildcard — so a newly added
    /// object type must explicitly declare its retypeability here. That
    /// compile-time forcing function is what prevents an authority type from
    /// silently becoming forgeable from untyped.
    pub fn is_retypeable_from_untyped(self) -> bool {
        match self {
            ObjectType::Untyped
            | ObjectType::Tcb
            | ObjectType::CNode
            | ObjectType::VSpace
            | ObjectType::Frame
            | ObjectType::SchedContext
            | ObjectType::MemoryObject
            | ObjectType::EventQueue
            | ObjectType::Watch
            | ObjectType::MessagePipe
            | ObjectType::MessagePipeCore
            | ObjectType::DataPipe
            | ObjectType::DataPipeCore
            | ObjectType::Timer
            | ObjectType::Pager
            | ObjectType::VmHierarchyState
            | ObjectType::PageTable => true,

            // Authority / control objects — kernel- or DeviceControl-minted
            // only. IrqHandler / IoPort flow from `DeviceControl::create_*`
            // (the seL4 IRQControl / IOPortControl model), never generic retype.
            ObjectType::KernelRng
            | ObjectType::SystemControl
            | ObjectType::Clock
            | ObjectType::SystemInfo
            | ObjectType::KernelDebug
            | ObjectType::DeviceControl
            | ObjectType::IrqHandler
            | ObjectType::IoPort
            | ObjectType::ExecAuthority => false,

            ObjectType::Null => false,
        }
    }
}

/// Base kernel object header with inline reference count
///
/// All kernel objects start with this header.
/// `parent_ut` and the `hlist`-style sibling links anchor every object in
/// its source `UntypedMemory`'s child registry; provenance and child
/// tracking live on the object so two caps to the same untyped cannot
/// disagree about who owns what.
#[repr(C)]
pub struct KernelObject {
    /// Object type
    pub obj_type: ObjectType,

    /// Size in bits (for memory objects)
    pub size_bits: u8,

    /// Reference count covering every live owner — both capability handles
    /// and kernel-internal references (e.g. `MemoryObject.cow_parent` raw
    /// pointers held under refcount). The reaper drops the object only when
    /// this hits zero, so internal owners must `increment_refcount` /
    /// `release_object` symmetrically.
    pub ref_count: AtomicU32,

    /// Intrusive reaper link.
    ///
    /// Guarded by `object::REAPER_LOCK`. Low bit = queued flag, remaining
    /// bits = next pointer while queued for deferred final cleanup.
    pub reaper_link: u64,

    /// Source `UntypedMemory` that carved this object. Null for root
    /// untypeds (`init.rs`-installed) and for objects that live in static
    /// kernel storage. Set in retype's terminal `add_child` step,
    /// cleared by `remove_child` when the object is reaped.
    pub parent_ut: *mut super::UntypedMemory,

    /// `hlist` next pointer in the parent untyped's child list.
    pub ut_sibling_next: *mut KernelObject,

    /// `hlist` pprev pointer (`&prev_node.ut_sibling_next`, or
    /// `&parent.child_head` for the head). `null` while detached.
    pub ut_sibling_pprev: *mut *mut KernelObject,
}

impl KernelObject {
    pub const fn new(obj_type: ObjectType, size_bits: u8) -> Self {
        Self {
            obj_type,
            size_bits,
            ref_count: AtomicU32::new(1),
            reaper_link: 0,
            parent_ut: core::ptr::null_mut(),
            ut_sibling_next: core::ptr::null_mut(),
            ut_sibling_pprev: core::ptr::null_mut(),
        }
    }
}
