//! System Call Handler
//!
//! Capability invocation dispatch.
//!
//! SPDX-License-Identifier: GPL-2.0-only

pub mod fastpath;

use crate::cap::{
    CNode, CapError, CapRights, Capability, FrameObject, IoPortRange, ObjectType, UntypedMemory,
};
use crate::ipc::{Endpoint, Message, Notification};
use crate::mm::vspace::{CowNotifRing, CowPool, PageFlags, VSpace, VSpaceError};
use crate::mm::{phys_to_virt, restore_irq, save_irq_disable, CAP_LOCK};
use crate::sched::thread::{BlockedReason, SchedContext, Tcb, ThreadState};
use core::sync::atomic::Ordering;
/// System call numbers
#[repr(u64)]
pub enum Syscall {
    Send = 0,
    Recv = 1,
    Call = 2,
    ReplyRecv = 3,
    NBSend = 4,
    Signal = 5,
    Wait = 6,
    Poll = 7,
    Yield = 8,
    Invoke = 9,
    DebugPutChar = 10,
    DebugDumpState = 11,
    ClockGetTime = 12,
    NanoSleep = 13,
    DebugPutStr = 14,
    DebugPutBuf = 15,
    DebugConsoleControl = 16,
    SetInvokeDepths = 17,
    Futex = 18,
    GetRandom = 19,
    Shutdown = 20,
    SendTimed = 21,
    RecvTimed = 22,
    RecvAny = 23,
    ReplyRecvAny = 24,
    RecvAnyTimed = 25,
    ReplyRecvAnyTimed = 26,
    NotifReturn = 27,
    ThreadExit = 28,
}

impl TryFrom<u64> for Syscall {
    type Error = SyscallError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Syscall::Send),
            1 => Ok(Syscall::Recv),
            2 => Ok(Syscall::Call),
            3 => Ok(Syscall::ReplyRecv),
            4 => Ok(Syscall::NBSend),
            5 => Ok(Syscall::Signal),
            6 => Ok(Syscall::Wait),
            7 => Ok(Syscall::Poll),
            8 => Ok(Syscall::Yield),
            9 => Ok(Syscall::Invoke),
            10 => Ok(Syscall::DebugPutChar),
            11 => Ok(Syscall::DebugDumpState),
            12 => Ok(Syscall::ClockGetTime),
            13 => Ok(Syscall::NanoSleep),
            14 => Ok(Syscall::DebugPutStr),
            15 => Ok(Syscall::DebugPutBuf),
            16 => Ok(Syscall::DebugConsoleControl),
            17 => Ok(Syscall::SetInvokeDepths),
            18 => Ok(Syscall::Futex),
            19 => Ok(Syscall::GetRandom),
            20 => Ok(Syscall::Shutdown),
            21 => Ok(Syscall::SendTimed),
            22 => Ok(Syscall::RecvTimed),
            23 => Ok(Syscall::RecvAny),
            24 => Ok(Syscall::ReplyRecvAny),
            25 => Ok(Syscall::RecvAnyTimed),
            26 => Ok(Syscall::ReplyRecvAnyTimed),
            27 => Ok(Syscall::NotifReturn),
            28 => Ok(Syscall::ThreadExit),
            _ => Err(SyscallError::InvalidOperation),
        }
    }
}

/// Message info word helpers
///
/// Format (seL4-aligned):
///   Bits  6:0  = Length (0-127, number of message registers used)
///   Bits 11:7  = ExtraCaps (0-31, number of capabilities to transfer)
///   Bits 51:12 = Label (40 bits, application-defined message label)
///   Bits 63:52 = Reserved
pub mod msg_info {
    const LENGTH_BITS: u64 = 7;
    const LENGTH_MASK: u64 = (1 << LENGTH_BITS) - 1; // 0x7F
    const EXTRACAPS_SHIFT: u64 = 7;
    const EXTRACAPS_BITS: u64 = 5;
    const EXTRACAPS_MASK: u64 = ((1 << EXTRACAPS_BITS) - 1) << EXTRACAPS_SHIFT; // 0xF80
    const LABEL_SHIFT: u64 = 12;
    const LABEL_MASK: u64 = 0xFF_FFFF_FFFF; // 40 bits

    /// Extract message label (bits 51:12)
    pub fn get_label(msg_info: u64) -> u64 {
        (msg_info >> LABEL_SHIFT) & LABEL_MASK
    }

    /// Extract message length (bits 6:0, max 127)
    pub fn get_length(msg_info: u64) -> usize {
        (msg_info & LENGTH_MASK) as usize
    }

    /// Extract number of extra capabilities (bits 11:7, max 31)
    pub fn get_extra_caps(msg_info: u64) -> usize {
        ((msg_info & EXTRACAPS_MASK) >> EXTRACAPS_SHIFT) as usize
    }

    /// Create a message info word
    pub fn make(label: u64, length: usize, extra_caps: usize) -> u64 {
        ((label & LABEL_MASK) << LABEL_SHIFT)
            | ((extra_caps as u64 & 0x1F) << EXTRACAPS_SHIFT)
            | (length as u64 & LENGTH_MASK)
    }
}

/// System call result (FFI-safe)
///
/// Under System V AMD64 ABI:
/// - `error` is returned in %rax
/// - `value` is returned in %rdx
#[repr(C)]
pub struct SyscallResult {
    pub error: u64,
    pub value: u64,
}

impl SyscallResult {
    pub const fn ok(value: u64) -> Self {
        Self { error: 0, value }
    }

    pub const fn err(error: SyscallError) -> Self {
        Self {
            error: error as u64,
            value: 0,
        }
    }
}

/// System call errors
#[repr(u64)]
pub enum SyscallError {
    None = 0,
    InvalidCapability = 1,
    InvalidOperation = 2,
    InsufficientRights = 3,
    InvalidArgument = 4,
    OutOfMemory = 5,
    NotFound = 6,
    Busy = 7,
    AlreadyExists = 8,
    WouldBlock = 9,
    BadAddress = 10,
    OutOfRange = 11,
    Cancelled = 12,
    Restart = 13,
    Deadlock = 14,
    Interrupted = 15,
    SlotOccupied = 0x18,
    AlreadyMapped = 0x19,
    AlreadyBound = 0x1A,
}

/// Maximum spin iterations waiting for cross-CPU suspend to complete.
/// ~1ms at 2GHz — the target CPU will process the IPI within single-digit microseconds.
const SUSPEND_SPIN_LIMIT: u32 = 2_000_000;

/// Look up capability from current thread's CSpace
///
/// This is the primary capability lookup function used by all syscall handlers.
/// It retrieves a capability from the current thread's CNode (capability space).
///
/// When in flat mode (depth=0), first tries direct slot lookup. If the address
/// exceeds the root CNode size, falls back to auto-detecting a sub-CNode in the
/// root and resolving through the seL4-style guard+radix tree.
///
/// # Arguments
/// * `cap_ptr` - Capability slot index in the thread's CSpace
///
/// # Returns
/// * `Ok(&Capability)` - Reference to the capability
/// * `Err(SyscallError::InvalidCapability)` - Slot is empty or CSpace is null
pub(crate) fn lookup_capability(cap_ptr: u64) -> Result<&'static Capability, SyscallError> {
    unsafe {
        // Get current thread's TCB
        let scheduler = crate::sched::scheduler::scheduler();
        let current_tcb = scheduler.current();

        if current_tcb.is_null() {
            return Err(SyscallError::InvalidOperation);
        }

        // Get thread's CSpace (CNode)
        let cspace = &*(*current_tcb).cspace_root;
        let depth = (*current_tcb).cspace_depth;

        if depth == 0 {
            // Flat mode: try direct slot index lookup first
            if let Some(cap) = cspace.get(cap_ptr as usize) {
                return Ok(cap);
            }
            // Fallback: auto-detect sub-CNode and resolve through tree
            lookup_expanded(cspace, cap_ptr)
        } else {
            // Multi-level mode: walk CNode tree
            crate::cap::cnode::resolve_address(cspace, cap_ptr, depth)
                .map_err(|_| SyscallError::InvalidCapability)
        }
    }
}

/// Auto-detect expanded CNode structure and resolve address through the tree.
///
/// When a flat lookup fails (address >= num_slots), this function probes root
/// slots to find a sub-CNode. It computes the root index by shifting cap_ptr
/// right by candidate sub_bits values, checks if root[root_idx] holds a CNode
/// with matching size_bits, and resolves through the full tree.
fn lookup_expanded(cspace: &CNode, cap_ptr: u64) -> Result<&'static Capability, SyscallError> {
    let root_bits = cspace.header.size_bits as usize;

    // Try sub_bits from 4..16 (all valid CNode sizes)
    for sub_bits in 4usize..=16 {
        let root_idx = (cap_ptr >> sub_bits) as usize;
        if root_idx >= cspace.num_slots() {
            continue;
        }
        if let Some(cap) = cspace.get(root_idx) {
            if cap.obj_type == ObjectType::CNode && !cap.object.is_null() {
                let sub_cnode = unsafe { &*(cap.object as *const CNode) };
                if sub_cnode.header.size_bits as usize == sub_bits {
                    let total_depth = (root_bits + sub_bits) as u8;
                    return crate::cap::cnode::resolve_address(cspace, cap_ptr, total_depth)
                        .map_err(|_| SyscallError::InvalidCapability);
                }
            }
        }
    }

    Err(SyscallError::InvalidCapability)
}

/// Auto-detect expanded CNode and resolve to CapRef (for untyped cap lookup).
///
/// Same logic as `lookup_expanded` but returns a CapRef instead of &Capability.
fn lookup_expanded_slot(
    cspace: &CNode,
    cap_ptr: u64,
) -> Result<crate::cap::cnode::CapRef, SyscallError> {
    let root_bits = cspace.header.size_bits as usize;

    for sub_bits in 4usize..=16 {
        let root_idx = (cap_ptr >> sub_bits) as usize;
        if root_idx >= cspace.num_slots() {
            continue;
        }
        if let Some(cap) = cspace.get(root_idx) {
            if cap.obj_type == ObjectType::CNode && !cap.object.is_null() {
                let sub_cnode = unsafe { &*(cap.object as *const CNode) };
                if sub_cnode.header.size_bits as usize == sub_bits {
                    let total_depth = (root_bits + sub_bits) as u8;
                    return crate::cap::cnode::resolve_address_slot(cspace, cap_ptr, total_depth)
                        .map_err(|_| SyscallError::InvalidCapability);
                }
            }
        }
    }

    Err(SyscallError::InvalidCapability)
}

/// Auto-detect expanded CNode and resolve to (*mut CNode, slot_index) for write ops.
fn lookup_expanded_for_slot(
    cspace: &CNode,
    cap_ptr: u64,
) -> Result<(*mut CNode, usize), SyscallError> {
    let root_bits = cspace.header.size_bits as usize;

    for sub_bits in 4usize..=16 {
        let root_idx = (cap_ptr >> sub_bits) as usize;
        if root_idx >= cspace.num_slots() {
            continue;
        }
        if let Some(cap) = cspace.get(root_idx) {
            if cap.obj_type == ObjectType::CNode && !cap.object.is_null() {
                let sub_cnode = unsafe { &*(cap.object as *const CNode) };
                if sub_cnode.header.size_bits as usize == sub_bits {
                    let total_depth = (root_bits + sub_bits) as u8;
                    return crate::cap::cnode::resolve_address_for_slot(
                        cspace,
                        cap_ptr,
                        total_depth,
                    )
                    .map_err(|_| SyscallError::InvalidCapability);
                }
            }
        }
    }

    Err(SyscallError::InvalidCapability)
}

/// Consume pending invoke depth values from the current thread.
///
/// Depths are written via SYS_SET_INVOKE_DEPTHS and consumed by the next
/// depth-aware invoke. After read, both values are reset to 0 to avoid stale
/// depth state affecting future invokes.
///
/// # Safety
/// Caller must ensure the current TCB is valid.
unsafe fn read_invoke_depths(tcb: *mut Tcb) -> (u8, u8) {
    unsafe {
        let d0 = (*tcb).invoke_depth0;
        let d1 = (*tcb).invoke_depth1;
        (*tcb).invoke_depth0 = 0;
        (*tcb).invoke_depth1 = 0;
        (d0, d1)
    }
}

/// Resolve a slot address within a CNode, using tree-walking when depth > 0.
///
/// When depth=0, returns the CNode pointer and flat index directly (backward compatible).
/// When depth>0, walks the CNode tree using seL4-style guard+radix resolution.
///
/// Returns (leaf CNode pointer, leaf slot index) on success.
fn resolve_invoke_slot(
    cnode: &CNode,
    addr: u64,
    depth: u8,
) -> Result<(*mut CNode, usize), SyscallError> {
    if depth == 0 {
        Ok((cnode as *const CNode as *mut CNode, addr as usize))
    } else {
        crate::cap::cnode::resolve_address_for_slot(cnode, addr, depth)
            .map_err(|_| SyscallError::InvalidCapability)
    }
}

/// Look up capability under CAP_LOCK and copy to stack.
///
/// Acquires CAP_LOCK, reads the capability from the current thread's CSpace,
/// copies it to a stack-local value, then releases CAP_LOCK. The returned
/// copy is safe to use after lock release — kernel objects are never freed
/// (owned by untyped memory parent), so object pointers remain valid.
fn lookup_cap_locked(cap_ptr: u64) -> Result<Capability, SyscallError> {
    unsafe {
        let irq = save_irq_disable();
        CAP_LOCK.lock();
        let result = lookup_capability(cap_ptr).map(|cap| *cap);
        CAP_LOCK.unlock();
        restore_irq(irq);
        result
    }
}

/// Validate capability has required type and rights
///
/// Helper function to check that a capability meets the requirements
/// for a specific operation. Used by syscall handlers to validate
/// capabilities before performing operations.
///
/// # Arguments
/// * `cap` - Capability to validate
/// * `expected_type` - Required object type (ObjectType::Null matches any)
/// * `required_rights` - Required access rights
///
/// # Returns
/// * `Ok(())` - Capability is valid
/// * `Err(SyscallError::InvalidOperation)` - Wrong object type
/// * `Err(SyscallError::InsufficientRights)` - Missing required rights
fn validate_capability(
    cap: &Capability,
    expected_type: ObjectType,
    required_rights: CapRights,
) -> Result<(), SyscallError> {
    // Check if capability is null
    if cap.is_null() {
        return Err(SyscallError::InvalidCapability);
    }

    // Check object type (ObjectType::Null is a wildcard)
    if expected_type != ObjectType::Null && cap.obj_type != expected_type {
        return Err(SyscallError::InvalidOperation);
    }

    // Check capability has required rights
    if !cap.has_right(required_rights) {
        return Err(SyscallError::InsufficientRights);
    }

    Ok(())
}

/// Validate endpoint capability with required rights
///
/// Convenience wrapper for validate_capability specific to endpoints.
/// Checks that the capability is an Endpoint and has the specified rights.
///
/// # Arguments
/// * `cap` - Capability to validate
/// * `required_rights` - Required IPC rights (SEND, RECV, CALL, etc.)
///
/// # Returns
/// * `Ok(())` - Valid endpoint capability
/// * `Err(SyscallError::InvalidCapability)` - Null capability
/// * `Err(SyscallError::InvalidOperation)` - Not an endpoint
/// * `Err(SyscallError::InsufficientRights)` - Missing required rights
pub(crate) fn validate_endpoint_cap(
    cap: &Capability,
    required_rights: CapRights,
) -> Result<(), SyscallError> {
    validate_capability(cap, ObjectType::Endpoint, required_rights)
}

/// Validate notification capability with required rights
///
/// Convenience wrapper for validate_capability specific to notifications.
/// Checks that the capability is a Notification and has the specified rights.
///
/// # Arguments
/// * `cap` - Capability to validate
/// * `required_rights` - Required rights (READ, WRITE)
///
/// # Returns
/// * `Ok(())` - Valid notification capability
/// * `Err(SyscallError::InvalidCapability)` - Null capability
/// * `Err(SyscallError::InvalidOperation)` - Not a notification
/// * `Err(SyscallError::InsufficientRights)` - Missing required rights
fn validate_notification_cap(
    cap: &Capability,
    required_rights: CapRights,
) -> Result<(), SyscallError> {
    validate_capability(cap, ObjectType::Notification, required_rights)
}

/// Construct Message from syscall arguments
///
/// Arguments:
/// - msg_info: Message info word (label + length + extra_caps, packed)
/// - mr0-mr3: Message registers (inline fastpath)
fn construct_message(msg_info: u64, mr0: u64, mr1: u64, mr2: u64, mr3: u64) -> Message {
    let label = msg_info::get_label(msg_info);
    let length = msg_info::get_length(msg_info).min(32);
    let extra_caps = msg_info::get_extra_caps(msg_info).min(4);
    let mut regs = [0u64; 32];
    let mut caps = [0u64; 4];

    // Copy inline registers based on length (max 4 in registers)
    if length > 0 {
        regs[0] = mr0;
    }
    if length > 1 {
        regs[1] = mr1;
    }
    if length > 2 {
        regs[2] = mr2;
    }
    if length > 3 {
        regs[3] = mr3;
    }

    // Pull overflow MRs and cap transfer slots from the sender's IPC buffer
    // while the sender is current (its VSpace is active in CR3).
    if length > 4 || extra_caps > 0 {
        unsafe {
            let scheduler = crate::sched::scheduler::scheduler();
            let current = scheduler.current();
            if !current.is_null() {
                let buf = (*current).ipc_buffer;
                if buf != 0 {
                    let ipc_buf = buf as *const crate::ipc::IpcBuffer;
                    // SMAP: temporarily allow user memory access
                    let _guard = crate::arch::uaccess::UserAccessGuard::new();

                    if length > 4 {
                        let overflow = (length - 4).min(28);
                        for i in 0..overflow {
                            regs[4 + i] = (*ipc_buf).msg[6 + i];
                        }
                    }

                    for i in 0..extra_caps {
                        caps[i] = (*ipc_buf).caps[i];
                    }
                }
            }
        }
    }

    Message {
        label,
        length,
        extra_caps,
        regs,
        caps,
    }
}

pub(crate) unsafe fn read_recv_any_endpoints(
    count: usize,
    out: &mut [*mut Endpoint; crate::sched::thread::MAX_RECV_WAIT_ENDPOINTS],
) -> Result<usize, SyscallError> {
    if count == 0 || count > crate::sched::thread::MAX_RECV_WAIT_ENDPOINTS {
        return Err(SyscallError::InvalidArgument);
    }

    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if current.is_null() {
        return Err(SyscallError::InvalidOperation);
    }

    let buf = (*current).ipc_buffer;
    if buf == 0 {
        return Err(SyscallError::BadAddress);
    }
    if validate_ipc_buffer_addr(buf).is_err() {
        return Err(SyscallError::BadAddress);
    }

    let ipc_buf = buf as *const crate::ipc::IpcBuffer;
    let _guard = crate::arch::uaccess::UserAccessGuard::new();

    let irq = unsafe { save_irq_disable() };
    CAP_LOCK.lock();

    let mut idx = 0usize;
    while idx < count {
        let slot = (*ipc_buf).reserved[idx];
        let cap = match lookup_capability(slot) {
            Ok(cap) => *cap,
            Err(err) => {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return Err(err);
            }
        };

        if let Err(err) = validate_endpoint_cap(&cap, CapRights::RECV) {
            CAP_LOCK.unlock();
            restore_irq(irq);
            return Err(err);
        }

        let endpoint = cap.object as *mut Endpoint;
        let mut dup_idx = 0usize;
        while dup_idx < idx {
            if out[dup_idx] == endpoint {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return Err(SyscallError::InvalidArgument);
            }
            dup_idx += 1;
        }

        out[idx] = endpoint;
        idx += 1;
    }

    CAP_LOCK.unlock();
    unsafe { restore_irq(irq) };
    Ok(count)
}

/// Read timeout_ns from the current thread's IPC buffer.
/// Returns 0 if no IPC buffer is mapped.
unsafe fn read_ipc_buffer_timeout() -> u64 {
    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if current.is_null() {
        return 0;
    }
    let buf = (*current).ipc_buffer;
    if buf == 0 {
        return 0;
    }
    let ipc_buf = buf as *const crate::ipc::IpcBuffer;
    let _guard = crate::arch::uaccess::UserAccessGuard::new();
    (*ipc_buf).timeout_ns
}

/// Write received IPC message to current thread's IPC buffer
///
/// Writes in `struct trona_msg` layout (matching userland overlay):
///   msg[0] = label
///   msg[1] = length
///   msg[2..5] = regs[0..3]  (inline MRs)
///   msg[6..21] = regs[4..19] (overflow)
///
/// Badge is written to ipc_buffer.badge.
pub(crate) unsafe fn write_msg_to_ipc_buffer(msg: &Message, badge: u64) {
    unsafe {
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();
        if current.is_null() {
            return;
        }
        let buf = (*current).ipc_buffer;
        if buf == 0 {
            return;
        }

        // Defensive guard: user processes can set IPC buffer addresses, and
        // mappings may disappear after exec/fork bugs. Never fault the kernel
        // while writing a reply — drop the write if the page is not mapped.
        if validate_ipc_buffer_addr(buf).is_err() {
            (*current).ipc_buffer = 0;
            return;
        }
        if (*current).vspace_root.is_null() {
            return;
        }
        let vspace = &mut *(*current).vspace_root;
        // Ensure the IPC buffer page is present AND writable. After fork,
        // the page may be COW (read-only), which would cause a kernel #PF
        // on the write below. ensure_writable resolves COW if needed.
        if !vspace.ensure_writable(buf) {
            (*current).ipc_buffer = 0;
            return;
        }

        let ipc_buf = buf as *mut crate::ipc::IpcBuffer;
        // SMAP: temporarily allow user memory access for IPC buffer write
        let _guard = crate::arch::uaccess::UserAccessGuard::new();

        // Write header: label and length
        (*ipc_buf).msg[0] = msg.label;
        (*ipc_buf).msg[1] = msg.length as u64;

        let reg_count = msg.length.min(32);

        // Write inline message registers (MR0-MR3) → msg[2..5]
        let inline_count = reg_count.min(4);
        for i in 0..inline_count {
            (*ipc_buf).msg[2 + i] = msg.regs[i];
        }

        // Write overflow message registers (MR4-MR31) → msg[6..33]
        if reg_count > 4 {
            let overflow_count = (reg_count - 4).min(28);
            for i in 0..overflow_count {
                (*ipc_buf).msg[6 + i] = msg.regs[4 + i];
            }
        }

        // Clear unused slots from end of message to end of regs area
        let first_clear = if reg_count <= 4 {
            2 + reg_count
        } else {
            6 + (reg_count - 4)
        };
        for i in first_clear.min(34)..34 {
            (*ipc_buf).msg[i] = 0;
        }

        // Write badge
        (*ipc_buf).badge = badge;
    }
}

/// Send message to endpoint (blocks until receiver ready)
fn syscall_send(
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> SyscallResult {
    // Phase 1: Cap lookup under CAP_LOCK
    let cap = match lookup_cap_locked(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };

    // Construct message (no lock — reads own IPC buffer, IRQs disabled by SFMASK)
    let msg = construct_message(msg_info, mr0, mr1, mr2, mr3);

    if cap.obj_type == ObjectType::Endpoint {
        match validate_endpoint_cap(&cap, CapRights::SEND) {
            Ok(()) => {}
            Err(e) => return SyscallResult::err(e),
        }

        // Phase 2: IPC under per-endpoint lock (managed inside method)
        unsafe {
            let irq = save_irq_disable();
            let endpoint = &mut *(cap.object as *mut Endpoint);
            if let Err(err) = endpoint.send(&msg, cap.badge) {
                restore_irq(irq);
                return SyscallResult::err(err);
            }
            restore_irq(irq);
        }
        return SyscallResult::ok(0);
    }

    // Reply capability path (saved via CNODE_SAVE_CALLER):
    // cap points to caller TCB and has REPLY right.
    if cap.obj_type == ObjectType::Tcb && cap.has_right(CapRights::REPLY) {
        unsafe {
            let caller = cap.object as *mut Tcb;
            if caller.is_null() {
                return SyscallResult::err(SyscallError::InvalidCapability);
            }

            // Saved reply caps cannot transfer capabilities.
            let mut reply_msg = msg;
            reply_msg.extra_caps = 0;
            reply_msg.caps = [0; 4];

            // Phase 2: Wake caller under per-TCB lock
            let irq = save_irq_disable();
            let caller_tcb = &*caller;
            caller_tcb.tcb_lock();

            let blocked_for_reply = matches!(
                (*caller).blocked_reason,
                Some(BlockedReason::ReplyWait { .. }) | Some(BlockedReason::FaultBlocked { .. })
            );
            if !blocked_for_reply || (*caller).state != ThreadState::Blocked {
                caller_tcb.tcb_unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidOperation);
            }

            (*caller).saved_caller_msg = reply_msg;
            (*caller).saved_caller_badge = 0;
            (*caller).blocked_reason = None;
            (*caller).blocked_endpoint = core::ptr::null_mut();

            crate::sched::scheduler::scheduler().enqueue(caller);

            caller_tcb.tcb_unlock();
            restore_irq(irq);

            // Phase 3: Delete one-shot reply cap under CAP_LOCK
            let irq = save_irq_disable();
            CAP_LOCK.lock();
            let current_tcb = crate::sched::scheduler::scheduler().current();
            if !current_tcb.is_null() && !(*current_tcb).cspace_root.is_null() {
                let cspace = &mut *(*current_tcb).cspace_root;
                let _ = cspace.delete(cap_ptr as usize);
            }
            CAP_LOCK.unlock();
            restore_irq(irq);
        }
        return SyscallResult::ok(0);
    }

    SyscallResult::err(SyscallError::InvalidOperation)
}

/// Receive message from endpoint (blocks until sender ready)
fn syscall_recv(cap_ptr: u64) -> SyscallResult {
    // Phase 1: Cap lookup under CAP_LOCK
    let cap = match lookup_cap_locked(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_endpoint_cap(&cap, CapRights::RECV) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    // Phase 2: IPC under per-endpoint lock (managed inside method)
    unsafe {
        let irq = save_irq_disable();
        let endpoint = &mut *(cap.object as *mut Endpoint);
        let (msg, badge) = match endpoint.recv() {
            Ok(v) => v,
            Err(err) => {
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };
        write_msg_to_ipc_buffer(&msg, badge);
        restore_irq(irq);
        SyscallResult::ok(badge)
    }
}

/// Call endpoint (send + wait for reply atomically)
fn syscall_call(
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> SyscallResult {
    // Phase 1: Cap lookup under CAP_LOCK
    let cap = match lookup_cap_locked(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_endpoint_cap(&cap, CapRights::CALL) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    let msg = construct_message(msg_info, mr0, mr1, mr2, mr3);

    // Phase 2: IPC under per-endpoint lock (managed inside method)
    unsafe {
        let irq = save_irq_disable();
        let current = crate::sched::scheduler::scheduler().current();

        // Fastpath may have woken us from ReplyWait with notification
        // and bailed to slowpath. Catch that here without re-issuing call.
        // Fastpath only enters ReplyWait (not CallSendBlocked), so intr=2.
        if (*current).woken_by_notification {
            (*current).woken_by_notification = false;
            return handle_call_interrupted(current, cap_ptr, msg_info, irq, 2);
        }

        let endpoint = &mut *(cap.object as *mut Endpoint);
        let (reply_msg, intr) = match endpoint.call(&msg, cap.badge) {
            Ok(v) => v,
            Err(err) => {
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };

        if intr != 0 {
            return handle_call_interrupted(current, cap_ptr, msg_info, irq, intr);
        }

        write_msg_to_ipc_buffer(&reply_msg, 0);
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

// ---------------------------------------------------------------------------
// Notification frame: kernel-injected context on the user stack for
// notification delivery (used by POSIX signal layer and future subsystems).
// ---------------------------------------------------------------------------

/// Magic value for notification frame validation
const NOTIFFRAME_MAGIC: u64 = 0x5A17_5349_4746_524D;

/// Notification frame pushed onto the user stack when the kernel interrupts
/// a blocking IPC call due to a bound notification.
///
/// The kernel saves the full user register state plus FPU context,
/// then redirects execution to the user-mode notification dispatcher.
/// After handlers run, userspace calls `SYS_NOTIF_RETURN` to
/// restore the original context.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
#[repr(C, align(64))]
struct NotifFrame {
    // General-purpose registers and control state (18 × 8 = 144 bytes)
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
    // Notification metadata (6 × 8 = 48 bytes)
    notification_bits: u64,
    interrupted_syscall: u64,
    syscall_cap_ptr: u64,
    syscall_msg_info: u64,
    restart_syscall: u64,
    magic: u64,
    // FPU/SSE/AVX state
    fpu_saved: u64,
    _fpu_pad: [u64; 7],
    fpu_state: [u8; 832],
}

/// Notification frame (aarch64 variant).
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct NotifFrame {
    // General-purpose registers x0-x30 (31 × 8 = 248 bytes)
    x: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    // Notification metadata
    notification_bits: u64,
    interrupted_syscall: u64,
    syscall_cap_ptr: u64,
    syscall_msg_info: u64,
    restart_syscall: u64,
    magic: u64,
    // NEON/FP state
    fpu_saved: u64,
    _fpu_pad: [u64; 1],
    fpu_state: [u8; 528],
}

/// Verify that all pages in `[addr, addr+size)` are mapped in the
/// current thread's VSpace. Returns `false` if any page is unmapped.
///
/// # Safety
/// Current thread's `vspace_root` must be valid. IRQs should be disabled.
unsafe fn verify_user_pages_mapped(
    tcb: *mut crate::sched::thread::Tcb,
    addr: u64,
    size: u64,
    writable: bool,
) -> bool {
    unsafe {
        if size == 0 {
            return true;
        }
        if (*tcb).vspace_root.is_null() {
            return false;
        }
        let last_byte = match addr.checked_add(size - 1) {
            Some(end) => end,
            None => return false,
        };
        let first_page = addr & !0xFFF;
        let last_page = last_byte & !0xFFF;

        if writable {
            let vspace = &mut *(*tcb).vspace_root;
            let mut page_addr = first_page;
            loop {
                if !vspace.ensure_writable(page_addr) {
                    return false;
                }
                if page_addr == last_page {
                    break;
                }
                page_addr += 0x1000;
            }
        } else {
            let vspace = &*(*tcb).vspace_root;
            let mut page_addr = first_page;
            loop {
                if vspace.resolve_page(page_addr).is_none() {
                    return false;
                }
                if page_addr == last_page {
                    break;
                }
                page_addr += 0x1000;
            }
        }
        true
    }
}

/// Consume and return pending notification bits from the TCB's bound
/// notification, atomically clearing them.
///
/// # Safety
/// `tcb` must be a valid TCB pointer. IRQs should be disabled.
unsafe fn consume_notification_bits(tcb: *mut crate::sched::thread::Tcb) -> u64 {
    unsafe {
        if (*tcb).bound_notification.is_null() {
            return 0;
        }
        let ntfn = &mut *((*tcb).bound_notification as *mut crate::ipc::Notification);
        ntfn.ntfn_lock();
        let bits = ntfn.bits.swap(0, core::sync::atomic::Ordering::SeqCst);
        ntfn.ntfn_unlock();
        bits
    }
}

/// Inject a notification frame onto the user stack and redirect execution
/// to the notification dispatcher.
///
/// Returns `Some(result)` on success with the arch-appropriate
/// `SyscallResult` to return to userspace, or `None` on failure
/// (e.g., stack overflow or unmapped page).
///
/// # Safety
/// Must be called with IRQs disabled. `tcb` must be the current thread.
/// The kernel stack must contain the user register state from syscall entry.
unsafe fn inject_notif_frame(
    tcb: *mut crate::sched::thread::Tcb,
    dispatcher: u64,
    cap_ptr: u64,
    msg_info: u64,
) -> Option<SyscallResult> {
    unsafe {
        let bits = consume_notification_bits(tcb);

        // Flush FPU state from hardware to TCB if this thread owns it
        let fpu_initialized = (*tcb).fpu_initialized;
        if fpu_initialized {
            crate::arch::fpu::flush_if_owner(tcb as *mut u8);
        }

        #[cfg(target_arch = "x86_64")]
        {
            // Read saved user registers from the per-thread kernel stack.
            // Layout (from syscall_entry pushes, syscall.S line 42-59):
            //   kst-8  = user_rsp    kst-72  = r8
            //   kst-16 = r15         kst-80  = rbp
            //   kst-24 = r14         kst-88  = rdi
            //   kst-32 = r13         kst-96  = rsi
            //   kst-40 = r12         kst-104 = rdx
            //   kst-48 = r11/RFLAGS  kst-112 = rcx/user RIP
            //   kst-56 = r10         kst-120 = rbx
            //   kst-64 = r9          kst-128 = rax/syscall#
            let kst = (*tcb).kernel_stack_top as *const u64;
            let user_rsp = *kst.offset(-1);

            let mut frame = NotifFrame {
                rax: *kst.offset(-16),
                rbx: *kst.offset(-15),
                rcx: *kst.offset(-14),
                rdx: *kst.offset(-13),
                rsi: *kst.offset(-12),
                rdi: *kst.offset(-11),
                rbp: *kst.offset(-10),
                rsp: user_rsp,
                r8: *kst.offset(-9),
                r9: *kst.offset(-8),
                r10: *kst.offset(-7),
                r11: *kst.offset(-6),
                r12: *kst.offset(-5),
                r13: *kst.offset(-4),
                r14: *kst.offset(-3),
                r15: *kst.offset(-2),
                rip: *kst.offset(-14),
                rflags: *kst.offset(-6),
                notification_bits: bits,
                interrupted_syscall: Syscall::Call as u64,
                syscall_cap_ptr: cap_ptr,
                syscall_msg_info: msg_info,
                restart_syscall: 0,
                magic: NOTIFFRAME_MAGIC,
                fpu_saved: if fpu_initialized { 1 } else { 0 },
                _fpu_pad: [0u64; 7],
                fpu_state: [0u8; 832],
            };

            if fpu_initialized {
                frame.fpu_state.copy_from_slice(&(*tcb).fpu_state.data);
            }

            let frame_size = core::mem::size_of::<NotifFrame>() as u64;
            // Keep the frame 64-byte aligned for XSAVE compatibility, and
            // reserve one synthetic return-address slot below it so the
            // dispatcher enters with the normal SysV x86_64 stack layout.
            let frame_addr = match user_rsp.checked_sub(frame_size) {
                Some(addr) => addr & !63,
                None => return None,
            };
            let dispatcher_rsp = match frame_addr.checked_sub(8) {
                Some(rsp) => rsp,
                None => return None,
            };

            if dispatcher_rsp < (*tcb).user_stack_min || dispatcher_rsp >= user_rsp {
                return None;
            }

            // Verify the synthetic return slot plus frame are writable before
            // touching user memory.
            if !verify_user_pages_mapped(tcb, dispatcher_rsp, frame_size + 8, true) {
                return None;
            }

            let synthetic_return = 0u64;
            if !crate::arch::uaccess::copy_to_user(frame_addr, &frame)
                || !crate::arch::uaccess::copy_to_user(dispatcher_rsp, &synthetic_return)
            {
                return None;
            }

            // Redirect: modify kernel stack so sysretq goes to dispatcher
            let kst = (*tcb).kernel_stack_top as *mut u64;
            *kst.offset(-14) = dispatcher; // RCX → user RIP = dispatcher
            *kst.offset(-1) = dispatcher_rsp; // user RSP = synthetic call frame
            *kst.offset(-11) = frame_addr; // RDI = frame pointer (1st arg)

            // x86_64: frame pointer delivered via RDI (1st arg register).
            // RAX (error) is written by SyscallResult, but dispatcher
            // ignores it — SyscallResult::ok(0) is fine.
            Some(SyscallResult::ok(0))
        }

        #[cfg(target_arch = "aarch64")]
        {
            let ctx = &(*tcb).context;
            let mut frame = NotifFrame {
                x: ctx.x,
                sp: ctx.user_sp,
                pc: ctx.return_elr,
                pstate: ctx.return_spsr,
                notification_bits: bits,
                interrupted_syscall: Syscall::Call as u64,
                syscall_cap_ptr: cap_ptr,
                syscall_msg_info: msg_info,
                restart_syscall: 0,
                magic: NOTIFFRAME_MAGIC,
                fpu_saved: if fpu_initialized { 1 } else { 0 },
                _fpu_pad: [0u64; 1],
                fpu_state: [0u8; 528],
            };

            if fpu_initialized {
                frame.fpu_state.copy_from_slice(&(*tcb).fpu_state.data);
            }

            let frame_size = core::mem::size_of::<NotifFrame>() as u64;
            let new_sp = (ctx.user_sp - frame_size) & !0xF;

            if new_sp < (*tcb).user_stack_min || new_sp >= ctx.user_sp {
                return None;
            }

            let frame_size_check = core::mem::size_of::<NotifFrame>() as u64;
            if !verify_user_pages_mapped(tcb, new_sp, frame_size_check, true) {
                return None;
            }

            if !crate::arch::uaccess::copy_to_user(new_sp, &frame) {
                return None;
            }

            let ctx = &mut (*tcb).context;
            ctx.user_sp = new_sp;
            ctx.return_elr = dispatcher;

            // aarch64: the syscall return path writes SyscallResult.error
            // to x0 (restore_el0_frame_from_current_tcb overwrites ctx.x[0]).
            // Deliver the frame pointer via SyscallResult.error so the
            // dispatcher receives it in x0 as its first argument.
            Some(SyscallResult {
                error: new_sp,
                value: 0,
            })
        }
    }
}

/// SYS_NOTIF_RETURN: restore user context from a notification frame on the user stack.
///
/// Always returns `Interrupted` (EINTR). SA_RESTART is handled at the
/// POSIX library level, not here, because:
/// - The notification handler may have issued IPC that overwrote the IPC buffer
/// - For ReplyWait interruptions, the message was already delivered to the
///   server, so re-sending would cause duplicate processing
fn syscall_notif_return(frame_ptr: u64) -> SyscallResult {
    unsafe {
        let irq = save_irq_disable();
        let current = crate::sched::scheduler::scheduler().current();

        // Verify pages are mapped before reading to avoid kernel fault
        let frame_size = core::mem::size_of::<NotifFrame>() as u64;
        if !verify_user_pages_mapped(current, frame_ptr, frame_size, false) {
            restore_irq(irq);
            return SyscallResult::err(SyscallError::BadAddress);
        }

        let frame: NotifFrame = match crate::arch::uaccess::copy_from_user(frame_ptr) {
            Some(f) => f,
            None => {
                restore_irq(irq);
                return SyscallResult::err(SyscallError::BadAddress);
            }
        };

        if frame.magic != NOTIFFRAME_MAGIC {
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidArgument);
        }

        // Restore FPU state from the notification frame. The handler may
        // have used FPU/SSE/NEON and corrupted the thread's FPU context.
        if frame.fpu_saved == 1 {
            (*current).fpu_state.data.copy_from_slice(&frame.fpu_state);
            // Invalidate FPU ownership so the next FPU instruction triggers
            // a lazy reload from the (now-restored) TCB state.
            crate::arch::fpu::disown_if_current(current as *mut u8);
        }

        // Restore user registers from the notification frame
        #[cfg(target_arch = "x86_64")]
        {
            let kst = (*current).kernel_stack_top as *mut u64;
            *kst.offset(-1) = frame.rsp;
            *kst.offset(-2) = frame.r15;
            *kst.offset(-3) = frame.r14;
            *kst.offset(-4) = frame.r13;
            *kst.offset(-5) = frame.r12;
            *kst.offset(-6) = frame.rflags; // R11
            *kst.offset(-7) = frame.r10;
            *kst.offset(-8) = frame.r9;
            *kst.offset(-9) = frame.r8;
            *kst.offset(-10) = frame.rbp;
            *kst.offset(-11) = frame.rdi;
            *kst.offset(-12) = frame.rsi;
            *kst.offset(-13) = frame.rdx;
            *kst.offset(-14) = frame.rip; // RCX = user RIP
            *kst.offset(-15) = frame.rbx;
            // RAX is overwritten by SyscallResult.error → Interrupted
        }

        #[cfg(target_arch = "aarch64")]
        {
            let ctx = &mut (*current).context;
            ctx.x = frame.x;
            ctx.user_sp = frame.sp;
            ctx.return_elr = frame.pc;
            ctx.return_spsr = frame.pstate;
        }

        restore_irq(irq);
        SyscallResult::err(SyscallError::Interrupted)
    }
}

fn syscall_thread_exit() -> SyscallResult {
    unsafe {
        let irq = save_irq_disable();
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();
        if current.is_null() {
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let tcb = &mut *current;
        tcb.tcb_lock();
        crate::sched::pip::pip_cleanup(current);
        detach_thread_wait_queues(current);
        tcb.state = ThreadState::Inactive;
        tcb.blocked_reason = None;
        Tcb::release_tcb_ref(tcb.clear_reply_tcb());
        tcb.reply_can_grant = false;
        tcb.saved_caller_msg = crate::ipc::Message::empty();
        tcb.saved_caller_badge = 0;
        tcb.tcb_unlock();

        scheduler.reschedule();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// Handle a Call syscall that was interrupted by a bound notification.
/// Injects a notification frame if a dispatcher is registered, otherwise
/// returns Interrupted directly.
///
/// # Safety
/// Must be called with IRQs disabled (`irq` from `save_irq_disable`).
/// `tcb` must be the current thread.
/// Handle a Call that was interrupted by a bound notification.
///
/// `intr`: 1 = CallSendBlocked (server never received → Restart),
///         2 = ReplyWait (server received, reply lost → Interrupted).
///
/// # Safety
/// IRQs disabled, `tcb` is current thread.
unsafe fn handle_call_interrupted(
    tcb: *mut crate::sched::thread::Tcb,
    cap_ptr: u64,
    msg_info: u64,
    irq: u64,
    intr: u8,
) -> SyscallResult {
    unsafe {
        let dispatcher = (*tcb).notification_dispatcher;
        if dispatcher != 0 {
            if let Some(result) = inject_notif_frame(tcb, dispatcher, cap_ptr, msg_info) {
                restore_irq(irq);
                return result;
            }
        }
        restore_irq(irq);
        // Restart = server never received (safe to retry)
        // Interrupted = server received, reply lost (non-idempotent ops must not retry)
        if intr == 1 {
            SyscallResult::err(SyscallError::Restart)
        } else {
            SyscallResult::err(SyscallError::Interrupted)
        }
    }
}

/// Reply to caller and receive next message (server pattern)
fn syscall_reply_recv(
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> SyscallResult {
    // Phase 1: Cap lookup under CAP_LOCK
    let cap = match lookup_cap_locked(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_endpoint_cap(&cap, CapRights::RECV) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    let reply = construct_message(msg_info, mr0, mr1, mr2, mr3);

    // Phase 2: IPC under per-endpoint lock (managed inside method)
    unsafe {
        let irq = save_irq_disable();
        let endpoint = &mut *(cap.object as *mut Endpoint);
        let (msg, badge) = match endpoint.reply_recv(&reply) {
            Ok(v) => v,
            Err(err) => {
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };
        write_msg_to_ipc_buffer(&msg, badge);
        restore_irq(irq);
        SyscallResult::ok(badge)
    }
}

fn syscall_recv_any(endpoint_count: u64) -> SyscallResult {
    let mut endpoints = [core::ptr::null_mut(); crate::sched::thread::MAX_RECV_WAIT_ENDPOINTS];
    let count = match unsafe { read_recv_any_endpoints(endpoint_count as usize, &mut endpoints) } {
        Ok(count) => count,
        Err(err) => return SyscallResult::err(err),
    };

    unsafe {
        let irq = save_irq_disable();
        let (msg, badge, source) = match Endpoint::recv_any(&endpoints[..count]) {
            Ok(v) => v,
            Err(err) => {
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };
        write_msg_to_ipc_buffer(&msg, badge);
        restore_irq(irq);
        SyscallResult::ok(source)
    }
}

fn syscall_reply_recv_any(
    endpoint_count: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> SyscallResult {
    let mut endpoints = [core::ptr::null_mut(); crate::sched::thread::MAX_RECV_WAIT_ENDPOINTS];
    let count = match unsafe { read_recv_any_endpoints(endpoint_count as usize, &mut endpoints) } {
        Ok(count) => count,
        Err(err) => return SyscallResult::err(err),
    };

    let reply = construct_message(msg_info, mr0, mr1, mr2, mr3);

    unsafe {
        let irq = save_irq_disable();
        let (msg, badge, source) = match Endpoint::reply_recv_any(&endpoints[..count], &reply) {
            Ok(v) => v,
            Err(err) => {
                restore_irq(irq);
                return SyscallResult::err(err);
            }
        };
        write_msg_to_ipc_buffer(&msg, badge);
        restore_irq(irq);
        SyscallResult::ok(source)
    }
}

fn syscall_recv_any_timed(endpoint_count: u64) -> SyscallResult {
    let mut endpoints = [core::ptr::null_mut(); crate::sched::thread::MAX_RECV_WAIT_ENDPOINTS];
    let count = match unsafe { read_recv_any_endpoints(endpoint_count as usize, &mut endpoints) } {
        Ok(count) => count,
        Err(err) => return SyscallResult::err(err),
    };

    let timeout_ns = unsafe { read_ipc_buffer_timeout() };

    unsafe {
        let irq = save_irq_disable();
        let (msg, badge, source, result) =
            match Endpoint::recv_any_timeout(&endpoints[..count], timeout_ns) {
                Ok(v) => v,
                Err(err) => {
                    restore_irq(irq);
                    return SyscallResult::err(err);
                }
            };
        if result == 0 {
            write_msg_to_ipc_buffer(&msg, badge);
            restore_irq(irq);
            SyscallResult::ok(source)
        } else {
            restore_irq(irq);
            SyscallResult::err(SyscallError::Cancelled)
        }
    }
}

fn syscall_reply_recv_any_timed(
    endpoint_count: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> SyscallResult {
    let mut endpoints = [core::ptr::null_mut(); crate::sched::thread::MAX_RECV_WAIT_ENDPOINTS];
    let count = match unsafe { read_recv_any_endpoints(endpoint_count as usize, &mut endpoints) } {
        Ok(count) => count,
        Err(err) => return SyscallResult::err(err),
    };

    let timeout_ns = unsafe { read_ipc_buffer_timeout() };

    let reply = construct_message(msg_info, mr0, mr1, mr2, mr3);
    unsafe {
        let irq = save_irq_disable();
        let (msg, badge, source, result) =
            match Endpoint::reply_recv_any_timeout(&endpoints[..count], &reply, timeout_ns) {
                Ok(v) => v,
                Err(err) => {
                    restore_irq(irq);
                    return SyscallResult::err(err);
                }
            };
        if result == 0 {
            write_msg_to_ipc_buffer(&msg, badge);
            restore_irq(irq);
            SyscallResult::ok(source)
        } else {
            restore_irq(irq);
            SyscallResult::err(SyscallError::Cancelled)
        }
    }
}

/// Non-blocking send to endpoint
fn syscall_nbsend(
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> SyscallResult {
    // Phase 1: Cap lookup under CAP_LOCK
    let cap = match lookup_cap_locked(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_endpoint_cap(&cap, CapRights::SEND) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    let msg = construct_message(msg_info, mr0, mr1, mr2, mr3);

    // Phase 2: IPC under per-endpoint lock (managed inside method)
    unsafe {
        let irq = save_irq_disable();
        let endpoint = &mut *(cap.object as *mut Endpoint);
        let result = match endpoint.nbsend(&msg, cap.badge) {
            Ok(()) => SyscallResult::ok(0),
            Err(err) => SyscallResult::err(err),
        };
        restore_irq(irq);
        result
    }
}

/// Signal a notification
fn syscall_signal(cap_ptr: u64, bits: u64) -> SyscallResult {
    // Phase 1: Cap lookup under CAP_LOCK
    let cap = match lookup_cap_locked(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_notification_cap(&cap, CapRights::WRITE) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    // Phase 2: Signal under per-notification lock (managed inside method)
    unsafe {
        let irq = save_irq_disable();
        let notification = &mut *(cap.object as *mut Notification);
        notification.signal(cap.badge | bits);
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// Wait on a notification
fn syscall_wait(cap_ptr: u64) -> SyscallResult {
    // Phase 1: Cap lookup under CAP_LOCK
    let cap = match lookup_cap_locked(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_notification_cap(&cap, CapRights::READ) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    // Phase 2: Wait under per-notification lock (managed inside method)
    unsafe {
        let irq = save_irq_disable();
        let notification = &mut *(cap.object as *mut Notification);
        let bits = notification.wait();
        restore_irq(irq);
        SyscallResult::ok(bits)
    }
}

/// Poll notification without blocking
fn syscall_poll(cap_ptr: u64) -> SyscallResult {
    // Phase 1: Cap lookup under CAP_LOCK
    let cap = match lookup_cap_locked(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    match validate_notification_cap(&cap, CapRights::READ) {
        Ok(()) => {}
        Err(e) => return SyscallResult::err(e),
    }

    // Phase 2: Poll is atomic swap — no lock needed
    unsafe {
        let notification = &mut *(cap.object as *mut Notification);
        match notification.poll() {
            Some(bits) => SyscallResult::ok(bits),
            None => SyscallResult::err(SyscallError::WouldBlock),
        }
    }
}

/// Set per-thread invoke depth hints for the next depth-aware capability invoke.
///
/// Args:
/// - depth0: depth hint for invoke arg0 slot address
/// - depth1: depth hint for invoke arg1 slot address
fn syscall_set_invoke_depths(depth0: u64, depth1: u64) -> SyscallResult {
    if depth0 > 64 || depth1 > 64 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let irq = save_irq_disable();
        let current_tcb = crate::sched::scheduler::scheduler().current();
        if current_tcb.is_null() {
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let tcb = &*current_tcb;
        tcb.tcb_lock();
        (*current_tcb).invoke_depth0 = depth0 as u8;
        (*current_tcb).invoke_depth1 = depth1 as u8;
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// Invoke capability operation
fn syscall_invoke(
    cap_ptr: u64,
    label: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> SyscallResult {
    // Stamp this invocation with a per-CPU monotonic sequence number for tracing.
    let seq = crate::arch::next_invoke_seq();
    crate::ktrace!(syscall, |_g| {
        _g.puts("[INVOKE] seq=");
        _g.hex(seq);
        _g.puts(" cap=");
        _g.hex(cap_ptr);
        _g.puts(" label=");
        _g.hex(label);
        _g.putc(b'\n');
    });

    // Phase 1: Initial cap lookup under CAP_LOCK
    let cap = match lookup_cap_locked(cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };

    syscall_invoke_inner(cap, label, cap_ptr, arg0, arg1, arg2, arg3)
}

fn syscall_invoke_inner(
    cap: crate::cap::Capability,
    label: u64,
    cap_ptr: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> SyscallResult {
    match (cap.obj_type, label) {
        (ObjectType::CNode, 0x10) => {
            // CNode_Copy: entire operation under CAP_LOCK
            //   arg0 = src slot index, arg1 = dest CNode cap_ptr
            //   arg2 = dest slot index, arg3 = rights mask
            //   Depths from SYS_SET_INVOKE_DEPTHS: d0=src_depth, d1=dest_depth
            unsafe {
                let irq = save_irq_disable();
                CAP_LOCK.lock();
                let current_tcb = crate::sched::scheduler::scheduler().current();
                let (src_depth, dest_depth) = if !current_tcb.is_null() {
                    read_invoke_depths(current_tcb)
                } else {
                    (0, 0)
                };
                let dest_cnode_cap = match lookup_capability(arg1) {
                    Ok(c) => c,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                if let Err(e) =
                    validate_capability(dest_cnode_cap, ObjectType::CNode, CapRights::WRITE)
                {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(e);
                }
                let rights = CapRights::from_bits(arg3 as u32);
                let src_root = &*(cap.object as *const CNode);
                let dest_root = &*(dest_cnode_cap.object as *const CNode);
                let (src_leaf, src_idx) = match resolve_invoke_slot(src_root, arg0, src_depth) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                let (dest_leaf, dest_idx) = match resolve_invoke_slot(dest_root, arg2, dest_depth) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                let result =
                    match (&mut *dest_leaf).copy_slot(dest_idx, &*src_leaf, src_idx, rights) {
                        Ok(()) => SyscallResult::ok(0),
                        Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
                    };
                CAP_LOCK.unlock();
                restore_irq(irq);
                result
            }
        }
        (ObjectType::CNode, 0x11) => {
            // CNode_Mint: entire operation under CAP_LOCK
            //   arg0 = src slot index, arg1 = dest CNode cap_ptr
            //   arg2 = dest slot index, arg3 = badge value
            //   Depths from SYS_SET_INVOKE_DEPTHS: d0=src_depth, d1=dest_depth
            unsafe {
                let irq = save_irq_disable();
                CAP_LOCK.lock();
                let current_tcb = crate::sched::scheduler::scheduler().current();
                let (src_depth, dest_depth) = if !current_tcb.is_null() {
                    read_invoke_depths(current_tcb)
                } else {
                    (0, 0)
                };
                let dest_cnode_cap = match lookup_capability(arg1) {
                    Ok(c) => c,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                if let Err(e) =
                    validate_capability(dest_cnode_cap, ObjectType::CNode, CapRights::WRITE)
                {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(e);
                }
                let rights = CapRights::from_bits(0xFFFFFFFF & !(1 << 3));
                let src_root = &*(cap.object as *const CNode);
                let dest_root = &*(dest_cnode_cap.object as *const CNode);
                let (src_leaf, src_idx) = match resolve_invoke_slot(src_root, arg0, src_depth) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                let (dest_leaf, dest_idx) = match resolve_invoke_slot(dest_root, arg2, dest_depth) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                let result = match (&mut *dest_leaf)
                    .mint_slot(dest_idx, &*src_leaf, src_idx, arg3, rights)
                {
                    Ok(()) => SyscallResult::ok(0),
                    Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
                };
                CAP_LOCK.unlock();
                restore_irq(irq);
                result
            }
        }
        (ObjectType::CNode, 0x12) => {
            // CNode_Move: entire operation under CAP_LOCK
            //   arg0 = dest slot index, arg1 = src CNode cap_ptr, arg2 = src slot index
            //   Depths from SYS_SET_INVOKE_DEPTHS: d0=dest_depth, d1=src_depth
            unsafe {
                let irq = save_irq_disable();
                CAP_LOCK.lock();
                let current_tcb = crate::sched::scheduler::scheduler().current();
                let (dest_depth, src_depth) = if !current_tcb.is_null() {
                    read_invoke_depths(current_tcb)
                } else {
                    (0, 0)
                };
                let src_cnode_cap = match lookup_capability(arg1) {
                    Ok(c) => c,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                if let Err(e) =
                    validate_capability(src_cnode_cap, ObjectType::CNode, CapRights::WRITE)
                {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(e);
                }
                let dest_root = &*(cap.object as *const CNode);
                let src_root = &*(src_cnode_cap.object as *const CNode);
                let (dest_leaf, dest_idx) = match resolve_invoke_slot(dest_root, arg0, dest_depth) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                let (src_leaf, src_idx) = match resolve_invoke_slot(src_root, arg2, src_depth) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                let result = match (&mut *dest_leaf).move_slot(dest_idx, &mut *src_leaf, src_idx) {
                    Ok(()) => SyscallResult::ok(0),
                    Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
                };
                CAP_LOCK.unlock();
                restore_irq(irq);
                result
            }
        }
        (ObjectType::CNode, 0x13) => {
            // CNode_Mutate: entire operation under CAP_LOCK
            //   arg0 = dest slot index, arg1 = src CNode cap_ptr
            //   arg2 = src slot index, arg3 = new badge value
            //   Depths from SYS_SET_INVOKE_DEPTHS: d0=dest_depth, d1=src_depth
            unsafe {
                let irq = save_irq_disable();
                CAP_LOCK.lock();
                let current_tcb = crate::sched::scheduler::scheduler().current();
                let (dest_depth, src_depth) = if !current_tcb.is_null() {
                    read_invoke_depths(current_tcb)
                } else {
                    (0, 0)
                };
                let src_cnode_cap = match lookup_capability(arg1) {
                    Ok(c) => c,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                if let Err(e) =
                    validate_capability(src_cnode_cap, ObjectType::CNode, CapRights::WRITE)
                {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(e);
                }
                let dest_root = &*(cap.object as *const CNode);
                let src_root = &*(src_cnode_cap.object as *const CNode);
                let (dest_leaf, dest_idx) = match resolve_invoke_slot(dest_root, arg0, dest_depth) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                let (src_leaf, src_idx) = match resolve_invoke_slot(src_root, arg2, src_depth) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                let result =
                    match (&mut *dest_leaf).mutate_slot(dest_idx, &mut *src_leaf, src_idx, arg3) {
                        Ok(()) => SyscallResult::ok(0),
                        Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
                    };
                CAP_LOCK.unlock();
                restore_irq(irq);
                result
            }
        }
        (ObjectType::CNode, 0x14) => {
            // CNode_Delete: entire operation under CAP_LOCK
            //   Depth from SYS_SET_INVOKE_DEPTHS: d0=arg0 depth
            if !cap.has_right(CapRights::WRITE) {
                return SyscallResult::err(SyscallError::InsufficientRights);
            }
            unsafe {
                let irq = save_irq_disable();
                CAP_LOCK.lock();
                let current_tcb = crate::sched::scheduler::scheduler().current();
                let (depth, _) = if !current_tcb.is_null() {
                    read_invoke_depths(current_tcb)
                } else {
                    (0, 0)
                };
                let cnode_root = &*(cap.object as *const CNode);
                let (leaf, idx) = match resolve_invoke_slot(cnode_root, arg0, depth) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                let result = match (&mut *leaf).delete(idx) {
                    Ok(()) => SyscallResult::ok(0),
                    Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
                };
                CAP_LOCK.unlock();
                restore_irq(irq);
                result
            }
        }
        (ObjectType::CNode, 0x15) => {
            // CNode_Revoke: entire operation under CAP_LOCK
            //   Depth from SYS_SET_INVOKE_DEPTHS: d0=arg0 depth
            if !cap.has_right(CapRights::WRITE) {
                return SyscallResult::err(SyscallError::InsufficientRights);
            }
            unsafe {
                let irq = save_irq_disable();
                CAP_LOCK.lock();
                let current_tcb = crate::sched::scheduler::scheduler().current();
                let (depth, _) = if !current_tcb.is_null() {
                    read_invoke_depths(current_tcb)
                } else {
                    (0, 0)
                };
                let cnode_root = &*(cap.object as *const CNode);
                let (leaf, idx) = match resolve_invoke_slot(cnode_root, arg0, depth) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                let result = match (&mut *leaf).revoke(idx) {
                    Ok(()) => SyscallResult::ok(0),
                    Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
                };
                CAP_LOCK.unlock();
                restore_irq(irq);
                result
            }
        }
        (ObjectType::CNode, 0x16) => {
            // CNode_SaveCaller: entire operation under CAP_LOCK
            //   arg0 = slot index to save the reply cap into
            //   Depth from SYS_SET_INVOKE_DEPTHS: d0=arg0 depth
            if !cap.has_right(CapRights::WRITE) {
                return SyscallResult::err(SyscallError::InsufficientRights);
            }
            unsafe {
                let irq = save_irq_disable();
                CAP_LOCK.lock();
                let current_tcb = crate::sched::scheduler::scheduler().current();
                if current_tcb.is_null() {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(SyscallError::InvalidOperation);
                }
                let (depth, _) = read_invoke_depths(current_tcb);
                let cnode_root = &*(cap.object as *const CNode);
                let (leaf, idx) = match resolve_invoke_slot(cnode_root, arg0, depth) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                let result = match (&mut *leaf).save_caller(idx, current_tcb) {
                    Ok(()) => SyscallResult::ok(0),
                    Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
                };
                CAP_LOCK.unlock();
                restore_irq(irq);
                result
            }
        }
        (ObjectType::CNode, 0x17) => {
            // CNODE_SET_GUARD: arg0 = guard value, arg1 = guard_bits
            // CNode must be empty (all slots null) to prevent invalidating existing addresses.
            if !cap.has_right(CapRights::WRITE) {
                return SyscallResult::err(SyscallError::InsufficientRights);
            }
            if arg1 > 64 {
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            unsafe {
                let irq = save_irq_disable();
                CAP_LOCK.lock();
                let cnode = &mut *(cap.object as *mut CNode);
                // Verify all slots are empty
                let num_slots = cnode.num_slots();
                let mut all_empty = true;
                for i in 0..num_slots {
                    if !cnode.is_slot_empty(i) {
                        all_empty = false;
                        break;
                    }
                }
                if !all_empty {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(SyscallError::InvalidOperation);
                }
                cnode.guard = arg0;
                cnode.guard_bits = arg1 as u8;
                CAP_LOCK.unlock();
                restore_irq(irq);
                SyscallResult::ok(0)
            }
        }
        (ObjectType::CNode, 0x18) => {
            // CNODE_GET_INFO: returns guard, guard_bits, size_bits, num_slots
            // via return value (packed) and IPC buffer.
            if !cap.has_right(CapRights::READ) {
                return SyscallResult::err(SyscallError::InsufficientRights);
            }
            unsafe {
                let irq = save_irq_disable();
                CAP_LOCK.lock();
                let cnode = &*(cap.object as *const CNode);
                let guard = cnode.guard;
                let guard_bits = cnode.guard_bits as u64;
                let size_bits = cnode.header.size_bits as u64;
                let num_slots = cnode.num_slots() as u64;
                CAP_LOCK.unlock();
                restore_irq(irq);

                // Write info to IPC buffer: msg[0]=guard, msg[1]=guard_bits,
                // msg[2]=size_bits, msg[3]=num_slots
                let scheduler = crate::sched::scheduler::scheduler();
                let current = scheduler.current();
                if !current.is_null() {
                    let buf = (*current).ipc_buffer;
                    if buf != 0
                        && validate_ipc_buffer_addr(buf).is_ok()
                        && !(*current).vspace_root.is_null()
                    {
                        let vs = &mut *(*current).vspace_root;
                        if vs.ensure_writable(buf) {
                            let _guard = crate::arch::uaccess::UserAccessGuard::new();
                            let ipc_buf = buf as *mut crate::ipc::IpcBuffer;
                            (*ipc_buf).msg[0] = guard;
                            (*ipc_buf).msg[1] = guard_bits;
                            (*ipc_buf).msg[2] = size_bits;
                            (*ipc_buf).msg[3] = num_slots;
                        }
                    }
                }
                SyscallResult::ok(0)
            }
        }

        // Untyped operations
        (ObjectType::Untyped, 0x20) => {
            // UNTYPED_RETYPE: arg0 = new_type, arg1 = size_bits, arg2 = dest_offset
            syscall_untyped_retype(&cap, cap_ptr, arg0, arg1, arg2)
        }
        (ObjectType::Untyped, 0x21) => {
            // UNTYPED_RESET: reset watermark after the untyped becomes child-free
            syscall_untyped_reset(&cap, cap_ptr)
        }

        // TCB operations
        (ObjectType::Tcb, 0x40) => {
            // TCB_CONFIGURE: arg0 = entry_rip, arg1 = entry_rsp, arg2 = ipc_buffer_addr
            syscall_tcb_configure(&cap, arg0, arg1, arg2)
        }
        (ObjectType::Tcb, 0x41) => {
            // TCB_RESUME
            syscall_tcb_resume(&cap)
        }
        (ObjectType::Tcb, 0x42) => {
            // TCB_SUSPEND
            syscall_tcb_suspend(&cap)
        }
        (ObjectType::Tcb, 0x43) => {
            // TCB_SET_SPACE: arg0 = cspace_cap_ptr, arg1 = vspace_cap_ptr, arg2 = cspace_depth
            syscall_tcb_set_space(&cap, arg0, arg1, arg2)
        }
        (ObjectType::Tcb, 0x44) => {
            // TCB_SET_AFFINITY: arg0 = cpu_id
            syscall_tcb_set_affinity(&cap, arg0)
        }
        (ObjectType::Tcb, 0x45) => {
            // TCB_READ_REGISTERS: arg0 = flags
            syscall_tcb_read_registers(&cap, arg0)
        }
        (ObjectType::Tcb, 0x46) => {
            // TCB_WRITE_REGISTERS: arg0 = flags, arg1 = rip, arg2 = rsp
            syscall_tcb_write_registers(&cap, arg0, arg1, arg2)
        }
        (ObjectType::Tcb, 0x47) => {
            // TCB_SET_PRIORITY: arg0 = priority
            syscall_tcb_set_priority(&cap, arg0)
        }
        (ObjectType::Tcb, 0x48) => {
            // TCB_SET_IPC_BUFFER: arg0 = addr
            syscall_tcb_set_ipc_buffer(&cap, arg0)
        }
        (ObjectType::Tcb, 0x49) => {
            // TCB_BIND_NOTIFICATION: arg0 = ntfn_cap_ptr
            syscall_tcb_bind_notification(&cap, arg0)
        }
        (ObjectType::Tcb, 0x4A) => {
            // TCB_UNBIND_NOTIFICATION
            syscall_tcb_unbind_notification(&cap)
        }
        (ObjectType::Tcb, 0x4B) => {
            // TCB_SET_FAULT_HANDLER: arg0 = fault_ep_cap_ptr
            syscall_tcb_set_fault_handler(&cap, arg0)
        }
        (ObjectType::Tcb, 0x4C) => {
            // TCB_COPY_FPU: copy FPU state from source TCB (arg0) to dest TCB (cap)
            syscall_tcb_copy_fpu(&cap, arg0)
        }
        (ObjectType::Tcb, 0x4D) => {
            // TCB_SET_TLS_BASE: arg0 = tls_base address
            syscall_tcb_set_tls_base(&cap, arg0)
        }
        (ObjectType::Tcb, 0x4E) => {
            // TCB_SET_NOTIFICATION_DISPATCHER: arg0 = dispatcher address
            syscall_tcb_set_notification_dispatcher(&cap, arg0)
        }
        (ObjectType::Tcb, 0x4F) => {
            // TCB_GET_SPACE_INFO: returns cspace_depth via IPC buffer msg[0]
            syscall_tcb_get_space_info(&cap)
        }

        // VSpace operations
        (ObjectType::VSpace, 0x50) => {
            // VSPACE_MAP: arg0 = frame_cap_ptr, arg1 = virt_addr, arg2 = flags_bits
            syscall_vspace_map(&cap, arg0, arg1, arg2)
        }
        (ObjectType::VSpace, 0x51) => {
            // VSPACE_UNMAP: arg0 = virt_addr
            syscall_vspace_unmap(&cap, arg0)
        }
        (ObjectType::VSpace, 0x52) => {
            // VSPACE_MAP_PT: arg0 = frame_cap_ptr, arg1 = virt_addr, arg2 = level
            syscall_vspace_map_pt(&cap, arg0, arg1, arg2)
        }
        (ObjectType::VSpace, 0x53) => {
            // VSPACE_WALK: arg0 = start_vaddr, arg1 = max_entries
            syscall_vspace_walk(&cap, arg0, arg1)
        }
        (ObjectType::VSpace, 0x54) => {
            // VSPACE_COPY_PAGE: arg0 = src_vaddr, arg1 = dst_frame_cap_ptr
            syscall_vspace_copy_page(&cap, arg0, arg1)
        }
        (ObjectType::VSpace, 0x55) => {
            // VSPACE_MAP_DEVICE: arg0 = device_untyped_cap_ptr,
            //                    arg1 = page_offset, arg2 = virt_addr, arg3 = flags_bits
            syscall_vspace_map_device(&cap, arg0, arg1, arg2, arg3)
        }
        (ObjectType::VSpace, 0x56) => {
            // VSPACE_CLONE_COW_PAGE: arg0 = src_vaddr,
            //                         arg1 = dst_vspace_cap_ptr,
            //                         arg2 = dst_vaddr
            syscall_vspace_clone_cow_page(&cap, arg0, arg1, arg2)
        }
        (ObjectType::VSpace, 0x57) => {
            // VSPACE_MAP_DEVICE_RANGE: arg0 = device_untyped_cap_ptr,
            //   arg1 = offset_start, arg2 = vaddr_start,
            //   arg3 = (count << 32) | flags
            syscall_vspace_map_device_range(&cap, arg0, arg1, arg2, arg3)
        }
        (ObjectType::VSpace, 0x58) => {
            // VSPACE_PROTECT: arg0 = virt_addr, arg1 = flags_bits
            syscall_vspace_protect(&cap, arg0, arg1)
        }
        (ObjectType::VSpace, 0x59) => {
            // VSPACE_MAP_DEMAND: arg0 = virt_addr, arg1 = flags_bits
            syscall_vspace_map_demand(&cap, arg0, arg1)
        }
        (ObjectType::VSpace, 0x5A) => {
            // VSPACE_MAP_DEMAND_RANGE: arg0 = virt_addr, arg1 = count, arg2 = flags_bits
            syscall_vspace_map_demand_range(&cap, arg0, arg1, arg2)
        }
        (ObjectType::VSpace, 0x5B) => {
            // VSPACE_COW_RESOLVE: arg0 = virt_addr, arg1 = frame_cap_ptr, arg2 = flags_bits
            syscall_vspace_cow_resolve(&cap, arg0, arg1, arg2)
        }
        (ObjectType::VSpace, 0x5C) => {
            // VSPACE_SET_COW_POOL: arg0 = pool_frame_cap_ptr, arg1 = src_cnode_cap_ptr, arg2 = count
            syscall_vspace_set_cow_pool(&cap, arg0, arg1, arg2)
        }
        (ObjectType::VSpace, 0x5D) => {
            // VSPACE_SET_COW_NOTIF: arg0 = ring_frame_cap_ptr, arg1 = notif_cap_ptr
            syscall_vspace_set_cow_notif(&cap, arg0, arg1)
        }
        (ObjectType::VSpace, 0x5E) => {
            // VSPACE_REPLENISH_COW_POOL: arg0 = src_cnode_cap_ptr, arg1 = start_slot, arg2 = count
            syscall_vspace_replenish_cow_pool(&cap, arg0, arg1, arg2)
        }
        (ObjectType::VSpace, 0x5F) => {
            // VSPACE_PROTECT_RANGE: arg0 = virt_addr, arg1 = count, arg2 = flags_bits
            syscall_vspace_protect_range(&cap, arg0, arg1, arg2)
        }
        (ObjectType::VSpace, 0x97) => {
            // VSPACE_MAP_MO: arg0 = mo_cap_ptr, arg1 = vaddr, arg2 = mo_offset, arg3 = count_and_flags
            syscall_vspace_map_mo(&cap, arg0, arg1, arg2, arg3)
        }
        (ObjectType::VSpace, 0x99) => {
            // VSPACE_SHARE_RO_PAGE: arg0 = src_vaddr,
            //   arg1 = dst_vspace_cap_ptr, arg2 = dst_vaddr
            syscall_vspace_share_ro_page(&cap, arg0, arg1, arg2)
        }
        (ObjectType::VSpace, 0x9A) => {
            // VSPACE_FORK_RANGE: cap = parent VSpace
            // arg0 = child_vspace_cap, arg1 = child_mo_cap,
            // arg2 = va_start, arg3 = (page_count<<32)|mo_offset
            syscall_vspace_fork_range(&cap, arg0, arg1, arg2, arg3)
        }

        // SchedContext operations
        (ObjectType::SchedContext, 0x30) => {
            // SC_CONFIGURE: arg0 = budget (microseconds), arg1 = period (microseconds)
            syscall_sc_configure(&cap, arg0, arg1)
        }
        (ObjectType::SchedContext, 0x31) => {
            // SC_BIND: arg0 = tcb_cap_ptr
            syscall_sc_bind(&cap, arg0)
        }
        (ObjectType::SchedContext, 0x32) => {
            // SC_UNBIND
            syscall_sc_unbind(&cap)
        }
        (ObjectType::SchedContext, 0x33) => {
            // SC_YIELD_TO: arg0 = target_sc_cap_ptr
            syscall_sc_yield_to(&cap, arg0)
        }
        (ObjectType::SchedContext, 0x34) => {
            // SC_CONSUMED: Query consumed time
            syscall_sc_consumed(&cap)
        }

        // IRQ operations
        (ObjectType::IrqHandler, 0x60) => {
            // IRQ_CONTROL_GET: arg0 = irq_num, arg1 = dest_cnode_cap, arg2 = dest_slot
            syscall_irq_control_get(&cap, arg0, arg1, arg2)
        }
        (ObjectType::IrqHandler, 0x61) => {
            // IRQ_HANDLER_ACK
            syscall_irq_handler_ack(&cap)
        }
        (ObjectType::IrqHandler, 0x62) => {
            // IRQ_HANDLER_SET_NOTIFICATION: arg0 = ntfn_cap_ptr
            syscall_irq_handler_set_notification(&cap, arg0)
        }
        (ObjectType::IrqHandler, 0x63) => {
            // IRQ_HANDLER_CLEAR
            syscall_irq_handler_clear(&cap)
        }
        (ObjectType::IrqHandler, 0x64) => {
            // DEVICE_UNTYPED_CREATE: arg0 = phys_addr, arg1 = size_bits,
            // arg2 = dest_cnode_cap, arg3 = dest_slot
            syscall_device_untyped_create(&cap, arg0, arg1, arg2, arg3)
        }
        (ObjectType::IrqHandler, 0x77) => {
            // IOPORT_CREATE: arg0 = base_port, arg1 = num_ports,
            // arg2 = dest_cnode_cap, arg3 = dest_slot
            syscall_ioport_create(&cap, arg0, arg1, arg2, arg3)
        }

        // IoPort operations
        (ObjectType::IoPort, 0x70) => {
            // IOPORT_IN8: arg0 = port offset
            syscall_ioport_in8(&cap, arg0)
        }
        (ObjectType::IoPort, 0x71) => {
            // IOPORT_OUT8: arg0 = port offset, arg1 = value
            syscall_ioport_out8(&cap, arg0, arg1)
        }
        (ObjectType::IoPort, 0x72) => {
            // IOPORT_IN16: arg0 = port offset
            syscall_ioport_in16(&cap, arg0)
        }
        (ObjectType::IoPort, 0x73) => {
            // IOPORT_OUT16: arg0 = port offset, arg1 = value
            syscall_ioport_out16(&cap, arg0, arg1)
        }
        (ObjectType::IoPort, 0x74) => {
            // IOPORT_IN32: arg0 = port offset
            syscall_ioport_in32(&cap, arg0)
        }
        (ObjectType::IoPort, 0x75) => {
            // IOPORT_OUT32: arg0 = port offset, arg1 = value
            syscall_ioport_out32(&cap, arg0, arg1)
        }
        (ObjectType::IoPort, 0x76) => {
            // IOPORT_CONFIGURE: arg0 = base_port, arg1 = num_ports
            syscall_ioport_configure(&cap, arg0, arg1)
        }

        // MemoryObject operations
        (ObjectType::MemoryObject, 0x90) => {
            // MO_COMMIT: arg0 = offset, arg1 = count, arg2 = ut_cap_ptr (0 = PMM)
            syscall_mo_commit(&cap, arg0, arg1, arg2)
        }
        (ObjectType::MemoryObject, 0x91) => {
            // MO_DECOMMIT: arg0 = offset, arg1 = count
            syscall_mo_decommit(&cap, arg0, arg1)
        }
        (ObjectType::MemoryObject, 0x92) => {
            // MO_GET_SIZE
            syscall_mo_get_size(&cap)
        }
        (ObjectType::MemoryObject, 0x93) => {
            // MO_CLONE: arg0 = child_mo_cap_ptr, arg1 = flags
            syscall_mo_clone(&cap, arg0, arg1)
        }
        (ObjectType::MemoryObject, 0x94) => {
            // MO_RESIZE: arg0 = new_page_count
            syscall_mo_resize(&cap, arg0)
        }
        (ObjectType::MemoryObject, 0x95) => {
            // MO_READ: arg0 = offset, arg1 = count
            syscall_mo_read(&cap, arg0, arg1)
        }
        (ObjectType::MemoryObject, 0x96) => {
            // MO_WRITE: arg0 = offset, arg1 = count
            syscall_mo_write(&cap, arg0, arg1)
        }
        (ObjectType::MemoryObject, 0x97) => {
            // MO_HAS_PAGE: arg0 = page index
            syscall_mo_has_page(&cap, arg0)
        }

        _ => SyscallResult::err(SyscallError::InvalidOperation),
    }
}

/// SC_CONFIGURE: Configure scheduling context parameters
///
/// Args:
/// - budget_us: Budget per period in microseconds (must be > 0)
/// - period_us: Period in microseconds (0 = sporadic, otherwise >= budget)
fn syscall_sc_configure(cap: &Capability, budget_us: u64, period_us: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    if budget_us == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // For periodic tasks, period must be >= budget
    if period_us != 0 && period_us < budget_us {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // Convert microseconds to ticks (1 tick = 1ms = 1000us)
    let budget_ticks = budget_us / 1000;
    let period_ticks = period_us / 1000;

    if budget_ticks == 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // Operation under per-SC lock (SC state mutation)
    unsafe {
        let irq = save_irq_disable();
        let sc = &mut *(cap.object as *mut SchedContext);
        sc.sc_lock();
        sc.budget = budget_ticks;
        sc.period = period_ticks;
        sc.remaining = budget_ticks;

        if period_ticks > 0 {
            let now = crate::arch::get_ticks() as u64;
            sc.deadline = now + period_ticks;
        } else {
            sc.deadline = u64::MAX;
        }
        sc.sc_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// SC_BIND: Bind a scheduling context to a TCB
///
/// Args:
/// - tcb_cap_ptr: Capability pointer to the target TCB
fn syscall_sc_bind(cap: &Capability, tcb_cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Sub-lookup under CAP_LOCK
    let tcb_cap = match lookup_cap_locked(tcb_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&tcb_cap, ObjectType::Tcb, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Operation under per-SC lock + per-TCB lock (lock order: sc_lock → tcb_lock)
    unsafe {
        let irq = save_irq_disable();
        let sc = &mut *(cap.object as *mut SchedContext);
        sc.sc_lock();
        let tcb = &mut *(tcb_cap.object as *mut Tcb);
        tcb.tcb_lock();

        if !sc.bound_tcb.is_null() {
            tcb.tcb_unlock();
            sc.sc_unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        if !tcb.sched_context.is_null() {
            tcb.tcb_unlock();
            sc.sc_unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        sc.bound_tcb = tcb as *mut Tcb;
        tcb.sched_context = sc as *mut SchedContext;
        tcb.base_priority = sc.deadline;
        tcb.priority = sc.deadline;

        // TCB holds a strong reference on the SchedContext
        crate::cap::increment_refcount(sc as *mut SchedContext as *mut crate::cap::KernelObject);

        if tcb.state == ThreadState::Ready {
            let scheduler = crate::sched::scheduler::scheduler();
            scheduler.remove_from_ready_queue(tcb as *mut Tcb);
            scheduler.enqueue(tcb as *mut Tcb);
        }
        tcb.tcb_unlock();
        sc.sc_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// SC_UNBIND: Unbind a scheduling context from its TCB
fn syscall_sc_unbind(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Operation under per-SC lock
    let old_sc;
    unsafe {
        let irq = save_irq_disable();
        let sc = &mut *(cap.object as *mut SchedContext);
        sc.sc_lock();

        if sc.bound_tcb.is_null() {
            sc.sc_unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let tcb = &mut *sc.bound_tcb;

        if tcb.state == ThreadState::Running || tcb.state == ThreadState::Ready {
            sc.sc_unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        old_sc = tcb.sched_context;
        tcb.sched_context = core::ptr::null_mut();
        sc.bound_tcb = core::ptr::null_mut();
        sc.sc_unlock();
        restore_irq(irq);
    }

    // Release TCB's strong reference on the SchedContext
    if !old_sc.is_null() {
        unsafe {
            crate::cap::release_object(
                old_sc as *mut crate::cap::KernelObject,
                ObjectType::SchedContext,
            );
        }
    }

    SyscallResult::ok(0)
}

/// SC_YIELD_TO: Transfer remaining budget to target scheduling context
///
/// Args:
/// - target_sc_cap_ptr: Capability pointer to the target SchedContext
fn syscall_sc_yield_to(cap: &Capability, target_sc_cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Sub-lookup under CAP_LOCK
    let target_cap = match lookup_cap_locked(target_sc_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&target_cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Operation under both SC locks (address-ordered to avoid ABBA deadlock)
    unsafe {
        let irq = save_irq_disable();
        let current_sc = &mut *(cap.object as *mut SchedContext);
        let target_sc = &mut *(target_cap.object as *mut SchedContext);

        // Lock in pointer-address order to prevent ABBA deadlock
        let current_ptr = current_sc as *mut SchedContext as usize;
        let target_ptr = target_sc as *mut SchedContext as usize;
        if current_ptr < target_ptr {
            current_sc.sc_lock();
            target_sc.sc_lock();
        } else if current_ptr > target_ptr {
            target_sc.sc_lock();
            current_sc.sc_lock();
        } else {
            // Same SC — just lock once
            current_sc.sc_lock();
        }

        target_sc.remaining += current_sc.remaining;
        current_sc.remaining = 0;

        if current_ptr != target_ptr {
            target_sc.sc_unlock();
        }

        let scheduler = crate::sched::scheduler::scheduler();
        current_sc.sc_unlock();
        scheduler.yield_current();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// TCB_CONFIGURE: Set thread entry point, stack, and IPC buffer
///
/// Args:
/// - entry_rip: Entry instruction pointer
/// - entry_rsp: Entry stack pointer
/// - ipc_buffer: IPC buffer virtual address
///
/// If the TCB has a VSpace set (via TCB_SET_SPACE), configures
/// the thread to enter usermode via the trampoline (iretq).
/// Otherwise treats it as a kernel thread (ring 0).
fn syscall_tcb_configure(
    cap: &Capability,
    entry_rip: u64,
    entry_rsp: u64,
    ipc_buffer: u64,
) -> SyscallResult {
    // Maximum automatic user-stack growth window below the configured top.
    const USER_STACK_GROW_LIMIT: u64 = 0x0010_0000; // 1 MiB

    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    if let Err(e) = validate_ipc_buffer_addr(ipc_buffer) {
        return SyscallResult::err(e);
    }

    crate::kdebug!(syscall, |_g| {
        _g.puts("[TCB_CONFIGURE] begin tcb=");
        _g.hex(cap.object as u64);
        _g.puts(" entry=");
        _g.hex(entry_rip);
        _g.puts(" rsp=");
        _g.hex(entry_rsp);
        _g.puts(" ipc=");
        _g.hex(ipc_buffer);
        _g.puts(" free=");
        _g.dec(crate::mm::pmm_free_count() as u64);
        _g.puts("\n");
    });

    // Allocate kernel stack (4 contiguous pages = 16 KiB).
    // A single page (4 KiB) overflows on deep syscall paths (IPC fastpath
    // with context switching, VSpace operations, capability chains).
    const KSTACK_PAGES: usize = 4;

    // pmm_alloc_contiguous has its own MM_LOCK — do BEFORE acquiring per-TCB lock
    let kstack_phys = match crate::mm::pmm_alloc_contiguous(KSTACK_PAGES) {
        Some(f) => f,
        None => {
            crate::kdebug!(syscall, |_g| {
                _g.puts("[TCB_CONFIGURE] kernel-stack alloc failed tcb=");
                _g.hex(cap.object as u64);
                _g.puts(" need_pages=");
                _g.dec(KSTACK_PAGES as u64);
                _g.puts(" free=");
                _g.dec(crate::mm::pmm_free_count() as u64);
                _g.puts("\n");
            });
            return SyscallResult::err(SyscallError::OutOfMemory);
        }
    };
    let kstack_owner = crate::mm::frame::FrameOwner::KernelPrivate {
        subkind: crate::mm::frame::KernelMetaKind::KernelStack,
    };
    for i in 0..KSTACK_PAGES {
        crate::mm::pmm_set_owner(kstack_phys + (i * crate::mm::PAGE_SIZE) as u64, &kstack_owner);
    }

    // TCB mutation under per-TCB lock
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();

        // Only allow configuring threads that are Inactive.
        // Configuring a Running/Ready/Blocked thread would corrupt its context.
        if tcb.state != ThreadState::Inactive {
            tcb.tcb_unlock();
            restore_irq(irq);
            for i in 0..KSTACK_PAGES {
                crate::mm::pmm_free(kstack_phys + (i * crate::mm::PAGE_SIZE) as u64, &kstack_owner);
            }
            crate::kdebug!(syscall, |_g| {
                _g.puts("[TCB_CONFIGURE] rejected busy tcb=");
                _g.hex(cap.object as u64);
                _g.puts(" state=");
                _g.dec(tcb.state as u64);
                _g.puts(" free=");
                _g.dec(crate::mm::pmm_free_count() as u64);
                _g.puts("\n");
            });
            return SyscallResult::err(SyscallError::Busy);
        }

        let kstack_virt = crate::mm::phys_to_virt(kstack_phys);
        let kstack_top = kstack_virt + (KSTACK_PAGES * crate::mm::PAGE_SIZE) as u64;
        core::ptr::write_bytes(
            kstack_virt as *mut u8,
            0,
            KSTACK_PAGES * crate::mm::PAGE_SIZE,
        );

        if !tcb.vspace_root.is_null() {
            #[cfg(target_arch = "x86_64")]
            let vspace_root = tcb.vspace_root;
            tcb.tcb_unlock();
            restore_irq(irq);

            #[cfg(target_arch = "x86_64")]
            let tramp_stack_top = {
                // Allocate trampoline stack outside lock
                let tramp_stack_phys =
                    match crate::mm::pmm_alloc(&crate::mm::frame::FrameOwner::KernelPrivate {
                        subkind: crate::mm::frame::KernelMetaKind::KernelStack,
                    }) {
                        Some(f) => f,
                        None => {
                            for i in 0..KSTACK_PAGES {
                                crate::mm::pmm_free(
                                    kstack_phys + (i * crate::mm::PAGE_SIZE) as u64,
                                    &kstack_owner,
                                );
                            }
                            crate::kdebug!(syscall, |_g| {
                                _g.puts("[TCB_CONFIGURE] trampoline alloc failed tcb=");
                                _g.hex(cap.object as u64);
                                _g.puts(" free=");
                                _g.dec(crate::mm::pmm_free_count() as u64);
                                _g.puts("\n");
                            });
                            return SyscallResult::err(SyscallError::OutOfMemory);
                        }
                    };
                let tramp_stack_virt = crate::mm::phys_to_virt(tramp_stack_phys);
                let tramp_stack_top = tramp_stack_virt + crate::mm::PAGE_SIZE as u64;
                core::ptr::write_bytes(tramp_stack_virt as *mut u8, 0, crate::mm::PAGE_SIZE);
                tramp_stack_top
            };

            let irq = save_irq_disable();
            tcb.tcb_lock();

            #[cfg(target_arch = "x86_64")]
            {
                let vspace = &*vspace_root;
                tcb.kernel_stack_top = kstack_top;
                tcb.trampoline_stack_top = tramp_stack_top;
                tcb.stack_canary = crate::arch::generate_stack_canary();
                tcb.context.rip = crate::arch::usermode_trampoline as *const () as u64;
                tcb.context.rsp = tramp_stack_top;
                tcb.context.r12 = entry_rip;
                tcb.context.r13 = entry_rsp;
                tcb.context.r14 = vspace.root();
                tcb.context.r15 = 0x0202;
                tcb.context.rflags = 0x202;
            }
            #[cfg(target_arch = "aarch64")]
            {
                tcb.kernel_stack_top = kstack_top;
                tcb.trampoline_stack_top = 0;
                tcb.stack_canary = crate::arch::generate_stack_canary();
                crate::arch::aarch64::context::init_user_thread_context(
                    &mut tcb.context,
                    kstack_top,
                    entry_rip,
                    entry_rsp,
                    0x0,
                );
            }

            tcb.ipc_buffer = ipc_buffer;
            tcb.user_stack_top = entry_rsp;
            tcb.user_stack_min = entry_rsp.saturating_sub(USER_STACK_GROW_LIMIT);
            // Reset FPU state for fresh execution (exec replaces the process image)
            tcb.fpu_initialized = false;
            tcb.fpu_state = crate::sched::thread::XSaveArea::zeroed();
            tcb.tcb_unlock();
            restore_irq(irq);
        } else {
            tcb.tcb_unlock();
            restore_irq(irq);
            for i in 0..KSTACK_PAGES {
                crate::mm::pmm_free(kstack_phys + (i * crate::mm::PAGE_SIZE) as u64, &kstack_owner);
            }
            crate::kdebug!(syscall, |_g| {
                _g.puts("[TCB_CONFIGURE] missing vspace root tcb=");
                _g.hex(cap.object as u64);
                _g.puts(" free=");
                _g.dec(crate::mm::pmm_free_count() as u64);
                _g.puts("\n");
            });
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
    }

    crate::kdebug!(syscall, |_g| {
        _g.puts("[TCB_CONFIGURE] success tcb=");
        _g.hex(cap.object as u64);
        _g.puts(" kstack_phys=");
        _g.hex(kstack_phys);
        _g.puts(" free=");
        _g.dec(crate::mm::pmm_free_count() as u64);
        _g.puts("\n");
    });

    SyscallResult::ok(0)
}

/// Detach a blocked thread from auxiliary wait queues before changing its run state.
///
/// Delegates to `sched::thread::detach_thread_wait_queues` which handles
/// endpoint, notification, sleep, futex, and VSpace waiter queues.
#[inline]
unsafe fn detach_thread_wait_queues(tcb: *mut Tcb) {
    unsafe {
        crate::sched::thread::detach_thread_wait_queues(tcb);
    }
}

/// Wait until a suspended thread is fully drained from scheduler ownership.
///
/// A thread is not safe to reuse merely because its state changed away from
/// `Running`: another CPU may still own its live kernel context, or the thread
/// may still be parked in a deferred switch-out slot awaiting post-switch
/// cleanup. `exec` reuses the same TCB immediately after `TCB_SUSPEND`, so the
/// suspend path must wait for both conditions to clear.
unsafe fn wait_for_tcb_quiesced(tcb: *mut Tcb, cpu_hint: Option<usize>) -> bool {
    let this_cpu = crate::arch::current_cpu() as usize;

    for spins in 0..SUSPEND_SPIN_LIMIT {
        let (running_cpu, pending_cpu, run_owner_cpu) = {
            let irq = save_irq_disable();
            let scheduler = crate::sched::scheduler::scheduler();
            scheduler.lock();

            // Same-CPU fast path: the target may be parked in *our* deferred
            // pending slot. On x86_64 the syscall entry path clears IF via
            // IA32_FMASK, so IRQs stay disabled throughout — timer_tick (and
            // therefore process_pending_enqueue) can never fire. Flush the
            // slot ourselves to break the self-deadlock.
            if scheduler.pending_cpu_for(tcb) == Some(this_cpu) {
                scheduler.process_pending_enqueue();
            }

            let running_cpu = scheduler.find_running_cpu(tcb);
            let pending_cpu = scheduler.pending_cpu_for(tcb);
            let run_owner_cpu = (*tcb).run_owner();
            scheduler.unlock();
            restore_irq(irq);
            (running_cpu, pending_cpu, run_owner_cpu)
        };

        if running_cpu.is_none() && pending_cpu.is_none() && run_owner_cpu.is_none() {
            return true;
        }

        if spins == 0 || (spins & 0x3ff) == 0 {
            if let Some(cpu) = running_cpu.or(pending_cpu).or(run_owner_cpu).or(cpu_hint) {
                if cpu != this_cpu {
                    crate::arch::send_ipi(cpu, crate::arch::IpiKind::Reschedule);
                }
            }
        }

        core::hint::spin_loop();
    }

    false
}

unsafe fn wait_for_tcb_quiesced_blocking(tcb: *mut Tcb, cpu_hint: Option<usize>) {
    while unsafe { !wait_for_tcb_quiesced(tcb, cpu_hint) } {
        crate::sched::yield_now();
    }
}

/// TCB_RESUME: Make a thread runnable
fn syscall_tcb_resume(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::RESUME) {
        return SyscallResult::err(e);
    }

    // Operation under per-TCB lock (TCB state transitions + scheduler)
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        match tcb.state {
            ThreadState::Running | ThreadState::Ready => {
                // Already runnable, no-op
            }
            ThreadState::Inactive => {
                let scheduler = crate::sched::scheduler::scheduler();
                scheduler.enqueue(tcb as *mut Tcb);
            }
            ThreadState::Blocked => {
                let scheduler = crate::sched::scheduler::scheduler();
                detach_thread_wait_queues(tcb as *mut Tcb);
                tcb.blocked_reason = None;
                scheduler.enqueue(tcb as *mut Tcb);
            }
            ThreadState::Waiting => {
                detach_thread_wait_queues(tcb as *mut Tcb);
                tcb.blocked_reason = None;
                let scheduler = crate::sched::scheduler::scheduler();
                scheduler.enqueue(tcb as *mut Tcb);
            }
        }
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// TCB_SUSPEND: Stop a thread
fn syscall_tcb_suspend(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::SUSPEND) {
        return SyscallResult::err(e);
    }

    let target_tcb = cap.object as *mut Tcb;

    // Operation under per-TCB lock (TCB state transitions + scheduler)
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *target_tcb;
        tcb.tcb_lock();
        let scheduler = crate::sched::scheduler::scheduler();
        let mut wait_for_quiesce = false;
        let mut cpu_hint = None;

        // Clean up PIP state before suspension
        crate::sched::pip::pip_cleanup(tcb as *mut Tcb);

        match tcb.state {
            ThreadState::Running => {
                tcb.state = ThreadState::Inactive;
                let this_cpu = crate::arch::current_cpu() as usize;
                // Scan current[] under scheduler lock to find target CPU
                scheduler.lock();
                let target_cpu = scheduler.find_running_cpu(tcb as *mut Tcb);
                scheduler.unlock();
                match target_cpu {
                    Some(cpu) if cpu == this_cpu => {
                        // Self-suspend: release lock, then reschedule
                        tcb.tcb_unlock();
                        scheduler.reschedule();
                        restore_irq(irq);
                        return SyscallResult::ok(0);
                    }
                    Some(cpu) => {
                        cpu_hint = Some(cpu);
                        wait_for_quiesce = true;
                    }
                    None => {
                        // The target may already be in the scheduler's deferred
                        // switch-out path. Wait for that bookkeeping to drain
                        // before reporting the TCB safe to reuse.
                        wait_for_quiesce = true;
                    }
                }

                detach_thread_wait_queues(tcb as *mut Tcb);
            }
            ThreadState::Ready => {
                tcb.state = ThreadState::Inactive;
                wait_for_quiesce = true;
            }
            ThreadState::Blocked => {
                detach_thread_wait_queues(tcb as *mut Tcb);
                tcb.state = ThreadState::Inactive;
                tcb.blocked_reason = None;
                Tcb::release_tcb_ref(tcb.clear_reply_tcb());
                tcb.reply_can_grant = false;
                tcb.saved_caller_msg = crate::ipc::Message::empty();
                tcb.saved_caller_badge = 0;
                wait_for_quiesce = true;
            }
            ThreadState::Waiting => {
                detach_thread_wait_queues(tcb as *mut Tcb);
                tcb.state = ThreadState::Inactive;
                tcb.blocked_reason = None;
                wait_for_quiesce = true;
            }
            ThreadState::Inactive => {}
        }
        tcb.tcb_unlock();
        restore_irq(irq);

        if wait_for_quiesce {
            wait_for_tcb_quiesced_blocking(target_tcb, cpu_hint);
            scheduler.cancel_pending_enqueue(target_tcb);
            scheduler.remove_from_ready_queue(target_tcb);
        }
    }

    SyscallResult::ok(0)
}

/// TCB_SET_SPACE: Set thread's CSpace and VSpace
///
/// Args:
/// - cspace_cap_ptr: Capability pointer to a CNode
/// - vspace_cap_ptr: Capability pointer to a VSpace
/// - cspace_depth: CSpace address depth (0 = flat mode, non-zero = multi-level tree)
fn syscall_tcb_set_space(
    cap: &Capability,
    cspace_cap_ptr: u64,
    vspace_cap_ptr: u64,
    cspace_depth: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // Sub-lookups under CAP_LOCK
    let cspace_cap = match lookup_cap_locked(cspace_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&cspace_cap, ObjectType::CNode, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let vspace_cap = match lookup_cap_locked(vspace_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&vspace_cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }

    // Validate depth (0 = flat, or reasonable bit width)
    if cspace_depth > 64 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // TCB mutation under per-TCB lock
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        // Release old refcounts
        if !tcb.cspace_root.is_null() {
            crate::cap::release_object(
                tcb.cspace_root as *mut crate::cap::KernelObject,
                crate::cap::ObjectType::CNode,
            );
        }
        if !tcb.vspace_root.is_null() {
            crate::cap::release_object(
                tcb.vspace_root as *mut crate::cap::KernelObject,
                crate::cap::ObjectType::VSpace,
            );
        }
        // Acquire new refcounts — keeps VSpace/CNode alive while TCB references them
        crate::cap::increment_refcount(cspace_cap.object as *mut crate::cap::KernelObject);
        crate::cap::increment_refcount(vspace_cap.object as *mut crate::cap::KernelObject);
        tcb.cspace_root = cspace_cap.object as *mut CNode;
        tcb.vspace_root = vspace_cap.object as *mut VSpace;
        tcb.cspace_depth = cspace_depth as u8;
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// TCB_SET_AFFINITY: Set CPU affinity for a thread
///
/// Args:
/// - cpu_id: Target CPU ID (0xFFFF_FFFF = any CPU)
fn syscall_tcb_set_affinity(cap: &Capability, cpu_id: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    let affinity = cpu_id as u32;
    if affinity != 0xFFFF_FFFF && (affinity as usize) >= crate::arch::MAX_CPUS {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // TCB mutation under per-TCB lock
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        tcb.cpu_affinity = affinity;

        // If thread is in ready queue, re-enqueue with new affinity
        if tcb.state == ThreadState::Ready {
            let scheduler = crate::sched::scheduler::scheduler();
            scheduler.remove_from_ready_queue(tcb as *mut Tcb);
            scheduler.enqueue(tcb as *mut Tcb);
        }
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// TCB_READ_REGISTERS: Read a thread's saved registers
///
/// Args:
/// - flags: Reserved for future use (must be 0)
///
/// Returns: RIP of the target thread in value
fn syscall_tcb_read_registers(cap: &Capability, _flags: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::READ) {
        return SyscallResult::err(e);
    }

    // TCB read under per-TCB lock
    unsafe {
        let irq = save_irq_disable();
        let tcb = &*(cap.object as *const Tcb);
        tcb.tcb_lock();
        let result = if tcb.state != ThreadState::Inactive {
            SyscallResult::err(SyscallError::Busy)
        } else {
            #[cfg(target_arch = "x86_64")]
            {
                SyscallResult::ok(tcb.context.rip)
            }
            #[cfg(target_arch = "aarch64")]
            {
                SyscallResult::ok(tcb.context.return_elr)
            }
        };
        tcb.tcb_unlock();
        restore_irq(irq);
        result
    }
}

/// TCB_WRITE_REGISTERS: Write a thread's saved registers
///
/// Args:
/// - flags: bit 0 = resume after write
/// - rip: New instruction pointer
/// - rsp: New stack pointer
fn syscall_tcb_write_registers(cap: &Capability, flags: u64, rip: u64, rsp: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // TCB mutation under per-TCB lock
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        // The saved `context` for Ready/Blocked/Waiting threads is often a
        // kernel continuation (e.g. switch_common resume point), not user RIP/RSP.
        // Allowing writes in those states can corrupt kernel return paths.
        if tcb.state != ThreadState::Inactive {
            tcb.tcb_unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::Busy);
        }

        #[cfg(target_arch = "x86_64")]
        {
            tcb.context.rip = rip;
            tcb.context.rsp = rsp;
        }
        #[cfg(target_arch = "aarch64")]
        {
            if !tcb.vspace_root.is_null() {
                tcb.context.return_elr = rip;
                tcb.context.user_sp = rsp;
                tcb.context.return_spsr = 0x0;
            } else {
                crate::arch::aarch64::context::init_kernel_thread_context(
                    &mut tcb.context,
                    rsp,
                    rip,
                );
            }
        }

        if flags & 1 != 0 && tcb.state == ThreadState::Inactive {
            let scheduler = crate::sched::scheduler::scheduler();
            scheduler.enqueue(tcb as *mut Tcb);
        }
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// TCB_SET_PRIORITY: Set thread priority (EDF deadline)
///
/// Args:
/// - priority: New priority value (deadline for EDF)
fn syscall_tcb_set_priority(cap: &Capability, priority: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // TCB mutation + scheduler under per-TCB lock
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        tcb.base_priority = priority;
        tcb.priority = priority;

        if tcb.state == ThreadState::Ready {
            let scheduler = crate::sched::scheduler::scheduler();
            scheduler.remove_from_ready_queue(tcb as *mut Tcb);
            scheduler.enqueue(tcb as *mut Tcb);
        }
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// Validate IPC buffer address
///
/// Must be 0 (no buffer), or page-aligned and in user-space address range.
fn validate_ipc_buffer_addr(addr: u64) -> Result<(), SyscallError> {
    if addr == 0 {
        return Ok(());
    }
    if addr & 0xFFF != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    if addr >= 0x0000_8000_0000_0000 {
        return Err(SyscallError::InvalidArgument);
    }
    Ok(())
}

/// TCB_SET_IPC_BUFFER: Change IPC buffer address
///
/// Args:
/// - addr: New IPC buffer virtual address
fn syscall_tcb_set_ipc_buffer(cap: &Capability, addr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    if let Err(e) = validate_ipc_buffer_addr(addr) {
        return SyscallResult::err(e);
    }

    // TCB mutation under per-TCB lock
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        tcb.ipc_buffer = addr;
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// TCB_BIND_NOTIFICATION: Bind a notification to this thread
///
/// Args:
/// - ntfn_cap_ptr: Capability pointer to a Notification
fn syscall_tcb_bind_notification(cap: &Capability, ntfn_cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // Sub-lookup under CAP_LOCK
    let ntfn_cap = match lookup_cap_locked(ntfn_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&ntfn_cap, ObjectType::Notification, CapRights::READ) {
        return SyscallResult::err(e);
    }

    // TCB + notification mutation under per-TCB lock
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        if !tcb.bound_notification.is_null() {
            tcb.tcb_unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::AlreadyBound);
        }

        let ntfn = &mut *(ntfn_cap.object as *mut crate::ipc::Notification);
        ntfn.ntfn_lock();
        if !ntfn.bound_tcb.is_null() {
            ntfn.ntfn_unlock();
            tcb.tcb_unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::AlreadyBound);
        }

        tcb.bound_notification = ntfn_cap.object as *mut u8;
        ntfn.bound_tcb = tcb as *mut Tcb;

        // TCB holds a strong reference on the bound Notification
        crate::cap::increment_refcount(ntfn_cap.object as *mut crate::cap::KernelObject);

        ntfn.ntfn_unlock();
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// TCB_UNBIND_NOTIFICATION: Unbind notification from this thread
fn syscall_tcb_unbind_notification(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // TCB + notification mutation under per-TCB lock
    let old_ntfn;
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        if tcb.bound_notification.is_null() {
            tcb.tcb_unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        old_ntfn = tcb.bound_notification;
        let ntfn = &mut *(tcb.bound_notification as *mut crate::ipc::Notification);
        ntfn.ntfn_lock();
        ntfn.bound_tcb = core::ptr::null_mut();
        ntfn.ntfn_unlock();
        tcb.bound_notification = core::ptr::null_mut();
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    // Release TCB's strong reference on the Notification
    if !old_ntfn.is_null() {
        unsafe {
            crate::cap::release_object(
                old_ntfn as *mut crate::cap::KernelObject,
                ObjectType::Notification,
            );
        }
    }

    SyscallResult::ok(0)
}

/// TCB_SET_FAULT_HANDLER: Set the fault handler endpoint for a thread
///
/// When a user-mode exception occurs in this thread, the kernel delivers
/// a fault message to the specified endpoint. A fault handler thread
/// waiting on the endpoint receives the message and can reply to resume
/// the faulting thread.
///
/// Args:
/// - fault_ep_cap_ptr: Capability pointer to an Endpoint (SEND right required)
fn syscall_tcb_set_fault_handler(cap: &Capability, fault_ep_cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    let fault_handler = if fault_ep_cap_ptr == 0 {
        None
    } else {
        let ep_cap = match lookup_cap_locked(fault_ep_cap_ptr) {
            Ok(c) => c,
            Err(e) => return SyscallResult::err(e),
        };
        if let Err(e) = validate_capability(&ep_cap, ObjectType::Endpoint, CapRights::SEND) {
            return SyscallResult::err(e);
        }
        Some((ep_cap.object as *mut u8, ep_cap.badge))
    };

    // Increment refcount on new fault handler endpoint (if setting, not clearing)
    if let Some((handler, _)) = fault_handler {
        unsafe {
            crate::cap::increment_refcount(handler as *mut crate::cap::KernelObject);
        }
    }

    // TCB mutation under per-TCB lock
    let old_handler;
    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        old_handler = tcb.fault_handler;
        match fault_handler {
            Some((handler, badge)) => {
                tcb.fault_handler = handler;
                tcb.fault_handler_badge = badge;
            }
            None => {
                tcb.fault_handler = core::ptr::null_mut();
                tcb.fault_handler_badge = 0;
            }
        }
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    // Release refcount on old fault handler endpoint
    if !old_handler.is_null() {
        unsafe {
            crate::cap::release_object(
                old_handler as *mut crate::cap::KernelObject,
                ObjectType::Endpoint,
            );
        }
    }

    SyscallResult::ok(0)
}

/// TCB_COPY_FPU: Copy FPU/SSE state from source TCB to destination TCB
///
/// Used by procmgr during fork to preserve the parent's FPU state in the child.
/// Args:
/// - dest_cap: destination (child) TCB capability
/// - src_cap_ptr: slot index of source (parent) TCB capability
fn syscall_tcb_copy_fpu(dest_cap: &Capability, src_cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(dest_cap, ObjectType::Tcb, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Look up source TCB cap under CAP_LOCK
    let src_cap = match lookup_cap_locked(src_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&src_cap, ObjectType::Tcb, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let dest_tcb = dest_cap.object as *mut Tcb;
        let src_tcb = src_cap.object as *mut Tcb;

        // Only copy FPU state if the source thread has actually used FPU.
        // Threads that never touched FPU instructions have fpu_initialized=false,
        // so we skip the 832-byte memcpy and hardware flush entirely.
        if (*src_tcb).fpu_initialized {
            // If source thread is the current FPU owner on this CPU, flush its
            // state from hardware registers into the TCB before copying.
            // The source is typically blocked in IPC (during fork), but its state
            // may still be live in hardware if it was the last FPU user on this CPU.
            crate::arch::fpu::flush_if_owner(src_tcb as *mut u8);

            core::ptr::copy_nonoverlapping(
                (*src_tcb).fpu_state.data.as_ptr(),
                (*dest_tcb).fpu_state.data.as_mut_ptr(),
                (*src_tcb).fpu_state.data.len(),
            );
        }
        (*dest_tcb).fpu_initialized = (*src_tcb).fpu_initialized;
    }

    SyscallResult::ok(0)
}

/// TCB_SET_TLS_BASE: Set the FS_BASE (TLS pointer) for a thread.
/// If the target is the current thread, also writes IA32_FS_BASE immediately.
fn syscall_tcb_set_tls_base(cap: &Capability, tls_base: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Canonical user address check: 0 (clear) or positive-half canonical
    if tls_base != 0 && tls_base >= 0x0000_8000_0000_0000 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let irq = save_irq_disable();
        let tcb = cap.object as *mut Tcb;
        (*tcb).tcb_lock();
        let current = crate::sched::scheduler::scheduler().current();

        if tcb == current {
            // Self: write field + apply MSR immediately
            (*tcb).tls_base = tls_base;
            crate::arch::write_fs_base(tls_base);
        } else {
            // Reject if target is Running on another CPU — do_context_switch
            // would overwrite our write with read_fs_base() when that CPU
            // context-switches away from the target thread.
            if (*tcb).state == ThreadState::Running {
                (*tcb).tcb_unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidOperation);
            }
            // Target is Inactive/Ready/Blocked — safe to write field
            (*tcb).tls_base = tls_base;
        }

        (*tcb).tcb_unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// TCB_SET_NOTIFICATION_DISPATCHER: Set the user-mode notification dispatcher
/// entry point for a thread. When non-zero, the kernel injects a notification
/// frame and redirects control to this address instead of returning EINTR.
fn syscall_tcb_set_notification_dispatcher(cap: &Capability, dispatcher: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // 0 clears the dispatcher. Otherwise require a user-space entry point.
    if dispatcher != 0 && dispatcher >= 0x0000_8000_0000_0000 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    #[cfg(target_arch = "aarch64")]
    if dispatcher & 0x3 != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let irq = save_irq_disable();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.tcb_lock();
        tcb.notification_dispatcher = dispatcher;
        tcb.tcb_unlock();
        restore_irq(irq);
    }
    SyscallResult::ok(0)
}

/// TCB_GET_SPACE_INFO: Read the CSpace depth of a thread
///
/// Returns cspace_depth in IPC buffer msg[0]. This allows userland
/// (e.g. the thread pool) to discover its own CSpace depth without
/// needing the spawner to communicate it out-of-band.
fn syscall_tcb_get_space_info(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let depth;
    unsafe {
        let irq = save_irq_disable();
        let tcb = &*(cap.object as *const Tcb);
        tcb.tcb_lock();
        depth = tcb.cspace_depth as u64;
        tcb.tcb_unlock();
        restore_irq(irq);
    }

    // Write to IPC buffer msg[0]
    unsafe {
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();
        if current.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let buf = (*current).ipc_buffer;
        if buf == 0 || validate_ipc_buffer_addr(buf).is_err() || (*current).vspace_root.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let vs = &mut *(*current).vspace_root;
        if !vs.ensure_writable(buf) {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let _guard = crate::arch::uaccess::UserAccessGuard::new();
        let ipc_buf = buf as *mut crate::ipc::IpcBuffer;
        (*ipc_buf).msg[0] = depth;
    }

    SyscallResult::ok(0)
}

/// SC_CONSUMED: Query consumed time from scheduling context
fn syscall_sc_consumed(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::READ) {
        return SyscallResult::err(e);
    }

    // SC read under per-SC lock
    unsafe {
        let irq = save_irq_disable();
        let sc = &*(cap.object as *const SchedContext);
        sc.sc_lock();
        let result = SyscallResult::ok(sc.consumed);
        sc.sc_unlock();
        restore_irq(irq);
        result
    }
}

/// Resolve an invoked capability pointer to the authoritative slot in the
/// current thread's CSpace.
fn resolve_current_cspace_cap_slot(
    cspace: &mut CNode,
    depth: u8,
    cap_ptr: u64,
) -> Result<crate::cap::CapSlot, SyscallError> {
    if depth == 0 {
        match cspace.get_ref(cap_ptr as usize) {
            Some(r) => Ok(r.slot),
            None => match lookup_expanded_slot(cspace, cap_ptr) {
                Ok(r) => Ok(r.slot),
                Err(_) => Err(SyscallError::InvalidCapability),
            },
        }
    } else {
        match crate::cap::cnode::resolve_address_slot(cspace, cap_ptr, depth) {
            Ok(r) => Ok(r.slot),
            Err(_) => Err(SyscallError::InvalidCapability),
        }
    }
}

/// UNTYPED_RETYPE: Create typed kernel objects from untyped memory
///
/// Args:
/// - new_type_raw: ObjectType as u64 (must be 1..=10, not 0/Null)
/// - size_bits: Size in bits (for variable-size objects)
/// - dest_offset: Destination offset in current thread's CSpace
///
/// Dest depth comes from per-thread invoke state set by SYS_SET_INVOKE_DEPTHS.
fn syscall_untyped_retype(
    cap: &Capability,
    cap_ptr: u64,
    new_type_raw: u64,
    size_bits: u64,
    dest_offset: u64,
) -> SyscallResult {
    let retype_seq = crate::arch::current_invoke_seq();
    crate::ktrace!(syscall, |_g| {
        _g.puts("[RETYPE] seq=");
        _g.hex(retype_seq);
        _g.puts(" cap=");
        _g.hex(cap_ptr);
        _g.puts(" type=");
        _g.hex(new_type_raw);
        _g.puts(" bits=");
        _g.hex(size_bits);
        _g.puts(" dest=");
        _g.hex(dest_offset);
        _g.putc(b'\n');
    });

    if let Err(e) = validate_capability(cap, ObjectType::Untyped, CapRights::RETYPE) {
        return SyscallResult::err(e);
    }

    let new_type = match new_type_raw {
        1 => ObjectType::Untyped,
        2 => ObjectType::Endpoint,
        3 => ObjectType::Notification,
        4 => ObjectType::Tcb,
        5 => ObjectType::CNode,
        6 => ObjectType::VSpace,
        7 => ObjectType::Frame,
        8 => ObjectType::IrqHandler,
        9 => ObjectType::IoPort,
        10 => ObjectType::SchedContext,
        11 => ObjectType::MemoryObject,
        _ => return SyscallResult::err(SyscallError::InvalidArgument),
    };

    // Entire operation under CAP_LOCK (modifies slot array + CDT)
    unsafe {
        let irq = save_irq_disable();
        CAP_LOCK.lock();
        let current_tcb = crate::sched::scheduler::scheduler().current();
        if current_tcb.is_null() {
            CAP_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let cspace = &mut *(*current_tcb).cspace_root;
        let depth = (*current_tcb).cspace_depth;

        let untyped_slot = match resolve_current_cspace_cap_slot(cspace, depth, cap_ptr) {
            Ok(slot) => slot,
            Err(e) => {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(e);
            }
        };

        // Read dest_depth from per-thread invoke state
        let (dest_depth, _) = read_invoke_depths(current_tcb);

        // Resolve destination CNode and slot index
        let (dest_cn_ptr, dest_idx) = if dest_depth > 0 {
            match resolve_invoke_slot(cspace, dest_offset, dest_depth) {
                Ok(v) => v,
                Err(e) => {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(e);
                }
            }
        } else {
            // Flat mode: try direct, then auto-detect expanded
            if (dest_offset as usize) < cspace.num_slots() {
                (cspace as *const CNode as *mut CNode, dest_offset as usize)
            } else {
                // Auto-detect expanded destination
                match lookup_expanded_for_slot(cspace, dest_offset) {
                    Ok(v) => v,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                }
            }
        };
        let dest_cn = &mut *dest_cn_ptr;

        // Re-read the capability from the authoritative slot: the slot may have
        // been modified between the initial lookup (before CAP_LOCK) and now.
        let live_cap = *crate::cap::get_cap(untyped_slot);
        if live_cap.obj_type != ObjectType::Untyped || live_cap.object.is_null() {
            CAP_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidCapability);
        }
        if !live_cap.rights.contains(CapRights::RETYPE) {
            CAP_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InsufficientRights);
        }
        let untyped = &mut *(live_cap.object as *mut UntypedMemory);
        let result = match untyped.retype(
            untyped_slot,
            new_type,
            size_bits as u8,
            1,
            dest_cn,
            dest_idx,
        ) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
        };
        CAP_LOCK.unlock();
        restore_irq(irq);
        result
    }
}

/// UNTYPED_RESET: Clear an untyped watermark once it has no live children.
fn syscall_untyped_reset(cap: &Capability, cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Untyped, CapRights::RETYPE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let irq = save_irq_disable();
        CAP_LOCK.lock();
        let current_tcb = crate::sched::scheduler::scheduler().current();
        if current_tcb.is_null() {
            CAP_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let cspace = &mut *(*current_tcb).cspace_root;
        let depth = (*current_tcb).cspace_depth;
        let untyped_slot = match resolve_current_cspace_cap_slot(cspace, depth, cap_ptr) {
            Ok(slot) => slot,
            Err(e) => {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(e);
            }
        };

        let live_cap = *crate::cap::get_cap(untyped_slot);
        if live_cap.obj_type != ObjectType::Untyped || live_cap.object.is_null() {
            CAP_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidCapability);
        }
        if !live_cap.rights.contains(CapRights::RETYPE) {
            CAP_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InsufficientRights);
        }

        let result = match crate::cap::UntypedTracker::reset(untyped_slot) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_cap_error(e)),
        };
        CAP_LOCK.unlock();
        restore_irq(irq);
        result
    }
}

/// VSPACE_MAP: Map a physical frame into a virtual address space
///
/// Args:
/// - frame_cap_ptr: Capability pointer to the frame
/// - virt_addr: Virtual address to map at
/// - flags_bits: Mapping flags (bit 0=writable, bit 1=user, bit 2=executable)
fn syscall_vspace_map(
    cap: &Capability,
    frame_cap_ptr: u64,
    virt_addr: u64,
    flags_bits: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    // Sub-lookup under CAP_LOCK
    let frame_cap = match lookup_cap_locked(frame_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&frame_cap, ObjectType::Frame, CapRights::READ) {
        return SyscallResult::err(e);
    }

    // W^X: writable + executable is not permitted
    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // VSpace operation (per-VSpace lock added in Task 6)
    unsafe {
        let frame = &*(frame_cap.object as *const FrameObject);
        let vspace = &mut *(cap.object as *mut VSpace);

        let flags = PageFlags {
            writable: flags_bits & 1 != 0,
            user: flags_bits & 2 != 0,
            executable: flags_bits & 4 != 0,
            cache_disable: flags_bits & 8 != 0,
            write_through: flags_bits & 16 != 0,
            cow: flags_bits & 32 != 0,
        };

        match vspace.map(virt_addr, frame.phys_addr, flags) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// VSPACE_UNMAP: Unmap a page from a virtual address space.
///
/// Args:
/// - virt_addr: Virtual address to unmap
fn syscall_vspace_unmap(cap: &Capability, virt_addr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::UNMAP) {
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

/// VSPACE_PROTECT: Change protection flags on a mapped page
///
/// Args:
/// - virt_addr: Virtual address of the page
/// - flags_bits: New mapping flags (bit 0=writable, bit 1=user, bit 2=executable)
fn syscall_vspace_protect(cap: &Capability, virt_addr: u64, flags_bits: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    // W^X: writable + executable is not permitted
    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let vspace = &mut *(cap.object as *mut VSpace);
        let flags = PageFlags {
            writable: flags_bits & 1 != 0,
            user: flags_bits & 2 != 0,
            executable: flags_bits & 4 != 0,
            cache_disable: flags_bits & 8 != 0,
            write_through: flags_bits & 16 != 0,
            cow: flags_bits & 32 != 0,
        };

        match vspace.protect(virt_addr, flags) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// VSPACE_PROTECT_RANGE: Change protection flags on a contiguous range of pages.
///
/// Args:
/// - virt_addr: Start virtual address (page-aligned)
/// - count: Number of pages
/// - flags_bits: New mapping flags (bit 0=writable, bit 1=user, bit 2=executable)
///
/// Returns number of pages successfully updated in value field.
fn syscall_vspace_protect_range(
    cap: &Capability,
    virt_addr: u64,
    count: u64,
    flags_bits: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    // W^X: writable + executable is not permitted
    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let vspace = &mut *(cap.object as *mut VSpace);
        let flags = PageFlags {
            writable: flags_bits & 1 != 0,
            user: flags_bits & 2 != 0,
            executable: flags_bits & 4 != 0,
            cache_disable: flags_bits & 8 != 0,
            write_through: flags_bits & 16 != 0,
            cow: flags_bits & 32 != 0,
        };

        match vspace.protect_range(virt_addr, count as usize, flags) {
            Ok(protected) => SyscallResult::ok(protected as u64),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// VSPACE_MAP_DEMAND: Install demand-page PTE at a single virtual address.
///
/// Args:
/// - virt_addr: Virtual address to set up for demand paging
/// - flags_bits: Mapping flags (writable, user, executable, etc.)
fn syscall_vspace_map_demand(cap: &Capability, virt_addr: u64, flags_bits: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    // W^X: writable + executable is not permitted
    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let vspace = &mut *(cap.object as *mut VSpace);
        let flags = PageFlags {
            writable: flags_bits & 1 != 0,
            user: flags_bits & 2 != 0,
            executable: flags_bits & 4 != 0,
            cache_disable: flags_bits & 8 != 0,
            write_through: flags_bits & 16 != 0,
            cow: false,
        };

        match vspace.map_demand(virt_addr, flags) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// VSPACE_MAP_DEMAND_RANGE: Install demand-page PTEs for a contiguous range.
///
/// Args:
/// - virt_addr: Start virtual address
/// - count: Number of pages
/// - flags_bits: Mapping flags
///
/// Returns number of pages successfully set up in value field.
fn syscall_vspace_map_demand_range(
    cap: &Capability,
    virt_addr: u64,
    count: u64,
    flags_bits: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    // W^X: writable + executable is not permitted
    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let vspace = &mut *(cap.object as *mut VSpace);
        let flags = PageFlags {
            writable: flags_bits & 1 != 0,
            user: flags_bits & 2 != 0,
            executable: flags_bits & 4 != 0,
            cache_disable: flags_bits & 8 != 0,
            write_through: flags_bits & 16 != 0,
            cow: false,
        };

        match vspace.map_demand_range(virt_addr, count as usize, flags) {
            Ok(mapped) => SyscallResult::ok(mapped as u64),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// VSPACE_COW_RESOLVE: Resolve a COW fault using a provided frame
///
/// Called by mmsrv when a VMFault indicates a COW page.
/// The frame capability provides the physical memory for the copy.
///
/// Args:
/// - virt_addr: Virtual address of the COW page to resolve
/// - frame_cap_ptr: Capability pointer to the new frame
/// - flags_bits: Mapping flags (currently preserved from existing PTE)
fn syscall_vspace_cow_resolve(
    cap: &Capability,
    virt_addr: u64,
    frame_cap_ptr: u64,
    flags_bits: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    let frame_cap = match lookup_cap_locked(frame_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&frame_cap, ObjectType::Frame, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        // SAFETY: cap.object was validated as VSpace type above.
        // frame_cap.object was validated as Frame type above.
        let frame = &*(frame_cap.object as *const FrameObject);
        let vspace = &mut *(cap.object as *mut VSpace);

        let flags = PageFlags {
            writable: flags_bits & 1 != 0,
            user: flags_bits & 2 != 0,
            executable: flags_bits & 4 != 0,
            cache_disable: flags_bits & 8 != 0,
            write_through: flags_bits & 16 != 0,
            cow: flags_bits & 32 != 0,
        };

        match vspace.resolve_cow_with_frame(virt_addr, frame.phys_addr, flags) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// VSPACE_SET_COW_POOL: Initialize the COW frame pool for a VSpace.
///
/// Registers a pool page and pre-populates it with frame physical addresses
/// from a CNode containing Frame capabilities.
///
/// Args:
/// - pool_frame_cap_ptr: Capability pointer to the pool page (Frame)
/// - src_cnode_cap_ptr: Capability pointer to CNode with Frame caps in slots 0..count-1
/// - count: Number of initial frame entries
fn syscall_vspace_set_cow_pool(
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

    let pool_frame_cap = match lookup_cap_locked(pool_frame_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&pool_frame_cap, ObjectType::Frame, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        // SAFETY: pool_frame_cap.object was validated as Frame type above.
        let pool_frame = &*(pool_frame_cap.object as *const FrameObject);
        let pool_phys = pool_frame.phys_addr;

        // Walk CNode slots under CAP_LOCK to extract frame physical addresses
        let irq = save_irq_disable();
        CAP_LOCK.lock();

        let src_cnode_cap = match lookup_capability(src_cnode_cap_ptr) {
            Ok(c) => c,
            Err(e) => {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(e);
            }
        };
        if let Err(e) = validate_capability(src_cnode_cap, ObjectType::CNode, CapRights::READ) {
            CAP_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(e);
        }

        let src_cnode = &*(src_cnode_cap.object as *const CNode);

        // SAFETY: pool_phys is a validated Frame physical address.
        // phys_to_virt returns the direct-map kernel virtual address.
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
            (*pool).entries[i].phys_addr = frame_obj.phys_addr;
        }

        (*pool).head.store(0, Ordering::Release);
        (*pool).tail.store(count as u16, Ordering::Release);

        CAP_LOCK.unlock();
        restore_irq(irq);

        // Store pool phys in VSpace
        let vspace = &mut *(cap.object as *mut VSpace);
        vspace.set_cow_pool_phys(pool_phys);
    }

    SyscallResult::ok(0)
}

/// VSPACE_SET_COW_NOTIF: Configure the COW notification ring and notification object.
///
/// Args:
/// - ring_frame_cap_ptr: Capability pointer to the notification ring page (Frame)
/// - notif_cap_ptr: Capability pointer to a Notification object
fn syscall_vspace_set_cow_notif(
    cap: &Capability,
    ring_frame_cap_ptr: u64,
    notif_cap_ptr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    let ring_frame_cap = match lookup_cap_locked(ring_frame_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&ring_frame_cap, ObjectType::Frame, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let notif_cap = match lookup_cap_locked(notif_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&notif_cap, ObjectType::Notification, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        // SAFETY: ring_frame_cap.object was validated as Frame type above.
        let ring_frame = &*(ring_frame_cap.object as *const FrameObject);
        let ring_phys = ring_frame.phys_addr;

        // SAFETY: notif_cap.object was validated as Notification type above.
        let notif_ptr = notif_cap.object as *mut Notification;

        // Initialize the ring
        let ring = phys_to_virt(ring_phys) as *mut CowNotifRing;
        (*ring).head.store(0, Ordering::Release);
        (*ring).tail.store(0, Ordering::Release);
        (*ring).overflow.store(0, Ordering::Release);

        // Store in VSpace
        let vspace = &mut *(cap.object as *mut VSpace);
        vspace.set_cow_notif(ring_phys, notif_ptr);
    }

    SyscallResult::ok(0)
}

/// VSPACE_REPLENISH_COW_POOL: Add more pre-allocated frames to the COW pool.
///
/// Called by mmsrv after consuming notification ring entries to refill the pool.
///
/// Args:
/// - src_cnode_cap_ptr: Capability pointer to CNode with Frame caps
/// - start_slot: First slot index in the CNode
/// - count: Number of frames to add
fn syscall_vspace_replenish_cow_pool(
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

        // Walk CNode slots under CAP_LOCK
        let irq = save_irq_disable();
        CAP_LOCK.lock();

        let src_cnode_cap = match lookup_capability(src_cnode_cap_ptr) {
            Ok(c) => c,
            Err(e) => {
                CAP_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(e);
            }
        };
        if let Err(e) = validate_capability(src_cnode_cap, ObjectType::CNode, CapRights::READ) {
            CAP_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(e);
        }

        let src_cnode = &*(src_cnode_cap.object as *const CNode);

        // SAFETY: pool_phys was validated during VSPACE_SET_COW_POOL.
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
            let pool_idx = (current_tail.wrapping_add(i as u16) % 510) as usize;
            (*pool).entries[pool_idx].phys_addr = frame_obj.phys_addr;
        }

        // Advance tail by count
        (*pool)
            .tail
            .store(current_tail.wrapping_add(count as u16), Ordering::Release);

        CAP_LOCK.unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// IRQ_CONTROL_GET: Acquire an IRQ handler capability
///
/// Args:
/// - irq_num: Hardware IRQ number
/// - dest_cnode_cap: Capability pointer to destination CNode
/// - dest_slot: Slot index in destination CNode
fn syscall_irq_control_get(
    cap: &Capability,
    irq_num: u64,
    dest_cnode_cap: u64,
    dest_slot: u64,
) -> SyscallResult {
    // Require IrqHandler type with CONFIGURE rights (acts as IrqControl)
    if let Err(e) = validate_capability(cap, ObjectType::IrqHandler, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    if irq_num as usize >= crate::ipc::irq::MAX_IRQS {
        return SyscallResult::err(SyscallError::OutOfRange);
    }

    // Look up destination CNode
    let dest_cap = match lookup_cap_locked(dest_cnode_cap) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&dest_cap, ObjectType::CNode, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Allocate + register under IRQ_LOCK (managed by irq.rs) to prevent SMP races.
    // Shared IRQs are allowed: multiple handlers can coexist on the same IRQ line.
    let handler_ptr = unsafe {
        let irq = save_irq_disable();

        // Allocate from pool
        let ptr = match crate::init::alloc_dynamic_irq_handler(irq_num as u32) {
            Some(p) => p,
            None => {
                restore_irq(irq);
                return SyscallResult::err(SyscallError::OutOfMemory);
            }
        };

        // Prepend to handler chain (shared IRQs: multiple handlers per IRQ)
        // Dynamic IRQ handlers are created for PCI devices which use
        // level-triggered, active-low interrupts per the PCI specification.
        (*ptr).level_triggered = true;
        crate::ipc::irq::register_handler(irq_num as usize, ptr);

        restore_irq(irq);
        ptr
    };

    // Do NOT unmask here — the IRQ stays masked until the driver binds a
    // notification and calls irq_handler_ack.  Unmasking immediately would
    // cause an IRQ storm for level-triggered PCI interrupts that are already
    // asserted (e.g. virtio ISR pending).  irq_handler_ack() calls
    // ioapic_unmask_level() when the driver is ready to receive.

    // Allocate a cap slot and set it up
    let slot = match crate::cap::alloc_slot() {
        Some(s) => s,
        None => {
            // Rollback: unregister handler
            unsafe {
                let irq = save_irq_disable();
                crate::ipc::irq::unregister_handler(handler_ptr);
                // Only mask IOAPIC if no other handler remains on this IRQ
                let should_mask = !crate::ipc::irq::has_handlers(irq_num as usize);
                restore_irq(irq);
                if should_mask {
                    crate::arch::ioapic_mask(irq_num as u32);
                }
            }
            return SyscallResult::err(SyscallError::OutOfMemory);
        }
    };
    let new_cap = crate::cap::get_cap_mut(slot);
    new_cap.object = handler_ptr as *mut crate::cap::KernelObject;
    new_cap.obj_type = ObjectType::IrqHandler;
    new_cap.rights = crate::cap::CapRights::ALL;
    new_cap.depth = 0;
    new_cap.badge = 0;

    // Insert into destination CNode
    unsafe {
        // SAFETY: dest_cap.object was validated as ObjectType::CNode above.
        let dest_cnode = &mut *(dest_cap.object as *mut CNode);
        if let Err(e) = dest_cnode.insert_ref(dest_slot as usize, crate::cap::CapRef { slot }) {
            // Rollback: free slot, unregister handler
            crate::cap::free_slot(slot);
            let irq = save_irq_disable();
            crate::ipc::irq::unregister_handler(handler_ptr);
            let should_mask = !crate::ipc::irq::has_handlers(irq_num as usize);
            restore_irq(irq);
            if should_mask {
                crate::arch::ioapic_mask(irq_num as u32);
            }
            let syscall_err = match e {
                CapError::InvalidSlot => SyscallError::OutOfRange,
                other => syscall_error_from_cap_error(other),
            };
            return SyscallResult::err(syscall_err);
        }
    }

    SyscallResult::ok(0)
}

/// IRQ_HANDLER_ACK: Acknowledge an IRQ (re-enable delivery)
fn syscall_irq_handler_ack(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IrqHandler, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // IRQ handler mutation (IRQ_LOCK managed by irq.rs)
    unsafe {
        let irq = save_irq_disable();
        let irq_handler = &mut *(cap.object as *mut crate::ipc::IrqHandler);
        irq_handler
            .acknowledged
            .store(true, core::sync::atomic::Ordering::Release);
        // Re-enable delivery at IOAPIC. dispatch_irq() only masks
        // level-triggered IRQs when no handler is ready to accept delivery;
        // edge-triggered ISA IRQs stay unmasked to avoid losing edges.
        let irq_num = irq_handler.irq_num;
        let level = irq_handler.level_triggered;
        restore_irq(irq);
        if level {
            crate::arch::ioapic_unmask_level(irq_num);
        } else {
            crate::arch::ioapic_unmask(irq_num);
        }
    }

    SyscallResult::ok(0)
}

/// IRQ_HANDLER_SET_NOTIFICATION: Bind a notification to an IRQ handler
///
/// Args:
/// - ntfn_cap_ptr: Capability pointer to a Notification
fn syscall_irq_handler_set_notification(cap: &Capability, ntfn_cap_ptr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IrqHandler, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // Sub-lookup under CAP_LOCK
    let ntfn_cap = match lookup_cap_locked(ntfn_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&ntfn_cap, ObjectType::Notification, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // IRQ handler mutation (IRQ_LOCK managed by irq.rs)
    unsafe {
        let irq = save_irq_disable();
        let irq_handler = &mut *(cap.object as *mut crate::ipc::IrqHandler);

        // Increment refcount on new notification — keeps it alive while
        // the IRQ handler references it (prevents UAF during dispatch_irq).
        crate::cap::increment_refcount(ntfn_cap.object as *mut crate::cap::KernelObject);

        // Swap out old notification and release its refcount
        let old_ntfn = irq_handler.notification.swap(
            ntfn_cap.object as *mut Notification,
            core::sync::atomic::Ordering::AcqRel,
        );
        restore_irq(irq);

        if !old_ntfn.is_null() {
            crate::cap::release_object(
                old_ntfn as *mut crate::cap::KernelObject,
                ObjectType::Notification,
            );
        }
    }

    SyscallResult::ok(0)
}

/// IRQ_HANDLER_CLEAR: Unbind notification from IRQ handler
///
/// Only masks the IOAPIC if no other handler on the same IRQ still has a
/// bound notification (shared IRQ support).
fn syscall_irq_handler_clear(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IrqHandler, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // IRQ handler mutation (IRQ_LOCK managed by irq.rs)
    let irq_num;
    let should_mask;
    let old_ntfn;
    unsafe {
        let irq = save_irq_disable();
        let irq_handler = &mut *(cap.object as *mut crate::ipc::IrqHandler);
        irq_num = irq_handler.irq_num;
        old_ntfn = irq_handler
            .notification
            .swap(core::ptr::null_mut(), core::sync::atomic::Ordering::AcqRel);
        // Only mask if no other handler on this IRQ has a notification
        should_mask = !crate::ipc::irq::has_active_notification(irq_num as usize);
        restore_irq(irq);
    }

    // Release refcount on the old notification (outside IRQ-disabled region)
    if !old_ntfn.is_null() {
        unsafe {
            crate::cap::release_object(
                old_ntfn as *mut crate::cap::KernelObject,
                ObjectType::Notification,
            );
        }
    }

    if should_mask {
        crate::arch::ioapic_mask(irq_num);
    }

    SyscallResult::ok(0)
}

/// DEVICE_UNTYPED_CREATE: Create a device untyped capability for MMIO access
///
/// Requires IrqControl (IrqHandler type with CONFIGURE rights).
/// Creates a device untyped from a physical address and places the cap in
/// the caller's CSpace.
///
/// Args:
/// - phys_addr: Physical address of the MMIO region (must be page-aligned)
/// - size_bits: Log2 size of the region (minimum 12 = 4KB)
/// - dest_cnode_cap: Capability pointer to destination CNode
/// - dest_slot: Slot index in destination CNode
fn syscall_device_untyped_create(
    cap: &Capability,
    phys_addr: u64,
    size_bits: u64,
    dest_cnode_cap: u64,
    dest_slot: u64,
) -> SyscallResult {
    // Require IrqHandler type with CONFIGURE rights (acts as IrqControl)
    if let Err(e) = validate_capability(cap, ObjectType::IrqHandler, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // Validate args
    if size_bits < 12 || size_bits > 32 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if phys_addr & 0xFFF != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // Look up destination CNode
    let dest_cap = match lookup_cap_locked(dest_cnode_cap) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&dest_cap, ObjectType::CNode, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Allocate from the device untyped pool
    let ut_ptr = match crate::init::alloc_device_untyped(phys_addr, size_bits as u8) {
        Some(ptr) => ptr,
        None => return SyscallResult::err(SyscallError::OutOfMemory),
    };

    // Allocate a cap slot and set it up
    let slot = match crate::cap::alloc_slot() {
        Some(s) => s,
        None => return SyscallResult::err(SyscallError::OutOfMemory),
    };
    let new_cap = crate::cap::get_cap_mut(slot);
    new_cap.object = ut_ptr as *mut crate::cap::KernelObject;
    new_cap.obj_type = ObjectType::Untyped;
    new_cap.rights = crate::cap::CapRights::ALL;
    new_cap.depth = 0;
    new_cap.badge = 0;

    // Insert into destination CNode
    unsafe {
        let dest_cnode = &mut *(dest_cap.object as *mut CNode);
        if let Err(e) = dest_cnode.insert_ref(dest_slot as usize, crate::cap::CapRef { slot }) {
            let syscall_err = match e {
                CapError::InvalidSlot => SyscallError::OutOfRange,
                other => syscall_error_from_cap_error(other),
            };
            return SyscallResult::err(syscall_err);
        }
    }

    SyscallResult::ok(0)
}

/// IOPORT_CREATE: Create an IoPort capability for an I/O port range
///
/// Requires IrqControl (IrqHandler type with CONFIGURE rights).
/// Creates an IoPort cap from a base port and port count, and places
/// the cap in the caller's CSpace.
///
/// Args:
/// - base_port: Base I/O port number
/// - num_ports: Number of consecutive ports
/// - dest_cnode_cap: Capability pointer to destination CNode
/// - dest_slot: Slot index in destination CNode
#[cfg(target_arch = "x86_64")]
fn syscall_ioport_create(
    cap: &Capability,
    base_port: u64,
    num_ports: u64,
    dest_cnode_cap: u64,
    dest_slot: u64,
) -> SyscallResult {
    // Require IrqHandler type with CONFIGURE rights (acts as IrqControl)
    if let Err(e) = validate_capability(cap, ObjectType::IrqHandler, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // Validate args
    if base_port > 0xFFFF || num_ports == 0 || num_ports > 0xFFFF {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if base_port + num_ports > 0x10000 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // Look up destination CNode
    let dest_cap = match lookup_cap_locked(dest_cnode_cap) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&dest_cap, ObjectType::CNode, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Allocate from the dynamic IoPort pool
    let iop_ptr = match crate::init::alloc_dynamic_ioport(base_port as u16, num_ports as u16) {
        Some(ptr) => ptr,
        None => return SyscallResult::err(SyscallError::OutOfMemory),
    };

    // Allocate a cap slot and set it up
    let slot = match crate::cap::alloc_slot() {
        Some(s) => s,
        None => return SyscallResult::err(SyscallError::OutOfMemory),
    };
    let new_cap = crate::cap::get_cap_mut(slot);
    new_cap.object = iop_ptr as *mut crate::cap::KernelObject;
    new_cap.obj_type = ObjectType::IoPort;
    new_cap.rights = crate::cap::CapRights::ALL;
    new_cap.depth = 0;
    new_cap.badge = 0;

    // Insert into destination CNode
    unsafe {
        let dest_cnode = &mut *(dest_cap.object as *mut CNode);
        if let Err(e) = dest_cnode.insert_ref(dest_slot as usize, crate::cap::CapRef { slot }) {
            let syscall_err = match e {
                CapError::InvalidSlot => SyscallError::OutOfRange,
                other => syscall_error_from_cap_error(other),
            };
            return SyscallResult::err(syscall_err);
        }
    }

    SyscallResult::ok(0)
}

#[cfg(target_arch = "aarch64")]
fn syscall_ioport_create(
    cap: &Capability,
    base_port: u64,
    num_ports: u64,
    dest_cnode_cap: u64,
    dest_slot: u64,
) -> SyscallResult {
    // Require IrqHandler type with CONFIGURE rights (acts as IrqControl)
    if let Err(e) = validate_capability(cap, ObjectType::IrqHandler, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // Validate args (same 64 KB port space as x86, mapped to PCI I/O window MMIO)
    if base_port > 0xFFFF || num_ports == 0 || num_ports > 0xFFFF {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if base_port + num_ports > 0x10000 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // Look up destination CNode
    let dest_cap = match lookup_cap_locked(dest_cnode_cap) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&dest_cap, ObjectType::CNode, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Allocate from the dynamic IoPort pool
    let iop_ptr = match crate::init::alloc_dynamic_ioport(base_port as u16, num_ports as u16) {
        Some(ptr) => ptr,
        None => return SyscallResult::err(SyscallError::OutOfMemory),
    };

    // Allocate a cap slot and set it up
    let slot = match crate::cap::alloc_slot() {
        Some(s) => s,
        None => return SyscallResult::err(SyscallError::OutOfMemory),
    };
    let new_cap = crate::cap::get_cap_mut(slot);
    new_cap.object = iop_ptr as *mut crate::cap::KernelObject;
    new_cap.obj_type = ObjectType::IoPort;
    new_cap.rights = crate::cap::CapRights::ALL;
    new_cap.depth = 0;
    new_cap.badge = 0;

    // Insert into destination CNode
    unsafe {
        let dest_cnode = &mut *(dest_cap.object as *mut CNode);
        if let Err(e) = dest_cnode.insert_ref(dest_slot as usize, crate::cap::CapRef { slot }) {
            let syscall_err = match e {
                CapError::InvalidSlot => SyscallError::OutOfRange,
                other => syscall_error_from_cap_error(other),
            };
            return SyscallResult::err(syscall_err);
        }
    }

    SyscallResult::ok(0)
}

/// IOPORT_IN8: Read a byte from an I/O port (x86_64 only)
#[cfg(target_arch = "x86_64")]
fn syscall_ioport_in8(cap: &Capability, offset: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        let val: u8;
        core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
        SyscallResult::ok(val as u64)
    }
}

/// IOPORT_OUT8: Write a byte to an I/O port (x86_64 only)
#[cfg(target_arch = "x86_64")]
fn syscall_ioport_out8(cap: &Capability, offset: u64, value: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        core::arch::asm!("out dx, al", in("al") value as u8, in("dx") port, options(nomem, nostack));
    }

    SyscallResult::ok(0)
}

/// IOPORT_IN16: Read a 16-bit word from an I/O port (x86_64 only)
#[cfg(target_arch = "x86_64")]
fn syscall_ioport_in16(cap: &Capability, offset: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset + 1 >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        let val: u16;
        core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack));
        SyscallResult::ok(val as u64)
    }
}

/// IOPORT_OUT16: Write a 16-bit word to an I/O port (x86_64 only)
#[cfg(target_arch = "x86_64")]
fn syscall_ioport_out16(cap: &Capability, offset: u64, value: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset + 1 >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        core::arch::asm!("out dx, ax", in("ax") value as u16, in("dx") port, options(nomem, nostack));
    }

    SyscallResult::ok(0)
}

/// IOPORT_IN32: Read a 32-bit dword from an I/O port (x86_64 only)
#[cfg(target_arch = "x86_64")]
fn syscall_ioport_in32(cap: &Capability, offset: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset + 3 >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        let val: u32;
        core::arch::asm!("in eax, dx", out("eax") val, in("dx") port, options(nomem, nostack));
        SyscallResult::ok(val as u64)
    }
}

/// IOPORT_OUT32: Write a 32-bit dword to an I/O port (x86_64 only)
#[cfg(target_arch = "x86_64")]
fn syscall_ioport_out32(cap: &Capability, offset: u64, value: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset + 3 >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        core::arch::asm!("out dx, eax", in("eax") value as u32, in("dx") port, options(nomem, nostack));
    }

    SyscallResult::ok(0)
}

/// IoPort I/O for aarch64 — PCI I/O ports emulated via MMIO window.
#[cfg(target_arch = "aarch64")]
fn syscall_ioport_in8(cap: &Capability, offset: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::READ) {
        return SyscallResult::err(e);
    }
    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        // SAFETY: Port is validated within IoPort range; MMIO window is mapped during boot.
        let val = unsafe { crate::arch::pci_io_read8(port) };
        SyscallResult::ok(val as u64)
    }
}
#[cfg(target_arch = "aarch64")]
fn syscall_ioport_out8(cap: &Capability, offset: u64, value: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        // SAFETY: Port is validated within IoPort range; MMIO window is mapped during boot.
        unsafe { crate::arch::pci_io_write8(port, value as u8) };
    }
    SyscallResult::ok(0)
}
#[cfg(target_arch = "aarch64")]
fn syscall_ioport_in16(cap: &Capability, offset: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::READ) {
        return SyscallResult::err(e);
    }
    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset + 1 >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        // SAFETY: Port is validated within IoPort range; MMIO window is mapped during boot.
        let val = unsafe { crate::arch::pci_io_read16(port) };
        SyscallResult::ok(val as u64)
    }
}
#[cfg(target_arch = "aarch64")]
fn syscall_ioport_out16(cap: &Capability, offset: u64, value: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset + 1 >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        // SAFETY: Port is validated within IoPort range; MMIO window is mapped during boot.
        unsafe { crate::arch::pci_io_write16(port, value as u16) };
    }
    SyscallResult::ok(0)
}
#[cfg(target_arch = "aarch64")]
fn syscall_ioport_in32(cap: &Capability, offset: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::READ) {
        return SyscallResult::err(e);
    }
    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset + 3 >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        // SAFETY: Port is validated within IoPort range; MMIO window is mapped during boot.
        let val = unsafe { crate::arch::pci_io_read32(port) };
        SyscallResult::ok(val as u64)
    }
}
#[cfg(target_arch = "aarch64")]
fn syscall_ioport_out32(cap: &Capability, offset: u64, value: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    unsafe {
        let ioport = &*(cap.object as *const IoPortRange);
        if offset + 3 >= ioport.num_ports as u64 {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        let port = match ioport.base_port.checked_add(offset as u16) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        // SAFETY: Port is validated within IoPort range; MMIO window is mapped during boot.
        unsafe { crate::arch::pci_io_write32(port, value as u32) };
    }
    SyscallResult::ok(0)
}

/// IOPORT_CONFIGURE: Set base port and port count on a freshly retyped IoPort
///
/// Can only be called once (when num_ports == 0). Prevents double-configuration.
///
/// Args:
/// - base_port: Base I/O port number
/// - num_ports: Number of ports in the range
fn syscall_ioport_configure(cap: &Capability, base_port: u64, num_ports: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::IoPort, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    if base_port > 0xFFFF || num_ports == 0 || num_ports > 0xFFFF {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    if base_port + num_ports > 0x10000 {
        return SyscallResult::err(SyscallError::OutOfRange);
    }

    unsafe {
        let ioport = &mut *(cap.object as *mut IoPortRange);
        // One-shot: reject if already configured
        if ioport.num_ports > 0 {
            return SyscallResult::err(SyscallError::AlreadyExists);
        }
        ioport.base_port = base_port as u16;
        ioport.num_ports = num_ports as u16;
    }

    SyscallResult::ok(0)
}

/// VSPACE_MAP_PT: Install a page table at a specific level
///
/// Args:
/// - frame_cap_ptr: Capability pointer to the page table frame
/// - virt_addr: Virtual address whose table hierarchy to install into
/// - level: Page table level (1=PT, 2=PD, 3=PDPT)
fn syscall_vspace_map_pt(
    cap: &Capability,
    frame_cap_ptr: u64,
    virt_addr: u64,
    level: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    if level < 1 || level > 3 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    // Sub-lookup under CAP_LOCK
    let frame_cap = match lookup_cap_locked(frame_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&frame_cap, ObjectType::Frame, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let frame = &*(frame_cap.object as *const FrameObject);
        let vspace = &mut *(cap.object as *mut VSpace);

        match vspace.install_page_table(virt_addr, frame.phys_addr, level as usize) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// VSPACE_WALK: Walk user-half page tables, returning mapped pages
///
/// Args:
/// - start_vaddr: Virtual address to start scanning from
/// - max_entries: Maximum number of entries to return
///
/// Returns via IPC buffer:
///   msg[0] = count (number of entries)
///   msg[1] = next_vaddr (0 if done)
///   words[30..] = (vaddr, phys, flags) tuples, 3 u64s each
fn syscall_vspace_walk(cap: &Capability, start_vaddr: u64, max_entries: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        const EXT_ENTRY_BASE_WORD: usize = 42;
        const WALK_MAGIC: u64 = 0x5357_4c4b_434f_4d50; // "SWLKCOMP"

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

        // Write results to caller's IPC buffer
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();
        if current.is_null() {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let buf = (*current).ipc_buffer;
        if buf == 0 {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        if (*current).vspace_root.is_null() || !(&mut *(*current).vspace_root).ensure_writable(buf)
        {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let ipc_buf = buf as *mut crate::ipc::IpcBuffer;
        let ipc_words = ipc_buf as *mut u64;
        let _guard = crate::arch::uaccess::UserAccessGuard::new();

        (*ipc_buf).msg[0] = count as u64;
        (*ipc_buf).msg[1] = next_vaddr;
        // Mark that extended tuple area is valid for this reply.
        *ipc_words.add(ipc_words_total - 1) = WALK_MAGIC;
        for i in 0..count {
            let out = EXT_ENTRY_BASE_WORD + i * 3;
            *ipc_words.add(out) = entries[i].0; // vaddr
            *ipc_words.add(out + 1) = entries[i].1; // phys
            *ipc_words.add(out + 2) = entries[i].2; // flags
        }
    }

    SyscallResult::ok(0)
}

/// VSPACE_COPY_PAGE: Copy 4K page from source VSpace into destination Frame.
///
/// Walks source VSpace page tables to find the physical page at src_vaddr,
/// then copies 4096 bytes into the destination Frame via kernel direct mapping.
fn syscall_vspace_copy_page(
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

    // Sub-lookup under CAP_LOCK
    let frame_cap = match lookup_cap_locked(dst_frame_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&frame_cap, ObjectType::Frame, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let vspace = &*(cap.object as *const VSpace);
        let frame = &*(frame_cap.object as *const FrameObject);

        let src_phys = match vspace.resolve_page(src_vaddr) {
            Some(p) => p,
            None => return SyscallResult::err(SyscallError::NotFound),
        };

        let src_ptr = crate::mm::phys_to_virt(src_phys) as *const u8;
        let dst_ptr = crate::mm::phys_to_virt(frame.phys_addr) as *mut u8;
        core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, crate::mm::PAGE_SIZE);
    }

    SyscallResult::ok(0)
}

/// VSPACE_CLONE_COW_PAGE: Share one source page into destination VSpace.
///
/// Writable source pages are converted to COW (read-only + software COW bit)
/// and mapped into destination as COW. Read-only pages are shared directly.
///
/// Args:
/// - src_vaddr: Source virtual page in the invoking VSpace
/// - dst_vspace_cap_ptr: Capability pointer to destination VSpace
/// - dst_vaddr: Destination virtual page in destination VSpace
fn syscall_vspace_clone_cow_page(
    cap: &Capability,
    src_vaddr: u64,
    dst_vspace_cap_ptr: u64,
    dst_vaddr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }
    if !cap.has_right(CapRights::MAP) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    if src_vaddr & 0xFFF != 0 || dst_vaddr & 0xFFF != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let dst_cap = match lookup_cap_locked(dst_vspace_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&dst_cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    unsafe {
        let src_vs = &mut *(cap.object as *mut VSpace);
        let dst_vs = &mut *(dst_cap.object as *mut VSpace);
        match src_vs.clone_page_cow_to(src_vaddr, dst_vs, dst_vaddr) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// VSPACE_SHARE_RO_PAGE: Share a read-only page from src to dst VSpace.
///
/// Copies the PTE if it is present and read-only. Returns an error for
/// writable or absent pages — the source VSpace is **never modified**.
/// This is used during fork for non-MO regions (e.g. shared library RO
/// pages) where we want to share the physical frame without COW-marking
/// the parent.
fn syscall_vspace_share_ro_page(
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

    let dst_cap = match lookup_cap_locked(dst_vspace_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&dst_cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    unsafe {
        // SAFETY: Both VSpace pointers validated above.
        let src_vs = &mut *(cap.object as *mut VSpace);
        let dst_vs = &mut *(dst_cap.object as *mut VSpace);
        match src_vs.share_ro_page_to(src_vaddr, dst_vs, dst_vaddr) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// VSPACE_MAP_DEVICE: Map a single 4K page from a device untyped region.
///
/// Args:
/// - device_untyped_cap_ptr: Capability pointer to a device Untyped object
/// - page_offset: Byte offset within the untyped region (must be 4K-aligned)
/// - virt_addr: Virtual address to map at (must be 4K-aligned)
/// - flags_bits: Mapping flags (same format as VSPACE_MAP)
fn syscall_vspace_map_device(
    cap: &Capability,
    device_untyped_cap_ptr: u64,
    page_offset: u64,
    virt_addr: u64,
    flags_bits: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    if page_offset & 0xFFF != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    let dev_cap = match lookup_cap_locked(device_untyped_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&dev_cap, ObjectType::Untyped, CapRights::READ) {
        return SyscallResult::err(e);
    }
    if (flags_bits & 1) != 0 && !dev_cap.has_right(CapRights::WRITE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    if (flags_bits & 4) != 0 && !dev_cap.has_right(CapRights::EXECUTE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    // W^X: writable + executable is not permitted
    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let dev_ut = &*(dev_cap.object as *const UntypedMemory);
        if !dev_ut.is_device {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let map_limit = crate::init::initrd_device_limit_for(dev_ut as *const UntypedMemory)
            .or_else(|| crate::init::fb_device_limit_for(dev_ut as *const UntypedMemory))
            .unwrap_or(dev_ut.size_bytes() as u64);

        let end = match page_offset.checked_add(0x1000) {
            Some(v) => v,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };
        if end > map_limit {
            return SyscallResult::err(SyscallError::OutOfRange);
        }

        let phys = match dev_ut.phys_addr.checked_add(page_offset) {
            Some(v) => v,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };

        let vspace = &mut *(cap.object as *mut VSpace);
        let flags = PageFlags {
            writable: flags_bits & 1 != 0,
            user: flags_bits & 2 != 0,
            executable: flags_bits & 4 != 0,
            cache_disable: flags_bits & 8 != 0,
            write_through: flags_bits & 16 != 0,
            cow: flags_bits & 32 != 0,
        };

        match vspace.map(virt_addr, phys, flags) {
            Ok(()) => SyscallResult::ok(0),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// VSPACE_MAP_DEVICE_RANGE: Batch-map contiguous 4K pages from a device untyped.
///
/// Args:
/// - device_untyped_cap_ptr: Capability pointer to a device Untyped object
/// - offset_start: Starting byte offset within the untyped region (must be 4K-aligned)
/// - vaddr_start: Starting virtual address (must be 4K-aligned)
/// - count_and_flags: (count << 32) | flags — count is number of 4K pages, flags as VSPACE_MAP
///
/// Returns: pages_mapped in value field. On partial failure, returns count mapped so far.
/// Capped at 8192 pages (32 MiB) per call.
fn syscall_vspace_map_device_range(
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

    let dev_cap = match lookup_cap_locked(device_untyped_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&dev_cap, ObjectType::Untyped, CapRights::READ) {
        return SyscallResult::err(e);
    }
    if (flags_bits & 1) != 0 && !dev_cap.has_right(CapRights::WRITE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    if (flags_bits & 4) != 0 && !dev_cap.has_right(CapRights::EXECUTE) {
        return SyscallResult::err(SyscallError::InsufficientRights);
    }
    // W^X: writable + executable is not permitted
    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let dev_ut = &*(dev_cap.object as *const UntypedMemory);
        if !dev_ut.is_device {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let map_limit = crate::init::initrd_device_limit_for(dev_ut as *const UntypedMemory)
            .or_else(|| crate::init::fb_device_limit_for(dev_ut as *const UntypedMemory))
            .unwrap_or(dev_ut.size_bytes() as u64);

        // Bounds check the entire range up front
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

        let flags = PageFlags {
            writable: flags_bits & 1 != 0,
            user: flags_bits & 2 != 0,
            executable: flags_bits & 4 != 0,
            cache_disable: flags_bits & 8 != 0,
            write_through: flags_bits & 16 != 0,
            cow: flags_bits & 32 != 0,
        };

        let vspace = &mut *(cap.object as *mut VSpace);
        let base_phys = dev_ut.phys_addr;
        let phys_start = match base_phys.checked_add(offset_start) {
            Some(v) => v,
            None => return SyscallResult::err(SyscallError::OutOfRange),
        };

        match vspace.map_range_partial(vaddr_start, phys_start, count as usize, flags) {
            Ok(mapped) => SyscallResult::ok(mapped as u64),
            Err(e) => SyscallResult::err(syscall_error_from_vspace_error(e)),
        }
    }
}

/// Convert VSpaceError to syscall error
fn syscall_error_from_vspace_error(err: VSpaceError) -> SyscallError {
    match err {
        VSpaceError::Alignment => SyscallError::InvalidArgument,
        VSpaceError::AlreadyMapped => SyscallError::AlreadyMapped,
        VSpaceError::NotMapped => SyscallError::NotFound,
        VSpaceError::OutOfMemory => SyscallError::OutOfMemory,
        VSpaceError::NotCow => SyscallError::InvalidOperation,
        VSpaceError::InvalidArgument => SyscallError::InvalidArgument,
    }
}

/// Convert CNode error to syscall error
fn syscall_error_from_cap_error(err: CapError) -> SyscallError {
    match err {
        CapError::InvalidSlot | CapError::InvalidArgument => SyscallError::InvalidArgument,
        CapError::SlotEmpty => SyscallError::NotFound,
        CapError::InsufficientRights => SyscallError::InsufficientRights,
        CapError::InsufficientMemory | CapError::OutOfSlots => SyscallError::OutOfMemory,
        CapError::SlotOccupied => SyscallError::SlotOccupied,
        CapError::HasChildren => SyscallError::InvalidOperation,
        _ => SyscallError::InvalidOperation,
    }
}

/// ClockGetTime: Return current monotonic time in nanoseconds
fn syscall_clock_gettime(clock_id: u64) -> SyscallResult {
    // Accept both the native SaltyOS IDs and the FreeBSD IDs used by some
    // imported userland sources.
    match clock_id {
        0 | 1 | 4 | 9 | 10 | 11 | 12 => {}
        _ => return SyscallResult::err(SyscallError::InvalidArgument),
    }
    let ns = crate::arch::now_ns();
    SyscallResult::ok(ns)
}

/// NanoSleep: Sleep for the specified duration
///
/// Args:
/// - seconds: Number of whole seconds to sleep
/// - nanoseconds: Additional nanoseconds (0-999,999,999)
fn syscall_nanosleep(seconds: u64, nanoseconds: u64) -> SyscallResult {
    if nanoseconds >= 1_000_000_000 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }
    let duration_ns = seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(nanoseconds);
    if duration_ns == 0 {
        return SyscallResult::ok(0);
    }

    let now = crate::arch::now_ns();
    let wakeup = now.saturating_add(duration_ns);

    let scheduler = crate::sched::scheduler::scheduler();
    scheduler.block_current_sleeping(wakeup);

    // When we resume (woken by timer or signal), return 0
    SyscallResult::ok(0)
}

/// Handle system call logic
///
/// Register mapping from assembly (after ABI translation):
///   syscall = RAX (syscall number)
///   cap_ptr = RDI (arg0 / capability pointer)
///   msg_info = RSI (arg1 / message info or label)
///   mr0 = RDX (arg2)
///   mr1 = RCX (arg3, from user R10)
///   mr2 = R8 (arg4, from user R8)
///   mr3 = R9 (arg5, from user R9 — currently unused by userspace)
pub fn handle(
    syscall: u64,
    cap_ptr: u64,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> SyscallResult {
    let syscall_num = match Syscall::try_from(syscall) {
        Ok(s) => s,
        Err(e) => return SyscallResult::err(e),
    };

    match syscall_num {
        Syscall::Send => syscall_send(cap_ptr, msg_info, mr0, mr1, mr2, mr3),
        Syscall::Recv => syscall_recv(cap_ptr),
        Syscall::Call => syscall_call(cap_ptr, msg_info, mr0, mr1, mr2, mr3),
        Syscall::ReplyRecv => syscall_reply_recv(cap_ptr, msg_info, mr0, mr1, mr2, mr3),
        Syscall::NBSend => syscall_nbsend(cap_ptr, msg_info, mr0, mr1, mr2, mr3),
        Syscall::Signal => syscall_signal(cap_ptr, msg_info),
        Syscall::Wait => syscall_wait(cap_ptr),
        Syscall::Poll => syscall_poll(cap_ptr),
        Syscall::Yield => {
            // Yield using per-CPU scheduler lock only (no global lock).
            crate::sched::yield_now();
            SyscallResult::ok(0)
        }
        Syscall::Invoke => syscall_invoke(cap_ptr, msg_info, mr0, mr1, mr2, mr3),
        Syscall::SetInvokeDepths => syscall_set_invoke_depths(cap_ptr, msg_info),
        Syscall::DebugPutChar => {
            // SAFETY: save/restore IRQ flags around spinlock
            let irq = unsafe { save_irq_disable() };
            crate::SERIAL_LOCK.lock();
            crate::serial_putc_hw(cap_ptr as u8);
            crate::console::flush_pending();
            crate::SERIAL_LOCK.unlock();
            unsafe { restore_irq(irq) };
            SyscallResult::ok(0)
        }
        Syscall::DebugPutStr => {
            // Batch serial output: cap_ptr = length (0..40), msg_info..mr3 = 5×8 = 40 data bytes
            let len = cap_ptr as usize;
            if len > 40 {
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            let regs = [msg_info, mr0, mr1, mr2, mr3];
            // SAFETY: reinterpreting register array as bytes; all 40 bytes are valid
            let data = unsafe { core::slice::from_raw_parts(regs.as_ptr() as *const u8, 40) };
            // SAFETY: save/restore IRQ flags around spinlock
            let irq = unsafe { save_irq_disable() };
            crate::SERIAL_LOCK.lock();
            crate::serial_write_hw(&data[..len]);
            crate::SERIAL_LOCK.unlock();
            unsafe { restore_irq(irq) };
            SyscallResult::ok(0)
        }
        Syscall::DebugPutBuf => {
            // Pointer-based serial output: cap_ptr = user pointer, msg_info = length (max 256)
            let len = msg_info as usize;
            if len > 256 || cap_ptr >= 0x0000_8000_0000_0000 {
                return SyscallResult::err(SyscallError::InvalidArgument);
            }
            // Copy from user space into kernel stack buffer before acquiring lock
            let user_ptr = cap_ptr as *const u8;
            let mut kbuf = [0u8; 256];
            {
                // SMAP: temporarily allow user memory access
                let _guard = crate::arch::uaccess::UserAccessGuard::new();
                for i in 0..len {
                    // SAFETY: pointer validated above to be in user space range;
                    // user pages are accessible via the active VSpace page tables
                    kbuf[i] = unsafe { core::ptr::read_volatile(user_ptr.add(i)) };
                }
            }
            // Write in 32-byte chunks, re-enabling IRQs between chunks.
            // This caps IRQ-disabled time to ~2.8ms per chunk (at 115200 baud)
            // instead of ~22ms for a full 256-byte buffer, allowing timer ticks
            // and IPIs to interleave with serial output.
            let mut off = 0;
            while off < len {
                let end = if off + 32 < len { off + 32 } else { len };
                // SAFETY: save/restore IRQ flags around spinlock
                let irq = unsafe { save_irq_disable() };
                crate::SERIAL_LOCK.lock();
                crate::serial_write_hw(&kbuf[off..end]);
                crate::SERIAL_LOCK.unlock();
                unsafe { restore_irq(irq) };
                off = end;
            }
            SyscallResult::ok(0)
        }
        Syscall::ClockGetTime => syscall_clock_gettime(cap_ptr),
        Syscall::NanoSleep => {
            // NanoSleep — block_current_sleeping uses per-CPU scheduler lock only
            unsafe {
                let irq = save_irq_disable();
                let result = syscall_nanosleep(cap_ptr, msg_info);
                restore_irq(irq);
                result
            }
        }
        Syscall::DebugConsoleControl => {
            // subcmd 0 = disable kernel framebuffer console, 1 = enable
            match cap_ptr {
                0 => crate::console::disable(),
                1 => crate::console::enable(),
                _ => return SyscallResult::err(SyscallError::InvalidArgument),
            }
            SyscallResult::ok(0)
        }
        Syscall::ThreadExit => syscall_thread_exit(),
        Syscall::DebugDumpState => {
            // Read scheduler state (debug only, no lock needed)
            unsafe {
                let irq = save_irq_disable();
                let scheduler = crate::sched::scheduler::scheduler();
                let current = scheduler.current();
                if !current.is_null() {
                    let tcb = &*current;
                    let s = crate::SerialGuard::acquire();
                    s.puts("[DEBUG] TCB state dump:\n");
                    #[cfg(target_arch = "x86_64")]
                    {
                        s.puts("  RIP=");
                        s.hex(tcb.context.rip);
                        s.puts(" RSP=");
                        s.hex(tcb.context.rsp);
                        s.puts("\n  RAX=");
                        s.hex(tcb.context.rax);
                        s.puts(" RBX=");
                        s.hex(tcb.context.rbx);
                        s.puts("\n  RCX=");
                        s.hex(tcb.context.rcx);
                        s.puts(" RDX=");
                        s.hex(tcb.context.rdx);
                        s.puts("\n  RSI=");
                        s.hex(tcb.context.rsi);
                        s.puts(" RDI=");
                        s.hex(tcb.context.rdi);
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        s.puts("  RET_ELR=");
                        s.hex(tcb.context.return_elr);
                        s.puts(" SP=");
                        s.hex(tcb.context.sp);
                        s.puts(" RET_SPSR=");
                        s.hex(tcb.context.return_spsr);
                    }
                    s.putc(b'\n');
                    drop(s);
                }
                // Print scheduling statistics
                for cpu in 0..crate::arch::MAX_CPUS {
                    if scheduler.timer_ticks[cpu] == 0 && cpu > 0 {
                        continue;
                    }
                    let s = crate::SerialGuard::acquire();
                    s.puts("[SCHED STATS] CPU");
                    s.dec(cpu as u64);
                    s.puts(": ctx=");
                    s.dec(scheduler.context_switches[cpu]);
                    s.puts(" tick=");
                    s.dec(scheduler.timer_ticks[cpu]);
                    s.puts(" idle=");
                    s.dec(scheduler.idle_ticks[cpu]);
                    s.puts(" ipi=");
                    s.dec(scheduler.ipi_reschedules[cpu]);
                    s.putc(b'\n');
                    drop(s);
                }
                restore_irq(irq);
            }
            SyscallResult::ok(0)
        }
        Syscall::Futex => {
            // cap_ptr = user virtual address (futex word)
            // msg_info = operation (FUTEX_WAIT=0, FUTEX_WAKE=1, FUTEX_WAIT_TIMEOUT=2)
            // mr0 = expected value (for WAIT) or max wake count (for WAKE)
            // mr1 = timeout in nanoseconds (for FUTEX_WAIT_TIMEOUT)
            crate::ipc::futex::syscall_futex(cap_ptr, msg_info, mr0, mr1)
        }
        Syscall::GetRandom => {
            // Returns a 64-bit hardware random number via RDRAND.
            // No arguments needed. Returns value in RDX.
            match crate::rng::rdrand64() {
                Some(val) => SyscallResult::ok(val),
                None => SyscallResult::err(SyscallError::InvalidOperation),
            }
        }
        Syscall::Shutdown => {
            // ACPI S5 power off. Does not return.
            crate::arch::shutdown();
        }
        Syscall::SendTimed => {
            // Same register layout as Send: (cap, msg_info, mr0, mr1, mr2, mr3).
            // Timeout is read from IpcBuffer.timeout_ns (set by userland).
            let cap = match lookup_cap_locked(cap_ptr) {
                Ok(c) => c,
                Err(e) => return SyscallResult::err(e),
            };

            if cap.obj_type != ObjectType::Endpoint {
                return SyscallResult::err(SyscallError::InvalidCapability);
            }
            if let Err(e) = validate_endpoint_cap(&cap, CapRights::SEND) {
                return SyscallResult::err(e);
            }

            let msg = construct_message(msg_info, mr0, mr1, mr2, mr3);
            let timeout_ns = unsafe {
                let scheduler = crate::sched::scheduler::scheduler();
                let current = scheduler.current();
                if !current.is_null() && (*current).ipc_buffer != 0 {
                    let ipc_buf = (*current).ipc_buffer as *const crate::ipc::IpcBuffer;
                    let _guard = crate::arch::uaccess::UserAccessGuard::new();
                    (*ipc_buf).timeout_ns
                } else {
                    0
                }
            };

            unsafe {
                let irq = save_irq_disable();
                let endpoint = &mut *(cap.object as *mut Endpoint);
                let result = match endpoint.send_timeout(&msg, cap.badge, timeout_ns) {
                    Ok(v) => v,
                    Err(err) => {
                        restore_irq(irq);
                        return SyscallResult::err(err);
                    }
                };
                restore_irq(irq);

                if result == 0 {
                    SyscallResult::ok(0)
                } else {
                    SyscallResult::err(SyscallError::Cancelled)
                }
            }
        }
        Syscall::RecvTimed => {
            // Timeout read from IpcBuffer.timeout_ns.
            // Returns badge in value, 0 in error on success, Cancelled (12) on timeout.
            let cap = match lookup_cap_locked(cap_ptr) {
                Ok(c) => c,
                Err(e) => return SyscallResult::err(e),
            };

            if cap.obj_type != ObjectType::Endpoint {
                return SyscallResult::err(SyscallError::InvalidCapability);
            }
            if let Err(e) = validate_endpoint_cap(&cap, CapRights::RECV) {
                return SyscallResult::err(e);
            }

            let timeout_ns = unsafe { read_ipc_buffer_timeout() };

            unsafe {
                let irq = save_irq_disable();
                let endpoint = &mut *(cap.object as *mut Endpoint);
                let (msg, badge, result) = match endpoint.recv_timeout(timeout_ns) {
                    Ok(v) => v,
                    Err(err) => {
                        restore_irq(irq);
                        return SyscallResult::err(err);
                    }
                };
                if result == 0 {
                    write_msg_to_ipc_buffer(&msg, badge);
                }
                restore_irq(irq);

                if result == 0 {
                    SyscallResult::ok(badge)
                } else {
                    SyscallResult::err(SyscallError::Cancelled)
                }
            }
        }
        Syscall::RecvAny => syscall_recv_any(cap_ptr),
        Syscall::ReplyRecvAny => syscall_reply_recv_any(cap_ptr, msg_info, mr0, mr1, mr2, mr3),
        Syscall::RecvAnyTimed => syscall_recv_any_timed(cap_ptr),
        Syscall::ReplyRecvAnyTimed => {
            syscall_reply_recv_any_timed(cap_ptr, msg_info, mr0, mr1, mr2, mr3)
        }
        Syscall::NotifReturn => syscall_notif_return(cap_ptr),
    }
}

// ---------------------------------------------------------------------------
// MemoryObject invoke implementations
// ---------------------------------------------------------------------------

/// MO_COMMIT: Allocate physical frames for pages [offset..offset+count].
///
/// When `ut_cap_ptr == 0`, frames are allocated from the PMM (existing path).
/// When `ut_cap_ptr != 0`, frames are allocated from the specified untyped
/// source's watermark or free list. Untyped-backed pages are tagged with
/// `PHYS_TAG_UNTYPED` so decommit/destroy can return them to the source.
fn syscall_mo_commit(cap: &Capability, offset: u64, count: u64, ut_cap_ptr: u64) -> SyscallResult {
    use crate::cap::memory_object::{PHYS_TAG_BUSY, PHYS_TAG_MASK, PHYS_TAG_UNTYPED};

    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        // SAFETY: cap.object validated as MemoryObject above.
        let mo = &mut *(cap.object as *mut crate::cap::memory_object::MemoryObject);
        let start = offset as usize;
        let cnt = count as usize;

        if start.checked_add(cnt).is_none() || start + cnt > mo.page_count as usize {
            return SyscallResult::err(SyscallError::OutOfRange);
        }

        let mo_ptr = cap.object as *mut crate::cap::memory_object::MemoryObject;
        let mut alloc = crate::mm::node_alloc::PmmNodeAllocator {
            owner: crate::mm::frame::FrameOwner::MoMeta {
                mo: mo_ptr,
                subkind: crate::mm::frame::MoMetaKind::Radix,
            },
            use_reserve: false,
        };

        if ut_cap_ptr == 0 {
            // ---------------------------------------------------------------
            // PMM path (existing behavior + commit_lock)
            // ---------------------------------------------------------------
            let mut committed = 0u64;
            for i in 0..cnt {
                let page_idx = start + i;

                mo.commit_lock.lock();
                let already =
                    mo.is_local_committed(page_idx) || mo.resolve_page(page_idx).is_some();
                mo.commit_lock.unlock();

                if already {
                    committed += 1;
                    continue;
                }

                let owner = crate::mm::frame::FrameOwner::MoData {
                    mo: mo_ptr,
                    page_idx: page_idx as u32,
                };
                let phys = match crate::mm::pmm_alloc(&owner) {
                    Some(p) => p,
                    None => break,
                };

                let frame_ptr = crate::mm::phys_to_virt(phys) as *mut u8;
                core::ptr::write_bytes(frame_ptr, 0, crate::mm::PAGE_SIZE);

                mo.commit_lock.lock();
                if !mo.commit_page(page_idx, phys, &mut alloc) {
                    mo.commit_lock.unlock();
                    crate::mm::pmm_free(phys, &owner);
                    break;
                }
                mo.commit_lock.unlock();
                committed += 1;
            }

            SyscallResult::ok(committed)
        } else {
            // ---------------------------------------------------------------
            // Untyped path: allocate frames from the specified untyped source
            // ---------------------------------------------------------------

            // Look up the untyped capability
            let ut_cap = match lookup_cap_locked(ut_cap_ptr) {
                Ok(c) => c,
                Err(e) => return SyscallResult::err(e),
            };
            if ut_cap.obj_type != ObjectType::Untyped {
                return SyscallResult::err(SyscallError::InvalidCapability);
            }
            let ut = &mut *(ut_cap.object as *mut crate::cap::UntypedMemory);
            if ut.is_device {
                return SyscallResult::err(SyscallError::InvalidCapability);
            }

            let mut committed = 0u64;
            for i in 0..cnt {
                let page_idx = start + i;

                // Step 1: Reserve slot under commit_lock
                mo.commit_lock.lock();
                let reserve = mo.pages.reserve_slot(page_idx, PHYS_TAG_BUSY, &mut alloc);
                mo.commit_lock.unlock();

                match reserve {
                    Ok(false) => {
                        // Already committed or BUSY — count as success
                        committed += 1;
                        continue;
                    }
                    Err(()) => {
                        // Radix node allocation failed
                        break;
                    }
                    Ok(true) => {
                        // BUSY sentinel placed — proceed to allocate frame
                    }
                }

                // Step 2: Allocate a frame from the untyped source
                ut.alloc_lock.lock();

                let phys = if ut.free_list_head != 0 {
                    // Pop from free list
                    let p = ut.free_list_head;
                    let next = *(crate::mm::phys_to_virt(p) as *const u64);
                    ut.free_list_head = next;
                    ut.free_list_count -= 1;
                    ut.alloc_lock.unlock();
                    p
                } else {
                    // Watermark bump: align to PAGE_SIZE and carve
                    let page_size = crate::mm::PAGE_SIZE as u64;
                    let aligned = (ut.watermark + page_size - 1) & !(page_size - 1);
                    let ut_size = ut.size_bytes() as u64;
                    if aligned + page_size > ut_size {
                        ut.alloc_lock.unlock();
                        // No space — clear BUSY sentinel
                        mo.commit_lock.lock();
                        mo.pages.remove(page_idx);
                        mo.commit_lock.unlock();
                        break;
                    }
                    let p = ut.phys_addr + aligned;
                    ut.watermark = aligned + page_size;
                    ut.alloc_lock.unlock();
                    p
                };

                // Step 3: Zero the page (outside all locks)
                let frame_ptr = crate::mm::phys_to_virt(phys) as *mut u8;
                core::ptr::write_bytes(frame_ptr, 0, crate::mm::PAGE_SIZE);

                // Step 4: Write final entry (overwrite BUSY with phys | UNTYPED tag)
                mo.commit_lock.lock();
                // insert() overwrites the BUSY sentinel directly — no remove needed.
                // Path already exists from reserve_slot, so no new node allocation.
                if !mo.commit_page(page_idx, phys | PHYS_TAG_UNTYPED, &mut alloc) {
                    mo.commit_lock.unlock();
                    // Return frame to untyped free list
                    ut.alloc_lock.lock();
                    *(crate::mm::phys_to_virt(phys) as *mut u64) = ut.free_list_head;
                    ut.free_list_head = phys;
                    ut.free_list_count += 1;
                    ut.alloc_lock.unlock();
                    break;
                }
                mo.commit_lock.unlock();
                committed += 1;
            }

            SyscallResult::ok(committed)
        }
    }
}

/// MO_DECOMMIT: Release physical frames for pages [offset..offset+count]
///
/// Frees locally-committed pages and clears their entries. Pages in the
/// hidden node chain (shared with COW siblings) are NOT freed — they are
/// owned by the node and released when all referencing MOs are destroyed.
///
/// Pages tagged with PHYS_TAG_UNTYPED are returned to the source untyped's
/// free list instead of pmm_free.
fn syscall_mo_decommit(cap: &Capability, offset: u64, count: u64) -> SyscallResult {
    use crate::cap::memory_object::{PHYS_TAG_BUSY, PHYS_TAG_MASK, PHYS_TAG_UNTYPED};

    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        // SAFETY: cap.object validated as MemoryObject above.
        let mo = &mut *(cap.object as *mut crate::cap::memory_object::MemoryObject);
        let start = offset as usize;
        let cnt = count as usize;

        if start.checked_add(cnt).is_none() || start + cnt > mo.page_count as usize {
            return SyscallResult::err(SyscallError::OutOfRange);
        }

        let mo_ptr = cap.object as *mut crate::cap::memory_object::MemoryObject;

        let mut decommitted = 0u64;
        for i in 0..cnt {
            let page_idx = start + i;

            mo.commit_lock.lock();
            let entry = mo.pages.get(page_idx);
            if entry == 0 || entry & PHYS_TAG_BUSY != 0 {
                mo.commit_lock.unlock();
                continue;
            }
            let phys = entry & !PHYS_TAG_MASK;
            mo.pages.remove(page_idx);
            mo.commit_lock.unlock();

            if phys == 0 {
                continue;
            }

            if entry & PHYS_TAG_UNTYPED != 0 {
                // Return to source untyped's free list
                let ut = crate::init::find_untyped_for_phys(phys);
                if !ut.is_null() {
                    (*ut).alloc_lock.lock();
                    *(crate::mm::phys_to_virt(phys) as *mut u64) = (*ut).free_list_head;
                    (*ut).free_list_head = phys;
                    (*ut).free_list_count += 1;
                    (*ut).alloc_lock.unlock();
                }
            } else {
                crate::mm::pmm_free(
                    phys,
                    &crate::mm::frame::FrameOwner::MoData {
                        mo: mo_ptr,
                        page_idx: page_idx as u32,
                    },
                );
            }
            decommitted += 1;
        }

        SyscallResult::ok(decommitted)
    }
}

/// MO_GET_SIZE: Return the page count of the memory object
fn syscall_mo_get_size(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::READ) {
        return SyscallResult::err(e);
    }
    // SAFETY: cap.object was validated as ObjectType::MemoryObject above and is non-null.
    unsafe {
        let mo = &*(cap.object as *const crate::cap::memory_object::MemoryObject);
        SyscallResult::ok(mo.page_count as u64)
    }
}

/// MO_CLONE: Initialize an existing MemoryObject as a COW snapshot child.
///
/// The caller must supply `child_mo_cap_ptr`, a capability pointer to a
/// freshly allocated MemoryObject object. This preserves the Untyped/MO
/// boundary: kernel object storage comes from Untyped retype, while MO_CLONE
/// only wires up the COW relationship.
fn syscall_mo_clone(cap: &Capability, child_mo_cap_ptr: u64, _flags: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let child_cap = match lookup_cap_locked(child_mo_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&child_cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    unsafe {
        let parent_mo = &mut *(cap.object as *mut crate::cap::memory_object::MemoryObject);
        let child_mo_ptr = child_cap.object as *mut crate::cap::memory_object::MemoryObject;
        if child_mo_ptr.is_null() || child_mo_ptr == parent_mo as *mut _ {
            return SyscallResult::err(SyscallError::InvalidArgument);
        }
        let child_mo = &mut *child_mo_ptr;

        let child_refcount = child_mo
            .header
            .ref_count
            .load(core::sync::atomic::Ordering::Acquire);
        let child_is_pristine = child_refcount != 0
            && child_mo.cow_parent == 0
            && child_mo.first_child.is_null()
            && child_mo.next_sibling.is_null()
            && child_mo.pages.is_empty()
            && child_mo.reverse_maps.inline_count == 0
            && child_mo.reverse_maps.overflow.is_null();
        if !child_is_pristine {
            return SyscallResult::err(SyscallError::Busy);
        }

        let child_untyped_phys = child_mo.untyped_phys;

        // Allocate a cap slot for the parent reference (cow_parent)
        let parent_ref_slot = match crate::cap::alloc_slot() {
            Some(s) => s,
            None => return SyscallResult::err(SyscallError::OutOfMemory),
        };

        // Copy parent cap into the parent_ref_slot to pin the parent
        let parent_ref_cap = crate::cap::get_cap_mut(parent_ref_slot);
        parent_ref_cap.object = cap.object;
        parent_ref_cap.obj_type = ObjectType::MemoryObject;
        parent_ref_cap.rights = CapRights::READ;
        parent_ref_cap.depth = 0;
        parent_ref_cap.badge = 0;
        crate::cap::increment_refcount(cap.object);

        // Initialize the already-allocated child object in place.
        core::ptr::write(
            child_mo_ptr,
            crate::cap::memory_object::MemoryObject::new(child_untyped_phys, parent_mo.page_count),
        );
        (*child_mo_ptr).kind = crate::cap::memory_object::MoKind::CowChild;
        (*child_mo_ptr).cow_parent = parent_ref_slot as u64;

        // Add child to parent's intrusive child list
        (*child_mo_ptr).next_sibling = parent_mo.first_child;
        parent_mo.first_child = child_mo_ptr;

        SyscallResult::ok(0)
    }
}

/// MO_RESIZE: Resize the memory object to new_page_count pages.
///
/// **Shrink**: decommits pages beyond new count via radix tree removal.
/// **Grow**: just updates page_count. Radix tree grows lazily on commit.
fn syscall_mo_resize(cap: &Capability, new_page_count: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let new_pc = new_page_count as usize;
    if new_pc == 0 || new_pc > u32::MAX as usize {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let mo = &mut *(cap.object as *mut crate::cap::memory_object::MemoryObject);
        let old_pc = mo.page_count as usize;

        if new_pc == old_pc {
            return SyscallResult::ok(0);
        }

        if new_pc < old_pc {
            // Shrink: free pages beyond new_pc
            use crate::cap::memory_object::{PHYS_TAG_BUSY, PHYS_TAG_MASK, PHYS_TAG_UNTYPED};
            let mo_ptr = cap.object as *mut crate::cap::memory_object::MemoryObject;
            for i in new_pc..old_pc {
                let entry = mo.pages.get(i);
                if entry == 0 || entry & PHYS_TAG_BUSY != 0 {
                    continue;
                }
                let phys = entry & !PHYS_TAG_MASK;
                mo.pages.remove(i);
                if phys == 0 {
                    continue;
                }
                if entry & PHYS_TAG_UNTYPED != 0 {
                    let ut = crate::init::find_untyped_for_phys(phys);
                    if !ut.is_null() {
                        (*ut).alloc_lock.lock();
                        *(crate::mm::phys_to_virt(phys) as *mut u64) = (*ut).free_list_head;
                        (*ut).free_list_head = phys;
                        (*ut).free_list_count += 1;
                        (*ut).alloc_lock.unlock();
                    }
                } else {
                    crate::mm::pmm_free(
                        phys,
                        &crate::mm::frame::FrameOwner::MoData {
                            mo: mo_ptr,
                            page_idx: i as u32,
                        },
                    );
                }
            }
            mo.page_count = new_pc as u32;
            return SyscallResult::ok(0);
        }

        // Grow: radix tree grows lazily on insert, just update count
        mo.page_count = new_pc as u32;
        SyscallResult::ok(0)
    }
}

/// MO_READ: Read bytes from MO committed pages into the caller's IPC buffer.
///
/// Args:
/// - offset: byte offset within the MO
/// - count: number of bytes to read
///
/// Copies data from MO's physical pages (via direct map) into the
/// current thread's IPC buffer at offset 0. No VSpace mapping needed.
fn syscall_mo_read(cap: &Capability, offset: u64, count: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let byte_count = count as usize;
    if byte_count == 0 {
        return SyscallResult::ok(0);
    }

    unsafe {
        let mo = &*(cap.object as *const crate::cap::memory_object::MemoryObject);
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();
        if current.is_null() || (*current).ipc_buffer == 0 {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let buf_addr = (*current).ipc_buffer;
        if (*current).vspace_root.is_null()
            || !(&mut *(*current).vspace_root).ensure_writable(buf_addr)
        {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let ipc_buf = buf_addr as *mut u8;
        let _guard = crate::arch::uaccess::UserAccessGuard::new();

        let mut bytes_read = 0usize;
        let mut src_off = offset as usize;

        while bytes_read < byte_count {
            let page_idx = src_off / crate::mm::PAGE_SIZE;
            let page_off = src_off % crate::mm::PAGE_SIZE;
            let chunk = core::cmp::min(crate::mm::PAGE_SIZE - page_off, byte_count - bytes_read);

            let phys = match mo.resolve_page(page_idx) {
                Some(p) => p,
                None => break, // Uncommitted page — stop
            };

            let src = (crate::mm::phys_to_virt(phys) as *const u8).add(page_off);
            let dst = ipc_buf.add(bytes_read);
            core::ptr::copy_nonoverlapping(src, dst, chunk);

            bytes_read += chunk;
            src_off += chunk;
        }

        SyscallResult::ok(bytes_read as u64)
    }
}

/// MO_WRITE: Write bytes from the caller's IPC buffer into MO committed pages.
///
/// Args:
/// - offset: byte offset within the MO
/// - count: number of bytes to write
///
/// Copies data from the current thread's IPC buffer into MO's physical
/// pages via direct map. Pages must already be committed.
fn syscall_mo_write(cap: &Capability, offset: u64, count: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let byte_count = count as usize;
    if byte_count == 0 {
        return SyscallResult::ok(0);
    }

    unsafe {
        let mo = &*(cap.object as *const crate::cap::memory_object::MemoryObject);
        let scheduler = crate::sched::scheduler::scheduler();
        let current = scheduler.current();
        if current.is_null() || (*current).ipc_buffer == 0 {
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        let ipc_buf = (*current).ipc_buffer as *const u8;
        let _guard = crate::arch::uaccess::UserAccessGuard::new();

        let mut bytes_written = 0usize;
        let mut dst_off = offset as usize;

        while bytes_written < byte_count {
            let page_idx = dst_off / crate::mm::PAGE_SIZE;
            let page_off = dst_off % crate::mm::PAGE_SIZE;
            let chunk = core::cmp::min(crate::mm::PAGE_SIZE - page_off, byte_count - bytes_written);

            let phys = match mo.resolve_page(page_idx) {
                Some(p) => p,
                None => break, // Uncommitted — stop
            };

            let src = ipc_buf.add(bytes_written);
            let dst = (crate::mm::phys_to_virt(phys) as *mut u8).add(page_off);
            core::ptr::copy_nonoverlapping(src, dst, chunk);

            bytes_written += chunk;
            dst_off += chunk;
        }

        SyscallResult::ok(bytes_written as u64)
    }
}

/// MO_HAS_PAGE: Check whether a page resolves in this MO or any COW ancestor.
///
/// Args:
/// - page_index: page index within the MO
///
/// Returns 1 if `resolve_page(page_index)` succeeds, else 0.
fn syscall_mo_has_page(cap: &Capability, page_index: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MemoryObject, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        let mo = &*(cap.object as *const crate::cap::memory_object::MemoryObject);
        let index = page_index as usize;
        if index >= mo.page_count as usize {
            return SyscallResult::err(SyscallError::OutOfRange);
        }
        SyscallResult::ok(if mo.resolve_page(index).is_some() {
            1
        } else {
            0
        })
    }
}

/// VSPACE_MAP_MO: Map a range of MemoryObject pages into a VSpace.
///
/// Args:
/// - mo_cap_ptr: Capability pointer to the MemoryObject
/// - vaddr: Starting virtual address (page-aligned)
/// - mo_offset: Page offset within the MO
/// - count_and_flags: (count << 32) | flags  (flags: bit0=W, bit1=U, bit2=X)
/// VSPACE_FORK_RANGE: Fork pages from parent VSpace to child VSpace.
///
/// For each present page in the parent:
/// - Read actual PTE flags (preserves EXECUTABLE, USER, etc.)
/// - If writable: set COW + clear WRITABLE in parent PTE, TLB flush
/// - Copy the (now COW) PTE into the child VSpace
/// - Register page in child MO's radix tree
/// - Update child Maple tree and map_count
///
/// This is the MO-aware replacement for vspace_clone_cow_page.
fn syscall_vspace_fork_range(
    parent_cap: &Capability,
    child_vs_cap_ptr: u64,
    child_mo_cap_ptr: u64,
    va_start: u64,
    count_and_offset: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(parent_cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let child_vs_cap = match lookup_cap_locked(child_vs_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&child_vs_cap, ObjectType::VSpace, CapRights::MAP) {
        return SyscallResult::err(e);
    }

    let child_mo_cap = match lookup_cap_locked(child_mo_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&child_mo_cap, ObjectType::MemoryObject, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    let page_count = (count_and_offset >> 32) as usize;
    let mo_offset = (count_and_offset & 0xFFFF_FFFF) as usize;

    if va_start & 0xFFF != 0 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let parent_vs = &mut *(parent_cap.object as *mut VSpace);
        let child_vs = &mut *(child_vs_cap.object as *mut VSpace);
        let child_mo = child_mo_cap.object as *mut crate::cap::memory_object::MemoryObject;

        let forked = parent_vs.fork_range(child_vs, va_start, page_count);

        if forked > 0 {
            if !(*child_mo).reverse_maps.ensure_slot(child_mo) {
                return SyscallResult::err(SyscallError::OutOfMemory);
            }
        }

        if forked > 0 && !child_vs.tracking.is_null() {
            let t = &mut *child_vs.tracking;
            let mut tree_alloc = crate::mm::node_alloc::PmmNodeAllocator {
                owner: crate::mm::frame::FrameOwner::KernelPrivate {
                    subkind: crate::mm::frame::KernelMetaKind::MapleNode,
                },
                use_reserve: false,
            };

            let irq = save_irq_disable();
            parent_vs.lock.lock();
            let first_pte = parent_vs.read_entry(va_start, 1).unwrap_or(0);
            parent_vs.lock.unlock();
            restore_irq(irq);

            let ff = VSpace::entry_flags_to_page_flags(first_pte);
            let mut perms: u8 = 0;
            if ff.writable || ff.cow {
                perms |= 0x01;
            }
            if ff.user {
                perms |= 0x02;
            }
            if ff.executable {
                perms |= 0x04;
            }

            let vma = crate::mm::vspace::VmArea {
                mo: child_mo,
                mo_offset: mo_offset as u32,
                page_count: forked as u32,
                perms,
                _pad: [0; 7],
            };
            if !t.mappings.insert(va_start, vma, &mut tree_alloc) {
                return SyscallResult::err(SyscallError::OutOfMemory);
            }
            vma.retain_mo_ref();
        }

        if forked > 0 {
            if !(*child_mo)
                .reverse_maps
                .add(crate::cap::memory_object::ReverseMapEntry {
                    vspace: child_vs as *mut VSpace,
                    va_start,
                    page_count: forked as u32,
                    mo_offset: mo_offset as u32,
                    perms: 0,
                    _pad: [0; 7],
                })
            {
                return SyscallResult::err(SyscallError::OutOfMemory);
            }
        }

        SyscallResult::ok(forked as u64)
    }
}

fn syscall_vspace_map_mo(
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

    let mo_cap = match lookup_cap_locked(mo_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&mo_cap, ObjectType::MemoryObject, CapRights::READ) {
        return SyscallResult::err(e);
    }

    let count = (count_and_flags >> 32) as usize;
    let flags_bits = count_and_flags & 0xFFFF_FFFF;

    // W^X
    if (flags_bits & 1 != 0) && (flags_bits & 4 != 0) {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        // SAFETY: Both caps validated above. Use raw pointer for MO to
        // avoid aliasing UB (we need both read and write access).
        let mo_ptr = mo_cap.object as *mut crate::cap::memory_object::MemoryObject;
        let vspace = &mut *(cap.object as *mut VSpace);

        let flags = PageFlags {
            writable: flags_bits & 1 != 0,
            user: flags_bits & 2 != 0,
            executable: flags_bits & 4 != 0,
            cache_disable: flags_bits & 8 != 0,
            write_through: flags_bits & 16 != 0,
            cow: false,
        };

        let offset = mo_offset as usize;
        if count > 0 && offset + count > (*mo_ptr).page_count as usize {
            return SyscallResult::err(SyscallError::OutOfRange);
        }

        let is_cloned = (*mo_ptr).cow_parent != 0;
        let mut alloc = crate::mm::node_alloc::PmmNodeAllocator {
            owner: crate::mm::frame::FrameOwner::MoMeta {
                mo: mo_ptr,
                subkind: crate::mm::frame::MoMetaKind::Radix,
            },
            use_reserve: false,
        };

        let mut mapped = 0u64;
        for i in 0..count {
            let page_vaddr = vaddr + (i as u64 * crate::mm::PAGE_SIZE as u64);

            if let Some((mut phys, depth)) = (*mo_ptr).resolve_page_depth(offset + i) {
                let page_idx = offset + i;

                // Eager flatten: if resolved from a deep ancestor chain,
                // copy the page locally so subsequent accesses are O(1).
                if depth > crate::cap::memory_object::COW_FLATTEN_THRESHOLD {
                    let flatten_owner = crate::mm::frame::FrameOwner::MoData {
                        mo: mo_ptr,
                        page_idx: page_idx as u32,
                    };
                    if let Some(new_phys) = crate::mm::pmm_alloc(&flatten_owner) {
                        let src = crate::mm::phys_to_virt(phys) as *const u8;
                        let dst = crate::mm::phys_to_virt(new_phys) as *mut u8;
                        core::ptr::copy_nonoverlapping(src, dst, crate::mm::PAGE_SIZE);
                        (*mo_ptr).commit_page(page_idx, new_phys, &mut alloc);
                        phys = new_phys;
                    }
                }

                // COW mapping: if page is from parent chain and writable
                // requested, map as read-only + COW.
                let from_parent = depth > 0 && !(*mo_ptr).is_local_committed(page_idx);
                let effective = if is_cloned && flags.writable && from_parent {
                    PageFlags {
                        writable: false,
                        cow: true,
                        ..flags
                    }
                } else {
                    flags
                };

                match vspace.map(page_vaddr, phys, effective) {
                    Ok(()) => {
                        // Only tag PMM owner for locally committed pages
                        // (depth == 0). Shared COW pages (depth > 0) are
                        // owned by the ancestor MO — don't overwrite.
                        if depth == 0 {
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
                // Uncommitted page → demand PTE
                match vspace.map_demand(page_vaddr, flags) {
                    Ok(()) => mapped += 1,
                    Err(_) => break,
                }
            }
        }

        if mapped > 0 {
            if !(*mo_ptr).reverse_maps.ensure_slot(mo_ptr) {
                return SyscallResult::err(SyscallError::OutOfMemory);
            }

            // Register reverse map on MO
            if !(*mo_ptr)
                .reverse_maps
                .add(crate::cap::memory_object::ReverseMapEntry {
                    vspace: cap.object as *mut VSpace,
                    va_start: vaddr,
                    page_count: mapped as u32,
                    mo_offset: offset as u32,
                    perms: (flags_bits & 0xFF) as u8,
                    _pad: [0; 7],
                })
            {
                return SyscallResult::err(SyscallError::OutOfMemory);
            }

            // Insert VmArea into VSpace Maple tree
            if !vspace.tracking.is_null() {
                let t = &mut *vspace.tracking;
                let mut tree_alloc = crate::mm::node_alloc::PmmNodeAllocator {
                    owner: crate::mm::frame::FrameOwner::KernelPrivate {
                        subkind: crate::mm::frame::KernelMetaKind::MapleNode,
                    },
                    use_reserve: false,
                };
                let vma = crate::mm::vspace::VmArea {
                    mo: mo_cap.object as *mut crate::cap::memory_object::MemoryObject,
                    mo_offset: offset as u32,
                    page_count: mapped as u32,
                    perms: (flags_bits & 0xFF) as u8,
                    _pad: [0; 7],
                };
                if !t.mappings.insert(vaddr, vma, &mut tree_alloc) {
                    if !vspace.tracking.is_null() {
                        let t = &*vspace.tracking;
                        if let Some((_start, existing)) = t.mappings.lookup(vaddr) {
                            if !existing.mo.is_null() {
                                (*existing.mo)
                                    .reverse_maps
                                    .remove(cap.object as *mut VSpace, vaddr);
                            }
                        }
                    }
                    return SyscallResult::err(SyscallError::OutOfMemory);
                }
                vma.retain_mo_ref();
            }
        }

        SyscallResult::ok(mapped)
    }
}

/// Syscall handler wrapper called from assembly
///
/// # ABI Note
/// System V AMD64 calling convention:
/// - Arguments: RDI, RSI, RDX, RCX, R8, R9, then stack
/// - Returns struct { u64, u64 } in RAX:RDX
///
/// Assembly maps user registers → System V before calling:
///   RDI = syscall number (user RAX)
///   RSI = cap_ptr (user RDI)
///   RDX = arg0 (user RSI)
///   RCX = arg1 (user RDX / arg2 in user convention)
///   R8  = arg2 (user R10 / arg3 in user convention)
///   R9  = arg3 (user R8 / arg4 in user convention)
///   stack = arg4 (user R9 / arg5 in user convention)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall_handle_rust(
    syscall: u64, // RDI (user RAX)
    cap_ptr: u64, // RSI (user RDI)
    arg0: u64,    // RDX (user RSI)
    arg1: u64,    // RCX (user RDX)
    arg2: u64,    // R8  (user R10)
    arg3: u64,    // R9  (user R8)
    arg4: u64,    // stack (user R9)
) -> SyscallResult {
    handle(syscall, cap_ptr, arg0, arg1, arg2, arg3, arg4)
}
