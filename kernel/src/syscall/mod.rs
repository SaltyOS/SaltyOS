//! System Call Handler
//!
//! Capability invocation dispatch.
//!
//! SPDX-License-Identifier: GPL-2.0-only

pub mod fastpath;

use crate::cap::{CapError, CapRights, Capability, CNode, FrameObject, IoPortRange, ObjectType, UntypedMemory};
use crate::ipc::{Endpoint, Message, Notification};
use crate::mm::{phys_to_virt, save_irq_disable, restore_irq, SCHED_IPC_LOCK, CAP_LOCK};
use crate::mm::vspace::{CowNotifRing, CowPool, PageFlags, VSpace, VSpaceError};
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
                    return crate::cap::cnode::resolve_address_for_slot(cspace, cap_ptr, total_depth)
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
fn construct_message(
    msg_info: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
    mr3: u64,
) -> Message {
    let label = msg_info::get_label(msg_info);
    let length = msg_info::get_length(msg_info).min(20);
    let extra_caps = msg_info::get_extra_caps(msg_info).min(4);
    let mut regs = [0u64; 20];
    let mut caps = [0u64; 4];

    // Copy inline registers based on length (max 4 in registers)
    if length > 0 { regs[0] = mr0; }
    if length > 1 { regs[1] = mr1; }
    if length > 2 { regs[2] = mr2; }
    if length > 3 { regs[3] = mr3; }

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
                    let _guard = crate::arch::smap::UserAccessGuard::new();

                    if length > 4 {
                        let overflow = (length - 4).min(16);
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

    Message { label, length, extra_caps, regs, caps }
}

/// Write received IPC message to current thread's IPC buffer
///
/// Writes in `struct salty_msg` layout (matching userland overlay):
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
        if current.is_null() { return; }
        let buf = (*current).ipc_buffer;
        if buf == 0 { return; }

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
        let vspace = &*(*current).vspace_root;
        if vspace.resolve_page(buf).is_none() {
            (*current).ipc_buffer = 0;
            return;
        }

        let ipc_buf = buf as *mut crate::ipc::IpcBuffer;
        // SMAP: temporarily allow user memory access for IPC buffer write
        let _guard = crate::arch::smap::UserAccessGuard::new();

        // Write header: label and length
        (*ipc_buf).msg[0] = msg.label;
        (*ipc_buf).msg[1] = msg.length as u64;

        let reg_count = msg.length.min(20);

        // Write inline message registers (MR0-MR3) → msg[2..5]
        let inline_count = reg_count.min(4);
        for i in 0..inline_count {
            (*ipc_buf).msg[2 + i] = msg.regs[i];
        }

        // Write overflow message registers (MR4-MR19) → msg[6..21]
        if reg_count > 4 {
            let overflow_count = (reg_count - 4).min(16);
            for i in 0..overflow_count {
                (*ipc_buf).msg[6 + i] = msg.regs[4 + i];
            }
        }

        // Clear unused slots from end of message to end of regs area
        let first_clear = if reg_count <= 4 { 2 + reg_count } else { 6 + (reg_count - 4) };
        for i in first_clear.min(22)..22 {
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

        // Phase 2: IPC under SCHED_IPC_LOCK
        unsafe {
            let irq = save_irq_disable();
            SCHED_IPC_LOCK.lock();
            let endpoint = &mut *(cap.object as *mut Endpoint);
            endpoint.send(&msg, cap.badge);
            SCHED_IPC_LOCK.unlock();
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

            // Phase 2: Wake caller under SCHED_IPC_LOCK
            let irq = save_irq_disable();
            SCHED_IPC_LOCK.lock();

            let blocked_for_reply = matches!(
                (*caller).blocked_reason,
                Some(BlockedReason::ReplyWait { .. }) | Some(BlockedReason::FaultBlocked { .. })
            );
            if !blocked_for_reply || (*caller).state != ThreadState::Blocked {
                SCHED_IPC_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidOperation);
            }

            (*caller).saved_caller_msg = reply_msg;
            (*caller).saved_caller_badge = 0;
            (*caller).blocked_reason = None;
            (*caller).blocked_endpoint = core::ptr::null_mut();

            crate::sched::scheduler::scheduler().enqueue(caller);

            SCHED_IPC_LOCK.unlock();
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

    // Phase 2: IPC under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let endpoint = &mut *(cap.object as *mut Endpoint);
        let (msg, badge) = endpoint.recv();
        write_msg_to_ipc_buffer(&msg, badge);
        SCHED_IPC_LOCK.unlock();
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

    // Phase 2: IPC under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let endpoint = &mut *(cap.object as *mut Endpoint);
        let reply_msg = endpoint.call(&msg, cap.badge);
        write_msg_to_ipc_buffer(&reply_msg, 0);
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
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

    // Phase 2: IPC under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let endpoint = &mut *(cap.object as *mut Endpoint);
        let (msg, badge) = endpoint.reply_recv(&reply);
        write_msg_to_ipc_buffer(&msg, badge);
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
        SyscallResult::ok(badge)
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

    // Phase 2: IPC under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let endpoint = &mut *(cap.object as *mut Endpoint);
        let result = if endpoint.nbsend(&msg, cap.badge) {
            SyscallResult::ok(0)
        } else {
            SyscallResult::err(SyscallError::WouldBlock)
        };
        SCHED_IPC_LOCK.unlock();
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

    // Phase 2: Signal under SCHED_IPC_LOCK (may wake threads)
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let notification = &mut *(cap.object as *mut Notification);
        notification.signal(cap.badge | bits);
        SCHED_IPC_LOCK.unlock();
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

    // Phase 2: Wait under SCHED_IPC_LOCK (may block/context-switch)
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let notification = &mut *(cap.object as *mut Notification);
        let bits = notification.wait();
        SCHED_IPC_LOCK.unlock();
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

    // Phase 2: Poll is atomic swap — no SCHED_IPC_LOCK needed
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
        SCHED_IPC_LOCK.lock();
        let current_tcb = crate::sched::scheduler::scheduler().current();
        if current_tcb.is_null() {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
        (*current_tcb).invoke_depth0 = depth0 as u8;
        (*current_tcb).invoke_depth1 = depth1 as u8;
        SCHED_IPC_LOCK.unlock();
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
    crate::kdebug!({
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
                } else { (0, 0) };
                let dest_cnode_cap = match lookup_capability(arg1) {
                    Ok(c) => c,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                if let Err(e) = validate_capability(dest_cnode_cap, ObjectType::CNode, CapRights::WRITE) {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(e);
                }
                let rights = CapRights::from_bits(arg3 as u32);
                let src_root = &*(cap.object as *const CNode);
                let dest_root = &*(dest_cnode_cap.object as *const CNode);
                let (src_leaf, src_idx) = match resolve_invoke_slot(src_root, arg0, src_depth) {
                    Ok(v) => v,
                    Err(e) => { CAP_LOCK.unlock(); restore_irq(irq); return SyscallResult::err(e); }
                };
                let (dest_leaf, dest_idx) = match resolve_invoke_slot(dest_root, arg2, dest_depth) {
                    Ok(v) => v,
                    Err(e) => { CAP_LOCK.unlock(); restore_irq(irq); return SyscallResult::err(e); }
                };
                let result = match (&mut *dest_leaf).copy_slot(dest_idx, &*src_leaf, src_idx, rights) {
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
                } else { (0, 0) };
                let dest_cnode_cap = match lookup_capability(arg1) {
                    Ok(c) => c,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                if let Err(e) = validate_capability(dest_cnode_cap, ObjectType::CNode, CapRights::WRITE) {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(e);
                }
                let rights = CapRights::from_bits(0xFFFFFFFF & !(1 << 3));
                let src_root = &*(cap.object as *const CNode);
                let dest_root = &*(dest_cnode_cap.object as *const CNode);
                let (src_leaf, src_idx) = match resolve_invoke_slot(src_root, arg0, src_depth) {
                    Ok(v) => v,
                    Err(e) => { CAP_LOCK.unlock(); restore_irq(irq); return SyscallResult::err(e); }
                };
                let (dest_leaf, dest_idx) = match resolve_invoke_slot(dest_root, arg2, dest_depth) {
                    Ok(v) => v,
                    Err(e) => { CAP_LOCK.unlock(); restore_irq(irq); return SyscallResult::err(e); }
                };
                let result = match (&mut *dest_leaf).mint_slot(dest_idx, &*src_leaf, src_idx, arg3, rights) {
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
                } else { (0, 0) };
                let src_cnode_cap = match lookup_capability(arg1) {
                    Ok(c) => c,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                if let Err(e) = validate_capability(src_cnode_cap, ObjectType::CNode, CapRights::WRITE) {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(e);
                }
                let dest_root = &*(cap.object as *const CNode);
                let src_root = &*(src_cnode_cap.object as *const CNode);
                let (dest_leaf, dest_idx) = match resolve_invoke_slot(dest_root, arg0, dest_depth) {
                    Ok(v) => v,
                    Err(e) => { CAP_LOCK.unlock(); restore_irq(irq); return SyscallResult::err(e); }
                };
                let (src_leaf, src_idx) = match resolve_invoke_slot(src_root, arg2, src_depth) {
                    Ok(v) => v,
                    Err(e) => { CAP_LOCK.unlock(); restore_irq(irq); return SyscallResult::err(e); }
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
                } else { (0, 0) };
                let src_cnode_cap = match lookup_capability(arg1) {
                    Ok(c) => c,
                    Err(e) => {
                        CAP_LOCK.unlock();
                        restore_irq(irq);
                        return SyscallResult::err(e);
                    }
                };
                if let Err(e) = validate_capability(src_cnode_cap, ObjectType::CNode, CapRights::WRITE) {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(e);
                }
                let dest_root = &*(cap.object as *const CNode);
                let src_root = &*(src_cnode_cap.object as *const CNode);
                let (dest_leaf, dest_idx) = match resolve_invoke_slot(dest_root, arg0, dest_depth) {
                    Ok(v) => v,
                    Err(e) => { CAP_LOCK.unlock(); restore_irq(irq); return SyscallResult::err(e); }
                };
                let (src_leaf, src_idx) = match resolve_invoke_slot(src_root, arg2, src_depth) {
                    Ok(v) => v,
                    Err(e) => { CAP_LOCK.unlock(); restore_irq(irq); return SyscallResult::err(e); }
                };
                let result = match (&mut *dest_leaf).mutate_slot(dest_idx, &mut *src_leaf, src_idx, arg3) {
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
                } else { (0, 0) };
                let cnode_root = &*(cap.object as *const CNode);
                let (leaf, idx) = match resolve_invoke_slot(cnode_root, arg0, depth) {
                    Ok(v) => v,
                    Err(e) => { CAP_LOCK.unlock(); restore_irq(irq); return SyscallResult::err(e); }
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
                } else { (0, 0) };
                let cnode_root = &*(cap.object as *const CNode);
                let (leaf, idx) = match resolve_invoke_slot(cnode_root, arg0, depth) {
                    Ok(v) => v,
                    Err(e) => { CAP_LOCK.unlock(); restore_irq(irq); return SyscallResult::err(e); }
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
                    Err(e) => { CAP_LOCK.unlock(); restore_irq(irq); return SyscallResult::err(e); }
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
                    if buf != 0 {
                        let ipc_buf = buf as *mut crate::ipc::IpcBuffer;
                        (*ipc_buf).msg[0] = guard;
                        (*ipc_buf).msg[1] = guard_bits;
                        (*ipc_buf).msg[2] = size_bits;
                        (*ipc_buf).msg[3] = num_slots;
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

    // Operation under SCHED_IPC_LOCK (SC state mutation)
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let sc = &mut *(cap.object as *mut SchedContext);
        sc.budget = budget_ticks;
        sc.period = period_ticks;
        sc.remaining = budget_ticks;

        if period_ticks > 0 {
            let now = crate::arch::get_ticks() as u64;
            sc.deadline = now + period_ticks;
        } else {
            sc.deadline = u64::MAX;
        }
        SCHED_IPC_LOCK.unlock();
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

    // Operation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let sc = &mut *(cap.object as *mut SchedContext);
        let tcb = &mut *(tcb_cap.object as *mut Tcb);

        if !sc.bound_tcb.is_null() {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        if !tcb.sched_context.is_null() {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        sc.bound_tcb = tcb as *mut Tcb;
        tcb.sched_context = sc as *mut SchedContext;
        tcb.base_priority = sc.deadline;
        tcb.priority = sc.deadline;

        if tcb.state == ThreadState::Ready {
            let scheduler = crate::sched::scheduler::scheduler();
            scheduler.remove_from_ready_queue(tcb as *mut Tcb);
            scheduler.enqueue(tcb as *mut Tcb);
        }
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// SC_UNBIND: Unbind a scheduling context from its TCB
fn syscall_sc_unbind(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Operation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let sc = &mut *(cap.object as *mut SchedContext);

        if sc.bound_tcb.is_null() {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let tcb = &mut *sc.bound_tcb;

        if tcb.state == ThreadState::Running || tcb.state == ThreadState::Ready {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        tcb.sched_context = core::ptr::null_mut();
        sc.bound_tcb = core::ptr::null_mut();
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
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

    // Operation under SCHED_IPC_LOCK (scheduler manipulation + context switch)
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let current_sc = &mut *(cap.object as *mut SchedContext);
        let target_sc = &mut *(target_cap.object as *mut SchedContext);

        target_sc.remaining += current_sc.remaining;
        current_sc.remaining = 0;

        let scheduler = crate::sched::scheduler::scheduler();
        // Use deferred enqueue to avoid SMP double-schedule race:
        // do not place the running TCB into ready queue before its context
        // has been saved by context_switch.
        scheduler.yield_current();
        SCHED_IPC_LOCK.unlock();
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

    // alloc_frame has its own MM_LOCK — do BEFORE acquiring SCHED_IPC_LOCK
    let kstack_phys = match crate::mm::alloc_frame() {
        Some(f) => f,
        None => return SyscallResult::err(SyscallError::OutOfMemory),
    };

    // TCB mutation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &mut *(cap.object as *mut Tcb);

        // Only allow configuring threads that are Inactive.
        // Configuring a Running/Ready/Blocked thread would corrupt its context.
        if tcb.state != ThreadState::Inactive {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::Busy);
        }

        let kstack_virt = crate::mm::phys_to_virt(kstack_phys);
        let kstack_top = kstack_virt + crate::mm::PAGE_SIZE as u64;
        core::ptr::write_bytes(kstack_virt as *mut u8, 0, crate::mm::PAGE_SIZE);
        tcb.kernel_stack_top = kstack_top;
        tcb.stack_canary = crate::arch::generate_stack_canary();

        if !tcb.vspace_root.is_null() {
            let vspace = &*tcb.vspace_root;
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);

            // Allocate trampoline stack outside lock
            let tramp_stack_phys = match crate::mm::alloc_frame() {
                Some(f) => f,
                None => return SyscallResult::err(SyscallError::OutOfMemory),
            };

            let irq = save_irq_disable();
            SCHED_IPC_LOCK.lock();
            let tramp_stack_virt = crate::mm::phys_to_virt(tramp_stack_phys);
            let tramp_stack_top = tramp_stack_virt + crate::mm::PAGE_SIZE as u64;
            core::ptr::write_bytes(tramp_stack_virt as *mut u8, 0, crate::mm::PAGE_SIZE);

            tcb.context.rip = crate::arch::usermode_trampoline as *const () as u64;
            tcb.context.rsp = tramp_stack_top;
            tcb.context.r12 = entry_rip;
            tcb.context.r13 = entry_rsp;
            tcb.context.r14 = vspace.root();
            tcb.context.r15 = 0x0202;
            tcb.context.rflags = 0x202;
            tcb.ipc_buffer = ipc_buffer;
            tcb.user_stack_top = entry_rsp;
            tcb.user_stack_min = entry_rsp.saturating_sub(USER_STACK_GROW_LIMIT);
            // Reset FPU state for fresh execution (exec replaces the process image)
            tcb.fpu_initialized = false;
            tcb.fpu_state = crate::sched::thread::XSaveArea::zeroed();
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
        } else {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }
    }

    SyscallResult::ok(0)
}

/// TCB_RESUME: Make a thread runnable
fn syscall_tcb_resume(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::RESUME) {
        return SyscallResult::err(e);
    }

    // Operation under SCHED_IPC_LOCK (TCB state transitions + scheduler)
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &mut *(cap.object as *mut Tcb);
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
                scheduler.with_lock(|sched| {
                    if matches!(tcb.blocked_reason, Some(BlockedReason::TimerBlocked)) {
                        crate::sched::sleep_queue::remove(tcb as *mut Tcb);
                        tcb.timer_wakeup_ns = 0;
                    }
                    if !tcb.blocked_endpoint.is_null() {
                        let ep = &mut *(tcb.blocked_endpoint as *mut crate::ipc::Endpoint);
                        ep.remove_from_queue(tcb as *mut Tcb);
                        tcb.blocked_endpoint = core::ptr::null_mut();
                    }
                    if !tcb.blocked_notification.is_null() {
                        let ntfn = &mut *(tcb.blocked_notification as *mut crate::ipc::Notification);
                        ntfn.remove_waiter(tcb as *mut Tcb);
                        tcb.blocked_notification = core::ptr::null_mut();
                    }
                    if matches!(tcb.blocked_reason, Some(BlockedReason::FutexBlocked)) {
                        crate::ipc::futex::futex_remove_thread(tcb as *mut Tcb);
                    }
                    if matches!(tcb.blocked_reason, Some(BlockedReason::FutexTimedBlocked)) {
                        crate::ipc::futex::futex_remove_thread(tcb as *mut Tcb);
                        crate::sched::sleep_queue::remove(tcb as *mut Tcb);
                        tcb.timer_wakeup_ns = 0;
                        tcb.futex_wakeup_result = 0;
                    }
                    tcb.blocked_reason = None;
                    sched.enqueue_unlocked(tcb as *mut Tcb);
                });
            }
            ThreadState::Waiting => {
                if !tcb.blocked_notification.is_null() {
                    let ntfn = &mut *(tcb.blocked_notification as *mut crate::ipc::Notification);
                    ntfn.remove_waiter(tcb as *mut Tcb);
                    tcb.blocked_notification = core::ptr::null_mut();
                }
                let scheduler = crate::sched::scheduler::scheduler();
                scheduler.enqueue(tcb as *mut Tcb);
            }
        }
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// TCB_SUSPEND: Stop a thread
fn syscall_tcb_suspend(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::SUSPEND) {
        return SyscallResult::err(e);
    }

    // Operation under SCHED_IPC_LOCK (TCB state transitions + scheduler)
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &mut *(cap.object as *mut Tcb);
        let scheduler = crate::sched::scheduler::scheduler();

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
                        // Self-suspend or same-CPU: reschedule locally
                        scheduler.reschedule();
                    }
                    Some(cpu) => {
                        // Cross-CPU: synchronous suspend. Release SCHED_IPC_LOCK
                        // before spinning — the IPI handler on the target CPU
                        // acquires it (irq_stub_sched_ipc → handle_reschedule_ipi).
                        let target_tcb_ptr = tcb as *mut Tcb as usize;
                        SCHED_IPC_LOCK.unlock();
                        restore_irq(irq);
                        // SAFETY: cpu is a valid CPU index from current[] scan
                        crate::arch::send_ipi(cpu, crate::arch::IpiKind::Reschedule);
                        // Spin until target CPU has context-switched away.
                        // Bounded: IPI + handler is single-digit microseconds.
                        // No ABA: TCB pointers are never freed/reused in this kernel.
                        let mut spins: u32 = 0;
                        while crate::sched::scheduler::current_on_cpu(cpu) == target_tcb_ptr {
                            core::hint::spin_loop();
                            spins += 1;
                            if spins >= SUSPEND_SPIN_LIMIT {
                                return SyscallResult::err(SyscallError::Busy);
                            }
                        }
                        return SyscallResult::ok(0);
                    }
                    None => {
                        // Thread already descheduled (raced with yield/block)
                    }
                }
            }
            ThreadState::Ready => {
                scheduler.remove_from_ready_queue(tcb as *mut Tcb);
                tcb.state = ThreadState::Inactive;
            }
            ThreadState::Blocked => {
                scheduler.with_lock(|_sched| {
                    if matches!(tcb.blocked_reason, Some(BlockedReason::TimerBlocked)) {
                        crate::sched::sleep_queue::remove(tcb as *mut Tcb);
                        tcb.timer_wakeup_ns = 0;
                    }
                    if !tcb.blocked_endpoint.is_null() {
                        let ep = &mut *(tcb.blocked_endpoint as *mut crate::ipc::Endpoint);
                        ep.remove_from_queue(tcb as *mut Tcb);
                        tcb.blocked_endpoint = core::ptr::null_mut();
                    }
                    if !tcb.blocked_notification.is_null() {
                        let ntfn = &mut *(tcb.blocked_notification as *mut crate::ipc::Notification);
                        ntfn.remove_waiter(tcb as *mut Tcb);
                        tcb.blocked_notification = core::ptr::null_mut();
                    }
                    if matches!(tcb.blocked_reason, Some(BlockedReason::FutexBlocked)) {
                        crate::ipc::futex::futex_remove_thread(tcb as *mut Tcb);
                    }
                    if matches!(tcb.blocked_reason, Some(BlockedReason::FutexTimedBlocked)) {
                        crate::ipc::futex::futex_remove_thread(tcb as *mut Tcb);
                        crate::sched::sleep_queue::remove(tcb as *mut Tcb);
                        tcb.timer_wakeup_ns = 0;
                        tcb.futex_wakeup_result = 0;
                    }
                    tcb.state = ThreadState::Inactive;
                    tcb.blocked_reason = None;
                    tcb.reply_tcb = core::ptr::null_mut();
                    tcb.reply_can_grant = false;
                    tcb.saved_caller_msg = crate::ipc::Message::empty();
                    tcb.saved_caller_badge = 0;
                });
            }
            ThreadState::Waiting => {
                if !tcb.blocked_notification.is_null() {
                    let ntfn = &mut *(tcb.blocked_notification as *mut crate::ipc::Notification);
                    ntfn.remove_waiter(tcb as *mut Tcb);
                    tcb.blocked_notification = core::ptr::null_mut();
                }
                tcb.state = ThreadState::Inactive;
            }
            ThreadState::Inactive => {}
        }
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
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

    // TCB mutation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.cspace_root = cspace_cap.object as *mut CNode;
        tcb.vspace_root = vspace_cap.object as *mut VSpace;
        tcb.cspace_depth = cspace_depth as u8;
        SCHED_IPC_LOCK.unlock();
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

    // TCB mutation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.cpu_affinity = affinity;

        // If thread is in ready queue, re-enqueue with new affinity
        if tcb.state == ThreadState::Ready {
            let scheduler = crate::sched::scheduler::scheduler();
            scheduler.remove_from_ready_queue(tcb as *mut Tcb);
            scheduler.enqueue(tcb as *mut Tcb);
        }
        SCHED_IPC_LOCK.unlock();
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

    // TCB read under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &*(cap.object as *const Tcb);
        let result = if tcb.state != ThreadState::Inactive {
            SyscallResult::err(SyscallError::Busy)
        } else {
            SyscallResult::ok(tcb.context.rip)
        };
        SCHED_IPC_LOCK.unlock();
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
fn syscall_tcb_write_registers(
    cap: &Capability,
    flags: u64,
    rip: u64,
    rsp: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // TCB mutation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &mut *(cap.object as *mut Tcb);
        // The saved `context` for Ready/Blocked/Waiting threads is often a
        // kernel continuation (e.g. switch_common resume point), not user RIP/RSP.
        // Allowing writes in those states can corrupt kernel return paths.
        if tcb.state != ThreadState::Inactive {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::Busy);
        }

        tcb.context.rip = rip;
        tcb.context.rsp = rsp;

        if flags & 1 != 0 && tcb.state == ThreadState::Inactive {
            let scheduler = crate::sched::scheduler::scheduler();
            scheduler.enqueue(tcb as *mut Tcb);
        }
        SCHED_IPC_LOCK.unlock();
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

    // TCB mutation + scheduler under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.base_priority = priority;
        tcb.priority = priority;

        if tcb.state == ThreadState::Ready {
            let scheduler = crate::sched::scheduler::scheduler();
            scheduler.remove_from_ready_queue(tcb as *mut Tcb);
            scheduler.enqueue(tcb as *mut Tcb);
        }
        SCHED_IPC_LOCK.unlock();
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

    // TCB mutation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.ipc_buffer = addr;
        SCHED_IPC_LOCK.unlock();
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

    // TCB + notification mutation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &mut *(cap.object as *mut Tcb);
        if !tcb.bound_notification.is_null() {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::Busy);
        }

        let ntfn = &mut *(ntfn_cap.object as *mut crate::ipc::Notification);
        if !ntfn.bound_tcb.is_null() {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::Busy);
        }

        tcb.bound_notification = ntfn_cap.object as *mut u8;
        ntfn.bound_tcb = tcb as *mut Tcb;
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// TCB_UNBIND_NOTIFICATION: Unbind notification from this thread
fn syscall_tcb_unbind_notification(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // TCB + notification mutation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &mut *(cap.object as *mut Tcb);
        if tcb.bound_notification.is_null() {
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            return SyscallResult::err(SyscallError::InvalidOperation);
        }

        let ntfn = &mut *(tcb.bound_notification as *mut crate::ipc::Notification);
        ntfn.bound_tcb = core::ptr::null_mut();
        tcb.bound_notification = core::ptr::null_mut();
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
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
fn syscall_tcb_set_fault_handler(
    cap: &Capability,
    fault_ep_cap_ptr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }

    // Sub-lookup under CAP_LOCK
    let ep_cap = match lookup_cap_locked(fault_ep_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&ep_cap, ObjectType::Endpoint, CapRights::SEND) {
        return SyscallResult::err(e);
    }

    // TCB mutation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let tcb = &mut *(cap.object as *mut Tcb);
        tcb.fault_handler = ep_cap.object as *mut u8;
        tcb.fault_handler_badge = ep_cap.badge;
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// TCB_COPY_FPU: Copy FPU/SSE state from source TCB to destination TCB
///
/// Used by procmgr during fork to preserve the parent's FPU state in the child.
/// Args:
/// - dest_cap: destination (child) TCB capability
/// - src_cap_ptr: slot index of source (parent) TCB capability
fn syscall_tcb_copy_fpu(
    dest_cap: &Capability,
    src_cap_ptr: u64,
) -> SyscallResult {
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
                832,
            );
        }
        (*dest_tcb).fpu_initialized = (*src_tcb).fpu_initialized;
    }

    SyscallResult::ok(0)
}

/// TCB_SET_TLS_BASE: Set the FS_BASE (TLS pointer) for a thread.
/// If the target is the current thread, also writes IA32_FS_BASE immediately.
fn syscall_tcb_set_tls_base(
    cap: &Capability,
    tls_base: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::Tcb, CapRights::WRITE) {
        return SyscallResult::err(e);
    }

    // Canonical user address check: 0 (clear) or positive-half canonical
    if tls_base != 0 && tls_base >= 0x0000_8000_0000_0000 {
        return SyscallResult::err(SyscallError::InvalidArgument);
    }

    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();

        let tcb = cap.object as *mut Tcb;
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
                SCHED_IPC_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::InvalidOperation);
            }
            // Target is Inactive/Ready/Blocked — safe to write field
            (*tcb).tls_base = tls_base;
        }

        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// SC_CONSUMED: Query consumed time from scheduling context
fn syscall_sc_consumed(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::SchedContext, CapRights::READ) {
        return SyscallResult::err(e);
    }

    // SC read under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let sc = &*(cap.object as *const SchedContext);
        let result = SyscallResult::ok(sc.consumed);
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
        result
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
    crate::kdebug!({
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

        // Resolve untyped cap_ref (may be in expanded slot)
        let cap_ref = if depth == 0 {
            // Try flat first, then expanded fallback
            match cspace.get_ref(cap_ptr as usize) {
                Some(r) => r,
                None => {
                    // Try expanded resolution for untyped caps in sub-CNodes
                    match lookup_expanded_slot(cspace, cap_ptr) {
                        Ok(r) => r,
                        Err(_) => {
                            CAP_LOCK.unlock();
                            restore_irq(irq);
                            return SyscallResult::err(SyscallError::InvalidCapability);
                        }
                    }
                }
            }
        } else {
            match crate::cap::cnode::resolve_address_slot(cspace, cap_ptr, depth) {
                Ok(r) => r,
                Err(_) => {
                    CAP_LOCK.unlock();
                    restore_irq(irq);
                    return SyscallResult::err(SyscallError::InvalidCapability);
                }
            }
        };
        let untyped_slot = cap_ref.slot;

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

/// VSPACE_UNMAP: Unmap a page from a virtual address space
///
/// Args:
/// - virt_addr: Virtual address to unmap
fn syscall_vspace_unmap(cap: &Capability, virt_addr: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::UNMAP) {
        return SyscallResult::err(e);
    }

    unsafe {
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
        (*pool).tail.store(current_tail.wrapping_add(count as u16), Ordering::Release);

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

    // Allocate + register under a single SCHED_IPC_LOCK hold to prevent SMP races.
    // Shared IRQs are allowed: multiple handlers can coexist on the same IRQ line.
    let handler_ptr = unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();

        // Allocate from pool while still under lock
        let ptr = match crate::init::alloc_dynamic_irq_handler(irq_num as u32) {
            Some(p) => p,
            None => {
                SCHED_IPC_LOCK.unlock();
                restore_irq(irq);
                return SyscallResult::err(SyscallError::OutOfMemory);
            }
        };

        // Prepend to handler chain (shared IRQs: multiple handlers per IRQ)
        crate::ipc::irq::register_handler(irq_num as usize, ptr);

        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
        ptr
    };

    // Dynamically unmask the IOAPIC redirection entry for this IRQ
    crate::arch::ioapic_unmask(irq_num as u32);

    // Allocate a cap slot and set it up
    let slot = match crate::cap::alloc_slot() {
        Some(s) => s,
        None => {
            // Rollback: unregister handler
            unsafe {
                let irq = save_irq_disable();
                SCHED_IPC_LOCK.lock();
                crate::ipc::irq::unregister_handler(handler_ptr);
                // Only mask IOAPIC if no other handler remains on this IRQ
                let should_mask = !crate::ipc::irq::has_handlers(irq_num as usize);
                SCHED_IPC_LOCK.unlock();
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
            SCHED_IPC_LOCK.lock();
            crate::ipc::irq::unregister_handler(handler_ptr);
            let should_mask = !crate::ipc::irq::has_handlers(irq_num as usize);
            SCHED_IPC_LOCK.unlock();
            restore_irq(irq);
            if should_mask {
                crate::arch::ioapic_mask(irq_num as u32);
            }
            let syscall_err = match e {
                CapError::InvalidSlot => SyscallError::OutOfRange,
                _ => SyscallError::AlreadyExists,
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

    // IRQ handler mutation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let irq_handler = &mut *(cap.object as *mut crate::ipc::IrqHandler);
        irq_handler.acknowledged = true;
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
    }

    SyscallResult::ok(0)
}

/// IRQ_HANDLER_SET_NOTIFICATION: Bind a notification to an IRQ handler
///
/// Args:
/// - ntfn_cap_ptr: Capability pointer to a Notification
fn syscall_irq_handler_set_notification(
    cap: &Capability,
    ntfn_cap_ptr: u64,
) -> SyscallResult {
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

    // IRQ handler mutation under SCHED_IPC_LOCK
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let irq_handler = &mut *(cap.object as *mut crate::ipc::IrqHandler);
        irq_handler.notification = ntfn_cap.object as *mut Notification;
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
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

    // IRQ handler mutation under SCHED_IPC_LOCK
    let irq_num;
    let should_mask;
    unsafe {
        let irq = save_irq_disable();
        SCHED_IPC_LOCK.lock();
        let irq_handler = &mut *(cap.object as *mut crate::ipc::IrqHandler);
        irq_num = irq_handler.irq_num;
        irq_handler.notification = core::ptr::null_mut();
        // Only mask if no other handler on this IRQ has a notification
        should_mask = !crate::ipc::irq::has_active_notification(irq_num as usize);
        SCHED_IPC_LOCK.unlock();
        restore_irq(irq);
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
                _ => SyscallError::AlreadyExists,
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
                _ => SyscallError::AlreadyExists,
            };
            return SyscallResult::err(syscall_err);
        }
    }

    SyscallResult::ok(0)
}

/// IOPORT_IN8: Read a byte from an I/O port
///
/// Args:
/// - offset: Port offset within the IoPort range
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

/// IOPORT_OUT8: Write a byte to an I/O port
///
/// Args:
/// - offset: Port offset within the IoPort range
/// - value: Byte value to write
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

/// IOPORT_IN16: Read a 16-bit word from an I/O port
///
/// Args:
/// - offset: Port offset within the IoPort range
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

/// IOPORT_OUT16: Write a 16-bit word to an I/O port
///
/// Args:
/// - offset: Port offset within the IoPort range
/// - value: 16-bit value to write
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

/// IOPORT_IN32: Read a 32-bit dword from an I/O port
///
/// Args:
/// - offset: Port offset within the IoPort range
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

/// IOPORT_OUT32: Write a 32-bit dword to an I/O port
///
/// Args:
/// - offset: Port offset within the IoPort range
/// - value: 32-bit value to write
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
fn syscall_vspace_walk(
    cap: &Capability,
    start_vaddr: u64,
    max_entries: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::VSpace, CapRights::READ) {
        return SyscallResult::err(e);
    }

    unsafe {
        const EXT_ENTRY_BASE_WORD: usize = 30;
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
        let ipc_buf = buf as *mut crate::ipc::IpcBuffer;
        let ipc_words = ipc_buf as *mut u64;

        (*ipc_buf).msg[0] = count as u64;
        (*ipc_buf).msg[1] = next_vaddr;
        // Mark that extended tuple area is valid for this reply.
        *ipc_words.add(ipc_words_total - 1) = WALK_MAGIC;
        for i in 0..count {
            let out = EXT_ENTRY_BASE_WORD + i * 3;
            *ipc_words.add(out) = entries[i].0;         // vaddr
            *ipc_words.add(out + 1) = entries[i].1;     // phys
            *ipc_words.add(out + 2) = entries[i].2;     // flags
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
        VSpaceError::AlreadyMapped => SyscallError::AlreadyExists,
        VSpaceError::NotMapped => SyscallError::NotFound,
        VSpaceError::OutOfMemory => SyscallError::OutOfMemory,
        VSpaceError::NotCow => SyscallError::InvalidOperation,
    }
}

/// Convert CNode error to syscall error
fn syscall_error_from_cap_error(err: CapError) -> SyscallError {
    match err {
        CapError::InvalidSlot | CapError::InvalidArgument => SyscallError::InvalidArgument,
        CapError::SlotEmpty => SyscallError::NotFound,
        CapError::InsufficientRights => SyscallError::InsufficientRights,
        CapError::InsufficientMemory | CapError::OutOfSlots => SyscallError::OutOfMemory,
        CapError::SlotOccupied => SyscallError::AlreadyExists,
        CapError::HasChildren => SyscallError::InvalidOperation,
        _ => SyscallError::InvalidOperation,
    }
}

/// ClockGetTime: Return current monotonic time in nanoseconds
fn syscall_clock_gettime(clock_id: u64) -> SyscallResult {
    // Only CLOCK_REALTIME(0) and CLOCK_MONOTONIC(1) are supported
    if clock_id > 1 {
        return SyscallResult::err(SyscallError::InvalidArgument);
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
    let duration_ns = seconds.saturating_mul(1_000_000_000).saturating_add(nanoseconds);
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
            // Yield under SCHED_IPC_LOCK using deferred enqueue.
            // The current thread is NOT placed in the ready queue until
            // context_switch has saved its registers (prevents SMP race).
            unsafe {
                let irq = save_irq_disable();
                SCHED_IPC_LOCK.lock();
                crate::sched::scheduler::scheduler().yield_current();
                SCHED_IPC_LOCK.unlock();
                restore_irq(irq);
            }
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
            let data = unsafe {
                core::slice::from_raw_parts(regs.as_ptr() as *const u8, 40)
            };
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
                let _guard = crate::arch::smap::UserAccessGuard::new();
                for i in 0..len {
                    // SAFETY: pointer validated above to be in user space range;
                    // user pages are accessible via the active VSpace page tables
                    kbuf[i] = unsafe { core::ptr::read_volatile(user_ptr.add(i)) };
                }
            }
            // SAFETY: save/restore IRQ flags around spinlock
            let irq = unsafe { save_irq_disable() };
            crate::SERIAL_LOCK.lock();
            crate::serial_write_hw(&kbuf[..len]);
            crate::SERIAL_LOCK.unlock();
            unsafe { restore_irq(irq) };
            SyscallResult::ok(0)
        }
        Syscall::ClockGetTime => syscall_clock_gettime(cap_ptr),
        Syscall::NanoSleep => {
            // NanoSleep under SCHED_IPC_LOCK (block_current_sleeping may context-switch)
            unsafe {
                let irq = save_irq_disable();
                SCHED_IPC_LOCK.lock();
                let result = syscall_nanosleep(cap_ptr, msg_info);
                SCHED_IPC_LOCK.unlock();
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
        Syscall::DebugDumpState => {
            // Read scheduler state under SCHED_IPC_LOCK
            unsafe {
                let irq = save_irq_disable();
                SCHED_IPC_LOCK.lock();
                let scheduler = crate::sched::scheduler::scheduler();
                let current = scheduler.current();
                if !current.is_null() {
                    let tcb = &*current;
                    let s = crate::SerialGuard::acquire();
                    s.puts("[DEBUG] TCB state dump:\n");
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
                SCHED_IPC_LOCK.unlock();
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
            // cap_ptr = cap slot, msg_info = message info, mr0 = MR0, mr1 = timeout_ns
            // Returns 0 on success, Cancelled (12) on timeout
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

            let msg = construct_message(msg_info, mr0, 0, 0, 0);
            let timeout_ns = mr1;

            unsafe {
                let irq = save_irq_disable();
                SCHED_IPC_LOCK.lock();
                let endpoint = &mut *(cap.object as *mut Endpoint);
                let result = endpoint.send_timeout(&msg, cap.badge, timeout_ns);
                SCHED_IPC_LOCK.unlock();
                restore_irq(irq);

                if result == 0 {
                    SyscallResult::ok(0)
                } else {
                    SyscallResult::err(SyscallError::Cancelled)
                }
            }
        }
        Syscall::RecvTimed => {
            // cap_ptr = cap slot, msg_info = timeout_ns
            // Returns badge in value, 0 in error on success, Cancelled (12) on timeout
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

            let timeout_ns = msg_info;

            unsafe {
                let irq = save_irq_disable();
                SCHED_IPC_LOCK.lock();
                let endpoint = &mut *(cap.object as *mut Endpoint);
                let (msg, badge, result) = endpoint.recv_timeout(timeout_ns);
                if result == 0 {
                    write_msg_to_ipc_buffer(&msg, badge);
                }
                SCHED_IPC_LOCK.unlock();
                restore_irq(irq);

                if result == 0 {
                    SyscallResult::ok(badge)
                } else {
                    SyscallResult::err(SyscallError::Cancelled)
                }
            }
        }
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
