// SPDX-License-Identifier: GPL-2.0-only
//! Current-root CSpace lookup and invoke-slot resolution helpers.

use super::{
    CAP_LOCK, CNode, CapRights, ObjectType, SyscallError, SyscallResult, cap, event,
    exec_authority, mo, pager, restore_irq, save_irq_disable, sc, system, tcb, validate_capability,
    vspace,
};
use crate::cap::{CapError, Capability};
use crate::sched::thread::Tcb;

/// Kernel-side u64 aliases for kernite UAPI invoke labels.
///
/// Pattern matches need named consts (Rust pattern syntax disallows
/// inline `as u64` casts), so the bindgen `KERNITE_INV_*: u32`
/// constants are widened here once and referenced by name in the
/// dispatch table below.
mod label {
    pub const CNODE_COPY: u64 = uapi::KERNITE_INV_CNODE_COPY as u64;
    pub const CNODE_MINT: u64 = uapi::KERNITE_INV_CNODE_MINT as u64;
    pub const CNODE_MOVE: u64 = uapi::KERNITE_INV_CNODE_MOVE as u64;
    pub const CNODE_MUTATE: u64 = uapi::KERNITE_INV_CNODE_MUTATE as u64;
    pub const CNODE_DELETE: u64 = uapi::KERNITE_INV_CNODE_DELETE as u64;
    pub const CNODE_REVOKE: u64 = uapi::KERNITE_INV_CNODE_REVOKE as u64;
    pub const CNODE_SET_GUARD: u64 = uapi::KERNITE_INV_CNODE_SET_GUARD as u64;
    pub const CNODE_GET_INFO: u64 = uapi::KERNITE_INV_CNODE_GET_INFO as u64;

    pub const UNTYPED_RETYPE: u64 = uapi::KERNITE_INV_UNTYPED_RETYPE as u64;
    pub const UNTYPED_RESET: u64 = uapi::KERNITE_INV_UNTYPED_RESET as u64;
    pub const UNTYPED_GET_STATS: u64 = uapi::KERNITE_INV_UNTYPED_GET_STATS as u64;

    pub const TCB_CONFIGURE: u64 = uapi::KERNITE_INV_TCB_CONFIGURE as u64;
    pub const TCB_START: u64 = uapi::KERNITE_INV_TCB_START as u64;
    pub const TCB_STOP: u64 = uapi::KERNITE_INV_TCB_STOP as u64;
    pub const TCB_KILL: u64 = uapi::KERNITE_INV_TCB_KILL as u64;
    pub const TCB_YIELD: u64 = uapi::KERNITE_INV_TCB_YIELD as u64;
    pub const TCB_GET_STATE: u64 = uapi::KERNITE_INV_TCB_GET_STATE as u64;
    pub const TCB_GET_ABI_VERSION: u64 = uapi::KERNITE_INV_TCB_GET_ABI_VERSION as u64;
    pub const TCB_SET_INVOKE_DEPTHS: u64 = uapi::KERNITE_INV_TCB_SET_INVOKE_DEPTHS as u64;
    pub const TCB_SET_SPACE: u64 = uapi::KERNITE_INV_TCB_SET_SPACE as u64;
    pub const TCB_SET_AFFINITY: u64 = uapi::KERNITE_INV_TCB_SET_AFFINITY as u64;
    pub const TCB_READ_REGISTERS: u64 = uapi::KERNITE_INV_TCB_READ_REGISTERS as u64;
    pub const TCB_WRITE_REGISTERS: u64 = uapi::KERNITE_INV_TCB_WRITE_REGISTERS as u64;
    pub const TCB_SET_PRIORITY: u64 = uapi::KERNITE_INV_TCB_SET_PRIORITY as u64;
    pub const TCB_SET_IPC_BUFFER: u64 = uapi::KERNITE_INV_TCB_SET_IPC_BUFFER as u64;
    pub const TCB_SET_FAULT_PIPE: u64 = uapi::KERNITE_INV_TCB_SET_FAULT_PIPE as u64;
    pub const TCB_COPY_FPU: u64 = uapi::KERNITE_INV_TCB_COPY_FPU as u64;
    pub const TCB_SET_TLS_BASE: u64 = uapi::KERNITE_INV_TCB_SET_TLS_BASE as u64;
    pub const TCB_SET_STACK_BOUNDS: u64 = uapi::KERNITE_INV_TCB_SET_STACK_BOUNDS as u64;
    pub const TCB_SET_SCHED_CLASS: u64 = uapi::KERNITE_INV_TCB_SET_SCHED_CLASS as u64;
    pub const TCB_GET_SPACE_INFO: u64 = uapi::KERNITE_INV_TCB_GET_SPACE_INFO as u64;
    pub const TCB_GET_CPU_TIMES: u64 = uapi::KERNITE_INV_TCB_GET_CPU_TIMES as u64;
    pub const TCB_GET_TRACE_ID: u64 = uapi::KERNITE_INV_TCB_GET_TRACE_ID as u64;
    pub const TCB_SET_ABI_TP: u64 = uapi::KERNITE_INV_TCB_SET_ABI_TP as u64;
    pub const TCB_EXIT_SELF: u64 = uapi::KERNITE_INV_TCB_EXIT_SELF as u64;

    pub const VSPACE_MAP: u64 = uapi::KERNITE_INV_VSPACE_MAP as u64;
    pub const VSPACE_UNMAP: u64 = uapi::KERNITE_INV_VSPACE_UNMAP as u64;
    pub const VSPACE_MAP_PT: u64 = uapi::KERNITE_INV_VSPACE_MAP_PT as u64;
    pub const VSPACE_WALK: u64 = uapi::KERNITE_INV_VSPACE_WALK as u64;
    pub const VSPACE_COPY_PAGE: u64 = uapi::KERNITE_INV_VSPACE_COPY_PAGE as u64;
    pub const VSPACE_MAP_DEVICE: u64 = uapi::KERNITE_INV_VSPACE_MAP_DEVICE as u64;
    pub const VSPACE_MAP_DEVICE_RANGE: u64 = uapi::KERNITE_INV_VSPACE_MAP_DEVICE_RANGE as u64;
    pub const VSPACE_PROTECT: u64 = uapi::KERNITE_INV_VSPACE_PROTECT as u64;
    pub const VSPACE_PROTECT_RANGE: u64 = uapi::KERNITE_INV_VSPACE_PROTECT_RANGE as u64;
    pub const VSPACE_MAP_DEMAND: u64 = uapi::KERNITE_INV_VSPACE_MAP_DEMAND as u64;
    pub const VSPACE_MAP_DEMAND_RANGE: u64 = uapi::KERNITE_INV_VSPACE_MAP_DEMAND_RANGE as u64;
    pub const VSPACE_SET_COW_POOL: u64 = uapi::KERNITE_INV_VSPACE_SET_COW_POOL as u64;
    pub const VSPACE_REPLENISH_COW_POOL: u64 = uapi::KERNITE_INV_VSPACE_REPLENISH_COW_POOL as u64;
    pub const VSPACE_MAP_MO: u64 = uapi::KERNITE_INV_VSPACE_MAP_MO as u64;
    pub const VSPACE_SHARE_RO_PAGE: u64 = uapi::KERNITE_INV_VSPACE_SHARE_RO_PAGE as u64;
    pub const VSPACE_FORK_RANGE: u64 = uapi::KERNITE_INV_VSPACE_FORK_RANGE as u64;
    pub const VSPACE_UNDO_FORK_RANGE: u64 = uapi::KERNITE_INV_VSPACE_UNDO_FORK_RANGE as u64;
    pub const VSPACE_GET_MEM_STATS: u64 = uapi::KERNITE_INV_VSPACE_GET_MEM_STATS as u64;
    pub const VSPACE_GET_RANGE_STATS: u64 = uapi::KERNITE_INV_VSPACE_GET_RANGE_STATS as u64;
    pub const VSPACE_GET_TRACE_ID: u64 = uapi::KERNITE_INV_VSPACE_GET_TRACE_ID as u64;
    pub const VSPACE_FUTEX_WAIT: u64 = uapi::KERNITE_INV_VSPACE_FUTEX_WAIT as u64;
    pub const VSPACE_FUTEX_WAKE: u64 = uapi::KERNITE_INV_VSPACE_FUTEX_WAKE as u64;
    pub const VSPACE_FUTEX_REQUEUE: u64 = uapi::KERNITE_INV_VSPACE_FUTEX_REQUEUE as u64;
    pub const VSPACE_RESOLVE_PAGE: u64 = uapi::KERNITE_INV_VSPACE_RESOLVE_PAGE as u64;

    pub const SC_CONFIGURE: u64 = uapi::KERNITE_INV_SC_CONFIGURE as u64;
    pub const SC_BIND: u64 = uapi::KERNITE_INV_SC_BIND as u64;

    pub const IRQ_BIND_EQ: u64 = uapi::KERNITE_INV_IRQ_BIND_EQ as u64;
    pub const IRQ_UNBIND_EQ: u64 = uapi::KERNITE_INV_IRQ_UNBIND_EQ as u64;
    pub const IRQ_ACK: u64 = uapi::KERNITE_INV_IRQ_ACK as u64;

    pub const IOPORT_READ_8: u64 = uapi::KERNITE_INV_IOPORT_READ_8 as u64;
    pub const IOPORT_READ_16: u64 = uapi::KERNITE_INV_IOPORT_READ_16 as u64;
    pub const IOPORT_READ_32: u64 = uapi::KERNITE_INV_IOPORT_READ_32 as u64;
    pub const IOPORT_WRITE_8: u64 = uapi::KERNITE_INV_IOPORT_WRITE_8 as u64;
    pub const IOPORT_WRITE_16: u64 = uapi::KERNITE_INV_IOPORT_WRITE_16 as u64;
    pub const IOPORT_WRITE_32: u64 = uapi::KERNITE_INV_IOPORT_WRITE_32 as u64;

    pub const MO_COMMIT: u64 = uapi::KERNITE_INV_MO_COMMIT as u64;
    pub const MO_DECOMMIT: u64 = uapi::KERNITE_INV_MO_DECOMMIT as u64;
    pub const MO_GET_SIZE: u64 = uapi::KERNITE_INV_MO_GET_SIZE as u64;
    pub const MO_CLONE: u64 = uapi::KERNITE_INV_MO_CLONE as u64;
    pub const MO_RESIZE: u64 = uapi::KERNITE_INV_MO_RESIZE as u64;
    pub const MO_READ: u64 = uapi::KERNITE_INV_MO_READ as u64;
    pub const MO_WRITE: u64 = uapi::KERNITE_INV_MO_WRITE as u64;
    pub const MO_HAS_PAGE: u64 = uapi::KERNITE_INV_MO_HAS_PAGE as u64;
    pub const MO_GET_MAP_COUNT: u64 = uapi::KERNITE_INV_MO_GET_MAP_COUNT as u64;
    pub const MO_UPDATE_PAGE_FLAGS: u64 = uapi::KERNITE_INV_MO_UPDATE_PAGE_FLAGS as u64;
    pub const MO_ATTACH_PAGER: u64 = uapi::KERNITE_INV_MO_ATTACH_PAGER as u64;
    pub const MO_SNAPSHOT: u64 = uapi::KERNITE_INV_MO_SNAPSHOT as u64;
    pub const MO_CLONE_RANGE: u64 = uapi::KERNITE_INV_MO_CLONE_RANGE as u64;
    pub const MO_MARK_EXECUTABLE: u64 = uapi::KERNITE_INV_MO_MARK_EXECUTABLE as u64;
    pub const MO_POPULATE_BORROWED: u64 = uapi::KERNITE_INV_MO_POPULATE_BORROWED as u64;

    pub const PAGER_BIND_EQ: u64 = uapi::KERNITE_INV_PAGER_BIND_EQ as u64;
    pub const PAGER_SUPPLY_PAGE: u64 = uapi::KERNITE_INV_PAGER_SUPPLY_PAGE as u64;
    pub const PAGER_SUPPLY_COPY: u64 = uapi::KERNITE_INV_PAGER_SUPPLY_COPY as u64;
    pub const PAGER_FAIL: u64 = uapi::KERNITE_INV_PAGER_FAIL as u64;
    pub const PAGER_DETACH: u64 = uapi::KERNITE_INV_PAGER_DETACH as u64;
    pub const PAGER_BEGIN_WRITEBACK: u64 = uapi::KERNITE_INV_PAGER_BEGIN_WRITEBACK as u64;
    pub const PAGER_WRITEBACK_DONE: u64 = uapi::KERNITE_INV_PAGER_WRITEBACK_DONE as u64;
    pub const PAGER_EVICT_PAGE: u64 = uapi::KERNITE_INV_PAGER_EVICT_PAGE as u64;

    pub const EQ_WAIT: u64 = uapi::KERNITE_INV_EQ_WAIT as u64;
    pub const EQ_POLL: u64 = uapi::KERNITE_INV_EQ_POLL as u64;
    pub const EQ_CANCEL: u64 = uapi::KERNITE_INV_EQ_CANCEL as u64;

    pub const WATCH_REGISTER: u64 = uapi::KERNITE_INV_WATCH_REGISTER as u64;
    pub const WATCH_DISARM: u64 = uapi::KERNITE_INV_WATCH_DISARM as u64;
    pub const WATCH_CANCEL: u64 = uapi::KERNITE_INV_WATCH_CANCEL as u64;

    pub const MP_WRITE: u64 = uapi::KERNITE_INV_MP_WRITE as u64;
    pub const MP_READ: u64 = uapi::KERNITE_INV_MP_READ as u64;
    pub const MP_CLOSE: u64 = uapi::KERNITE_INV_MP_CLOSE as u64;
    pub const MP_CALL: u64 = uapi::KERNITE_INV_MP_CALL as u64;
    pub const MP_CORE_PAIR: u64 = uapi::KERNITE_INV_MP_CORE_PAIR as u64;

    pub const DP_PRODUCE: u64 = uapi::KERNITE_INV_DP_PRODUCE as u64;
    pub const DP_CONSUME: u64 = uapi::KERNITE_INV_DP_CONSUME as u64;
    pub const DP_QUERY: u64 = uapi::KERNITE_INV_DP_QUERY as u64;
    pub const DP_CLOSE: u64 = uapi::KERNITE_INV_DP_CLOSE as u64;
    pub const DP_SET_RX_THRESHOLD: u64 = uapi::KERNITE_INV_DP_SET_RX_THRESHOLD as u64;
    pub const DP_SET_TX_THRESHOLD: u64 = uapi::KERNITE_INV_DP_SET_TX_THRESHOLD as u64;
    pub const DP_SHUTDOWN: u64 = uapi::KERNITE_INV_DP_SHUTDOWN as u64;
    pub const DP_CORE_PAIR: u64 = uapi::KERNITE_INV_DP_CORE_PAIR as u64;

    pub const TIMER_SET: u64 = uapi::KERNITE_INV_TIMER_SET as u64;
    pub const TIMER_CANCEL: u64 = uapi::KERNITE_INV_TIMER_CANCEL as u64;
    pub const TIMER_QUERY: u64 = uapi::KERNITE_INV_TIMER_QUERY as u64;

    pub const RNG_READ: u64 = uapi::KERNITE_INV_RNG_READ as u64;
    pub const SYSTEM_SHUTDOWN: u64 = uapi::KERNITE_INV_SYSTEM_SHUTDOWN as u64;
    pub const SYSTEM_REBOOT: u64 = uapi::KERNITE_INV_SYSTEM_REBOOT as u64;
    pub const CLOCK_READ: u64 = uapi::KERNITE_INV_CLOCK_READ as u64;
    pub const SYSINFO_GET_INFO: u64 = uapi::KERNITE_INV_SYSINFO_GET_INFO as u64;
    pub const SYSINFO_GET_MEMINFO: u64 = uapi::KERNITE_INV_SYSINFO_GET_MEMINFO as u64;
    pub const KDEBUG_PUTCHAR: u64 = uapi::KERNITE_INV_KDEBUG_PUTCHAR as u64;
    pub const KDEBUG_PUTSTR: u64 = uapi::KERNITE_INV_KDEBUG_PUTSTR as u64;
    pub const KDEBUG_PUTBUF: u64 = uapi::KERNITE_INV_KDEBUG_PUTBUF as u64;
    pub const KDEBUG_DUMP_STATE: u64 = uapi::KERNITE_INV_KDEBUG_DUMP_STATE as u64;
    pub const KDEBUG_CONSOLE_CONTROL: u64 = uapi::KERNITE_INV_KDEBUG_CONSOLE_CONTROL as u64;

    pub const DEVICE_CONTROL_CREATE_IOPORT: u64 =
        uapi::KERNITE_INV_DEVICE_CONTROL_CREATE_IOPORT as u64;
    pub const DEVICE_CONTROL_CREATE_DEVICE_UNTYPED: u64 =
        uapi::KERNITE_INV_DEVICE_CONTROL_CREATE_DEVICE_UNTYPED as u64;
    pub const DEVICE_CONTROL_CREATE_IRQ_HANDLER: u64 =
        uapi::KERNITE_INV_DEVICE_CONTROL_CREATE_IRQ_HANDLER as u64;
}

/// Build a fastpath-eligible `MpRecord` from the register-passed
/// `(msg_info, mr0, mr1)` triple. Returns `None` for any record
/// shape the fastpath cannot serve (length > 2 register words, any
/// cap carriers).
fn build_fastpath_record(
    msg_info: u64,
    mr0: u64,
    mr1: u64,
) -> Option<crate::ipc::message_pipe::MpRecord> {
    use crate::ipc::message_pipe::MpRecord;
    let length = super::msg_info::get_length(msg_info);
    let extra_caps = super::msg_info::get_extra_caps(msg_info);
    if length > 2 || extra_caps != 0 {
        return None;
    }
    let mut record = MpRecord::empty();
    record.label = super::msg_info::get_label(msg_info);
    record.length = length as u64;
    if length > 0 {
        record.words[0] = mr0;
    }
    if length > 1 {
        record.words[1] = mr1;
    }
    Some(record)
}

/// Common publish step: validate the pipe pointers, hand the record
/// to `MessagePipeCore::try_write_fast`, and translate the boolean
/// result into a `SyscallResult` / bail token. Shared by `MP_WRITE`
/// fastpath.
///
/// `MP_WRITE` fastpath does not carry user-supplied caps
/// (extra_caps == 0 gate above), so we publish with empty carriers.
/// `MP_CALL` deliberately stays on the slowpath because it performs
/// a write followed by a read on the same endpoint.
fn publish_fastpath_record(
    cap: &super::Capability,
    record: crate::ipc::message_pipe::MpRecord,
) -> Option<super::SyscallResult> {
    use crate::ipc::message_pipe::{CarrierSlots, MessagePipe};
    let mp = cap.object as *mut MessagePipe;
    if mp.is_null() {
        return None;
    }
    let core_ptr = unsafe { (*mp).core };
    if core_ptr.is_null() {
        return None;
    }
    let me = unsafe { (*mp).which_side };
    if unsafe { (*core_ptr).try_write_fast(me, record, CarrierSlots::empty()) } {
        Some(super::SyscallResult::ok(0))
    } else {
        None
    }
}

/// `MP_WRITE` fastpath. Returns `Some(result)` if the fastpath
/// handled the call (with the resulting `SyscallResult`), or `None`
/// to signal the slowpath should retry. All bailout reasons return
/// `None` so the caller's record / carriers are untouched.
pub(crate) fn try_mp_write_fastpath(
    cap: &super::Capability,
    msg_info: u64,
    mr0: u64,
    mr1: u64,
) -> Option<super::SyscallResult> {
    if !cap.has_right(super::CapRights::WRITE) {
        return None;
    }
    let flags =
        unsafe { super::support::read_current_ipc_word(super::support::IPC_FLAGS_WORD) }.ok()?;
    let txid =
        unsafe { super::support::read_current_ipc_word(super::support::IPC_MP_TXID_WORD) }.ok()?;
    if flags != 0 || txid != 0 {
        return None;
    }
    let mut record = build_fastpath_record(msg_info, mr0, mr1)?;
    record.badge = cap.badge;
    publish_fastpath_record(cap, record)
}

/// `MP_READ` fastpath. Mailbox-only — peeks the caller's
/// `mp_fast_mailbox` for a `MailboxKind::Message` deposit published
/// from this pipe core, copies the record body to the caller's IPC
/// buffer, and commits. Bails when:
/// * Cap lacks `READ` right.
/// * Pipe core null (peer side already finalized).
/// * Mailbox empty / source mismatch / wrong kind / scheduler not
///   yet attached to a TCB.
/// * Record carries cap carriers (slowpath owns the cap-install
///   dance for those).
/// * IPC-buffer write faults (rolled back via `abort_peek`).
pub(crate) fn try_mp_read_fastpath(cap: &super::Capability) -> Option<super::SyscallResult> {
    use crate::ipc::message_pipe::{MailboxKind, MessagePipe};

    if !cap.has_right(super::CapRights::READ) {
        return None;
    }
    let mp = cap.object as *mut MessagePipe;
    if mp.is_null() {
        return None;
    }
    let core_ptr = unsafe { (*mp).core };
    if core_ptr.is_null() {
        return None;
    }

    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if current.is_null() {
        return None;
    }

    let core_obj = core_ptr as *mut crate::cap::KernelObject;
    let wait_seq = unsafe { (*current).wait_seq };
    let (kind, record, carriers) =
        match unsafe { (*current).mp_fast_mailbox.try_peek(core_obj, wait_seq) } {
            Some(t) => t,
            None => return None,
        };
    if !matches!(kind, MailboxKind::Message) {
        // Reply mailbox is explicit fault delivery completion, not
        // ordinary `MP_READ`.
        unsafe {
            (*current)
                .mp_fast_mailbox
                .abort_peek(kind, record, carriers)
        };
        return None;
    }
    if record.cap_count != 0 {
        // Carriers in the record require the slowpath's full cap-
        // install dance.
        unsafe {
            (*current)
                .mp_fast_mailbox
                .abort_peek(kind, record, carriers)
        };
        return None;
    }

    let installed =
        [crate::ipc::transfer::InstalledCap::null(); crate::ipc::message_pipe::MP_MSG_CAPS];
    if super::pipe::write_mp_record_to_ipc(&record, &installed).is_err() {
        unsafe {
            (*current)
                .mp_fast_mailbox
                .abort_peek(kind, record, carriers)
        };
        return None;
    }

    unsafe { (*current).mp_fast_mailbox.commit_peek(kind) };
    Some(super::SyscallResult::ok(record.label))
}

fn current_root_cspace() -> *mut CNode {
    unsafe {
        let current_tcb = crate::sched::scheduler::scheduler().current();
        if current_tcb.is_null() {
            core::ptr::null_mut()
        } else {
            (*current_tcb).cspace_root
        }
    }
}

#[inline]
fn is_current_root_cspace(cnode: &CNode) -> bool {
    core::ptr::eq(cnode as *const CNode, current_root_cspace() as *const CNode)
}

#[inline]
pub(super) fn resolve_current_root_capref(
    cap_ptr: u64,
) -> Result<crate::cap::CapRef, SyscallError> {
    let root = current_root_cspace();
    if root.is_null() {
        return Err(SyscallError::InvalidOperation);
    }
    crate::cap::cnode::resolve_root_cspace_slot(unsafe { &*root }, cap_ptr)
        .map_err(|_| SyscallError::InvalidCapability)
}

#[inline]
fn lookup_current_root_capability(cap_ptr: u64) -> Result<Capability, SyscallError> {
    let cap_ref = resolve_current_root_capref(cap_ptr)?;
    Ok(cap_ref.get())
}

#[inline]
fn resolve_current_root_read_slot_cap_error(cap_ptr: u64) -> Result<(*mut CNode, usize), CapError> {
    let root = current_root_cspace();
    if root.is_null() {
        return Err(CapError::InvalidOperation);
    }
    crate::cap::cnode::resolve_root_cspace_read_slot(unsafe { &*root }, cap_ptr)
}

#[inline]
fn resolve_current_root_write_slot_cap_error(
    cap_ptr: u64,
) -> Result<(*mut CNode, usize), CapError> {
    let root = current_root_cspace();
    if root.is_null() {
        return Err(CapError::InvalidOperation);
    }
    crate::cap::cnode::resolve_root_cspace_for_slot(unsafe { &*root }, cap_ptr)
}

pub(crate) unsafe fn read_invoke_depths(tcb: *mut Tcb) -> (u8, u8) {
    unsafe {
        let d0 = (*tcb).invoke_depth0;
        let d1 = (*tcb).invoke_depth1;
        (*tcb).invoke_depth0 = 0;
        (*tcb).invoke_depth1 = 0;
        (d0, d1)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CnodeCopySlots {
    pub src_leaf: *mut CNode,
    pub src_idx: usize,
    pub dest_leaf: *mut CNode,
    pub dest_idx: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct CnodeWriteSlot {
    pub leaf: *mut CNode,
    pub idx: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct CnodeCopyRequest {
    pub slots: CnodeCopySlots,
    pub rights: CapRights,
}

#[derive(Clone, Copy)]
pub(crate) struct CnodeMoveRequest {
    pub slots: CnodeCopySlots,
}

#[derive(Clone, Copy)]
pub(crate) struct CnodeWriteRequest {
    pub slot: CnodeWriteSlot,
}

#[derive(Clone, Copy)]
pub(crate) struct InvokeTarget {
    pub cap_ptr: u64,
    pub cap: Capability,
}

impl InvokeTarget {
    pub(crate) fn invoke(
        self,
        label: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
    ) -> SyscallResult {
        let cap = self.cap;
        let cap_ptr = self.cap_ptr;

        // v1 fastpath — `MP_WRITE` on a `MessagePipe` cap whose peer
        // is already parked on `PipeRead` (same- or cross-CPU) skips
        // ring queueing entirely and publishes the record into the
        // peer's `mp_fast_mailbox` (`MailboxKind::Message`). Bailing
        // here drops back to the slowpath dispatch below with no
        // observable side-effect.
        if label == label::MP_WRITE && cap.obj_type == ObjectType::MessagePipe {
            if let Some(result) = try_mp_write_fastpath(&cap, arg0, arg1, arg2) {
                return result;
            }
        }

        match (cap.obj_type, label) {
            // CNode.
            (ObjectType::CNode, label::CNODE_COPY) => {
                cap::syscall_cnode_copy(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::CNode, label::CNODE_MINT) => {
                cap::syscall_cnode_mint(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::CNode, label::CNODE_MOVE) => {
                cap::syscall_cnode_move(&cap, arg0, arg1, arg2)
            }
            (ObjectType::CNode, label::CNODE_MUTATE) => {
                cap::syscall_cnode_mutate(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::CNode, label::CNODE_DELETE) => cap::syscall_cnode_delete(&cap, arg0),
            (ObjectType::CNode, label::CNODE_REVOKE) => cap::syscall_cnode_revoke(&cap, arg0),
            (ObjectType::CNode, label::CNODE_SET_GUARD) => {
                cap::syscall_cnode_set_guard(&cap, arg0, arg1)
            }
            (ObjectType::CNode, label::CNODE_GET_INFO) => cap::syscall_cnode_get_info(&cap),

            // Untyped.
            (ObjectType::Untyped, label::UNTYPED_RETYPE) => {
                cap::syscall_untyped_retype(&cap, cap_ptr, arg0, arg1, arg2)
            }
            (ObjectType::Untyped, label::UNTYPED_RESET) => {
                cap::syscall_untyped_reset(&cap, cap_ptr)
            }
            (ObjectType::Untyped, label::UNTYPED_GET_STATS) => {
                system::syscall_untyped_get_stats(&cap, arg0)
            }

            // TCB.
            (ObjectType::Tcb, label::TCB_CONFIGURE) => {
                tcb::syscall_tcb_configure(&cap, arg0, arg1, arg2)
            }
            (ObjectType::Tcb, label::TCB_START) => tcb::syscall_tcb_start(&cap),
            (ObjectType::Tcb, label::TCB_STOP) => tcb::syscall_tcb_stop(&cap),
            (ObjectType::Tcb, label::TCB_KILL) => tcb::syscall_tcb_kill(&cap),
            (ObjectType::Tcb, label::TCB_YIELD) => tcb::syscall_tcb_yield(&cap),
            (ObjectType::Tcb, label::TCB_GET_STATE) => tcb::syscall_tcb_get_state(&cap),
            (ObjectType::Tcb, label::TCB_GET_ABI_VERSION) => tcb::syscall_tcb_get_abi_version(&cap),
            (ObjectType::Tcb, label::TCB_SET_INVOKE_DEPTHS) => {
                tcb::syscall_tcb_set_invoke_depths(&cap, arg0, arg1)
            }
            (ObjectType::Tcb, label::TCB_SET_SPACE) => {
                tcb::syscall_tcb_set_space(&cap, arg0, arg1, arg2)
            }
            (ObjectType::Tcb, label::TCB_SET_AFFINITY) => tcb::syscall_tcb_set_affinity(&cap, arg0),
            (ObjectType::Tcb, label::TCB_READ_REGISTERS) => {
                tcb::syscall_tcb_read_registers(&cap, arg0)
            }
            (ObjectType::Tcb, label::TCB_WRITE_REGISTERS) => {
                tcb::syscall_tcb_write_registers(&cap, arg0, arg1, arg2)
            }
            (ObjectType::Tcb, label::TCB_SET_PRIORITY) => tcb::syscall_tcb_set_priority(&cap, arg0),
            (ObjectType::Tcb, label::TCB_SET_IPC_BUFFER) => {
                tcb::syscall_tcb_set_ipc_buffer(&cap, arg0)
            }
            (ObjectType::Tcb, label::TCB_SET_FAULT_PIPE) => {
                tcb::syscall_tcb_set_fault_pipe(&cap, arg0)
            }
            (ObjectType::Tcb, label::TCB_COPY_FPU) => tcb::syscall_tcb_copy_fpu(&cap, arg0),
            (ObjectType::Tcb, label::TCB_SET_TLS_BASE) => tcb::syscall_tcb_set_tls_base(&cap, arg0),
            (ObjectType::Tcb, label::TCB_SET_STACK_BOUNDS) => {
                tcb::syscall_tcb_set_stack_bounds(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::Tcb, label::TCB_SET_SCHED_CLASS) => {
                tcb::syscall_tcb_set_sched_class(&cap, arg0)
            }
            (ObjectType::Tcb, label::TCB_GET_SPACE_INFO) => tcb::syscall_tcb_get_space_info(&cap),
            (ObjectType::Tcb, label::TCB_GET_CPU_TIMES) => tcb::syscall_tcb_get_cpu_times(&cap),
            (ObjectType::Tcb, label::TCB_GET_TRACE_ID) => tcb::syscall_tcb_get_trace_id(&cap),
            (ObjectType::Tcb, label::TCB_SET_ABI_TP) => tcb::syscall_tcb_set_abi_tp(&cap, arg0),
            (ObjectType::Tcb, label::TCB_EXIT_SELF) => tcb::syscall_tcb_exit_self(&cap),

            // VSpace.
            (ObjectType::VSpace, label::VSPACE_MAP) => {
                vspace::syscall_vspace_map(&cap, arg0, arg1, arg2)
            }
            (ObjectType::VSpace, label::VSPACE_UNMAP) => vspace::syscall_vspace_unmap(&cap, arg0),
            (ObjectType::VSpace, label::VSPACE_MAP_PT) => {
                vspace::syscall_vspace_map_pt(&cap, arg0, arg1, arg2)
            }
            (ObjectType::VSpace, label::VSPACE_WALK) => {
                vspace::syscall_vspace_walk(&cap, arg0, arg1)
            }
            (ObjectType::VSpace, label::VSPACE_RESOLVE_PAGE) => {
                vspace::syscall_vspace_resolve_page(&cap, arg0)
            }
            (ObjectType::VSpace, label::VSPACE_COPY_PAGE) => {
                vspace::syscall_vspace_copy_page(&cap, arg0, arg1)
            }
            (ObjectType::VSpace, label::VSPACE_MAP_DEVICE) => {
                vspace::syscall_vspace_map_device(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::VSpace, label::VSPACE_MAP_DEVICE_RANGE) => {
                vspace::syscall_vspace_map_device_range(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::VSpace, label::VSPACE_PROTECT) => {
                vspace::syscall_vspace_protect(&cap, arg0, arg1)
            }
            (ObjectType::VSpace, label::VSPACE_PROTECT_RANGE) => {
                vspace::syscall_vspace_protect_range(&cap, arg0, arg1, arg2)
            }
            (ObjectType::VSpace, label::VSPACE_MAP_DEMAND) => {
                vspace::syscall_vspace_map_demand(&cap, arg0, arg1)
            }
            (ObjectType::VSpace, label::VSPACE_MAP_DEMAND_RANGE) => {
                vspace::syscall_vspace_map_demand_range(&cap, arg0, arg1, arg2)
            }
            (ObjectType::VSpace, label::VSPACE_SET_COW_POOL) => {
                vspace::syscall_vspace_set_cow_pool(&cap, arg0, arg1, arg2)
            }
            (ObjectType::VSpace, label::VSPACE_REPLENISH_COW_POOL) => {
                vspace::syscall_vspace_replenish_cow_pool(&cap, arg0, arg1, arg2)
            }
            (ObjectType::VSpace, label::VSPACE_MAP_MO) => {
                vspace::syscall_vspace_map_mo(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::VSpace, label::VSPACE_SHARE_RO_PAGE) => {
                vspace::syscall_vspace_share_ro_page(&cap, arg0, arg1, arg2)
            }
            (ObjectType::VSpace, label::VSPACE_FORK_RANGE) => {
                vspace::syscall_vspace_fork_range(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::VSpace, label::VSPACE_UNDO_FORK_RANGE) => {
                vspace::syscall_vspace_undo_fork_range(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::VSpace, label::VSPACE_GET_MEM_STATS) => {
                vspace::syscall_vspace_get_mem_stats(&cap, arg0)
            }
            (ObjectType::VSpace, label::VSPACE_GET_RANGE_STATS) => {
                vspace::syscall_vspace_get_range_stats(&cap, arg0, arg1, arg2)
            }
            (ObjectType::VSpace, label::VSPACE_GET_TRACE_ID) => {
                vspace::syscall_vspace_get_trace_id(&cap)
            }
            (ObjectType::VSpace, label::VSPACE_FUTEX_WAIT) => {
                crate::ipc::futex::syscall_vspace_futex_wait(&cap, arg0, arg1 as u32, arg2)
            }
            (ObjectType::VSpace, label::VSPACE_FUTEX_WAKE) => {
                crate::ipc::futex::syscall_vspace_futex_wake(&cap, arg0, arg1 as u32)
            }
            (ObjectType::VSpace, label::VSPACE_FUTEX_REQUEUE) => {
                // arg2 packs the two counts: (wake_count << 32) | requeue_count.
                crate::ipc::futex::syscall_vspace_futex_requeue(
                    &cap,
                    arg0,
                    arg1,
                    (arg2 >> 32) as u32,
                    arg2 as u32,
                    arg3 as u32,
                )
            }

            // SchedContext.
            (ObjectType::SchedContext, label::SC_CONFIGURE) => {
                sc::syscall_sc_configure(&cap, arg0, arg1)
            }
            (ObjectType::SchedContext, label::SC_BIND) => sc::syscall_sc_bind(&cap, arg0),

            // IoPort.
            (ObjectType::IoPort, label::IOPORT_READ_8) => {
                super::ioport::syscall_ioport_read_8(&cap, arg0)
            }
            (ObjectType::IoPort, label::IOPORT_READ_16) => {
                super::ioport::syscall_ioport_read_16(&cap, arg0)
            }
            (ObjectType::IoPort, label::IOPORT_READ_32) => {
                super::ioport::syscall_ioport_read_32(&cap, arg0)
            }
            (ObjectType::IoPort, label::IOPORT_WRITE_8) => {
                super::ioport::syscall_ioport_write_8(&cap, arg0, arg1)
            }
            (ObjectType::IoPort, label::IOPORT_WRITE_16) => {
                super::ioport::syscall_ioport_write_16(&cap, arg0, arg1)
            }
            (ObjectType::IoPort, label::IOPORT_WRITE_32) => {
                super::ioport::syscall_ioport_write_32(&cap, arg0, arg1)
            }

            // IrqHandler.
            (ObjectType::IrqHandler, label::IRQ_BIND_EQ) => {
                event::syscall_irq_bind_eq(&cap, arg0, arg1)
            }
            (ObjectType::IrqHandler, label::IRQ_UNBIND_EQ) => event::syscall_irq_unbind_eq(&cap),
            (ObjectType::IrqHandler, label::IRQ_ACK) => event::syscall_irq_ack(&cap),

            // KernelRng / SystemControl / Clock / SystemInfo / KernelDebug.
            (ObjectType::KernelRng, label::RNG_READ) => system::syscall_rng_read(&cap, arg0, arg1),
            (ObjectType::SystemControl, label::SYSTEM_SHUTDOWN) => {
                system::syscall_system_shutdown(&cap)
            }
            (ObjectType::SystemControl, label::SYSTEM_REBOOT) => {
                system::syscall_system_reboot(&cap)
            }
            (ObjectType::Clock, label::CLOCK_READ) => system::syscall_clock_read(&cap, arg0),
            (ObjectType::SystemInfo, label::SYSINFO_GET_INFO) => {
                system::syscall_system_get_info(&cap, arg0, arg1, arg2)
            }
            (ObjectType::SystemInfo, label::SYSINFO_GET_MEMINFO) => {
                system::syscall_system_get_meminfo(&cap, arg0)
            }
            (ObjectType::KernelDebug, label::KDEBUG_PUTCHAR) => {
                system::syscall_kdebug_putchar(&cap, arg0)
            }
            (ObjectType::KernelDebug, label::KDEBUG_PUTSTR) => {
                system::syscall_kdebug_putstr(&cap, arg0, arg1)
            }
            (ObjectType::KernelDebug, label::KDEBUG_PUTBUF) => {
                system::syscall_kdebug_putbuf(&cap, arg0, arg1)
            }
            (ObjectType::KernelDebug, label::KDEBUG_DUMP_STATE) => {
                system::syscall_kdebug_dump_state(&cap)
            }
            (ObjectType::KernelDebug, label::KDEBUG_CONSOLE_CONTROL) => {
                system::syscall_kdebug_console_control(&cap, arg0)
            }
            (ObjectType::DeviceControl, label::DEVICE_CONTROL_CREATE_IOPORT) => {
                system::syscall_device_control_create_ioport(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::DeviceControl, label::DEVICE_CONTROL_CREATE_DEVICE_UNTYPED) => {
                system::syscall_device_control_create_device_untyped(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::DeviceControl, label::DEVICE_CONTROL_CREATE_IRQ_HANDLER) => {
                system::syscall_device_control_create_irq_handler(&cap, arg0, arg1, arg2, arg3)
            }

            // EventQueue.
            (ObjectType::EventQueue, label::EQ_WAIT) => event::syscall_eq_wait(&cap, arg0),
            (ObjectType::EventQueue, label::EQ_POLL) => event::syscall_eq_poll(&cap),
            (ObjectType::EventQueue, label::EQ_CANCEL) => event::syscall_eq_cancel(&cap),

            // Watch.
            (ObjectType::Watch, label::WATCH_REGISTER) => {
                event::syscall_watch_register(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::Watch, label::WATCH_DISARM) => event::syscall_watch_disarm(&cap),
            (ObjectType::Watch, label::WATCH_CANCEL) => event::syscall_watch_cancel(&cap),

            // Timer.
            (ObjectType::Timer, label::TIMER_SET) => {
                event::syscall_timer_set(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::Timer, label::TIMER_CANCEL) => event::syscall_timer_cancel(&cap),
            (ObjectType::Timer, label::TIMER_QUERY) => event::syscall_timer_query(&cap),

            // MessagePipe.
            (ObjectType::MessagePipe, label::MP_WRITE) => {
                super::pipe::syscall_mp_write(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::MessagePipe, label::MP_READ) => super::pipe::syscall_mp_read(&cap),
            (ObjectType::MessagePipe, label::MP_CLOSE) => super::pipe::syscall_mp_close(&cap),
            (ObjectType::MessagePipe, label::MP_CALL) => {
                super::pipe::syscall_mp_call(&cap, arg0, arg1)
            }
            (ObjectType::MessagePipeCore, label::MP_CORE_PAIR) => {
                super::pipe::syscall_mp_pair(&cap, arg0, arg1)
            }

            // DataPipe.
            (ObjectType::DataPipe, label::DP_PRODUCE) => {
                super::pipe::syscall_dp_produce(&cap, arg0, arg1)
            }
            (ObjectType::DataPipe, label::DP_CONSUME) => {
                super::pipe::syscall_dp_consume(&cap, arg0, arg1)
            }
            (ObjectType::DataPipe, label::DP_QUERY) => super::pipe::syscall_dp_query(&cap),
            (ObjectType::DataPipe, label::DP_CLOSE) => super::pipe::syscall_dp_close(&cap),
            (ObjectType::DataPipe, label::DP_SET_RX_THRESHOLD) => {
                super::pipe::syscall_dp_set_rx_threshold(&cap, arg0)
            }
            (ObjectType::DataPipe, label::DP_SET_TX_THRESHOLD) => {
                super::pipe::syscall_dp_set_tx_threshold(&cap, arg0)
            }
            (ObjectType::DataPipe, label::DP_SHUTDOWN) => super::pipe::syscall_dp_shutdown(&cap),
            (ObjectType::DataPipeCore, label::DP_CORE_PAIR) => {
                // arg2 != 0 selects datagram (record-boundary) mode.
                super::pipe::syscall_dp_pair(&cap, arg0, arg1, arg2)
            }

            // MemoryObject.
            (ObjectType::MemoryObject, label::MO_COMMIT) => {
                mo::syscall_mo_commit(&cap, arg0, arg1, arg2)
            }
            (ObjectType::MemoryObject, label::MO_DECOMMIT) => {
                mo::syscall_mo_decommit(&cap, arg0, arg1)
            }
            (ObjectType::MemoryObject, label::MO_GET_SIZE) => mo::syscall_mo_get_size(&cap),
            (ObjectType::MemoryObject, label::MO_CLONE) => {
                mo::syscall_mo_clone(&cap, arg0, arg1, arg2)
            }
            (ObjectType::MemoryObject, label::MO_CLONE_RANGE) => {
                mo::syscall_mo_clone_range(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::MemoryObject, label::MO_SNAPSHOT) => {
                mo::syscall_mo_snapshot(&cap, arg0, arg1, arg2)
            }
            (ObjectType::MemoryObject, label::MO_RESIZE) => mo::syscall_mo_resize(&cap, arg0),
            (ObjectType::MemoryObject, label::MO_READ) => mo::syscall_mo_read(&cap, arg0, arg1),
            (ObjectType::MemoryObject, label::MO_WRITE) => mo::syscall_mo_write(&cap, arg0, arg1),
            (ObjectType::MemoryObject, label::MO_HAS_PAGE) => mo::syscall_mo_has_page(&cap, arg0),
            (ObjectType::MemoryObject, label::MO_GET_MAP_COUNT) => {
                mo::syscall_mo_get_map_count(&cap)
            }
            (ObjectType::MemoryObject, label::MO_UPDATE_PAGE_FLAGS) => {
                mo::syscall_mo_update_page_flags(&cap, arg0, arg1, arg2)
            }
            (ObjectType::MemoryObject, label::MO_ATTACH_PAGER) => {
                mo::syscall_mo_attach_pager(&cap, arg0, arg1)
            }
            (ObjectType::MemoryObject, label::MO_POPULATE_BORROWED) => {
                mo::syscall_mo_populate_borrowed(&cap, arg0, arg1, arg2)
            }

            (ObjectType::Pager, label::PAGER_BIND_EQ) => {
                pager::syscall_pager_bind_eq(&cap, arg0, arg1, arg2)
            }
            (ObjectType::Pager, label::PAGER_SUPPLY_PAGE) => {
                pager::syscall_pager_supply_page(&cap, arg0, arg1, arg2)
            }
            (ObjectType::Pager, label::PAGER_SUPPLY_COPY) => {
                pager::syscall_pager_supply_copy(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::Pager, label::PAGER_FAIL) => {
                pager::syscall_pager_fail(&cap, arg0, arg1, arg2)
            }
            (ObjectType::Pager, label::PAGER_DETACH) => pager::syscall_pager_detach(&cap, arg0),
            (ObjectType::Pager, label::PAGER_BEGIN_WRITEBACK) => {
                pager::syscall_pager_begin_writeback(&cap, arg0, arg1)
            }
            (ObjectType::Pager, label::PAGER_WRITEBACK_DONE) => {
                pager::syscall_pager_writeback_done(&cap, arg0, arg1, arg2, arg3)
            }
            (ObjectType::Pager, label::PAGER_EVICT_PAGE) => {
                pager::syscall_pager_evict_page(&cap, arg0, arg1)
            }

            // ExecAuthority — confer EXECUTE on a MemoryObject (the sole
            // EXECUTE-introducing op; gated by possession of this authority).
            (ObjectType::ExecAuthority, label::MO_MARK_EXECUTABLE) => {
                exec_authority::syscall_mo_mark_executable(&cap, arg0, arg1, arg2)
            }

            _ => SyscallResult::err(super::SyscallError::InvalidOperation),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct UntypedRetypeRequest {
    pub untyped_slot: crate::cap::CapSlot,
    pub dest_leaf: *mut CNode,
    pub dest_idx: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct UntypedResetRequest {
    pub untyped_slot: crate::cap::CapSlot,
}

impl CnodeCopyRequest {
    #[inline]
    pub(crate) unsafe fn copy(self) -> Result<(), CapError> {
        unsafe {
            (&mut *self.slots.dest_leaf).copy_slot(
                self.slots.dest_idx,
                &*self.slots.src_leaf,
                self.slots.src_idx,
                self.rights,
            )
        }
    }

    #[inline]
    pub(crate) unsafe fn mint(self, badge: u64) -> Result<(), CapError> {
        unsafe {
            (&mut *self.slots.dest_leaf).mint_slot(
                self.slots.dest_idx,
                &*self.slots.src_leaf,
                self.slots.src_idx,
                badge,
                self.rights,
            )
        }
    }

    /// Confer EXECUTE on the resolved source MemoryObject into the resolved
    /// destination slot. `self.rights` is ignored — `confer_exec_slot` uses the
    /// fixed conferral rights (see `Capability::confer_exec`).
    #[inline]
    pub(crate) unsafe fn confer_exec(self) -> Result<(), CapError> {
        unsafe {
            (&mut *self.slots.dest_leaf).confer_exec_slot(
                self.slots.dest_idx,
                &*self.slots.src_leaf,
                self.slots.src_idx,
            )
        }
    }
}

impl CnodeMoveRequest {
    #[inline]
    pub(crate) unsafe fn move_slot(self) -> Result<(), CapError> {
        unsafe {
            (&mut *self.slots.dest_leaf).move_slot(
                self.slots.dest_idx,
                &mut *self.slots.src_leaf,
                self.slots.src_idx,
            )
        }
    }

    #[inline]
    pub(crate) unsafe fn mutate(self, badge: u64) -> Result<(), CapError> {
        unsafe {
            (&mut *self.slots.dest_leaf).mutate_slot(
                self.slots.dest_idx,
                &mut *self.slots.src_leaf,
                self.slots.src_idx,
                badge,
            )
        }
    }
}

impl CnodeWriteRequest {
    #[inline]
    pub(crate) unsafe fn delete(self) -> Result<(), CapError> {
        unsafe { (&mut *self.slot.leaf).delete(self.slot.idx) }
    }

    #[inline]
    pub(crate) unsafe fn revoke(self) -> Result<(), CapError> {
        unsafe { (&mut *self.slot.leaf).revoke(self.slot.idx) }
    }
}

impl UntypedRetypeRequest {
    #[inline]
    pub(crate) unsafe fn retype(
        self,
        new_type: ObjectType,
        size_bits: u8,
        create_kind: crate::cap::memory_object::MoKind,
    ) -> Result<(), CapError> {
        unsafe {
            let live_cap = crate::cap::get_cap(self.untyped_slot);
            if live_cap.obj_type != ObjectType::Untyped || live_cap.object.is_null() {
                return Err(CapError::InvalidOperation);
            }
            if !live_cap.rights.contains(CapRights::CONFIGURE) {
                return Err(CapError::InsufficientRights);
            }
            let untyped = &mut *(live_cap.object as *mut crate::cap::UntypedMemory);
            untyped.retype(
                self.untyped_slot,
                new_type,
                size_bits,
                1,
                &mut *self.dest_leaf,
                self.dest_idx,
                create_kind,
            )
        }
    }
}

impl UntypedResetRequest {
    #[inline]
    pub(crate) fn reset(self) -> Result<(), CapError> {
        let live_cap = crate::cap::get_cap(self.untyped_slot);
        if live_cap.obj_type != ObjectType::Untyped || live_cap.object.is_null() {
            return Err(CapError::InvalidOperation);
        }
        if !live_cap.rights.contains(CapRights::CONFIGURE) {
            return Err(CapError::InsufficientRights);
        }
        // Object-based gating: any cap pointing at the same
        // `UntypedMemory` sees the union of every child added via
        // `add_child`. Replaces the cap-local `UntypedTracker::reset`
        // which only saw the birth cap's children list and missed
        // peers added through cnode_copy'd caps (split-brain).
        unsafe { (*(live_cap.object as *mut crate::cap::UntypedMemory)).reset_state() }
    }
}

#[inline]
fn current_invoke_depths() -> (u8, u8) {
    unsafe {
        let current_tcb = crate::sched::scheduler::scheduler().current();
        if current_tcb.is_null() {
            (0, 0)
        } else {
            read_invoke_depths(current_tcb)
        }
    }
}

#[cfg(any(klog_trace, klog_mod_cap))]
fn trace_cap_error_name(g: &crate::kernel::printk::SerialGuard, err: CapError) {
    g.puts(match err {
        CapError::InvalidSlot => "InvalidSlot",
        CapError::SlotOccupied => "SlotOccupied",
        CapError::SlotEmpty => "SlotEmpty",
        CapError::InsufficientRights => "InsufficientRights",
        CapError::DepthExceeded => "DepthExceeded",
        CapError::InvalidOperation => "InvalidOperation",
        CapError::InvalidBadge => "InvalidBadge",
        CapError::InsufficientMemory => "InsufficientMemory",
        CapError::OutOfSlots => "OutOfSlots",
        CapError::OutOfClasses => "OutOfClasses",
        CapError::NotAChild => "NotAChild",
        CapError::HasChildren => "HasChildren",
        CapError::HasDerivedCaps => "HasDerivedCaps",
        CapError::ObjectInUse => "ObjectInUse",
        CapError::InvalidState => "InvalidState",
        CapError::InvalidArgument => "InvalidArgument",
        CapError::GuardMismatch => "GuardMismatch",
    });
}

pub(crate) fn clear_pending_invoke_depths() {
    unsafe {
        let irq = save_irq_disable();
        let current_tcb = crate::sched::scheduler::scheduler().current();
        if !current_tcb.is_null() {
            let tcb = &*current_tcb;
            tcb.tcb_lock();
            (*current_tcb).invoke_depth0 = 0;
            (*current_tcb).invoke_depth1 = 0;
            tcb.tcb_unlock();
        }
        restore_irq(irq);
    }
}

#[inline]
pub(crate) unsafe fn with_cap_lock<R>(f: impl FnOnce() -> R) -> R {
    unsafe {
        let irq = save_irq_disable();
        CAP_LOCK.lock();
        let result = f();
        CAP_LOCK.unlock();
        restore_irq(irq);
        result
    }
}

pub(crate) fn lookup_capability(cap_ptr: u64) -> Result<Capability, SyscallError> {
    lookup_current_root_capability(cap_ptr)
}

#[inline]
pub(crate) fn lookup_typed_capability(
    cap_ptr: u64,
    obj_type: ObjectType,
    rights: CapRights,
) -> Result<Capability, SyscallError> {
    let cap = lookup_capability(cap_ptr)?;
    validate_capability(&cap, obj_type, rights)?;
    Ok(cap)
}

pub(crate) fn lookup_cap_locked(cap_ptr: u64) -> Result<Capability, SyscallError> {
    unsafe { with_cap_lock(|| lookup_capability(cap_ptr)) }
}

#[inline]
pub(crate) fn lookup_invoke_target_locked(cap_ptr: u64) -> Result<InvokeTarget, SyscallError> {
    Ok(InvokeTarget {
        cap_ptr,
        cap: lookup_cap_locked(cap_ptr)?,
    })
}

#[inline]
pub(crate) fn lookup_typed_cap_locked(
    cap_ptr: u64,
    obj_type: ObjectType,
    rights: CapRights,
) -> Result<Capability, SyscallError> {
    let cap = lookup_cap_locked(cap_ptr)?;
    validate_capability(&cap, obj_type, rights)?;
    Ok(cap)
}

/// Validate and delete a typed capability from the current root CSpace,
/// then keep `CAP_LOCK` held while `f` performs the post-delete
/// ownership transition.
///
/// This is used by consuming syscalls such as `PAGER_SUPPLY_PAGE`, where
/// the caller-provided cap must cease to exist before the underlying
/// object ownership is transferred to another subsystem.
pub(crate) fn consume_current_root_typed_cap_with_locked<R>(
    cap_ptr: u64,
    obj_type: ObjectType,
    rights: CapRights,
    f: impl FnOnce(Capability) -> Result<R, SyscallError>,
) -> Result<R, SyscallError> {
    unsafe {
        with_cap_lock(|| {
            let root = current_root_cspace();
            if root.is_null() {
                return Err(SyscallError::InvalidOperation);
            }
            let (leaf, idx) = crate::cap::cnode::resolve_root_cspace_read_slot(&*root, cap_ptr)
                .map_err(super::syscall_error_from_cap_error)?;
            let cap = (*leaf).get(idx).ok_or(SyscallError::InvalidCapability)?;
            validate_capability(&cap, obj_type, rights)?;
            (&mut *leaf)
                .delete(idx)
                .map_err(super::syscall_error_from_cap_error)?;
            f(cap)
        })
    }
}

#[inline]
pub(crate) fn lookup_cnode_root(
    cap_ptr: u64,
    rights: CapRights,
) -> Result<*mut CNode, SyscallError> {
    let cap = lookup_typed_capability(cap_ptr, ObjectType::CNode, rights)?;
    Ok(cap.object as *mut CNode)
}

#[inline]
pub(crate) fn lookup_cnode_root_locked(
    cap_ptr: u64,
    rights: CapRights,
) -> Result<*mut CNode, SyscallError> {
    let cap = lookup_typed_cap_locked(cap_ptr, ObjectType::CNode, rights)?;
    Ok(cap.object as *mut CNode)
}

#[derive(Clone, Copy)]
pub(crate) struct TcbRequest {
    pub cap: Capability,
}

#[derive(Clone, Copy)]
pub(crate) struct SchedContextRequest {
    pub cap: Capability,
}

impl TcbRequest {
    #[inline]
    pub(crate) fn tcb(self) -> *mut Tcb {
        self.cap.object as *mut Tcb
    }
}

impl SchedContextRequest {
    #[inline]
    pub(crate) fn sched_context(self) -> *mut crate::sched::thread::SchedContext {
        self.cap.object as *mut crate::sched::thread::SchedContext
    }
}

#[inline]
pub(crate) fn resolve_tcb_request(
    cap_ptr: u64,
    rights: CapRights,
) -> Result<TcbRequest, SyscallError> {
    Ok(TcbRequest {
        cap: lookup_typed_cap_locked(cap_ptr, ObjectType::Tcb, rights)?,
    })
}

#[inline]
pub(crate) fn resolve_sched_context_request(
    cap_ptr: u64,
    rights: CapRights,
) -> Result<SchedContextRequest, SyscallError> {
    Ok(SchedContextRequest {
        cap: lookup_typed_cap_locked(cap_ptr, ObjectType::SchedContext, rights)?,
    })
}

pub(crate) fn resolve_current_root_cap_slot(
    cspace: &mut CNode,
    cap_ptr: u64,
) -> Result<crate::cap::CapSlot, SyscallError> {
    match crate::cap::cnode::resolve_root_cspace_slot(cspace, cap_ptr) {
        // Reject a stale CNode entry (slot freed + reused since written)
        // before handing the raw slot to untyped retype / reset.
        Ok(r) if r.is_live() => Ok(r.slot),
        Ok(_) | Err(_) => Err(SyscallError::InvalidCapability),
    }
}

pub(crate) fn resolve_invoke_read_slot(
    cnode: &CNode,
    addr: u64,
    depth: u8,
) -> Result<(*mut CNode, usize), SyscallError> {
    resolve_invoke_read_slot_cap_error(cnode, addr, depth)
        .map_err(|_| SyscallError::InvalidCapability)
}

pub(crate) fn resolve_invoke_read_slot_cap_error(
    cnode: &CNode,
    addr: u64,
    depth: u8,
) -> Result<(*mut CNode, usize), CapError> {
    if is_current_root_cspace(cnode) {
        resolve_current_root_read_slot_cap_error(addr)
    } else if depth == 0 {
        let index = addr as usize;
        if cnode.get_ref(index).is_some() {
            Ok((cnode as *const CNode as *mut CNode, index))
        } else {
            Err(CapError::SlotEmpty)
        }
    } else {
        crate::cap::cnode::resolve_address_for_slot(cnode, addr, depth)
    }
}

pub(crate) fn resolve_invoke_write_slot(
    cnode: &CNode,
    addr: u64,
    depth: u8,
) -> Result<(*mut CNode, usize), SyscallError> {
    resolve_invoke_write_slot_cap_error(cnode, addr, depth)
        .map_err(|_| SyscallError::InvalidCapability)
}

pub(crate) fn resolve_invoke_write_slot_cap_error(
    cnode: &CNode,
    addr: u64,
    depth: u8,
) -> Result<(*mut CNode, usize), CapError> {
    if is_current_root_cspace(cnode) {
        resolve_current_root_write_slot_cap_error(addr)
    } else if depth == 0 {
        let index = addr as usize;
        if index < cnode.num_slots() {
            Ok((cnode as *const CNode as *mut CNode, index))
        } else {
            Err(CapError::InvalidSlot)
        }
    } else {
        crate::cap::cnode::resolve_address_for_slot(cnode, addr, depth)
    }
}

pub(crate) fn resolve_cnode_copy_slots(
    src_root: &CNode,
    src_slot: u64,
    dest_root: &CNode,
    dest_slot: u64,
) -> Result<CnodeCopySlots, SyscallError> {
    let (src_depth, dest_depth) = current_invoke_depths();
    let (src_leaf, src_idx) =
        match resolve_invoke_read_slot_cap_error(src_root, src_slot, src_depth) {
            Ok(v) => v,
            Err(e) => {
                crate::kernel::printk::ktrace!(cap, |g| {
                    g.puts("[CAP] cnode_copy resolve failed phase=src_read src_root=");
                    g.hex(src_root as *const CNode as u64);
                    g.puts(" src_slot=");
                    g.hex(src_slot);
                    g.puts(" src_depth=");
                    g.hex(src_depth as u64);
                    g.puts(" dest_root=");
                    g.hex(dest_root as *const CNode as u64);
                    g.puts(" dest_slot=");
                    g.hex(dest_slot);
                    g.puts(" dest_depth=");
                    g.hex(dest_depth as u64);
                    g.puts(" err=");
                    trace_cap_error_name(&g, e);
                    g.puts("\n");
                });
                return Err(super::syscall_error_from_cap_error(e));
            }
        };
    let (dest_leaf, dest_idx) =
        match resolve_invoke_write_slot_cap_error(dest_root, dest_slot, dest_depth) {
            Ok(v) => v,
            Err(e) => {
                crate::kernel::printk::ktrace!(cap, |g| {
                    g.puts("[CAP] cnode_copy resolve failed phase=dest_write src_root=");
                    g.hex(src_root as *const CNode as u64);
                    g.puts(" src_slot=");
                    g.hex(src_slot);
                    g.puts(" src_depth=");
                    g.hex(src_depth as u64);
                    g.puts(" dest_root=");
                    g.hex(dest_root as *const CNode as u64);
                    g.puts(" dest_slot=");
                    g.hex(dest_slot);
                    g.puts(" dest_depth=");
                    g.hex(dest_depth as u64);
                    g.puts(" err=");
                    trace_cap_error_name(&g, e);
                    g.puts("\n");
                });
                return Err(super::syscall_error_from_cap_error(e));
            }
        };
    Ok(CnodeCopySlots {
        src_leaf,
        src_idx,
        dest_leaf,
        dest_idx,
    })
}

pub(crate) fn resolve_cnode_move_slots(
    dest_root: &CNode,
    dest_slot: u64,
    src_root: &CNode,
    src_slot: u64,
) -> Result<CnodeCopySlots, SyscallError> {
    let (dest_depth, src_depth) = current_invoke_depths();
    let (dest_leaf, dest_idx) =
        match resolve_invoke_write_slot_cap_error(dest_root, dest_slot, dest_depth) {
            Ok(v) => v,
            Err(e) => {
                crate::kernel::printk::ktrace!(cap, |g| {
                    g.puts("[CAP] cnode_move resolve failed phase=dest_write dest_root=");
                    g.hex(dest_root as *const CNode as u64);
                    g.puts(" dest_slot=");
                    g.hex(dest_slot);
                    g.puts(" dest_depth=");
                    g.hex(dest_depth as u64);
                    g.puts(" src_root=");
                    g.hex(src_root as *const CNode as u64);
                    g.puts(" src_slot=");
                    g.hex(src_slot);
                    g.puts(" src_depth=");
                    g.hex(src_depth as u64);
                    g.puts(" err=");
                    trace_cap_error_name(&g, e);
                    g.puts("\n");
                });
                return Err(super::syscall_error_from_cap_error(e));
            }
        };
    let (src_leaf, src_idx) =
        match resolve_invoke_read_slot_cap_error(src_root, src_slot, src_depth) {
            Ok(v) => v,
            Err(e) => {
                crate::kernel::printk::ktrace!(cap, |g| {
                    g.puts("[CAP] cnode_move resolve failed phase=src_read dest_root=");
                    g.hex(dest_root as *const CNode as u64);
                    g.puts(" dest_slot=");
                    g.hex(dest_slot);
                    g.puts(" dest_depth=");
                    g.hex(dest_depth as u64);
                    g.puts(" src_root=");
                    g.hex(src_root as *const CNode as u64);
                    g.puts(" src_slot=");
                    g.hex(src_slot);
                    g.puts(" src_depth=");
                    g.hex(src_depth as u64);
                    g.puts(" err=");
                    trace_cap_error_name(&g, e);
                    g.puts("\n");
                });
                return Err(super::syscall_error_from_cap_error(e));
            }
        };
    Ok(CnodeCopySlots {
        src_leaf,
        src_idx,
        dest_leaf,
        dest_idx,
    })
}

pub(crate) fn resolve_cnode_write_slot(
    cnode_root: &CNode,
    slot: u64,
) -> Result<CnodeWriteSlot, SyscallError> {
    let (depth, _) = current_invoke_depths();
    let (leaf, idx) = resolve_invoke_write_slot_cap_error(cnode_root, slot, depth)
        .map_err(super::syscall_error_from_cap_error)?;
    Ok(CnodeWriteSlot { leaf, idx })
}

pub(crate) fn resolve_cnode_copy_request(
    src_root: &CNode,
    src_slot: u64,
    dest_cnode_cap_ptr: u64,
    dest_slot: u64,
    rights_bits: u64,
) -> Result<CnodeCopyRequest, SyscallError> {
    let dest_cnode = match lookup_cnode_root(dest_cnode_cap_ptr, CapRights::WRITE) {
        Ok(v) => v,
        Err(e) => {
            crate::kernel::printk::ktrace!(cap, |g| {
                g.puts("[CAP] cnode_copy resolve failed phase=dest_cnode_lookup src_root=");
                g.hex(src_root as *const CNode as u64);
                g.puts(" src_slot=");
                g.hex(src_slot);
                g.puts(" dest_cnode_cap=");
                g.hex(dest_cnode_cap_ptr);
                g.puts(" dest_slot=");
                g.hex(dest_slot);
                g.puts(" err=");
                g.hex(e as u64);
                g.puts("\n");
            });
            return Err(e);
        }
    };
    let slots = resolve_cnode_copy_slots(src_root, src_slot, unsafe { &*dest_cnode }, dest_slot)?;
    Ok(CnodeCopyRequest {
        slots,
        rights: CapRights::from_bits(rights_bits as u32),
    })
}

/// Resolve the source MemoryObject (addressed in the current root CSpace at
/// `src_mo_cap_ptr`) and the destination (`dest_cnode_cap_ptr` / `dest_slot`)
/// for `mo_mark_executable`. Reuses the cnode-copy slot resolution; the rights
/// field is unused because the conferral rights are fixed.
pub(crate) fn resolve_confer_exec_request(
    src_mo_cap_ptr: u64,
    dest_cnode_cap_ptr: u64,
    dest_slot: u64,
) -> Result<CnodeCopyRequest, SyscallError> {
    let root = current_root_cspace();
    if root.is_null() {
        return Err(SyscallError::InvalidOperation);
    }
    resolve_cnode_copy_request(
        unsafe { &*root },
        src_mo_cap_ptr,
        dest_cnode_cap_ptr,
        dest_slot,
        0,
    )
}

pub(crate) fn resolve_cnode_move_request(
    dest_root: &CNode,
    dest_slot: u64,
    src_cnode_cap_ptr: u64,
    src_slot: u64,
) -> Result<CnodeMoveRequest, SyscallError> {
    let src_cnode = match lookup_cnode_root(src_cnode_cap_ptr, CapRights::WRITE) {
        Ok(v) => v,
        Err(e) => {
            crate::kernel::printk::ktrace!(cap, |g| {
                g.puts("[CAP] cnode_move resolve failed phase=src_cnode_lookup dest_root=");
                g.hex(dest_root as *const CNode as u64);
                g.puts(" dest_slot=");
                g.hex(dest_slot);
                g.puts(" src_cnode_cap=");
                g.hex(src_cnode_cap_ptr);
                g.puts(" src_slot=");
                g.hex(src_slot);
                g.puts(" err=");
                g.hex(e as u64);
                g.puts("\n");
            });
            return Err(e);
        }
    };
    let slots = resolve_cnode_move_slots(dest_root, dest_slot, unsafe { &*src_cnode }, src_slot)?;
    Ok(CnodeMoveRequest { slots })
}

pub(crate) fn resolve_cnode_write_request(
    cnode_root: &CNode,
    slot: u64,
) -> Result<CnodeWriteRequest, SyscallError> {
    Ok(CnodeWriteRequest {
        slot: resolve_cnode_write_slot(cnode_root, slot)?,
    })
}

pub(crate) fn resolve_untyped_retype_request(
    current_tcb: *mut Tcb,
    cap_ptr: u64,
    dest_offset: u64,
) -> Result<UntypedRetypeRequest, SyscallError> {
    unsafe {
        if current_tcb.is_null() || (*current_tcb).cspace_root.is_null() {
            return Err(SyscallError::InvalidOperation);
        }

        let cspace = &mut *(*current_tcb).cspace_root;
        let untyped_slot = resolve_current_root_cap_slot(cspace, cap_ptr)?;
        let (dest_depth, _) = read_invoke_depths(current_tcb);
        let (dest_leaf, dest_idx) = if dest_depth > 0 {
            resolve_invoke_write_slot(cspace, dest_offset, dest_depth)?
        } else if (dest_offset as usize) < cspace.num_slots() {
            (cspace as *const CNode as *mut CNode, dest_offset as usize)
        } else {
            return Err(SyscallError::InvalidCapability);
        };

        Ok(UntypedRetypeRequest {
            untyped_slot,
            dest_leaf,
            dest_idx,
        })
    }
}

pub(crate) fn resolve_untyped_reset_request(
    current_tcb: *mut Tcb,
    cap_ptr: u64,
) -> Result<UntypedResetRequest, SyscallError> {
    unsafe {
        if current_tcb.is_null() || (*current_tcb).cspace_root.is_null() {
            return Err(SyscallError::InvalidOperation);
        }

        let cspace = &mut *(*current_tcb).cspace_root;
        Ok(UntypedResetRequest {
            untyped_slot: resolve_current_root_cap_slot(cspace, cap_ptr)?,
        })
    }
}
