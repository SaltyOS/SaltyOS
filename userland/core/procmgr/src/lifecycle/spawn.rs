//! Transactional spawn pipeline
//!
//! Uses the centralized allocator for slot management and rollback-safe
//! object creation. Replaces the stride-based handle_spawn.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona::types::core::*;
use crate::base::alloc::Allocator;
use crate::base::mmsrv_ipc;
use crate::loader::stack_build::{
    alloc_zeroed_staged_stack_page, append_nul_terminated_bytes, commit_staged_top_stack_page,
    pack_spawn_argv_strings, write_dynamic_stack,
};
use crate::personality::PersonalityKind;
use crate::base::proc_table;

use crate::loader::mem_util::{free_staging_buffer};

pub(crate) fn compute_ready_timeout_ns(
    configured_timeout_ns: u64,
    is_dynamic: bool,
    elf_size_bytes: usize,
    lib_window_pages: usize,
) -> u64 {
    if configured_timeout_ns != 0 {
        return configured_timeout_ns;
    }

    let mut timeout_ns = crate::READY_TIMEOUT_NS_DEFAULT;
    if is_dynamic {
        timeout_ns = timeout_ns.saturating_add(3_000_000_000);
    }

    let elf_chunks = ((elf_size_bytes as u64).saturating_add(128 * 1024 - 1)) / (128 * 1024);
    let elf_bonus_ms = core::cmp::min(elf_chunks.saturating_mul(150), 4_000);
    timeout_ns = timeout_ns.saturating_add(elf_bonus_ms.saturating_mul(1_000_000));

    let lib_bonus_ms = core::cmp::min(lib_window_pages as u64 * 8, 3_000);
    timeout_ns.saturating_add(lib_bonus_ms.saturating_mul(1_000_000))
}

// Layout offsets within a reservation (sequential, not absolute cap slots).
const OFF_TCB: usize = 0;
const OFF_VSPACE: usize = 1;
const OFF_CNODE: usize = 2;
const OFF_SC: usize = 3;
const OFF_STACK_FR: usize = 4;
const OFF_IPC_FR: usize = 5;
const OFF_SIGNAL_NTFN: usize = 6;
#[allow(dead_code)]
const OFF_READY_NTFN: usize = 7;
pub(crate) const OFF_FIXED_END: usize = 8;

const OBJ_TCB: u64 = trona::OBJ_TCB;
const OBJ_VSPACE: u64 = trona::OBJ_VSPACE;
const OBJ_CNODE: u64 = trona::OBJ_CNODE;
const OBJ_SCHED_CONTEXT: u64 = trona::OBJ_SCHED_CONTEXT;
const OBJ_FRAME: u64 = trona::OBJ_FRAME;
const OBJ_NOTIFICATION: u64 = trona::OBJ_NOTIFICATION;
const TRONA_OK: u64 = trona::TRONA_OK;
const TRONA_OUT_OF_MEMORY: u64 = trona::TRONA_OUT_OF_MEMORY;
const TRONA_NOT_FOUND: u64 = trona::TRONA_NOT_FOUND;
const TRONA_BUSY: u64 = trona::TRONA_BUSY;
const TRONA_OUT_OF_RANGE: u64 = trona::TRONA_OUT_OF_RANGE;
const TRONA_INVALID_ARGUMENT: u64 = trona::TRONA_INVALID_ARGUMENT;
const VSPACE_FLAG_WRITABLE: u64 = trona::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = trona::VSPACE_FLAG_USER;
const CAP_RIGHTS_ALL: u64 = trona::CAP_RIGHTS_ALL;
const INITRD_COPY_RIGHTS: u64 = (1 << 0) | (1 << 2) | (1 << 3);

use trona::layout::{self, CspaceLayoutProfile, VmLayoutPlan};

use crate::base::child_layout::{ChildCapLayout, ChildSlotAlloc, CHILD_RTLD_FRAME_SLOT_START};
const CAP_SELF_CSPACE: Cap = crate::CAP_SELF_CSPACE;
const CAP_RECV_SCRATCH: Cap = crate::CAP_RECV_SCRATCH;
const CAP_REPLY_TEMP: Cap = crate::CAP_REPLY_TEMP;
const SPAWN_FLAG_USE_PRE_EP: u64 = trona::SPAWN_FLAG_USE_PRE_EP;


use crate::loader::stack_build::StackBuildError;

const SPAWN_FLAG_RESPAWN: u64 = trona::SPAWN_FLAG_RESPAWN;
const SPAWN_FLAG_START_SUSPENDED: u64 = trona::SPAWN_FLAG_START_SUSPENDED;

pub(crate) struct SpawnPlan {
    pub(crate) is_dynamic: bool,
    pub(crate) readiness_mode: u64,
    pub(crate) ready_timeout_ns: u64,
    pub(crate) total_slots: usize,
    pub(crate) is_display: bool,
    pub(crate) lib_window_pages: usize,
    pub(crate) layout: VmLayoutPlan,
}

pub(crate) struct SpawnChildBase {
    pub(crate) slot_idx: usize,
    pub(crate) pid: u32,
    pub(crate) child_tcb: Cap,
    pub(crate) child_vs: Cap,
    pub(crate) child_cn: Cap,
    pub(crate) child_sc: Cap,
    pub(crate) child_sig_ntfn: Cap,
    pub(crate) ready_badge_bit: u8,
    pub(crate) cn_size_bits: u64,
    pub(crate) cap_layout: ChildCapLayout,
}

unsafe fn prepopulate_spawn_process(
    slot_idx: usize,
    kind: PersonalityKind,
    start_suspended: bool,
    pid: u32,
    child_tcb: Cap,
    child_vs: Cap,
    child_cn: Cap,
    child_sc: Cap,
    shared_lib_base: u64,
    layout: VmLayoutPlan,
    use_pre_ep: bool,
    cap_layout: ChildCapLayout,
) {
    unsafe {
        let p = proc_table::proctab(slot_idx);
        p.set_personality_kind(kind);
        p.state = if start_suspended {
            proc_table::ProcessState::Stopped
        } else {
            proc_table::ProcessState::Running
        };
        p.tcb_cap = child_tcb;
        p.vspace_cap = child_vs;
        p.cnode_cap = child_cn;
        p.sc_cap = child_sc;
        p.pid = pid;
        p.badge = pid as u64;
        p.shared_lib_base = shared_lib_base;
        p.layout = layout;
        p.has_service_ep = use_pre_ep;
        p.mmsrv_registered = true;
        p.start_time_ns = proc_table::monotonic_now_ns();
        p.cap_layout = cap_layout;
    }
}

unsafe fn commit_spawn_process(
    slot_idx: usize,
    caller_badge: u64,
    kind: PersonalityKind,
    start_suspended: bool,
    pid: u32,
    child_tcb: Cap,
    child_vs: Cap,
    child_cn: Cap,
    child_sc: Cap,
    slot_base: Cap,
    slot_count: u16,
    shared_lib_base: u64,
    lib_map: proc_table::ProcLibMap,
    layout: VmLayoutPlan,
    use_pre_ep: bool,
    ready_badge_bit: u8,
    is_notify: bool,
    ready_timeout_ns: u64,
    cap_layout: ChildCapLayout,
) -> Option<usize> {
    unsafe {
        let caller_idx = proc_table::find_by_badge(caller_badge);
        let parent_pid = if let Some(ci) = caller_idx {
            proc_table::proctab(ci).pid
        } else {
            0
        };

        let p = proc_table::proctab(slot_idx);
        p.set_personality_kind(kind);
        p.pid = pid;
        p.ppid = parent_pid;
        p.state = if start_suspended {
            proc_table::ProcessState::Stopped
        } else {
            proc_table::ProcessState::Running
        };
        p.exit_code = 0;
        p.badge = pid as u64;
        p.tcb_cap = child_tcb;
        p.vspace_cap = child_vs;
        p.cnode_cap = child_cn;
        p.sc_cap = child_sc;
        p.slot_base = slot_base;
        p.slot_count = slot_count;
        p.shared_lib_base = shared_lib_base;
        p.lib_map = lib_map;
        p.layout = layout;
        p.has_service_ep = use_pre_ep;
        p.mmsrv_registered = true;
        p.start_time_ns = proc_table::monotonic_now_ns();
        p.ready_badge_bit = ready_badge_bit;
        p.wait_ready_on_resume = start_suspended && is_notify;
        p.ready_timeout_ns = if is_notify { ready_timeout_ns } else { 0 };
        p.cap_layout = cap_layout;

        caller_idx
    }
}

unsafe fn initialize_spawn_process_common(
    p: &mut proc_table::Process,
    caller_idx: Option<usize>,
    pid: u32,
    child_sig_ntfn: Cap,
    exec_path: &[u8],
    exec_path_len: usize,
) {
    unsafe {
        p.sid = if let Some(ci) = caller_idx {
            proc_table::proctab(ci).sid
        } else {
            pid
        };
        p.ctty_dev = if let Some(ci) = caller_idx {
            proc_table::proctab(ci).ctty_dev
        } else {
            0
        };
        p.ctty_pgrp = if let Some(ci) = caller_idx {
            proc_table::proctab(ci).ctty_pgrp
        } else {
            0
        };
        p.signal_ntfn = child_sig_ntfn;
        p.pgid = if let Some(ci) = caller_idx {
            proc_table::proctab(ci).pgid
        } else {
            pid
        };

        let exe_copy = if exec_path_len >= proc_table::MAX_EXE_PATH_LEN {
            proc_table::MAX_EXE_PATH_LEN - 1
        } else {
            exec_path_len
        };
        p.waiter_reply = 0;
        p.waiter_pid = 0;
        p.any_waiter_reply = 0;
        p.waiting_for_any = 0;
        p.stop_status = 0;
        for i in 0..exe_copy {
            p.exe_path[i] = exec_path[i];
        }
        for i in exe_copy..proc_table::MAX_EXE_PATH_LEN {
            p.exe_path[i] = 0;
        }
    }
}

unsafe fn initialize_posix_spawn_process(p: &mut proc_table::Process) {
    let posix = p.posix_mut();
    for i in 0..proc_table::NSIG {
        posix.sig_disposition[i] = proc_table::SIG_DISP_DFL;
    }
}

fn set_process_name(p: &mut proc_table::Process, name: &[u8], name_len: usize) {
    let name_copy = if name_len > 31 { 31 } else { name_len };
    for i in 0..name_copy {
        p.name[i] = name[i];
    }
    for i in name_copy..32 {
        p.name[i] = 0;
    }
}

fn set_respawn_binary(p: &mut proc_table::Process, name: &[u8], name_len: usize) {
    let copy_len = if name_len > proc_table::MAX_NAME_LEN {
        proc_table::MAX_NAME_LEN
    } else {
        name_len
    };
    for i in 0..copy_len {
        p.respawn_binary[i] = name[i];
    }
    for i in copy_len..proc_table::MAX_NAME_LEN {
        p.respawn_binary[i] = 0;
    }
}


unsafe fn maybe_defer_spawn_readiness(
    slot_idx: usize,
    start_suspended: bool,
    is_notify: bool,
) -> bool {
    unsafe {
        if !start_suspended && is_notify {
            if crate::base::readiness::defer_readiness(slot_idx) {
                return true;
            }

            // Defer failed (OOM) — graceful degradation: clear readiness fields
            // and reply immediately. The child is already running.
            let p = proc_table::proctab(slot_idx);
            crate::base::readiness::free_readiness_bit(p.ready_badge_bit);
            p.ready_badge_bit = crate::base::readiness::BIT_NONE;
            p.ready_timeout_ns = 0;
        }
        false
    }
}

unsafe fn cleanup_prepopulated_spawn_process(slot_idx: usize) {
    unsafe {
        core::ptr::write(
            proc_table::proctab(slot_idx) as *mut proc_table::Process,
            proc_table::Process::zeroed(),
        );
    }
}

pub(crate) unsafe fn configure_spawn_scheduler(
    alloc: &mut Allocator,
    reply: &mut TronaMsg,
    pid: u32,
    child_tcb: Cap,
    child_sc: Cap,
) -> bool {
    let err = trona::invoke::sc_configure(child_sc, 10000, 100000);
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] SC configure failed\n");
        });
        mmsrv_ipc::deregister_from_mmsrv(pid);
        alloc.rollback(trona::caps::rsrcsrv_ep());
        reply.label = TRONA_OUT_OF_MEMORY;
        return false;
    }
    let err = trona::invoke::sc_bind(child_sc, child_tcb);
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] SC bind failed\n");
        });
        mmsrv_ipc::deregister_from_mmsrv(pid);
        alloc.rollback(trona::caps::rsrcsrv_ep());
        reply.label = TRONA_OUT_OF_MEMORY;
        return false;
    }
    true
}

unsafe fn map_spawn_ipc_buffer(
    alloc: &mut Allocator,
    reply: &mut TronaMsg,
    pid: u32,
    ipc_buf_base: u64,
    log_prefix: &[u8],
) -> bool {
    unsafe {
        let mut mm_msg = TronaMsg::zeroed();
        let mut mm_reply = TronaMsg::zeroed();
        mm_msg.label = trona::protocol::MM_MAP_BATCH;
        mm_msg.length = 4;
        mm_msg.regs[0] = pid as u64;
        mm_msg.regs[1] = ipc_buf_base;
        mm_msg.regs[2] = 1;
        mm_msg.regs[3] = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
        let err = trona::ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const mm_msg,
            &raw mut mm_reply,
        );
        if err != 0 || mm_reply.label != TRONA_OK || mm_reply.regs[0] != 1 {
            trona::uerror!(|_lb| {
                _lb.bytes(log_prefix);
                _lb.str(b"MM_MAP_BATCH ipc failed err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(mm_reply.label);
                _lb.str(b" mapped=");
                _lb.hex(mm_reply.regs[0]);
                _lb.str(b" pid=");
                _lb.hex(pid as u64);
                _lb.str(b"\n");
            });
            mmsrv_ipc::deregister_from_mmsrv(pid);
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        true
    }
}


pub(crate) unsafe fn effective_child_cnode_bits(child_cn: Cap) -> u64 {
    unsafe {
        let mut cnode_bits: u64 = 10;
        let cinfo = trona::invoke::cnode_get_info(child_cn);
        if cinfo.error == 0 {
            let ctx = &*crate::ipc_ctx();
            if !ctx.ipc_buffer.is_null() {
                let buf = &*ctx.ipc_buffer;
                let bits = buf.msg[2];
                if bits >= 4 && bits <= 16 {
                    cnode_bits = bits;
                }
            }
        }
        cnode_bits
    }
}

pub(crate) unsafe fn child_service_cspace_layout(
    child_cn: Cap,
    frame_slot_start: u64,
) -> trona::TronaCspaceLayoutV1 {
    unsafe {
        let cnode_bits = effective_child_cnode_bits(child_cn);
        service_cspace_layout(cnode_bits, frame_slot_start)
    }
}

pub(crate) fn service_cspace_layout(
    cnode_bits: u64,
    frame_slot_start: u64,
) -> trona::TronaCspaceLayoutV1 {
    layout::compute_cspace_layout(
        cnode_bits,
        frame_slot_start,
        CspaceLayoutProfile::DefaultService,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn finalize_spawn_launch(
    alloc: &mut Allocator,
    reply: &mut TronaMsg,
    badge: u64,
    kind: PersonalityKind,
    plan: &SpawnPlan,
    start_suspended: bool,
    spawn_flags: u64,
    slot_idx: usize,
    pid: u32,
    child_tcb: Cap,
    child_vs: Cap,
    child_cn: Cap,
    child_sc: Cap,
    ready_badge_bit: u8,
    child_sig_ntfn: Cap,
    shared_lib_base: u64,
    lib_map: proc_table::ProcLibMap,
    use_pre_ep: bool,
    name: &[u8],
    name_len: usize,
    exec_path: &[u8],
    exec_path_len: usize,
    child_entry_rip: u64,
    child_rsp: u64,
    start_log_prefix: &[u8],
    cap_layout: ChildCapLayout,
) -> bool {
    unsafe {
        if !map_spawn_ipc_buffer(
            alloc,
            reply,
            pid,
            plan.layout.ipc_buf.base,
            start_log_prefix,
        ) {
            return false;
        }

        let err = trona::invoke::tcb_configure(child_tcb, child_entry_rip, child_rsp, 0);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] TCB configure failed\n");
            });
            crate::base::readiness::free_readiness_bit(ready_badge_bit);
            mmsrv_ipc::deregister_from_mmsrv(pid);
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        let err = trona::invoke::tcb_set_ipc_buffer(child_tcb, plan.layout.ipc_buf.base);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] set child IPC buffer failed\n");
            });
            crate::base::readiness::free_readiness_bit(ready_badge_bit);
            mmsrv_ipc::deregister_from_mmsrv(pid);
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }

        prepopulate_spawn_process(
            slot_idx,
            kind,
            start_suspended,
            pid,
            child_tcb,
            child_vs,
            child_cn,
            child_sc,
            shared_lib_base,
            plan.layout,
            use_pre_ep,
            cap_layout,
        );

        let is_notify = plan.readiness_mode == trona::SPAWN_READY_NOTIFY;
        // Pre-register the pending readiness wait (before tcb_resume) so the
        // `pending_ready_reply != 0` invariant is established before the
        // child can deliver its first `SYS_SIGNAL`. Otherwise an early-signal
        // race could OR a badge bit into procmgr's notification word before
        // proctab knows it is waiting.
        if !start_suspended && is_notify {
            // Transiently copy the bit into proctab so `defer_readiness`
            // (which looks it up in the udebug trace) sees the assignment.
            // commit_spawn_process below will rewrite the full proctab
            // entry, preserving `ready_badge_bit`.
            proc_table::proctab(slot_idx).ready_badge_bit = ready_badge_bit;
        }

        if !start_suspended {
            let err = trona::invoke::tcb_resume(child_tcb);
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] TCB resume failed\n");
                });
                crate::base::readiness::free_readiness_bit(ready_badge_bit);
                cleanup_prepopulated_spawn_process(slot_idx);
                mmsrv_ipc::deregister_from_mmsrv(pid);
                alloc.rollback(trona::caps::rsrcsrv_ep());
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        let (slot_base, slot_count) = alloc.commit();
        let caller_idx = commit_spawn_process(
            slot_idx,
            badge,
            kind,
            start_suspended,
            pid,
            child_tcb,
            child_vs,
            child_cn,
            child_sc,
            slot_base,
            slot_count,
            shared_lib_base,
            lib_map,
            plan.layout,
            use_pre_ep,
            ready_badge_bit,
            is_notify,
            plan.ready_timeout_ns,
            cap_layout,
        );

        {
            let p = proc_table::proctab(slot_idx);
            set_process_name(p, name, name_len);
            initialize_spawn_process_common(
                p,
                caller_idx,
                pid,
                child_sig_ntfn,
                exec_path,
                exec_path_len,
            );
            if p.is_posix() {
                initialize_posix_spawn_process(p);
            }

            if (spawn_flags & SPAWN_FLAG_RESPAWN) != 0 {
                p.respawn = true;
                set_respawn_binary(p, name, name_len);
            }
        }

        if maybe_defer_spawn_readiness(slot_idx, start_suspended, is_notify) {
            return true;
        }

        trona::udebug!(|_lb| {
            _lb.bytes(start_log_prefix);
            _lb.str(b"process started PID=");
            _lb.hex(pid as u64);
            _lb.str(b"\n");
        });
        reply.label = TRONA_OK;
        reply.length = 1;
        reply.regs[0] = pid as u64;
        false
    }
}

unsafe fn ensure_caller_registered_posix(badge: u64) {
    unsafe {
        let caller_idx = proc_table::find_by_badge(badge);
        if caller_idx.is_none() && badge != 0 {
            if let Some(ci) = proc_table::alloc_proc() {
                let p = proc_table::proctab(ci);
                p.set_personality_kind(PersonalityKind::Posix);
                p.pid = badge as u32;
                p.ppid = 0;
                p.state = proc_table::ProcessState::Running;
                p.badge = badge;
                p.start_time_ns = proc_table::monotonic_now_ns();
                p.sid = badge as u32;
                p.pgid = badge as u32;
                p.ctty_dev = 0;
                p.ctty_pgrp = 0;
            }
        }
    }
}

pub(crate) unsafe fn prepare_spawn_child_base(
    alloc: &mut Allocator,
    reply: &mut TronaMsg,
    badge: u64,
    plan: &SpawnPlan,
    policy_cnode_bits: u8,
    use_pre_ep: bool,
) -> Option<SpawnChildBase> {
    unsafe {
        ensure_caller_registered_posix(badge);

        let slot_idx = match proc_table::alloc_proc() {
            Some(idx) => idx,
            None => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] process table full\n");
                });
                reply.label = TRONA_OUT_OF_MEMORY;
                return None;
            }
        };
        proc_table::proctab(slot_idx).state = proc_table::ProcessState::Spawning;

        let pid = proc_table::NEXT_PID;
        proc_table::NEXT_PID += 1;

        if !alloc.reserve(pid as u64, plan.total_slots) {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] slot reservation failed\n");
            });
            reply.label = TRONA_OUT_OF_MEMORY;
            return None;
        }

        macro_rules! realize_mm {
            ($ty:expr, $sz:expr, $off:expr, $what:expr) => {
                match alloc.realize_via_rsrcsrv_at(trona::caps::rsrcsrv_ep(), $ty, $sz, $off) {
                    Ok(s) => s,
                    Err(e) => {
                        trona::uerror!(|_lb| {
                            _lb.str(b"[PROCMGR] alloc ");
                            _lb.bytes($what);
                            _lb.str(b" failed err=");
                            _lb.hex(e as u64);
                            _lb.str(b"\n");
                        });
                        alloc.rollback(trona::caps::rsrcsrv_ep());
                        reply.label = TRONA_OUT_OF_MEMORY;
                        return None;
                    }
                }
            };
        }

        let child_tcb = realize_mm!(OBJ_TCB, 0, OFF_TCB, b"TCB");
        let child_vs = realize_mm!(OBJ_VSPACE, 0, OFF_VSPACE, b"VSpace");
        let cn_size_bits = if policy_cnode_bits > 0 {
            policy_cnode_bits as u64
        } else {
            0
        };
        let child_cn = realize_mm!(OBJ_CNODE, cn_size_bits, OFF_CNODE, b"CNode");
        let child_sc = realize_mm!(OBJ_SCHED_CONTEXT, 0, OFF_SC, b"SC");
        let child_sig_ntfn = realize_mm!(OBJ_NOTIFICATION, 0, OFF_SIGNAL_NTFN, b"signal ntfn");
        // Allocate a readiness badge bit for Type=notify services. The
        // badge slot within procmgr's bound notification is per-spawn and
        // is released in `complete_readiness_{ok,timeout}` or on spawn
        // rollback (see the handful of error paths below that call
        // `release_readiness_bit_on_rollback`).
        let ready_badge_bit = if plan.readiness_mode == trona::SPAWN_READY_NOTIFY {
            match crate::base::readiness::alloc_readiness_bit() {
                Some(b) => b,
                None => {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] readiness bitmap exhausted\n");
                    });
                    alloc.rollback(trona::caps::rsrcsrv_ep());
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return None;
                }
            }
        } else {
            crate::base::readiness::BIT_NONE
        };

        // Allocate the child cspace layout from a dynamic cursor. All
        // well-known well-known slots below CHILD_RTLD_FRAME_SLOT_START are
        // drawn in order; the child reads them back through `AT_TRONA_*`
        // auxv tags (delivered via the auxv emit sites further below).
        let cap_layout = {
            let mut slot_alloc = ChildSlotAlloc::new(0, CHILD_RTLD_FRAME_SLOT_START);
            match ChildCapLayout::from_alloc(&mut slot_alloc) {
                Some(l) => l,
                None => {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] child cspace cursor exhausted\n");
                    });
                    crate::base::readiness::free_readiness_bit(ready_badge_bit);
                    alloc.rollback(trona::caps::rsrcsrv_ep());
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return None;
                }
            }
        };

        let err = trona::invoke::cnode_mint(
            CAP_SELF_CSPACE,
            crate::base::cap_helpers::mmsrv_authority_raw(),
            child_cn,
            cap_layout.mmsrv_ep,
            pid as u64,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] mint mmsrv EP into child failed err=");
                _lb.hex(err as u64);
                _lb.str(b" child_cn=");
                _lb.hex(child_cn);
                _lb.str(b" dst_slot=");
                _lb.hex(cap_layout.mmsrv_ep);
                _lb.str(b"\n");
            });
            crate::base::readiness::free_readiness_bit(ready_badge_bit);
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = TRONA_OUT_OF_MEMORY;
            return None;
        }

        // Mint rsrcsrv EP into the child's cursor-allocated rsrcsrv slot
        // (badged with child pid) so the child can call RES_ALLOC_OBJECT for
        // itself.
        let err = trona::invoke::cnode_mint(
            CAP_SELF_CSPACE,
            crate::base::cap_helpers::rsrcsrv_authority_raw(),
            child_cn,
            cap_layout.rsrcsrv_ep,
            pid as u64,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] mint rsrcsrv EP into child failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            crate::base::readiness::free_readiness_bit(ready_badge_bit);
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = TRONA_OUT_OF_MEMORY;
            return None;
        }

        let err = copy_child_caps_tx(
            child_tcb,
            child_vs,
            child_cn,
            child_sc,
            child_sig_ntfn,
            ready_badge_bit,
            plan.readiness_mode == trona::SPAWN_READY_NOTIFY,
            plan.is_display,
            pid,
            if use_pre_ep { CAP_RECV_SCRATCH } else { 0 },
            &cap_layout,
        );
        if err != 0 {
            crate::base::readiness::free_readiness_bit(ready_badge_bit);
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = TRONA_OUT_OF_MEMORY;
            return None;
        }

        // CSpace expansion is handled by procmgr's own bound-notification
        // path — children are registered in the CLIENTS table at spawn time.
        // The client's bound-ntfn slot was chosen by the cursor above and is
        // delivered to the child via `AT_TRONA_CSPACE_NTFN`.
        crate::base::cspace::register_client(pid as u64, child_cn, cap_layout.cspace_ntfn);

        let err = trona::invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] TCB set_space failed\n");
            });
            crate::base::readiness::free_readiness_bit(ready_badge_bit);
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = TRONA_OUT_OF_MEMORY;
            return None;
        }

        {
            let temp_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] fault EP slot alloc failed\n");
                    });
                    crate::base::readiness::free_readiness_bit(ready_badge_bit);
                    alloc.rollback(trona::caps::rsrcsrv_ep());
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return None;
                }
            };
            let err = trona::invoke::cnode_mint(
                CAP_SELF_CSPACE,
                crate::base::cap_helpers::mmsrv_authority_raw(),
                CAP_SELF_CSPACE,
                temp_slot,
                pid as u64,
            );
            if err != 0 {
                trona::uwarn!(|_lb| {
                    _lb.str(b"[PROCMGR] WARN: fault EP mint failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b" temp_slot=");
                    _lb.hex(temp_slot);
                    _lb.str(b"\n");
                });
            } else {
                let err2 = trona::invoke::tcb_set_fault_handler(child_tcb, temp_slot);
                if err2 != 0 {
                    trona::uwarn!(|_lb| {
                        _lb.str(b"[PROCMGR] WARN: tcb_set_fault_handler failed err=");
                        _lb.hex(err2 as u64);
                        _lb.str(b"\n");
                    });
                }
            }
            trona::invoke::cnode_delete(CAP_SELF_CSPACE, temp_slot);
            alloc.free_single_slot(temp_slot);
        }

        let heap_base = plan.layout.heap_base();
        let mmap_base = trona::layout::compute_mmap_base(&plan.layout, heap_base);
        if !mmsrv_ipc::register_with_mmsrv(pid, child_vs, heap_base, mmap_base) {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] SPAWN: mmsrv register failed\n");
            });
            crate::base::readiness::free_readiness_bit(ready_badge_bit);
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = TRONA_OUT_OF_MEMORY;
            return None;
        }

        Some(SpawnChildBase {
            slot_idx,
            pid,
            child_tcb,
            child_vs,
            child_cn,
            child_sc,
            child_sig_ntfn,
            ready_badge_bit,
            cn_size_bits,
            cap_layout,
        })
    }
}

/// Compute total slots needed for a spawn.
///
/// All frame allocation (ELF, RTLD, stack, initrd, boot info) is handled
/// by mmsrv. Procmgr only needs slots for the fixed kernel objects.
pub(crate) fn compute_slot_budget() -> usize {
    OFF_FIXED_END + 6 // 8 fixed slots + margin
}

/// Transactional spawn: preflight → reserve → realize → commit.
/// On any failure, rolls back all allocated objects and slots.
pub unsafe fn handle_spawn_tx(
    msg: &TronaMsg,
    reply: &mut TronaMsg,
    badge: u64,
    alloc: &mut Allocator,
) -> bool {
    unsafe {
        // Parse message — new wire format:
        //   regs[0] = name_len
        //   regs[1] = spawn_policy bitfield
        //   regs[2] = timeout_ns
        //   regs[3] = spawn_flags
        //   regs[4] = spawn_args_len (NUL-separated args bytes)
        //   regs[5..] = name bytes, then spawn args bytes
        let name_reg_idx = 5usize;
        let spawn_policy = msg.regs[1];
        let requested_timeout_ns = msg.regs[2];
        let spawn_flags = msg.regs[3];
        let spawn_args_len = msg.regs[4] as usize;
        let name_len_wire = msg.regs[0] as usize;
        let name_words = (name_len_wire + 7) / 8;
        let args_reg_idx = name_reg_idx + name_words;
        let use_pre_ep = (spawn_flags & SPAWN_FLAG_USE_PRE_EP) != 0;
        let start_suspended = (spawn_flags & SPAWN_FLAG_START_SUSPENDED) != 0;
        let readiness_mode = trona::spawn_policy_readiness(spawn_policy);
        let policy_map_initrd = trona::spawn_policy_map_initrd(spawn_policy);
        let policy_is_display = trona::spawn_policy_is_display(spawn_policy);
        let policy_cnode_bits = trona::spawn_policy_cnode_bits(spawn_policy);
        let (name, name_len) = crate::extract_name(msg, name_reg_idx);
        let mut exec_path = [0u8; proc_table::MAX_EXE_PATH_LEN];
        let exec_path_len = core::cmp::min(name_len, proc_table::MAX_EXE_PATH_LEN - 1);
        for i in 0..exec_path_len {
            exec_path[i] = name[i];
        }
        exec_path[exec_path_len] = 0;
        let base_start = crate::basename_of(&name, name_len);
        let is_display = policy_is_display;

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] SPAWN: '");
            _lb.bytes(&name[..name_len]);
            _lb.str(b"'\n");
        });

        let initrd = crate::INITRD_VADDR as *const u8;
        let initrd_size = crate::read_boot_info_initrd_size();

        // Strip leading '/' for CPIO lookup — archive uses "bin/foo" keys
        let cpio_off = if name_len > 0 && name[0] == b'/' {
            1
        } else {
            0
        };
        let cpio_name_ptr = name.as_ptr().add(cpio_off);
        let cpio_name_len = name_len - cpio_off;

        // Find ELF in initrd
        let mut elf_entry = CpioEntry::zeroed();
        let mut found = trona_loader::cpio::cpio_find_file(
            initrd,
            initrd_size,
            cpio_name_ptr,
            cpio_name_len,
            &raw mut elf_entry,
        ) != 0;
        if !found && cpio_name_len + 4 <= proc_table::MAX_NAME_LEN {
            let mut legacy = [0u8; proc_table::MAX_NAME_LEN + 5];
            for i in 0..cpio_name_len {
                legacy[i] = name[cpio_off + i];
            }
            legacy[cpio_name_len] = b'.';
            legacy[cpio_name_len + 1] = b'e';
            legacy[cpio_name_len + 2] = b'l';
            legacy[cpio_name_len + 3] = b'f';
            found = trona_loader::cpio::cpio_find_file(
                initrd,
                initrd_size,
                legacy.as_ptr(),
                cpio_name_len + 4,
                &raw mut elf_entry,
            ) != 0;
        }
        // VFS fallback: stream large ELFs instead of buffering the whole file.
        // Path is already absolute — no badge-based resolution needed.
        let mut vfs_source = crate::loader::vfs_load::VfsExecSource::none();
        if !found {
            if let Some(source) = crate::loader::vfs_load::try_open_exec_source_from_vfs(&name, name_len) {
                if let Some((data, data_len)) = source.buffered_data() {
                    elf_entry.data = data;
                    elf_entry.data_len = data_len;
                }
                found = true;
                vfs_source = source;
            }
        }
        if !found {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] binary not found in initrd or VFS\n");
            });
            reply.label = TRONA_NOT_FOUND;
            return false;
        }

        // ---- PE detection: check for MZ magic ----
        let is_pe = vfs_source.streamed().is_none()
            && elf_entry.data_len >= 2
            && trona_loader::pe_loader::pe_is_pe(elf_entry.data, elf_entry.data_len);
        let kind = if is_pe {
            PersonalityKind::Win32
        } else {
            PersonalityKind::Posix
        };
        let subsystem_id = kind.subsystem_id();

        if is_pe {
            // Delegate to PE-specific spawn path
            return crate::lifecycle::spawn_pe::handle_pe_spawn_inner(
                msg,
                reply,
                badge,
                alloc,
                elf_entry.data,
                elf_entry.data_len,
                &name,
                name_len,
                &exec_path,
                exec_path_len,
                kind,
                readiness_mode,
                requested_timeout_ns,
                spawn_flags,
                spawn_args_len,
                args_reg_idx,
                use_pre_ep,
                start_suspended,
                policy_map_initrd,
                policy_is_display,
                policy_cnode_bits,
                is_display,
            );
        }

        let vfs_stream = vfs_source.streamed();
        // ---- PREFLIGHT: Build SpawnPlan ----
        let Some(elf_runtime) = crate::loader::elf_load::plan_elf_runtime(
            elf_entry.data,
            elf_entry.data_len,
            vfs_stream,
            initrd,
            initrd_size,
            true || policy_map_initrd,
        ) else {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] ELF too large for VA layout\n");
            });
            crate::loader::vfs_load::cleanup_exec_source(&mut vfs_source);
            reply.label = TRONA_INVALID_ARGUMENT;
            return false;
        };
        let is_dynamic = elf_runtime.is_dynamic;

        let effective_timeout_ns = if readiness_mode == trona::SPAWN_READY_NOTIFY {
            compute_ready_timeout_ns(
                requested_timeout_ns,
                is_dynamic,
                if let Some(vfs) = vfs_stream {
                    vfs.file_size
                } else {
                    elf_entry.data_len
                },
                elf_runtime.lib_window_pages,
            )
        } else {
            0 // IMMEDIATE mode: no timeout needed
        };

        let plan = SpawnPlan {
            is_dynamic,
            readiness_mode,
            ready_timeout_ns: effective_timeout_ns,
            total_slots: compute_slot_budget(),
            is_display,
            lib_window_pages: elf_runtime.lib_window_pages,
            layout: elf_runtime.layout,
        };

        // Auto-register this child as a provider before its listener EP is
        // moved out of CAP_RECV_SCRATCH into the child's CSpace. The
        // adoption helper does a cnode_copy first, leaving the scratch slot
        // intact for the subsequent move inside copy_child_caps_tx.
        if use_pre_ep {
            let basename = &name[base_start..name_len];
            let _ = crate::service::registry::adopt_provider_from_scratch(basename);
        }

        let Some(base) =
            prepare_spawn_child_base(alloc, reply, badge, &plan, policy_cnode_bits, use_pre_ep)
        else {
            crate::loader::vfs_load::cleanup_exec_source(&mut vfs_source);
            return false;
        };

        let slot_idx = base.slot_idx;
        let pid = base.pid;
        let child_tcb = base.child_tcb;
        let child_vs = base.child_vs;
        let child_cn = base.child_cn;
        let child_sc = base.child_sc;
        let child_sig_ntfn = base.child_sig_ntfn;
        let ready_badge_bit = base.ready_badge_bit;
        let cn_size_bits = base.cn_size_bits;
        let cap_layout = base.cap_layout;
        let Some(elf_loads) = crate::loader::elf_load::load_elf_runtime(
            elf_entry.data,
            elf_entry.data_len,
            vfs_stream,
            &elf_runtime,
            initrd,
            initrd_size,
            pid,
            child_vs,
        ) else {
            crate::loader::vfs_load::cleanup_exec_source(&mut vfs_source);
            mmsrv_ipc::deregister_from_mmsrv(pid);
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = TRONA_NOT_FOUND;
            return false;
        };
        let elf_result = elf_loads.elf_result;
        let rtld_result = elf_loads.rtld_result;
        let shared_lib_base = elf_loads.shared_lib_base;
        let shared_lib_map = elf_loads.shared_lib_map;

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] layout pid=");
            _lb.hex(pid as u64);
            _lb.str(b" elf=[");
            _lb.hex(plan.layout.elf_code.base);
            _lb.str(b",");
            _lb.hex(plan.layout.elf_code.end());
            _lb.str(b") rtld=[");
            _lb.hex(plan.layout.rtld.base);
            _lb.str(b",");
            _lb.hex(plan.layout.rtld.end());
            _lb.str(b") shlib=[");
            _lb.hex(plan.layout.shared_libs.base);
            _lb.str(b",");
            _lb.hex(plan.layout.shared_libs.end());
            _lb.str(b") elf_entry=");
            _lb.hex(elf_result.entry);
            _lb.str(b" rtld_entry=");
            _lb.hex(rtld_result.entry);
            _lb.str(b" rtld_base=");
            _lb.hex(rtld_result.base);
            _lb.str(b" shlib_base=");
            _lb.hex(shared_lib_base);
            _lb.str(b"\n");
        });

        if !configure_spawn_scheduler(alloc, reply, pid, child_tcb, child_sc) {
            crate::loader::vfs_load::cleanup_exec_source(&mut vfs_source);
            return false;
        }

        // ---- Map initrd and boot info for dynamic executables ----
        if plan.is_dynamic {
            if mmsrv_ipc::map_initrd_to_child_tx(
                child_vs,
                initrd,
                initrd_size,
                pid,
                plan.lib_window_pages,
                plan.layout.initrd.base,
            ) != 0
            {
                crate::loader::vfs_load::cleanup_exec_source(&mut vfs_source);
                mmsrv_ipc::deregister_from_mmsrv(pid);
                alloc.rollback(trona::caps::rsrcsrv_ep());
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
            if mmsrv_ipc::map_boot_info_to_child_tx(child_vs, pid) != 0 {
                crate::loader::vfs_load::cleanup_exec_source(&mut vfs_source);
                mmsrv_ipc::deregister_from_mmsrv(pid);
                alloc.rollback(trona::caps::rsrcsrv_ep());
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        }

        // ---- Materialize stack via mmsrv from a local staged top-page image ----
        let stack_pages = plan.layout.stack.page_count();
        let stack_stage = match alloc_zeroed_staged_stack_page(alloc, reply, pid) {
            Some(stage) => stage,
            None => {
                crate::loader::vfs_load::cleanup_exec_source(&mut vfs_source);
                return false;
            }
        };

        // ---- Write stack data into the staged top page ----
        let mut child_entry_rip = elf_result.entry;
        let mut child_rsp = plan.layout.stack_top;
        let (phdr_vaddr, phent, phnum) = if let Some(vfs) = vfs_stream {
            (
                plan.layout.elf_code.base + vfs.phdr_vaddr,
                vfs.phent,
                vfs.phnum,
            )
        } else {
            let mut phdr_vaddr = 0u64;
            let mut phent = 0u64;
            let mut phnum = 0u64;
            if trona_loader::elf_dynamic::elf_get_phdr_info(
                elf_entry.data,
                elf_entry.data_len,
                plan.layout.elf_code.base,
                &raw mut phdr_vaddr,
                &raw mut phent,
                &raw mut phnum,
            ) != 0
            {
                crate::loader::vfs_load::cleanup_exec_source(&mut vfs_source);
                mmsrv_ipc::deregister_from_mmsrv(pid);
                alloc.rollback(trona::caps::rsrcsrv_ep());
                reply.label = TRONA_INVALID_ARGUMENT;
                return false;
            }
            (phdr_vaddr, phent, phnum)
        };

        if plan.is_dynamic {
            // Pass library window size for AT_TRONA_INITRD_SZ
            let initrd_window_size = plan.lib_window_pages * 4096;

            // Build argv/envp for the child process.
            let mut str_buf = [0u8; 256];
            let (argc, mut str_pos) = pack_spawn_argv_strings(
                msg,
                args_reg_idx,
                spawn_args_len,
                &name,
                name_len,
                &exec_path,
                exec_path_len,
                &mut str_buf,
                true,
            );

            // envp strings
            let mut path_env = [0u8; 48];
            let prefix = b"PATH=";
            let mut pi = 0usize;
            while pi < prefix.len() {
                path_env[pi] = prefix[pi];
                pi += 1;
            }
            let dp = trona::consts::posix::DEFAULT_PATH;
            let mut di = 0usize;
            while di < dp.len() && pi < path_env.len() {
                path_env[pi] = dp[di];
                pi += 1;
                di += 1;
            }

            let env_strs: [&[u8]; 4] =
                [&path_env[..pi], b"HOME=/", b"TERM=vt100", b"SHELL=/bin/sh"];
            for env in &env_strs {
                append_nul_terminated_bytes(&mut str_buf, &mut str_pos, env);
            }

            match write_dynamic_stack(
                phdr_vaddr,
                phent,
                phnum,
                0, // stk_frame unused in pre_mapped mode
                &elf_result,
                &rtld_result,
                initrd_window_size,
                shared_lib_base,
                argc,
                4,
                &str_buf,
                str_pos,
                plan.layout.scratch.base,
                plan.layout.initrd.base,
                plan.layout.stack_top,
                service_cspace_layout(cn_size_bits, cap_layout.frame_slot_start),
                &cap_layout,
                stack_stage,
                true, // pre_mapped: stack top page already at PROCMGR_SCRATCH_VADDR
                &name[base_start..name_len],
                pid,
                child_cn,
            ) {
                Ok(rsp) => {
                    child_rsp = rsp;
                    child_entry_rip = rtld_result.entry;
                }
                Err(err) => {
                    free_staging_buffer(stack_stage, 1);
                    crate::loader::vfs_load::cleanup_exec_source(&mut vfs_source);
                    mmsrv_ipc::deregister_from_mmsrv(pid);
                    alloc.rollback(trona::caps::rsrcsrv_ep());
                    reply.label = match err {
                        StackBuildError::OutOfMemory => TRONA_OUT_OF_MEMORY,
                        StackBuildError::InvalidArgument => TRONA_INVALID_ARGUMENT,
                        StackBuildError::TooLarge => TRONA_OUT_OF_RANGE,
                    };
                    return false;
                }
            }
        }

        // ELF scratch buffer no longer needed (all elf_entry.data users complete).
        crate::loader::vfs_load::cleanup_exec_source(&mut vfs_source);

        if !commit_staged_top_stack_page(
            alloc,
            reply,
            pid,
            plan.layout.stack.base,
            plan.layout.stack_top,
            stack_pages,
            stack_stage,
        ) {
            return false;
        }
        free_staging_buffer(stack_stage, 1);

        return finalize_spawn_launch(
            alloc,
            reply,
            badge,
            kind,
            &plan,
            start_suspended,
            spawn_flags,
            slot_idx,
            pid,
            child_tcb,
            child_vs,
            child_cn,
            child_sc,
            ready_badge_bit,
            child_sig_ntfn,
            shared_lib_base,
            shared_lib_map,
            use_pre_ep,
            &name,
            name_len,
            &exec_path,
            exec_path_len,
            child_entry_rip,
            child_rsp,
            b"[PROCMGR] ",
            cap_layout,
        );
    }
}

/// Copy standard caps into child CNode using the cursor-allocated layout.
///
/// `ready_badge_bit` is the readiness bit this spawn was assigned via
/// `readiness::alloc_readiness_bit()`. It is ignored when `with_ready_ntfn`
/// is `false`. The readiness cap is a badged mint of procmgr's bound
/// notification — see the notification dispatcher in `main.rs`.
fn copy_child_caps_tx(
    child_tcb: Cap,
    child_vs: Cap,
    child_cn: Cap,
    child_sc: Cap,
    child_sig_ntfn: Cap,
    ready_badge_bit: u8,
    with_ready_ntfn: bool,
    with_fb_untyped: bool,
    pid: u32,
    pre_service_ep: Cap,
    cap_layout: &ChildCapLayout,
) -> i32 {
    let mut err;
    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        child_tcb,
        child_cn,
        cap_layout.self_tcb,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] copy TCB cap failed dst=");
            _lb.hex(cap_layout.self_tcb);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        return err;
    }

    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        child_vs,
        child_cn,
        cap_layout.self_vspace,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] copy VSpace cap failed dst=");
            _lb.hex(cap_layout.self_vspace);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        return err;
    }

    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        child_cn,
        child_cn,
        cap_layout.self_cspace,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] copy CNode cap failed dst=");
            _lb.hex(cap_layout.self_cspace);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        return err;
    }

    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        child_sc,
        child_cn,
        cap_layout.sc,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] copy SC cap failed dst=");
            _lb.hex(cap_layout.sc);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        return err;
    }

    err = trona::invoke::cnode_mint(
        CAP_SELF_CSPACE,
        trona::caps::service_ep(),
        child_cn,
        cap_layout.procmgr_ep,
        pid as u64,
    );
    if err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] mint EP cap failed err=");
            _lb.hex(err as u64);
            _lb.str(b" dst=");
            _lb.hex(cap_layout.procmgr_ep);
            _lb.str(b"\n");
        });
        return err;
    }

    if pre_service_ep != 0 {
        err = trona::invoke::cnode_move(
            child_cn,
            cap_layout.service_ep,
            CAP_SELF_CSPACE,
            pre_service_ep,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] copy pre-service EP failed err=");
                _lb.hex(err as u64);
                _lb.str(b" dst=");
                _lb.hex(cap_layout.service_ep);
                _lb.str(b"\n");
            });
            return err;
        }
    }

    err = trona::invoke::cnode_mint(
        CAP_SELF_CSPACE,
        trona::caps::vfs_ep(),
        child_cn,
        cap_layout.vfs_ep,
        pid as u64,
    );
    if err != 0 {
        trona::uwarn!(|_lb| {
            _lb.str(b"[PROCMGR] WARN: mint VFS EP failed, trying unbadged copy\n");
        });
        err = trona::invoke::cnode_copy(
            CAP_SELF_CSPACE,
            trona::caps::vfs_ep(),
            child_cn,
            cap_layout.vfs_ep,
            CAP_RIGHTS_ALL,
        );
        if err != 0 {
            trona::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] WARN: copy VFS EP cap failed dst=");
                _lb.hex(cap_layout.vfs_ep);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
        }
    }

    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        trona::caps::namesrv_ep(),
        child_cn,
        cap_layout.namesrv_ep,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uwarn!(|_lb| {
            _lb.str(b"[PROCMGR] WARN: copy Nameserv EP cap failed dst=");
            _lb.hex(cap_layout.namesrv_ep);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
    }

    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        child_sig_ntfn,
        child_cn,
        cap_layout.signal_ntfn,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        trona::uwarn!(|_lb| {
            _lb.str(b"[PROCMGR] WARN: copy signal ntfn cap failed dst=");
            _lb.hex(cap_layout.signal_ntfn);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
    }

    if with_ready_ntfn {
        // Mint a badged copy of procmgr's bound notification into the
        // child's readiness slot. `SYS_SIGNAL` from the child will OR
        // `1 << ready_badge_bit` into procmgr's notification word and
        // wake `reply_recv` directly.
        // SAFETY: BOUND_NTFN is initialised once during procmgr setup and
        // never mutated afterwards; single-threaded read.
        let bound = unsafe { *(&raw const crate::BOUND_NTFN) };
        let badge = 1u64 << (ready_badge_bit as u64);
        err = trona::invoke::cnode_mint(
            CAP_SELF_CSPACE,
            bound,
            child_cn,
            cap_layout.ready_ntfn,
            badge,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] mint readiness ntfn cap failed dst=");
                _lb.hex(cap_layout.ready_ntfn);
                _lb.str(b" badge=");
                _lb.hex(badge);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            return err;
        }
        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] ready ntfn minted pid=");
            _lb.hex(pid as u64);
            _lb.str(b" bit=");
            _lb.hex(ready_badge_bit as u64);
            _lb.str(b" dst=");
            _lb.hex(cap_layout.ready_ntfn);
            _lb.str(b" badge=");
            _lb.hex(badge);
            _lb.str(b"\n");
        });
    }

    if with_fb_untyped {
        err = trona::invoke::cnode_copy(
            CAP_SELF_CSPACE,
            trona::caps::fb_untyped(),
            child_cn,
            cap_layout.fb_untyped,
            CAP_RIGHTS_ALL,
        );
        if err != 0 {
            trona::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] WARN: copy framebuffer untyped cap failed\n");
            });
        }
    }

    // Provide initrd device-untyped
    err = trona::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        trona::caps::initrd_untyped(),
        child_cn,
        cap_layout.initrd_untyped,
        INITRD_COPY_RIGHTS,
    );
    if err != 0 {
        trona::uwarn!(|_lb| {
            _lb.str(b"[PROCMGR] WARN: copy initrd untyped cap failed\n");
        });
    }

    // Note: root untypeds are no longer mirrored to children.
    // Child-private regions are materialized by mmsrv and populated via
    // staged copy transactions from procmgr.

    trona::udebug!(|_lb| {
        _lb.str(b"[PROCMGR] cap_layout pid=");
        _lb.hex(pid as u64);
        _lb.str(b" ready=");
        _lb.hex(cap_layout.ready_ntfn);
        _lb.str(b" signal=");
        _lb.hex(cap_layout.signal_ntfn);
        _lb.str(b" fb_ut=");
        _lb.hex(cap_layout.fb_untyped);
        _lb.str(b" initrd_ut=");
        _lb.hex(cap_layout.initrd_untyped);
        _lb.str(b" pm_ep=");
        _lb.hex(cap_layout.procmgr_ep);
        _lb.str(b" mm_ep=");
        _lb.hex(cap_layout.mmsrv_ep);
        _lb.str(b" extras_base=");
        _lb.hex(cap_layout.extras_base);
        _lb.str(b" frame_start=");
        _lb.hex(cap_layout.frame_slot_start);
        _lb.str(b"\n");
    });

    0
}
