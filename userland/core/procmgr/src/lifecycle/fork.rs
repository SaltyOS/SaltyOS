//! Fork handler
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::*;
use trona_kernel::ipc;

use crate::base::proc_table::{
    COMPLETION_EVENT_FORK_COMMITTED, NEXT_PID, NSIG, ObserverEventRecord, ProcessState, alloc_proc,
    find_by_badge, proctab,
};
use crate::personality::PersonalityKind;
use trona_runtime::spawn::layout::{
    CHILD_RTLD_FRAME_SLOT_START, CapLayoutProfile, ChildCapLayout, ChildSlotAlloc,
};

unsafe fn notify_vfs_child_exit(badge: u64) {
    if !crate::base::vfs_notify::enqueue_client_exit(badge) {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[PROCMGR] VFS client-exit queue full badge=");
            _lb.hex(badge);
            _lb.str(b"\n");
        });
    }
}

unsafe fn rollback_unpublished_fork_child(
    alloc: &mut crate::base::alloc::Allocator,
    slot_idx: usize,
    badge: u64,
) {
    unsafe {
        notify_vfs_child_exit(badge);
        crate::lifecycle::spawn::rollback_unpublished_child(
            alloc,
            slot_idx,
            badge,
            crate::base::readiness::BIT_NONE,
        );
    }
}

pub(crate) unsafe fn handle_fork(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let alloc = &mut *(&raw mut crate::ALLOCATOR);

        let parent_rsp = msg.regs[0];
        let child_entry = msg.regs[1];

        if child_entry == 0 {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some(parent_idx) = find_by_badge(badge) else {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK from unknown badge\n");
            });
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };
        let parent_pid = proctab(parent_idx).pid;
        let _parent_shared_base = proctab(parent_idx).shared_lib_base;
        let parent_lib_map = proctab(parent_idx).lib_map;
        let parent_layout = proctab(parent_idx).layout;
        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] FORK from PID=");
            _lb.hex(parent_pid as u64);
            _lb.str(b"\n");
        });

        let Some(slot_idx) = alloc_proc() else {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: process table full\n");
            });
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        };
        proctab(slot_idx).state = ProcessState::Spawning;

        let child_pid = NEXT_PID;
        NEXT_PID += 1;

        macro_rules! abort_fork_unpublished {
            ($label:expr) => {{
                rollback_unpublished_fork_child(alloc, slot_idx, child_pid as u64);
                reply.label = $label;
                return;
            }};
        }

        macro_rules! abort_fork_published {
            ($label:expr) => {{
                crate::lifecycle::exit::abort_spawning_process(slot_idx);
                reply.label = $label;
                return;
            }};
        }

        // Reserve slots for fixed kernel objects (TCB, VSpace, CNode, SC, Notification) + margin.
        let total_slots = 8;
        if !alloc.reserve(child_pid as u64, total_slots) {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: slot reservation failed\n");
            });
            abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
        }

        // Core objects (TCB/VSpace/CNode/SC) allocated via rsrcsrv with
        // owner_id = child_pid so the handles are accounted to the child.
        macro_rules! realize_mm {
            ($ty:expr, $what:expr) => {
                match alloc.realize_via_rsrcsrv_next(
                    trona_runtime::client::caps::rsrcsrv_ep(),
                    $ty,
                    0,
                ) {
                    Ok(s) => s,
                    Err(_) => {
                        trona_runtime::uerror!(|_lb| {
                            _lb.str($what);
                        });
                        abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
                    }
                }
            };
        }

        let child_tcb = realize_mm!(crate::OBJ_TCB, b"[PROCMGR] FORK: TCB alloc failed\n");
        let child_vs = realize_mm!(crate::OBJ_VSPACE, b"[PROCMGR] FORK: VSpace alloc failed\n");
        let child_cn = realize_mm!(crate::OBJ_CNODE, b"[PROCMGR] FORK: CNode alloc failed\n");
        let child_sc = realize_mm!(
            crate::OBJ_SCHED_CONTEXT,
            b"[PROCMGR] FORK: SC alloc failed\n"
        );
        // IPC frame allocated by mmsrv via MM_MAP_BATCH below
        let child_sig_ntfn = realize_mm!(
            crate::OBJ_NOTIFICATION,
            b"[PROCMGR] FORK: signal ntfn alloc failed\n"
        );

        // Allocate the fork-child cspace layout from a dynamic cursor.
        let cap_layout = {
            let mut slot_alloc = ChildSlotAlloc::new(0, CHILD_RTLD_FRAME_SLOT_START);
            match ChildCapLayout::from_alloc(CapLayoutProfile::Procmgr, &mut slot_alloc) {
                Some(l) => l,
                None => {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] FORK: child cspace cursor exhausted\n");
                    });
                    abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
                }
            }
        };

        // Per-page COW cloning is now handled by mmsrv via MM_FORK_REGIONS.
        // mmsrv allocates child MemoryObjects up front and then asks the
        // kernel MO_CLONE path to wire parent/child COW state in place.
        // For legacy (non-MO) regions, mmsrv falls back to per-page
        // vspace_clone_cow_page internally.

        // Mint mmsrv EP into child CNode at the cursor-allocated mmsrv slot
        // (badged with child pid).
        let err = trona_kernel::invoke::cnode_mint(
            crate::CAP_SELF_CSPACE,
            crate::base::cap_helpers::mmsrv_authority_raw(),
            child_cn,
            cap_layout.mmsrv_ep,
            child_pid as u64,
        );
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: mint mmsrv EP failed\n");
            });
            abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
        }

        // Mint rsrcsrv EP into child CNode at the cursor-allocated rsrcsrv
        // slot (badged with child pid). Children use this to allocate kernel
        // objects via RES_ALLOC_OBJECT after the fork completes.
        let err = trona_kernel::invoke::cnode_mint(
            crate::CAP_SELF_CSPACE,
            crate::base::cap_helpers::rsrcsrv_authority_raw(),
            child_cn,
            cap_layout.rsrcsrv_ep,
            child_pid as u64,
        );
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: mint rsrcsrv EP failed\n");
            });
            abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
        }

        // Copy caps into child CNode
        macro_rules! copy_or_fail {
            ($src:expr, $dst:expr, $what:expr) => {
                if trona_kernel::invoke::cnode_copy(
                    crate::CAP_SELF_CSPACE,
                    $src,
                    child_cn,
                    $dst,
                    crate::CAP_RIGHTS_ALL,
                ) != 0
                {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str($what);
                    });
                    abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
                }
            };
        }
        copy_or_fail!(
            child_tcb,
            cap_layout.self_tcb,
            b"[PROCMGR] FORK: copy TCB cap failed\n"
        );
        copy_or_fail!(
            child_vs,
            cap_layout.self_vspace,
            b"[PROCMGR] FORK: copy VSpace cap failed\n"
        );
        copy_or_fail!(
            child_cn,
            cap_layout.self_cspace,
            b"[PROCMGR] FORK: copy CNode cap failed\n"
        );
        copy_or_fail!(
            child_sc,
            cap_layout.sc,
            b"[PROCMGR] FORK: copy SC cap failed\n"
        );

        let err = trona_kernel::invoke::cnode_mint(
            crate::CAP_SELF_CSPACE,
            trona_runtime::client::caps::service_client_ep(),
            child_cn,
            cap_layout.init_ep,
            child_pid as u64,
        );
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: mint procmgr control EP failed\n");
            });
            abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
        }

        let err = trona_kernel::invoke::cnode_mint(
            crate::CAP_SELF_CSPACE,
            crate::base::cap_helpers::vfs_provider_ep(),
            child_cn,
            cap_layout.vfs_ep,
            child_pid as u64,
        );
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: mint child VFS EP failed\n");
            });
            abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
        }
        let _ = trona_kernel::invoke::cnode_copy(
            crate::CAP_SELF_CSPACE,
            trona_runtime::client::caps::namesrv_ep(),
            child_cn,
            cap_layout.namesrv_ep,
            crate::CAP_RIGHTS_ALL,
        );
        let _ = trona_kernel::invoke::cnode_copy(
            crate::CAP_SELF_CSPACE,
            child_sig_ntfn,
            child_cn,
            cap_layout.signal_ntfn,
            crate::CAP_RIGHTS_ALL,
        );
        // Keep fork child cap layout aligned with spawn path so rtld/slot alloc
        // can use initrd device mapping and mirrored untyped sources.
        let _ = trona_kernel::invoke::cnode_copy(
            crate::CAP_SELF_CSPACE,
            trona_runtime::client::caps::initrd_untyped(),
            child_cn,
            cap_layout.initrd_untyped,
            crate::INITRD_COPY_RIGHTS,
        );
        // Note: root untypeds no longer mirrored -- children use mmsrv.

        // CSpace expansion is driven entirely by the child's own substrate
        // slot_alloc self-expand path against the rsrcsrv authority — no
        // procmgr-side client registration or bound-notification fan-out is
        // involved any more.
        let _ = child_cn;
        let _ = cap_layout;

        // Configure child TCB
        let err = trona_kernel::invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: set_space failed\n");
            });
            abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
        }

        // Set fault handler: badged mmsrv EP so VMFaults route to mmsrv
        {
            let temp_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => {
                    abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
                }
            };
            let err = trona_kernel::invoke::cnode_mint(
                crate::CAP_SELF_CSPACE,
                crate::base::cap_helpers::mmsrv_authority_raw(),
                crate::CAP_SELF_CSPACE,
                temp_slot,
                child_pid as u64,
            );
            if err == 0 {
                trona_kernel::invoke::tcb_set_fault_handler(child_tcb, temp_slot);
            }
            trona_kernel::invoke::cnode_delete(crate::CAP_SELF_CSPACE, temp_slot);
            alloc.free_single_slot(temp_slot);
        }

        let err = trona_kernel::invoke::tcb_configure(child_tcb, child_entry, parent_rsp, 0);
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: configure failed err=");
                _lb.hex(err as u64);
                _lb.str(b" child_pid=");
                _lb.hex(child_pid as u64);
                _lb.str(b" tcb=");
                _lb.hex(child_tcb);
                _lb.str(b"\n");
            });
            abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
        }
        // Copy parent's FPU/SSE state to child (preserves XMM registers across fork)
        let err = trona_kernel::invoke::tcb_copy_fpu(child_tcb, proctab(parent_idx).tcb_cap);
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: copy FPU state failed\n");
            });
            abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
        }
        // Copy parent's TLS base to child TCB so FS_BASE is correct after
        // context switch.  The child has a COW copy of the parent's TLS block
        // at the same virtual address, so it needs the same FS_BASE.
        let parent_tls_base = msg.regs[9];
        if parent_tls_base != 0 {
            let err = trona_kernel::invoke::tcb_set_tls_base(child_tcb, parent_tls_base);
            if err != 0 {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: set TLS base failed\n");
                });
            }
        }

        let err = trona_kernel::invoke::tcb_set_ipc_buffer(child_tcb, parent_layout.ipc_buf.base);
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: set IPC buf failed\n");
            });
            abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
        }

        // Clone FD table BEFORE resuming child
        {
            let mut clone_msg = TronaMsg::zeroed();
            let mut clone_reply = TronaMsg::zeroed();
            clone_msg.label = trona_protocol::vfs::public::VFS_POSIX_CLONE_FDS;
            clone_msg.length = 2;
            clone_msg.regs[0] = badge;
            clone_msg.regs[1] = child_pid as u64;
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                crate::base::cap_helpers::vfs_provider_ep(),
                &raw const clone_msg,
                &raw mut clone_reply,
            );
            if err != 0 || clone_reply.label != crate::TRONA_OK {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: VFS clone_fds failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b" reply=");
                    _lb.hex(clone_reply.label);
                    _lb.str(b", aborting fork\n");
                });
                abort_fork_unpublished!(crate::TRONA_INVALID_OPERATION);
            }
        }

        // Register child with mmsrv (VSpace cap transfer + initial state)
        {
            let fork_heap_base = parent_layout.elf_code.end();
            let fork_mmap_base =
                trona_runtime::spawn::layout::compute_mmap_base(&parent_layout, fork_heap_base);
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona_protocol::mm::MM_REGISTER;
            mm_msg.length = 4;
            mm_msg.regs[0] = child_pid as u64; // client badge
            // Seed with dynamic defaults; MM_FORK_REGIONS overwrites with exact runtime state.
            mm_msg.regs[1] = fork_heap_base;
            mm_msg.regs[2] = fork_mmap_base;
            mm_msg.regs[3] = child_pid as u64;
            ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, child_vs);
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                trona_runtime::client::caps::mmsrv_ep(),
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != crate::TRONA_OK {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: mmsrv register failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                abort_fork_unpublished!(crate::TRONA_OUT_OF_MEMORY);
            }
        }

        crate::lifecycle::spawn::publish_provisional_process(
            alloc,
            slot_idx,
            badge,
            PersonalityKind::Posix,
            child_pid,
            child_tcb,
            child_vs,
            child_cn,
            child_sc,
            child_sig_ntfn,
            proctab(parent_idx).shared_lib_base,
            parent_lib_map,
            parent_layout,
            proctab(parent_idx).has_service_ep,
            crate::base::readiness::BIT_NONE,
            cap_layout,
            true,
        );

        // Clone parent's memory state to child in mmsrv
        {
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona_protocol::mm::MM_FORK_REGIONS;
            mm_msg.length = 2;
            mm_msg.regs[0] = badge; // parent badge
            mm_msg.regs[1] = child_pid as u64; // child badge
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                trona_runtime::client::caps::mmsrv_ep(),
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != crate::TRONA_OK {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: mmsrv fork_regions failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b" label=");
                    _lb.hex(mm_reply.label);
                    _lb.str(b" child_pid=");
                    _lb.hex(child_pid as u64);
                    _lb.str(b"\n");
                });
                abort_fork_published!(crate::TRONA_OUT_OF_MEMORY);
            }
        }

        // Map IPC buffer for child via mmsrv (zero-filled, child only).
        // MM_FORK_REGIONS intentionally skips the parent's IPC region so this
        // remains the single owner of child IPC-buffer instantiation.
        {
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona_protocol::mm::MM_MAP_BATCH;
            mm_msg.length = 4;
            mm_msg.regs[0] = child_pid as u64;
            mm_msg.regs[1] = parent_layout.ipc_buf.base;
            mm_msg.regs[2] = 1; // 1 page
            mm_msg.regs[3] = crate::VSPACE_FLAG_WRITABLE | crate::VSPACE_FLAG_USER;
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                trona_runtime::client::caps::mmsrv_ep(),
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != crate::TRONA_OK || mm_reply.regs[0] != 1 {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: MM_MAP_BATCH ipc failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b" label=");
                    _lb.hex(mm_reply.label);
                    _lb.str(b" mapped=");
                    _lb.hex(mm_reply.regs[0]);
                    _lb.str(b" child_pid=");
                    _lb.hex(child_pid as u64);
                    _lb.str(b"\n");
                });
                abort_fork_published!(crate::TRONA_OUT_OF_MEMORY);
            }
        }

        let child_entry_page = child_entry & !0xFFFu64;
        if crate::base::mmsrv_ipc::prefault_range_in_mmsrv(
            child_pid as u64,
            child_entry_page,
            1,
            trona_protocol::posix_abi::mm::PROT_READ as u64
                | trona_protocol::posix_abi::mm::PROT_EXEC as u64,
        ) != 0
        {
            abort_fork_published!(crate::TRONA_OUT_OF_MEMORY);
        }

        // Publish the child's stack bounds to its TCB. MM_FORK_REGIONS
        // has replicated the parent's REGION_KIND_STACK VmArea into the
        // child VSpace at the same coordinates, so the kernel's VmArea
        // re-check in TCB_SET_STACK_BOUNDS is satisfied. Parent
        // `stack_spec` (guard / prefault / reserve) is inherited
        // byte-for-byte; manifest re-evaluation during fork is
        // forbidden (see memory-model-audit I22).
        let parent_stack_spec = parent_layout.stack_spec;
        if let Some(stack_mat) = trona_runtime::spawn::stack_plan::plan_stack_materialization(
            parent_stack_spec,
            parent_layout.stack_top,
        ) {
            let err = trona_kernel::invoke::tcb_set_stack_bounds(
                child_tcb,
                stack_mat.stack_top,
                stack_mat.reserve_base,
                stack_mat.guard_bottom,
            );
            if err != 0 {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: tcb_set_stack_bounds failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                abort_fork_published!(crate::TRONA_OUT_OF_MEMORY);
            }
        }

        // Prefault the top `prefault_pages` of the child stack. Using
        // the parent's `stack_spec` rather than parent_rsp keeps the
        // prefault extent consistent with whatever the manifest asked
        // for, so the child cannot miss into mmsrv on its very first
        // return from fork.
        let stack_prefault_pages = parent_stack_spec.prefault_pages.max(1) as u64;
        let stack_prefault_bytes = stack_prefault_pages * 4096;
        let stack_prefault_base =
            parent_layout.stack_top.saturating_sub(stack_prefault_bytes) & !0xFFFu64;
        if crate::base::mmsrv_ipc::prefault_range_in_mmsrv(
            child_pid as u64,
            stack_prefault_base,
            stack_prefault_pages,
            trona_protocol::posix_abi::mm::PROT_READ as u64
                | trona_protocol::posix_abi::mm::PROT_WRITE as u64,
        ) != 0
        {
            abort_fork_published!(crate::TRONA_OUT_OF_MEMORY);
        }

        // Schedule the child
        let err = trona_kernel::invoke::sc_configure(child_sc, 10_000_000, 100_000_000);
        if err != 0 {
            abort_fork_published!(crate::TRONA_OUT_OF_MEMORY);
        }
        let err = trona_kernel::invoke::sc_bind(child_sc, child_tcb);
        if err != 0 {
            abort_fork_published!(crate::TRONA_OUT_OF_MEMORY);
        }

        // Finalize the published provisional process before resume so the child
        // can immediately query procmgr (e.g. INIT_GET_THREAD_CAPS) without racing.
        let p = proctab(slot_idx);
        p.set_personality_kind(PersonalityKind::Posix);
        p.pid = child_pid;
        p.ppid = parent_pid;
        p.completion_observer_pid = parent_pid;
        p.state = ProcessState::Running;
        p.badge = child_pid as u64;
        p.tcb_cap = child_tcb;
        p.vspace_cap = child_vs;
        p.cnode_cap = child_cn;
        p.sc_cap = child_sc;
        p.cap_layout = cap_layout;
        p.shared_lib_base = proctab(parent_idx).shared_lib_base;
        p.lib_map = parent_lib_map;
        p.layout = parent_layout;
        p.mmsrv_registered = true;
        p.has_service_ep = proctab(parent_idx).has_service_ep;
        p.start_time_ns = crate::base::proc_table::monotonic_now_ns();
        p.timer_interval_ns = 0;
        p.timer_deadline_ns = 0;
        p.ready_badge_bit = crate::base::readiness::BIT_NONE;
        p.pgid = proctab(parent_idx).pgid;
        p.sid = proctab(parent_idx).sid;
        p.ctty_dev = proctab(parent_idx).ctty_dev;
        p.ctty_pgrp = proctab(parent_idx).ctty_pgrp;
        p.signal_ntfn = child_sig_ntfn;
        p.stop_status = 0;
        p.completion_event_kind = crate::base::proc_table::COMPLETION_EVENT_NONE;
        p.completion_event_status = 0;
        p.completion_event_cookie = 0;
        p.completion_wait_reply = 0;
        p.completion_wait_target_pid = 0;
        p.completion_wait_options = 0;
        p.completion_wait_deadline_ns = 0;
        p.completion_wait_wake_retry_deadline_ns = 0;
        p.observer_event_count = 0;
        p.exe_path = proctab(parent_idx).exe_path;
        p.wait_ready_on_resume = false;
        p.ready_timeout_ns = 0;
        p.pending_ready_reply = 0;
        p.pending_ready_deadline_ns = 0;
        {
            let posix = p.posix_mut();
            for i in 0..NSIG {
                posix.sig_disposition[i] = proctab(parent_idx).posix().sig_disposition[i];
            }
            posix.umask = proctab(parent_idx).posix().umask;
            posix.uid = proctab(parent_idx).posix().uid;
            posix.gid = proctab(parent_idx).posix().gid;
            posix.euid = proctab(parent_idx).posix().euid;
            posix.egid = proctab(parent_idx).posix().egid;
            posix.suid = proctab(parent_idx).posix().suid;
            posix.sgid = proctab(parent_idx).posix().sgid;
            posix.ngroups = proctab(parent_idx).posix().ngroups;
            posix.groups = proctab(parent_idx).posix().groups;
            posix.rlimits = proctab(parent_idx).posix().rlimits;
        }

        p.launch_pending = false;
        if !crate::server::enqueue_post_reply_resume(child_tcb) {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] WARN: post-reply resume queue full for INIT_FORK, resuming immediately\n");
            });
            let err = trona_kernel::invoke::tcb_resume(child_tcb);
            if err != 0 {
                p.launch_pending = true;
                abort_fork_published!(crate::TRONA_OUT_OF_MEMORY);
            }
        }

        crate::base::trace_meta::emit_process_mapping(
            b"fork",
            child_pid,
            p.ppid,
            child_tcb,
            child_vs,
            &proctab(parent_idx).name,
            &p.exe_path,
        );

        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] FORK: child PID=");
            _lb.hex(child_pid as u64);
            _lb.str(b" started\n");
        });
        if msg.length >= 11 {
            proctab(slot_idx).completion_event_kind = COMPLETION_EVENT_FORK_COMMITTED;
            proctab(slot_idx).completion_event_status = 0;
            proctab(slot_idx).completion_event_cookie = msg.regs[10];
            let _ = crate::lifecycle::wait::append_observer_event(
                parent_idx,
                ObserverEventRecord {
                    kind: COMPLETION_EVENT_FORK_COMMITTED,
                    pid: child_pid,
                    status: 0,
                    cookie: msg.regs[10],
                },
            );
        }

        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = child_pid as u64;
    }
}

pub(crate) unsafe fn handle_fork_result(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let Some(parent_idx) = find_by_badge(badge) else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };
        let txid = msg.regs[0];
        let Some(child_pid) =
            crate::lifecycle::wait::consume_fork_committed_event(parent_idx, txid)
        else {
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };

        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = child_pid as u64;
    }
}
