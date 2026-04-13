//! Fork handler
//! SPDX-License-Identifier: GPL-2.0-only

use trona::ipc;
use trona::types::core::*;

use crate::base::child_layout::{ChildCapLayout, ChildSlotAlloc, CHILD_RTLD_FRAME_SLOT_START};
use crate::personality::PersonalityKind;
use crate::base::proc_table::{
    alloc_proc, find_by_badge, proctab, NEXT_PID, NSIG, ProcessState,
};

unsafe fn cleanup_failed_fork_child(idx: usize) {
    unsafe {
        let pid = proctab(idx).pid;
        let badge = proctab(idx).badge;
        let tcb_cap = proctab(idx).tcb_cap;

        if proctab(idx).mmsrv_registered {
            let _ = crate::base::mmsrv_ipc::quiesce_and_deregister_mmsrv_client(tcb_cap, pid, badge);
            proctab(idx).mmsrv_registered = false;
        }

        let mut vfs_msg = TronaMsg::zeroed();
        vfs_msg.label = trona::protocol::VFS_CLIENT_EXIT;
        vfs_msg.length = 1;
        vfs_msg.regs[0] = badge;
        let _ = ipc::send_timed_ctx(
            crate::ipc_ctx(),
            trona::caps::vfs_ep(),
            &raw const vfs_msg,
            50_000_000,
        );

        crate::lifecycle::exit::free_proc_alloc_slots(idx);
        crate::base::proc_table::cleanup_proc_resources(idx, crate::CAP_SELF_CSPACE);
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
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK from unknown badge\n");
            });
            reply.label = crate::TRONA_NOT_FOUND;
            return;
        };
        let parent_pid = proctab(parent_idx).pid;
        let _parent_shared_base = proctab(parent_idx).shared_lib_base;
        let parent_lib_map = proctab(parent_idx).lib_map;
        let parent_layout = proctab(parent_idx).layout;
        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] FORK from PID=");
            _lb.hex(parent_pid as u64);
            _lb.str(b"\n");
        });

        let Some(slot_idx) = alloc_proc() else {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: process table full\n");
            });
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        };
        proctab(slot_idx).state = ProcessState::Spawning;

        let child_pid = NEXT_PID;
        NEXT_PID += 1;

        // Reserve slots for fixed kernel objects (TCB, VSpace, CNode, SC, Notification) + margin.
        let total_slots = 8;
        if !alloc.reserve(child_pid as u64, total_slots) {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: slot reservation failed\n");
            });
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Core objects (TCB/VSpace/CNode/SC) allocated via rsrcsrv with
        // owner_id = child_pid so the handles are accounted to the child.
        macro_rules! realize_mm {
            ($ty:expr, $what:expr) => {
                match alloc.realize_via_rsrcsrv_next(trona::caps::rsrcsrv_ep(), $ty, 0) {
                    Ok(s) => s,
                    Err(_) => {
                        trona::uerror!(|_lb| {
                            _lb.str($what);
                        });
                        alloc.rollback(trona::caps::rsrcsrv_ep());
                        reply.label = crate::TRONA_OUT_OF_MEMORY;
                        return;
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
            match ChildCapLayout::from_alloc(&mut slot_alloc) {
                Some(l) => l,
                None => {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] FORK: child cspace cursor exhausted\n");
                    });
                    alloc.rollback(trona::caps::rsrcsrv_ep());
                    reply.label = crate::TRONA_OUT_OF_MEMORY;
                    return;
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
        let err = trona::invoke::cnode_mint(
            crate::CAP_SELF_CSPACE,
            crate::base::cap_helpers::mmsrv_authority_raw(),
            child_cn,
            cap_layout.mmsrv_ep,
            child_pid as u64,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: mint mmsrv EP failed\n");
            });
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Mint rsrcsrv EP into child CNode at the cursor-allocated rsrcsrv
        // slot (badged with child pid). Children use this to allocate kernel
        // objects via RES_ALLOC_OBJECT after the fork completes.
        let err = trona::invoke::cnode_mint(
            crate::CAP_SELF_CSPACE,
            crate::base::cap_helpers::rsrcsrv_authority_raw(),
            child_cn,
            cap_layout.rsrcsrv_ep,
            child_pid as u64,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: mint rsrcsrv EP failed\n");
            });
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Copy caps into child CNode
        macro_rules! copy_or_fail {
            ($src:expr, $dst:expr, $what:expr) => {
                if trona::invoke::cnode_copy(
                    crate::CAP_SELF_CSPACE,
                    $src,
                    child_cn,
                    $dst,
                    crate::CAP_RIGHTS_ALL,
                ) != 0
                {
                    trona::uerror!(|_lb| {
                        _lb.str($what);
                    });
                    alloc.rollback(trona::caps::rsrcsrv_ep());
                    reply.label = crate::TRONA_OUT_OF_MEMORY;
                    return;
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

        let err = trona::invoke::cnode_mint(
            crate::CAP_SELF_CSPACE,
            trona::caps::service_ep(),
            child_cn,
            cap_layout.procmgr_ep,
            child_pid as u64,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: mint procmgr control EP failed\n");
            });
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }

        let err = trona::invoke::cnode_mint(
            crate::CAP_SELF_CSPACE,
            trona::caps::vfs_ep(),
            child_cn,
            cap_layout.vfs_ep,
            child_pid as u64,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: mint child VFS EP failed\n");
            });
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }
        let _ = trona::invoke::cnode_copy(
            crate::CAP_SELF_CSPACE,
            trona::caps::namesrv_ep(),
            child_cn,
            cap_layout.namesrv_ep,
            crate::CAP_RIGHTS_ALL,
        );
        let _ = trona::invoke::cnode_copy(
            crate::CAP_SELF_CSPACE,
            child_sig_ntfn,
            child_cn,
            cap_layout.signal_ntfn,
            crate::CAP_RIGHTS_ALL,
        );
        // Keep fork child cap layout aligned with spawn path so rtld/slot alloc
        // can use initrd device mapping and mirrored untyped sources.
        let _ = trona::invoke::cnode_copy(
            crate::CAP_SELF_CSPACE,
            trona::caps::initrd_untyped(),
            child_cn,
            cap_layout.initrd_untyped,
            crate::INITRD_COPY_RIGHTS,
        );
        // Note: root untypeds no longer mirrored -- children use mmsrv.

        // CSpace expansion is handled by procmgr's own bound-notification
        // path — children are registered in the CLIENTS table at fork time.
        // The client's cspace_ntfn slot was chosen by the cursor and is
        // delivered to the child via `AT_TRONA_CSPACE_NTFN`.
        crate::base::cspace::register_client(child_pid as u64, child_cn, cap_layout.cspace_ntfn);

        // Configure child TCB
        let err = trona::invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: set_space failed\n");
            });
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Set fault handler: badged mmsrv EP so VMFaults route to mmsrv
        {
            let temp_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => {
                    alloc.rollback(trona::caps::rsrcsrv_ep());
                    reply.label = crate::TRONA_OUT_OF_MEMORY;
                    return;
                }
            };
            let err = trona::invoke::cnode_mint(
                crate::CAP_SELF_CSPACE,
                crate::base::cap_helpers::mmsrv_authority_raw(),
                crate::CAP_SELF_CSPACE,
                temp_slot,
                child_pid as u64,
            );
            if err == 0 {
                trona::invoke::tcb_set_fault_handler(child_tcb, temp_slot);
            }
            trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, temp_slot);
            alloc.free_single_slot(temp_slot);
        }

        let err = trona::invoke::tcb_configure(child_tcb, child_entry, parent_rsp, 0);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: configure failed err=");
                _lb.hex(err as u64);
                _lb.str(b" child_pid=");
                _lb.hex(child_pid as u64);
                _lb.str(b" tcb=");
                _lb.hex(child_tcb);
                _lb.str(b"\n");
            });
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }
        // Copy parent's FPU/SSE state to child (preserves XMM registers across fork)
        let err = trona::invoke::tcb_copy_fpu(child_tcb, proctab(parent_idx).tcb_cap);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: copy FPU state failed\n");
            });
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }
        // Copy parent's TLS base to child TCB so FS_BASE is correct after
        // context switch.  The child has a COW copy of the parent's TLS block
        // at the same virtual address, so it needs the same FS_BASE.
        let parent_tls_base = msg.regs[9];
        if parent_tls_base != 0 {
            let err = trona::invoke::tcb_set_tls_base(child_tcb, parent_tls_base);
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: set TLS base failed\n");
                });
            }
        }

        let err = trona::invoke::tcb_set_ipc_buffer(child_tcb, parent_layout.ipc_buf.base);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] FORK: set IPC buf failed\n");
            });
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Clone FD table BEFORE resuming child
        {
            let mut clone_msg = TronaMsg::zeroed();
            let mut clone_reply = TronaMsg::zeroed();
            clone_msg.label = trona::protocol::VFS_POSIX_CLONE_FDS;
            clone_msg.length = 2;
            clone_msg.regs[0] = badge;
            clone_msg.regs[1] = child_pid as u64;
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                trona::caps::vfs_ep(),
                &raw const clone_msg,
                &raw mut clone_reply,
            );
            if err != 0 || clone_reply.label != crate::TRONA_OK {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: VFS clone_fds failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b" reply=");
                    _lb.hex(clone_reply.label);
                    _lb.str(b", aborting fork\n");
                });
                alloc.rollback(trona::caps::rsrcsrv_ep());
                reply.label = crate::TRONA_INVALID_OPERATION;
                return;
            }
        }

        // Register child with mmsrv (VSpace cap transfer + initial state)
        {
            let fork_heap_base = parent_layout.elf_code.end();
            let fork_mmap_base = trona::layout::compute_mmap_base(&parent_layout, fork_heap_base);
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona::protocol::MM_REGISTER;
            mm_msg.length = 4;
            mm_msg.regs[0] = child_pid as u64; // client badge
                                               // Seed with dynamic defaults; MM_FORK_REGIONS overwrites with exact runtime state.
            mm_msg.regs[1] = fork_heap_base;
            mm_msg.regs[2] = fork_mmap_base;
            mm_msg.regs[3] = child_pid as u64;
            ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, child_vs);
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                trona::caps::mmsrv_ep(),
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != crate::TRONA_OK {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: mmsrv register failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                alloc.rollback(trona::caps::rsrcsrv_ep());
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return;
            }
        }

        // Clone parent's memory state to child in mmsrv
        {
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona::protocol::MM_FORK_REGIONS;
            mm_msg.length = 2;
            mm_msg.regs[0] = badge; // parent badge
            mm_msg.regs[1] = child_pid as u64; // child badge
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                trona::caps::mmsrv_ep(),
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != crate::TRONA_OK {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: mmsrv fork_regions failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b" label=");
                    _lb.hex(mm_reply.label);
                    _lb.str(b" child_pid=");
                    _lb.hex(child_pid as u64);
                    _lb.str(b"\n");
                });
                // Deregister child from mmsrv and abort fork
                {
                    let mut dereg = TronaMsg::zeroed();
                    let mut drep = TronaMsg::zeroed();
                    dereg.label = trona::protocol::MM_DEREGISTER;
                    dereg.length = 1;
                    dereg.regs[0] = child_pid as u64;
                    let _ = ipc::call_ctx(
                        crate::ipc_ctx(),
                        trona::caps::mmsrv_ep(),
                        &raw const dereg,
                        &raw mut drep,
                    );
                }
                alloc.rollback(trona::caps::rsrcsrv_ep());
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return;
            }
        }

        // Map IPC buffer for child via mmsrv (zero-filled, child only).
        // MM_FORK_REGIONS intentionally skips the parent's IPC region so this
        // remains the single owner of child IPC-buffer instantiation.
        {
            let mut mm_msg = TronaMsg::zeroed();
            let mut mm_reply = TronaMsg::zeroed();
            mm_msg.label = trona::protocol::MM_MAP_BATCH;
            mm_msg.length = 4;
            mm_msg.regs[0] = child_pid as u64;
            mm_msg.regs[1] = parent_layout.ipc_buf.base;
            mm_msg.regs[2] = 1; // 1 page
            mm_msg.regs[3] = crate::VSPACE_FLAG_WRITABLE | crate::VSPACE_FLAG_USER;
            let err = ipc::call_ctx(
                crate::ipc_ctx(),
                trona::caps::mmsrv_ep(),
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != crate::TRONA_OK || mm_reply.regs[0] != 1 {
                trona::uerror!(|_lb| {
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
                // Deregister child from mmsrv on failure
                {
                    let mut dereg = TronaMsg::zeroed();
                    let mut drep = TronaMsg::zeroed();
                    dereg.label = trona::protocol::MM_DEREGISTER;
                    dereg.length = 1;
                    dereg.regs[0] = child_pid as u64;
                    let _ = ipc::call_ctx(
                        crate::ipc_ctx(),
                        trona::caps::mmsrv_ep(),
                        &raw const dereg,
                        &raw mut drep,
                    );
                }
                alloc.rollback(trona::caps::rsrcsrv_ep());
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return;
            }
        }

        let child_entry_page = child_entry & !0xFFFu64;
        if crate::base::mmsrv_ipc::prefault_range_in_mmsrv(
            child_pid as u64,
            child_entry_page,
            1,
            trona::consts::posix::PROT_READ as u64 | trona::consts::posix::PROT_EXEC as u64,
        ) != 0
        {
            // Deregister child from mmsrv on failure
            {
                let mut dereg = TronaMsg::zeroed();
                let mut drep = TronaMsg::zeroed();
                dereg.label = trona::protocol::MM_DEREGISTER;
                dereg.length = 1;
                dereg.regs[0] = child_pid as u64;
                let _ = ipc::call_ctx(
                    crate::ipc_ctx(),
                    trona::caps::mmsrv_ep(),
                    &raw const dereg,
                    &raw mut drep,
                );
            }
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }

        let stack_prefault_base = parent_rsp.saturating_sub(8192) & !0xFFFu64;
        if crate::base::mmsrv_ipc::prefault_range_in_mmsrv(
            child_pid as u64,
            stack_prefault_base,
            2,
            trona::consts::posix::PROT_READ as u64 | trona::consts::posix::PROT_WRITE as u64,
        ) != 0
        {
            // Deregister child from mmsrv on failure
            {
                let mut dereg = TronaMsg::zeroed();
                let mut drep = TronaMsg::zeroed();
                dereg.label = trona::protocol::MM_DEREGISTER;
                dereg.length = 1;
                dereg.regs[0] = child_pid as u64;
                let _ = ipc::call_ctx(
                    crate::ipc_ctx(),
                    trona::caps::mmsrv_ep(),
                    &raw const dereg,
                    &raw mut drep,
                );
            }
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Schedule the child
        let err = trona::invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 {
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }
        let err = trona::invoke::sc_bind(child_sc, child_tcb);
        if err != 0 {
            alloc.rollback(trona::caps::rsrcsrv_ep());
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Commit and populate proc table BEFORE resume so the child can
        // immediately query procmgr (e.g. PM_GET_THREAD_CAPS) without racing.
        let (slot_base, slot_count) = alloc.commit();

        let p = proctab(slot_idx);
        p.set_personality_kind(PersonalityKind::Posix);
        p.pid = child_pid;
        p.ppid = parent_pid;
        p.state = ProcessState::Running;
        p.exit_code = 0;
        p.badge = child_pid as u64;
        p.tcb_cap = child_tcb;
        p.vspace_cap = child_vs;
        p.cnode_cap = child_cn;
        p.sc_cap = child_sc;
        p.cap_layout = cap_layout;
        p.slot_base = slot_base;
        p.slot_count = slot_count;
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
        p.waiter_reply = 0;
        p.waiter_pid = 0;
        p.any_waiter_reply = 0;
        p.waiting_for_any = 0;
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

        let err = trona::invoke::tcb_resume(child_tcb);
        if err != 0 {
            cleanup_failed_fork_child(slot_idx);
            reply.label = crate::TRONA_OUT_OF_MEMORY;
            return;
        }

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] FORK: child PID=");
            _lb.hex(child_pid as u64);
            _lb.str(b" started\n");
        });
        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = child_pid as u64;
    }
}
