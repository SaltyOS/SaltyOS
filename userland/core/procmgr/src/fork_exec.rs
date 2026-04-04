//! Fork and exec handlers
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::ipc;
use trona::types::core::*;

use crate::proc_table::{
    alloc_proc, find_by_badge, proctab, MAX_NAME_LEN, NEXT_PID, NSIG, PROC_FREE, PROC_RUNNING,
    SIG_DISP_CATCH, SIG_DISP_DFL,
};

pub(crate) unsafe fn handle_fork(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let alloc = &mut *(&raw mut super::ALLOCATOR);

        let parent_rsp = msg.regs[0];
        let child_entry = msg.regs[1];

        if child_entry == 0 {
            reply.label = super::TRONA_INVALID_ARGUMENT;
            return;
        }

        let Some(parent_idx) = find_by_badge(badge) else {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK from unknown badge\n"); });
            reply.label = super::TRONA_NOT_FOUND;
            return;
        };
        let parent_pid = proctab(parent_idx).pid;
        let parent_vs = proctab(parent_idx).vspace_cap;

        let _parent_shared_base = proctab(parent_idx).shared_lib_base;
        let parent_lib_map = proctab(parent_idx).lib_map;
        let parent_layout = proctab(parent_idx).layout;
        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] FORK from PID=");
            _lb.hex(parent_pid as u64);
            _lb.str(b"\n");
        });

        let Some(slot_idx) = alloc_proc() else {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: process table full\n"); });
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        };

        let child_pid = NEXT_PID;
        NEXT_PID += 1;

        // Pre-provision mmsrv untyped (breaks Procmgr↔MMSRV cycle)
        super::spawn_tx::ensure_mmsrv_capacity(alloc);

        // Reserve slots for fixed kernel objects (TCB, VSpace, CNode, SC, Notification) + margin.
        let total_slots = 8;
        if !alloc.reserve(total_slots) {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: slot reservation failed\n"); });
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Core objects (TCB/VSpace/CNode/SC) prefer primary untyped.
        macro_rules! realize_mm {
            ($ty:expr, $what:expr) => {
                match alloc.realize_via_mmsrv_next(super::CAP_MMSRV_EP, $ty, 0) {
                    Ok(s) => s,
                    Err(_) => {
                        trona::uerror!(|_lb| { _lb.str($what); });
                        alloc.rollback();
                        reply.label = super::TRONA_OUT_OF_MEMORY;
                        return;
                    }
                }
            };
        }

        let child_tcb = realize_mm!(super::OBJ_TCB, b"[PROCMGR] FORK: TCB alloc failed\n");
        let child_vs = realize_mm!(super::OBJ_VSPACE, b"[PROCMGR] FORK: VSpace alloc failed\n");
        let child_cn = realize_mm!(super::OBJ_CNODE, b"[PROCMGR] FORK: CNode alloc failed\n");
        let child_sc = realize_mm!(
            super::OBJ_SCHED_CONTEXT,
            b"[PROCMGR] FORK: SC alloc failed\n"
        );
        // IPC frame allocated by mmsrv via MM_MAP_BATCH below
        let child_sig_ntfn = realize_mm!(
            super::OBJ_NOTIFICATION,
            b"[PROCMGR] FORK: signal ntfn alloc failed\n"
        );

        // Per-page COW cloning is now handled by mmsrv via MM_FORK_REGIONS.
        // mmsrv uses MO_CLONE for MemoryObject-backed regions, which creates
        // a hidden page node that safely shares physical pages between parent
        // and child without the cap-refcount/frame-lifetime mismatch.
        // For legacy (non-MO) regions, mmsrv falls back to per-page
        // vspace_clone_cow_page internally.

        // Mint mmsrv EP into child CNode slot 7 (badged with child pid)
        let err = trona::invoke::cnode_mint(
            super::CAP_SELF_CSPACE,
            super::CAP_MMSRV_EP_UNBADGED,
            child_cn,
            super::CHILD_CAP_MMSRV_EP,
            child_pid as u64,
        );
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: mint mmsrv EP failed\n"); });
            alloc.rollback();
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Copy caps into child CNode
        macro_rules! copy_or_fail {
            ($src:expr, $dst:expr, $what:expr) => {
                if trona::invoke::cnode_copy(
                    super::CAP_SELF_CSPACE,
                    $src,
                    child_cn,
                    $dst,
                    super::CAP_RIGHTS_ALL,
                ) != 0
                {
                    trona::uerror!(|_lb| { _lb.str($what); });
                    alloc.rollback();
                    reply.label = super::TRONA_OUT_OF_MEMORY;
                    return;
                }
            };
        }
        copy_or_fail!(
            child_tcb,
            super::CHILD_CAP_TCB,
            b"[PROCMGR] FORK: copy TCB cap failed\n"
        );
        copy_or_fail!(
            child_vs,
            super::CHILD_CAP_VSPACE,
            b"[PROCMGR] FORK: copy VSpace cap failed\n"
        );
        copy_or_fail!(
            child_cn,
            super::CHILD_CAP_CSPACE,
            b"[PROCMGR] FORK: copy CNode cap failed\n"
        );

        let err = trona::invoke::cnode_mint(
            super::CAP_SELF_CSPACE,
            super::CAP_SERVER_EP,
            child_cn,
            super::CHILD_CAP_EP,
            child_pid as u64,
        );
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: mint server EP failed\n"); });
            alloc.rollback();
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        }
        let err = trona::invoke::cnode_mint(
            super::CAP_SELF_CSPACE,
            super::CAP_VFS_EP,
            child_cn,
            super::CHILD_CAP_VFS,
            child_pid as u64,
        );
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: mint child VFS EP failed\n"); });
            alloc.rollback();
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        }
        let _ = trona::invoke::cnode_copy(
            super::CAP_SELF_CSPACE,
            super::CAP_NAMESRV_EP,
            child_cn,
            super::CHILD_CAP_NAMESRV,
            super::CAP_RIGHTS_ALL,
        );
        let _ = trona::invoke::cnode_copy(
            super::CAP_SELF_CSPACE,
            child_sig_ntfn,
            child_cn,
            super::CHILD_CAP_SIGNAL_NTFN,
            super::CAP_RIGHTS_ALL,
        );
        // Keep fork child cap layout aligned with spawn path so rtld/slot alloc
        // can use initrd device mapping and mirrored untyped sources.
        let _ = trona::invoke::cnode_copy(
            super::CAP_SELF_CSPACE,
            super::CAP_INITRD_UNTYPED,
            child_cn,
            super::CAP_INITRD_UNTYPED,
            super::INITRD_COPY_RIGHTS,
        );
        // Note: root untypeds no longer mirrored -- children use mmsrv.

        // Mint CSpace expansion notification into child CNode
        let pm_ntfn = *(&raw const super::PM_BOUND_NTFN);
        if pm_ntfn != 0 {
            let cs_badge = 1u64 << (16 + slot_idx);
            let _ = trona::invoke::cnode_mint(
                super::CAP_SELF_CSPACE,
                pm_ntfn,
                child_cn,
                super::CHILD_CAP_CSPACE_NTFN,
                cs_badge,
            );
        }

        // Configure child TCB
        let err = trona::invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: set_space failed\n"); });
            alloc.rollback();
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Set fault handler: badged mmsrv EP so VMFaults route to mmsrv
        {
            let temp_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => {
                    alloc.rollback();
                    reply.label = super::TRONA_OUT_OF_MEMORY;
                    return;
                }
            };
            let err = trona::invoke::cnode_mint(
                super::CAP_SELF_CSPACE,
                super::CAP_MMSRV_EP_UNBADGED,
                super::CAP_SELF_CSPACE,
                temp_slot,
                child_pid as u64,
            );
            if err == 0 {
                trona::invoke::tcb_set_fault_handler(child_tcb, temp_slot);
            }
            trona::invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_slot);
            alloc.free_single_slot(temp_slot);
        }

        let err = trona::invoke::tcb_configure(child_tcb, child_entry, parent_rsp, 0);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: configure failed\n"); });
            alloc.rollback();
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        }
        // Copy parent's FPU/SSE state to child (preserves XMM registers across fork)
        let err = trona::invoke::tcb_copy_fpu(child_tcb, proctab(parent_idx).tcb_cap);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: copy FPU state failed\n"); });
            alloc.rollback();
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        }
        // Copy parent's TLS base to child TCB so FS_BASE is correct after
        // context switch.  The child has a COW copy of the parent's TLS block
        // at the same virtual address, so it needs the same FS_BASE.
        let parent_tls_base = msg.regs[9];
        if parent_tls_base != 0 {
            let err = trona::invoke::tcb_set_tls_base(child_tcb, parent_tls_base);
            if err != 0 {
                trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: set TLS base failed\n"); });
            }
        }

        let err = trona::invoke::tcb_set_ipc_buffer(child_tcb, parent_layout.ipc_buf.base);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: set IPC buf failed\n"); });
            alloc.rollback();
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Clone FD table BEFORE resuming child
        {
            let mut clone_msg = TronaMsg::zeroed();
            let mut clone_reply = TronaMsg::zeroed();
            clone_msg.label = trona::protocol::VFS_CLONE_FDS;
            clone_msg.length = 2;
            clone_msg.regs[0] = badge;
            clone_msg.regs[1] = child_pid as u64;
            let err = ipc::call_ctx(
                super::ipc_ctx(),
                super::CAP_VFS_EP,
                &raw const clone_msg,
                &raw mut clone_reply,
            );
            if err != 0 || clone_reply.label != super::TRONA_OK {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: VFS clone_fds failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b" reply=");
                    _lb.hex(clone_reply.label);
                    _lb.str(b", aborting fork\n");
                });
                alloc.rollback();
                reply.label = super::TRONA_INVALID_OPERATION;
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
            ipc::set_send_cap_ctx(super::ipc_ctx(), 0, child_vs);
            let err = ipc::call_ctx(
                super::ipc_ctx(),
                super::CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != super::TRONA_OK {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] FORK: mmsrv register failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                alloc.rollback();
                reply.label = super::TRONA_OUT_OF_MEMORY;
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
                super::ipc_ctx(),
                super::CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != super::TRONA_OK {
                trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: mmsrv fork_regions failed, aborting\n"); });
                // Deregister child from mmsrv and abort fork
                {
                    let mut dereg = TronaMsg::zeroed();
                    let mut drep = TronaMsg::zeroed();
                    dereg.label = trona::protocol::MM_DEREGISTER;
                    dereg.length = 1;
                    dereg.regs[0] = child_pid as u64;
                    let _ = ipc::call_ctx(
                        super::ipc_ctx(),
                        super::CAP_MMSRV_EP,
                        &raw const dereg,
                        &raw mut drep,
                    );
                }
                alloc.rollback();
                reply.label = super::TRONA_OUT_OF_MEMORY;
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
            mm_msg.regs[3] = super::VSPACE_FLAG_WRITABLE | super::VSPACE_FLAG_USER;
            let err = ipc::call_ctx(
                super::ipc_ctx(),
                super::CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != super::TRONA_OK || mm_reply.regs[0] != 1 {
                trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] FORK: MM_MAP_BATCH ipc failed\n"); });
                // Deregister child from mmsrv on failure
                {
                    let mut dereg = TronaMsg::zeroed();
                    let mut drep = TronaMsg::zeroed();
                    dereg.label = trona::protocol::MM_DEREGISTER;
                    dereg.length = 1;
                    dereg.regs[0] = child_pid as u64;
                    let _ = ipc::call_ctx(
                        super::ipc_ctx(),
                        super::CAP_MMSRV_EP,
                        &raw const dereg,
                        &raw mut drep,
                    );
                }
                alloc.rollback();
                reply.label = super::TRONA_OUT_OF_MEMORY;
                return;
            }
        }

        // Schedule the child
        let err = trona::invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 {
            alloc.rollback();
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        }
        let err = trona::invoke::sc_bind(child_sc, child_tcb);
        if err != 0 {
            alloc.rollback();
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        }

        // Commit and populate proc table BEFORE resume so the child can
        // immediately query procmgr (e.g. PM_GET_THREAD_CAPS) without racing.
        let (slot_base, slot_count) = alloc.commit();

        let p = proctab(slot_idx);
        p.set_posix_personality();
        p.pid = child_pid;
        p.ppid = parent_pid;
        p.state = PROC_RUNNING;
        p.exit_code = 0;
        p.badge = child_pid as u64;
        p.tcb_cap = child_tcb;
        p.vspace_cap = child_vs;
        p.cnode_cap = child_cn;
        p.sc_cap = child_sc;
        p.slot_base = slot_base;
        p.slot_count = slot_count;
        p.shared_lib_base = proctab(parent_idx).shared_lib_base;
        p.lib_map = parent_lib_map;
        p.layout = parent_layout;
        p.mmsrv_registered = true;
        p.has_service_ep = proctab(parent_idx).has_service_ep;
        p.timer_interval_ns = 0;
        p.timer_deadline_ns = 0;
        p.ready_ntfn = 0;
        p.wait_ready_on_resume = false;
        p.ready_timeout_ns = 0;
        p.pending_ready_reply = 0;
        p.pending_ready_deadline_ns = 0;
        {
            let posix = p.posix_mut();
            posix.waiter_reply = 0;
            posix.waiter_pid = 0;
            posix.signal_ntfn = child_sig_ntfn;
            posix.pgid = proctab(parent_idx).posix().pgid;
            posix.sid = proctab(parent_idx).posix().sid;
            posix.exe_path = proctab(parent_idx).posix().exe_path;
            for i in 0..NSIG {
                posix.sig_disposition[i] = proctab(parent_idx).posix().sig_disposition[i];
            }
            posix.umask = proctab(parent_idx).posix().umask;
        }

        let err = trona::invoke::tcb_resume(child_tcb);
        if err != 0 {
            // Unlikely after successful sc_bind, but clean up proc table entry.
            p.state = PROC_FREE;
            reply.label = super::TRONA_OUT_OF_MEMORY;
            return;
        }

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] FORK: child PID=");
            _lb.hex(child_pid as u64);
            _lb.str(b" started\n");
        });
        reply.label = super::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = child_pid as u64;
    }
}

unsafe fn abort_destroyed_exec(
    idx: usize,
    reply: &mut TronaMsg,
    vfs_source: &mut super::vfs_load::VfsExecSource,
) {
    unsafe {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] EXEC: terminating PID=");
            _lb.hex(proctab(idx).pid as u64);
            _lb.str(b" after destructive failure\n");
        });

        super::vfs_load::cleanup_exec_source(vfs_source);
        let _ = crate::posix::signal::terminate_proc(idx, crate::posix::PM_SIGKILL);
        reply.label = 0;
    }
}

pub(crate) unsafe fn handle_exec(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let alloc = &mut *(&raw mut super::ALLOCATOR);

        let Some(idx) = find_by_badge(badge) else {
            reply.label = super::TRONA_NOT_FOUND;
            return;
        };

        if msg.regs[0] > 64 {
            reply.label = super::TRONA_INVALID_ARGUMENT;
            return;
        }

        let (name, name_len) = super::extract_name(msg, 1);
        let mut exec_path = [0u8; crate::proc_table::MAX_EXE_PATH_LEN];
        let exec_path_len = super::vfs_load::derive_exec_path_for_badge(
            &name,
            name_len,
            badge,
            &mut exec_path,
        );

        // Parse argv/envp from message registers after the path
        let path_regs = 1 + ((msg.regs[0] as usize + 7) / 8);
        let argc: u32;
        let envc: u32;
        let mut exec_str_data = [0u8; IPC_BUFFER_RESERVED_BYTES];
        let exec_str_len: usize;
        if msg.length as usize <= path_regs + 1 {
            reply.label = super::TRONA_INVALID_ARGUMENT;
            return;
        }

        let packed = msg.regs[path_regs];
        argc = (packed >> 32) as u32;
        envc = (packed & 0xFFFF_FFFF) as u32;
        exec_str_len = msg.regs[path_regs + 1] as usize;
        if exec_str_len > exec_str_data.len() {
            reply.label = super::TRONA_OUT_OF_RANGE;
            return;
        }
        if exec_str_len != 0 {
            let ctx = &*super::ipc_ctx();
            if ctx.ipc_buffer.is_null() {
                reply.label = super::TRONA_INVALID_ARGUMENT;
                return;
            }

            let src = (*ctx.ipc_buffer).reserved.as_ptr() as *const u8;
            for i in 0..exec_str_len {
                exec_str_data[i] = *src.add(i);
            }
        }

        let mut argv0_len = 0usize;
        while argv0_len < exec_str_len && exec_str_data[argv0_len] != 0 {
            argv0_len += 1;
        }

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] EXEC PID=");
            _lb.hex(proctab(idx).pid as u64);
            _lb.str(b" -> '");
            _lb.bytes(&name[..name_len]);
            _lb.str(b"' argc=");
            _lb.hex(argc as u64);
            _lb.str(b" envc=");
            _lb.hex(envc as u64);
            _lb.str(b" argv0='");
            if argv0_len != 0 {
                _lb.bytes(&exec_str_data[..argv0_len]);
            }
            _lb.str(b"'\n");
        });
        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = super::read_boot_info_initrd_size();

        let mut elf_entry = CpioEntry::zeroed();

        let mut found = trona_loader::cpio::cpio_find_file(
            initrd,
            initrd_size,
            name.as_ptr(),
            name_len,
            &raw mut elf_entry,
        ) != 0;
        let mut base_off = 0usize;
        let mut base_len = name_len;
        if !found && name_len > 0 && name[0] == b'/' {
            base_off = 1;
            base_len = name_len - 1;
            found = trona_loader::cpio::cpio_find_file(
                initrd,
                initrd_size,
                (&name[base_off]) as *const u8,
                base_len,
                &raw mut elf_entry,
            ) != 0;
        }

        if !found && base_len + 4 <= MAX_NAME_LEN {
            let mut legacy = [0u8; MAX_NAME_LEN + 5];
            for i in 0..base_len {
                legacy[i] = name[base_off + i];
            }
            legacy[base_len] = b'.';
            legacy[base_len + 1] = b'e';
            legacy[base_len + 2] = b'l';
            legacy[base_len + 3] = b'f';
            found = trona_loader::cpio::cpio_find_file(
                initrd,
                initrd_size,
                legacy.as_ptr(),
                base_len + 4,
                &raw mut elf_entry,
            ) != 0;
        }
        // VFS fallback: use a buffered source for small files and a streamed
        // source for large ELFs to avoid buffering the entire binary in procmgr.
        let mut vfs_source = super::vfs_load::VfsExecSource::none();
        if !found {
            if let Some(source) =
                super::vfs_load::try_open_exec_source_from_vfs_for_badge(&name, name_len, badge)
            {
                if let Some((data, data_len)) = source.buffered_data() {
                    elf_entry.data = data;
                    elf_entry.data_len = data_len;
                }
                found = true;
                vfs_source = source;
            }
        }
        if !found {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] EXEC: ELF not found in initrd or VFS\n"); });
            reply.label = super::TRONA_NOT_FOUND;
            return;
        }

        let vfs_stream = vfs_source.streamed();
        let is_dynamic = if let Some(vfs) = vfs_stream {
            vfs.is_dynamic
        } else {
            trona_loader::elf_dynamic::elf_has_interp(elf_entry.data, elf_entry.data_len)
        };
        let proc_vs = proctab(idx).vspace_cap;
        let pid = proctab(idx).pid;

        // 1. Deregister old mappings from mmsrv so it doesn't hold stale frame refs
        super::spawn_tx::deregister_from_mmsrv(pid);

        // 2. Unmap existing user pages
        let mut walk_start: u64 = 0;
        loop {
            let err = trona::invoke::vspace_walk(proc_vs, walk_start, super::VSPACE_WALK_BATCH);
            if err != 0 {
                break;
            }
            let Some((count, next_addr)) = trona::invoke::vspace_walk_result_header() else {
                break;
            };
            if count == 0 {
                break;
            }

            for i in 0..count {
                let Some((page_vaddr, _, _)) = trona::invoke::vspace_walk_result_entry(i as usize)
                else {
                    break;
                };
                trona::invoke::vspace_unmap(proc_vs, page_vaddr);
            }

            if next_addr == 0 {
                break;
            }
            walk_start = next_addr;
        }

        // 2a. Clean old RTLD/dynamic slots from child CSpace to prevent slot collision
        {
            let child_cn = proctab(idx).cnode_cap;
            let frame_floor = if proctab(idx).has_service_ep {
                super::CHILD_CAP_SERVICE_EP + 1
            } else {
                super::CHILD_RTLD_FRAME_SLOT_START
            };
            let mut cnode_bits: u64 = 10;
            let cinfo = trona::invoke::cnode_get_info(child_cn);
            if cinfo.error == 0 {
                let ctx = &*super::ipc_ctx();
                if !ctx.ipc_buffer.is_null() {
                    let buf = &*ctx.ipc_buffer;
                    let bits = buf.msg[2];
                    if bits >= 4 && bits <= 16 {
                        cnode_bits = bits;
                    }
                }
            }
            let cnode_total = 1u64 << cnode_bits;
            for slot in frame_floor..cnode_total {
                trona::invoke::cnode_delete(child_cn, slot);
            }
        }

        // 2b. Free old procmgr-side frame slots beyond the fixed objects
        let old_slot_base = proctab(idx).slot_base;
        let old_slot_count = proctab(idx).slot_count as usize;
        let off_fixed = super::spawn_tx::OFF_FIXED_END;

        if old_slot_count > off_fixed {
            for i in off_fixed..old_slot_count {
                let slot = old_slot_base + i as u64;
                let err = trona::invoke::cnode_revoke(super::CAP_SELF_CSPACE, slot);
                if err != 0 {
                    trona::invoke::cnode_delete(super::CAP_SELF_CSPACE, slot);
                }
            }
            alloc.free_slots(old_slot_base + off_fixed as u64, old_slot_count - off_fixed);
            proctab(idx).slot_count = off_fixed as u16;
        }

        // 3. Compute layout
        let elf_span = if let Some(vfs) = vfs_stream {
            vfs.elf_span
        } else {
            trona_loader::elf_loader::elf_compute_load_span(elf_entry.data, elf_entry.data_len)
        };
        let rtld_span = if is_dynamic {
            if let Some(vfs) = vfs_stream {
                super::spawn_tx::count_rtld_span_by_name(
                    vfs.interp_name.as_ptr(),
                    vfs.interp_name_len,
                    initrd,
                    initrd_size,
                )
            } else {
                super::spawn_tx::count_rtld_span_for_exec(
                    elf_entry.data,
                    elf_entry.data_len,
                    initrd,
                    initrd_size,
                )
            }
        } else {
            0
        };
        let needed_owned = if is_dynamic && vfs_stream.is_none() {
            trona_loader::elf_dynamic::elf_get_needed(elf_entry.data, elf_entry.data_len)
        } else {
            trona_loader::elf_dynamic::NeededLibs::new()
        };
        let needed = if let Some(vfs) = vfs_stream {
            &vfs.needed
        } else {
            &needed_owned
        };
        let shared_lib_cache_pages = super::spawn_tx::shared_lib_va_pages_for_needed(needed);
        let lib_window_pages = if is_dynamic {
            super::spawn_tx::compute_lib_window_pages(initrd, initrd_size)
        } else {
            0
        };
        let layout = trona::layout::compute_vm_layout_randomized(
            elf_span,
            rtld_span,
            shared_lib_cache_pages,
            is_dynamic,
            lib_window_pages * 4096,
            || trona::syscall::sys_getrandom(),
        );
        if layout.stack_top == 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] EXEC: ELF too large for VA layout\n"); });
            abort_destroyed_exec(idx, reply, &mut vfs_source);
            return;
        }

        // 4. Re-register with mmsrv for the new exec image
        let heap_base = layout.heap_base();
        let mmap_base = trona::layout::compute_mmap_base(&layout, heap_base);
        super::spawn_tx::register_with_mmsrv(pid, proc_vs, heap_base, mmap_base);

        // 5. Load ELF via mmsrv
        let mut elf_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        let err = if let Some(vfs) = vfs_stream {
            super::spawn_tx::exec_load_elf_vfs_mmsrv(
                vfs,
                layout.elf_code.base,
                pid,
                proc_vs,
                &raw mut elf_result,
            )
        } else {
            super::spawn_tx::exec_load_elf_mmsrv(
                elf_entry.data,
                elf_entry.data_len,
                layout.elf_code.base,
                pid,
                proc_vs,
                &raw mut elf_result,
            )
        };
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] EXEC: ELF load failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            abort_destroyed_exec(idx, reply, &mut vfs_source);
            return;
        }

        // 5b. Load rtld if dynamic
        let mut rtld_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        if is_dynamic {
            let rtld_load = if let Some(vfs) = vfs_stream {
                super::spawn_tx::exec_load_rtld_mmsrv_by_name(
                    vfs.interp_name.as_ptr(),
                    vfs.interp_name_len,
                    initrd,
                    initrd_size,
                    layout.rtld.base,
                    pid,
                    proc_vs,
                )
            } else {
                super::spawn_tx::exec_load_rtld_mmsrv(
                    elf_entry.data,
                    elf_entry.data_len,
                    initrd,
                    initrd_size,
                    layout.rtld.base,
                    pid,
                    proc_vs,
                )
            };
            match rtld_load {
                Some(r) => rtld_result = r,
                None => {
                    abort_destroyed_exec(idx, reply, &mut vfs_source);
                    return;
                }
            }
        }
        // 6. Map initrd and boot info for dynamic executables
        if is_dynamic {
            let initrd_window_size = lib_window_pages * 4096;
            let err = super::spawn_tx::exec_map_initrd_mmsrv(
                proc_vs,
                initrd,
                initrd_window_size,
                pid,
                layout.initrd.base,
            );
            if err != 0 {
                abort_destroyed_exec(idx, reply, &mut vfs_source);
                return;
            }

            let err = super::spawn_tx::exec_map_bootinfo_mmsrv(pid);
            if err != 0 {
                abort_destroyed_exec(idx, reply, &mut vfs_source);
                return;
            }
        }

        // 7. Map IPC buffer via mmsrv
        let err = super::spawn_tx::exec_map_ipc_buf_mmsrv(pid, layout.ipc_buf.base);
        if err != 0 {
            abort_destroyed_exec(idx, reply, &mut vfs_source);
            return;
        }

        // 8. Map shared library frames if available
        let (shared_lib_base, shared_lib_map) = if is_dynamic {
            super::spawn_tx::map_shared_lib_to_vspace(
                proc_vs,
                layout.shared_libs.base,
                needed,
                pid,
            )
        } else {
            (0, crate::proc_table::ProcLibMap::zeroed())
        };

        // 9. Build the stack top page locally, then materialize it in mmsrv.
        let stack_pages = layout.stack.page_count();
        let stack_stage = super::spawn_tx::alloc_staging_buffer(1);
        if stack_stage.is_null() {
            abort_destroyed_exec(idx, reply, &mut vfs_source);
            return;
        }
        super::spawn_tx::volatile_zero(stack_stage, 4096);

        // 10. Entry point and final stack image.
        let mut new_entry = elf_result.entry;
        let new_rsp: u64;
        let (phdr_vaddr, phent, phnum) = if let Some(vfs) = vfs_stream {
            (
                layout.elf_code.base + vfs.phdr_vaddr,
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
                layout.elf_code.base,
                &raw mut phdr_vaddr,
                &raw mut phent,
                &raw mut phnum,
            ) != 0
            {
                super::spawn_tx::free_staging_buffer(stack_stage, 1);
                abort_destroyed_exec(idx, reply, &mut vfs_source);
                return;
            }
            (phdr_vaddr, phent, phnum)
        };

        if is_dynamic {
            let mut exec_cnode_bits: u64 = 10;
            let cinfo = trona::invoke::cnode_get_info(proctab(idx).cnode_cap);
            if cinfo.error == 0 {
                let ctx = &*super::ipc_ctx();
                if !ctx.ipc_buffer.is_null() {
                    let buf = &*ctx.ipc_buffer;
                    let bits = buf.msg[2];
                    if bits >= 4 && bits <= 16 {
                        exec_cnode_bits = bits;
                    }
                }
            }
            match super::spawn_tx::write_dynamic_stack(
                phdr_vaddr,
                phent,
                phnum,
                0,
                &elf_result,
                &rtld_result,
                lib_window_pages * 4096,
                shared_lib_base,
                argc,
                envc,
                &exec_str_data,
                exec_str_len,
                layout.scratch.base,
                layout.initrd.base,
                layout.stack_top,
                exec_cnode_bits,
                if proctab(idx).has_service_ep {
                    super::CHILD_CAP_SERVICE_EP + 1
                } else {
                    super::CHILD_RTLD_FRAME_SLOT_START
                },
                stack_stage,
                true,
            ) {
                Ok(rsp) => {
                    new_rsp = rsp;
                    new_entry = rtld_result.entry;
                }
                Err(_) => {
                    super::spawn_tx::free_staging_buffer(stack_stage, 1);
                    abort_destroyed_exec(idx, reply, &mut vfs_source);
                    return;
                }
            }
        } else {
            match super::spawn_tx::write_static_stack(
                0,
                argc,
                envc,
                &exec_str_data,
                exec_str_len,
                layout.scratch.base,
                layout.initrd.base,
                layout.stack_top,
                stack_stage,
                true,
            ) {
                Ok(rsp) => {
                    new_rsp = rsp;
                }
                Err(_) => {
                    super::spawn_tx::free_staging_buffer(stack_stage, 1);
                    abort_destroyed_exec(idx, reply, &mut vfs_source);
                    return;
                }
            }
        }

        match super::spawn_tx::alloc_private_copy_from_client_region_to_mmsrv(
            pid,
            layout.stack.base,
            stack_pages as u64,
            layout.stack_top - 4096,
            stack_stage as u64,
            1,
            super::VSPACE_FLAG_WRITABLE | super::VSPACE_FLAG_USER,
        ) {
            Ok(base) if base == layout.stack.base => {}
            _ => {
                super::spawn_tx::free_staging_buffer(stack_stage, 1);
                abort_destroyed_exec(idx, reply, &mut vfs_source);
                return;
            }
        }
        super::spawn_tx::free_staging_buffer(stack_stage, 1);

        // ELF scratch buffer no longer needed (all elf_entry.data users complete).
        super::vfs_load::cleanup_exec_source(&mut vfs_source);

        // 11. Suspend and reconfigure
        let susp_err = trona::invoke::tcb_suspend_retry(proctab(idx).tcb_cap, 64);
        if susp_err != 0 {
            trona::syscall::syscall(trona::SYS_NANOSLEEP, 2_000_000, 0, 0, 0, 0, 0);
            let err2 = trona::invoke::tcb_suspend_retry(proctab(idx).tcb_cap, 64);
            if err2 != 0 {
                trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] EXEC: tcb_suspend failed\n"); });
                abort_destroyed_exec(idx, reply, &mut vfs_source);
                return;
            }
        }
        trona::syscall::syscall(trona::SYS_YIELD, 0, 0, 0, 0, 0, 0);

        // POSIX: exec resets caught signals to SIG_DFL
        if proctab(idx).is_posix() {
            for i in 0..NSIG {
                if proctab(idx).posix().sig_disposition[i] == SIG_DISP_CATCH {
                    proctab(idx).posix_mut().sig_disposition[i] = SIG_DISP_DFL;
                }
            }
        }

        let err = trona::invoke::tcb_configure(proctab(idx).tcb_cap, new_entry, new_rsp, 0);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] EXEC: tcb_configure failed\n"); });
            abort_destroyed_exec(idx, reply, &mut vfs_source);
            return;
        }
        let err = trona::invoke::tcb_set_tls_base(proctab(idx).tcb_cap, 0);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] EXEC: clear TLS base failed\n"); });
            abort_destroyed_exec(idx, reply, &mut vfs_source);
            return;
        }
        trona::invoke::tcb_set_ipc_buffer(proctab(idx).tcb_cap, layout.ipc_buf.base);

        let err = trona::invoke::tcb_resume(proctab(idx).tcb_cap);
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[PROCMGR] EXEC: resume failed\n"); });
            abort_destroyed_exec(idx, reply, &mut vfs_source);
            return;
        }

        proctab(idx).shared_lib_base = shared_lib_base;
        proctab(idx).lib_map = shared_lib_map;
        proctab(idx).layout = layout;

        // Update process name from exec binary
        {
            let name_copy = if name_len > 31 { 31 } else { name_len };
            for i in 0..name_copy {
                proctab(idx).name[i] = name[i];
            }
            for i in name_copy..32 {
                proctab(idx).name[i] = 0;
            }
            if proctab(idx).is_posix() {
                let exe_copy = if exec_path_len >= crate::proc_table::MAX_EXE_PATH_LEN {
                    crate::proc_table::MAX_EXE_PATH_LEN - 1
                } else {
                    exec_path_len
                };
                for i in 0..exe_copy {
                    proctab(idx).posix_mut().exe_path[i] = exec_path[i];
                }
                for i in exe_copy..crate::proc_table::MAX_EXE_PATH_LEN {
                    proctab(idx).posix_mut().exe_path[i] = 0;
                }
            }
        }

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] EXEC: PID=");
            _lb.hex(proctab(idx).pid as u64);
            _lb.str(b" -> entry=");
            _lb.hex(new_entry);
            _lb.str(b"\n");
        });

        // Don't reply -- process image replaced and resumed.
    }
}
