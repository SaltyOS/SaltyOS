//! Fork and exec handlers
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

use salty::ipc;
use salty::serial::LineBuf;
use salty::types::*;

use crate::proc_table::{
    alloc_proc, find_by_badge, proctab, proctab_cap, MAX_NAME_LEN, NEXT_PID, NSIG, PROC_RUNNING,
    SIG_DISP_CATCH, SIG_DISP_DFL,
};

pub(crate) unsafe fn handle_fork(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let alloc = &mut *(&raw mut super::ALLOCATOR);

        let parent_rsp = msg.regs[0];
        let child_entry = msg.regs[1];

        if child_entry == 0 {
            reply.label = super::SALTY_INVALID_ARGUMENT;
            return;
        }

        let Some(parent_idx) = find_by_badge(badge) else {
            super::puts(b"[PROCMGR] FORK from unknown badge\n");
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };
        let parent_pid = proctab(parent_idx).pid;
        let parent_vs = proctab(parent_idx).vspace_cap;

        let _parent_shared_base = proctab(parent_idx).shared_lib_base;
        let parent_lib_map = proctab(parent_idx).lib_map;
        let parent_layout = proctab(parent_idx).layout;
        let initrd_base = parent_layout.initrd.base;
        let initrd_end = parent_layout
            .initrd
            .base
            .saturating_add(parent_layout.initrd.size);
        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] FORK from PID=");
            lb.hex(parent_pid as u64);
            lb.str(b"\n");
            lb.flush();
        }

        let Some(slot_idx) = alloc_proc() else {
            super::puts(b"[PROCMGR] FORK: process table full\n");
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        };

        let child_pid = NEXT_PID;
        NEXT_PID += 1;

        // Count parent pages as an upper bound for reservation sizing
        // (skip IPC buf and initrd window pages).
        let mut page_count: usize = 0;
        {
            let mut walk_start: u64 = 0;
            loop {
                let err =
                    salty::invoke::vspace_walk(parent_vs, walk_start, super::VSPACE_WALK_BATCH);
                if err != 0 {
                    break;
                }
                let Some((count, next_addr)) = salty::invoke::vspace_walk_result_header() else {
                    break;
                };
                if count == 0 {
                    break;
                }
                for i in 0..count as usize {
                    let Some((page_vaddr, _, _)) = salty::invoke::vspace_walk_result_entry(i)
                    else {
                        break;
                    };
                    if page_vaddr == parent_layout.ipc_buf.base {
                        continue;
                    }
                    if parent_layout.initrd.size > 0
                        && page_vaddr >= initrd_base
                        && page_vaddr < initrd_end
                    {
                        continue;
                    }
                    page_count += 1;
                }
                if next_addr == 0 {
                    break;
                }
                walk_start = next_addr;
            }
        }

        // Reserve with a generous upper bound (fixed objects + page budget + margin).
        let total_slots = 7 + page_count + 4;
        if !alloc.reserve(total_slots) {
            super::puts(b"[PROCMGR] FORK: slot reservation failed\n");
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }

        // Core objects (TCB/VSpace/CNode/SC) prefer primary untyped.
        macro_rules! realize_core {
            ($ty:expr, $what:expr) => {
                match alloc.realize_core_object($ty, 0) {
                    Ok(s) => s,
                    Err(_) => {
                        super::puts($what);
                        alloc.rollback();
                        reply.label = super::SALTY_OUT_OF_MEMORY;
                        return;
                    }
                }
            };
        }
        macro_rules! realize {
            ($ty:expr, $what:expr) => {
                match alloc.realize_object($ty, 0) {
                    Ok(s) => s,
                    Err(_) => {
                        super::puts($what);
                        alloc.rollback();
                        reply.label = super::SALTY_OUT_OF_MEMORY;
                        return;
                    }
                }
            };
        }

        let child_tcb = realize_core!(super::OBJ_TCB, b"[PROCMGR] FORK: TCB retype failed\n");
        let child_vs = realize_core!(super::OBJ_VSPACE, b"[PROCMGR] FORK: VSpace retype failed\n");
        let child_cn = realize_core!(super::OBJ_CNODE, b"[PROCMGR] FORK: CNode retype failed\n");
        let child_sc = realize_core!(
            super::OBJ_SCHED_CONTEXT,
            b"[PROCMGR] FORK: SC retype failed\n"
        );
        // IPC frame allocated by mmsrv via MM_MAP_BATCH below
        let child_sig_ntfn = realize!(
            super::OBJ_NOTIFICATION,
            b"[PROCMGR] FORK: signal ntfn retype failed\n"
        );

        // Walk parent VSpace again and copy pages
        let mut walk_start: u64 = 0;
        let child_entry_page = child_entry & !0xFFFu64;
        let mut child_entry_path: u64 = 0;

        loop {
            let err = salty::invoke::vspace_walk(parent_vs, walk_start, super::VSPACE_WALK_BATCH);
            if err != 0 {
                break;
            }
            let Some((count, next_addr)) = salty::invoke::vspace_walk_result_header() else {
                break;
            };
            if count == 0 {
                break;
            }

            for i in 0..count as usize {
                let Some((page_vaddr, _, _)) = salty::invoke::vspace_walk_result_entry(i) else {
                    break;
                };
                if page_vaddr == parent_layout.ipc_buf.base {
                    continue;
                }

                // Skip initrd window pages -- child doesn't need them after fork
                if parent_layout.initrd.size > 0
                    && page_vaddr >= initrd_base
                    && page_vaddr < initrd_end
                {
                    continue;
                }

                let cerr = salty::invoke::vspace_clone_cow_page(
                    parent_vs, page_vaddr, child_vs, page_vaddr,
                );
                if cerr != 0 {
                    let mut lb = LineBuf::new();
                    lb.str(b"[PROCMGR] FORK: clone_cow failed at ");
                    lb.hex(page_vaddr);
                    lb.str(b" err=");
                    lb.hex(cerr as u64);
                    lb.str(b"\n");
                    lb.flush();
                    alloc.rollback();
                    reply.label = super::SALTY_INVALID_OPERATION;
                    return;
                }

                if page_vaddr == child_entry_page {
                    child_entry_path = 3; // COW clone
                }
            }

            if next_addr == 0 {
                break;
            }
            walk_start = next_addr;
        }

        if child_entry_path != 3 {
            super::puts(b"[PROCMGR] FORK: child entry page missing after COW clone\n");
            alloc.rollback();
            reply.label = super::SALTY_INVALID_OPERATION;
            return;
        }

        // Mint mmsrv EP into child CNode slot 7 (badged with child pid)
        let err = salty::invoke::cnode_mint(
            super::CAP_SELF_CSPACE,
            super::CAP_MMSRV_EP_UNBADGED,
            child_cn,
            super::CHILD_CAP_MMSRV_EP,
            child_pid as u64,
        );
        if err != 0 {
            super::puts(b"[PROCMGR] FORK: mint mmsrv EP failed\n");
            alloc.rollback();
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }

        // Copy caps into child CNode
        macro_rules! copy_or_fail {
            ($src:expr, $dst:expr, $what:expr) => {
                if salty::invoke::cnode_copy(
                    super::CAP_SELF_CSPACE,
                    $src,
                    child_cn,
                    $dst,
                    super::CAP_RIGHTS_ALL,
                ) != 0
                {
                    super::puts($what);
                    alloc.rollback();
                    reply.label = super::SALTY_OUT_OF_MEMORY;
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

        let err = salty::invoke::cnode_mint(
            super::CAP_SELF_CSPACE,
            super::CAP_SERVER_EP,
            child_cn,
            super::CHILD_CAP_EP,
            child_pid as u64,
        );
        if err != 0 {
            super::puts(b"[PROCMGR] FORK: mint server EP failed\n");
            alloc.rollback();
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }
        let err = salty::invoke::cnode_mint(
            super::CAP_SELF_CSPACE,
            super::CAP_VFS_EP,
            child_cn,
            super::CHILD_CAP_VFS,
            child_pid as u64,
        );
        if err != 0 {
            super::puts(b"[PROCMGR] FORK: mint child VFS EP failed\n");
            alloc.rollback();
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }
        let _ = salty::invoke::cnode_copy(
            super::CAP_SELF_CSPACE,
            super::CAP_NAMESERV_EP,
            child_cn,
            super::CHILD_CAP_NAMESERV,
            super::CAP_RIGHTS_ALL,
        );
        let _ = salty::invoke::cnode_copy(
            super::CAP_SELF_CSPACE,
            child_sig_ntfn,
            child_cn,
            super::CHILD_CAP_SIGNAL_NTFN,
            super::CAP_RIGHTS_ALL,
        );
        // Keep fork child cap layout aligned with spawn path so rtld/slot alloc
        // can use initrd device mapping and mirrored untyped sources.
        let _ = salty::invoke::cnode_copy(
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
            let _ = salty::invoke::cnode_mint(
                super::CAP_SELF_CSPACE,
                pm_ntfn,
                child_cn,
                super::CHILD_CAP_CSPACE_NTFN,
                cs_badge,
            );
        }

        // Configure child TCB
        let err = salty::invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            super::puts(b"[PROCMGR] FORK: set_space failed\n");
            alloc.rollback();
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }

        // Set fault handler: badged mmsrv EP so VMFaults route to mmsrv
        {
            let temp_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => {
                    alloc.rollback();
                    reply.label = super::SALTY_OUT_OF_MEMORY;
                    return;
                }
            };
            let err = salty::invoke::cnode_mint(
                super::CAP_SELF_CSPACE,
                super::CAP_MMSRV_EP_UNBADGED,
                super::CAP_SELF_CSPACE,
                temp_slot,
                child_pid as u64,
            );
            if err == 0 {
                salty::invoke::tcb_set_fault_handler(child_tcb, temp_slot);
            }
            salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_slot);
            alloc.free_single_slot(temp_slot);
        }

        let err = salty::invoke::tcb_configure(child_tcb, child_entry, parent_rsp, 0);
        if err != 0 {
            super::puts(b"[PROCMGR] FORK: configure failed\n");
            alloc.rollback();
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }
        // Copy parent's FPU/SSE state to child (preserves XMM registers across fork)
        let err = salty::invoke::tcb_copy_fpu(child_tcb, proctab(parent_idx).tcb_cap);
        if err != 0 {
            super::puts(b"[PROCMGR] FORK: copy FPU state failed\n");
            alloc.rollback();
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }
        // Copy parent's TLS base to child TCB so FS_BASE is correct after
        // context switch.  The child has a COW copy of the parent's TLS block
        // at the same virtual address, so it needs the same FS_BASE.
        let parent_tls_base = msg.regs[9];
        if parent_tls_base != 0 {
            let err = salty::invoke::tcb_set_tls_base(child_tcb, parent_tls_base);
            if err != 0 {
                super::puts(b"[PROCMGR] FORK: set TLS base failed\n");
            }
        }

        let err = salty::invoke::tcb_set_ipc_buffer(child_tcb, parent_layout.ipc_buf.base);
        if err != 0 {
            super::puts(b"[PROCMGR] FORK: set IPC buf failed\n");
            alloc.rollback();
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }

        // Clone FD table BEFORE resuming child
        {
            let mut clone_msg = SaltyMsg::zeroed();
            let mut clone_reply = SaltyMsg::zeroed();
            clone_msg.label = salty::consts::POSIX_VFS_CLONE_FDS;
            clone_msg.length = 2;
            clone_msg.regs[0] = badge;
            clone_msg.regs[1] = child_pid as u64;
            let err = ipc::call_ctx(
                super::ipc_ctx(),
                super::CAP_VFS_EP,
                &raw const clone_msg,
                &raw mut clone_reply,
            );
            if err != 0 || clone_reply.label != super::SALTY_OK {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] FORK: VFS clone_fds failed err=");
                lb.hex(err as u64);
                lb.str(b" reply=");
                lb.hex(clone_reply.label);
                lb.str(b", aborting fork\n");
                lb.flush();
                alloc.rollback();
                reply.label = super::SALTY_INVALID_OPERATION;
                return;
            }
        }

        // Register child with mmsrv (VSpace cap transfer + initial state)
        {
            let fork_heap_base = parent_layout.elf_code.end();
            let fork_mmap_base = salty::layout::compute_mmap_base(&parent_layout, fork_heap_base);
            let mut mm_msg = SaltyMsg::zeroed();
            let mut mm_reply = SaltyMsg::zeroed();
            mm_msg.label = salty::consts::MM_REGISTER;
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
            if err != 0 || mm_reply.label != super::SALTY_OK {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] FORK: mmsrv register failed err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
                alloc.rollback();
                reply.label = super::SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // Clone parent's memory state to child in mmsrv
        {
            let mut mm_msg = SaltyMsg::zeroed();
            let mut mm_reply = SaltyMsg::zeroed();
            mm_msg.label = salty::consts::MM_FORK_REGIONS;
            mm_msg.length = 2;
            mm_msg.regs[0] = badge; // parent badge
            mm_msg.regs[1] = child_pid as u64; // child badge
            let err = ipc::call_ctx(
                super::ipc_ctx(),
                super::CAP_MMSRV_EP,
                &raw const mm_msg,
                &raw mut mm_reply,
            );
            if err != 0 || mm_reply.label != super::SALTY_OK {
                super::puts(b"[PROCMGR] FORK: mmsrv fork_regions failed\n");
            }
        }

        // Map IPC buffer for child via mmsrv (zero-filled, child only)
        {
            let mut mm_msg = SaltyMsg::zeroed();
            let mut mm_reply = SaltyMsg::zeroed();
            mm_msg.label = salty::consts::MM_MAP_BATCH;
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
            if err != 0 || mm_reply.label != super::SALTY_OK || mm_reply.regs[0] != 1 {
                super::puts(b"[PROCMGR] FORK: MM_MAP_BATCH ipc failed\n");
                // Deregister child from mmsrv on failure
                {
                    let mut dereg = SaltyMsg::zeroed();
                    let mut drep = SaltyMsg::zeroed();
                    dereg.label = salty::consts::MM_DEREGISTER;
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
                reply.label = super::SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // Schedule the child
        let err = salty::invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 {
            alloc.rollback();
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }
        let err = salty::invoke::sc_bind(child_sc, child_tcb);
        if err != 0 {
            alloc.rollback();
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }
        let err = salty::invoke::tcb_resume(child_tcb);
        if err != 0 {
            alloc.rollback();
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }

        // Commit and record
        let (slot_base, slot_count) = alloc.commit();

        let p = proctab(slot_idx);
        p.pid = child_pid;
        p.ppid = parent_pid;
        p.sid = proctab(parent_idx).sid;
        p.state = PROC_RUNNING;
        p.exit_code = 0;
        p.badge = child_pid as u64;
        p.tcb_cap = child_tcb;
        p.vspace_cap = child_vs;
        p.cnode_cap = child_cn;
        p.sc_cap = child_sc;
        p.waiter_reply = 0;
        p.waiter_pid = 0;
        p.signal_ntfn = child_sig_ntfn;
        p.pgid = proctab(parent_idx).pgid;
        p.slot_base = slot_base;
        p.slot_count = slot_count;
        p.shared_lib_base = proctab(parent_idx).shared_lib_base;
        p.lib_map = parent_lib_map;
        p.layout = parent_layout;
        p.mmsrv_registered = true;
        p.has_service_ep = proctab(parent_idx).has_service_ep;
        for i in 0..NSIG {
            p.sig_disposition[i] = proctab(parent_idx).sig_disposition[i];
        }
        p.umask = proctab(parent_idx).umask;

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] FORK: child PID=");
            lb.hex(child_pid as u64);
            lb.str(b" started\n");
            lb.flush();
        }
        reply.label = super::SALTY_OK;
        reply.length = 1;
        reply.regs[0] = child_pid as u64;
    }
}

pub(crate) unsafe fn handle_exec(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let alloc = &mut *(&raw mut super::ALLOCATOR);

        let Some(idx) = find_by_badge(badge) else {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        };

        let (name, name_len) = super::extract_name(msg, 1);

        // Parse argv/envp from message registers after the path
        let path_regs = 1 + ((msg.regs[0] as usize + 7) / 8);
        let mut argc: u32 = 0;
        let mut envc: u32 = 0;
        let mut exec_str_data = [0u8; 128];
        let mut exec_str_len: usize = 0;
        if msg.length as usize > path_regs {
            let packed = msg.regs[path_regs];
            argc = (packed >> 32) as u32;
            envc = (packed & 0xFFFF_FFFF) as u32;
            let str_start = path_regs + 1;
            if msg.length as usize > str_start {
                let str_regs = msg.length as usize - str_start;
                let str_bytes = str_regs * 8;
                exec_str_len = if str_bytes > 128 { 128 } else { str_bytes };
                let src = &msg.regs[str_start] as *const u64 as *const u8;
                for i in 0..exec_str_len {
                    exec_str_data[i] = *src.add(i);
                }
            }
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] EXEC PID=");
            lb.hex(proctab(idx).pid as u64);
            lb.str(b" -> '");
            lb.bytes(&name[..name_len]);
            lb.str(b"' argc=");
            lb.hex(argc as u64);
            lb.str(b" envc=");
            lb.hex(envc as u64);
            lb.str(b"\n");
            lb.flush();
        }
        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = super::read_boot_info_initrd_size();

        let mut elf_entry = CpioEntry::zeroed();

        let mut found = salty::cpio::cpio_find_file(
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
            found = salty::cpio::cpio_find_file(
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
            found = salty::cpio::cpio_find_file(
                initrd,
                initrd_size,
                legacy.as_ptr(),
                base_len + 4,
                &raw mut elf_entry,
            ) != 0;
        }
        if !found {
            super::puts(b"[PROCMGR] EXEC: ELF not found\n");
            reply.label = super::SALTY_NOT_FOUND;
            return;
        }

        let is_dynamic = salty::elf_dynamic::elf_has_interp(elf_entry.data, elf_entry.data_len);
        let proc_vs = proctab(idx).vspace_cap;
        let pid = proctab(idx).pid;

        // 1. Deregister old mappings from mmsrv so it doesn't hold stale frame refs
        super::spawn_tx::deregister_from_mmsrv(pid);

        // 2. Unmap existing user pages
        let mut walk_start: u64 = 0;
        loop {
            let err = salty::invoke::vspace_walk(proc_vs, walk_start, super::VSPACE_WALK_BATCH);
            if err != 0 {
                break;
            }
            let Some((count, next_addr)) = salty::invoke::vspace_walk_result_header() else {
                break;
            };
            if count == 0 {
                break;
            }

            for i in 0..count {
                let Some((page_vaddr, _, _)) = salty::invoke::vspace_walk_result_entry(i as usize)
                else {
                    break;
                };
                salty::invoke::vspace_unmap(proc_vs, page_vaddr);
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
            let cinfo = salty::invoke::cnode_get_info(child_cn);
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
                salty::invoke::cnode_delete(child_cn, slot);
            }
        }

        // 2b. Free old procmgr-side frame slots beyond the fixed objects
        let old_slot_base = proctab(idx).slot_base;
        let old_slot_count = proctab(idx).slot_count as usize;
        let off_fixed = super::spawn_tx::OFF_FIXED_END;

        if old_slot_count > off_fixed {
            for i in off_fixed..old_slot_count {
                let slot = old_slot_base + i as u64;
                let err = salty::invoke::cnode_revoke(super::CAP_SELF_CSPACE, slot);
                if err != 0 {
                    salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, slot);
                }
            }
            alloc.free_slots(old_slot_base + off_fixed as u64, old_slot_count - off_fixed);
            proctab(idx).slot_count = off_fixed as u16;
        }

        // 3. Compute layout
        let elf_span = salty::elf_loader::elf_compute_load_span(elf_entry.data, elf_entry.data_len);
        let rtld_span = if is_dynamic {
            super::spawn_tx::count_rtld_span_for_exec(
                elf_entry.data,
                elf_entry.data_len,
                initrd,
                initrd_size,
            )
        } else {
            0
        };
        let needed = if is_dynamic {
            salty::elf_dynamic::elf_get_needed(elf_entry.data, elf_entry.data_len)
        } else {
            salty::elf_dynamic::NeededLibs::new()
        };
        let shared_lib_cache_pages = super::spawn_tx::shared_lib_va_pages_for_needed(&needed);
        let lib_window_pages = if is_dynamic {
            super::spawn_tx::compute_lib_window_pages(initrd, initrd_size)
        } else {
            0
        };
        let layout = salty::layout::compute_vm_layout_randomized(
            elf_span,
            rtld_span,
            shared_lib_cache_pages,
            is_dynamic,
            lib_window_pages * 4096,
            || salty::syscall::sys_getrandom(),
        );
        if layout.stack_top == 0 {
            super::puts(b"[PROCMGR] EXEC: ELF too large for VA layout\n");
            reply.label = super::SALTY_INVALID_ARGUMENT;
            return;
        }

        // 4. Re-register with mmsrv for the new exec image
        let heap_base = layout.heap_base();
        let mmap_base = salty::layout::compute_mmap_base(&layout, heap_base);
        super::spawn_tx::register_with_mmsrv(pid, proc_vs, heap_base, mmap_base);

        // 5. Load ELF via mmsrv
        let mut elf_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        let err = super::spawn_tx::exec_load_elf_mmsrv(
            elf_entry.data,
            elf_entry.data_len,
            layout.elf_code.base,
            pid,
            proc_vs,
            &raw mut elf_result,
        );
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] EXEC: ELF load failed err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            super::spawn_tx::deregister_from_mmsrv(pid);
            reply.label = super::SALTY_INVALID_ARGUMENT;
            return;
        }

        // 5b. Load rtld if dynamic
        let mut rtld_result = ElfLoadResult {
            entry: 0,
            base: 0,
            brk: 0,
        };
        if is_dynamic {
            match super::spawn_tx::exec_load_rtld_mmsrv(
                elf_entry.data,
                elf_entry.data_len,
                initrd,
                initrd_size,
                layout.rtld.base,
                pid,
                proc_vs,
            ) {
                Some(r) => rtld_result = r,
                None => {
                    super::spawn_tx::deregister_from_mmsrv(pid);
                    reply.label = super::SALTY_NOT_FOUND;
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
                super::spawn_tx::deregister_from_mmsrv(pid);
                reply.label = super::SALTY_OUT_OF_MEMORY;
                return;
            }

            let err = super::spawn_tx::exec_map_bootinfo_mmsrv(pid);
            if err != 0 {
                super::spawn_tx::deregister_from_mmsrv(pid);
                reply.label = super::SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // 7. Map IPC buffer via mmsrv
        let err = super::spawn_tx::exec_map_ipc_buf_mmsrv(pid, layout.ipc_buf.base);
        if err != 0 {
            super::spawn_tx::deregister_from_mmsrv(pid);
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }

        // 8. Map shared library frames if available
        let (shared_lib_base, shared_lib_map) = if is_dynamic {
            super::spawn_tx::map_shared_lib_to_vspace(
                proc_vs,
                layout.shared_libs.base,
                &needed,
                pid,
            )
        } else {
            (0, crate::proc_table::ProcLibMap::zeroed())
        };

        // 9. Set up stack via mmsrv (top page left mapped at PROCMGR_SCRATCH_VADDR)
        let stack_pages = layout.stack.page_count();
        let err = super::spawn_tx::exec_map_stack_mmsrv(
            pid,
            layout.stack.base,
            stack_pages,
            layout.stack_top,
        );
        if err != 0 {
            super::spawn_tx::deregister_from_mmsrv(pid);
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }

        // 10. Entry point and dynamic stack (top page already at PROCMGR_SCRATCH_VADDR)
        let mut new_entry = elf_result.entry;
        let mut new_rsp: u64;

        if is_dynamic {
            let mut exec_cnode_bits: u64 = 10;
            let cinfo = salty::invoke::cnode_get_info(proctab(idx).cnode_cap);
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
                elf_entry.data,
                elf_entry.data_len,
                0,
                &elf_result,
                &rtld_result,
                lib_window_pages * 4096,
                shared_lib_base,
                argc,
                envc,
                &exec_str_data,
                exec_str_len,
                layout.elf_code.base,
                layout.scratch.base,
                layout.initrd.base,
                layout.stack_top,
                exec_cnode_bits,
                if proctab(idx).has_service_ep {
                    super::CHILD_CAP_SERVICE_EP + 1
                } else {
                    super::CHILD_RTLD_FRAME_SLOT_START
                },
                true, // pre-mapped: stack top already at PROCMGR_SCRATCH_VADDR via mmsrv
            ) {
                Ok(rsp) => {
                    new_rsp = rsp;
                    new_entry = rtld_result.entry;
                }
                Err(()) => {
                    super::spawn_tx::unmap_window_from_mmsrv(super::PROCMGR_SCRATCH_VADDR, 1);
                    super::spawn_tx::deregister_from_mmsrv(pid);
                    reply.label = super::SALTY_OUT_OF_MEMORY;
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
                true, // pre-mapped: stack top already at PROCMGR_SCRATCH_VADDR via mmsrv
            ) {
                Ok(rsp) => {
                    new_rsp = rsp;
                }
                Err(()) => {
                    super::spawn_tx::unmap_window_from_mmsrv(super::PROCMGR_SCRATCH_VADDR, 1);
                    super::spawn_tx::deregister_from_mmsrv(pid);
                    reply.label = super::SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
        }

        // Unmap the stack top write window
        super::spawn_tx::unmap_window_from_mmsrv(super::PROCMGR_SCRATCH_VADDR, 1);

        // 11. Suspend and reconfigure
        let susp_err = salty::invoke::tcb_suspend_retry(proctab(idx).tcb_cap, 16);
        if susp_err != 0 {
            super::puts(b"[PROCMGR] EXEC: tcb_suspend failed\n");
            super::spawn_tx::deregister_from_mmsrv(pid);
            reply.label = super::SALTY_BUSY;
            return;
        }

        // POSIX: exec resets caught signals to SIG_DFL
        for i in 0..NSIG {
            if proctab(idx).sig_disposition[i] == SIG_DISP_CATCH {
                proctab(idx).sig_disposition[i] = SIG_DISP_DFL;
            }
        }

        let err = salty::invoke::tcb_configure(proctab(idx).tcb_cap, new_entry, new_rsp, 0);
        if err != 0 {
            super::puts(b"[PROCMGR] EXEC: tcb_configure failed\n");
            super::spawn_tx::deregister_from_mmsrv(pid);
            reply.label = super::SALTY_INVALID_ARGUMENT;
            return;
        }
        salty::invoke::tcb_set_ipc_buffer(proctab(idx).tcb_cap, layout.ipc_buf.base);

        let err = salty::invoke::tcb_resume(proctab(idx).tcb_cap);
        if err != 0 {
            super::puts(b"[PROCMGR] EXEC: resume failed\n");
            super::spawn_tx::deregister_from_mmsrv(pid);
            reply.label = super::SALTY_INVALID_ARGUMENT;
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
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] EXEC: PID=");
            lb.hex(proctab(idx).pid as u64);
            lb.str(b" -> entry=");
            lb.hex(new_entry);
            lb.str(b"\n");
            lb.flush();
        }

        // Don't reply -- process image replaced and resumed.
    }
}
