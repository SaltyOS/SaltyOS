//! Process spawning helpers
//! Extracted from original init spawn_server/phase3_spawn_console.
//! SPDX-License-Identifier: GPL-2.0-only

use salty::consts::*;
use salty::cpio;
use salty::elf_dynamic;
use salty::elf_loader;
use salty::invoke;
use salty::ipc;
use salty::serial;
use salty::types::*;

pub struct ExtraCapCopy {
    pub src: Cap,
    pub dst: u64,
}

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn hex(v: u64) {
    serial::serial_hex(v);
}

pub unsafe fn spawn_server(
    ut: Cap,
    cap_base: Cap,
    elf_name: &[u8],
    label: &[u8],
    extras: &[ExtraCapCopy],
    map_initrd: bool,
    cnode_size_bits: u64,
) -> i32 {
    puts(b"[INIT] Spawning ");
    puts(label);
    puts(b" (");
    puts(elf_name);
    puts(b")\n");

    unsafe {
        let initrd = super::INITRD_VADDR as *const u8;
        let initrd_size = cpio::cpio_archive_size(initrd, 1024 * 1024);

        let mut entry = CpioEntry::zeroed();
        if cpio::cpio_find_file(initrd, initrd_size, elf_name.as_ptr(), elf_name.len(), &raw mut entry) == 0 {
            puts(b"[INIT] ");
            puts(elf_name);
            puts(b" not found in initrd\n");
            return -1;
        }

        let is_dynamic = elf_dynamic::elf_has_interp(entry.data, entry.data_len);
        if is_dynamic {
            puts(b"[INIT] ");
            puts(label);
            puts(b" is dynamically linked\n");
        }

        let child_tcb = cap_base + super::COFF_TCB;
        let child_vs = cap_base + super::COFF_VSPACE;
        let child_cn = cap_base + super::COFF_CNODE;
        let child_sc = cap_base + super::COFF_SC;
        let child_stk_fr = cap_base + super::COFF_STACK_FR;
        let child_ipc_fr = cap_base + super::COFF_IPC_FR;
        let child_ep = cap_base + super::COFF_EP;

        macro_rules! retype {
            ($obj:expr, $slot:expr, $name:expr) => {
                let err = invoke::untyped_retype(ut, $obj, 0, $slot);
                if err != 0 { puts(b"[INIT] retype "); puts($name); puts(b" failed\n"); return -1; }
            };
        }

        retype!(OBJ_TCB, child_tcb, b"TCB");
        retype!(OBJ_VSPACE, child_vs, b"VSpace");
        retype!(OBJ_CNODE, child_cn, b"CNode");
        retype!(OBJ_SCHED_CONTEXT, child_sc, b"SC");
        retype!(OBJ_FRAME, child_stk_fr, b"stack frame");
        retype!(OBJ_FRAME, child_ipc_fr, b"IPC frame");
        retype!(OBJ_ENDPOINT, child_ep, b"EP");

        if cnode_size_bits > 0 {
            invoke::cnode_delete(CAP_SELF_CSPACE, child_cn);
            let err = invoke::untyped_retype(ut, OBJ_CNODE, cnode_size_bits, child_cn);
            if err != 0 {
                puts(b"[INIT] retype CNode (large) failed\n");
                return -1;
            }
        }

        let mut loader_ctx = ElfLoaderCtx {
            untyped: ut,
            self_vspace: CAP_SELF_VSPACE,
            child_vspace: child_vs,
            scratch_vaddr: SCRATCH_VADDR,
            next_frame_slot: cap_base + super::COFF_FRAME_START,
            alloc_frame_slot: Some(super::init_alloc_frame_slot),
            alloc_opaque: core::ptr::null_mut(),
            record_page: None,
            record_opaque: core::ptr::null_mut(),
        };

        let mut elf_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        let err = elf_loader::elf_load(
            entry.data,
            entry.data_len,
            super::CHILD_CODE_VADDR,
            &mut loader_ctx,
            &raw mut elf_result,
        );
        if err != 0 {
            puts(b"[INIT] ELF load failed err=");
            hex(err as u64);
            puts(b"\n");
            return -1;
        }

        puts(b"[INIT] ELF loaded: entry=");
        hex(elf_result.entry);
        puts(b"\n");

        let mut rtld_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };

        if is_dynamic {
            let rtld_name = b"ld-salty.so";
            let mut rtld_entry = CpioEntry::zeroed();
            if cpio::cpio_find_file(initrd, initrd_size, rtld_name.as_ptr(), rtld_name.len(), &raw mut rtld_entry) == 0 {
                puts(b"[INIT] rtld not found in initrd\n");
                return -1;
            }

            let err = elf_loader::elf_load(
                rtld_entry.data,
                rtld_entry.data_len,
                super::CHILD_RTLD_VADDR,
                &mut loader_ctx,
                &raw mut rtld_result,
            );
            if err != 0 {
                puts(b"[INIT] rtld ELF load failed\n");
                return -1;
            }

            puts(b"[INIT] rtld loaded: entry=");
            hex(rtld_result.entry);
            puts(b" base=");
            hex(rtld_result.base);
            puts(b"\n");
        }

        // Map stack pages
        for pg in 0..super::SRV_STACK_PAGES {
            let page_vaddr = super::CHILD_STACK_VADDR + pg as u64 * 4096;
            let frame_slot;

            if pg == super::SRV_STACK_PAGES - 1 {
                frame_slot = child_stk_fr;
            } else {
                frame_slot = super::init_alloc_frame_slot(core::ptr::null_mut());
                let err = invoke::untyped_retype(ut, OBJ_FRAME, 0, frame_slot);
                if err != 0 {
                    puts(b"[INIT] stack frame retype failed\n");
                    return -1;
                }
            }

            let err = invoke::vspace_map(
                child_vs,
                frame_slot,
                page_vaddr,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                puts(b"[INIT] stack map failed\n");
                return -1;
            }
        }

        // Map IPC buffer
        let err = invoke::vspace_map(
            child_vs,
            child_ipc_fr,
            super::CHILD_IPC_BUF_VADDR,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[INIT] IPC buf map failed\n");
            return -1;
        }

        // Map initrd if needed
        if map_initrd || is_dynamic {
            let initrd_pages = (initrd_size + 4095) / 4096;
            puts(b"[INIT] Mapping initrd into child (");
            hex(initrd_pages as u64);
            puts(b" pages)\n");

            for pg in 0..initrd_pages {
                let fr_slot = super::init_alloc_frame_slot(core::ptr::null_mut());
                let err = invoke::untyped_retype(ut, OBJ_FRAME, 0, fr_slot);
                if err != 0 {
                    puts(b"[INIT] initrd frame retype failed\n");
                    return -1;
                }

                let err = invoke::vspace_map(
                    CAP_SELF_VSPACE,
                    fr_slot,
                    SCRATCH_VADDR,
                    VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
                );
                if err != 0 {
                    puts(b"[INIT] initrd scratch map failed\n");
                    return -1;
                }

                let scratch = SCRATCH_VADDR as *mut u8;
                let isrc = initrd.add(pg * 4096);
                let mut copy_len = 4096;
                if pg * 4096 + copy_len > initrd_size {
                    copy_len = initrd_size - pg * 4096;
                }
                for i in 0..copy_len {
                    core::ptr::write_volatile(scratch.add(i), *isrc.add(i));
                }
                for i in copy_len..4096 {
                    core::ptr::write_volatile(scratch.add(i), 0);
                }

                invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

                let err = invoke::vspace_map(
                    child_vs,
                    fr_slot,
                    super::CHILD_INITRD_VADDR + pg as u64 * 4096,
                    VSPACE_FLAG_USER,
                );
                if err != 0 {
                    puts(b"[INIT] initrd child map failed\n");
                    return -1;
                }
            }
            puts(b"[INIT] Initrd mapped in child VSpace\n");
        }

        // Copy standard caps
        macro_rules! copy_cap {
            ($src:expr, $dst:expr) => {
                invoke::cnode_copy(CAP_SELF_CSPACE, $src, child_cn, $dst, CAP_RIGHTS_ALL)
            };
        }

        if copy_cap!(child_tcb, 0) != 0 { puts(b"[INIT] copy TCB failed\n"); return -1; }
        if copy_cap!(child_vs, 1) != 0 { puts(b"[INIT] copy VSpace failed\n"); return -1; }
        if copy_cap!(child_cn, 2) != 0 { puts(b"[INIT] copy CNode failed\n"); return -1; }
        if copy_cap!(child_ep, 3) != 0 { puts(b"[INIT] copy EP failed\n"); return -1; }

        let err = copy_cap!(ut, 7);
        if err != 0 {
            if is_dynamic {
                puts(b"[INIT] copy Untyped to child failed\n");
                return -1;
            }
            puts(b"[INIT] WARN: copy Untyped to child failed\n");
        }

        for extra in extras {
            if extra.src == 0 && extra.dst == 0 {
                continue;
            }
            let err = copy_cap!(extra.src, extra.dst);
            if err != 0 {
                puts(b"[INIT] WARN: extra cap copy failed slot=");
                hex(extra.dst);
                puts(b"\n");
            }
        }

        // Configure TCB
        let err = invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 { puts(b"[INIT] TCB set_space failed\n"); return -1; }

        let mut child_entry = elf_result.entry;
        let mut child_rsp = super::SRV_STACK_TOP;

        if is_dynamic {
            let err = invoke::vspace_map(
                CAP_SELF_VSPACE,
                child_stk_fr,
                SCRATCH_VADDR,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                puts(b"[INIT] dynamic stack scratch map failed\n");
                return -1;
            }

            let mut phdr_vaddr: u64 = 0;
            let mut phent: u64 = 0;
            let mut phnum: u64 = 0;
            if elf_dynamic::elf_get_phdr_info(
                entry.data,
                entry.data_len,
                super::CHILD_CODE_VADDR,
                &raw mut phdr_vaddr,
                &raw mut phent,
                &raw mut phnum,
            ) != 0 {
                puts(b"[INIT] dynamic phdr info extraction failed\n");
                invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);
                return -1;
            }

            let srv_stack_frame_size: u64 = 3 * 8 + 13 * 2 * 8 + 8;
            let stack_base = (SCRATCH_VADDR + 4096 - srv_stack_frame_size) as *mut u64;

            let mut idx: usize = 0;
            core::ptr::write_volatile(stack_base.add(idx), 0); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), 0); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), 0); idx += 1;

            core::ptr::write_volatile(stack_base.add(idx), super::AT_PHDR); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), phdr_vaddr); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_PHENT); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), phent); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_PHNUM); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), phnum); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_ENTRY); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), elf_result.entry); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_BASE); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), rtld_result.base); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_PAGESZ); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), 4096); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_SALTY_UNTYPED); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::CAP_CHILD_UNTYPED_OFFSET); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_SALTY_VSPACE); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), 1); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_SALTY_SCRATCH); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::CHILD_SCRATCH_VADDR); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_SALTY_INITRD); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::CHILD_INITRD_VADDR); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_SALTY_INITRD_SZ); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), initrd_size as u64); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_SALTY_FRAME_SLOT); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::CHILD_RTLD_FRAME_SLOT_START); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), super::AT_NULL); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), 0); idx += 1;
            core::ptr::write_volatile(stack_base.add(idx), 0);

            invoke::vspace_unmap(CAP_SELF_VSPACE, SCRATCH_VADDR);

            child_rsp = super::SRV_STACK_TOP - srv_stack_frame_size;
            child_entry = rtld_result.entry;
        }

        let err = invoke::tcb_configure(child_tcb, child_entry, child_rsp, 0);
        if err != 0 { puts(b"[INIT] TCB configure failed\n"); return -1; }

        invoke::tcb_set_ipc_buffer(child_tcb, super::CHILD_IPC_BUF_VADDR);

        let err = invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 { puts(b"[INIT] SC configure failed\n"); return -1; }

        let err = invoke::sc_bind(child_sc, child_tcb);
        if err != 0 { puts(b"[INIT] SC bind failed\n"); return -1; }

        let err = invoke::tcb_resume(child_tcb);
        if err != 0 { puts(b"[INIT] TCB resume failed\n"); return -1; }

        puts(b"[INIT] ");
        puts(label);
        puts(b" started!\n");
        0
    }
}

/// Spawn via procmgr IPC (for post-procmgr services).
pub unsafe fn pm_spawn(pm_ep: Cap, prog: &[u8]) -> i32 {
    unsafe {
        let len = prog.len();
        let mut spawn_msg = SaltyMsg::zeroed();
        spawn_msg.label = 1; // PM_SPAWN
        spawn_msg.length = 1 + ((len as u64 + 7) / 8);
        spawn_msg.regs[0] = len as u64;
        let dst = &raw mut spawn_msg.regs[1] as *mut u8;
        for i in 0..len {
            *dst.add(i) = prog[i];
        }

        let mut spawn_reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(super::ipc_ctx(), pm_ep, &raw const spawn_msg, &raw mut spawn_reply);
        if err != 0 || spawn_reply.label != SALTY_OK {
            return -1;
        }

        spawn_reply.regs[0] as i32
    }
}
