//! SaltyOS Process Manager
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Panic handler provided by libsalty.so (dynamic linking).

#![no_std]
#![no_main]

use salty::ipc;
use salty::serial::LineBuf;
use salty::types::*;

// ---- Cap layout (set by init for this process) ----
const CAP_SELF_TCB: Cap = 0;
const CAP_SELF_VSPACE: Cap = 1;
const CAP_SELF_CSPACE: Cap = 2;
const CAP_SERVER_EP: Cap = 3;
const CAP_UNTYPED: Cap = 7;
const CAP_NAMESERV_EP: Cap = 8;
const CAP_VFS_EP: Cap = 9;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

// ---- Protocol labels ----
const PM_SPAWN: u64 = 1;
const PM_EXIT: u64 = 2;
const PM_WAIT: u64 = 3;
const PM_GETPID: u64 = 4;
const PM_FORK: u64 = 5;
const PM_EXEC: u64 = 6;
const PM_GETPPID: u64 = 7;
const PM_KILL: u64 = 8;
const PM_SIGACTION: u64 = 9;

// ---- Signal constants ----
const SIG_DISP_DFL: u8 = 0;
const SIG_DISP_IGN: u8 = 1;
const SIG_DISP_CATCH: u8 = 2;
const NSIG: usize = 32;
const PM_SIGKILL: usize = 9;
const PM_SIGCHLD: usize = 17;
const PM_SIGCONT: usize = 18;
const PM_SIGSTOP: usize = 19;

// ---- Process states ----
const PROC_FREE: u8 = 0;
const PROC_RUNNING: u8 = 1;
const PROC_ZOMBIE: u8 = 2;
const PROC_STOPPED: u8 = 3;

// ---- Process table limits ----
const MAX_PROCESSES: usize = 32;
const MAX_NAME_LEN: usize = 32;

// ---- Child VSpace layout ----
const CHILD_CODE_VADDR: u64 = 0x0000_0000_0040_0000;
const CHILD_STACK_VADDR: u64 = 0x0000_0000_0080_0000;
const CHILD_STACK_PAGES: usize = 4;
const CHILD_STACK_SIZE: u64 = CHILD_STACK_PAGES as u64 * 4096;
const CHILD_STACK_TOP: u64 = CHILD_STACK_VADDR + CHILD_STACK_SIZE;
const CHILD_IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;
const CHILD_RTLD_VADDR: u64 = 0x0000_0000_0200_0000;
const CHILD_INITRD_VADDR: u64 = 0x0000_0000_0100_0000;
const CHILD_SCRATCH_VADDR: u64 = 0x0000_0000_0400_0000;
const CHILD_RTLD_FRAME_SLOT_START: u64 = 64;
const PROCMGR_SCRATCH_VADDR: u64 = 0x0000_0000_0500_0000;

// ---- Cap slots for child objects ----
const CAP_PROC_BASE: Cap = 256;
const CAP_PROC_STRIDE: Cap = 512;
const CAP_OFF_TCB: Cap = 0;
const CAP_OFF_VSPACE: Cap = 1;
const CAP_OFF_CNODE: Cap = 2;
const CAP_OFF_SC: Cap = 3;
const CAP_OFF_STACK_FR: Cap = 4;
const CAP_OFF_IPC_FR: Cap = 5;
const CAP_OFF_SIGNAL_NTFN: Cap = 6;
const CAP_OFF_FRAME_START: Cap = 16;
const CAP_REPLY_BASE: Cap = CAP_PROC_BASE + CAP_PROC_STRIDE * MAX_PROCESSES as u64;

// ---- Child CNode layout ----
const CHILD_CAP_TCB: u64 = 0;
const CHILD_CAP_VSPACE: u64 = 1;
const CHILD_CAP_CSPACE: u64 = 2;
const CHILD_CAP_EP: u64 = 3;
const CHILD_CAP_VFS: u64 = 4;
const CHILD_CAP_NAMESERV: u64 = 5;
const CHILD_CAP_SIGNAL_NTFN: u64 = 6;
const CHILD_CAP_UNTYPED: u64 = 7;
const CHILD_CNODE_SLOTS: u64 = 1024;

// ---- Auxiliary vector types ----
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_SALTY_UNTYPED: u64 = 0x1000;
const AT_SALTY_VSPACE: u64 = 0x1001;
const AT_SALTY_SCRATCH: u64 = 0x1002;
const AT_SALTY_INITRD: u64 = 0x1003;
const AT_SALTY_INITRD_SZ: u64 = 0x1004;
const AT_SALTY_FRAME_SLOT: u64 = 0x1005;

// ---- x86_64 page-table bits ----
const X86_PTE_WRITABLE: u64 = 1 << 1;
const X86_PTE_NX: u64 = 1 << 63;

// ---- waitpid options ----
const WNOHANG: u32 = 1;
const WUNTRACED: u32 = 2;

// ---- Shorthand re-exports ----
const OBJ_TCB: u64 = salty::OBJ_TCB;
const OBJ_VSPACE: u64 = salty::OBJ_VSPACE;
const OBJ_CNODE: u64 = salty::OBJ_CNODE;
const OBJ_SCHED_CONTEXT: u64 = salty::OBJ_SCHED_CONTEXT;
const OBJ_FRAME: u64 = salty::OBJ_FRAME;
const OBJ_NOTIFICATION: u64 = salty::OBJ_NOTIFICATION;
const SALTY_OK: u64 = salty::SALTY_OK;
const SALTY_OUT_OF_MEMORY: u64 = salty::SALTY_OUT_OF_MEMORY;
const SALTY_NOT_FOUND: u64 = salty::SALTY_NOT_FOUND;
const SALTY_INVALID_ARGUMENT: u64 = salty::SALTY_INVALID_ARGUMENT;
const SALTY_INVALID_OPERATION: u64 = salty::SALTY_INVALID_OPERATION;
const VSPACE_FLAG_WRITABLE: u64 = salty::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = salty::VSPACE_FLAG_USER;
const VSPACE_FLAG_EXECUTABLE: u64 = salty::VSPACE_FLAG_EXECUTABLE;
const CAP_RIGHTS_ALL: u64 = salty::CAP_RIGHTS_ALL;
const INITRD_VADDR: u64 = salty::INITRD_VADDR;

// ===========================================================================
// Process struct
// ===========================================================================

struct Process {
    pid: u32,
    ppid: u32,
    state: u8,
    exit_code: i32,
    badge: u64,
    tcb_cap: Cap,
    vspace_cap: Cap,
    cnode_cap: Cap,
    sc_cap: Cap,
    waiter_reply: Cap,
    waiter_pid: u32,
    any_waiter_reply: Cap,
    waiting_for_any: u8,
    signal_ntfn: Cap,
    sig_disposition: [u8; NSIG],
    stop_status: i32,
}

impl Process {
    const fn zeroed() -> Self {
        Process {
            pid: 0, ppid: 0, state: PROC_FREE, exit_code: 0, badge: 0,
            tcb_cap: 0, vspace_cap: 0, cnode_cap: 0, sc_cap: 0,
            waiter_reply: 0, waiter_pid: 0,
            any_waiter_reply: 0, waiting_for_any: 0,
            signal_ntfn: 0, sig_disposition: [SIG_DISP_DFL; NSIG], stop_status: 0,
        }
    }
}

// ===========================================================================
// Static state
// ===========================================================================

static mut PROCTAB: [Process; MAX_PROCESSES] = {
    const ZERO: Process = Process::zeroed();
    [ZERO; MAX_PROCESSES]
};
static mut NEXT_PID: u32 = 2;

// ===========================================================================
// Helpers
// ===========================================================================

fn puts(s: &[u8]) { salty::serial::serial_puts(s); }
fn ipc_ctx() -> *mut IpcContext { &raw mut salty::__salty_ipc_ctx }

unsafe fn strlen(s: *const u8) -> usize {
    let mut len = 0;
    unsafe { while *s.add(len) != 0 { len += 1; } }
    len
}

fn find_by_badge(badge: u64) -> Option<usize> {
    unsafe {
        for i in 0..MAX_PROCESSES {
            if PROCTAB[i].state != PROC_FREE && PROCTAB[i].badge == badge {
                return Some(i);
            }
        }
    }
    None
}

fn find_by_pid(pid: u32) -> Option<usize> {
    unsafe {
        for i in 0..MAX_PROCESSES {
            if PROCTAB[i].state != PROC_FREE && PROCTAB[i].pid == pid {
                return Some(i);
            }
        }
    }
    None
}

fn alloc_proc() -> Option<usize> {
    unsafe {
        for i in 0..MAX_PROCESSES {
            if PROCTAB[i].state == PROC_FREE {
                return Some(i);
            }
        }
    }
    None
}

unsafe fn cleanup_proc_resources(idx: usize) {
    unsafe {
        let base = CAP_PROC_BASE + idx as u64 * CAP_PROC_STRIDE;
        let child_cn = PROCTAB[idx].cnode_cap;

        if child_cn != 0 {
            for i in 0..CHILD_CNODE_SLOTS {
                let err = salty::invoke::cnode_revoke(child_cn, i);
                if err != 0 {
                    salty::invoke::cnode_delete(child_cn, i);
                }
            }
        }

        for i in 0..CAP_PROC_STRIDE {
            let slot = base + i;
            let err = salty::invoke::cnode_revoke(CAP_SELF_CSPACE, slot);
            if err != 0 {
                salty::invoke::cnode_delete(CAP_SELF_CSPACE, slot);
            }
        }

        let p = &mut PROCTAB[idx];
        p.pid = 0; p.ppid = 0; p.exit_code = 0; p.badge = 0;
        p.tcb_cap = 0; p.vspace_cap = 0; p.cnode_cap = 0; p.sc_cap = 0;
        p.waiter_reply = 0; p.waiter_pid = 0; p.signal_ntfn = 0; p.stop_status = 0;
        for i in 0..NSIG { p.sig_disposition[i] = SIG_DISP_DFL; }
        p.state = PROC_FREE;
    }
}

fn signal_ntfn(ntfn: Cap, bits: u64) {
    salty::syscall::syscall(salty::SYS_SIGNAL, ntfn, bits, 0, 0, 0, 0);
}

/// Extract ELF name from message regs, append ".elf" if needed.
/// Returns the name buffer and its length.
fn extract_name(msg: &SaltyMsg) -> ([u8; MAX_NAME_LEN + 5], usize) {
    let mut name = [0u8; MAX_NAME_LEN + 5];
    let mut name_len = msg.regs[0] as usize;
    if name_len > MAX_NAME_LEN { name_len = MAX_NAME_LEN; }

    let raw = unsafe { &*(&msg.regs[1] as *const u64 as *const [u8; 160]) };
    for i in 0..name_len {
        name[i] = raw[i];
    }

    let has_elf = name_len >= 4
        && name[name_len - 4] == b'.'
        && name[name_len - 3] == b'e'
        && name[name_len - 2] == b'l'
        && name[name_len - 1] == b'f';
    if !has_elf && name_len + 4 <= MAX_NAME_LEN {
        name[name_len] = b'.'; name_len += 1;
        name[name_len] = b'e'; name_len += 1;
        name[name_len] = b'l'; name_len += 1;
        name[name_len] = b'f'; name_len += 1;
    }
    name[name_len] = 0;
    (name, name_len)
}

/// Set up the auxv stack frame for a dynamic executable.
/// Returns the adjusted child RSP.
unsafe fn write_dynamic_stack(
    elf_data: *const u8,
    elf_data_len: usize,
    stk_frame: Cap,
    elf_result: &ElfLoadResult,
    rtld_result: &ElfLoadResult,
    initrd_size: usize,
) -> Result<u64, ()> {
    unsafe {
        let err = salty::invoke::vspace_map(
            CAP_SELF_VSPACE, stk_frame, PROCMGR_SCRATCH_VADDR,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[PROCMGR] dynamic stack scratch map failed\n");
            return Err(());
        }

        let mut phdr_vaddr: u64 = 0;
        let mut phent: u64 = 0;
        let mut phnum: u64 = 0;
        if salty::elf_dynamic::elf_get_phdr_info(
            elf_data, elf_data_len, CHILD_CODE_VADDR,
            &raw mut phdr_vaddr, &raw mut phent, &raw mut phnum,
        ) != 0 {
            puts(b"[PROCMGR] dynamic phdr info extraction failed\n");
            salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
            return Err(());
        }

        let auxv_entries: u64 = 13;
        let stack_frame_size: u64 = 3 * 8 + auxv_entries * 2 * 8 + 8;

        let stack_base = (PROCMGR_SCRATCH_VADDR + 4096 - stack_frame_size) as *mut u64;
        let mut idx: usize = 0;
        let mut w = |v: u64| {
            core::ptr::write_volatile(stack_base.add(idx), v);
            idx += 1;
        };
        w(0); // argc
        w(0); // argv terminator
        w(0); // envp terminator
        w(AT_PHDR);     w(phdr_vaddr);
        w(AT_PHENT);    w(phent);
        w(AT_PHNUM);    w(phnum);
        w(AT_ENTRY);    w(elf_result.entry);
        w(AT_BASE);     w(rtld_result.base);
        w(AT_PAGESZ);   w(4096);
        w(AT_SALTY_UNTYPED);    w(CHILD_CAP_UNTYPED);
        w(AT_SALTY_VSPACE);     w(CHILD_CAP_VSPACE);
        w(AT_SALTY_SCRATCH);    w(CHILD_SCRATCH_VADDR);
        w(AT_SALTY_INITRD);     w(CHILD_INITRD_VADDR);
        w(AT_SALTY_INITRD_SZ);  w(initrd_size as u64);
        w(AT_SALTY_FRAME_SLOT); w(CHILD_RTLD_FRAME_SLOT_START);
        w(AT_NULL);     w(0);
        w(0); // padding

        salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
        Ok(CHILD_STACK_TOP - stack_frame_size)
    }
}

/// Load the rtld and return its load result. Returns None on failure.
unsafe fn load_rtld(
    elf_data: *const u8,
    elf_data_len: usize,
    initrd: *const u8,
    initrd_size: usize,
    loader_ctx: &mut ElfLoaderCtx,
) -> Option<ElfLoadResult> {
    unsafe {
        let mut rtld_name = b"ld-salty.so".as_ptr();
        let mut rtld_name_len = 10usize;

        let interp = salty::elf_dynamic::elf_get_interp(elf_data, elf_data_len);
        if !interp.is_null() && *interp != 0 {
            let mut last = interp;
            let mut p = interp;
            while *p != 0 {
                if *p == b'/' { last = p.add(1); }
                p = p.add(1);
            }
            if *last != 0 {
                rtld_name = last;
                rtld_name_len = strlen(last);
            }
        }

        let mut rtld_entry = CpioEntry::zeroed();
        if salty::cpio::cpio_find_file(initrd, initrd_size, rtld_name, rtld_name_len, &raw mut rtld_entry) == 0 {
            puts(b"[PROCMGR] rtld not found in initrd\n");
            return None;
        }

        let mut rtld_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        let err = salty::elf_loader::elf_load(
            rtld_entry.data, rtld_entry.data_len,
            CHILD_RTLD_VADDR, loader_ctx, &raw mut rtld_result,
        );
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] rtld load failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
            return None;
        }
        Some(rtld_result)
    }
}

/// Copy caps into child CNode (TCB, VSpace, CNode, EP, VFS, Nameserv, Untyped, Signal).
fn copy_child_caps(
    child_tcb: Cap, child_vs: Cap, child_cn: Cap,
    child_sig_ntfn: Cap, pid: u32, is_dynamic: bool,
) -> i32 {
    let mut err;
    err = salty::invoke::cnode_copy(CAP_SELF_CSPACE, child_tcb, child_cn, CHILD_CAP_TCB, CAP_RIGHTS_ALL);
    if err != 0 { puts(b"[PROCMGR] copy TCB cap failed\n"); return err; }

    err = salty::invoke::cnode_copy(CAP_SELF_CSPACE, child_vs, child_cn, CHILD_CAP_VSPACE, CAP_RIGHTS_ALL);
    if err != 0 { puts(b"[PROCMGR] copy VSpace cap failed\n"); return err; }

    err = salty::invoke::cnode_copy(CAP_SELF_CSPACE, child_cn, child_cn, CHILD_CAP_CSPACE, CAP_RIGHTS_ALL);
    if err != 0 { puts(b"[PROCMGR] copy CNode cap failed\n"); return err; }

    err = salty::invoke::cnode_mint(CAP_SELF_CSPACE, CAP_SERVER_EP, child_cn, CHILD_CAP_EP, pid as u64);
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] mint EP cap failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
        return err;
    }

    err = salty::invoke::cnode_copy(CAP_SELF_CSPACE, CAP_UNTYPED, child_cn, CHILD_CAP_UNTYPED, CAP_RIGHTS_ALL);
    if err != 0 {
        if is_dynamic {
            puts(b"[PROCMGR] copy Untyped cap failed\n");
            return err;
        }
        puts(b"[PROCMGR] WARN: copy Untyped cap failed\n");
    }

    // Give each process a uniquely badged VFS endpoint so VFS can maintain
    // per-process client state keyed by PID badge.
    err = salty::invoke::cnode_mint(CAP_SELF_CSPACE, CAP_VFS_EP, child_cn, CHILD_CAP_VFS, pid as u64);
    if err != 0 {
        puts(b"[PROCMGR] WARN: mint VFS EP cap failed, trying unbadged copy\n");
        err = salty::invoke::cnode_copy(CAP_SELF_CSPACE, CAP_VFS_EP, child_cn, CHILD_CAP_VFS, CAP_RIGHTS_ALL);
        if err != 0 { puts(b"[PROCMGR] WARN: copy VFS EP cap failed\n"); }
    }

    err = salty::invoke::cnode_copy(CAP_SELF_CSPACE, CAP_NAMESERV_EP, child_cn, CHILD_CAP_NAMESERV, CAP_RIGHTS_ALL);
    if err != 0 { puts(b"[PROCMGR] WARN: copy Nameserv EP cap failed\n"); }

    err = salty::invoke::cnode_copy(CAP_SELF_CSPACE, child_sig_ntfn, child_cn, CHILD_CAP_SIGNAL_NTFN, CAP_RIGHTS_ALL);
    if err != 0 { puts(b"[PROCMGR] WARN: copy signal ntfn cap failed\n"); }

    0
}

/// Map initrd pages into child VSpace (for dynamic executables).
unsafe fn map_initrd_to_child(
    child_vs: Cap,
    initrd: *const u8,
    initrd_size: usize,
    loader_ctx: &mut ElfLoaderCtx,
    base: Cap,
) -> i32 {
    unsafe {
        let initrd_pages = (initrd_size + 4095) / 4096;
        for pg in 0..initrd_pages {
            let frame_limit = base + CAP_PROC_STRIDE;
            if loader_ctx.next_frame_slot >= frame_limit {
                puts(b"[PROCMGR] initrd frame slot overflow\n");
                return -1;
            }
            let fr_slot = loader_ctx.next_frame_slot;
            loader_ctx.next_frame_slot += 1;
            let err = salty::invoke::untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, fr_slot);
            if err != 0 {
                puts(b"[PROCMGR] initrd frame retype failed\n");
                return -1;
            }

            let err = salty::invoke::vspace_map(
                CAP_SELF_VSPACE, fr_slot, PROCMGR_SCRATCH_VADDR,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                puts(b"[PROCMGR] initrd scratch map failed\n");
                return -1;
            }

            let scratch = PROCMGR_SCRATCH_VADDR as *mut u8;
            let src = initrd.add(pg * 4096);
            let mut copy_len = 4096usize;
            if pg * 4096 + copy_len > initrd_size {
                copy_len = initrd_size - pg * 4096;
            }
            for i in 0..copy_len {
                core::ptr::write_volatile(scratch.add(i), *src.add(i));
            }
            for i in copy_len..4096 {
                core::ptr::write_volatile(scratch.add(i), 0);
            }

            salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

            let err = salty::invoke::vspace_map(
                child_vs, fr_slot, CHILD_INITRD_VADDR + pg as u64 * 4096,
                VSPACE_FLAG_USER,
            );
            if err != 0 {
                puts(b"[PROCMGR] initrd child map failed\n");
                return -1;
            }
        }
        0
    }
}

// ===========================================================================
// handle_spawn
// ===========================================================================

unsafe fn handle_spawn(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let (name, name_len) = extract_name(msg);

        let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] SPAWN: '");
        lb.bytes(&name[..name_len]);
        lb.str(b"'\n");
        lb.flush();

        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = salty::cpio::cpio_archive_size(initrd, 1024 * 1024);

        let mut elf_entry = CpioEntry::zeroed();
        if salty::cpio::cpio_find_file(initrd, initrd_size, name.as_ptr(), name_len, &raw mut elf_entry) == 0 {
            puts(b"[PROCMGR] ELF not found in initrd\n");
            reply.label = SALTY_NOT_FOUND;
            return;
        }

        let is_dynamic = salty::elf_dynamic::elf_has_interp(elf_entry.data, elf_entry.data_len);
        if is_dynamic { puts(b"[PROCMGR] ELF is dynamically linked\n"); }
        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] Found ELF ("); lb.hex(elf_entry.data_len as u64); lb.str(b" bytes)\n"); lb.flush(); }

        // Auto-register caller if unknown
        let caller_idx = find_by_badge(badge);
        if caller_idx.is_none() && badge != 0 {
            if let Some(ci) = alloc_proc() {
                PROCTAB[ci].pid = badge as u32;
                PROCTAB[ci].ppid = 0;
                PROCTAB[ci].state = PROC_RUNNING;
                PROCTAB[ci].badge = badge;
            }
        }

        let Some(slot_idx) = alloc_proc() else {
            puts(b"[PROCMGR] process table full\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        };

        let pid = NEXT_PID;
        NEXT_PID += 1;
        let base = CAP_PROC_BASE + slot_idx as u64 * CAP_PROC_STRIDE;

        let child_tcb = base + CAP_OFF_TCB;
        let child_vs = base + CAP_OFF_VSPACE;
        let child_cn = base + CAP_OFF_CNODE;
        let child_sc = base + CAP_OFF_SC;
        let child_stk_fr = base + CAP_OFF_STACK_FR;
        let child_ipc_fr = base + CAP_OFF_IPC_FR;
        let child_sig_ntfn = base + CAP_OFF_SIGNAL_NTFN;

        // 1. Retype child objects
        macro_rules! retype {
            ($ty:expr, $slot:expr) => {
                if salty::invoke::untyped_retype(CAP_UNTYPED, $ty, 0, $slot) != 0 {
                    reply.label = SALTY_OUT_OF_MEMORY; return;
                }
            };
        }
        retype!(OBJ_TCB, child_tcb);
        retype!(OBJ_VSPACE, child_vs);
        retype!(OBJ_CNODE, child_cn);
        retype!(OBJ_SCHED_CONTEXT, child_sc);
        retype!(OBJ_FRAME, child_stk_fr);
        retype!(OBJ_FRAME, child_ipc_fr);
        retype!(OBJ_NOTIFICATION, child_sig_ntfn);

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] Objects retyped for PID "); lb.hex(pid as u64); lb.str(b"\n"); lb.flush(); }

        // 2. Load ELF
        let mut loader_ctx = ElfLoaderCtx {
            untyped: CAP_UNTYPED, self_vspace: CAP_SELF_VSPACE,
            child_vspace: child_vs, scratch_vaddr: PROCMGR_SCRATCH_VADDR,
            next_frame_slot: base + CAP_OFF_FRAME_START,
            alloc_frame_slot: None, alloc_opaque: core::ptr::null_mut(),
            record_page: None, record_opaque: core::ptr::null_mut(),
        };

        let mut elf_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        let err = salty::elf_loader::elf_load(
            elf_entry.data, elf_entry.data_len,
            CHILD_CODE_VADDR, &mut loader_ctx, &raw mut elf_result,
        );
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] ELF load failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }
        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] ELF loaded: entry="); lb.hex(elf_result.entry); lb.str(b"\n"); lb.flush(); }

        // 2b. Load rtld if dynamic
        let mut rtld_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        if is_dynamic {
            match load_rtld(elf_entry.data, elf_entry.data_len, initrd, initrd_size, &mut loader_ctx) {
                Some(r) => rtld_result = r,
                None => { reply.label = SALTY_NOT_FOUND; return; }
            }
        }

        // 3. Map stack pages
        for pg in 0..CHILD_STACK_PAGES {
            let page_vaddr = CHILD_STACK_VADDR + pg as u64 * 4096;
            let frame_slot;
            if pg == CHILD_STACK_PAGES - 1 {
                frame_slot = child_stk_fr;
            } else {
                let frame_limit = base + CAP_PROC_STRIDE;
                if loader_ctx.next_frame_slot >= frame_limit {
                    puts(b"[PROCMGR] stack frame slot overflow\n");
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
                frame_slot = loader_ctx.next_frame_slot;
                loader_ctx.next_frame_slot += 1;
                let err = salty::invoke::untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, frame_slot);
                if err != 0 {
                    puts(b"[PROCMGR] stack frame retype failed\n");
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
            let err = salty::invoke::vspace_map(
                child_vs, frame_slot, page_vaddr,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] stack map failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // 4. Map IPC buffer
        let err = salty::invoke::vspace_map(
            child_vs, child_ipc_fr, CHILD_IPC_BUF_VADDR,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[PROCMGR] IPC buf map failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // 4b. Map initrd for dynamic executables
        if is_dynamic {
            if map_initrd_to_child(child_vs, initrd, initrd_size, &mut loader_ctx, base) != 0 {
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // 5. Copy caps into child CNode
        let err = copy_child_caps(child_tcb, child_vs, child_cn, child_sig_ntfn, pid, is_dynamic);
        if err != 0 {
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // 6. Configure child TCB
        let err = salty::invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            puts(b"[PROCMGR] TCB set_space failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        let mut child_entry_rip = elf_result.entry;
        let mut child_rsp = CHILD_STACK_TOP;

        if is_dynamic {
            match write_dynamic_stack(
                elf_entry.data, elf_entry.data_len,
                child_stk_fr, &elf_result, &rtld_result, initrd_size,
            ) {
                Ok(rsp) => {
                    child_rsp = rsp;
                    child_entry_rip = rtld_result.entry;
                }
                Err(()) => {
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
        }

        let err = salty::invoke::tcb_configure(child_tcb, child_entry_rip, child_rsp, 0);
        if err != 0 {
            puts(b"[PROCMGR] TCB configure failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let err = salty::invoke::tcb_set_ipc_buffer(child_tcb, CHILD_IPC_BUF_VADDR);
        if err != 0 {
            puts(b"[PROCMGR] set child IPC buffer failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // 7. Schedule
        let err = salty::invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 { puts(b"[PROCMGR] SC configure failed\n"); reply.label = SALTY_OUT_OF_MEMORY; return; }
        let err = salty::invoke::sc_bind(child_sc, child_tcb);
        if err != 0 { puts(b"[PROCMGR] SC bind failed\n"); reply.label = SALTY_OUT_OF_MEMORY; return; }

        // 8. Start
        let err = salty::invoke::tcb_resume(child_tcb);
        if err != 0 { puts(b"[PROCMGR] TCB resume failed\n"); reply.label = SALTY_OUT_OF_MEMORY; return; }

        // Record in process table
        let caller_idx = find_by_badge(badge);
        let p = &mut PROCTAB[slot_idx];
        p.pid = pid;
        p.ppid = if let Some(ci) = caller_idx { PROCTAB[ci].pid } else { 0 };
        p.state = PROC_RUNNING;
        p.exit_code = 0;
        p.badge = pid as u64;
        p.tcb_cap = child_tcb;
        p.vspace_cap = child_vs;
        p.cnode_cap = child_cn;
        p.sc_cap = child_sc;
        p.waiter_reply = 0;
        p.waiter_pid = 0;
        p.signal_ntfn = child_sig_ntfn;
        for i in 0..NSIG { p.sig_disposition[i] = SIG_DISP_DFL; }

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] Process started PID="); lb.hex(pid as u64); lb.str(b"\n"); lb.flush(); }
        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = pid as u64;
    }
}

// ===========================================================================
// handle_exit
// ===========================================================================

unsafe fn handle_exit(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let raw_code = msg.regs[0] as i32;
        let exit_code = raw_code << 8;

        let Some(idx) = find_by_badge(badge) else {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] EXIT from unknown badge="); lb.hex(badge); lb.str(b"\n"); lb.flush();
            reply.label = SALTY_NOT_FOUND;
            return;
        };

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] EXIT PID="); lb.hex(PROCTAB[idx].pid as u64);
        lb.str(b" code="); lb.hex(exit_code as u64); lb.str(b"\n"); lb.flush(); }

        PROCTAB[idx].state = PROC_ZOMBIE;
        PROCTAB[idx].exit_code = exit_code;

        salty::invoke::invoke(PROCTAB[idx].tcb_cap, salty::TCB_SUSPEND, 0, 0, 0, 0);

        // Deliver SIGCHLD to parent
        let ppid = PROCTAB[idx].ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if PROCTAB[pi].state == PROC_RUNNING
                && PROCTAB[pi].signal_ntfn != 0
                && PROCTAB[pi].sig_disposition[PM_SIGCHLD] == SIG_DISP_CATCH
            {
                signal_ntfn(PROCTAB[pi].signal_ntfn, 1u64 << PM_SIGCHLD);
            }
        }

        // Wake specific-child waiter
        if PROCTAB[idx].waiter_reply != 0 {
            { let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] Waking waiter for PID="); lb.hex(PROCTAB[idx].pid as u64); lb.str(b"\n"); lb.flush(); }

            let mut wake = SaltyMsg::zeroed();
            wake.label = SALTY_OK;
            wake.length = 2;
            wake.regs[0] = exit_code as u64;
            wake.regs[1] = PROCTAB[idx].pid as u64;

            let waiter_cap = PROCTAB[idx].waiter_reply;
            salty::ipc::send_ctx(ipc_ctx(), waiter_cap, &raw const wake);
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, waiter_cap);
            PROCTAB[idx].waiter_reply = 0;
            PROCTAB[idx].waiter_pid = 0;
            cleanup_proc_resources(idx);
            return;
        }

        // Wake any-child waiter on parent
        if let Some(pi) = find_by_pid(ppid) {
            if PROCTAB[pi].waiting_for_any != 0 {
                { let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] Waking any-waiter parent PID="); lb.hex(PROCTAB[pi].pid as u64);
                lb.str(b" for child PID="); lb.hex(PROCTAB[idx].pid as u64); lb.str(b"\n"); lb.flush(); }

                let mut wake = SaltyMsg::zeroed();
                wake.label = SALTY_OK;
                wake.length = 2;
                wake.regs[0] = exit_code as u64;
                wake.regs[1] = PROCTAB[idx].pid as u64;

                let waiter_cap = PROCTAB[pi].any_waiter_reply;
                salty::ipc::send_ctx(ipc_ctx(), waiter_cap, &raw const wake);
                salty::invoke::cnode_delete(CAP_SELF_CSPACE, waiter_cap);
                PROCTAB[pi].any_waiter_reply = 0;
                PROCTAB[pi].waiting_for_any = 0;
                cleanup_proc_resources(idx);
            }
        }
    }
}

// ===========================================================================
// handle_wait
// ===========================================================================

/// Returns true if caller is blocked (skip reply).
unsafe fn handle_wait(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) -> bool {
    unsafe {
        let child_pid = msg.regs[0] as u32;
        let options = msg.regs[1] as u32;

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = SALTY_NOT_FOUND;
            return false;
        };
        let caller_pid = PROCTAB[caller_idx].pid;

        // waitpid(-1): wait for any child
        if child_pid == u32::MAX {
            let mut zombie_idx: Option<usize> = None;
            let mut stopped_idx: Option<usize> = None;
            let mut has_living = false;

            for i in 0..MAX_PROCESSES {
                if PROCTAB[i].state != PROC_FREE && PROCTAB[i].ppid == caller_pid {
                    if PROCTAB[i].state == PROC_ZOMBIE && zombie_idx.is_none() {
                        zombie_idx = Some(i);
                    } else if PROCTAB[i].state == PROC_STOPPED && stopped_idx.is_none() {
                        stopped_idx = Some(i);
                    }
                    if PROCTAB[i].state == PROC_RUNNING || PROCTAB[i].state == PROC_STOPPED {
                        has_living = true;
                    }
                }
            }

            if let Some(zi) = zombie_idx {
                reply.label = SALTY_OK;
                reply.length = 2;
                reply.regs[0] = PROCTAB[zi].exit_code as u64;
                reply.regs[1] = PROCTAB[zi].pid as u64;
                cleanup_proc_resources(zi);
                return false;
            }

            if (options & WUNTRACED) != 0 {
                if let Some(si) = stopped_idx {
                    reply.label = SALTY_OK;
                    reply.length = 2;
                    reply.regs[0] = PROCTAB[si].stop_status as u64;
                    reply.regs[1] = PROCTAB[si].pid as u64;
                    return false;
                }
            }

            if !has_living {
                reply.label = SALTY_NOT_FOUND;
                return false;
            }

            if (options & WNOHANG) != 0 {
                reply.label = SALTY_OK;
                reply.length = 2;
                reply.regs[0] = 0;
                reply.regs[1] = 0;
                return false;
            }

            // Block
            let reply_slot = CAP_REPLY_BASE + MAX_PROCESSES as u64 + caller_idx as u64;
            let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
            if err != 0 {
                reply.label = SALTY_OUT_OF_MEMORY;
                return false;
            }
            PROCTAB[caller_idx].any_waiter_reply = reply_slot;
            PROCTAB[caller_idx].waiting_for_any = 1;
            { let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] WAIT(-1) blocking parent PID="); lb.hex(caller_pid as u64); lb.str(b"\n"); lb.flush(); }
            return true;
        }

        // waitpid(specific child)
        let Some(ci) = find_by_pid(child_pid) else {
            reply.label = SALTY_NOT_FOUND;
            return false;
        };
        if PROCTAB[ci].ppid != caller_pid {
            reply.label = SALTY_NOT_FOUND;
            return false;
        }

        if PROCTAB[ci].state == PROC_ZOMBIE {
            reply.label = SALTY_OK;
            reply.length = 2;
            reply.regs[0] = PROCTAB[ci].exit_code as u64;
            reply.regs[1] = PROCTAB[ci].pid as u64;
            cleanup_proc_resources(ci);
            return false;
        }

        if (options & WUNTRACED) != 0 && PROCTAB[ci].state == PROC_STOPPED {
            reply.label = SALTY_OK;
            reply.length = 2;
            reply.regs[0] = PROCTAB[ci].stop_status as u64;
            reply.regs[1] = PROCTAB[ci].pid as u64;
            return false;
        }

        if (options & WNOHANG) != 0 {
            reply.label = SALTY_OK;
            reply.length = 2;
            reply.regs[0] = 0;
            reply.regs[1] = 0;
            return false;
        }

        // Block
        let reply_slot = CAP_REPLY_BASE + ci as u64;
        let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] save_caller failed for WAIT, err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
            reply.label = SALTY_OUT_OF_MEMORY;
            return false;
        }
        PROCTAB[ci].waiter_reply = reply_slot;
        PROCTAB[ci].waiter_pid = caller_pid;
        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] WAIT blocking for PID="); lb.hex(child_pid as u64); lb.str(b"\n"); lb.flush(); }
        true
    }
}

// ===========================================================================
// handle_getpid / handle_getppid
// ===========================================================================

unsafe fn handle_getpid(reply: &mut SaltyMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = SALTY_NOT_FOUND;
        return;
    };
    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { PROCTAB[idx].pid as u64 };
}

unsafe fn handle_getppid(reply: &mut SaltyMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = SALTY_NOT_FOUND;
        return;
    };
    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { PROCTAB[idx].ppid as u64 };
}

// ===========================================================================
// Signal handling
// ===========================================================================

fn sig_default_is_terminate(sig: usize) -> bool {
    !matches!(sig, PM_SIGCHLD | PM_SIGCONT | PM_SIGSTOP)
}

unsafe fn sig_terminate_proc(idx: usize, sig: usize) {
    unsafe {
        let exit_code = (sig & 0x7f) as i32;

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] SIGKILL/terminate PID="); lb.hex(PROCTAB[idx].pid as u64);
        lb.str(b" sig="); lb.hex(sig as u64); lb.str(b"\n"); lb.flush(); }

        salty::invoke::invoke(PROCTAB[idx].tcb_cap, salty::TCB_SUSPEND, 0, 0, 0, 0);
        PROCTAB[idx].state = PROC_ZOMBIE;
        PROCTAB[idx].exit_code = exit_code;

        // Deliver SIGCHLD to parent
        let ppid = PROCTAB[idx].ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if (PROCTAB[pi].state == PROC_RUNNING || PROCTAB[pi].state == PROC_STOPPED)
                && PROCTAB[pi].signal_ntfn != 0
                && PROCTAB[pi].sig_disposition[PM_SIGCHLD] == SIG_DISP_CATCH
            {
                signal_ntfn(PROCTAB[pi].signal_ntfn, 1u64 << PM_SIGCHLD);
            }
        }

        // Wake specific-child waiter
        if PROCTAB[idx].waiter_reply != 0 {
            let mut wake = SaltyMsg::zeroed();
            wake.label = SALTY_OK;
            wake.length = 2;
            wake.regs[0] = exit_code as u64;
            wake.regs[1] = PROCTAB[idx].pid as u64;

            salty::ipc::send_ctx(ipc_ctx(), PROCTAB[idx].waiter_reply, &raw const wake);
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, PROCTAB[idx].waiter_reply);
            PROCTAB[idx].waiter_reply = 0;
            PROCTAB[idx].waiter_pid = 0;
            cleanup_proc_resources(idx);
            return;
        }

        // Wake any-child waiter on parent
        if let Some(pi) = find_by_pid(ppid) {
            if PROCTAB[pi].waiting_for_any != 0 {
                let mut wake = SaltyMsg::zeroed();
                wake.label = SALTY_OK;
                wake.length = 2;
                wake.regs[0] = exit_code as u64;
                wake.regs[1] = PROCTAB[idx].pid as u64;

                salty::ipc::send_ctx(ipc_ctx(), PROCTAB[pi].any_waiter_reply, &raw const wake);
                salty::invoke::cnode_delete(CAP_SELF_CSPACE, PROCTAB[pi].any_waiter_reply);
                PROCTAB[pi].any_waiter_reply = 0;
                PROCTAB[pi].waiting_for_any = 0;
                cleanup_proc_resources(idx);
            }
        }
    }
}

unsafe fn handle_kill(msg: &SaltyMsg, reply: &mut SaltyMsg, _badge: u64) {
    unsafe {
        let target_pid = msg.regs[0] as u32;
        let sig = msg.regs[1] as usize;

        if sig == 0 || sig >= NSIG {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };
        if PROCTAB[ti].state != PROC_RUNNING && PROCTAB[ti].state != PROC_STOPPED {
            reply.label = SALTY_NOT_FOUND;
            return;
        }

        // SIGKILL: always terminate
        if sig == PM_SIGKILL {
            sig_terminate_proc(ti, sig);
            reply.label = SALTY_OK;
            reply.length = 0;
            return;
        }

        // SIGSTOP: always stop
        if sig == PM_SIGSTOP {
            if PROCTAB[ti].state == PROC_RUNNING {
                salty::invoke::invoke(PROCTAB[ti].tcb_cap, salty::TCB_SUSPEND, 0, 0, 0, 0);
                PROCTAB[ti].state = PROC_STOPPED;
                PROCTAB[ti].stop_status = ((sig as i32) << 8) | 0x7f;

                let ppid = PROCTAB[ti].ppid;
                if let Some(pi) = find_by_pid(ppid) {
                    if (PROCTAB[pi].state == PROC_RUNNING || PROCTAB[pi].state == PROC_STOPPED)
                        && PROCTAB[pi].signal_ntfn != 0
                        && PROCTAB[pi].sig_disposition[PM_SIGCHLD] == SIG_DISP_CATCH
                    {
                        signal_ntfn(PROCTAB[pi].signal_ntfn, 1u64 << PM_SIGCHLD);
                    }
                }
            }
            reply.label = SALTY_OK;
            reply.length = 0;
            return;
        }

        // SIGCONT: resume stopped
        if sig == PM_SIGCONT {
            if PROCTAB[ti].state == PROC_STOPPED {
                salty::invoke::invoke(PROCTAB[ti].tcb_cap, salty::TCB_RESUME, 0, 0, 0, 0);
                PROCTAB[ti].state = PROC_RUNNING;
                PROCTAB[ti].stop_status = 0;

                let ppid = PROCTAB[ti].ppid;
                if let Some(pi) = find_by_pid(ppid) {
                    if (PROCTAB[pi].state == PROC_RUNNING || PROCTAB[pi].state == PROC_STOPPED)
                        && PROCTAB[pi].signal_ntfn != 0
                        && PROCTAB[pi].sig_disposition[PM_SIGCHLD] == SIG_DISP_CATCH
                    {
                        signal_ntfn(PROCTAB[pi].signal_ntfn, 1u64 << PM_SIGCHLD);
                    }
                }
            }
            if PROCTAB[ti].sig_disposition[sig] == SIG_DISP_CATCH && PROCTAB[ti].signal_ntfn != 0 {
                signal_ntfn(PROCTAB[ti].signal_ntfn, 1u64 << sig);
            }
            reply.label = SALTY_OK;
            reply.length = 0;
            return;
        }

        // Cannot deliver most signals to stopped processes
        if PROCTAB[ti].state != PROC_RUNNING {
            reply.label = SALTY_OK;
            reply.length = 0;
            return;
        }

        let disp = PROCTAB[ti].sig_disposition[sig];

        if disp == SIG_DISP_IGN {
            reply.label = SALTY_OK;
            reply.length = 0;
            return;
        }

        if disp == SIG_DISP_DFL {
            if sig_default_is_terminate(sig) {
                sig_terminate_proc(ti, sig);
            }
            reply.label = SALTY_OK;
            reply.length = 0;
            return;
        }

        // SIG_DISP_CATCH: deliver via notification
        if PROCTAB[ti].signal_ntfn != 0 {
            signal_ntfn(PROCTAB[ti].signal_ntfn, 1u64 << sig);
        }
        reply.label = SALTY_OK;
        reply.length = 0;
    }
}

unsafe fn handle_sigaction(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let sig = msg.regs[0] as usize;
        let disp = msg.regs[1] as u8;

        if sig == 0 || sig >= NSIG || sig == PM_SIGKILL || sig == PM_SIGSTOP {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }
        if disp > SIG_DISP_CATCH {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let Some(idx) = find_by_badge(badge) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };
        PROCTAB[idx].sig_disposition[sig] = disp;
        reply.label = SALTY_OK;
        reply.length = 0;
    }
}

// ===========================================================================
// handle_fork
// ===========================================================================

unsafe fn handle_fork(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let parent_rsp = msg.regs[0];
        let child_entry = msg.regs[1];
        let saved_rbp = msg.regs[2];
        let saved_rbx = msg.regs[3];
        let saved_r12 = msg.regs[4];
        let saved_r13 = msg.regs[5];
        let saved_r14 = msg.regs[6];
        let saved_r15 = msg.regs[7];
        let return_rip = msg.regs[8];

        if child_entry == 0 || return_rip == 0 {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }
        if (parent_rsp & 0xFFF) > (4096 - 56) {
            puts(b"[PROCMGR] FORK: parent stack frame crosses page boundary\n");
            reply.label = SALTY_INVALID_OPERATION;
            return;
        }

        let Some(parent_idx) = find_by_badge(badge) else {
            puts(b"[PROCMGR] FORK from unknown badge\n");
            reply.label = SALTY_NOT_FOUND;
            return;
        };
        let parent_pid = PROCTAB[parent_idx].pid;
        let parent_vs = PROCTAB[parent_idx].vspace_cap;

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] FORK from PID="); lb.hex(parent_pid as u64); lb.str(b"\n"); lb.flush(); }

        let Some(slot_idx) = alloc_proc() else {
            puts(b"[PROCMGR] FORK: process table full\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        };

        let child_pid = NEXT_PID;
        NEXT_PID += 1;
        let base = CAP_PROC_BASE + slot_idx as u64 * CAP_PROC_STRIDE;

        let child_tcb = base + CAP_OFF_TCB;
        let child_vs = base + CAP_OFF_VSPACE;
        let child_cn = base + CAP_OFF_CNODE;
        let child_sc = base + CAP_OFF_SC;
        let child_ipc_fr = base + CAP_OFF_IPC_FR;
        let child_sig_ntfn = base + CAP_OFF_SIGNAL_NTFN;

        // 1. Retype child kernel objects
        macro_rules! retype {
            ($ty:expr, $slot:expr) => {
                if salty::invoke::untyped_retype(CAP_UNTYPED, $ty, 0, $slot) != 0 {
                    reply.label = SALTY_OUT_OF_MEMORY; return;
                }
            };
        }
        retype!(OBJ_TCB, child_tcb);
        retype!(OBJ_VSPACE, child_vs);
        retype!(OBJ_CNODE, child_cn);
        retype!(OBJ_SCHED_CONTEXT, child_sc);
        retype!(OBJ_FRAME, child_ipc_fr);
        retype!(OBJ_NOTIFICATION, child_sig_ntfn);

        // 2. Walk parent VSpace and copy all pages
        let mut next_frame = base + CAP_OFF_FRAME_START;
        let mut walk_start: u64 = 0;
        let mut total_pages = 0u64;
        let rsp_page_vaddr = parent_rsp & !0xFFFu64;
        let mut rsp_frame: Cap = 0;

        loop {
            let err = salty::invoke::vspace_walk(parent_vs, walk_start, 6);
            if err != 0 {
                puts(b"[PROCMGR] FORK: vspace_walk failed\n");
                break;
            }

            let ipc = IPC_BUF_VADDR as *const u64;
            let count = core::ptr::read_volatile(ipc);
            let next_addr = core::ptr::read_volatile(ipc.add(1));

            if count == 0 { break; }

            for i in 0..count {
                let page_vaddr = core::ptr::read_volatile(ipc.add(2 + i as usize * 3));
                let _page_phys = core::ptr::read_volatile(ipc.add(2 + i as usize * 3 + 1));
                let page_flags = core::ptr::read_volatile(ipc.add(2 + i as usize * 3 + 2));

                if page_vaddr == CHILD_IPC_BUF_VADDR { continue; }

                let err = salty::invoke::untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, next_frame);
                if err != 0 {
                    puts(b"[PROCMGR] FORK: frame retype failed\n");
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }

                let err = salty::invoke::vspace_copy_page(parent_vs, page_vaddr, next_frame);
                if err != 0 {
                    let mut lb = LineBuf::new();
                    lb.str(b"[PROCMGR] FORK: copy_page failed at "); lb.hex(page_vaddr);
                    lb.str(b" err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
                    reply.label = SALTY_INVALID_OPERATION;
                    return;
                }

                let mut map_flags = VSPACE_FLAG_USER;
                if page_flags & X86_PTE_WRITABLE != 0 { map_flags |= VSPACE_FLAG_WRITABLE; }
                if page_flags & X86_PTE_NX == 0 { map_flags |= VSPACE_FLAG_EXECUTABLE; }

                let err = salty::invoke::vspace_map(child_vs, next_frame, page_vaddr, map_flags);
                if err != 0 {
                    let mut lb = LineBuf::new();
                    lb.str(b"[PROCMGR] FORK: child map failed at "); lb.hex(page_vaddr);
                    lb.str(b" err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }

                if page_vaddr == rsp_page_vaddr { rsp_frame = next_frame; }

                next_frame += 1;
                total_pages += 1;

                if next_frame >= base + CAP_PROC_STRIDE {
                    puts(b"[PROCMGR] FORK: frame slot overflow\n");
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }

            if next_addr == 0 { break; }
            walk_start = next_addr;
        }

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] FORK: copied "); lb.hex(total_pages); lb.str(b" pages\n"); lb.flush(); }

        if rsp_frame == 0 {
            puts(b"[PROCMGR] FORK: parent RSP page not mapped in child\n");
            reply.label = SALTY_INVALID_OPERATION;
            return;
        }

        // Reconstruct fork trampoline frame on child stack
        let err = salty::invoke::vspace_map(
            CAP_SELF_VSPACE, rsp_frame, PROCMGR_SCRATCH_VADDR,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[PROCMGR] FORK: stack scratch map failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        {
            let off = (parent_rsp - rsp_page_vaddr) as usize;
            let saved = (PROCMGR_SCRATCH_VADDR + off as u64) as *mut u64;
            core::ptr::write_volatile(saved.add(0), saved_r15);
            core::ptr::write_volatile(saved.add(1), saved_r14);
            core::ptr::write_volatile(saved.add(2), saved_r13);
            core::ptr::write_volatile(saved.add(3), saved_r12);
            core::ptr::write_volatile(saved.add(4), saved_rbx);
            core::ptr::write_volatile(saved.add(5), saved_rbp);
            core::ptr::write_volatile(saved.add(6), return_rip);
        }
        salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);

        // 3. Map IPC buffer in child
        let err = salty::invoke::vspace_map(
            child_vs, child_ipc_fr, CHILD_IPC_BUF_VADDR,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[PROCMGR] FORK: IPC buf map failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // 4. Copy caps into child CNode
        salty::invoke::cnode_copy(CAP_SELF_CSPACE, child_tcb, child_cn, CHILD_CAP_TCB, CAP_RIGHTS_ALL);
        salty::invoke::cnode_copy(CAP_SELF_CSPACE, child_vs, child_cn, CHILD_CAP_VSPACE, CAP_RIGHTS_ALL);
        salty::invoke::cnode_copy(CAP_SELF_CSPACE, child_cn, child_cn, CHILD_CAP_CSPACE, CAP_RIGHTS_ALL);
        salty::invoke::cnode_mint(CAP_SELF_CSPACE, CAP_SERVER_EP, child_cn, CHILD_CAP_EP, child_pid as u64);
        let err = salty::invoke::cnode_mint(
            CAP_SELF_CSPACE, CAP_VFS_EP, child_cn, CHILD_CAP_VFS, child_pid as u64,
        );
        if err != 0 {
            puts(b"[PROCMGR] FORK: mint child VFS EP failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        salty::invoke::cnode_copy(CAP_SELF_CSPACE, CAP_NAMESERV_EP, child_cn, CHILD_CAP_NAMESERV, CAP_RIGHTS_ALL);
        salty::invoke::cnode_copy(CAP_SELF_CSPACE, CAP_UNTYPED, child_cn, CHILD_CAP_UNTYPED, CAP_RIGHTS_ALL);
        salty::invoke::cnode_copy(CAP_SELF_CSPACE, child_sig_ntfn, child_cn, CHILD_CAP_SIGNAL_NTFN, CAP_RIGHTS_ALL);

        // 5. Configure child TCB
        let err = salty::invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            puts(b"[PROCMGR] FORK: set_space failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let err = salty::invoke::tcb_configure(child_tcb, child_entry, parent_rsp, 0);
        if err != 0 {
            puts(b"[PROCMGR] FORK: configure failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let err = salty::invoke::tcb_set_ipc_buffer(child_tcb, CHILD_IPC_BUF_VADDR);
        if err != 0 {
            puts(b"[PROCMGR] FORK: set IPC buf failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // 6. Clone FD table BEFORE resuming child (Bug 5: race condition)
        {
            let mut clone_msg = SaltyMsg::zeroed();
            let mut clone_reply = SaltyMsg::zeroed();
            clone_msg.label = salty::consts::POSIX_VFS_CLONE_FDS;
            clone_msg.length = 2;
            clone_msg.regs[0] = badge; // parent badge
            clone_msg.regs[1] = child_pid as u64; // child badge
            let err = ipc::call_ctx(ipc_ctx(), CAP_VFS_EP, &raw const clone_msg, &raw mut clone_reply);
            if err != 0 || clone_reply.label != SALTY_OK {
                puts(b"[PROCMGR] FORK: VFS clone_fds failed, aborting fork\n");
                reply.label = SALTY_INVALID_OPERATION;
                return;
            }
        }

        // 7. Schedule the child
        let err = salty::invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 { reply.label = SALTY_OUT_OF_MEMORY; return; }
        let err = salty::invoke::sc_bind(child_sc, child_tcb);
        if err != 0 { reply.label = SALTY_OUT_OF_MEMORY; return; }
        let err = salty::invoke::tcb_resume(child_tcb);
        if err != 0 { reply.label = SALTY_OUT_OF_MEMORY; return; }

        // Record in process table
        let p = &mut PROCTAB[slot_idx];
        p.pid = child_pid;
        p.ppid = parent_pid;
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
        // Fork inherits parent's signal dispositions
        for i in 0..NSIG {
            p.sig_disposition[i] = PROCTAB[parent_idx].sig_disposition[i];
        }

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] FORK: child PID="); lb.hex(child_pid as u64); lb.str(b" started\n"); lb.flush(); }
        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = child_pid as u64;
    }
}

// ===========================================================================
// handle_exec
// ===========================================================================

unsafe fn handle_exec(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let Some(idx) = find_by_badge(badge) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };

        let (name, name_len) = extract_name(msg);

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] EXEC PID="); lb.hex(PROCTAB[idx].pid as u64);
        lb.str(b" -> '");
        lb.bytes(&name[..name_len]);
        lb.str(b"'\n");
        lb.flush(); }

        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = salty::cpio::cpio_archive_size(initrd, 1024 * 1024);

        let mut elf_entry = CpioEntry::zeroed();
        if salty::cpio::cpio_find_file(initrd, initrd_size, name.as_ptr(), name_len, &raw mut elf_entry) == 0 {
            puts(b"[PROCMGR] EXEC: ELF not found\n");
            reply.label = SALTY_NOT_FOUND;
            return;
        }

        let is_dynamic = salty::elf_dynamic::elf_has_interp(elf_entry.data, elf_entry.data_len);
        let proc_vs = PROCTAB[idx].vspace_cap;

        // 1. Unmap existing user pages
        let mut walk_start: u64 = 0;
        loop {
            let err = salty::invoke::vspace_walk(proc_vs, walk_start, 6);
            if err != 0 { break; }

            let ipc = IPC_BUF_VADDR as *const u64;
            let count = core::ptr::read_volatile(ipc);
            let next_addr = core::ptr::read_volatile(ipc.add(1));
            if count == 0 { break; }

            for i in 0..count {
                let page_vaddr = core::ptr::read_volatile(ipc.add(2 + i as usize * 3));
                if page_vaddr == CHILD_IPC_BUF_VADDR { continue; }
                salty::invoke::vspace_unmap(proc_vs, page_vaddr);
            }

            if next_addr == 0 { break; }
            walk_start = next_addr;
        }

        // 2. Load new ELF
        let slot_i = idx;
        let frame_base = CAP_PROC_BASE + slot_i as u64 * CAP_PROC_STRIDE + CAP_OFF_FRAME_START;
        let frame_limit = CAP_PROC_BASE + slot_i as u64 * CAP_PROC_STRIDE + CAP_PROC_STRIDE;

        // Reclaim frame slots
        for slot in frame_base..frame_limit {
            let cerr = salty::invoke::cnode_revoke(CAP_SELF_CSPACE, slot);
            if cerr != 0 { salty::invoke::cnode_delete(CAP_SELF_CSPACE, slot); }
        }

        let mut loader_ctx = ElfLoaderCtx {
            untyped: CAP_UNTYPED, self_vspace: CAP_SELF_VSPACE,
            child_vspace: proc_vs, scratch_vaddr: PROCMGR_SCRATCH_VADDR,
            next_frame_slot: frame_base,
            alloc_frame_slot: None, alloc_opaque: core::ptr::null_mut(),
            record_page: None, record_opaque: core::ptr::null_mut(),
        };

        let mut elf_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        let err = salty::elf_loader::elf_load(
            elf_entry.data, elf_entry.data_len,
            CHILD_CODE_VADDR, &mut loader_ctx, &raw mut elf_result,
        );
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] EXEC: ELF load failed\n");
            lb.str(b"[PROCMGR] EXEC: ELF load err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // 2b. Load rtld if dynamic
        let mut rtld_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        if is_dynamic {
            match load_rtld(elf_entry.data, elf_entry.data_len, initrd, initrd_size, &mut loader_ctx) {
                Some(r) => rtld_result = r,
                None => { reply.label = SALTY_NOT_FOUND; return; }
            }
        }

        // 3. Set up new stack
        if loader_ctx.next_frame_slot >= frame_limit {
            puts(b"[PROCMGR] EXEC: stack frame slot overflow\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let stk_frame = loader_ctx.next_frame_slot;
        loader_ctx.next_frame_slot += 1;

        for pg in 0..CHILD_STACK_PAGES {
            let fr;
            if pg == CHILD_STACK_PAGES - 1 {
                fr = stk_frame;
            } else {
                if loader_ctx.next_frame_slot >= frame_limit {
                    puts(b"[PROCMGR] EXEC: stack frame slot overflow\n");
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
                fr = loader_ctx.next_frame_slot;
                loader_ctx.next_frame_slot += 1;
            }
            let err = salty::invoke::untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, fr);
            if err != 0 { reply.label = SALTY_OUT_OF_MEMORY; return; }

            let err = salty::invoke::vspace_map(
                proc_vs, fr, CHILD_STACK_VADDR + pg as u64 * 4096,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 { reply.label = SALTY_OUT_OF_MEMORY; return; }
        }

        // 5. Map initrd for dynamic executables
        if is_dynamic {
            let base_cap = CAP_PROC_BASE + slot_i as u64 * CAP_PROC_STRIDE;
            if map_initrd_to_child(proc_vs, initrd, initrd_size, &mut loader_ctx, base_cap) != 0 {
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // 6. Entry point and dynamic stack
        let mut new_entry = elf_result.entry;
        let mut new_rsp = CHILD_STACK_TOP;

        if is_dynamic {
            match write_dynamic_stack(
                elf_entry.data, elf_entry.data_len,
                stk_frame, &elf_result, &rtld_result, initrd_size,
            ) {
                Ok(rsp) => {
                    new_rsp = rsp;
                    new_entry = rtld_result.entry;
                }
                Err(()) => {
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
        }

        // 7. Suspend and reconfigure
        salty::invoke::tcb_suspend(PROCTAB[idx].tcb_cap);

        // POSIX: exec resets caught signals to SIG_DFL
        for i in 0..NSIG {
            if PROCTAB[idx].sig_disposition[i] == SIG_DISP_CATCH {
                PROCTAB[idx].sig_disposition[i] = SIG_DISP_DFL;
            }
        }

        let err = salty::invoke::tcb_configure(PROCTAB[idx].tcb_cap, new_entry, new_rsp, 0);
        if err != 0 {
            puts(b"[PROCMGR] EXEC: tcb_configure failed\n");
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }
        salty::invoke::tcb_set_ipc_buffer(PROCTAB[idx].tcb_cap, CHILD_IPC_BUF_VADDR);

        let err = salty::invoke::tcb_resume(PROCTAB[idx].tcb_cap);
        if err != 0 {
            puts(b"[PROCMGR] EXEC: resume failed\n");
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] EXEC: PID="); lb.hex(PROCTAB[idx].pid as u64);
        lb.str(b" -> entry="); lb.hex(new_entry); lb.str(b"\n"); lb.flush(); }

        // Don't reply — process image replaced and resumed.
    }
}

// ===========================================================================
// Entry point
// ===========================================================================

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[PROCMGR] SaltyOS process manager starting\n");

    unsafe {
        // Set IPC buffer
        let err = salty::invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] FAIL: set IPC buffer err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
            idle();
        }
        salty::ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
        puts(b"[PROCMGR] IPC buffer ready\n");

        // Initialize process table
        for i in 0..MAX_PROCESSES {
            PROCTAB[i].state = PROC_FREE;
        }

        // Register with name server
        if CAP_NAMESERV_EP != 0 {
            let mut reg_msg = SaltyMsg::zeroed();
            let mut reg_reply = SaltyMsg::zeroed();
            let svc_name = b"procmgr";
            reg_msg.label = salty::consts::POSIX_NS_REGISTER;
            reg_msg.regs[0] = svc_name.len() as u64;
            reg_msg.length = 1 + (svc_name.len() as u64 + 7) / 8;
            let dst = &raw mut reg_msg.regs[1] as *mut u8;
            for i in 0..svc_name.len() { *dst.add(i) = svc_name[i]; }
            reg_msg.regs[2] = 0;
            reg_msg.regs[3] = 0;

            // Set up cap transfer: send our server EP
            salty::ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);

            let err = salty::ipc::call_ctx(ipc_ctx(), CAP_NAMESERV_EP, &raw const reg_msg, &raw mut reg_reply);
            if err == 0 && reg_reply.label == SALTY_OK {
                puts(b"[PROCMGR] registered with nameserv\n");
            } else {
                puts(b"[PROCMGR] WARN: nameserv registration failed\n");
            }
        }

        // Initial recv
        let mut msg = SaltyMsg::zeroed();
        let mut badge: u64 = 0;

        let err = salty::ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge);
        if err != 0 {
            puts(b"[PROCMGR] initial recv failed\n");
            idle();
        }

        // Server loop
        loop {
            let mut reply = SaltyMsg::zeroed();
            let mut skip_reply = false;

            match msg.label {
                PM_SPAWN => handle_spawn(&msg, &mut reply, badge),
                PM_EXIT => {
                    handle_exit(&msg, &mut reply, badge);
                    skip_reply = true;
                }
                PM_WAIT => {
                    skip_reply = handle_wait(&msg, &mut reply, badge);
                }
                PM_GETPID => handle_getpid(&mut reply, badge),
                PM_FORK => handle_fork(&msg, &mut reply, badge),
                PM_EXEC => {
                    handle_exec(&msg, &mut reply, badge);
                    if reply.label == 0 { skip_reply = true; }
                }
                PM_GETPPID => handle_getppid(&mut reply, badge),
                PM_KILL => handle_kill(&msg, &mut reply, badge),
                PM_SIGACTION => handle_sigaction(&msg, &mut reply, badge),
                _ => {
                    let mut lb = LineBuf::new();
                    lb.str(b"[PROCMGR] unknown label="); lb.hex(msg.label); lb.str(b"\n"); lb.flush();
                    reply.label = SALTY_INVALID_OPERATION;
                }
            }

            let err = if skip_reply {
                salty::ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge)
            } else {
                salty::ipc::reply_recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw const reply, &raw mut msg, &raw mut badge)
            };
            if err != 0 {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] reply_recv failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
                break;
            }
        }
    }

    idle();
}

fn idle() -> ! {
    loop { salty::syscall::syscall(salty::SYS_YIELD, 0, 0, 0, 0, 0, 0); }
}
