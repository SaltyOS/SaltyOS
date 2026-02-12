//! SaltyOS Process Manager
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Panic handler provided by libsalty.so (dynamic linking).

#![no_std]
#![no_main]

mod alloc;
mod proc_table;
mod spawn_tx;

use salty::ipc;
use salty::serial::LineBuf;
use salty::types::*;

use proc_table::{
    alloc_proc, cleanup_proc_resources, find_by_badge, find_by_pid,
    MAX_NAME_LEN, MAX_PROCESSES, NEXT_PID, NSIG, PROCTAB,
    PROC_FREE, PROC_RUNNING, PROC_STOPPED, PROC_ZOMBIE,
    SIG_DISP_CATCH, SIG_DISP_DFL, SIG_DISP_IGN,
};

// ---- Cap layout (set by init for this process) ----
const CAP_SELF_TCB: Cap = 0;
const CAP_SELF_VSPACE: Cap = 1;
const CAP_SELF_CSPACE: Cap = 2;
const CAP_SERVER_EP: Cap = 3;
const CAP_UNTYPED: Cap = 7;
const CAP_NAMESERV_EP: Cap = 8;
const CAP_VFS_EP: Cap = 9;
const CAP_INITRD_UNTYPED: Cap = 12;
const CAP_UNTYPED_START: Cap = 16;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

// ---- Protocol labels ----
const PM_SPAWN: u64 = 1;
const PM_SPAWN_FLAG_WAIT_READY: u64 = 1 << 0;
const PM_EXIT: u64 = 2;
const PM_WAIT: u64 = 3;
const PM_GETPID: u64 = 4;
const PM_FORK: u64 = 5;
const PM_EXEC: u64 = 6;
const PM_GETPPID: u64 = 7;
const PM_KILL: u64 = 8;
const PM_SIGACTION: u64 = 9;
const PM_GETUID: u64 = 10;
const PM_GETGID: u64 = 11;
const PM_SETPGID: u64 = 12;
const PM_GETPGID: u64 = 13;
const PM_SETSID: u64 = 14;
const PM_GETEUID: u64 = 15;
const PM_GETEGID: u64 = 16;
const PM_GETGROUPS: u64 = 17;
const PM_EXPAND_CSPACE: u64 = 18;

const PM_SIGKILL: usize = 9;
const PM_SIGCHLD: usize = 17;
const PM_SIGCONT: usize = 18;
const PM_SIGSTOP: usize = 19;

// ---- Child VSpace layout ----
// Keep code+rtld+libs+stack+IPC+scratch in one 2MiB PT window
// (0x200000..0x3fffff) to reduce per-process PT pressure in lowmem boots.
const CHILD_CODE_VADDR: u64 = 0x0000_0000_0021_0000;
const CHILD_STACK_VADDR: u64 = 0x0000_0000_003F_8000;
const CHILD_STACK_PAGES: usize = 4;
const CHILD_STACK_SIZE: u64 = CHILD_STACK_PAGES as u64 * 4096;
const CHILD_STACK_TOP: u64 = CHILD_STACK_VADDR + CHILD_STACK_SIZE;
const CHILD_IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;
const CHILD_RTLD_VADDR: u64 = 0x0000_0000_0028_0000;
const CHILD_INITRD_VADDR: u64 = 0x0000_0000_0100_0000;
const CHILD_SCRATCH_VADDR: u64 = 0x0000_0000_003F_F000;
const CHILD_RTLD_FRAME_SLOT_START: u64 = 64;
const PROCMGR_SCRATCH_VADDR: u64 = 0x0000_0000_0500_0000;

// ---- Child CNode layout ----
const CHILD_CAP_TCB: u64 = 0;
const CHILD_CAP_VSPACE: u64 = 1;
const CHILD_CAP_CSPACE: u64 = 2;
const CHILD_CAP_EP: u64 = 3;
const CHILD_CAP_VFS: u64 = 4;
const CHILD_CAP_NAMESERV: u64 = 5;
const CHILD_CAP_SIGNAL_NTFN: u64 = 6;
const CHILD_CAP_UNTYPED: u64 = 7;
const CHILD_CAP_READINESS_NTFN: u64 = salty::CAP_READINESS_NTFN;
const CHILD_UT_BITS_DEFAULT: u8 = 16;
const CHILD_UT_BITS_MIN: u8 = 12;
const READY_SIGNAL_BITS: u64 = 1;
const READY_WAIT_YIELDS_STATIC: usize = 20_000;
const READY_WAIT_YIELDS_DYNAMIC: usize = 200_000;

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
const OBJ_UNTYPED: u64 = salty::OBJ_UNTYPED;
const OBJ_SCHED_CONTEXT: u64 = salty::OBJ_SCHED_CONTEXT;
const OBJ_FRAME: u64 = salty::OBJ_FRAME;
const OBJ_NOTIFICATION: u64 = salty::OBJ_NOTIFICATION;
const SALTY_OK: u64 = salty::SALTY_OK;
const SALTY_OUT_OF_MEMORY: u64 = salty::SALTY_OUT_OF_MEMORY;
const SALTY_NOT_FOUND: u64 = salty::SALTY_NOT_FOUND;
const SALTY_INVALID_ARGUMENT: u64 = salty::SALTY_INVALID_ARGUMENT;
const SALTY_INVALID_OPERATION: u64 = salty::SALTY_INVALID_OPERATION;
const SALTY_WOULD_BLOCK: u64 = salty::SALTY_WOULD_BLOCK;
const VSPACE_FLAG_WRITABLE: u64 = salty::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = salty::VSPACE_FLAG_USER;
const VSPACE_FLAG_EXECUTABLE: u64 = salty::VSPACE_FLAG_EXECUTABLE;
const CAP_RIGHTS_ALL: u64 = salty::CAP_RIGHTS_ALL;
const UT_MIRROR_COUNT: Cap = 8;
const INITRD_VADDR: u64 = salty::INITRD_VADDR;
const BOOTINFO_VADDR: u64 = salty::BOOTINFO_VADDR;
const BOOTINFO_MAGIC: u64 = salty::BOOTINFO_MAGIC;

static mut ALLOCATOR: alloc::Allocator = alloc::Allocator::new();

fn read_boot_info_initrd_size() -> usize {
    unsafe {
        let page = BOOTINFO_VADDR as *const u64;
        let magic = core::ptr::read_volatile(page);
        if magic != BOOTINFO_MAGIC {
            return 0;
        }
        core::ptr::read_volatile(page.add(2)) as usize
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

fn puts(s: &[u8]) { salty::serial::serial_puts(s); }
fn ipc_ctx() -> *mut IpcContext { &raw mut salty::__salty_ipc_ctx }

fn signal_ready() {
    let _ = salty::syscall::syscall(salty::SYS_SIGNAL, salty::CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

fn signal_ntfn(ntfn: Cap, bits: u64) {
    salty::syscall::syscall(salty::SYS_SIGNAL, ntfn, bits, 0, 0, 0, 0);
}

fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

/// Extract ELF name from message regs, append ".elf" if needed.
/// Returns the name buffer and its length.
fn extract_name(msg: &SaltyMsg, name_reg_idx: usize) -> ([u8; MAX_NAME_LEN + 5], usize) {
    let mut name = [0u8; MAX_NAME_LEN + 5];
    let mut name_len = msg.regs[0] as usize;
    if name_len > MAX_NAME_LEN { name_len = MAX_NAME_LEN; }

    for i in 0..name_len {
        unsafe {
            let src = msg.regs.as_ptr().add(name_reg_idx) as *const u8;
            name[i] = *src.add(i);
        }
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

unsafe fn wait_for_child_ready(
    child_tcb: Cap,
    ready_ntfn: Cap,
    child_name: &[u8],
    wait_yields: usize,
) -> i32 {
    for _ in 0..wait_yields {
        let poll = salty::syscall::syscall(salty::SYS_POLL, ready_ntfn, 0, 0, 0, 0, 0);
        if poll.error == 0 {
            if (poll.value & READY_SIGNAL_BITS) != 0 {
                return 0;
            }
        } else if poll.error != SALTY_WOULD_BLOCK {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] ready poll failed err=");
            lb.hex(poll.error);
            lb.str(b"\n");
            lb.flush();
            let _ = salty::invoke::tcb_suspend(child_tcb);
            return -1;
        }
        let _ = salty::syscall::syscall(salty::SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }

    let mut lb = LineBuf::new();
    lb.str(b"[PROCMGR] child ready timeout: ");
    lb.bytes(child_name);
    lb.str(b"\n");
    lb.flush();
    let _ = salty::invoke::tcb_suspend(child_tcb);
    -1
}

// ===========================================================================
// Allocator slot cleanup helper
// ===========================================================================

/// Free allocator-tracked bitmap slots for a process. Must be called BEFORE
/// cleanup_proc_resources so that slot_base/slot_count are still valid for
/// cap revocation.
///
/// This function:
/// 1. Frees any outstanding waiter reply slots (revoke + free bitmap)
/// 2. Revokes + frees the exec frame range (separate from primary slots)
/// 3. Frees the primary slot range bitmap (caps revoked by cleanup_proc_resources)
unsafe fn free_proc_alloc_slots(idx: usize) {
    unsafe {
        let alloc = &mut *(&raw mut ALLOCATOR);

        // Free any outstanding waiter reply slots
        if PROCTAB[idx].waiter_reply != 0 {
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, PROCTAB[idx].waiter_reply);
            alloc.free_single_slot(PROCTAB[idx].waiter_reply);
            PROCTAB[idx].waiter_reply = 0;
        }
        if PROCTAB[idx].any_waiter_reply != 0 {
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, PROCTAB[idx].any_waiter_reply);
            alloc.free_single_slot(PROCTAB[idx].any_waiter_reply);
            PROCTAB[idx].any_waiter_reply = 0;
        }

        // Revoke + free exec frame range if present
        if PROCTAB[idx].frame_count > 0 {
            let fb = PROCTAB[idx].frame_base;
            let fc = PROCTAB[idx].frame_count as usize;
            for i in 0..fc {
                let slot = fb + i as u64;
                let err = salty::invoke::cnode_revoke(CAP_SELF_CSPACE, slot);
                if err != 0 { salty::invoke::cnode_delete(CAP_SELF_CSPACE, slot); }
            }
            alloc.free_slots(fb, fc);
            PROCTAB[idx].frame_base = 0;
            PROCTAB[idx].frame_count = 0;
        }

        // Free primary slot range bitmap (caps are revoked by cleanup_proc_resources)
        if PROCTAB[idx].slot_count > 0 {
            alloc.free_slots(PROCTAB[idx].slot_base, PROCTAB[idx].slot_count as usize);
            // Don't zero slot_base/slot_count here -- cleanup_proc_resources
            // still needs them for cap revocation. They get zeroed there.
        }
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
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(waiter_cap);
            PROCTAB[idx].waiter_reply = 0;
            PROCTAB[idx].waiter_pid = 0;
            free_proc_alloc_slots(idx);
            cleanup_proc_resources(idx, CAP_SELF_CSPACE);
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
                (&mut *(&raw mut ALLOCATOR)).free_single_slot(waiter_cap);
                PROCTAB[pi].any_waiter_reply = 0;
                PROCTAB[pi].waiting_for_any = 0;
                free_proc_alloc_slots(idx);
                cleanup_proc_resources(idx, CAP_SELF_CSPACE);
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
                free_proc_alloc_slots(zi);
                cleanup_proc_resources(zi, CAP_SELF_CSPACE);
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
            let reply_slot = match (&mut *(&raw mut ALLOCATOR)).alloc_single_slot() {
                Some(s) => s,
                None => { reply.label = SALTY_OUT_OF_MEMORY; return false; }
            };
            let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
            if err != 0 {
                (&mut *(&raw mut ALLOCATOR)).free_single_slot(reply_slot);
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
            free_proc_alloc_slots(ci);
            cleanup_proc_resources(ci, CAP_SELF_CSPACE);
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
        let reply_slot = match (&mut *(&raw mut ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => { reply.label = SALTY_OUT_OF_MEMORY; return false; }
        };
        let err = salty::invoke::cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] save_caller failed for WAIT, err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(reply_slot);
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

            let waiter_cap = PROCTAB[idx].waiter_reply;
            salty::ipc::send_ctx(ipc_ctx(), waiter_cap, &raw const wake);
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, waiter_cap);
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(waiter_cap);
            PROCTAB[idx].waiter_reply = 0;
            PROCTAB[idx].waiter_pid = 0;
            free_proc_alloc_slots(idx);
            cleanup_proc_resources(idx, CAP_SELF_CSPACE);
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

                let waiter_cap = PROCTAB[pi].any_waiter_reply;
                salty::ipc::send_ctx(ipc_ctx(), waiter_cap, &raw const wake);
                salty::invoke::cnode_delete(CAP_SELF_CSPACE, waiter_cap);
                (&mut *(&raw mut ALLOCATOR)).free_single_slot(waiter_cap);
                PROCTAB[pi].any_waiter_reply = 0;
                PROCTAB[pi].waiting_for_any = 0;
                free_proc_alloc_slots(idx);
                cleanup_proc_resources(idx, CAP_SELF_CSPACE);
            }
        }
    }
}

/// Deliver a signal to a single process by table index.
/// Returns true if the signal was delivered (or ignored), false if target invalid.
unsafe fn deliver_signal_to(ti: usize, sig: usize) -> bool {
    unsafe {
        if PROCTAB[ti].state != PROC_RUNNING && PROCTAB[ti].state != PROC_STOPPED {
            return false;
        }

        // SIGKILL: always terminate
        if sig == PM_SIGKILL {
            sig_terminate_proc(ti, sig);
            return true;
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
            return true;
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
            return true;
        }

        // Cannot deliver most signals to stopped processes
        if PROCTAB[ti].state != PROC_RUNNING {
            return true;
        }

        let disp = PROCTAB[ti].sig_disposition[sig];

        if disp == SIG_DISP_IGN {
            return true;
        }

        if disp == SIG_DISP_DFL {
            if sig_default_is_terminate(sig) {
                sig_terminate_proc(ti, sig);
            }
            return true;
        }

        // SIG_DISP_CATCH: deliver via notification
        if PROCTAB[ti].signal_ntfn != 0 {
            signal_ntfn(PROCTAB[ti].signal_ntfn, 1u64 << sig);
        }
        true
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

        // pid==0: send signal to all processes in the foreground process group (pgid==0)
        if target_pid == 0 {
            for i in 0..MAX_PROCESSES {
                if PROCTAB[i].state != PROC_FREE && PROCTAB[i].pgid == 0 {
                    deliver_signal_to(i, sig);
                }
            }
            reply.label = SALTY_OK;
            reply.length = 0;
            return;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };

        if !deliver_signal_to(ti, sig) {
            reply.label = SALTY_NOT_FOUND;
            return;
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
        let alloc = &mut *(&raw mut ALLOCATOR);

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

        // Count parent pages first
        let mut page_count: usize = 0;
        {
            let mut walk_start: u64 = 0;
            loop {
                let err = salty::invoke::vspace_walk(parent_vs, walk_start, 6);
                if err != 0 { break; }
                let ipc = IPC_BUF_VADDR as *const u64;
                let count = core::ptr::read_volatile(ipc);
                let next_addr = core::ptr::read_volatile(ipc.add(1));
                if count == 0 { break; }
                for i in 0..count as usize {
                    let page_vaddr = core::ptr::read_volatile(ipc.add(2 + i * 3));
                    if page_vaddr != CHILD_IPC_BUF_VADDR { page_count += 1; }
                }
                if next_addr == 0 { break; }
                walk_start = next_addr;
            }
        }

        // Reserve: 7 fixed objects + page frames + margin
        let total_slots = 7 + page_count + 4;
        if !alloc.reserve(total_slots) {
            puts(b"[PROCMGR] FORK: slot reservation failed\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        macro_rules! realize {
            ($ty:expr, $what:expr) => {
                match alloc.realize_object($ty, 0) {
                    Ok(s) => s,
                    Err(_) => {
                        puts($what);
                        alloc.rollback();
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                }
            };
        }

        let child_tcb = realize!(OBJ_TCB, b"[PROCMGR] FORK: TCB retype failed\n");
        let child_vs = realize!(OBJ_VSPACE, b"[PROCMGR] FORK: VSpace retype failed\n");
        let child_cn = realize!(OBJ_CNODE, b"[PROCMGR] FORK: CNode retype failed\n");
        let child_sc = realize!(OBJ_SCHED_CONTEXT, b"[PROCMGR] FORK: SC retype failed\n");
        let child_ipc_fr = realize!(OBJ_FRAME, b"[PROCMGR] FORK: IPC frame retype failed\n");
        let child_sig_ntfn = realize!(OBJ_NOTIFICATION, b"[PROCMGR] FORK: signal ntfn retype failed\n");

        // Child untyped with downshift
        let child_ut_slot = {
            let mut bits = CHILD_UT_BITS_DEFAULT;
            let mut result: Option<Cap> = None;
            while bits >= CHILD_UT_BITS_MIN {
                match alloc.realize_object(OBJ_UNTYPED, bits as u64) {
                    Ok(s) => { result = Some(s); break; }
                    Err(_) => { bits -= 1; }
                }
            }
            match result {
                Some(s) => s,
                None => {
                    puts(b"[PROCMGR] FORK: child untyped unavailable\n");
                    alloc.rollback();
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
        };

        // Walk parent VSpace again and copy pages
        let mut walk_start: u64 = 0;
        let mut total_pages = 0u64;
        let rsp_page_vaddr = parent_rsp & !0xFFFu64;
        let mut rsp_frame: Cap = 0;

        loop {
            let err = salty::invoke::vspace_walk(parent_vs, walk_start, 6);
            if err != 0 { break; }
            let ipc = IPC_BUF_VADDR as *const u64;
            let count = core::ptr::read_volatile(ipc);
            let next_addr = core::ptr::read_volatile(ipc.add(1));
            if count == 0 { break; }

            for i in 0..count as usize {
                let page_vaddr = core::ptr::read_volatile(ipc.add(2 + i * 3));
                let _page_phys = core::ptr::read_volatile(ipc.add(2 + i * 3 + 1));
                let page_flags = core::ptr::read_volatile(ipc.add(2 + i * 3 + 2));
                if page_vaddr == CHILD_IPC_BUF_VADDR { continue; }

                let next_frame = match alloc.realize_object(OBJ_FRAME, 0) {
                    Ok(s) => s,
                    Err(_) => {
                        puts(b"[PROCMGR] FORK: frame retype failed\n");
                        alloc.rollback();
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                };

                let err = salty::invoke::vspace_copy_page(parent_vs, page_vaddr, next_frame);
                if err != 0 {
                    let mut lb = LineBuf::new();
                    lb.str(b"[PROCMGR] FORK: copy_page failed at "); lb.hex(page_vaddr);
                    lb.str(b" err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
                    alloc.rollback();
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
                    alloc.rollback();
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }

                if page_vaddr == rsp_page_vaddr { rsp_frame = next_frame; }
                total_pages += 1;
            }

            if next_addr == 0 { break; }
            walk_start = next_addr;
        }

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] FORK: copied "); lb.hex(total_pages); lb.str(b" pages\n"); lb.flush(); }

        if rsp_frame == 0 {
            puts(b"[PROCMGR] FORK: parent RSP page not mapped in child\n");
            alloc.rollback();
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
            alloc.rollback();
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

        // Map IPC buffer in child
        let err = salty::invoke::vspace_map(
            child_vs, child_ipc_fr, CHILD_IPC_BUF_VADDR,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[PROCMGR] FORK: IPC buf map failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Copy child untyped into child CNode
        let cerr = salty::invoke::cnode_copy(
            CAP_SELF_CSPACE, child_ut_slot, child_cn, CHILD_CAP_UNTYPED, CAP_RIGHTS_ALL,
        );
        if cerr != 0 {
            puts(b"[PROCMGR] FORK: copy child untyped cap failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Copy caps into child CNode
        macro_rules! copy_or_fail {
            ($src:expr, $dst:expr, $what:expr) => {
                if salty::invoke::cnode_copy(CAP_SELF_CSPACE, $src, child_cn, $dst, CAP_RIGHTS_ALL) != 0 {
                    puts($what);
                    alloc.rollback();
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            };
        }
        copy_or_fail!(child_tcb, CHILD_CAP_TCB, b"[PROCMGR] FORK: copy TCB cap failed\n");
        copy_or_fail!(child_vs, CHILD_CAP_VSPACE, b"[PROCMGR] FORK: copy VSpace cap failed\n");
        copy_or_fail!(child_cn, CHILD_CAP_CSPACE, b"[PROCMGR] FORK: copy CNode cap failed\n");

        let err = salty::invoke::cnode_mint(CAP_SELF_CSPACE, CAP_SERVER_EP, child_cn, CHILD_CAP_EP, child_pid as u64);
        if err != 0 {
            puts(b"[PROCMGR] FORK: mint server EP failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let err = salty::invoke::cnode_mint(CAP_SELF_CSPACE, CAP_VFS_EP, child_cn, CHILD_CAP_VFS, child_pid as u64);
        if err != 0 {
            puts(b"[PROCMGR] FORK: mint child VFS EP failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let _ = salty::invoke::cnode_copy(CAP_SELF_CSPACE, CAP_NAMESERV_EP, child_cn, CHILD_CAP_NAMESERV, CAP_RIGHTS_ALL);
        let _ = salty::invoke::cnode_copy(CAP_SELF_CSPACE, child_sig_ntfn, child_cn, CHILD_CAP_SIGNAL_NTFN, CAP_RIGHTS_ALL);

        // Configure child TCB
        let err = salty::invoke::tcb_set_space(child_tcb, child_cn, child_vs);
        if err != 0 {
            puts(b"[PROCMGR] FORK: set_space failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let err = salty::invoke::tcb_configure(child_tcb, child_entry, parent_rsp, 0);
        if err != 0 {
            puts(b"[PROCMGR] FORK: configure failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        let err = salty::invoke::tcb_set_ipc_buffer(child_tcb, CHILD_IPC_BUF_VADDR);
        if err != 0 {
            puts(b"[PROCMGR] FORK: set IPC buf failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
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
            let err = ipc::call_ctx(ipc_ctx(), CAP_VFS_EP, &raw const clone_msg, &raw mut clone_reply);
            if err != 0 || clone_reply.label != SALTY_OK {
                puts(b"[PROCMGR] FORK: VFS clone_fds failed, aborting fork\n");
                alloc.rollback();
                reply.label = SALTY_INVALID_OPERATION;
                return;
            }
        }

        // Schedule the child
        let err = salty::invoke::sc_configure(child_sc, 10000, 100000);
        if err != 0 { alloc.rollback(); reply.label = SALTY_OUT_OF_MEMORY; return; }
        let err = salty::invoke::sc_bind(child_sc, child_tcb);
        if err != 0 { alloc.rollback(); reply.label = SALTY_OUT_OF_MEMORY; return; }
        let err = salty::invoke::tcb_resume(child_tcb);
        if err != 0 { alloc.rollback(); reply.label = SALTY_OUT_OF_MEMORY; return; }

        // Commit and record
        let (slot_base, slot_count) = alloc.commit();

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
        p.pgid = PROCTAB[parent_idx].pgid;
        p.slot_base = slot_base;
        p.slot_count = slot_count;
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
        let alloc = &mut *(&raw mut ALLOCATOR);

        let Some(idx) = find_by_badge(badge) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };

        let (name, name_len) = extract_name(msg, 1);

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] EXEC PID="); lb.hex(PROCTAB[idx].pid as u64);
        lb.str(b" -> '");
        lb.bytes(&name[..name_len]);
        lb.str(b"'\n");
        lb.flush(); }

        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = read_boot_info_initrd_size();

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

        // 2. Free old frame slots beyond the fixed objects
        let old_slot_base = PROCTAB[idx].slot_base;
        let old_slot_count = PROCTAB[idx].slot_count as usize;
        let off_fixed = spawn_tx::OFF_FIXED_END;

        if old_slot_count > off_fixed {
            for i in off_fixed..old_slot_count {
                let slot = old_slot_base + i as u64;
                let err = salty::invoke::cnode_revoke(CAP_SELF_CSPACE, slot);
                if err != 0 { salty::invoke::cnode_delete(CAP_SELF_CSPACE, slot); }
            }
            alloc.free_slots(old_slot_base + off_fixed as u64, old_slot_count - off_fixed);
            PROCTAB[idx].slot_count = off_fixed as u16;
        }

        // Free previous exec frame range if present
        if PROCTAB[idx].frame_count > 0 {
            let fb = PROCTAB[idx].frame_base;
            let fc = PROCTAB[idx].frame_count as usize;
            for i in 0..fc {
                let slot = fb + i as u64;
                let err = salty::invoke::cnode_revoke(CAP_SELF_CSPACE, slot);
                if err != 0 { salty::invoke::cnode_delete(CAP_SELF_CSPACE, slot); }
            }
            alloc.free_slots(fb, fc);
            PROCTAB[idx].frame_base = 0;
            PROCTAB[idx].frame_count = 0;
        }

        // 3. Allocate new frame slots
        let estimated_frames = 40; // ELF + rtld + stack + initrd + boot_info + margin
        let (frame_base, frame_count) = match alloc.alloc_slots(estimated_frames) {
            Some(pair) => pair,
            None => {
                puts(b"[PROCMGR] EXEC: frame slot alloc failed\n");
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        };
        let mut next_frame = frame_base;
        let frame_limit = frame_base + frame_count as u64;

        // 4. Load new ELF using alloc callback for frame allocation
        struct ExecFrameCtx {
            alloc: *mut alloc::Allocator,
            next_frame: *mut u64,
            frame_limit: u64,
            error: i32,
        }

        unsafe extern "C" fn exec_alloc_frame(opaque: *mut u8) -> u64 {
            unsafe {
                let ctx = &mut *(opaque as *mut ExecFrameCtx);
                let next = *ctx.next_frame;
                if next >= ctx.frame_limit {
                    ctx.error = salty::SALTY_OUT_OF_MEMORY as i32;
                    return 0;
                }
                let alloc = &mut *ctx.alloc;
                let err = alloc.retype_any(salty::OBJ_FRAME, 0, next);
                if err != 0 {
                    ctx.error = err;
                    return 0;
                }
                *ctx.next_frame = next + 1;
                next
            }
        }

        let mut exec_ctx = ExecFrameCtx {
            alloc: alloc as *mut alloc::Allocator,
            next_frame: &raw mut next_frame,
            frame_limit,
            error: 0,
        };

        let mut loader_ctx = ElfLoaderCtx {
            untyped: 0, self_vspace: CAP_SELF_VSPACE,
            child_vspace: proc_vs, scratch_vaddr: PROCMGR_SCRATCH_VADDR,
            next_frame_slot: 0,
            alloc_frame_slot: Some(exec_alloc_frame),
            alloc_opaque: &raw mut exec_ctx as *mut u8,
            record_page: None, record_opaque: core::ptr::null_mut(),
        };

        let mut elf_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        let err = salty::elf_loader::elf_load(
            elf_entry.data, elf_entry.data_len,
            CHILD_CODE_VADDR, &mut loader_ctx, &raw mut elf_result,
        );
        if err != 0 || exec_ctx.error != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] EXEC: ELF load failed err=");
            lb.hex(if err != 0 { err as u64 } else { exec_ctx.error as u64 });
            lb.str(b"\n"); lb.flush();
            alloc.free_slots(frame_base, frame_count);
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // 4b. Load rtld if dynamic
        let mut rtld_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        if is_dynamic {
            match spawn_tx::load_rtld(elf_entry.data, elf_entry.data_len, initrd, initrd_size, &mut loader_ctx) {
                Some(r) => rtld_result = r,
                None => {
                    alloc.free_slots(frame_base, frame_count);
                    reply.label = SALTY_NOT_FOUND;
                    return;
                }
            }
            if exec_ctx.error != 0 {
                alloc.free_slots(frame_base, frame_count);
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // 5. Set up new stack
        for pg in 0..CHILD_STACK_PAGES {
            if next_frame >= frame_limit {
                puts(b"[PROCMGR] EXEC: stack frame slot overflow\n");
                alloc.free_slots(frame_base, frame_count);
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
            let fr = next_frame;
            next_frame += 1;
            let err = alloc.retype_any(OBJ_FRAME, 0, fr);
            if err != 0 {
                alloc.free_slots(frame_base, frame_count);
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
            let err = salty::invoke::vspace_map(
                proc_vs, fr, CHILD_STACK_VADDR + pg as u64 * 4096,
                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
            );
            if err != 0 {
                alloc.free_slots(frame_base, frame_count);
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }
        let stk_frame = next_frame - 1; // last stack frame for dynamic stack setup

        // 6. Map initrd and boot info for dynamic executables
        if is_dynamic {
            // Map initrd
            let initrd_pages = (initrd_size + 4095) / 4096;
            let mut mapped_device = true;
            for pg in 0..initrd_pages {
                let err = salty::invoke::vspace_map_device(
                    proc_vs, CAP_INITRD_UNTYPED, (pg as u64) * 4096,
                    CHILD_INITRD_VADDR + pg as u64 * 4096, VSPACE_FLAG_USER,
                );
                if err != 0 {
                    for mapped_pg in 0..pg {
                        salty::invoke::vspace_unmap(proc_vs, CHILD_INITRD_VADDR + mapped_pg as u64 * 4096);
                    }
                    mapped_device = false;
                    break;
                }
            }
            if !mapped_device {
                // Copy fallback
                for pg in 0..initrd_pages {
                    if next_frame >= frame_limit {
                        alloc.free_slots(frame_base, frame_count);
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                    let fr = next_frame;
                    next_frame += 1;
                    let err = alloc.retype_any(OBJ_FRAME, 0, fr);
                    if err != 0 {
                        alloc.free_slots(frame_base, frame_count);
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                    let err = salty::invoke::vspace_map(CAP_SELF_VSPACE, fr, PROCMGR_SCRATCH_VADDR, VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
                    if err != 0 {
                        alloc.free_slots(frame_base, frame_count);
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                    let scratch = PROCMGR_SCRATCH_VADDR as *mut u8;
                    let src = initrd.add(pg * 4096);
                    let mut copy_len = 4096usize;
                    if pg * 4096 + copy_len > initrd_size { copy_len = initrd_size - pg * 4096; }
                    for i in 0..copy_len { core::ptr::write_volatile(scratch.add(i), *src.add(i)); }
                    for i in copy_len..4096 { core::ptr::write_volatile(scratch.add(i), 0); }
                    salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
                    let err = salty::invoke::vspace_map(proc_vs, fr, CHILD_INITRD_VADDR + pg as u64 * 4096, VSPACE_FLAG_USER);
                    if err != 0 {
                        alloc.free_slots(frame_base, frame_count);
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                }
            }

            // Map boot info
            if next_frame >= frame_limit {
                alloc.free_slots(frame_base, frame_count);
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
            let bi_fr = next_frame;
            let err = alloc.retype_any(OBJ_FRAME, 0, bi_fr);
            if err != 0 {
                alloc.free_slots(frame_base, frame_count);
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
            let err = salty::invoke::vspace_map(CAP_SELF_VSPACE, bi_fr, PROCMGR_SCRATCH_VADDR, VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
            if err != 0 {
                alloc.free_slots(frame_base, frame_count);
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
            let bi_src = BOOTINFO_VADDR as *const u8;
            let scratch = PROCMGR_SCRATCH_VADDR as *mut u8;
            for i in 0..4096usize { core::ptr::write_volatile(scratch.add(i), core::ptr::read_volatile(bi_src.add(i))); }
            salty::invoke::vspace_unmap(CAP_SELF_VSPACE, PROCMGR_SCRATCH_VADDR);
            let err = salty::invoke::vspace_map(proc_vs, bi_fr, BOOTINFO_VADDR, VSPACE_FLAG_USER);
            if err != 0 {
                alloc.free_slots(frame_base, frame_count);
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // 7. Entry point and dynamic stack
        let mut new_entry = elf_result.entry;
        let mut new_rsp = CHILD_STACK_TOP;

        if is_dynamic {
            match spawn_tx::write_dynamic_stack(
                elf_entry.data, elf_entry.data_len,
                stk_frame, &elf_result, &rtld_result, initrd_size,
            ) {
                Ok(rsp) => { new_rsp = rsp; new_entry = rtld_result.entry; }
                Err(()) => {
                    alloc.free_slots(frame_base, frame_count);
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
        }

        // 8. Suspend and reconfigure
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
            alloc.free_slots(frame_base, frame_count);
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }
        salty::invoke::tcb_set_ipc_buffer(PROCTAB[idx].tcb_cap, CHILD_IPC_BUF_VADDR);

        let err = salty::invoke::tcb_resume(PROCTAB[idx].tcb_cap);
        if err != 0 {
            puts(b"[PROCMGR] EXEC: resume failed\n");
            alloc.free_slots(frame_base, frame_count);
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Record frame range
        PROCTAB[idx].frame_base = frame_base;
        PROCTAB[idx].frame_count = frame_count as u16;

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] EXEC: PID="); lb.hex(PROCTAB[idx].pid as u64);
        lb.str(b" -> entry="); lb.hex(new_entry); lb.str(b"\n"); lb.flush(); }

        // Don't reply -- process image replaced and resumed.
    }
}

// ===========================================================================
// Process group and UID/GID handlers
// ===========================================================================

unsafe fn handle_setpgid(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;
        let mut pgid = msg.regs[1] as u32;

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };
        let caller_pid = PROCTAB[caller_idx].pid;

        // pid=0 means self
        if target_pid == 0 {
            target_pid = caller_pid;
        }
        // pgid=0 means pgid=pid
        if pgid == 0 {
            pgid = target_pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };

        PROCTAB[ti].pgid = pgid;
        reply.label = SALTY_OK;
        reply.length = 0;
    }
}

unsafe fn handle_getpgid(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let mut target_pid = msg.regs[0] as u32;

        if target_pid == 0 {
            let Some(caller_idx) = find_by_badge(badge) else {
                reply.label = SALTY_NOT_FOUND;
                return;
            };
            target_pid = PROCTAB[caller_idx].pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };

        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = PROCTAB[ti].pgid as u64;
    }
}

unsafe fn handle_setsid(reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let Some(idx) = find_by_badge(badge) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };
        let pid = PROCTAB[idx].pid;
        PROCTAB[idx].pgid = pid;
        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = pid as u64;
    }
}

unsafe fn handle_getuid(reply: &mut SaltyMsg, _badge: u64) {
    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

unsafe fn handle_geteuid(reply: &mut SaltyMsg, _badge: u64) {
    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

unsafe fn handle_getgid(reply: &mut SaltyMsg, _badge: u64) {
    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

unsafe fn handle_getegid(reply: &mut SaltyMsg, _badge: u64) {
    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

unsafe fn handle_getgroups(reply: &mut SaltyMsg) {
    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = 0;
}

// ===========================================================================
// CSpace expansion
// ===========================================================================

/// Handle EXPAND_CSPACE request from a child process.
///
/// The child requests more capability slots. We retype a new sub-CNode from
/// the child's untyped, set a guard on it, and insert it into an empty root
/// CNode slot so the child's address space grows.
///
/// msg.regs[0] = requested size_bits for the new sub-CNode (4..16)
///
/// reply.regs[0] = base address of the new slot range (on success)
/// reply.regs[1] = number of new slots (on success)
unsafe fn handle_expand_cspace(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    let ci = match find_by_badge(badge) {
        Some(i) => i,
        None => { reply.label = SALTY_NOT_FOUND; return; }
    };

    let child_cn = unsafe { PROCTAB[ci].cnode_cap };

    // Requested sub-CNode size_bits (default to 10 = 1024 slots if 0)
    let req_bits = msg.regs[0];
    let size_bits = if req_bits == 0 { 10u64 } else { req_bits };
    if size_bits < 4 || size_bits > 16 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return;
    }

    // Use cnode_get_info to know the root CNode size.
    let info = salty::invoke::cnode_get_info(child_cn);
    if info.error != 0 {
        reply.label = SALTY_INVALID_OPERATION;
        return;
    }
    let (root_num_slots, root_size_bits) = unsafe {
        let ctx = &*ipc_ctx();
        let buf = &*ctx.ipc_buffer;
        (buf.msg[3], buf.msg[2])
    };

    // Find an empty root slot (scan from slot 64 upward, leaving low slots
    // for well-known caps). We attempt retype directly — if the kernel
    // returns SlotOccupied, we try the next slot.
    let mut target_slot: u64 = u64::MAX;
    for slot in 64..root_num_slots {
        target_slot = slot;
        break;
    }

    if target_slot == u64::MAX {
        reply.label = SALTY_OUT_OF_MEMORY;
        return;
    }

    // Retype a new CNode from this child's dedicated untyped into a
    // procmgr-local temp slot.
    let proc_slot_base = unsafe { PROCTAB[ci].slot_base };
    let child_ut = if proc_slot_base != 0 { proc_slot_base + 7 } else { 0 };
    if child_ut == 0 {
        reply.label = SALTY_INVALID_OPERATION;
        return;
    }
    let temp_slot = match unsafe { (&mut *(&raw mut ALLOCATOR)).alloc_single_slot() } {
        Some(s) => s,
        None => { reply.label = SALTY_OUT_OF_MEMORY; return; }
    };

    let err = salty::invoke::untyped_retype(child_ut, OBJ_CNODE, size_bits, temp_slot);
    if err != 0 {
        unsafe { (&mut *(&raw mut ALLOCATOR)).free_single_slot(temp_slot) };
        reply.label = SALTY_OUT_OF_MEMORY;
        return;
    }

    // Set guard on the new sub-CNode so its address range starts at
    // target_slot << size_bits within the address space.
    let guard_val = target_slot;
    let guard_bits = root_size_bits;
    let err = salty::invoke::cnode_set_guard(temp_slot, guard_val, guard_bits);
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] set_guard failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
        salty::invoke::cnode_delete(CAP_SELF_CSPACE, temp_slot);
        unsafe { (&mut *(&raw mut ALLOCATOR)).free_single_slot(temp_slot) };
        reply.label = SALTY_INVALID_OPERATION;
        return;
    }

    // Copy the sub-CNode cap into the child's root CNode at target_slot.
    let err = salty::invoke::cnode_copy(
        CAP_SELF_CSPACE,
        temp_slot,
        child_cn,
        target_slot,
        CAP_RIGHTS_ALL,
    );
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] expand copy failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
        salty::invoke::cnode_delete(CAP_SELF_CSPACE, temp_slot);
        unsafe { (&mut *(&raw mut ALLOCATOR)).free_single_slot(temp_slot) };
        reply.label = SALTY_OUT_OF_MEMORY;
        return;
    }

    // Clean up temp slot
    salty::invoke::cnode_delete(CAP_SELF_CSPACE, temp_slot);
    unsafe { (&mut *(&raw mut ALLOCATOR)).free_single_slot(temp_slot) };

    let new_slots = 1u64 << size_bits;
    let base_addr = target_slot << size_bits;

    reply.label = SALTY_OK;
    reply.length = 2;
    reply.regs[0] = base_addr;
    reply.regs[1] = new_slots;
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

        // Initialize the centralized allocator
        (*(&raw mut ALLOCATOR)).init(
            CAP_SELF_CSPACE,
            CAP_UNTYPED,
            CHILD_UT_BITS_DEFAULT,
            CAP_UNTYPED_START,
            UT_MIRROR_COUNT as usize,
        );

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
        signal_ready();

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
                PM_SPAWN => spawn_tx::handle_spawn_tx(&msg, &mut reply, badge, &mut *(&raw mut ALLOCATOR)),
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
                PM_GETUID => handle_getuid(&mut reply, badge),
                PM_GETGID => handle_getgid(&mut reply, badge),
                PM_SETPGID => handle_setpgid(&msg, &mut reply, badge),
                PM_GETPGID => handle_getpgid(&msg, &mut reply, badge),
                PM_SETSID => handle_setsid(&mut reply, badge),
                PM_GETEUID => handle_geteuid(&mut reply, badge),
                PM_GETEGID => handle_getegid(&mut reply, badge),
                PM_GETGROUPS => handle_getgroups(&mut reply),
                PM_EXPAND_CSPACE => handle_expand_cspace(&msg, &mut reply, badge),
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
