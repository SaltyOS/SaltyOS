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
const CAP_NAMESERV_EP: Cap = 64;   // NeedEP nameserv:64
const CAP_VFS_EP: Cap = 65;        // NeedEP vfs:65
const CAP_FB_UNTYPED: Cap = 66;    // CopyCap 13:66
const CAP_INITRD_UNTYPED: Cap = 12;
const CAP_RECV_SCRATCH: Cap = 15;  // Scratch slot for receiving transferred caps
const CAP_UNTYPED_START: Cap = 16;

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
const PM_GETUID: u64 = 10;
const PM_GETGID: u64 = 11;
const PM_SETPGID: u64 = 12;
const PM_GETPGID: u64 = 13;
const PM_SETSID: u64 = 14;
const PM_GETEUID: u64 = 15;
const PM_GETEGID: u64 = 16;
const PM_GETGROUPS: u64 = 17;
const PM_EXPAND_CSPACE: u64 = 18;
const PM_EXPAND_CSPACE_ASYNC: u64 = 19;
const PM_EXPAND_COLLECT: u64 = 20;
const PM_REGISTER: u64 = 21;
const PM_GETSID: u64 = 22;
const PM_GETPGID_BADGE: u64 = 23;
const PM_GETSID_BADGE: u64 = 24;
const PM_KILL_PGID: u64 = 25;
const PM_INJECT_CAP: u64 = 26;
const SALTY_PENDING: u64 = 0x80;

const PM_SIGKILL: usize = 9;
const PM_SIGCHLD: usize = 17;
const PM_SIGCONT: usize = 18;
const PM_SIGSTOP: usize = 19;

use salty::layout::{self, VmLayoutPlan};

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
const CHILD_CAP_SERVICE_EP: u64 = 68; // Pre-created service EP
const CHILD_CAP_READINESS_NTFN: u64 = salty::CAP_READINESS_NTFN;
const CHILD_UT_BITS_DEFAULT: u8 = 16;
const CHILD_UT_BITS_MIN: u8 = 12;
const READY_SIGNAL_BITS: u64 = 1;
const READY_TIMEOUT_NS_DEFAULT: u64 = 10_000_000_000; // 10s
const READY_WAIT_YIELDS_FALLBACK: usize = 200_000;

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
const AT_SALTY_SHARED_LIB_BASE: u64 = 0x1006;
const AT_SALTY_SLOT_BASE: u64 = 0x1007;
const AT_SALTY_SLOT_COUNT: u64 = 0x1008;
const AT_SALTY_EXPAND_EP: u64 = 0x1009;

// ---- x86_64 page-table bits ----
const X86_PTE_WRITABLE: u64 = 1 << 1;
const X86_PTE_COW: u64 = 1 << 9;
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
const INITRD_COPY_RIGHTS: u64 = (1 << 0) | (1 << 2) | (1 << 3);
const UT_MIRROR_COUNT: Cap = 8;
const INITRD_VADDR: u64 = salty::INITRD_VADDR;
const BOOTINFO_VADDR: u64 = salty::BOOTINFO_VADDR;
const BOOTINFO_MAGIC: u64 = salty::BOOTINFO_MAGIC;

// ---- UT expansion via bound notification ----
const UT_EXPAND_BASE: u64 = salty::consts::UT_EXPAND_BASE;
const MAX_UT_EXPANSIONS: usize = salty::consts::MAX_UT_EXPANSIONS;
const UT_EXPAND_BITS: u64 = 20; // 1MB per expansion untyped
const CHILD_CAP_EXPAND_NTFN: u64 = 9; // Minted notification for UT expansion signaling

/// Procmgr's bound notification cap (for receiving UT expansion signals).
static mut PM_BOUND_NTFN: Cap = 0;
static mut PM_TRACE_BADGE: u64 = 0;
static mut PM_TRACE_BUDGET: u32 = 256;
static mut PM_WAIT_TRACE_BUDGET: u32 = 128;
static mut PM_INJECT_DEBUG_BUDGET: u32 = 32;

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

fn strip_elf_suffix(name: &mut [u8], mut len: usize) -> usize {
    if len >= 4
        && name[len - 4] == b'.'
        && name[len - 3] == b'e'
        && name[len - 2] == b'l'
        && name[len - 1] == b'f'
    {
        len -= 4;
    }
    len
}

fn path_basename(path: &[u8]) -> &[u8] {
    let mut i = path.len();
    while i > 0 {
        if path[i - 1] == b'/' {
            return &path[i..];
        }
        i -= 1;
    }
    path
}

/// Respawn a process by crafting a synthetic POSIX_PM_SPAWN message.
/// Called from handle_exit when the process has the respawn flag set.
unsafe fn respawn_process(binary: &[u8; MAX_NAME_LEN]) {
    unsafe {
        let mut name_len = 0usize;
        while name_len < MAX_NAME_LEN && binary[name_len] != 0 {
            name_len += 1;
        }
        if name_len == 0 {
            return;
        }

        let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] Respawning: ");
        lb.bytes(&binary[..name_len]);
        lb.str(b"\n");
        lb.flush();

        // Build synthetic spawn message
        let mut msg = SaltyMsg::zeroed();
        msg.label = PM_SPAWN;
        let packed_name_words = (name_len as u64 + 7) / 8;
        msg.regs[0] = name_len as u64;
        // policy: SPAWN_READY_IMMEDIATE, no initrd, no display, default cnode
        msg.regs[1] = salty::SPAWN_READY_IMMEDIATE;
        msg.regs[2] = 0; // timeout
        msg.regs[3] = salty::SPAWN_FLAG_RESPAWN; // preserve respawn flag
        msg.regs[4] = 0; // no spawn args
        msg.length = 5 + packed_name_words;

        let dst = &raw mut msg.regs[5] as *mut u8;
        for i in 0..name_len {
            *dst.add(i) = binary[i];
        }

        let mut reply = SaltyMsg::zeroed();
        let alloc = &mut *(&raw mut ALLOCATOR);
        spawn_tx::handle_spawn_tx(&msg, &mut reply, 0, alloc);

        if reply.label == SALTY_OK {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] Respawned PID=");
            lb.hex(reply.regs[0]);
            lb.str(b"\n");
            lb.flush();
        } else {
            // Retry once after a short delay
            salty::serial::serial_puts(b"[PROCMGR] Respawn failed, retrying...\n");
            salty::syscall::syscall(salty::SYS_NANOSLEEP, 100_000_000, 0, 0, 0, 0, 0);
            let mut reply2 = SaltyMsg::zeroed();
            spawn_tx::handle_spawn_tx(&msg, &mut reply2, 0, alloc);
            if reply2.label != SALTY_OK {
                salty::serial::serial_puts(b"[PROCMGR] Respawn retry failed\n");
            }
        }
    }
}

/// Extract process path/name from message regs and normalize by stripping
/// an optional trailing ".elf" suffix.
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

    name_len = strip_elf_suffix(&mut name, name_len);
    name[name_len] = 0;
    (name, name_len)
}

unsafe fn wait_for_child_ready(
    child_tcb: Cap,
    ready_ntfn: Cap,
    child_name: &[u8],
    timeout_ns: u64,
) -> i32 {
    let start_ns = {
        let now = salty::syscall::syscall(salty::SYS_CLOCK_GETTIME, 1, 0, 0, 0, 0, 0);
        if now.error == 0 { Some(now.value) } else { None }
    };
    let mut yields: usize = 0;

    loop {
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

        let timed_out = if let Some(start) = start_ns {
            let now = salty::syscall::syscall(salty::SYS_CLOCK_GETTIME, 1, 0, 0, 0, 0, 0);
            if now.error == 0 {
                now.value.saturating_sub(start) >= timeout_ns
            } else {
                yields >= READY_WAIT_YIELDS_FALLBACK
            }
        } else {
            yields >= READY_WAIT_YIELDS_FALLBACK
        };
        if timed_out {
            break;
        }

        let _ = salty::syscall::syscall(salty::SYS_YIELD, 0, 0, 0, 0, 0, 0);
        yields += 1;
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

        // Ensure VFS tears down all per-client fd state/refcounts for this badge.
        // Use non-blocking send so PM_EXIT path cannot wedge waiting for VFS reply.
        let mut vfs_msg = SaltyMsg::zeroed();
        vfs_msg.label = salty::consts::POSIX_VFS_CLIENT_EXIT;
        vfs_msg.length = 1;
        vfs_msg.regs[0] = badge;
        let mut vfs_err = 0i32;
        let mut vfs_sent = false;
        for _ in 0..16 {
            vfs_err = ipc::nbsend_ctx(ipc_ctx(), CAP_VFS_EP, &raw const vfs_msg);
            if vfs_err == 0 {
                vfs_sent = true;
                break;
            }
            salty::syscall::syscall(salty::SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
        if !vfs_sent {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] EXIT: VFS client-exit sync failed err=");
            lb.hex(vfs_err as u64);
            lb.str(b" badge=");
            lb.hex(badge);
            lb.str(b"\n");
            lb.flush();
        }

        PROCTAB[idx].state = PROC_ZOMBIE;
        PROCTAB[idx].exit_code = exit_code;

        // Save respawn info before cleanup clears it
        let should_respawn = PROCTAB[idx].respawn;
        let mut saved_binary = [0u8; MAX_NAME_LEN];
        if should_respawn {
            saved_binary = PROCTAB[idx].respawn_binary;
        }

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
            if should_respawn {
                respawn_process(&saved_binary);
            }
            return;
        }

        // Wake any-child waiter on parent
        let mut reaped = false;
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
                reaped = true;
            }
        }

        // Respawnable process with no waiter: reap immediately and respawn
        if !reaped && should_respawn {
            free_proc_alloc_slots(idx);
            cleanup_proc_resources(idx, CAP_SELF_CSPACE);
            reaped = true;
        }

        if reaped && should_respawn {
            respawn_process(&saved_binary);
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
            let mut child_count: u32 = 0;

            for i in 0..MAX_PROCESSES {
                if PROCTAB[i].state != PROC_FREE && PROCTAB[i].ppid == caller_pid {
                    child_count += 1;
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
            if PM_TRACE_BADGE != 0 && badge == PM_TRACE_BADGE && PM_WAIT_TRACE_BUDGET > 0 {
                PM_WAIT_TRACE_BUDGET -= 1;
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR][WAIT] opt=");
                lb.hex(options as u64);
                lb.str(b" caller_pid=");
                lb.hex(caller_pid as u64);
                lb.str(b" children=");
                lb.dec(child_count as u64);
                lb.str(b" living=");
                lb.dec(has_living as u64);
                lb.str(b" zombie=");
                lb.dec(zombie_idx.is_some() as u64);
                lb.str(b" stopped=");
                lb.dec(stopped_idx.is_some() as u64);
                lb.str(b"\n");
                lb.flush();
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
    unsafe {
        if PM_TRACE_BADGE != 0 && badge == PM_TRACE_BADGE && PM_TRACE_BUDGET > 0 {
            PM_TRACE_BUDGET -= 1;
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR][TRACE] getpid->");
            lb.hex(PROCTAB[idx].pid as u64);
            lb.str(b"\n");
            lb.flush();
        }
    }
    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { PROCTAB[idx].pid as u64 };
}

unsafe fn handle_getppid(reply: &mut SaltyMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = SALTY_NOT_FOUND;
        return;
    };
    unsafe {
        if PM_TRACE_BADGE != 0 && badge == PM_TRACE_BADGE && PM_TRACE_BUDGET > 0 {
            PM_TRACE_BUDGET -= 1;
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR][TRACE] getppid->");
            lb.hex(PROCTAB[idx].ppid as u64);
            lb.str(b"\n");
            lb.flush();
        }
    }
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

unsafe fn handle_kill(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let target_pid = msg.regs[0] as u32;
        let sig = msg.regs[1] as usize;

        if sig == 0 || sig >= NSIG {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let Some(caller_idx) = find_by_badge(badge) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };

        // pid==0: send signal to all processes in caller's process group.
        if target_pid == 0 {
            let caller_pgid = PROCTAB[caller_idx].pgid;
            let mut delivered = false;
            for i in 0..MAX_PROCESSES {
                if PROCTAB[i].state != PROC_FREE && PROCTAB[i].pgid == caller_pgid {
                    delivered |= deliver_signal_to(i, sig);
                }
            }
            if !delivered {
                reply.label = SALTY_NOT_FOUND;
                return;
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

/// POSIX_PM_KILL_PGID: send signal to an explicit process group.
/// Called by ttyd when ISIG chars arrive (e.g., Ctrl-C → SIGINT to fg_pgrp).
/// msg.regs[0] = target_pgid, msg.regs[1] = sig
unsafe fn handle_kill_pgid(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let target_pgid = msg.regs[0] as u32;
        let sig = msg.regs[1] as usize;

        if sig == 0 || sig >= NSIG {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let mut delivered = false;
        for i in 0..MAX_PROCESSES {
            if PROCTAB[i].state != PROC_FREE && PROCTAB[i].pgid == target_pgid {
                delivered |= deliver_signal_to(i, sig);
            }
        }

        if !delivered {
            reply.label = SALTY_NOT_FOUND;
            return;
        }

        reply.label = SALTY_OK;
        reply.length = 0;
    }
}

/// PM_INJECT_CAP: inject a capability into a child's CSpace.
/// Called by init after pm_spawn to deliver NeedEP/CopyCap caps.
///   msg.regs[0] = target PID
///   msg.regs[1] = dst_slot in child's CSpace
///   extra_caps[0] = cap to inject (received at CAP_RECV_SCRATCH)
unsafe fn handle_inject_cap(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        let dst_slot = msg.regs[1];

        let idx = match find_by_pid(pid) {
            Some(i) => i,
            None => {
                reply.label = SALTY_INVALID_ARGUMENT;
                return;
            }
        };

        let child_cn = PROCTAB[idx].cnode_cap;
        if child_cn == 0 {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        if PM_INJECT_DEBUG_BUDGET > 0 {
            let probe = salty::syscall::syscall(salty::SYS_SIGNAL, CAP_RECV_SCRATCH, 0, 0, 0, 0, 0);
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR][INJECT] pid=");
            lb.hex(pid as u64);
            lb.str(b" dst=");
            lb.hex(dst_slot);
            lb.str(b" probe_sig_err=");
            lb.hex(probe.error);
            lb.str(b"\n");
            lb.flush();
            PM_INJECT_DEBUG_BUDGET -= 1;
        }

        // Cap was received at CAP_RECV_SCRATCH via IPC cap transfer.
        // Move it into the child slot so the scratch slot is freed for the
        // next injected cap in the same boot sequence.
        let err = salty::invoke::cnode_move(
            child_cn, dst_slot,
            CAP_SELF_CSPACE, CAP_RECV_SCRATCH,
        );
        if PM_INJECT_DEBUG_BUDGET > 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR][INJECT] copy_err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            PM_INJECT_DEBUG_BUDGET -= 1;
        }
        reply.label = if err == 0 { SALTY_OK } else { SALTY_INVALID_OPERATION };
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

        let parent_shared_base = PROCTAB[parent_idx].shared_lib_base;
        let parent_lib_map = PROCTAB[parent_idx].lib_map;
        let parent_layout = PROCTAB[parent_idx].layout;
        let initrd_size = read_boot_info_initrd_size() as u64;
        let mut initrd_phys_base = 0u64;
        let mut initrd_phys_end = 0u64;
        if initrd_size != 0 && parent_layout.initrd.size > 0 {
            let err = salty::invoke::vspace_walk(parent_vs, parent_layout.initrd.base, 1);
            if err == 0 {
                let ipc = IPC_BUF_VADDR as *const u64;
                let count = core::ptr::read_volatile(ipc);
                if count != 0 {
                    let vaddr = core::ptr::read_volatile(ipc.add(2));
                    let phys = core::ptr::read_volatile(ipc.add(3));
                    if vaddr == parent_layout.initrd.base {
                        initrd_phys_base = phys;
                        initrd_phys_end = phys + ((initrd_size + 0xFFF) & !0xFFF);
                    }
                }
            }
        }

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] FORK from PID="); lb.hex(parent_pid as u64); lb.str(b"\n"); lb.flush(); }

        let Some(slot_idx) = alloc_proc() else {
            puts(b"[PROCMGR] FORK: process table full\n");
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        };

        let child_pid = NEXT_PID;
        NEXT_PID += 1;

        // Count parent pages as an upper bound for reservation sizing
        // (skip IPC buf, initrd window pages, and shared lib RO cache pages).
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
                    if page_vaddr == parent_layout.ipc_buf.base { continue; }
                    if parent_layout.initrd.size > 0 && page_vaddr >= parent_layout.initrd.base { continue; }
                    if spawn_tx::lookup_shared_lib_page(page_vaddr, &parent_lib_map).is_some() { continue; }
                    page_count += 1;
                }
                if next_addr == 0 { break; }
                walk_start = next_addr;
            }
        }

        // Reserve with a generous upper bound (fixed objects + page budget + margin).
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
                let page_phys = core::ptr::read_volatile(ipc.add(2 + i * 3 + 1));
                let page_flags = core::ptr::read_volatile(ipc.add(2 + i * 3 + 2));
                if page_vaddr == parent_layout.ipc_buf.base { continue; }

                // Skip initrd window pages — child doesn't need them after fork
                if parent_layout.initrd.size > 0 && page_vaddr >= parent_layout.initrd.base { continue; }

                // Share cached lib RO pages instead of copying
                if let Some((cached_cap, cached_flags)) =
                    spawn_tx::lookup_shared_lib_page(page_vaddr, &parent_lib_map)
                {
                    let err = salty::invoke::vspace_map(child_vs, cached_cap, page_vaddr, cached_flags);
                    if err != 0 {
                        let mut lb = LineBuf::new();
                        lb.str(b"[PROCMGR] FORK: shared lib map failed at "); lb.hex(page_vaddr);
                        lb.str(b" err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
                        alloc.rollback();
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                    total_pages += 1;
                    continue;
                }

                // Preserve initrd-backed immutable pages as device mappings.
                if initrd_phys_end > initrd_phys_base
                    && (page_flags & X86_PTE_WRITABLE) == 0
                    && page_phys >= initrd_phys_base
                    && page_phys < initrd_phys_end
                {
                    let mut map_flags = VSPACE_FLAG_USER;
                    if page_flags & X86_PTE_NX == 0 { map_flags |= VSPACE_FLAG_EXECUTABLE; }
                    let dev_off = page_phys - initrd_phys_base;
                    let derr = salty::invoke::vspace_map_device(
                        child_vs,
                        CAP_INITRD_UNTYPED,
                        dev_off,
                        page_vaddr,
                        map_flags,
                    );
                    if derr == 0 {
                        total_pages += 1;
                        continue;
                    }
                }

                // Policy: keep fork on eager copy path for now.
                // COW path currently reproduces child-start corruption at RIP=0x3484ac
                // under interactive shell exec workloads.

                let copied_frame = match alloc.realize_object(OBJ_FRAME, 0) {
                    Ok(s) => s,
                    Err(_) => {
                        puts(b"[PROCMGR] FORK: frame retype failed\n");
                        alloc.rollback();
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return;
                    }
                };

                let err = salty::invoke::vspace_copy_page(parent_vs, page_vaddr, copied_frame);
                if err != 0 {
                    let mut lb = LineBuf::new();
                    lb.str(b"[PROCMGR] FORK: copy_page failed at "); lb.hex(page_vaddr);
                    lb.str(b" err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
                    alloc.rollback();
                    reply.label = SALTY_INVALID_OPERATION;
                    return;
                }

                let mut map_flags = VSPACE_FLAG_USER;
                if page_flags & X86_PTE_WRITABLE != 0 || page_flags & X86_PTE_COW != 0 {
                    map_flags |= VSPACE_FLAG_WRITABLE;
                }
                if page_flags & X86_PTE_NX == 0 { map_flags |= VSPACE_FLAG_EXECUTABLE; }

                let err = salty::invoke::vspace_map(child_vs, copied_frame, page_vaddr, map_flags);
                if err != 0 {
                    let mut lb = LineBuf::new();
                    lb.str(b"[PROCMGR] FORK: child map failed at "); lb.hex(page_vaddr);
                    lb.str(b" err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
                    alloc.rollback();
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }

                if page_vaddr == rsp_page_vaddr { rsp_frame = copied_frame; }
                total_pages += 1;
            }

            if next_addr == 0 { break; }
            walk_start = next_addr;
        }

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] FORK: mapped "); lb.hex(total_pages); lb.str(b" pages\n"); lb.flush(); }

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
            child_vs, child_ipc_fr, parent_layout.ipc_buf.base,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            puts(b"[PROCMGR] FORK: IPC buf map failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // Child untyped with downshift.
        // Allocate this after page-copy work so fork can prioritize frames.
        let child_ut_slot = {
            let mut bits = CHILD_UT_BITS_DEFAULT;
            let mut result: Option<Cap> = None;
            let mut selected_bits: u8 = 0;
            while bits >= CHILD_UT_BITS_MIN {
                match alloc.realize_object(OBJ_UNTYPED, bits as u64) {
                    Ok(s) => {
                        result = Some(s);
                        selected_bits = bits;
                        break;
                    }
                    Err(_) => {
                        bits -= 1;
                    }
                }
            }
            match result {
                Some(s) => {
                    let mut lb = LineBuf::new();
                    lb.str(b"[PROCMGR] FORK: child untyped bits=2^");
                    lb.hex(selected_bits as u64);
                    lb.str(b"\n");
                    lb.flush();
                    s
                }
                None => {
                    puts(b"[PROCMGR] FORK: child untyped unavailable\n");
                    alloc.rollback();
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
        };

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
        // Keep fork child cap layout aligned with spawn path so rtld/slot alloc
        // can use initrd device mapping and mirrored untyped sources.
        let _ = salty::invoke::cnode_copy(
            CAP_SELF_CSPACE,
            CAP_INITRD_UNTYPED,
            child_cn,
            CAP_INITRD_UNTYPED,
            INITRD_COPY_RIGHTS,
        );
        for ut_slot in CAP_UNTYPED_START..(CAP_UNTYPED_START + UT_MIRROR_COUNT) {
            let _ = salty::invoke::cnode_copy(
                CAP_SELF_CSPACE,
                ut_slot,
                child_cn,
                ut_slot,
                CAP_RIGHTS_ALL,
            );
        }

        // Mint UT expansion notification into child CNode
        let pm_ntfn = *(&raw const PM_BOUND_NTFN);
        if pm_ntfn != 0 {
            let ntfn_badge = 1u64 << slot_idx;
            let _ = salty::invoke::cnode_mint(
                CAP_SELF_CSPACE, pm_ntfn,
                child_cn, CHILD_CAP_EXPAND_NTFN,
                ntfn_badge,
            );
        }

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
        let err = salty::invoke::tcb_set_ipc_buffer(child_tcb, parent_layout.ipc_buf.base);
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
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] FORK: VFS clone_fds failed err=");
                lb.hex(err as u64);
                lb.str(b" reply=");
                lb.hex(clone_reply.label);
                lb.str(b", aborting fork\n");
                lb.flush();
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
        p.sid = PROCTAB[parent_idx].sid;
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
        p.shared_lib_base = PROCTAB[parent_idx].shared_lib_base;
        p.lib_map = parent_lib_map;
        p.layout = parent_layout;
        p.child_ut_cap = child_ut_slot;
        p.ut_expand_count = 0;
        p.has_service_ep = PROCTAB[parent_idx].has_service_ep;
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

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] EXEC PID="); lb.hex(PROCTAB[idx].pid as u64);
        lb.str(b" -> '");
        lb.bytes(&name[..name_len]);
        lb.str(b"' argc="); lb.hex(argc as u64);
        lb.str(b" envc="); lb.hex(envc as u64);
        lb.str(b"\n");
        lb.flush(); }
        if bytes_eq(path_basename(&name[..name_len]), b"bash") {
            PM_TRACE_BADGE = badge;
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] tracing badge=");
            lb.hex(badge);
            lb.str(b" (bash)\n");
            lb.flush();

            // Dump argv/envp as parsed from exec payload to verify shell mode.
            let mut pos = 0usize;
            for ai in 0..argc {
                if pos >= exec_str_len {
                    break;
                }
                let start = pos;
                while pos < exec_str_len && exec_str_data[pos] != 0 {
                    pos += 1;
                }
                let mut ab = LineBuf::new();
                ab.str(b"[PROCMGR][BASH_ARG] i=");
                ab.dec(ai as u64);
                ab.str(b" v='");
                ab.bytes(&exec_str_data[start..pos]);
                ab.str(b"'\n");
                ab.flush();
                if pos < exec_str_len {
                    pos += 1;
                }
            }
            for ei in 0..envc {
                if pos >= exec_str_len {
                    break;
                }
                let start = pos;
                while pos < exec_str_len && exec_str_data[pos] != 0 {
                    pos += 1;
                }
                let mut eb = LineBuf::new();
                eb.str(b"[PROCMGR][BASH_ENV] i=");
                eb.dec(ei as u64);
                eb.str(b" v='");
                eb.bytes(&exec_str_data[start..pos]);
                eb.str(b"'\n");
                eb.flush();
                if pos < exec_str_len {
                    pos += 1;
                }
            }
        }

        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = read_boot_info_initrd_size();

        let mut elf_entry = CpioEntry::zeroed();

        let mut found = salty::cpio::cpio_find_file(
            initrd, initrd_size, name.as_ptr(), name_len, &raw mut elf_entry,
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
                if page_vaddr == PROCTAB[idx].layout.ipc_buf.base { continue; }
                salty::invoke::vspace_unmap(proc_vs, page_vaddr);
            }

            if next_addr == 0 { break; }
            walk_start = next_addr;
        }

        // 2a. Clean old RTLD/dynamic slots from child CSpace to prevent slot collision
        {
            let child_cn = PROCTAB[idx].cnode_cap;
            let frame_floor = if PROCTAB[idx].has_service_ep {
                CHILD_CAP_SERVICE_EP + 1
            } else {
                CHILD_RTLD_FRAME_SLOT_START
            };
            // Query CNode size for upper bound
            let mut cnode_bits: u64 = 10;
            let cinfo = salty::invoke::cnode_get_info(child_cn);
            if cinfo.error == 0 {
                let ctx = &*ipc_ctx();
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

        // 3. Compute layout and allocate new frame slots based on actual ELF page counts
        let elf_pages = unsafe {
            salty::elf_loader::elf_count_load_pages(elf_entry.data, elf_entry.data_len)
        };
        let elf_span = unsafe {
            salty::elf_loader::elf_compute_load_span(elf_entry.data, elf_entry.data_len)
        };
        let rtld_pages = if is_dynamic {
            unsafe { spawn_tx::count_rtld_pages_for_exec(
                elf_entry.data, elf_entry.data_len, initrd, initrd_size,
            ) }
        } else {
            0
        };
        let rtld_span = if is_dynamic {
            unsafe { spawn_tx::count_rtld_span_for_exec(
                elf_entry.data, elf_entry.data_len, initrd, initrd_size,
            ) }
        } else {
            0
        };
        // Parse DT_NEEDED for selective shared lib mapping
        let needed = if is_dynamic {
            unsafe { salty::elf_dynamic::elf_get_needed(elf_entry.data, elf_entry.data_len) }
        } else {
            salty::elf_dynamic::NeededLibs::new()
        };
        let shared_lib_cache_pages = spawn_tx::shared_lib_va_pages_for_needed(&needed);
        let layout = layout::compute_vm_layout(
            elf_span,
            rtld_span,
            shared_lib_cache_pages,
            is_dynamic,
            initrd_size,
        );
        if layout.stack_top == 0 {
            puts(b"[PROCMGR] EXEC: ELF too large for VA layout\n");
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }
        let estimated_frames = elf_pages + rtld_pages + layout.stack.page_count() + 6;
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
            layout.elf_code.base, &mut loader_ctx, &raw mut elf_result,
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
            match spawn_tx::load_rtld(elf_entry.data, elf_entry.data_len, initrd, initrd_size, &mut loader_ctx, layout.rtld.base) {
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
        let stack_pages = layout.stack.page_count();
        for pg in 0..stack_pages {
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
                proc_vs, fr, layout.stack.base + pg as u64 * 4096,
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
                    layout.initrd.base + pg as u64 * 4096, VSPACE_FLAG_USER,
                );
                if err != 0 {
                    for mapped_pg in 0..pg {
                        salty::invoke::vspace_unmap(proc_vs, layout.initrd.base + mapped_pg as u64 * 4096);
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
                    let err = salty::invoke::vspace_map(proc_vs, fr, layout.initrd.base + pg as u64 * 4096, VSPACE_FLAG_USER);
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

        // 7. Map shared library RO frames if available
        let (shared_lib_base, shared_lib_map) = if is_dynamic {
            unsafe { spawn_tx::map_shared_lib_to_vspace(proc_vs, layout.shared_libs.base, &needed) }
        } else {
            (0, proc_table::ProcLibMap::zeroed())
        };

        // 8. Entry point and dynamic stack
        let mut new_entry = elf_result.entry;
        let mut new_rsp = layout.stack_top;

        if is_dynamic {
            // exec inherits parent CNode; derive actual size_bits from child CNode
            let mut exec_cnode_bits: u64 = 10;
            let cinfo = salty::invoke::cnode_get_info(PROCTAB[idx].cnode_cap);
            if cinfo.error == 0 {
                unsafe {
                    let ctx = &*ipc_ctx();
                    if !ctx.ipc_buffer.is_null() {
                        let buf = &*ctx.ipc_buffer;
                        let bits = buf.msg[2];
                        if bits >= 4 && bits <= 16 {
                            exec_cnode_bits = bits;
                        }
                    }
                }
            }
            match spawn_tx::write_dynamic_stack(
                elf_entry.data, elf_entry.data_len,
                stk_frame, &elf_result, &rtld_result, initrd_size,
                shared_lib_base,
                argc, envc, &exec_str_data, exec_str_len,
                layout.elf_code.base,
                layout.scratch.base,
                layout.initrd.base,
                layout.stack_top,
                exec_cnode_bits,
                if PROCTAB[idx].has_service_ep { CHILD_CAP_SERVICE_EP + 1 } else { CHILD_RTLD_FRAME_SLOT_START },
            ) {
                Ok(rsp) => { new_rsp = rsp; new_entry = rtld_result.entry; }
                Err(()) => {
                    alloc.free_slots(frame_base, frame_count);
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
        } else {
            // Static executable: write argv/envp to the top stack frame
            match spawn_tx::write_static_stack(
                stk_frame,
                argc, envc, &exec_str_data, exec_str_len,
                layout.scratch.base,
                layout.initrd.base,
                layout.stack_top,
            ) {
                Ok(rsp) => { new_rsp = rsp; }
                Err(()) => {
                    alloc.free_slots(frame_base, frame_count);
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
        }

        // 9. Suspend and reconfigure
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
        salty::invoke::tcb_set_ipc_buffer(PROCTAB[idx].tcb_cap, layout.ipc_buf.base);

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
        PROCTAB[idx].shared_lib_base = shared_lib_base;
        PROCTAB[idx].lib_map = shared_lib_map;
        PROCTAB[idx].layout = layout;

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
        let caller_sid = PROCTAB[caller_idx].sid;

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

        if target_pid != caller_pid && PROCTAB[ti].ppid != caller_pid {
            reply.label = SALTY_INVALID_OPERATION;
            return;
        }

        if PROCTAB[ti].sid != caller_sid {
            reply.label = SALTY_INVALID_OPERATION;
            return;
        }

        if PROCTAB[ti].pid == PROCTAB[ti].sid {
            reply.label = SALTY_INVALID_OPERATION;
            return;
        }

        if pgid != target_pid {
            let Some(gi) = find_by_pid(pgid) else {
                reply.label = SALTY_NOT_FOUND;
                return;
            };
            if PROCTAB[gi].sid != PROCTAB[ti].sid {
                reply.label = SALTY_INVALID_OPERATION;
                return;
            }
        }

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
        if PROCTAB[idx].pgid == pid {
            reply.label = SALTY_INVALID_OPERATION;
            return;
        }
        PROCTAB[idx].sid = pid;
        PROCTAB[idx].pgid = pid;
        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = pid as u64;
    }
}

unsafe fn handle_getsid(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
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
        reply.regs[0] = PROCTAB[ti].sid as u64;
    }
}

unsafe fn handle_getpgid_badge(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };

        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = PROCTAB[ti].pgid as u64;
    }
}

unsafe fn handle_getsid_badge(msg: &SaltyMsg, reply: &mut SaltyMsg) {
    unsafe {
        let target_badge = msg.regs[0];
        let Some(ti) = find_by_badge(target_badge) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };

        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = PROCTAB[ti].sid as u64;
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

    // We will probe root slots from 64 upward and attach the new sub-CNode
    // at the first free one.
    let mut target_slot: u64 = u64::MAX;

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

    // Set guard and attempt insertion into each candidate root slot.
    // The first successful copy becomes the new sub-CNode anchor.
    // Sub-CNode gets guard=0, guard_bits=0. The seL4 resolver uses
    // root_bits to index the root CNode, then sub_bits to index the sub-CNode.
    // Address encoding: (root_idx << sub_bits) | sub_idx.
    let err = salty::invoke::cnode_set_guard(temp_slot, 0, 0);
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] set_guard failed err="); lb.hex(err as u64); lb.str(b"\n"); lb.flush();
        salty::invoke::cnode_delete(CAP_SELF_CSPACE, temp_slot);
        unsafe { (&mut *(&raw mut ALLOCATOR)).free_single_slot(temp_slot) };
        reply.label = SALTY_INVALID_OPERATION;
        return;
    }

    for slot in 64..root_num_slots {
        let err = salty::invoke::cnode_copy(
            CAP_SELF_CSPACE,
            temp_slot,
            child_cn,
            slot,
            CAP_RIGHTS_ALL,
        );
        if err == 0 {
            target_slot = slot;
            break;
        }
    }

    if target_slot == u64::MAX {
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
// Async CSpace expansion
// ===========================================================================

/// Handle PM_EXPAND_CSPACE_ASYNC (NBSend): perform the expansion work and
/// store the result. No reply is sent (NBSend has no reply cap).
unsafe fn handle_expand_cspace_async(msg: &SaltyMsg, badge: u64) {
    let ci = match find_by_badge(badge) {
        Some(i) => i,
        None => return, // NBSend: no reply, just drop
    };

    unsafe {
        let child_cn = PROCTAB[ci].cnode_cap;

        let req_bits = msg.regs[0];
        let size_bits = if req_bits == 0 { 10u64 } else { req_bits };
        if size_bits < 4 || size_bits > 16 {
            return;
        }

        let info = salty::invoke::cnode_get_info(child_cn);
        if info.error != 0 {
            return;
        }
        let (root_num_slots, root_size_bits) = {
            let ctx = &*ipc_ctx();
            let buf = &*ctx.ipc_buffer;
            (buf.msg[3], buf.msg[2])
        };

        // Determine child untyped: init-registered uses child_ut_cap,
        // procmgr-spawned uses slot_base + 7
        let proc_slot_base = PROCTAB[ci].slot_base;
        let child_ut = if PROCTAB[ci].child_ut_cap != 0 {
            PROCTAB[ci].child_ut_cap
        } else if proc_slot_base != 0 {
            proc_slot_base + 7
        } else {
            return;
        };

        let temp_slot = match (&mut *(&raw mut ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => return,
        };

        let err = salty::invoke::untyped_retype(child_ut, OBJ_CNODE, size_bits, temp_slot);
        if err != 0 {
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(temp_slot);
            return;
        }

        // Sub-CNode gets guard=0, guard_bits=0 (same as blocking path).
        let err = salty::invoke::cnode_set_guard(temp_slot, 0, 0);
        if err != 0 {
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, temp_slot);
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(temp_slot);
            return;
        }

        let mut target_slot: u64 = u64::MAX;
        for slot in 64..root_num_slots {
            let err = salty::invoke::cnode_copy(
                CAP_SELF_CSPACE, temp_slot,
                child_cn, slot,
                CAP_RIGHTS_ALL,
            );
            if err == 0 {
                target_slot = slot;
                break;
            }
        }

        salty::invoke::cnode_delete(CAP_SELF_CSPACE, temp_slot);
        (&mut *(&raw mut ALLOCATOR)).free_single_slot(temp_slot);

        if target_slot == u64::MAX {
            return;
        }

        let new_slots = 1u64 << size_bits;
        let base_addr = target_slot << size_bits;

        PROCTAB[ci].expand_pending = true;
        PROCTAB[ci].expand_result_base = base_addr;
        PROCTAB[ci].expand_result_count = new_slots;
    }
}

/// Handle PM_EXPAND_COLLECT (Call): return the stored expansion result.
unsafe fn handle_expand_collect(reply: &mut SaltyMsg, badge: u64) {
    let ci = match find_by_badge(badge) {
        Some(i) => i,
        None => { reply.label = SALTY_NOT_FOUND; return; }
    };

    unsafe {
        if PROCTAB[ci].expand_pending {
            reply.label = SALTY_OK;
            reply.length = 2;
            reply.regs[0] = PROCTAB[ci].expand_result_base;
            reply.regs[1] = PROCTAB[ci].expand_result_count;
            PROCTAB[ci].expand_pending = false;
        } else {
            reply.label = SALTY_PENDING;
        }
    }
}

// ===========================================================================
// Notification-based untyped expansion
// ===========================================================================

/// Handle UT expansion requests delivered via bound notification.
///
/// Each bit in `bits` corresponds to a process table index. When a child
/// signals the procmgr's bound notification (minted with badge = 1 << idx),
/// the kernel ORs the badge into the notification word. On delivery, we
/// scan the bits and grant untypeds at deterministic child CNode slots.
unsafe fn handle_ut_expand_notification(bits: u64) {
    unsafe {
        let alloc = &mut *(&raw mut ALLOCATOR);
        for i in 0..MAX_PROCESSES {
            if bits & (1u64 << i) == 0 { continue; }
            if PROCTAB[i].state != PROC_RUNNING { continue; }

            let n = PROCTAB[i].ut_expand_count as u64;
            if n >= MAX_UT_EXPANSIONS as u64 { continue; }

            let child_cn = PROCTAB[i].cnode_cap;
            if child_cn == 0 { continue; }

            let dest_child_slot = UT_EXPAND_BASE + n;

            // Allocate temp slot and retype untyped from procmgr's pool
            let pm_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => continue,
            };

            let mut err = salty::invoke::untyped_retype(
                CAP_UNTYPED, OBJ_UNTYPED, UT_EXPAND_BITS, pm_slot,
            );
            if err != 0 {
                for ut in CAP_UNTYPED_START..CAP_UNTYPED_START + UT_MIRROR_COUNT {
                    err = salty::invoke::untyped_retype(
                        ut, OBJ_UNTYPED, UT_EXPAND_BITS, pm_slot,
                    );
                    if err == 0 { break; }
                }
            }
            if err != 0 {
                alloc.free_single_slot(pm_slot);
                continue;
            }

            // Copy the untyped into child's CNode at the deterministic slot
            let copy_err = salty::invoke::cnode_copy(
                CAP_SELF_CSPACE, pm_slot,
                child_cn, dest_child_slot,
                CAP_RIGHTS_ALL,
            );
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, pm_slot);
            alloc.free_single_slot(pm_slot);

            if copy_err != 0 {
                continue;
            }

            PROCTAB[i].ut_expand_count += 1;

            {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] ut-expand: granted ");
                lb.hex(1u64 << UT_EXPAND_BITS);
                lb.str(b"B untyped to idx=");
                lb.hex(i as u64);
                lb.str(b" slot=");
                lb.hex(dest_child_slot);
                lb.str(b"\n");
                lb.flush();
            }
        }
    }
}

/// Handle PM_REGISTER (Call): register an init-spawned service in the proc table.
/// msg.regs[0] = badge used for this child
/// IPC buffer caps[0] = child's CNode cap (transferred via cap slot)
unsafe fn handle_register(msg: &SaltyMsg, reply: &mut SaltyMsg, _badge: u64) {
    let reg_badge = msg.regs[0];

    unsafe {
        // The CNode cap was transferred to CAP_RECV_SCRATCH by cap transfer
        let child_cn_scratch = CAP_RECV_SCRATCH;

        // Verify we received a cap by probing it
        let cn_info = salty::invoke::cnode_get_info(child_cn_scratch);
        if cn_info.error != 0 {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Move CNode cap from scratch to a permanent allocator-managed slot.
        // Must use cnode_move (not cnode_copy) to avoid creating a CDT child,
        // which would prevent cnode_delete(scratch) from clearing the slot.
        let cn_perm = match (&mut *(&raw mut ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => { reply.label = SALTY_OUT_OF_MEMORY; return; }
        };
        let err = salty::invoke::cnode_move(
            CAP_SELF_CSPACE, cn_perm,
            CAP_SELF_CSPACE, child_cn_scratch,
        );
        if err != 0 {
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(cn_perm);
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let ci = match alloc_proc() {
            Some(i) => i,
            None => {
                salty::invoke::cnode_delete(CAP_SELF_CSPACE, cn_perm);
                (&mut *(&raw mut ALLOCATOR)).free_single_slot(cn_perm);
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        };

        PROCTAB[ci].pid = NEXT_PID;
        NEXT_PID += 1;
        PROCTAB[ci].sid = PROCTAB[ci].pid;
        PROCTAB[ci].pgid = PROCTAB[ci].pid;
        PROCTAB[ci].badge = reg_badge;
        PROCTAB[ci].state = PROC_RUNNING;
        PROCTAB[ci].cnode_cap = cn_perm;

        // Copy child's untyped (slot 7 in child's CNode) into procmgr's CSpace
        if let Some(ut_slot) = (&mut *(&raw mut ALLOCATOR)).alloc_single_slot() {
            let err = salty::invoke::cnode_copy(
                cn_perm, 7,
                CAP_SELF_CSPACE, ut_slot,
                CAP_RIGHTS_ALL,
            );
            if err == 0 {
                PROCTAB[ci].child_ut_cap = ut_slot;
            } else {
                (&mut *(&raw mut ALLOCATOR)).free_single_slot(ut_slot);
            }
        }

        // Mint UT expansion notification into child CNode
        let pm_ntfn = *(&raw const PM_BOUND_NTFN);
        if pm_ntfn != 0 {
            let ntfn_badge = 1u64 << ci;
            let _ = salty::invoke::cnode_mint(
                CAP_SELF_CSPACE, pm_ntfn,
                cn_perm, CHILD_CAP_EXPAND_NTFN,
                ntfn_badge,
            );
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] PM_REGISTER badge=");
            lb.hex(reg_badge);
            lb.str(b" pid=");
            lb.hex(PROCTAB[ci].pid as u64);
            lb.str(b"\n");
            lb.flush();
        }

        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = PROCTAB[ci].pid as u64;
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

        // Initialize the centralized allocator
        (*(&raw mut ALLOCATOR)).init(
            CAP_SELF_CSPACE,
            CAP_UNTYPED,
            CHILD_UT_BITS_DEFAULT,
            CAP_UNTYPED_START,
            UT_MIRROR_COUNT as usize,
        );

        // Pre-load shared library RO pages into frame cache.
        // Must happen before any allocator use — init copies shared lib caps
        // into slots 0x80+, which can overlap SLOT_POOL_BASE (256).
        spawn_tx::init_shared_lib_cache(&mut *(&raw mut ALLOCATOR));

        // Create and bind a notification for UT expansion signaling.
        // Children signal this notification; procmgr detects via bound notification
        // delivery during recv/reply_recv.
        {
            let alloc = &mut *(&raw mut ALLOCATOR);
            let ntfn_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => {
                    puts(b"[PROCMGR] WARN: could not alloc slot for bound ntfn\n");
                    0
                }
            };
            if ntfn_slot != 0 {
                let err = alloc.retype_any(OBJ_NOTIFICATION, 0, ntfn_slot);
                if err != 0 {
                    puts(b"[PROCMGR] WARN: retype notification failed\n");
                    alloc.free_single_slot(ntfn_slot);
                } else {
                    let err = salty::invoke::tcb_bind_notification(CAP_SELF_TCB, ntfn_slot);
                    if err != 0 {
                        puts(b"[PROCMGR] WARN: bind notification failed\n");
                    } else {
                        *(&raw mut PM_BOUND_NTFN) = ntfn_slot;
                        puts(b"[PROCMGR] bound notification ready for UT expansion\n");
                    }
                }
            }
        }

        // Signal ready BEFORE registration — init needs to proceed to spawn nameserv.
        // The registration Call will block in the EP send queue until nameserv starts.
        signal_ready();

        // Register with nameserv — blocks until nameserv Recv()s
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
            ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
            let err = ipc::call_ctx(ipc_ctx(), CAP_NAMESERV_EP, &raw const reg_msg, &raw mut reg_reply);
            if err == 0 && reg_reply.label == SALTY_OK {
                puts(b"[PROCMGR] registered with nameserv\n");
            } else {
                puts(b"[PROCMGR] WARN: nameserv registration failed\n");
            }
        }

        // Initial recv
        let mut msg = SaltyMsg::zeroed();
        let mut badge: u64 = 0;

        salty::invoke::cnode_delete(CAP_SELF_CSPACE, CAP_RECV_SCRATCH);
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_RECV_SCRATCH, 0);

        let err = salty::ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge);
        if err != 0 {
            puts(b"[PROCMGR] initial recv failed\n");
            idle();
        }

        // Server loop
        loop {
            let mut reply = SaltyMsg::zeroed();
            let mut skip_reply = false;
            if PM_TRACE_BADGE != 0 && badge == PM_TRACE_BADGE && msg.label != 0 && PM_TRACE_BUDGET > 0 {
                PM_TRACE_BUDGET -= 1;
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR][TRACE] l=");
                lb.hex(msg.label);
                lb.str(b" b=");
                lb.hex(badge);
                lb.str(b" r0=");
                lb.hex(msg.regs[0]);
                lb.str(b" r1=");
                lb.hex(msg.regs[1]);
                lb.str(b"\n");
                lb.flush();
            }

            // Bound notification delivery: label=0 and badge!=0 means the
            // kernel delivered a notification word instead of an IPC message.
            // Process UT expansion requests encoded as badge bits.
            if msg.label == 0 && badge != 0 {
                handle_ut_expand_notification(badge);
                skip_reply = true;
            } else {

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
                PM_KILL_PGID => handle_kill_pgid(&msg, &mut reply),
                PM_INJECT_CAP => handle_inject_cap(&msg, &mut reply),
                PM_SIGACTION => handle_sigaction(&msg, &mut reply, badge),
                PM_GETUID => handle_getuid(&mut reply, badge),
                PM_GETGID => handle_getgid(&mut reply, badge),
                PM_SETPGID => handle_setpgid(&msg, &mut reply, badge),
                PM_GETPGID => handle_getpgid(&msg, &mut reply, badge),
                PM_SETSID => handle_setsid(&mut reply, badge),
                PM_GETSID => handle_getsid(&msg, &mut reply, badge),
                PM_GETEUID => handle_geteuid(&mut reply, badge),
                PM_GETEGID => handle_getegid(&mut reply, badge),
                PM_GETGROUPS => handle_getgroups(&mut reply),
                PM_EXPAND_CSPACE => handle_expand_cspace(&msg, &mut reply, badge),
                PM_EXPAND_CSPACE_ASYNC => {
                    handle_expand_cspace_async(&msg, badge);
                    skip_reply = true;
                }
                PM_EXPAND_COLLECT => handle_expand_collect(&mut reply, badge),
                PM_REGISTER => handle_register(&msg, &mut reply, badge),
                PM_GETPGID_BADGE => handle_getpgid_badge(&msg, &mut reply),
                PM_GETSID_BADGE => handle_getsid_badge(&msg, &mut reply),
                _ => {
                    let mut lb = LineBuf::new();
                    lb.str(b"[PROCMGR] unknown label="); lb.hex(msg.label); lb.str(b"\n"); lb.flush();
                    reply.label = SALTY_INVALID_OPERATION;
                }
            }

            } // end else (notification vs IPC dispatch)

            salty::invoke::cnode_delete(CAP_SELF_CSPACE, CAP_RECV_SCRATCH);
            ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_RECV_SCRATCH, 0);

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
