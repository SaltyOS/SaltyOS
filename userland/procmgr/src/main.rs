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
    init_proctab, proctab, proctab_cap,
    MAX_NAME_LEN, NEXT_PID, NSIG,
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
const VSPACE_WALK_BATCH: u64 = 48;

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

use salty::layout::{self};

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
const CHILD_CAP_MMSRV_EP: u64 = 7;
const CHILD_CAP_READINESS_NTFN: u64 = 14;
const CHILD_CAP_SERVICE_EP: u64 = 68; // Pre-created service EP
const CAP_READINESS_NTFN: u64 = 14; // Self readiness notification
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
const AT_SALTY_VSPACE: u64 = 0x1001;
const AT_SALTY_SCRATCH: u64 = 0x1002;
const AT_SALTY_INITRD: u64 = 0x1003;
const AT_SALTY_INITRD_SZ: u64 = 0x1004;
const AT_SALTY_FRAME_SLOT: u64 = 0x1005;
const AT_SALTY_SHARED_LIB_BASE: u64 = 0x1006;
const AT_SALTY_SLOT_BASE: u64 = 0x1007;
const AT_SALTY_SLOT_COUNT: u64 = 0x1008;
const AT_SALTY_CSPACE_NTFN: u64 = 0x100A;

// ---- waitpid options ----
const WNOHANG: u32 = 1;
const WUNTRACED: u32 = 2;

// ---- Shorthand re-exports ----
const OBJ_TCB: u64 = salty::OBJ_TCB;
const OBJ_VSPACE: u64 = salty::OBJ_VSPACE;
const OBJ_CNODE: u64 = salty::OBJ_CNODE;
const OBJ_SCHED_CONTEXT: u64 = salty::OBJ_SCHED_CONTEXT;
const OBJ_NOTIFICATION: u64 = salty::OBJ_NOTIFICATION;
const SALTY_OK: u64 = salty::SALTY_OK;
const SALTY_OUT_OF_MEMORY: u64 = salty::SALTY_OUT_OF_MEMORY;
const SALTY_NOT_FOUND: u64 = salty::SALTY_NOT_FOUND;
const SALTY_INVALID_ARGUMENT: u64 = salty::SALTY_INVALID_ARGUMENT;
const SALTY_INVALID_OPERATION: u64 = salty::SALTY_INVALID_OPERATION;
const SALTY_WOULD_BLOCK: u64 = salty::SALTY_WOULD_BLOCK;
const VSPACE_FLAG_WRITABLE: u64 = salty::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = salty::VSPACE_FLAG_USER;
const CAP_RIGHTS_ALL: u64 = salty::CAP_RIGHTS_ALL;
const INITRD_COPY_RIGHTS: u64 = (1 << 0) | (1 << 2) | (1 << 3);
const UT_MIRROR_COUNT: Cap = 8;
const INITRD_VADDR: u64 = salty::INITRD_VADDR;
const BOOTINFO_VADDR: u64 = salty::BOOTINFO_VADDR;
const BOOTINFO_MAGIC: u64 = salty::BOOTINFO_MAGIC;

// ---- CSpace expansion via bound notification ----
const CHILD_CAP_CSPACE_NTFN: u64 = 10; // Minted notification for CSpace expansion signaling
const CSPACE_EXPAND_BASE: u64 = salty::consts::CSPACE_EXPAND_BASE;
const MAX_CSPACE_EXPANSIONS: usize = salty::consts::MAX_CSPACE_EXPANSIONS;
const CSPACE_EXPAND_BITS: u64 = 10; // 1024 slots per expansion sub-CNode

/// Procmgr's bound notification cap (for receiving CSpace expansion signals).
static mut PM_BOUND_NTFN: Cap = 0;

/// mmsrv endpoint cap (via NeedEP=mmsrv:67).
const CAP_MMSRV_EP: Cap = 67;
/// Unbadged mmsrv endpoint cap for minting into children (preserves GRANT right).
const CAP_MMSRV_EP_UNBADGED: Cap = 68;

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
    let _ = salty::syscall::syscall(salty::SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
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

        // Service CSpace expansion requests during child startup by polling
        // the bound notification. Without this, a child that needs CSpace
        // expansion before signaling readiness would deadlock.
        unsafe {
            let bound_ntfn = *(&raw const PM_BOUND_NTFN);
            if bound_ntfn != 0 {
                let np = salty::syscall::syscall(salty::SYS_POLL, bound_ntfn, 0, 0, 0, 0, 0);
                if np.error == 0 && np.value != 0 {
                    let cs_bits = (np.value >> 16) & 0xFFFF;
                    if cs_bits != 0 { handle_cspace_expand_ntfn(cs_bits); }
                }
            }
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
        if proctab(idx).waiter_reply != 0 {
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, proctab(idx).waiter_reply);
            alloc.free_single_slot(proctab(idx).waiter_reply);
            proctab(idx).waiter_reply = 0;
        }
        if proctab(idx).any_waiter_reply != 0 {
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, proctab(idx).any_waiter_reply);
            alloc.free_single_slot(proctab(idx).any_waiter_reply);
            proctab(idx).any_waiter_reply = 0;
        }

        // Free primary slot range bitmap (caps are revoked by cleanup_proc_resources)
        if proctab(idx).slot_count > 0 {
            alloc.free_slots(proctab(idx).slot_base, proctab(idx).slot_count as usize);
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
        lb.str(b"[PROCMGR] EXIT PID="); lb.hex(proctab(idx).pid as u64);
        lb.str(b" code="); lb.hex(exit_code as u64); lb.str(b"\n"); lb.flush(); }

        // Deregister from mmsrv if registered
        if proctab(idx).mmsrv_registered {
            let mut mm_msg = SaltyMsg::zeroed();
            let mut mm_reply = SaltyMsg::zeroed();
            mm_msg.label = salty::consts::MM_DEREGISTER;
            mm_msg.length = 1;
            mm_msg.regs[0] = badge;
            let _ = ipc::call_ctx(ipc_ctx(), CAP_MMSRV_EP, &raw const mm_msg, &raw mut mm_reply);
        }

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

        proctab(idx).state = PROC_ZOMBIE;
        proctab(idx).exit_code = exit_code;

        // Save respawn info before cleanup clears it
        let should_respawn = proctab(idx).respawn;
        let mut saved_binary = [0u8; MAX_NAME_LEN];
        if should_respawn {
            saved_binary = proctab(idx).respawn_binary;
        }

        salty::invoke::invoke(proctab(idx).tcb_cap, salty::TCB_SUSPEND, 0, 0, 0, 0);

        // Deliver SIGCHLD to parent
        let ppid = proctab(idx).ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if proctab(pi).state == PROC_RUNNING
                && proctab(pi).signal_ntfn != 0
                && proctab(pi).sig_disposition[PM_SIGCHLD] == SIG_DISP_CATCH
            {
                signal_ntfn(proctab(pi).signal_ntfn, 1u64 << PM_SIGCHLD);
            }
        }

        // Wake specific-child waiter
        if proctab(idx).waiter_reply != 0 {
            { let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] Waking waiter for PID="); lb.hex(proctab(idx).pid as u64); lb.str(b"\n"); lb.flush(); }

            let mut wake = SaltyMsg::zeroed();
            wake.label = SALTY_OK;
            wake.length = 2;
            wake.regs[0] = exit_code as u64;
            wake.regs[1] = proctab(idx).pid as u64;

            let waiter_cap = proctab(idx).waiter_reply;
            salty::ipc::send_ctx(ipc_ctx(), waiter_cap, &raw const wake);
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, waiter_cap);
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(waiter_cap);
            proctab(idx).waiter_reply = 0;
            proctab(idx).waiter_pid = 0;
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
            if proctab(pi).waiting_for_any != 0 {
                { let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] Waking any-waiter parent PID="); lb.hex(proctab(pi).pid as u64);
                lb.str(b" for child PID="); lb.hex(proctab(idx).pid as u64); lb.str(b"\n"); lb.flush(); }

                let mut wake = SaltyMsg::zeroed();
                wake.label = SALTY_OK;
                wake.length = 2;
                wake.regs[0] = exit_code as u64;
                wake.regs[1] = proctab(idx).pid as u64;

                let waiter_cap = proctab(pi).any_waiter_reply;
                salty::ipc::send_ctx(ipc_ctx(), waiter_cap, &raw const wake);
                salty::invoke::cnode_delete(CAP_SELF_CSPACE, waiter_cap);
                (&mut *(&raw mut ALLOCATOR)).free_single_slot(waiter_cap);
                proctab(pi).any_waiter_reply = 0;
                proctab(pi).waiting_for_any = 0;
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
        let caller_pid = proctab(caller_idx).pid;

        // waitpid(-1): wait for any child
        if child_pid == u32::MAX {
            let mut zombie_idx: Option<usize> = None;
            let mut stopped_idx: Option<usize> = None;
            let mut has_living = false;
            let mut _child_count: u32 = 0;

            for i in 0..proctab_cap() {
                if proctab(i).state != PROC_FREE && proctab(i).ppid == caller_pid {
                    _child_count += 1;
                    if proctab(i).state == PROC_ZOMBIE && zombie_idx.is_none() {
                        zombie_idx = Some(i);
                    } else if proctab(i).state == PROC_STOPPED && stopped_idx.is_none() {
                        stopped_idx = Some(i);
                    }
                    if proctab(i).state == PROC_RUNNING || proctab(i).state == PROC_STOPPED {
                        has_living = true;
                    }
                }
            }
            if let Some(zi) = zombie_idx {
                reply.label = SALTY_OK;
                reply.length = 2;
                reply.regs[0] = proctab(zi).exit_code as u64;
                reply.regs[1] = proctab(zi).pid as u64;
                free_proc_alloc_slots(zi);
                cleanup_proc_resources(zi, CAP_SELF_CSPACE);
                return false;
            }

            if (options & WUNTRACED) != 0 {
                if let Some(si) = stopped_idx {
                    reply.label = SALTY_OK;
                    reply.length = 2;
                    reply.regs[0] = proctab(si).stop_status as u64;
                    reply.regs[1] = proctab(si).pid as u64;
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
            proctab(caller_idx).any_waiter_reply = reply_slot;
            proctab(caller_idx).waiting_for_any = 1;
            { let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] WAIT(-1) blocking parent PID="); lb.hex(caller_pid as u64); lb.str(b"\n"); lb.flush(); }
            return true;
        }

        // waitpid(specific child)
        let Some(ci) = find_by_pid(child_pid) else {
            reply.label = SALTY_NOT_FOUND;
            return false;
        };
        if proctab(ci).ppid != caller_pid {
            reply.label = SALTY_NOT_FOUND;
            return false;
        }

        if proctab(ci).state == PROC_ZOMBIE {
            reply.label = SALTY_OK;
            reply.length = 2;
            reply.regs[0] = proctab(ci).exit_code as u64;
            reply.regs[1] = proctab(ci).pid as u64;
            free_proc_alloc_slots(ci);
            cleanup_proc_resources(ci, CAP_SELF_CSPACE);
            return false;
        }

        if (options & WUNTRACED) != 0 && proctab(ci).state == PROC_STOPPED {
            reply.label = SALTY_OK;
            reply.length = 2;
            reply.regs[0] = proctab(ci).stop_status as u64;
            reply.regs[1] = proctab(ci).pid as u64;
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
        proctab(ci).waiter_reply = reply_slot;
        proctab(ci).waiter_pid = caller_pid;
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
    reply.regs[0] = unsafe { proctab(idx).pid as u64 };
}

unsafe fn handle_getppid(reply: &mut SaltyMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = SALTY_NOT_FOUND;
        return;
    };
    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { proctab(idx).ppid as u64 };
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
        lb.str(b"[PROCMGR] SIGKILL/terminate PID="); lb.hex(proctab(idx).pid as u64);
        lb.str(b" sig="); lb.hex(sig as u64); lb.str(b"\n"); lb.flush(); }

        salty::invoke::invoke(proctab(idx).tcb_cap, salty::TCB_SUSPEND, 0, 0, 0, 0);
        proctab(idx).state = PROC_ZOMBIE;
        proctab(idx).exit_code = exit_code;

        // Deliver SIGCHLD to parent
        let ppid = proctab(idx).ppid;
        if let Some(pi) = find_by_pid(ppid) {
            if (proctab(pi).state == PROC_RUNNING || proctab(pi).state == PROC_STOPPED)
                && proctab(pi).signal_ntfn != 0
                && proctab(pi).sig_disposition[PM_SIGCHLD] == SIG_DISP_CATCH
            {
                signal_ntfn(proctab(pi).signal_ntfn, 1u64 << PM_SIGCHLD);
            }
        }

        // Wake specific-child waiter
        if proctab(idx).waiter_reply != 0 {
            let mut wake = SaltyMsg::zeroed();
            wake.label = SALTY_OK;
            wake.length = 2;
            wake.regs[0] = exit_code as u64;
            wake.regs[1] = proctab(idx).pid as u64;

            let waiter_cap = proctab(idx).waiter_reply;
            salty::ipc::send_ctx(ipc_ctx(), waiter_cap, &raw const wake);
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, waiter_cap);
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(waiter_cap);
            proctab(idx).waiter_reply = 0;
            proctab(idx).waiter_pid = 0;
            free_proc_alloc_slots(idx);
            cleanup_proc_resources(idx, CAP_SELF_CSPACE);
            return;
        }

        // Wake any-child waiter on parent
        if let Some(pi) = find_by_pid(ppid) {
            if proctab(pi).waiting_for_any != 0 {
                let mut wake = SaltyMsg::zeroed();
                wake.label = SALTY_OK;
                wake.length = 2;
                wake.regs[0] = exit_code as u64;
                wake.regs[1] = proctab(idx).pid as u64;

                let waiter_cap = proctab(pi).any_waiter_reply;
                salty::ipc::send_ctx(ipc_ctx(), waiter_cap, &raw const wake);
                salty::invoke::cnode_delete(CAP_SELF_CSPACE, waiter_cap);
                (&mut *(&raw mut ALLOCATOR)).free_single_slot(waiter_cap);
                proctab(pi).any_waiter_reply = 0;
                proctab(pi).waiting_for_any = 0;
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
        if proctab(ti).state != PROC_RUNNING && proctab(ti).state != PROC_STOPPED {
            return false;
        }

        // SIGKILL: always terminate
        if sig == PM_SIGKILL {
            sig_terminate_proc(ti, sig);
            return true;
        }

        // SIGSTOP: always stop
        if sig == PM_SIGSTOP {
            if proctab(ti).state == PROC_RUNNING {
                salty::invoke::invoke(proctab(ti).tcb_cap, salty::TCB_SUSPEND, 0, 0, 0, 0);
                proctab(ti).state = PROC_STOPPED;
                proctab(ti).stop_status = ((sig as i32) << 8) | 0x7f;

                let ppid = proctab(ti).ppid;
                if let Some(pi) = find_by_pid(ppid) {
                    if (proctab(pi).state == PROC_RUNNING || proctab(pi).state == PROC_STOPPED)
                        && proctab(pi).signal_ntfn != 0
                        && proctab(pi).sig_disposition[PM_SIGCHLD] == SIG_DISP_CATCH
                    {
                        signal_ntfn(proctab(pi).signal_ntfn, 1u64 << PM_SIGCHLD);
                    }
                }
            }
            return true;
        }

        // SIGCONT: resume stopped
        if sig == PM_SIGCONT {
            if proctab(ti).state == PROC_STOPPED {
                salty::invoke::invoke(proctab(ti).tcb_cap, salty::TCB_RESUME, 0, 0, 0, 0);
                proctab(ti).state = PROC_RUNNING;
                proctab(ti).stop_status = 0;

                let ppid = proctab(ti).ppid;
                if let Some(pi) = find_by_pid(ppid) {
                    if (proctab(pi).state == PROC_RUNNING || proctab(pi).state == PROC_STOPPED)
                        && proctab(pi).signal_ntfn != 0
                        && proctab(pi).sig_disposition[PM_SIGCHLD] == SIG_DISP_CATCH
                    {
                        signal_ntfn(proctab(pi).signal_ntfn, 1u64 << PM_SIGCHLD);
                    }
                }
            }
            if proctab(ti).sig_disposition[sig] == SIG_DISP_CATCH && proctab(ti).signal_ntfn != 0 {
                signal_ntfn(proctab(ti).signal_ntfn, 1u64 << sig);
            }
            return true;
        }

        // Cannot deliver most signals to stopped processes
        if proctab(ti).state != PROC_RUNNING {
            return true;
        }

        let disp = proctab(ti).sig_disposition[sig];

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
        if proctab(ti).signal_ntfn != 0 {
            signal_ntfn(proctab(ti).signal_ntfn, 1u64 << sig);
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
            let caller_pgid = proctab(caller_idx).pgid;
            let mut delivered = false;
            for i in 0..proctab_cap() {
                if proctab(i).state != PROC_FREE && proctab(i).pgid == caller_pgid {
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
        for i in 0..proctab_cap() {
            if proctab(i).state != PROC_FREE && proctab(i).pgid == target_pgid {
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

        let child_cn = proctab(idx).cnode_cap;
        if child_cn == 0 {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // Cap was received at CAP_RECV_SCRATCH via IPC cap transfer.
        // Move it into the child slot so the scratch slot is freed for the
        // next injected cap in the same boot sequence.
        let err = salty::invoke::cnode_move(
            child_cn, dst_slot,
            CAP_SELF_CSPACE, CAP_RECV_SCRATCH,
        );
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
        proctab(idx).sig_disposition[sig] = disp;
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

        if child_entry == 0 {
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        let Some(parent_idx) = find_by_badge(badge) else {
            puts(b"[PROCMGR] FORK from unknown badge\n");
            reply.label = SALTY_NOT_FOUND;
            return;
        };
        let parent_pid = proctab(parent_idx).pid;
        let parent_vs = proctab(parent_idx).vspace_cap;

        let _parent_shared_base = proctab(parent_idx).shared_lib_base;
        let parent_lib_map = proctab(parent_idx).lib_map;
        let parent_layout = proctab(parent_idx).layout;
        let initrd_base = parent_layout.initrd.base;
        let initrd_end = parent_layout.initrd.base.saturating_add(parent_layout.initrd.size);
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
        // (skip IPC buf and initrd window pages).
        let mut page_count: usize = 0;
        {
            let mut walk_start: u64 = 0;
            loop {
                let err = salty::invoke::vspace_walk(parent_vs, walk_start, VSPACE_WALK_BATCH);
                if err != 0 { break; }
                let Some((count, next_addr)) = salty::invoke::vspace_walk_result_header() else {
                    break;
                };
                if count == 0 { break; }
                for i in 0..count as usize {
                    let Some((page_vaddr, _, _)) = salty::invoke::vspace_walk_result_entry(i) else {
                        break;
                    };
                    if page_vaddr == parent_layout.ipc_buf.base { continue; }
                    if parent_layout.initrd.size > 0
                        && page_vaddr >= initrd_base
                        && page_vaddr < initrd_end
                    {
                        continue;
                    }
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

        // Core objects (TCB/VSpace/CNode/SC) prefer primary untyped.
        macro_rules! realize_core {
            ($ty:expr, $what:expr) => {
                match alloc.realize_core_object($ty, 0) {
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

        let child_tcb = realize_core!(OBJ_TCB, b"[PROCMGR] FORK: TCB retype failed\n");
        let child_vs = realize_core!(OBJ_VSPACE, b"[PROCMGR] FORK: VSpace retype failed\n");
        let child_cn = realize_core!(OBJ_CNODE, b"[PROCMGR] FORK: CNode retype failed\n");
        let child_sc = realize_core!(OBJ_SCHED_CONTEXT, b"[PROCMGR] FORK: SC retype failed\n");
        // IPC frame allocated by mmsrv via MM_MAP_BATCH below
        let child_sig_ntfn = realize!(OBJ_NOTIFICATION, b"[PROCMGR] FORK: signal ntfn retype failed\n");

        // Walk parent VSpace again and copy pages
        let mut walk_start: u64 = 0;
        let child_entry_page = child_entry & !0xFFFu64;
        let mut child_entry_path: u64 = 0;

        loop {
            let err = salty::invoke::vspace_walk(parent_vs, walk_start, VSPACE_WALK_BATCH);
            if err != 0 { break; }
            let Some((count, next_addr)) = salty::invoke::vspace_walk_result_header() else {
                break;
            };
            if count == 0 { break; }

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
                    parent_vs,
                    page_vaddr,
                    child_vs,
                    page_vaddr,
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
                    reply.label = SALTY_INVALID_OPERATION;
                    return;
                }

                if page_vaddr == child_entry_page {
                    child_entry_path = 3; // COW clone
                }
            }

            if next_addr == 0 { break; }
            walk_start = next_addr;
        }

        if child_entry_path != 3 {
            puts(b"[PROCMGR] FORK: child entry page missing after COW clone\n");
            alloc.rollback();
            reply.label = SALTY_INVALID_OPERATION;
            return;
        }

        // Mint mmsrv EP into child CNode slot 7 (badged with child pid)
        let err = salty::invoke::cnode_mint(
            CAP_SELF_CSPACE, CAP_MMSRV_EP_UNBADGED, child_cn, CHILD_CAP_MMSRV_EP, child_pid as u64,
        );
        if err != 0 {
            puts(b"[PROCMGR] FORK: mint mmsrv EP failed\n");
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
        // Note: root untypeds no longer mirrored — children use mmsrv.

        // Mint CSpace expansion notification into child CNode
        let pm_ntfn = *(&raw const PM_BOUND_NTFN);
        if pm_ntfn != 0 {
            let cs_badge = 1u64 << (16 + slot_idx);
            let _ = salty::invoke::cnode_mint(
                CAP_SELF_CSPACE, pm_ntfn,
                child_cn, CHILD_CAP_CSPACE_NTFN,
                cs_badge,
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

        // Set fault handler: badged mmsrv EP so VMFaults route to mmsrv
        {
            let temp_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => {
                    alloc.rollback();
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            };
            let err = salty::invoke::cnode_mint(
                CAP_SELF_CSPACE, CAP_MMSRV_EP_UNBADGED,
                CAP_SELF_CSPACE, temp_slot,
                child_pid as u64,
            );
            if err == 0 {
                salty::invoke::tcb_set_fault_handler(child_tcb, temp_slot);
            }
            salty::invoke::cnode_delete(CAP_SELF_CSPACE, temp_slot);
            alloc.free_single_slot(temp_slot);
        }

        let err = salty::invoke::tcb_configure(child_tcb, child_entry, parent_rsp, 0);
        if err != 0 {
            puts(b"[PROCMGR] FORK: configure failed\n");
            alloc.rollback();
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }
        // Copy parent's FPU/SSE state to child (preserves XMM registers across fork)
        let err = salty::invoke::tcb_copy_fpu(child_tcb, proctab(parent_idx).tcb_cap);
        if err != 0 {
            puts(b"[PROCMGR] FORK: copy FPU state failed\n");
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

        // Register child with mmsrv (VSpace cap transfer + initial state)
        {
            let fork_heap_base = parent_layout.elf_code.end();
            let fork_mmap_base = layout::compute_mmap_base(&parent_layout, fork_heap_base);
            let mut mm_msg = SaltyMsg::zeroed();
            let mut mm_reply = SaltyMsg::zeroed();
            mm_msg.label = salty::consts::MM_REGISTER;
            mm_msg.length = 4;
            mm_msg.regs[0] = child_pid as u64; // client badge
            // Seed with dynamic defaults; MM_FORK_REGIONS overwrites with exact runtime state.
            mm_msg.regs[1] = fork_heap_base;
            mm_msg.regs[2] = fork_mmap_base;
            mm_msg.regs[3] = child_pid as u64;
            ipc::set_send_cap_ctx(ipc_ctx(), 0, child_vs);
            let err = ipc::call_ctx(ipc_ctx(), CAP_MMSRV_EP, &raw const mm_msg, &raw mut mm_reply);
            if err != 0 || mm_reply.label != SALTY_OK {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] FORK: mmsrv register failed err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
                alloc.rollback();
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // Clone parent's memory state to child in mmsrv
        {
            let mut mm_msg = SaltyMsg::zeroed();
            let mut mm_reply = SaltyMsg::zeroed();
            mm_msg.label = salty::consts::MM_FORK_REGIONS;
            mm_msg.length = 2;
            mm_msg.regs[0] = badge;            // parent badge
            mm_msg.regs[1] = child_pid as u64; // child badge
            let err = ipc::call_ctx(ipc_ctx(), CAP_MMSRV_EP, &raw const mm_msg, &raw mut mm_reply);
            if err != 0 || mm_reply.label != SALTY_OK {
                puts(b"[PROCMGR] FORK: mmsrv fork_regions failed\n");
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
            mm_msg.regs[3] = VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER;
            let err = ipc::call_ctx(ipc_ctx(), CAP_MMSRV_EP, &raw const mm_msg, &raw mut mm_reply);
            if err != 0 || mm_reply.label != SALTY_OK || mm_reply.regs[0] != 1 {
                puts(b"[PROCMGR] FORK: MM_MAP_BATCH ipc failed\n");
                // Deregister child from mmsrv on failure
                {
                    let mut dereg = SaltyMsg::zeroed();
                    let mut drep = SaltyMsg::zeroed();
                    dereg.label = salty::consts::MM_DEREGISTER;
                    dereg.length = 1;
                    dereg.regs[0] = child_pid as u64;
                    let _ = ipc::call_ctx(ipc_ctx(), CAP_MMSRV_EP, &raw const dereg, &raw mut drep);
                }
                alloc.rollback();
                reply.label = SALTY_OUT_OF_MEMORY;
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
        lb.str(b"[PROCMGR] EXEC PID="); lb.hex(proctab(idx).pid as u64);
        lb.str(b" -> '");
        lb.bytes(&name[..name_len]);
        lb.str(b"' argc="); lb.hex(argc as u64);
        lb.str(b" envc="); lb.hex(envc as u64);
        lb.str(b"\n");
        lb.flush(); }
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
        let proc_vs = proctab(idx).vspace_cap;
        let pid = proctab(idx).pid;

        // 1. Deregister old mappings from mmsrv so it doesn't hold stale frame refs
        spawn_tx::deregister_from_mmsrv(pid);

        // 2. Unmap existing user pages
        let mut walk_start: u64 = 0;
        loop {
            let err = salty::invoke::vspace_walk(proc_vs, walk_start, VSPACE_WALK_BATCH);
            if err != 0 { break; }
            let Some((count, next_addr)) = salty::invoke::vspace_walk_result_header() else {
                break;
            };
            if count == 0 { break; }

            for i in 0..count {
                let Some((page_vaddr, _, _)) = salty::invoke::vspace_walk_result_entry(i as usize) else {
                    break;
                };
                salty::invoke::vspace_unmap(proc_vs, page_vaddr);
            }

            if next_addr == 0 { break; }
            walk_start = next_addr;
        }

        // 2a. Clean old RTLD/dynamic slots from child CSpace to prevent slot collision
        {
            let child_cn = proctab(idx).cnode_cap;
            let frame_floor = if proctab(idx).has_service_ep {
                CHILD_CAP_SERVICE_EP + 1
            } else {
                CHILD_RTLD_FRAME_SLOT_START
            };
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

        // 2b. Free old procmgr-side frame slots beyond the fixed objects
        let old_slot_base = proctab(idx).slot_base;
        let old_slot_count = proctab(idx).slot_count as usize;
        let off_fixed = spawn_tx::OFF_FIXED_END;

        if old_slot_count > off_fixed {
            for i in off_fixed..old_slot_count {
                let slot = old_slot_base + i as u64;
                let err = salty::invoke::cnode_revoke(CAP_SELF_CSPACE, slot);
                if err != 0 { salty::invoke::cnode_delete(CAP_SELF_CSPACE, slot); }
            }
            alloc.free_slots(old_slot_base + off_fixed as u64, old_slot_count - off_fixed);
            proctab(idx).slot_count = off_fixed as u16;
        }

        // 3. Compute layout
        let elf_span =
            salty::elf_loader::elf_compute_load_span(elf_entry.data, elf_entry.data_len);
        let rtld_span = if is_dynamic {
            spawn_tx::count_rtld_span_for_exec(
                elf_entry.data, elf_entry.data_len, initrd, initrd_size,
            )
        } else {
            0
        };
        let needed = if is_dynamic {
            salty::elf_dynamic::elf_get_needed(elf_entry.data, elf_entry.data_len)
        } else {
            salty::elf_dynamic::NeededLibs::new()
        };
        let shared_lib_cache_pages = spawn_tx::shared_lib_va_pages_for_needed(&needed);
        let lib_window_pages = if is_dynamic {
            spawn_tx::compute_lib_window_pages(initrd, initrd_size)
        } else {
            0
        };
        let layout = layout::compute_vm_layout(
            elf_span,
            rtld_span,
            shared_lib_cache_pages,
            is_dynamic,
            lib_window_pages * 4096,
        );
        if layout.stack_top == 0 {
            puts(b"[PROCMGR] EXEC: ELF too large for VA layout\n");
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // 4. Re-register with mmsrv for the new exec image
        let heap_base = layout.code_end();
        let mmap_base = layout::compute_mmap_base(&layout, heap_base);
        spawn_tx::register_with_mmsrv(pid, proc_vs, heap_base, mmap_base);

        // 5. Load ELF via mmsrv
        let mut elf_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        let err = spawn_tx::exec_load_elf_mmsrv(
            elf_entry.data, elf_entry.data_len,
            layout.elf_code.base, pid, proc_vs, &raw mut elf_result,
        );
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] EXEC: ELF load failed err=");
            lb.hex(err as u64);
            lb.str(b"\n"); lb.flush();
            spawn_tx::deregister_from_mmsrv(pid);
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        // 5b. Load rtld if dynamic
        let mut rtld_result = ElfLoadResult { entry: 0, base: 0, brk: 0 };
        if is_dynamic {
            match spawn_tx::exec_load_rtld_mmsrv(
                elf_entry.data, elf_entry.data_len,
                initrd, initrd_size,
                layout.rtld.base, pid, proc_vs,
            ) {
                Some(r) => rtld_result = r,
                None => {
                    spawn_tx::deregister_from_mmsrv(pid);
                    reply.label = SALTY_NOT_FOUND;
                    return;
                }
            }
        }

        // 6. Map initrd and boot info for dynamic executables
        if is_dynamic {
            let initrd_window_size = lib_window_pages * 4096;
            let err = spawn_tx::exec_map_initrd_mmsrv(
                proc_vs, initrd, initrd_window_size, pid, layout.initrd.base,
            );
            if err != 0 {
                spawn_tx::deregister_from_mmsrv(pid);
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }

            let err = spawn_tx::exec_map_bootinfo_mmsrv(pid);
            if err != 0 {
                spawn_tx::deregister_from_mmsrv(pid);
                reply.label = SALTY_OUT_OF_MEMORY;
                return;
            }
        }

        // 7. Map IPC buffer via mmsrv
        let err = spawn_tx::exec_map_ipc_buf_mmsrv(pid, layout.ipc_buf.base);
        if err != 0 {
            spawn_tx::deregister_from_mmsrv(pid);
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // 8. Map shared library frames if available
        let (shared_lib_base, shared_lib_map) = if is_dynamic {
            spawn_tx::map_shared_lib_to_vspace(proc_vs, layout.shared_libs.base, &needed, pid)
        } else {
            (0, proc_table::ProcLibMap::zeroed())
        };

        // 9. Set up stack via mmsrv (top page left mapped at PROCMGR_SCRATCH_VADDR)
        let stack_pages = layout.stack.page_count();
        let err = spawn_tx::exec_map_stack_mmsrv(
            pid, layout.stack.base, stack_pages, layout.stack_top,
        );
        if err != 0 {
            spawn_tx::deregister_from_mmsrv(pid);
            reply.label = SALTY_OUT_OF_MEMORY;
            return;
        }

        // 10. Entry point and dynamic stack (top page already at PROCMGR_SCRATCH_VADDR)
        let mut new_entry = elf_result.entry;
        let mut new_rsp: u64;

        if is_dynamic {
            let mut exec_cnode_bits: u64 = 10;
            let cinfo = salty::invoke::cnode_get_info(proctab(idx).cnode_cap);
            if cinfo.error == 0 {
                let ctx = &*ipc_ctx();
                if !ctx.ipc_buffer.is_null() {
                    let buf = &*ctx.ipc_buffer;
                    let bits = buf.msg[2];
                    if bits >= 4 && bits <= 16 {
                        exec_cnode_bits = bits;
                    }
                }
            }
            match spawn_tx::write_dynamic_stack(
                elf_entry.data, elf_entry.data_len,
                0, &elf_result, &rtld_result, lib_window_pages * 4096,
                shared_lib_base,
                argc, envc, &exec_str_data, exec_str_len,
                layout.elf_code.base,
                layout.scratch.base,
                layout.initrd.base,
                layout.stack_top,
                exec_cnode_bits,
                if proctab(idx).has_service_ep { CHILD_CAP_SERVICE_EP + 1 } else { CHILD_RTLD_FRAME_SLOT_START },
                true, // pre-mapped: stack top already at PROCMGR_SCRATCH_VADDR via mmsrv
            ) {
                Ok(rsp) => { new_rsp = rsp; new_entry = rtld_result.entry; }
                Err(()) => {
                    spawn_tx::unmap_window_from_mmsrv(PROCMGR_SCRATCH_VADDR, 1);
                    spawn_tx::deregister_from_mmsrv(pid);
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
        } else {
            match spawn_tx::write_static_stack(
                0,
                argc, envc, &exec_str_data, exec_str_len,
                layout.scratch.base,
                layout.initrd.base,
                layout.stack_top,
                true, // pre-mapped: stack top already at PROCMGR_SCRATCH_VADDR via mmsrv
            ) {
                Ok(rsp) => { new_rsp = rsp; }
                Err(()) => {
                    spawn_tx::unmap_window_from_mmsrv(PROCMGR_SCRATCH_VADDR, 1);
                    spawn_tx::deregister_from_mmsrv(pid);
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return;
                }
            }
        }

        // Unmap the stack top write window
        spawn_tx::unmap_window_from_mmsrv(PROCMGR_SCRATCH_VADDR, 1);

        // 11. Suspend and reconfigure
        salty::invoke::tcb_suspend(proctab(idx).tcb_cap);

        // POSIX: exec resets caught signals to SIG_DFL
        for i in 0..NSIG {
            if proctab(idx).sig_disposition[i] == SIG_DISP_CATCH {
                proctab(idx).sig_disposition[i] = SIG_DISP_DFL;
            }
        }

        let err = salty::invoke::tcb_configure(proctab(idx).tcb_cap, new_entry, new_rsp, 0);
        if err != 0 {
            puts(b"[PROCMGR] EXEC: tcb_configure failed\n");
            spawn_tx::deregister_from_mmsrv(pid);
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }
        salty::invoke::tcb_set_ipc_buffer(proctab(idx).tcb_cap, layout.ipc_buf.base);

        let err = salty::invoke::tcb_resume(proctab(idx).tcb_cap);
        if err != 0 {
            puts(b"[PROCMGR] EXEC: resume failed\n");
            spawn_tx::deregister_from_mmsrv(pid);
            reply.label = SALTY_INVALID_ARGUMENT;
            return;
        }

        proctab(idx).shared_lib_base = shared_lib_base;
        proctab(idx).lib_map = shared_lib_map;
        proctab(idx).layout = layout;

        { let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] EXEC: PID="); lb.hex(proctab(idx).pid as u64);
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
        let caller_pid = proctab(caller_idx).pid;
        let caller_sid = proctab(caller_idx).sid;

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

        if target_pid != caller_pid && proctab(ti).ppid != caller_pid {
            reply.label = SALTY_INVALID_OPERATION;
            return;
        }

        if proctab(ti).sid != caller_sid {
            reply.label = SALTY_INVALID_OPERATION;
            return;
        }

        if proctab(ti).pid == proctab(ti).sid {
            reply.label = SALTY_INVALID_OPERATION;
            return;
        }

        if pgid != target_pid {
            let Some(gi) = find_by_pid(pgid) else {
                reply.label = SALTY_NOT_FOUND;
                return;
            };
            if proctab(gi).sid != proctab(ti).sid {
                reply.label = SALTY_INVALID_OPERATION;
                return;
            }
        }

        proctab(ti).pgid = pgid;
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
            target_pid = proctab(caller_idx).pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };

        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).pgid as u64;
    }
}

unsafe fn handle_setsid(reply: &mut SaltyMsg, badge: u64) {
    unsafe {
        let Some(idx) = find_by_badge(badge) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };
        let pid = proctab(idx).pid;
        if proctab(idx).pgid == pid {
            reply.label = SALTY_INVALID_OPERATION;
            return;
        }
        proctab(idx).sid = pid;
        proctab(idx).pgid = pid;
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
            target_pid = proctab(caller_idx).pid;
        }

        let Some(ti) = find_by_pid(target_pid) else {
            reply.label = SALTY_NOT_FOUND;
            return;
        };

        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ti).sid as u64;
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
        reply.regs[0] = proctab(ti).pgid as u64;
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
        reply.regs[0] = proctab(ti).sid as u64;
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

    let child_cn = unsafe { proctab(ci).cnode_cap };

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
    let (root_num_slots, _root_size_bits) = unsafe {
        let ctx = &*ipc_ctx();
        let buf = &*ctx.ipc_buffer;
        (buf.msg[3], buf.msg[2])
    };

    // We will probe root slots from 64 upward and attach the new sub-CNode
    // at the first free one.
    let mut target_slot: u64 = u64::MAX;

    // Retype a new sub-CNode into a procmgr-local temp slot.
    // Use allocator-wide untyped sources instead of a per-child dedicated
    // untyped so expansion keeps working after child-local UT depletion.
    let temp_slot = match unsafe { (&mut *(&raw mut ALLOCATOR)).alloc_single_slot() } {
        Some(s) => s,
        None => { reply.label = SALTY_OUT_OF_MEMORY; return; }
    };

    let err = unsafe { (&mut *(&raw mut ALLOCATOR)).retype_core_object(OBJ_CNODE, size_bits, temp_slot) };
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
        let child_cn = proctab(ci).cnode_cap;

        let req_bits = msg.regs[0];
        let size_bits = if req_bits == 0 { 10u64 } else { req_bits };
        if size_bits < 4 || size_bits > 16 {
            return;
        }

        let info = salty::invoke::cnode_get_info(child_cn);
        if info.error != 0 {
            return;
        }
        let (root_num_slots, _root_size_bits) = {
            let ctx = &*ipc_ctx();
            let buf = &*ctx.ipc_buffer;
            (buf.msg[3], buf.msg[2])
        };

        let temp_slot = match (&mut *(&raw mut ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => return,
        };

        let err = (&mut *(&raw mut ALLOCATOR)).retype_core_object(OBJ_CNODE, size_bits, temp_slot);
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

        proctab(ci).expand_pending = true;
        proctab(ci).expand_result_base = base_addr;
        proctab(ci).expand_result_count = new_slots;
    }
}

/// Handle PM_EXPAND_COLLECT (Call): return the stored expansion result.
unsafe fn handle_expand_collect(reply: &mut SaltyMsg, badge: u64) {
    let ci = match find_by_badge(badge) {
        Some(i) => i,
        None => { reply.label = SALTY_NOT_FOUND; return; }
    };

    unsafe {
        if proctab(ci).expand_pending {
            reply.label = SALTY_OK;
            reply.length = 2;
            reply.regs[0] = proctab(ci).expand_result_base;
            reply.regs[1] = proctab(ci).expand_result_count;
            proctab(ci).expand_pending = false;
        } else {
            reply.label = SALTY_PENDING;
        }
    }
}

/// Handle CSpace expansion requests delivered via bound notification (upper 16 bits).
///
/// Each bit i (0-15) in `bits` corresponds to proctab(i). When a child signals
/// the procmgr's bound notification with badge = 1 << (16 + idx), the kernel ORs
/// the badge bits. We retype a sub-CNode and copy it into the child's root CNode
/// at deterministic slots [CSPACE_EXPAND_BASE .. CSPACE_EXPAND_BASE + count).
unsafe fn handle_cspace_expand_ntfn(bits: u64) {
    unsafe {
        let alloc = &mut *(&raw mut ALLOCATOR);
        for i in 0..proctab_cap() {
            if bits & (1u64 << i) == 0 { continue; }
            if proctab(i).state != PROC_RUNNING { continue; }

            let n = proctab(i).cspace_expand_count as u64;
            if n >= MAX_CSPACE_EXPANSIONS as u64 { continue; }

            let child_cn = proctab(i).cnode_cap;
            if child_cn == 0 { continue; }

            let dest_child_slot = CSPACE_EXPAND_BASE + n;

            // Allocate temp slot and retype sub-CNode from procmgr's pool
            let pm_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => continue,
            };

            let err = alloc.retype_core_object(OBJ_CNODE, CSPACE_EXPAND_BITS, pm_slot);
            if err != 0 {
                alloc.free_single_slot(pm_slot);
                continue;
            }

            // Sub-CNode: guard=0, guard_bits=0 (flat two-level addressing)
            let err = salty::invoke::cnode_set_guard(pm_slot, 0, 0);
            if err != 0 {
                salty::invoke::cnode_delete(CAP_SELF_CSPACE, pm_slot);
                alloc.free_single_slot(pm_slot);
                continue;
            }

            // Move into child's root CNode at the deterministic slot.
            // cnode_move transfers atomically without creating a CDT parent→child
            // relationship, so the source slot becomes empty and can be freed.
            let move_err = salty::invoke::cnode_move(
                child_cn, dest_child_slot,
                CAP_SELF_CSPACE, pm_slot,
            );
            if move_err == 0 {
                alloc.free_single_slot(pm_slot);
            }

            if move_err != 0 {
                continue;
            }

            proctab(i).cspace_expand_count += 1;

            {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] cspace-expand: granted ");
                lb.hex(1u64 << CSPACE_EXPAND_BITS);
                lb.str(b" slots to idx=");
                lb.hex(i as u64);
                lb.str(b" root_slot=");
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

        proctab(ci).pid = NEXT_PID;
        NEXT_PID += 1;
        proctab(ci).sid = proctab(ci).pid;
        proctab(ci).pgid = proctab(ci).pid;
        proctab(ci).badge = reg_badge;
        proctab(ci).state = PROC_RUNNING;
        proctab(ci).cnode_cap = cn_perm;

        // Mint CSpace expansion notification (upper 16 bits badge)
        let pm_ntfn = *(&raw const PM_BOUND_NTFN);
        if pm_ntfn != 0 {
            let cs_badge = 1u64 << (16 + ci);
            let _ = salty::invoke::cnode_mint(
                CAP_SELF_CSPACE, pm_ntfn,
                cn_perm, CHILD_CAP_CSPACE_NTFN,
                cs_badge,
            );
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] PM_REGISTER badge=");
            lb.hex(reg_badge);
            lb.str(b" pid=");
            lb.hex(proctab(ci).pid as u64);
            lb.str(b"\n");
            lb.flush();
        }

        reply.label = SALTY_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ci).pid as u64;
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

        // Initialize mmsrv client
        salty::posix_mm::posix_mm_init(CAP_MMSRV_EP);

        // Initialize process table (allocates via mmsrv)
        init_proctab();

        // Initialize the centralized allocator
        (*(&raw mut ALLOCATOR)).init(
            CAP_SELF_CSPACE,
            CAP_UNTYPED,
            CAP_UNTYPED_START,
            UT_MIRROR_COUNT as usize,
        );

        // Pre-load shared library RO pages into frame cache.
        // Must happen before any allocator use — init copies shared lib caps
        // into slots 0x80+, which can overlap SLOT_POOL_BASE (256).
        spawn_tx::init_shared_lib_cache(&mut *(&raw mut ALLOCATOR));

        // Create and bind a notification for CSpace expansion signaling.
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
                        puts(b"[PROCMGR] bound notification ready for CSpace expansion\n");
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

        // Phase 4 integrity probe: read from initrd offset 0x45A000
        // (PT[90] of PD[10] — first zero seen in Phase 3).
        // If this faults, corruption exists before any spawn requests.
        {
            let probe_ptr = (INITRD_VADDR + 0x45A000) as *const u8;
            let probe_val = unsafe { core::ptr::read_volatile(probe_ptr) };
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] initrd probe @0x45A000 = 0x");
            lb.hex(probe_val as u64);
            lb.str(b"\n");
            lb.flush();
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
            // Bound notification delivery: label=0 and badge!=0 means the
            // kernel delivered a notification word instead of an IPC message.
            // Upper 16 bits: CSpace expansion.
            if msg.label == 0 && badge != 0 {
                let cs_bits = (badge >> 16) & 0xFFFF;
                if cs_bits != 0 { handle_cspace_expand_ntfn(cs_bits); }
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
