//! SaltyOS Process Manager
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Panic handler provided by libbesalt.so (dynamic linking).

#![no_std]
#![no_main]

mod alloc;
mod cspace;
mod exit_wait;
mod fork_exec;
mod proc_table;
mod session;
mod signal;
mod spawn_tx;

use besalt::ipc;
use besalt::serial::LineBuf;
use besalt::types::*;

use proc_table::{
    find_by_badge, find_by_pid, init_proctab, proctab, proctab_cap, MAX_NAME_LEN, PROC_FREE,
};

// ---- Cap layout (set by init for this process) ----
const CAP_SELF_TCB: Cap = 0;
const CAP_SELF_VSPACE: Cap = 1;
const CAP_SELF_CSPACE: Cap = 2;
const CAP_SERVER_EP: Cap = 3;
const CAP_UNTYPED: Cap = 7;
const CAP_NAMESERV_EP: Cap = 64; // NeedEP nameserv:64
const CAP_VFS_EP: Cap = 65; // NeedEP vfs:65
const CAP_FB_UNTYPED: Cap = 66; // CopyCap 13:66
const CAP_INITRD_UNTYPED: Cap = 12;
const CAP_RECV_SCRATCH: Cap = 15; // Scratch slot for receiving transferred caps
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
const PM_LIST_PIDS: u64 = 27;
const PM_GET_PROC_INFO: u64 = 28;
const PM_RESUME: u64 = 29;
const PM_UMASK: u64 = 30;
const BESALT_PENDING: u64 = 0x80;

const PM_SIGKILL: usize = 9;
const PM_SIGCHLD: usize = 17;
const PM_SIGCONT: usize = 18;
const PM_SIGSTOP: usize = 19;
const PM_SIGTSTP: usize = 20;
const PM_SIGTTIN: usize = 21;
const PM_SIGTTOU: usize = 22;

use besalt::layout::{self};

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
const AT_BESALT_VSPACE: u64 = 0x1001;
const AT_BESALT_SCRATCH: u64 = 0x1002;
const AT_BESALT_INITRD: u64 = 0x1003;
const AT_BESALT_INITRD_SZ: u64 = 0x1004;
const AT_BESALT_FRAME_SLOT: u64 = 0x1005;
const AT_BESALT_SHARED_LIB_BASE: u64 = 0x1006;
const AT_BESALT_SLOT_BASE: u64 = 0x1007;
const AT_BESALT_SLOT_COUNT: u64 = 0x1008;
const AT_BESALT_CSPACE_NTFN: u64 = 0x100A;

// ---- waitpid options ----
const WNOHANG: u32 = 1;
const WUNTRACED: u32 = 2;

// ---- Shorthand re-exports ----
const OBJ_TCB: u64 = besalt::OBJ_TCB;
const OBJ_VSPACE: u64 = besalt::OBJ_VSPACE;
const OBJ_CNODE: u64 = besalt::OBJ_CNODE;
const OBJ_SCHED_CONTEXT: u64 = besalt::OBJ_SCHED_CONTEXT;
const OBJ_NOTIFICATION: u64 = besalt::OBJ_NOTIFICATION;
const BESALT_OK: u64 = besalt::BESALT_OK;
const BESALT_OUT_OF_MEMORY: u64 = besalt::BESALT_OUT_OF_MEMORY;
const BESALT_NOT_FOUND: u64 = besalt::BESALT_NOT_FOUND;
const BESALT_INVALID_ARGUMENT: u64 = besalt::BESALT_INVALID_ARGUMENT;
const BESALT_INVALID_OPERATION: u64 = besalt::BESALT_INVALID_OPERATION;
const BESALT_WOULD_BLOCK: u64 = besalt::BESALT_WOULD_BLOCK;
const BESALT_BUSY: u64 = besalt::BESALT_BUSY;
const VSPACE_FLAG_WRITABLE: u64 = besalt::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = besalt::VSPACE_FLAG_USER;
const CAP_RIGHTS_ALL: u64 = besalt::CAP_RIGHTS_ALL;
const INITRD_COPY_RIGHTS: u64 = (1 << 0) | (1 << 2) | (1 << 3);
const UT_MIRROR_COUNT: Cap = 8;
const INITRD_VADDR: u64 = besalt::INITRD_VADDR;
const BOOTINFO_VADDR: u64 = besalt::BOOTINFO_VADDR;
const BOOTINFO_MAGIC: u64 = besalt::BOOTINFO_MAGIC;

// ---- CSpace expansion via bound notification ----
const CHILD_CAP_CSPACE_NTFN: u64 = 10; // Minted notification for CSpace expansion signaling
const CSPACE_EXPAND_BASE: u64 = besalt::consts::CSPACE_EXPAND_BASE;
const MAX_CSPACE_EXPANSIONS: usize = besalt::consts::MAX_CSPACE_EXPANSIONS;
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

fn puts(s: &[u8]) {
    besalt::serial::serial_puts(s);
}
fn ipc_ctx() -> *mut IpcContext {
    &raw mut besalt::__besalt_ipc_ctx
}

fn signal_ready() {
    let _ = besalt::syscall::syscall(besalt::SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
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

/// Extract process path/name from message regs and normalize by stripping
/// an optional trailing ".elf" suffix.
/// Returns the name buffer and its length.
fn extract_name(msg: &BesaltMsg, name_reg_idx: usize) -> ([u8; MAX_NAME_LEN + 5], usize) {
    let mut name = [0u8; MAX_NAME_LEN + 5];
    let mut name_len = msg.regs[0] as usize;
    if name_len > MAX_NAME_LEN {
        name_len = MAX_NAME_LEN;
    }

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
        let now = besalt::syscall::syscall(besalt::SYS_CLOCK_GETTIME, 1, 0, 0, 0, 0, 0);
        if now.error == 0 {
            Some(now.value)
        } else {
            None
        }
    };
    let mut yields: usize = 0;

    loop {
        let poll = besalt::syscall::syscall(besalt::SYS_POLL, ready_ntfn, 0, 0, 0, 0, 0);
        if poll.error == 0 {
            if (poll.value & READY_SIGNAL_BITS) != 0 {
                return 0;
            }
        } else if poll.error != BESALT_WOULD_BLOCK {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] ready poll failed err=");
            lb.hex(poll.error);
            lb.str(b"\n");
            lb.flush();
            let _ = besalt::invoke::tcb_suspend_retry(child_tcb, 4);
            return -1;
        }

        // Service CSpace expansion requests during child startup by polling
        // the bound notification. Without this, a child that needs CSpace
        // expansion before signaling readiness would deadlock.
        unsafe {
            let bound_ntfn = *(&raw const PM_BOUND_NTFN);
            if bound_ntfn != 0 {
                let np = besalt::syscall::syscall(besalt::SYS_POLL, bound_ntfn, 0, 0, 0, 0, 0);
                if np.error == 0 && np.value != 0 {
                    let cs_bits = (np.value >> 16) & 0xFFFF;
                    if cs_bits != 0 {
                        cspace::handle_cspace_expand_ntfn(cs_bits);
                    }
                }
            }
        }

        let timed_out = if let Some(start) = start_ns {
            let now = besalt::syscall::syscall(besalt::SYS_CLOCK_GETTIME, 1, 0, 0, 0, 0, 0);
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

        let _ = besalt::syscall::syscall(besalt::SYS_YIELD, 0, 0, 0, 0, 0, 0);
        yields += 1;
    }

    let mut lb = LineBuf::new();
    lb.str(b"[PROCMGR] child ready timeout: ");
    lb.bytes(child_name);
    lb.str(b"\n");
    lb.flush();
    let _ = besalt::invoke::tcb_suspend_retry(child_tcb, 4);
    -1
}

// ===========================================================================
// handle_getpid / handle_getppid
// ===========================================================================

unsafe fn handle_getpid(reply: &mut BesaltMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = BESALT_NOT_FOUND;
        return;
    };
    reply.label = BESALT_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { proctab(idx).pid as u64 };
}

unsafe fn handle_getppid(reply: &mut BesaltMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = BESALT_NOT_FOUND;
        return;
    };
    reply.label = BESALT_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { proctab(idx).ppid as u64 };
}

/// List all active PIDs.
/// Reply: regs[0..18] = PIDs (up to 18), regs[19] = count.
unsafe fn handle_list_pids(reply: &mut BesaltMsg) {
    unsafe {
        let cap = proc_table::proctab_cap();
        let mut count: usize = 0;
        for i in 0..cap {
            let p = &*proc_table::proctab(i);
            if p.state != proc_table::PROC_FREE && count < 19 {
                reply.regs[count] = p.pid as u64;
                count += 1;
            }
        }
        reply.regs[19] = count as u64;
        reply.label = BESALT_OK;
        reply.length = 20;
    }
}

/// Get process info for a given PID.
/// Request: regs[0] = pid
/// Reply: regs[0]=pid, regs[1]=ppid, regs[2]=pgid, regs[3]=sid,
///        regs[4]=state, regs[5..9]=name(32B)
unsafe fn handle_get_proc_info(msg: &BesaltMsg, reply: &mut BesaltMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        let Some(idx) = proc_table::find_by_pid(pid) else {
            reply.label = BESALT_NOT_FOUND;
            return;
        };
        let p = &*proc_table::proctab(idx);
        reply.regs[0] = p.pid as u64;
        reply.regs[1] = p.ppid as u64;
        reply.regs[2] = p.pgid as u64;
        reply.regs[3] = p.sid as u64;
        reply.regs[4] = p.state as u64;
        // Pack name (32 bytes = 4 u64s) into regs[5..9]
        let dst = &mut reply.regs[5] as *mut u64 as *mut u8;
        for i in 0..32 {
            *dst.add(i) = p.name[i];
        }
        reply.label = BESALT_OK;
        reply.length = 9;
    }
}

// ===========================================================================
// handle_umask
// ===========================================================================

unsafe fn handle_umask(msg: &BesaltMsg, reply: &mut BesaltMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = BESALT_NOT_FOUND;
        return;
    };
    unsafe {
        let p = proctab(idx);
        let old = p.umask;
        p.umask = (msg.regs[0] as u32) & 0o777;
        reply.label = BESALT_OK;
        reply.length = 1;
        reply.regs[0] = old as u64;
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
        let err = besalt::invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] FAIL: set IPC buffer err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            idle();
        }
        besalt::ipc::ipc_context_init(ipc_ctx(), IPC_BUF_VADDR as *mut IpcBuffer);
        puts(b"[PROCMGR] IPC buffer ready\n");

        // Initialize mmsrv client
        besalt::posix_mm::posix_mm_init(CAP_MMSRV_EP);

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
                    let err = besalt::invoke::tcb_bind_notification(CAP_SELF_TCB, ntfn_slot);
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
            let mut reg_msg = BesaltMsg::zeroed();
            let mut reg_reply = BesaltMsg::zeroed();
            let svc_name = b"procmgr";
            reg_msg.label = besalt::consts::POSIX_NS_REGISTER;
            reg_msg.regs[0] = svc_name.len() as u64;
            reg_msg.length = 1 + (svc_name.len() as u64 + 7) / 8;
            let dst = &raw mut reg_msg.regs[1] as *mut u8;
            for i in 0..svc_name.len() {
                *dst.add(i) = svc_name[i];
            }
            reg_msg.regs[2] = 0;
            reg_msg.regs[3] = 0;
            ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
            let err = ipc::call_ctx(
                ipc_ctx(),
                CAP_NAMESERV_EP,
                &raw const reg_msg,
                &raw mut reg_reply,
            );
            if err == 0 && reg_reply.label == BESALT_OK {
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
        let mut msg = BesaltMsg::zeroed();
        let mut badge: u64 = 0;

        besalt::invoke::cnode_delete(CAP_SELF_CSPACE, CAP_RECV_SCRATCH);
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_RECV_SCRATCH, 0);

        let err = besalt::ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge);
        if err != 0 {
            puts(b"[PROCMGR] initial recv failed\n");
            idle();
        }

        // Server loop
        loop {
            let mut reply = BesaltMsg::zeroed();
            let mut skip_reply = false;
            // Bound notification delivery: label=0 and badge!=0 means the
            // kernel delivered a notification word instead of an IPC message.
            // Upper 16 bits: CSpace expansion.
            if msg.label == 0 && badge != 0 {
                let cs_bits = (badge >> 16) & 0xFFFF;
                if cs_bits != 0 {
                    cspace::handle_cspace_expand_ntfn(cs_bits);
                }
                skip_reply = true;
            } else {
                match msg.label {
                    PM_SPAWN => spawn_tx::handle_spawn_tx(
                        &msg,
                        &mut reply,
                        badge,
                        &mut *(&raw mut ALLOCATOR),
                    ),
                    PM_EXIT => {
                        exit_wait::handle_exit(&msg, &mut reply, badge);
                        skip_reply = true;
                    }
                    PM_WAIT => {
                        skip_reply = exit_wait::handle_wait(&msg, &mut reply, badge);
                    }
                    PM_GETPID => handle_getpid(&mut reply, badge),
                    PM_FORK => fork_exec::handle_fork(&msg, &mut reply, badge),
                    PM_EXEC => {
                        fork_exec::handle_exec(&msg, &mut reply, badge);
                        if reply.label == 0 {
                            skip_reply = true;
                        }
                    }
                    PM_GETPPID => handle_getppid(&mut reply, badge),
                    PM_KILL => signal::handle_kill(&msg, &mut reply, badge),
                    PM_KILL_PGID => signal::handle_kill_pgid(&msg, &mut reply),
                    PM_INJECT_CAP => signal::handle_inject_cap(&msg, &mut reply),
                    PM_RESUME => signal::handle_resume(&msg, &mut reply),
                    PM_SIGACTION => signal::handle_sigaction(&msg, &mut reply, badge),
                    PM_GETUID => session::handle_getuid(&mut reply, badge),
                    PM_GETGID => session::handle_getgid(&mut reply, badge),
                    PM_SETPGID => session::handle_setpgid(&msg, &mut reply, badge),
                    PM_GETPGID => session::handle_getpgid(&msg, &mut reply, badge),
                    PM_SETSID => session::handle_setsid(&mut reply, badge),
                    PM_GETSID => session::handle_getsid(&msg, &mut reply, badge),
                    PM_GETEUID => session::handle_geteuid(&mut reply, badge),
                    PM_GETEGID => session::handle_getegid(&mut reply, badge),
                    PM_GETGROUPS => session::handle_getgroups(&mut reply),
                    PM_EXPAND_CSPACE => cspace::handle_expand_cspace(&msg, &mut reply, badge),
                    PM_EXPAND_CSPACE_ASYNC => {
                        cspace::handle_expand_cspace_async(&msg, badge);
                        skip_reply = true;
                    }
                    PM_EXPAND_COLLECT => cspace::handle_expand_collect(&mut reply, badge),
                    PM_REGISTER => cspace::handle_register(&msg, &mut reply, badge),
                    PM_GETPGID_BADGE => session::handle_getpgid_badge(&msg, &mut reply),
                    PM_GETSID_BADGE => session::handle_getsid_badge(&msg, &mut reply),
                    PM_LIST_PIDS => handle_list_pids(&mut reply),
                    PM_GET_PROC_INFO => handle_get_proc_info(&msg, &mut reply),
                    PM_UMASK => handle_umask(&msg, &mut reply, badge),
                    _ => {
                        let mut lb = LineBuf::new();
                        lb.str(b"[PROCMGR] unknown label=");
                        lb.hex(msg.label);
                        lb.str(b"\n");
                        lb.flush();
                        reply.label = BESALT_INVALID_OPERATION;
                    }
                }
            } // end else (notification vs IPC dispatch)

            besalt::invoke::cnode_delete(CAP_SELF_CSPACE, CAP_RECV_SCRATCH);
            ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_RECV_SCRATCH, 0);

            let err = if skip_reply {
                besalt::ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, &raw mut msg, &raw mut badge)
            } else {
                besalt::ipc::reply_recv_ctx(
                    ipc_ctx(),
                    CAP_SERVER_EP,
                    &raw const reply,
                    &raw mut msg,
                    &raw mut badge,
                )
            };
            if err != 0 {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] reply_recv failed err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
                break;
            }
        }
    }

    idle();
}

fn idle() -> ! {
    loop {
        besalt::syscall::syscall(besalt::SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
