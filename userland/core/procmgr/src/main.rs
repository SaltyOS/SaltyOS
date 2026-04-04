//! SaltyOS Process Manager
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Panic handler provided by libtrona.so (dynamic linking).

#![no_std]
#![no_main]

mod alloc;
mod cspace;
mod fork_exec;
mod posix;
mod proc_table;
mod readiness;
mod spawn_tx;
mod vfs_load;

use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use proc_table::{
    find_by_badge, find_by_pid, init_proctab, proctab, proctab_cap,
    MAX_NAME_LEN, PROC_FREE,
};

// ---- Cap layout (set by init for this process) ----
const CAP_SELF_TCB: Cap = 0;
const CAP_SELF_VSPACE: Cap = 1;
const CAP_SELF_CSPACE: Cap = 2;
const CAP_SERVER_EP: Cap = 3;
const CAP_UNTYPED: Cap = 7;
const CAP_NAMESRV_EP: Cap = 64; // NeedEP namesrv:64
const CAP_VFS_EP: Cap = 65; // NeedEP vfs:65
const CAP_FB_UNTYPED: Cap = 66; // CopyCap 13:66
const CAP_INITRD_UNTYPED: Cap = 12;
const CAP_RECV_SCRATCH: Cap = 15; // Scratch slot for receiving transferred caps
const CAP_REPLY_TEMP: Cap = 86; // Temporary reply cap for timed receive path
const CAP_UNTYPED_START: Cap = 16;

const VSPACE_WALK_BATCH: u64 = 48;

const TRONA_PENDING: u64 = 0x80;

use trona::layout::{self};

const CHILD_RTLD_FRAME_SLOT_START: u64 = 64;
const PROCMGR_SCRATCH_VADDR: u64 = 0x0000_0000_0500_0000;

// ---- Child CNode layout ----
const CHILD_CAP_TCB: u64 = 0;
const CHILD_CAP_VSPACE: u64 = 1;
const CHILD_CAP_CSPACE: u64 = 2;
const CHILD_CAP_EP: u64 = 3;
const CHILD_CAP_VFS: u64 = 4;
const CHILD_CAP_NAMESRV: u64 = 5;
const CHILD_CAP_SIGNAL_NTFN: u64 = 6;
const CHILD_CAP_MMSRV_EP: u64 = 7;
const CHILD_CAP_SC: u64 = 9;
const CHILD_CAP_READINESS_NTFN: u64 = 14;
const CHILD_CAP_SERVICE_EP: u64 = 68; // Pre-created service EP
const CHILD_CAP_WIN32SRV_EP: u64 = 69; // win32/csrss EP for PE processes
const CAP_READINESS_NTFN: u64 = 14; // Self readiness notification
const READY_SIGNAL_BITS: u64 = 1;
const READY_TIMEOUT_NS_DEFAULT: u64 = 10_000_000_000; // 10s
const READY_POLL_QUANTUM_NS: u64 = 1_000_000; // 1ms

// ---- Auxiliary vector types ----
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_TRONA_VSPACE: u64 = 0x1001;
const AT_TRONA_SCRATCH: u64 = 0x1002;
const AT_TRONA_INITRD: u64 = 0x1003;
const AT_TRONA_INITRD_SZ: u64 = 0x1004;
const AT_TRONA_FRAME_SLOT: u64 = 0x1005;
const AT_TRONA_SHARED_LIB_BASE: u64 = 0x1006;
const AT_TRONA_SLOT_BASE: u64 = 0x1007;
const AT_TRONA_SLOT_COUNT: u64 = 0x1008;
const AT_TRONA_CSPACE_NTFN: u64 = 0x100A;
const AT_TRONA_MM_EP: u64 = 0x100B;
const AT_TRONA_IPC_BUFFER: u64 = 0x100C;
const AT_TRONA_SC_CAP: u64 = 0x100E;
const AT_SALTYOS_PE_BASE: u64 = 0x2000;
const AT_SALTYOS_PE_SIZE: u64 = 0x2001;
const AT_SALTYOS_WIN32SRV: u64 = 0x2002;
const AT_SALTYOS_KERNEL32_BASE: u64 = 0x2003;
const AT_SALTYOS_KERNEL32_SIZE: u64 = 0x2004;

// ---- Shorthand re-exports ----
const OBJ_TCB: u64 = trona::OBJ_TCB;
const OBJ_UNTYPED: u64 = trona::OBJ_UNTYPED;
const OBJ_VSPACE: u64 = trona::OBJ_VSPACE;
const OBJ_CNODE: u64 = trona::OBJ_CNODE;
const OBJ_SCHED_CONTEXT: u64 = trona::OBJ_SCHED_CONTEXT;
const OBJ_NOTIFICATION: u64 = trona::OBJ_NOTIFICATION;
const TRONA_OK: u64 = trona::TRONA_OK;
const TRONA_OUT_OF_MEMORY: u64 = trona::TRONA_OUT_OF_MEMORY;
const TRONA_NOT_FOUND: u64 = trona::TRONA_NOT_FOUND;
const TRONA_OUT_OF_RANGE: u64 = trona::TRONA_OUT_OF_RANGE;
const TRONA_INVALID_ARGUMENT: u64 = trona::TRONA_INVALID_ARGUMENT;
const TRONA_INVALID_OPERATION: u64 = trona::TRONA_INVALID_OPERATION;
const TRONA_WOULD_BLOCK: u64 = trona::TRONA_WOULD_BLOCK;
const TRONA_CANCELLED: u64 = trona::TRONA_CANCELLED;
const VSPACE_FLAG_WRITABLE: u64 = trona::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = trona::VSPACE_FLAG_USER;
const CAP_RIGHTS_ALL: u64 = trona::CAP_RIGHTS_ALL;
const INITRD_COPY_RIGHTS: u64 = (1 << 0) | (1 << 2) | (1 << 3);
const UT_MIRROR_COUNT: Cap = 16;
const INITRD_VADDR: u64 = trona::INITRD_VADDR;
const BOOTINFO_VADDR: u64 = trona::BOOTINFO_VADDR;
const BOOTINFO_MAGIC: u64 = trona::BOOTINFO_MAGIC;

// ---- CSpace expansion via bound notification ----
const CHILD_CAP_CSPACE_NTFN: u64 = 10; // Minted notification for CSpace expansion signaling
const CSPACE_EXPAND_BASE: u64 = trona::consts::CSPACE_EXPAND_BASE;
const MAX_CSPACE_EXPANSIONS: usize = trona::consts::MAX_CSPACE_EXPANSIONS;
const CSPACE_EXPAND_BITS: u64 = 10; // 1024 slots per expansion sub-CNode

/// Procmgr's bound notification cap (for receiving CSpace expansion signals).
static mut PM_BOUND_NTFN: Cap = 0;
/// TCB to resume after the current caller has been replied to.
static mut POST_REPLY_RESUME_TCB: Cap = 0;

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

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

fn signal_ready() {
    let _ = trona::syscall::syscall(trona::SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
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
fn extract_name(msg: &TronaMsg, name_reg_idx: usize) -> ([u8; MAX_NAME_LEN + 5], usize) {
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

// ===========================================================================
// handle_getpid / handle_getppid
// ===========================================================================

unsafe fn handle_getpid(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = TRONA_NOT_FOUND;
        return;
    };
    reply.label = TRONA_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { proctab(idx).pid as u64 };
}

unsafe fn handle_getppid(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = TRONA_NOT_FOUND;
        return;
    };
    reply.label = TRONA_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { proctab(idx).ppid as u64 };
}

unsafe fn handle_get_thread_caps(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = TRONA_NOT_FOUND;
        return;
    };
    reply.label = TRONA_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { proctab(idx).sc_cap };
}

/// List all active PIDs.
/// Reply: regs[0..18] = PIDs (up to 18), regs[19] = count.
unsafe fn handle_list_pids(reply: &mut TronaMsg) {
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
        reply.label = TRONA_OK;
        reply.length = 20;
    }
}

unsafe fn recv_with_timer(
    msg: *mut TronaMsg,
    badge: *mut u64,
) -> i32 {
    unsafe {
        let has_timers = posix::timer::has_pending_timers();
        let has_readiness = readiness::has_pending_readiness();
        if has_timers || has_readiness {
            let now = trona::syscall::syscall(
                trona::SYS_CLOCK_GETTIME,
                trona::consts::CLOCK_REALTIME as u64,
                0, 0, 0, 0, 0,
            );
            if now.error == 0 {
                let timer_deadline = if has_timers {
                    posix::timer::nearest_deadline_ns()
                } else {
                    u64::MAX
                };
                let ready_deadline = if has_readiness {
                    readiness::nearest_readiness_deadline_ns()
                } else {
                    u64::MAX
                };
                let deadline = timer_deadline.min(ready_deadline);

                if deadline <= now.value {
                    if !msg.is_null() {
                        *msg = TronaMsg::zeroed();
                    }
                    if !badge.is_null() {
                        *badge = 1;
                    }
                    return 0;
                }

                let mut timeout = deadline.saturating_sub(now.value).max(100_000);
                // Child readiness notifications are polled, not bound to procmgr's
                // TCB, so they do not wake recv_timed directly. Cap the sleep so the
                // main loop periodically re-polls readiness even when no IPC arrives.
                if has_readiness {
                    timeout = timeout.min(READY_POLL_QUANTUM_NS);
                }
                let err = trona::ipc::recv_timed_ctx(
                    ipc_ctx(),
                    CAP_SERVER_EP,
                    timeout,
                    msg,
                    badge,
                );
                if err as u64 == TRONA_CANCELLED {
                    if !msg.is_null() {
                        *msg = TronaMsg::zeroed();
                    }
                    if !badge.is_null() {
                        *badge = 1;
                    }
                    return 0;
                }
                return err;
            }

            // If the clock read failed, keep making progress on deferred timers /
            // readiness with a short timed receive instead of blocking forever.
            let timeout = if has_readiness {
                READY_POLL_QUANTUM_NS
            } else {
                100_000
            };
            let err = trona::ipc::recv_timed_ctx(
                ipc_ctx(),
                CAP_SERVER_EP,
                timeout,
                msg,
                badge,
            );
            if err as u64 == TRONA_CANCELLED {
                if !msg.is_null() {
                    *msg = TronaMsg::zeroed();
                }
                if !badge.is_null() {
                    *badge = 1;
                }
                return 0;
            }
            return err;
        }

        trona::ipc::recv_ctx(ipc_ctx(), CAP_SERVER_EP, msg, badge)
    }
}

unsafe fn run_post_reply_work() {
    unsafe {
        let tcb = POST_REPLY_RESUME_TCB;
        if tcb == 0 {
            return;
        }

        let mut pid = 0u32;
        for i in 0..proctab_cap() {
            if proctab(i).state != PROC_FREE && proctab(i).tcb_cap == tcb {
                pid = proctab(i).pid;
                break;
            }
        }

        POST_REPLY_RESUME_TCB = 0;
        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] deferred resume begin pid=");
            _lb.hex(pid as u64);
            _lb.str(b" tcb=");
            _lb.hex(tcb);
            _lb.str(b"\n");
        });
        let err = trona::invoke::tcb_resume(tcb);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] deferred resume failed err=");
                _lb.hex(err as u64);
                _lb.str(b" tcb=");
                _lb.hex(tcb);
                _lb.str(b"\n");
            });
        } else {
            trona::udebug!(|_lb| {
                _lb.str(b"[PROCMGR] deferred resume ok pid=");
                _lb.hex(pid as u64);
                _lb.str(b" tcb=");
                _lb.hex(tcb);
                _lb.str(b"\n");
            });
        }
    }
}

/// Get process info for a given PID.
/// Request: regs[0] = pid
/// Reply: regs[0]=pid, regs[1]=ppid, regs[2]=pgid, regs[3]=sid,
///        regs[4]=state, regs[5..9]=name(32B)
unsafe fn handle_get_proc_info(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        let Some(idx) = proc_table::find_by_pid(pid) else {
            reply.label = TRONA_NOT_FOUND;
            return;
        };
        let p = &*proc_table::proctab(idx);
        reply.regs[0] = p.pid as u64;
        reply.regs[1] = p.ppid as u64;
        reply.regs[2] = p.posix().pgid as u64;
        reply.regs[3] = p.posix().sid as u64;
        reply.regs[4] = p.state as u64;
        // Pack name (32 bytes = 4 u64s) into regs[5..9]
        let dst = &mut reply.regs[5] as *mut u64 as *mut u8;
        for i in 0..32 {
            *dst.add(i) = p.name[i];
        }
        reply.label = TRONA_OK;
        reply.length = 9;
    }
}



// ===========================================================================
// handle_request_untyped
// ===========================================================================

/// PM_REQUEST_UNTYPED: mmsrv requests a sub-untyped when its sources are
/// exhausted.
///   msg.regs[0] = desired sub-untyped size_bits (e.g. 28 = 256 MB)
/// Reply sends the sub-untyped cap via extra_caps (1 cap transferred).
unsafe fn handle_request_untyped(
    msg: &TronaMsg,
    reply: &mut TronaMsg,
    allocator: &mut alloc::Allocator,
) {
    unsafe {
        let requested_bits = msg.regs[0];
        // Clamp size_bits: minimum 20 (1 MB), maximum 30 (1 GB)
        let size_bits = if requested_bits < 20 {
            20
        } else if requested_bits > 30 {
            30
        } else {
            requested_bits
        };

        // Allocate a temporary slot for the sub-untyped
        let temp_slot = match allocator.alloc_single_slot() {
            Some(s) => s,
            None => {
                reply.label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        // Try the requested size first, then fall back to smaller sizes
        let mut actual_bits = size_bits;
        let mut success = false;
        while actual_bits >= 20 {
            let err = allocator.retype_any(OBJ_UNTYPED, actual_bits, temp_slot);
            if err == 0 {
                success = true;
                break;
            }
            actual_bits -= 1;
        }

        if !success {
            allocator.free_single_slot(temp_slot);
            reply.label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // Stage the sub-untyped cap for transfer via IPC extra_caps
        ipc::set_send_cap_ctx(ipc_ctx(), 0, temp_slot);

        reply.label = TRONA_OK;
        reply.length = 1;
        reply.regs[0] = actual_bits;

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] Provisioned sub-untyped 2^");
            _lb.hex(actual_bits);
            _lb.str(b" to mmsrv\n");
        });
    }
}

// ===========================================================================
// Entry point
// ===========================================================================

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona::uinfo!(|_lb| {
        _lb.str(b"[PROCMGR] SaltyOS process manager starting\n");
    });

    unsafe {
        // Initialize process table (allocates via mmsrv)
        init_proctab();
        trona::uinfo!(|_lb| {
            _lb.str(b"[PROCMGR] process table ready\n");
        });

        // Initialize the centralized allocator
        (*(&raw mut ALLOCATOR)).init(
            CAP_SELF_CSPACE,
            CAP_UNTYPED,
            CAP_UNTYPED_START,
            UT_MIRROR_COUNT as usize,
        );
        trona::uinfo!(|_lb| {
            _lb.str(b"[PROCMGR] allocator ready\n");
        });

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
                    trona::uwarn!(|_lb| {
                        _lb.str(b"[PROCMGR] WARN: could not alloc slot for bound ntfn\n");
                    });
                    0
                }
            };
            if ntfn_slot != 0 {
                // Request notification object from mmsrv (centralized allocator)
                trona::ipc::set_receive_slot_ctx(
                    ipc_ctx(),
                    CAP_SELF_CSPACE,
                    ntfn_slot,
                    0,
                );
                let mut mm_msg = trona::types::TronaMsg::zeroed();
                let mut mm_reply = trona::types::TronaMsg::zeroed();
                mm_msg.label = trona::protocol::MM_ALLOC_OBJECT;
                mm_msg.length = 2;
                mm_msg.regs[0] = OBJ_NOTIFICATION;
                mm_msg.regs[1] = 0;
                let err = trona::ipc::call_ctx(
                    ipc_ctx(),
                    CAP_MMSRV_EP,
                    &raw const mm_msg,
                    &raw mut mm_reply,
                );
                let alloc_ok = err == 0 && mm_reply.label == trona::TRONA_OK;
                if !alloc_ok {
                    trona::uwarn!(|_lb| {
                        _lb.str(b"[PROCMGR] WARN: alloc notification from mmsrv failed\n");
                    });
                    alloc.free_single_slot(ntfn_slot);
                } else {
                    let err = trona::invoke::tcb_bind_notification(CAP_SELF_TCB, ntfn_slot);
                    if err != 0 {
                        trona::uwarn!(|_lb| {
                            _lb.str(b"[PROCMGR] WARN: bind notification failed\n");
                        });
                    } else {
                        *(&raw mut PM_BOUND_NTFN) = ntfn_slot;
                        trona::uinfo!(|_lb| {
                            _lb.str(b"[PROCMGR] bound notification ready for CSpace expansion\n");
                        });
                    }
                }
            }
        }

        // Signal ready BEFORE registration — init needs to proceed to spawn namesrv.
        // The registration Call will block in the EP send queue until namesrv starts.
        signal_ready();

        // Register with namesrv — blocks until namesrv Recv()s
        if CAP_NAMESRV_EP != 0 {
            let mut reg_msg = TronaMsg::zeroed();
            let mut reg_reply = TronaMsg::zeroed();
            let svc_name = b"procmgr";
            reg_msg.label = trona::protocol::NS_REGISTER;
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
                CAP_NAMESRV_EP,
                &raw const reg_msg,
                &raw mut reg_reply,
            );
            if err == 0 && reg_reply.label == TRONA_OK {
                trona::uinfo!(|_lb| {
                    _lb.str(b"[PROCMGR] registered with namesrv\n");
                });
            } else {
                trona::uwarn!(|_lb| {
                    _lb.str(b"[PROCMGR] WARN: namesrv registration failed\n");
                });
            }
        }

        // Initial recv
        let mut msg = TronaMsg::zeroed();
        let mut badge: u64 = 0;

        trona::invoke::cnode_delete(CAP_SELF_CSPACE, CAP_RECV_SCRATCH);
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_RECV_SCRATCH, 0);

        let err = recv_with_timer(&raw mut msg, &raw mut badge);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] initial recv failed\n");
            });
            idle();
        }

        // Server loop
        loop {
            posix::timer::process_expired_timers();
            readiness::check_pending_readiness();

            let mut reply = TronaMsg::zeroed();
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
                // Try POSIX subsystem dispatch first (includes subsystem guard).
                if let Some(posix_skip) = posix::dispatch_posix(msg.label, &msg, &mut reply, badge) {
                    if !posix::is_posix_caller(badge) {
                        reply.label = TRONA_INVALID_OPERATION;
                    } else {
                        skip_reply = posix_skip;
                    }
                } else {
                // Subsystem-neutral handlers
                match msg.label {
                    PM_SPAWN => {
                        if spawn_tx::handle_spawn_tx(
                            &msg,
                            &mut reply,
                            badge,
                            &mut *(&raw mut ALLOCATOR),
                        ) {
                            skip_reply = true;
                        }
                    }
                    PM_EXIT => {
                        posix::exit_wait::handle_exit(&msg, &mut reply, badge);
                        skip_reply = true;
                    }
                    PM_GETPID => handle_getpid(&mut reply, badge),
                    PM_GETPPID => handle_getppid(&mut reply, badge),
                    PM_INJECT_CAP => posix::signal::handle_inject_cap(&msg, &mut reply),
                    PM_RESUME => {
                        if posix::signal::handle_resume(&msg, &mut reply) {
                            skip_reply = true;
                        }
                    }
                    PM_EXPAND_CSPACE => cspace::handle_expand_cspace(&msg, &mut reply, badge),
                    PM_EXPAND_CSPACE_ASYNC => {
                        cspace::handle_expand_cspace_async(&msg, badge);
                        skip_reply = true;
                    }
                    PM_EXPAND_COLLECT => cspace::handle_expand_collect(&mut reply, badge),
                    PM_REGISTER => cspace::handle_register(&msg, &mut reply, badge),
                    PM_LIST_PIDS => handle_list_pids(&mut reply),
                    PM_GET_PROC_INFO => handle_get_proc_info(&msg, &mut reply),
                    PM_REQUEST_UNTYPED => handle_request_untyped(&msg, &mut reply, &mut *(&raw mut ALLOCATOR)),
                    PM_GET_THREAD_CAPS => handle_get_thread_caps(&mut reply, badge),
                    PM_DUMP_PENDING => {
                        trona::uinfo!(|_lb| {
                            _lb.str(b"[PROCMGR] dump: POST_REPLY_RESUME_TCB=");
                            _lb.hex(*(&raw const POST_REPLY_RESUME_TCB));
                            _lb.str(b" has_timers=");
                            _lb.dec(if posix::timer::has_pending_timers() { 1 } else { 0 });
                            _lb.str(b" has_readiness=");
                            _lb.dec(if readiness::has_pending_readiness() { 1 } else { 0 });
                            _lb.str(b"\n");
                        });
                        reply.label = TRONA_OK;
                    }
                    _ => {
                        trona::uerror!(|_lb| {
                            _lb.str(b"[PROCMGR] unknown label=");
                            _lb.hex(msg.label);
                            _lb.str(b"\n");
                        });
                        reply.label = TRONA_INVALID_OPERATION;
                    }
                }
                } // end non-posix dispatch
            } // end else (notification vs IPC dispatch)

            trona::invoke::cnode_delete(CAP_SELF_CSPACE, CAP_RECV_SCRATCH);
            ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_RECV_SCRATCH, 0);

            let err = if skip_reply {
                recv_with_timer(&raw mut msg, &raw mut badge)
            } else if POST_REPLY_RESUME_TCB != 0
                || posix::timer::has_pending_timers()
                || readiness::has_pending_readiness()
            {
                let has_post_reply_resume = POST_REPLY_RESUME_TCB != 0;
                if has_post_reply_resume {
                    trona::udebug!(|_lb| {
                        _lb.str(b"[PROCMGR] reply-before-post-work begin label=");
                        _lb.hex(msg.label);
                        _lb.str(b" badge=");
                        _lb.hex(badge);
                        _lb.str(b"\n");
                    });
                }
                let save_err = trona::invoke::cnode_save_caller(CAP_SELF_CSPACE, CAP_REPLY_TEMP);
                if save_err != 0 {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] save_caller failed for timed recv err=");
                        _lb.hex(save_err as u64);
                        _lb.str(b"\n");
                    });
                    break;
                }
                let send_err = trona::ipc::send_ctx(ipc_ctx(), CAP_REPLY_TEMP, &raw const reply);
                trona::invoke::cnode_delete(CAP_SELF_CSPACE, CAP_REPLY_TEMP);
                if send_err != 0 {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] reply send failed before timed recv err=");
                        _lb.hex(send_err as u64);
                        _lb.str(b"\n");
                    });
                    break;
                }
                if has_post_reply_resume {
                    trona::udebug!(|_lb| {
                        _lb.str(b"[PROCMGR] reply-before-post-work sent label=");
                        _lb.hex(msg.label);
                        _lb.str(b" badge=");
                        _lb.hex(badge);
                        _lb.str(b"\n");
                    });
                }
                run_post_reply_work();
                recv_with_timer(&raw mut msg, &raw mut badge)
            } else {
                trona::ipc::reply_recv_ctx(
                    ipc_ctx(),
                    CAP_SERVER_EP,
                    &raw const reply,
                    &raw mut msg,
                    &raw mut badge,
                )
            };
            if err != 0 {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] reply_recv failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                break;
            }
        }
    }

    1
}

fn idle() -> ! {
    loop {
        trona::syscall::syscall(trona::SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
