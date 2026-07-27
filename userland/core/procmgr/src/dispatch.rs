//! Process manager IPC dispatch.
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::{KinfoProc, TronaMsg};
use trona_protocol::posix::*;

use crate::base::proc_table::{self, ProcessState, find_by_badge};
use crate::base::readiness;
use crate::lifecycle::thread;
use crate::personality::posix;
use crate::service::registry as service_registry;
use crate::{
    ALLOCATOR, POST_REPLY_RESUME_COUNT, TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION,
    TRONA_NOT_FOUND, TRONA_OK, personality,
};

unsafe fn handle_getpid(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = TRONA_NOT_FOUND;
        return;
    };
    reply.label = TRONA_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { proc_table::proctab(idx).pid as u64 };
}

unsafe fn handle_getppid(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = TRONA_NOT_FOUND;
        return;
    };
    reply.label = TRONA_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { proc_table::proctab(idx).ppid as u64 };
}

unsafe fn handle_get_thread_caps(reply: &mut TronaMsg, badge: u64) {
    let Some(idx) = find_by_badge(badge) else {
        reply.label = TRONA_NOT_FOUND;
        return;
    };
    reply.label = TRONA_OK;
    reply.length = 1;
    reply.regs[0] = unsafe { proc_table::proctab(idx).cap_layout.sc };
}

unsafe fn handle_list_pids(reply: &mut TronaMsg) {
    unsafe {
        let cap = proc_table::proctab_cap();
        let mut count: usize = 0;
        for i in 0..cap {
            let p = &*proc_table::proctab(i);
            if p.state != ProcessState::Free && count < 19 {
                reply.regs[count] = p.pid as u64;
                count += 1;
            }
        }
        reply.regs[19] = count as u64;
        reply.label = TRONA_OK;
        reply.length = 20;
    }
}

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
        reply.regs[2] = p.pgid as u64;
        reply.regs[3] = p.sid as u64;
        reply.regs[4] = p.state as u64;
        let dst = &mut reply.regs[5] as *mut u64 as *mut u8;
        for i in 0..32 {
            *dst.add(i) = p.name[i];
        }
        reply.regs[9] = p.start_time_ns;
        reply.regs[10] = p.ctty_dev;
        reply.regs[11] = p.ctty_pgrp as u64;
        reply.label = TRONA_OK;
        reply.length = 12;
    }
}

/// INIT_GET_PROC_TIMES: sum per-thread CPU runtime for a pid.
/// Request: regs[0] = pid
/// Reply: regs[0]=user_time_ns, regs[1]=system_time_ns, regs[2]=num_threads,
///        regs[3]=start_time_ns
unsafe fn handle_get_proc_times(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        let Some(idx) = proc_table::find_by_pid(pid) else {
            reply.label = TRONA_NOT_FOUND;
            return;
        };
        let p = &*proc_table::proctab(idx);

        // Live runtime from the primary TCB.
        let (main_ut, main_st) = if p.tcb_cap != 0 {
            trona_kernel::invoke::tcb_get_cpu_times_ctx(trona_runtime::current_ipc_ctx(), p.tcb_cap)
                .unwrap_or((0, 0))
        } else {
            // Process has exited: use the snapshot taken at exit time.
            (p.exit.exit_user_time_ns, p.exit.exit_system_time_ns)
        };

        // Add runtime from already-reaped auxiliary threads.
        let total_ut = main_ut.saturating_add(p.dead_thread_user_time_ns);
        let total_st = main_st.saturating_add(p.dead_thread_system_time_ns);

        // Add live auxiliary thread runtime.
        let mut num_threads: u32 = 1; // primary
        let (mut aux_ut, mut aux_st) = (0u64, 0u64);
        for i in 0..proc_table::MAX_THREADS_PER_PROC {
            let e = &p.threads.entries[i];
            if e.state == proc_table::ThreadState::Unused {
                continue;
            }
            num_threads += 1;
            if e.tcb_cap != 0 {
                if let Some((ut, st)) = trona_kernel::invoke::tcb_get_cpu_times_ctx(
                    trona_runtime::current_ipc_ctx(),
                    e.tcb_cap,
                ) {
                    aux_ut = aux_ut.saturating_add(ut);
                    aux_st = aux_st.saturating_add(st);
                }
            }
        }

        reply.regs[0] = total_ut.saturating_add(aux_ut);
        reply.regs[1] = total_st.saturating_add(aux_st);
        reply.regs[2] = num_threads as u64;
        reply.regs[3] = p.start_time_ns;
        reply.label = TRONA_OK;
        reply.length = 4;
    }
}

/// INIT_GET_SYSTEM_STATS: aggregate process-table counts.
/// Request: no payload.
/// Reply: regs[0]=procs_total, regs[1]=procs_running, regs[2]=last_pid
unsafe fn handle_get_system_stats(reply: &mut TronaMsg) {
    unsafe {
        let cap = proc_table::proctab_cap();
        let mut procs_total: u64 = 0;
        let mut procs_running: u64 = 0;
        let mut last_pid: u32 = 0;
        for i in 0..cap {
            let p = &*proc_table::proctab(i);
            if p.state == proc_table::ProcessState::Free {
                continue;
            }
            procs_total += 1;
            if p.state == proc_table::ProcessState::Running {
                procs_running += 1;
            }
            if p.pid > last_pid {
                last_pid = p.pid;
            }
        }
        reply.regs[0] = procs_total;
        reply.regs[1] = procs_running;
        reply.regs[2] = last_pid as u64;
        reply.label = TRONA_OK;
        reply.length = 3;
    }
}

/// INIT_GET_KINFO_PROC: return a KinfoProc snapshot via the IPC buffer reserved area.
/// Request: regs[0] = pid
/// Reply: IPC buffer reserved region holds a KinfoProc; regs[0] = sizeof(KinfoProc)
unsafe fn handle_get_kinfo_proc(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        let Some(idx) = proc_table::find_by_pid(pid) else {
            reply.label = TRONA_NOT_FOUND;
            return;
        };
        let p = &*proc_table::proctab(idx);

        let mut ki = KinfoProc::zeroed();
        ki.size = core::mem::size_of::<KinfoProc>() as u32;
        ki.pid = p.pid;
        ki.ppid = p.ppid;
        ki.pgid = p.pgid;
        ki.sid = p.sid;
        ki.tpgid = p.ctty_pgrp;
        ki.tty_dev = p.ctty_dev as u32;
        ki.state = p.state as u8;
        ki.start_time_ns = p.start_time_ns;
        ki.num_threads = 1 + p.threads.count as u32;

        // Credential fields (POSIX only).
        if p.is_posix() {
            let ps = p.posix();
            ki.uid = ps.uid;
            ki.gid = ps.gid;
            ki.euid = ps.euid;
            ki.egid = ps.egid;
        }

        // CPU runtime in nanoseconds.
        let (main_ut, main_st) = if p.tcb_cap != 0 {
            trona_kernel::invoke::tcb_get_cpu_times_ctx(trona_runtime::current_ipc_ctx(), p.tcb_cap)
                .unwrap_or((0, 0))
        } else {
            (p.exit.exit_user_time_ns, p.exit.exit_system_time_ns)
        };
        ki.user_time_ns = main_ut.saturating_add(p.dead_thread_user_time_ns);
        ki.system_time_ns = main_st.saturating_add(p.dead_thread_system_time_ns);

        // Process name (both p.name and ki.comm are [u8; 32]).
        for i in 0..32 {
            ki.comm[i] = p.name[i];
        }

        if let Ok(vm) = crate::base::mmsrv_ipc::get_client_vm_snapshot(p.pid) {
            ki.vm_size = vm.vm_reserved_bytes;
            ki.vm_rss = vm.vm_resident_pages.saturating_mul(4096);
        }

        // Write KinfoProc into the IPC buffer reserved area.
        let ctx = &*crate::ipc_ctx();
        if !ctx.ipc_buffer.is_null() {
            let dst = (*ctx.ipc_buffer).reserved.as_mut_ptr() as *mut KinfoProc;
            core::ptr::write(dst, ki);
        }

        reply.regs[0] = core::mem::size_of::<KinfoProc>() as u64;
        reply.label = TRONA_OK;
    }
}

/// INIT_GET_CLIENT_VM_STATS: fetch a per-pid memory-accounting snapshot.
/// Request: regs[0] = pid
/// Reply: IPC buffer reserved area holds one `TronaProcMemSnapshot`;
/// `regs[0] = sizeof(TronaProcMemSnapshot)`.
unsafe fn handle_get_client_vm_stats(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        if proc_table::find_by_pid(pid).is_none() {
            reply.label = TRONA_NOT_FOUND;
            return;
        }
        let snap = match crate::base::mmsrv_ipc::get_client_vm_snapshot(pid) {
            Ok(s) => s,
            Err(e) => {
                reply.label = e;
                return;
            }
        };

        let ctx = &*crate::ipc_ctx();
        if ctx.ipc_buffer.is_null() {
            reply.label = TRONA_INVALID_OPERATION;
            return;
        }
        let dst = (*ctx.ipc_buffer).reserved.as_mut_ptr()
            as *mut trona_kernel::core_types::sysinfo::TronaProcMemSnapshot;
        core::ptr::write(dst, snap);
        reply.regs[0] =
            core::mem::size_of::<trona_kernel::core_types::sysinfo::TronaProcMemSnapshot>() as u64;
        reply.label = TRONA_OK;
        reply.length = 1;
    }
}

/// INIT_KILL_OOM_VICTIM: mmsrv has selected `regs[0] = pid` as the
/// OOM victim. Deliver `SIGKILL` through the standard POSIX signal
/// path; Win32 personalities follow the same termination machinery.
/// Reply: `TRONA_OK` on success, `TRONA_NOT_FOUND` when the pid is
/// already gone.
unsafe fn handle_kill_oom_victim(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        match proc_table::find_by_pid(pid) {
            Some(idx) => {
                crate::personality::posix::signal::terminate_proc(
                    idx,
                    crate::personality::posix::PM_SIGKILL,
                );
                reply.label = TRONA_OK;
            }
            None => {
                reply.label = TRONA_NOT_FOUND;
            }
        }
        reply.label = TRONA_OK;
        reply.length = 1;
    }
}

/// INIT_LIST_PIDS_BUF: paginated pid listing via IPC buffer reserved area.
/// Request: regs[0]=offset, regs[1]=max_requested
/// Reply: regs[0]=count_returned, regs[1]=total; pids as u32[] in reserved area
unsafe fn handle_list_pids_buf(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let offset = msg.regs[0] as usize;
        let max_requested = msg.regs[1] as usize;
        let cap = proc_table::proctab_cap();

        // First pass: count total live processes.
        let mut total: usize = 0;
        for i in 0..cap {
            let p = &*proc_table::proctab(i);
            if p.state != proc_table::ProcessState::Free {
                total += 1;
            }
        }

        // Second pass: collect pids from `offset`, up to `max_requested`.
        let ctx = &*crate::ipc_ctx();
        if ctx.ipc_buffer.is_null() {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }
        let reserved_bytes = trona_kernel::core_types::core::IPC_BUFFER_RESERVED_BYTES;
        let max_pids = reserved_bytes / 4; // u32 per pid
        let max_count = if max_requested == 0 || max_requested > max_pids {
            max_pids
        } else {
            max_requested
        };

        let dst = (*ctx.ipc_buffer).reserved.as_mut_ptr() as *mut u32;
        let mut count = 0usize;
        let mut seen = 0usize;
        for i in 0..cap {
            if count >= max_count {
                break;
            }
            let p = &*proc_table::proctab(i);
            if p.state == proc_table::ProcessState::Free {
                continue;
            }
            if seen < offset {
                seen += 1;
                continue;
            }
            *dst.add(count) = p.pid;
            count += 1;
            seen += 1;
        }

        reply.regs[0] = count as u64;
        reply.regs[1] = total as u64;
        reply.label = TRONA_OK;
        reply.length = 2;
    }
}

/// INIT_GET_ARGV: return NUL-separated argv of pid via IPC buffer reserved area.
/// Request: regs[0] = pid
/// Reply: regs[0] = argv_len bytes written
unsafe fn handle_get_argv(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let pid = msg.regs[0] as u32;
        let Some(idx) = proc_table::find_by_pid(pid) else {
            reply.label = TRONA_NOT_FOUND;
            return;
        };
        let p = &*proc_table::proctab(idx);
        let argv_len = p.argv_len as usize;

        let ctx = &*crate::ipc_ctx();
        if ctx.ipc_buffer.is_null() {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }

        let dst = (*ctx.ipc_buffer).reserved.as_mut_ptr() as *mut u8;
        for i in 0..argv_len {
            *dst.add(i) = p.argv_buf[i];
        }

        reply.regs[0] = argv_len as u64;
        reply.label = TRONA_OK;
        reply.length = 1;
    }
}

pub(crate) unsafe fn handle_message(msg: &TronaMsg, badge: u64, reply: &mut TronaMsg) -> bool {
    if msg.label == 0 {
        // CSpace expansion bits are gone — every userspace process now
        // drives its own substrate-side `slot_alloc::self_expand`, so
        // procmgr only sees the readiness bit fan-out here.
        let ready_bits = badge & readiness::BADGE_MASK;
        if ready_bits != 0 {
            unsafe { readiness::handle_ready_bits(ready_bits) };
        }
        return true;
    }

    // Reject operations targeting processes in transitional states (Spawning/Exiting).
    // INIT_SPAWN and INIT_EXIT are exempt: spawn creates a new process (caller isn't
    // transitional), and exit is the transition itself.
    if badge != 0 && msg.label != INIT_SPAWN && msg.label != INIT_EXIT {
        if let Some(idx) = find_by_badge(badge) {
            if unsafe { proc_table::proctab(idx).state.is_transitional() } {
                reply.label = trona_protocol::posix::TRONA_BUSY;
                return false;
            }
        }
    }

    if let Some(posix_skip) = unsafe { posix::dispatch_posix(msg.label, msg, reply, badge) } {
        if !posix::is_posix_caller(badge) {
            reply.label = TRONA_INVALID_OPERATION;
            return false;
        }
        return posix_skip;
    }

    match msg.label {
        INIT_SPAWN => {
            let alloc = unsafe { &mut *(&raw mut ALLOCATOR) };
            if unsafe { crate::lifecycle::spawn::handle_spawn_tx(msg, reply, badge, alloc) } {
                return true;
            }
        }
        INIT_EXIT => {
            unsafe { crate::lifecycle::exit::handle_exit(msg, reply, badge) };
            return true;
        }
        INIT_GETPID => unsafe { handle_getpid(reply, badge) },
        INIT_GETPPID => unsafe { handle_getppid(reply, badge) },
        PM_INJECT_CAP => unsafe { posix::signal::handle_inject_cap(msg, reply) },
        PM_RESUME => {
            if unsafe { posix::signal::handle_resume(msg, reply) } {
                return true;
            }
        }
        PM_REGISTER => unsafe { crate::base::cspace::handle_register(msg, reply, badge) },
        PM_LIST_PIDS => unsafe { handle_list_pids(reply) },
        PM_GET_PROC_INFO => unsafe { handle_get_proc_info(msg, reply) },
        INIT_GET_THREAD_CAPS => unsafe { handle_get_thread_caps(reply, badge) },
        PM_REGISTER_PERSONALITY_PROVIDER => unsafe {
            personality::handle_register_provider(msg, reply)
        },
        INIT_THREAD_CREATE => unsafe { thread::handle_thread_create(msg, reply, badge) },
        INIT_THREAD_EXIT => {
            unsafe { thread::handle_thread_exit(msg, badge) };
            return true;
        }
        INIT_THREAD_JOIN => {
            if unsafe { thread::handle_thread_join(msg, reply, badge) } {
                return true;
            }
        }
        INIT_THREAD_DETACH => unsafe { thread::handle_thread_detach(msg, reply, badge) },
        PM_THREAD_LIST => unsafe { thread::handle_thread_list(msg, reply, badge) },
        PM_REGISTER_SERVICE_DEFS => unsafe {
            service_registry::handle_register_service_defs(msg, reply)
        },
        PM_REGISTER_PROVIDER => unsafe { service_registry::handle_register_provider(msg, reply) },
        INIT_GET_PROC_TIMES => unsafe { handle_get_proc_times(msg, reply) },
        INIT_GET_SYSTEM_STATS => unsafe { handle_get_system_stats(reply) },
        INIT_GET_KINFO_PROC => unsafe { handle_get_kinfo_proc(msg, reply) },
        INIT_LIST_PIDS_BUF => unsafe { handle_list_pids_buf(msg, reply) },
        INIT_GET_ARGV => unsafe { handle_get_argv(msg, reply) },
        INIT_GET_CLIENT_VM_STATS => unsafe { handle_get_client_vm_stats(msg, reply) },
        INIT_KILL_OOM_VICTIM => unsafe { handle_kill_oom_victim(msg, reply) },
        PM_DUMP_PENDING => {
            trona_runtime::uinfo!(|_lb| {
                _lb.str(b"[PROCMGR] dump: POST_REPLY_RESUME_COUNT=");
                _lb.dec(unsafe { *(&raw const POST_REPLY_RESUME_COUNT) as u64 });
                _lb.str(b" has_timers=");
                _lb.dec(if posix::timer::has_pending_timers() {
                    1
                } else {
                    0
                });
                _lb.str(b" has_readiness=");
                _lb.dec(if readiness::has_pending_readiness() {
                    1
                } else {
                    0
                });
                _lb.str(b"\n");
            });
            reply.label = TRONA_OK;
        }
        _ => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] unknown label=");
                _lb.hex(msg.label);
                _lb.str(b"\n");
            });
            reply.label = TRONA_INVALID_OPERATION;
        }
    }

    false
}
