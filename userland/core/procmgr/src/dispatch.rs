//! Process manager IPC dispatch.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::protocol::*;
use trona::types::TronaMsg;

use crate::base::proc_table::{self, find_by_badge, ProcessState};
use crate::{
    personality, ALLOCATOR, POST_REPLY_RESUME_COUNT, TRONA_INVALID_OPERATION,
    TRONA_NOT_FOUND, TRONA_OK,
};
use crate::base::readiness;
use crate::lifecycle::thread;
use crate::personality::posix;
use crate::service::registry as service_registry;

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

pub(crate) unsafe fn handle_message(msg: &TronaMsg, badge: u64, reply: &mut TronaMsg) -> bool {
    if msg.label == 0 {
        let ready_bits = badge & readiness::BADGE_MASK;
        let cspace_bits = badge & readiness::CSPACE_BADGE_MASK;
        if ready_bits != 0 {
            unsafe { readiness::handle_ready_bits(ready_bits) };
        }
        if cspace_bits != 0 {
            unsafe { crate::base::cspace::handle_cspace_expand_request(cspace_bits) };
        }
        return true;
    }

    // Reject operations targeting processes in transitional states (Spawning/Exiting).
    // PM_SPAWN and PM_EXIT are exempt: spawn creates a new process (caller isn't
    // transitional), and exit is the transition itself.
    if badge != 0 && msg.label != PM_SPAWN && msg.label != PM_EXIT {
        if let Some(idx) = find_by_badge(badge) {
            if unsafe { proc_table::proctab(idx).state.is_transitional() } {
                reply.label = trona::TRONA_BUSY;
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
        PM_SPAWN => {
            let alloc = unsafe { &mut *(&raw mut ALLOCATOR) };
            if unsafe { crate::lifecycle::spawn::handle_spawn_tx(msg, reply, badge, alloc) } {
                return true;
            }
        }
        PM_EXIT => {
            unsafe { crate::lifecycle::exit::handle_exit(msg, reply, badge) };
            return true;
        }
        PM_GETPID => unsafe { handle_getpid(reply, badge) },
        PM_GETPPID => unsafe { handle_getppid(reply, badge) },
        PM_INJECT_CAP => unsafe { posix::signal::handle_inject_cap(msg, reply) },
        PM_RESUME => {
            if unsafe { posix::signal::handle_resume(msg, reply) } {
                return true;
            }
        }
        PM_REGISTER => unsafe { crate::base::cspace::handle_register(msg, reply, badge) },
        PM_LIST_PIDS => unsafe { handle_list_pids(reply) },
        PM_GET_PROC_INFO => unsafe { handle_get_proc_info(msg, reply) },
        PM_GET_THREAD_CAPS => unsafe { handle_get_thread_caps(reply, badge) },
        PM_REGISTER_PERSONALITY_PROVIDER => unsafe {
            personality::handle_register_provider(msg, reply)
        },
        PM_THREAD_CREATE => unsafe { thread::handle_thread_create(msg, reply, badge) },
        PM_THREAD_EXIT => {
            unsafe { thread::handle_thread_exit(msg, badge) };
            return true;
        }
        PM_THREAD_JOIN => {
            if unsafe { thread::handle_thread_join(msg, reply, badge) } {
                return true;
            }
        }
        PM_THREAD_DETACH => unsafe { thread::handle_thread_detach(msg, reply, badge) },
        PM_THREAD_LIST => unsafe { thread::handle_thread_list(msg, reply, badge) },
        PM_REGISTER_SERVICE_DEFS => unsafe {
            service_registry::handle_register_service_defs(msg, reply)
        },
        PM_REGISTER_PROVIDER => unsafe { service_registry::handle_register_provider(msg, reply) },
        PM_DUMP_PENDING => {
            trona::uinfo!(|_lb| {
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
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] unknown label=");
                _lb.hex(msg.label);
                _lb.str(b"\n");
            });
            reply.label = TRONA_INVALID_OPERATION;
        }
    }

    false
}
