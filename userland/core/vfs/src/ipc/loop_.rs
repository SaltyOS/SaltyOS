// SPDX-License-Identifier: GPL-2.0-only
//! VFS IPC event loops — single-threaded and worker-pool modes.

use trona::consts::kernel::*;
use trona::consts::server::TRONA_TIMED_OUT;
use trona::ipc;
use trona::types::core::*;
use trona::worker::WorkerLoopControl;

use crate::personality::posix::poll;
use crate::server::consts::*;
use crate::{current_recv_slot, ipc_ctx};
use super::timer_wheel;

#[inline]
unsafe fn arm_current_recv_slot(ctx: *mut IpcContext) {
    unsafe {
        let slot = crate::current_recv_slot();
        if slot != 0 {
            ipc::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, slot, 0);
        }
    }
}

#[inline]
unsafe fn recycle_current_recv_slot(ctx: *mut IpcContext) {
    unsafe {
        let slot = current_recv_slot();
        if slot != 0 {
            let _ = trona::invoke::cnode_delete(CAP_SELF_CSPACE, slot);
            ipc::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, slot, 0);
        }
    }
}

// ===========================================================================
// Worker count computation
// ===========================================================================

#[cfg(vfs_worker_pool)]
pub(crate) fn compute_vfs_worker_count() -> (usize, bool) {
    if let Some(raw) = option_env!("VFS_WORKER_COUNT_OVERRIDE") {
        if let Ok(parsed) = raw.parse::<usize>() {
            if parsed > 0 {
                return (parsed.clamp(1, 32), true);
            }
        }
    }
    (cfg_if_cpus(), false)
}

#[cfg(vfs_worker_pool)]
const fn cfg_if_cpus() -> usize {
    let cpus = if cfg!(vfs_cpus_1) { 1 }
    else if cfg!(vfs_cpus_2) { 2 }
    else if cfg!(vfs_cpus_4) { 4 }
    else if cfg!(vfs_cpus_8) { 8 }
    else if cfg!(vfs_cpus_16) { 16 }
    else if cfg!(vfs_cpus_32) { 32 }
    else if cfg!(vfs_cpus_64) { 64 }
    else if cfg!(vfs_cpus_128) { 128 }
    else if cfg!(vfs_cpus_256) { 256 }
    else { 4 };

    let computed = cpus * 2 + cpus / 3;
    let min4 = if computed < 4 { 4 } else { computed };
    if min4 > 32 { 32 } else { min4 }
}

// ===========================================================================
// Worker-pool hooks
// ===========================================================================

#[cfg(vfs_worker_pool)]
fn current_timer_worker_id() -> u32 {
    match trona::tls::current_tls() {
        Some(tls) => unsafe { (*tls).thread_id as u32 },
        None => 0,
    }
}

#[cfg(vfs_worker_pool)]
pub(crate) unsafe fn vfs_worker_on_enter(ctx: *mut IpcContext, _worker_idx: usize) {
    unsafe {
        arm_current_recv_slot(ctx);
        let worker_id = current_timer_worker_id();
        let _ = timer_wheel::try_claim_timer(worker_id);
    }
}

#[cfg(vfs_worker_pool)]
pub(crate) unsafe fn vfs_worker_next_timeout_ns(_ctx: *mut IpcContext, _worker_idx: usize) -> u64 {
    unsafe {
        let worker_id = current_timer_worker_id();
        let is_owner = if timer_wheel::am_i_timer_owner(worker_id) {
            true
        } else {
            timer_wheel::try_claim_timer(worker_id)
        };
        if !is_owner {
            return 0;
        }
        timer_wheel::refresh_heartbeat();
        timer_wheel::process_expired_timers();
        timer_wheel::relative_timeout_ns(poll::monotonic_now_ns())
    }
}

#[cfg(vfs_worker_pool)]
pub(crate) unsafe fn vfs_worker_on_timeout(_ctx: *mut IpcContext, _worker_idx: usize) {
    unsafe {
        let worker_id = current_timer_worker_id();
        if timer_wheel::am_i_timer_owner(worker_id) || timer_wheel::try_claim_timer(worker_id) {
            timer_wheel::refresh_heartbeat();
            timer_wheel::process_expired_timers();
        }
    }
}

#[cfg(vfs_worker_pool)]
pub(crate) unsafe fn vfs_worker_handler(
    _ctx: *mut IpcContext,
    msg: *mut TronaMsg,
    badge: u64,
    recv_source: u64,
    reply: *mut TronaMsg,
) -> WorkerLoopControl {
    unsafe {
        let skip_reply = vfs_dispatch(msg as *const TronaMsg, badge, recv_source, reply);
        recycle_current_recv_slot(ipc_ctx());

        if skip_reply {
            WorkerLoopControl::SkipReply
        } else {
            WorkerLoopControl::Reply
        }
    }
}
