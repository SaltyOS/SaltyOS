// SPDX-License-Identifier: GPL-2.0-only
//! Owner receive / reply loop.
//!
//! The rebuilt VFS keeps the traditional server shape:
//! `recv -> dispatch -> reply_recv`.
//! What changes is ownership discipline: all mutable service state lives
//! behind one `&mut VfsState`, and this loop is the only place that owns
//! that reference.

use core::sync::atomic::{AtomicBool, Ordering};

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_kernel::syscall;
use trona_runtime::core::ipc_timer::IpcTimer;
use uapi::{CLOCK_MONOTONIC, IPC_RECV_SOURCE_NOTIFICATION, SYS_CLOCK_GETTIME};

use super::VfsState;

const OWNER_IDLE_TICK_NS: u64 = 100_000_000;
const OWNER_TIMEOUT_LOG_EVERY: u64 = 10;
const OWNER_SLOW_OP_MS: u64 = 25;
const ROOTFS_STATUS_READY: u8 = 1;
const OWNER_IDLE_TIMER_LABEL: u64 = 0x5646_535f_5449_4d52;
static OWNER_IDLE_TIMER: IpcTimer = IpcTimer::new(OWNER_IDLE_TIMER_LABEL);
static OWNER_IDLE_TIMER_READY: AtomicBool = AtomicBool::new(false);

fn rootfs_status_name(status: u8) -> &'static [u8] {
    match status {
        0 => b"pending",
        1 => b"ready",
        2 => b"failed",
        _ => b"unknown",
    }
}

fn log_owner_timeout_state(state: &VfsState, tick: u64, have_reply: bool) {
    let real_root_valid = state.bootstrap.real_root_mount.is_valid();
    let pivot_pending = real_root_valid && state.bootstrap.real_root_mount != state.root_mount;
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] owner timeout tick=");
        _lb.dec(tick);
        _lb.str(b" have_reply=");
        _lb.dec(have_reply as u64);
        _lb.str(b" rootfs=");
        _lb.bytes(rootfs_status_name(state.rootfs.status));
        _lb.str(b" retry=");
        _lb.dec(state.rootfs.retry_count as u64);
        _lb.str(b" next=");
        _lb.hex(state.rootfs.next_retry_ns);
        _lb.str(b" real_root=");
        _lb.dec(real_root_valid as u64);
        _lb.str(b" pivot_pending=");
        _lb.dec(pivot_pending as u64);
        _lb.str(b" workers=");
        _lb.dec(state.workers_spawned as u64);
        _lb.str(b" clients=");
        _lb.dec(state.clients.len() as u64);
        _lb.str(b"/");
        _lb.dec(state.clients.capacity() as u64);
        _lb.str(b" open_files=");
        _lb.dec(state.open_files.len() as u64);
        _lb.str(b"/");
        _lb.dec(state.open_files.capacity() as u64);
        _lb.str(b" vnodes=");
        _lb.dec(state.vnodes.len() as u64);
        _lb.str(b"/");
        _lb.dec(state.vnodes.capacity() as u64);
        _lb.str(b" mounts=");
        _lb.dec(state.mounts.len() as u64);
        _lb.str(b"/");
        _lb.dec(state.mounts.capacity() as u64);
        _lb.str(b" saltyfs_mounts=");
        _lb.dec(state.saltyfs_mounts.len() as u64);
        _lb.str(b"\n");
    });
}

fn should_log_owner_timeout_state(state: &VfsState) -> bool {
    let real_root_valid = state.bootstrap.real_root_mount.is_valid();
    let pivot_pending = real_root_valid && state.bootstrap.real_root_mount != state.root_mount;
    state.rootfs.status != ROOTFS_STATUS_READY || pivot_pending
}

fn monotonic_now_ns() -> u64 {
    let now = syscall::syscall(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC as u64, 0, 0, 0, 0, 0);
    if now.error == 0 { now.value } else { 0 }
}

fn log_slow_owner_op(state: &VfsState, op: u64, badge: u64, source: u32, elapsed_ns: u64) {
    trona_runtime::uwarn!(|_lb| {
        _lb.str(b"[VFS] slow op component=vfs op=");
        _lb.hex(op);
        _lb.str(b" stage=owner_dispatch badge=");
        _lb.hex(badge);
        _lb.str(b" source=");
        _lb.hex(source as u64);
        _lb.str(b" elapsed_ms=");
        _lb.dec(elapsed_ns / 1_000_000);
        _lb.str(b" workers=");
        _lb.dec(state.workers_spawned as u64);
        _lb.str(b" dataplane=owner-thread");
        _lb.str(b"\n");
    });
}

unsafe fn ensure_owner_idle_timer_started() -> bool {
    if OWNER_IDLE_TIMER_READY.load(Ordering::Acquire) {
        return true;
    }

    match unsafe {
        OWNER_IDLE_TIMER
            .start_with_runtime_untyped(trona_runtime::client::caps::service_client_ep())
    } {
        Ok(()) => {
            OWNER_IDLE_TIMER_READY.store(true, Ordering::Release);
            true
        }
        Err(err) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] owner timer spawn failed err=");
                _lb.dec(err.as_i32() as u64);
                _lb.str(b"\n");
            });
            false
        }
    }
}

/// Enter the owner loop. Never returns.
///
/// # Safety
///
/// The caller must ensure `state` stays owner-thread private for the
/// lifetime of the loop.
pub(crate) unsafe fn run_owner_loop(state: &mut VfsState) -> ! {
    if !unsafe { ensure_owner_idle_timer_started() } {
        crate::idle();
    }

    let endpoint_buf = [
        trona_runtime::client::caps::service_recv_ep(),
        state.netsrv_callback_ep,
    ];
    let endpoint_count = if state.netsrv_callback_ep != 0 { 2 } else { 1 };
    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    let mut badge = 0u64;
    let mut source = 0u64;
    let mut have_reply = false;
    let mut timeout_ticks = 0u64;

    loop {
        crate::boot::rootfs::maybe_drive(state);

        let poll_timeout_ns = crate::fileops::tty_wait::next_poll_timeout_ns(state);
        let timer_ns = if poll_timeout_ns == 0 {
            OWNER_IDLE_TICK_NS
        } else {
            core::cmp::min(OWNER_IDLE_TICK_NS, poll_timeout_ns)
        };
        let armed_seq = OWNER_IDLE_TIMER.arm_after(timer_ns);
        let err = if have_reply {
            unsafe {
                ipc::reply_recv_any_ctx(
                    crate::ipc_ctx(),
                    endpoint_buf.as_ptr(),
                    endpoint_count,
                    &raw const reply,
                    &raw mut msg,
                    &raw mut badge,
                    &raw mut source,
                )
            }
        } else {
            unsafe {
                ipc::recv_any_ctx(
                    crate::ipc_ctx(),
                    endpoint_buf.as_ptr(),
                    endpoint_count,
                    &raw mut msg,
                    &raw mut badge,
                    &raw mut source,
                )
            }
        };
        OWNER_IDLE_TIMER.disarm();

        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] owner recv failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            crate::idle();
        }

        if OWNER_IDLE_TIMER.is_armed_timeout_message(&msg, armed_seq) {
            unsafe {
                // Reply for the previous dispatch (if any) has already
                // been flushed by the next `reply_recv_any_ctx` at the
                // top of the loop, so this is the safe place to do
                // outbound synchronous IPC: drive inet rearms here
                // rather than from inside `drive_deferred_waiters`,
                // which also runs in dispatch-pre-reply contexts.
                drain_backend_completions(state);
                crate::fileops::tty_wait::drive_deferred_waiters(state);
                crate::fileops::inet_wait::drive_inet_waiters(state);
                super::pending_ops::drain_cancelled();
            }
            timeout_ticks = timeout_ticks.wrapping_add(1);
            if timeout_ticks % OWNER_TIMEOUT_LOG_EVERY == 0 && should_log_owner_timeout_state(state)
            {
                log_owner_timeout_state(state, timeout_ticks, have_reply);
            }
            have_reply = false;
            continue;
        }
        OWNER_IDLE_TIMER.disarm();

        if source == IPC_RECV_SOURCE_NOTIFICATION {
            unsafe {
                let tty_badge = badge & crate::fileops::tty_wait::TTY_NTFN_BITS_MASK;

                // Notification bits are a wake hint; the completion ring is
                // the authoritative queue. Drain it on every notification so
                // coalesced or fallback wake paths cannot strand replies.
                drain_backend_completions(state);
                if tty_badge != 0 {
                    crate::fileops::tty_wait::handle_tty_notification(state, tty_badge);
                } else {
                    crate::fileops::tty_wait::drive_deferred_waiters(state);
                }
            }
            have_reply = false;
            continue;
        }

        reply = TronaMsg::zeroed();
        let dispatch_start_ns = monotonic_now_ns();
        let op_label = msg.label;
        state.dispatch_request(&raw const msg, badge, source as u32, &raw mut reply);
        let dispatch_end_ns = monotonic_now_ns();
        if dispatch_start_ns != 0 && dispatch_end_ns >= dispatch_start_ns {
            let elapsed_ns = dispatch_end_ns - dispatch_start_ns;
            if elapsed_ns / 1_000_000 >= OWNER_SLOW_OP_MS {
                log_slow_owner_op(state, op_label, badge, source as u32, elapsed_ns);
            }
        }
        have_reply = reply.label != crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
        unsafe {
            crate::fileops::tty_wait::drive_deferred_waiters(state);
            super::pending_ops::drain_cancelled();
        }
    }
}

/// Drain every completion the workers have queued. Each completion is
/// routed back to its dispatch site by `op_kind` so per-op state
/// commits run on the owner before the saved reply is shipped.
unsafe fn drain_backend_completions(state: &mut VfsState) {
    while let Some(completion) = super::backend_rpc::pop_completion() {
        unsafe { complete_backend_op(state, completion) };
    }
}

unsafe fn complete_backend_op(
    state: &mut VfsState,
    completion: super::backend_rpc::PendingBackendCompletion,
) {
    // tty stdio provisioning chain (multi-stage state machine — owner
    // state changes + per-fd RPC follow-ups + final saved reply).
    if unsafe { super::dispatch::complete_provision_tty_stdio_to(state, &completion) } {
        return;
    }

    // procfs read completion (PidStatus/PidStat/PidStatm/PidComm/PidCmdline).
    if unsafe { crate::fs::procfs::complete_procfs_read(state, &completion) } {
        return;
    }

    // procfs readlink completion (PidExe).
    if unsafe { crate::fs::procfs::complete_procfs_readlink(&completion) } {
        return;
    }

    // procfs readdir completion (root pid-enumeration via INIT_LIST_PIDS_BUF).
    if unsafe { crate::fs::procfs::complete_procfs_readdir(state, &completion) } {
        return;
    }

    // saltyfs per-vop disk-IO completion runs BEFORE namei resume so
    // the saltyfs handler can commit owner-side state (materialise the
    // looked-up child, refresh attrs, install the new vnode) before
    // `complete_namei_resume` re-drives `lookup_path_dynamic_resume`
    // and re-calls the saltyfs vop expecting that state. The handler
    // matches on `BACKEND_OP_SALTYFS_*` and returns `false` for ops
    // adopted into a `*_CONT` (the syscall continuation owns the saved
    // reply) so the cascade falls through; it returns `true` only when
    // saltyfs is itself the syscall (PendingOp kind
    // `PO_KIND_BACKEND_RPC` not adopted into a `*_CONT`).
    if unsafe { crate::fs::saltyfs::complete_saltyfs_op(state, &completion) } {
        return;
    }

    // namei resume — re-drives the path walk after a vop deferral has
    // returned. Backends that emit Deferred mid-walk transfer the op
    // to PO_KIND_NAMEI_RESUME so this handler picks it up.
    if unsafe { super::namei::complete_namei_resume(state, &completion) } {
        return;
    }

    // Waiter completion — tty / inet / socket / fifo / poll. Each wait
    // table now lives as a `PendingOp + op_id`; the dispatcher matches
    // on `PO_KIND_*_WAIT` internally and ships the saved reply when
    // the wait condition resolves.
    if unsafe { crate::fileops::tty_wait::complete_wait_op(state, &completion) } {
        return;
    }

    // Backend-RPC completions: ttysrv / mmsrv / netsrv non-wait
    // sync RPCs that used to be `ipc::call_ctx` from inside the owner
    // thread. Each dispatcher matches on `completion.op_kind`
    // (BACKEND_OP_TTYSRV_* / MMSRV_* / NETSRV_*) and ships the saved
    // reply per the specific RPC's wire shape.
    if unsafe { crate::fileops::device::complete_device_op(state, &completion) } {
        return;
    }
    if unsafe { crate::fileops::shm::complete_shm_op(state, &completion) } {
        return;
    }
    if unsafe { crate::fileops::socket::complete_netsrv_op(state, &completion) } {
        return;
    }

    // Default path: hand the backend's reply through unchanged.
    let final_reply = match completion.op_kind {
        super::backend_rpc::BACKEND_OP_NONE => completion.backend_reply,
        _ => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] unknown backend op_kind=");
                _lb.dec(completion.op_kind as u64);
                _lb.str(b"\n");
            });
            let mut reply = TronaMsg::zeroed();
            reply.label = uapi::TRONA_INVALID_OPERATION;
            reply
        }
    };
    let op_id = super::pending_ops::PendingOpId::from_raw(completion.op_id);
    let reply_slot = unsafe { super::pending_ops::take_reply_slot(op_id) };
    if reply_slot != 0 {
        unsafe {
            crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const final_reply);
        }
    }
    unsafe {
        super::pending_ops::free(op_id);
    }
}
