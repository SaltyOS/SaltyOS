//! Process manager reply/receive transition path.
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicBool, Ordering};

use trona_kernel::core_types::TronaMsg;
use trona_runtime::core::ipc_timer::IpcTimer;
use uapi::KERNITE_INV_CNODE_DELETE;

use crate::base::readiness;
use crate::personality::posix;
use crate::{CAP_RECV_SCRATCH, CAP_SELF_CSPACE, POST_REPLY_RESUME_COUNT, ipc_ctx, server};

const RECV_TIMER_LABEL: u64 = 0x5052_4f43_5449_4d52;
static RECV_TIMER: IpcTimer = IpcTimer::new(RECV_TIMER_LABEL);
static RECV_TIMER_READY: AtomicBool = AtomicBool::new(false);

unsafe fn prepare_receive_slot() {
    unsafe {
        // Cancel any leftover payload cap at CAP_RECV_SCRATCH.
        // set_receive_slot_ctx is sticky across iterations, but assert
        // it on every transition for clarity.
        let _ = trona_kernel::invoke::invoke(
            CAP_SELF_CSPACE,
            KERNITE_INV_CNODE_DELETE as u64,
            CAP_RECV_SCRATCH,
            0,
            0,
            0,
        );
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx(),
            CAP_SELF_CSPACE,
            CAP_RECV_SCRATCH,
            0,
        );
    }
}

pub(crate) unsafe fn initialize_recv_timer() {
    let _ = unsafe { ensure_recv_timer_started() };
}

unsafe fn ensure_recv_timer_started() -> bool {
    if RECV_TIMER_READY.load(Ordering::Acquire) {
        return true;
    }

    match unsafe {
        RECV_TIMER.start_with_runtime_untyped(trona_runtime::client::caps::service_client_ep())
    } {
        Ok(()) => {
            RECV_TIMER_READY.store(true, Ordering::Release);
            true
        }
        Err(err) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] recv timer spawn failed err=");
                _lb.dec(err.as_i32() as u64);
                _lb.str(b"\n");
            });
            false
        }
    }
}

#[inline]
unsafe fn zero_timeout_message(msg: *mut TronaMsg, badge: *mut u64) {
    unsafe {
        if !msg.is_null() {
            *msg = TronaMsg::zeroed();
        }
        if !badge.is_null() {
            *badge = 0;
        }
    }
}

fn clock_now_ns(clock_id: u64) -> Option<u64> {
    let now =
        trona_kernel::syscall::syscall(uapi::KERNITE_SYS_CLOCK_GETTIME, clock_id, 0, 0, 0, 0, 0);
    if now.error == 0 {
        Some(now.value)
    } else {
        None
    }
}

unsafe fn compute_recv_timeout_ns() -> Option<u64> {
    let has_timers = posix::timer::has_pending_timers();
    let has_readiness = readiness::has_pending_readiness();
    let has_wait_deadlines = crate::lifecycle::wait::has_pending_wait_deadlines();
    let has_teardowns = crate::lifecycle::exit::has_pending_teardowns();
    let has_respawns = crate::lifecycle::exit::has_pending_respawns();
    if !(has_timers || has_readiness || has_wait_deadlines || has_teardowns || has_respawns) {
        return None;
    }

    let now_realtime = if has_timers {
        match clock_now_ns(trona_runtime::core::server_consts::CLOCK_REALTIME as u64) {
            Some(now) => now,
            None => return Some(100_000),
        }
    } else {
        0
    };

    let now_monotonic = if has_readiness || has_wait_deadlines || has_teardowns || has_respawns {
        match clock_now_ns(trona_runtime::core::server_consts::CLOCK_MONOTONIC as u64) {
            Some(now) => now,
            None => return Some(100_000),
        }
    } else {
        0
    };

    let mut timeout_ns = u64::MAX;

    if has_timers {
        let deadline = posix::timer::nearest_deadline_ns();
        if deadline <= now_realtime {
            return Some(0);
        }
        timeout_ns = timeout_ns.min(deadline.saturating_sub(now_realtime));
    }

    if has_readiness {
        let deadline = readiness::nearest_readiness_deadline_ns();
        if deadline <= now_monotonic {
            return Some(0);
        }
        timeout_ns = timeout_ns.min(deadline.saturating_sub(now_monotonic));
    }

    if has_wait_deadlines {
        let deadline = crate::lifecycle::wait::nearest_completion_wait_deadline_ns();
        if deadline <= now_monotonic {
            return Some(0);
        }
        timeout_ns = timeout_ns.min(deadline.saturating_sub(now_monotonic));
    }

    if has_teardowns {
        let deadline = crate::lifecycle::exit::nearest_teardown_deadline_ns();
        if deadline <= now_monotonic {
            return Some(0);
        }
        timeout_ns = timeout_ns.min(deadline.saturating_sub(now_monotonic));
    }

    if has_respawns {
        let deadline = crate::lifecycle::exit::nearest_respawn_deadline_ns();
        if deadline <= now_monotonic {
            return Some(0);
        }
        timeout_ns = timeout_ns.min(deadline.saturating_sub(now_monotonic));
    }

    Some(timeout_ns.max(100_000))
}

unsafe fn recv_with_timeout_ns(msg: *mut TronaMsg, badge: *mut u64, timeout_ns: u64) -> i32 {
    if !unsafe { ensure_recv_timer_started() } {
        return crate::TRONA_OUT_OF_MEMORY as i32;
    }

    let armed_seq = RECV_TIMER.arm_after(timeout_ns);
    let err = unsafe {
        trona_kernel::ipc::recv_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::service_recv_ep(),
            msg,
            badge,
        )
    };
    if err != 0 {
        RECV_TIMER.disarm();
        return err;
    }

    if !msg.is_null() && unsafe { RECV_TIMER.is_armed_timeout_message(&*msg, armed_seq) } {
        unsafe { zero_timeout_message(msg, badge) };
    } else {
        RECV_TIMER.disarm();
    }
    0
}

unsafe fn recv_with_timer(msg: *mut TronaMsg, badge: *mut u64) -> i32 {
    match unsafe { compute_recv_timeout_ns() } {
        Some(0) => {
            unsafe { zero_timeout_message(msg, badge) };
            0
        }
        Some(timeout_ns) => unsafe { recv_with_timeout_ns(msg, badge, timeout_ns) },
        None => unsafe {
            trona_kernel::ipc::recv_ctx(
                ipc_ctx(),
                trona_runtime::client::caps::service_recv_ep(),
                msg,
                badge,
            )
        },
    }
}

pub(crate) unsafe fn prime_receive(msg: *mut TronaMsg, badge: *mut u64) -> i32 {
    unsafe {
        prepare_receive_slot();
        recv_with_timer(msg, badge)
    }
}

pub(crate) unsafe fn advance_after_dispatch(
    skip_reply: bool,
    reply: &TronaMsg,
    msg: *mut TronaMsg,
    badge: *mut u64,
) -> i32 {
    unsafe {
        let timeout_ns = compute_recv_timeout_ns();

        if skip_reply {
            // Deferred dispatch or intentionally not replied. Clear the
            // receive scratch before the next receive.
            prepare_receive_slot();
            return match timeout_ns {
                Some(0) => {
                    zero_timeout_message(msg, badge);
                    0
                }
                Some(timeout_ns) => recv_with_timeout_ns(msg, badge, timeout_ns),
                None => trona_kernel::ipc::recv_ctx(
                    ipc_ctx(),
                    trona_runtime::client::caps::service_recv_ep(),
                    msg,
                    badge,
                ),
            };
        }

        if POST_REPLY_RESUME_COUNT != 0 || timeout_ns.is_some() {
            // Reply-then-timed-recv path.
            let err = trona_kernel::ipc::mp_write_reply_ctx(
                ipc_ctx(),
                trona_runtime::client::caps::service_recv_ep(),
                reply as *const TronaMsg,
            );
            if err != 0 {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] mp_write_reply failed before timed recv err=");
                    _lb.hex(err as u64);
                    _lb.str(b"\n");
                });
                return err;
            }

            prepare_receive_slot();
            server::run_post_reply_work();
            return match timeout_ns {
                Some(0) => {
                    zero_timeout_message(msg, badge);
                    0
                }
                Some(timeout_ns) => recv_with_timeout_ns(msg, badge, timeout_ns),
                None => trona_kernel::ipc::recv_ctx(
                    ipc_ctx(),
                    trona_runtime::client::caps::service_recv_ep(),
                    msg,
                    badge,
                ),
            };
        }

        // Atomic path: `mp_write_reply_read_ctx` sends the reply and
        // immediately recv's the next inbound on the same MP.
        trona_kernel::ipc::mp_write_reply_read_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::service_recv_ep(),
            reply as *const TronaMsg,
            msg,
            badge,
        )
    }
}
