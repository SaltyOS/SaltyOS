// SPDX-License-Identifier: GPL-2.0-only
//
//! Owner reactor entry point.
//!
//! Wraps `EventLoop<VfsDispatcher>`. The owner thread
//! sits on `EQ_WAIT(state.owner_eq)` and loops dispatching one
//! event at a time. The reactor is single-threaded by design —
//! every posix handler runs to completion under the owner TCB
//! before the next event is drained.
//!
//! Receive-scratch arming: the dispatcher needs a stable cnode slot
//! for user-supplied caps trailing in MP_CALL. The owner loop treats
//! that slot as scratch: every live cap must be moved out by the
//! dispatcher, and the slot is cleared/re-armed before the next
//! `MP_READ`.

use trona_kernel::core_types::IpcContext;
use trona_server::event_loop::EventLoop;

use crate::ipc::dispatch::VfsDispatcher;
use crate::owner::VfsState;

/// Initialise and arm the receive scratch slot. Idempotent across
/// reactor restarts; after allocation, each call clears stale scratch
/// contents before staging the slot as the next receive destination.
unsafe fn arm_receive_scratch(state: &mut VfsState) -> bool {
    if state.recv_scratch_slot == 0 {
        let slot = trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"vfs recv scratch");
        if slot == 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] arm_receive_scratch: slot_alloc exhausted\n");
            });
            return false;
        }
        state.recv_scratch_slot = slot;
    }
    let ctx = trona_posix::tls::current_ipc_ctx();
    let window = trona_server::recv_slot::FixedRecvWindow::new(
        state.recv_scratch_slot,
        1,
        trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
    );
    unsafe {
        window.arm(ctx, uapi::KERNITE_CAP_SELF_CSPACE as u64);
    }
    true
}

/// Run the reactor forever. Returns only on EQ_WAIT failure
/// (treated as fatal — the owner thread idles in a yield loop so
/// the supervisor can observe the fault and tear down vfs).
pub(crate) fn run(state: &mut VfsState) -> ! {
    if unsafe { !arm_receive_scratch(state) } {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] reactor: receive scratch arming failed; idling\n");
        });
        loop {
            trona_kernel::syscall::invoke(
                uapi::KERNITE_CAP_SELF_TCB as u64,
                uapi::KERNITE_INV_TCB_YIELD as u64,
                0,
                0,
                0,
                0,
            );
        }
    }
    let dispatcher =
        VfsDispatcher::new(state as *mut VfsState, trona_posix::tls::current_ipc_ctx());
    let mut reactor: EventLoop<VfsDispatcher> = EventLoop::new(state.owner_eq.as_raw(), dispatcher);
    let ipc_ctx: *mut IpcContext = trona_posix::tls::current_ipc_ctx();
    let mut sweep_tick: u32 = 0;
    loop {
        let r = unsafe { reactor.run_iteration(ipc_ctx) };
        // Promote every ordering-hold op (currently fsync /
        // fdatasync) whose barrier completed during this
        // iteration. The gate accumulates ready entries each
        // time `OrderingGate::complete` clears a waiter; the
        // drain merges the saved backend ack with the lane's
        // aggregate error and emits the public reply. Running
        // it once per iteration keeps reply latency at one
        // event-loop tick after the last predecessor settles
        // without leaving readiness records to accumulate.
        crate::owner::ordering_drain::drain(state);
        crate::owner::pager_rpc::drain_mmsrv_writeback_done_queue(state);
        let _ = crate::owner::pager_rpc::retry_finished_mmsrv_writeback_barriers_budget(state, 8);
        unsafe {
            let _ = crate::owner::pager_rpc::issue_mmsrv_writeback_barriers_budget(state, 2);
        }
        // `Arena::release` only flips slots into `Reclaimable`;
        // without a periodic `sweep`, every cancelled `PendingOp`,
        // closed `OpenObject`, and unpinned `Vnode` would accumulate
        // forever. Drive the sweep on a coarse cadence so hot dispatch
        // stays cheap, tightening it (every 16 vs 64 iterations) while a
        // spine arena is under memory pressure.
        sweep_tick = sweep_tick.wrapping_add(1);
        let cadence_mask = if crate::owner::reclaim::under_pressure(state) {
            0x0F
        } else {
            0x3F
        };
        if sweep_tick & cadence_mask == 0 {
            unsafe {
                let _ = crate::owner::pager_rpc::issue_writeback_budget(state, 4);
            }
            crate::owner::reclaim::sweep_once(state);
        }
        if r != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] reactor iteration err=");
                _lb.hex(r as u64);
                _lb.str(b"\n");
            });
            trona_kernel::syscall::invoke(
                uapi::KERNITE_CAP_SELF_TCB as u64,
                uapi::KERNITE_INV_TCB_YIELD as u64,
                0,
                0,
                0,
                0,
            );
        }
        let _ = unsafe { arm_receive_scratch(state) };
    }
}
