// SPDX-License-Identifier: GPL-2.0-only
//! Owner event loop — the single-threaded VFS main loop.
//!
//! Replaces `ipc/loop_.rs`. The owner loop owns `VfsState` and is the sole
//! mutator of all VFS state. Workers are dispatched via work queues and
//! return results via completion queues.
//!
//! Loop structure:
//! 1. Drain worker completions
//! 2. Process timer expirations (poll deadlines, PTY timeouts)
//! 3. Sweep reclaimable arena slots
//! 4. Dispatch incoming IPC message
//! 5. reply_recv (or recv if skip_reply)

use trona_kernel::core_types::*;
use trona_protocol::common::TRONA_TIMED_OUT;
use uapi::*;

use crate::ipc::timer_wheel;
use crate::owner::VfsState;
use crate::owner::dispatch::vfs_dispatch_owned;
use crate::server::consts::*;

/// Run the single-threaded owner event loop.
///
/// This function never returns. It owns `state` for the lifetime of the
/// VFS server process.
///
/// # Safety
///
/// Must be called exactly once, after `VfsState::new()` and bootstrap
/// stages have completed.
pub(crate) unsafe fn run_owner_loop(state: &mut VfsState, recv_endpoints: &[u64]) -> ! {
    let ctx = crate::ipc_ctx();

    let mut msg = TronaMsg::zeroed();
    let mut reply = TronaMsg::zeroed();
    let mut badge: u64 = 0;
    let mut recv_source: u64 = 0;

    // Arm the receive slot.
    unsafe {
        let slot = state.current_recv_slot;
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, slot, 0);
    }

    // Initial blocking receive.
    let mut have_message = unsafe {
        let err = trona_kernel::ipc::recv_any_ctx(
            ctx,
            recv_endpoints.as_ptr(),
            recv_endpoints.len(),
            &raw mut msg,
            &raw mut badge,
            &raw mut recv_source,
        );
        err == 0
    };

    loop {
        // 1. Drain worker completions.
        unsafe {
            crate::owner::worker::worker_drain_completions(state);
        }

        // 2. Process timer expirations through the unified `VfsEvent`
        //    classification surface so any future wire-driven timer
        //    source converges on the same dispatch pattern.
        unsafe {
            let now_ns = crate::personality::posix::poll::monotonic_now_ns();
            crate::owner::dispatch::dispatch_timer_fired(state, now_ns);
        }

        // 3. Periodic arena sweep.
        state.maybe_sweep();

        // 4. Dispatch incoming message.
        let mut skip_reply = true;
        if have_message {
            reply = TronaMsg::zeroed();
            skip_reply = unsafe {
                vfs_dispatch_owned(state, &raw const msg, badge, recv_source, &raw mut reply)
            };

            // Recycle receive slot.
            unsafe {
                let slot = state.current_recv_slot;
                trona_runtime::core::ipc_ext::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, slot, 0);
            }
        }

        // 5. Compute next timeout (timer wheel).
        let timeout_ns = {
            let rel = timer_wheel::relative_timeout_ns(
                crate::personality::posix::poll::monotonic_now_ns(),
            );
            if rel == 0 { u64::MAX } else { rel }
        };

        // 6. reply_recv or recv.
        let err = if skip_reply {
            // No reply to send — just receive next message.
            if timeout_ns == u64::MAX {
                unsafe {
                    trona_kernel::ipc::recv_any_ctx(
                        ctx,
                        recv_endpoints.as_ptr(),
                        recv_endpoints.len(),
                        &raw mut msg,
                        &raw mut badge,
                        &raw mut recv_source,
                    )
                }
            } else {
                unsafe {
                    trona_kernel::ipc::recv_any_timed_ctx(
                        ctx,
                        recv_endpoints.as_ptr(),
                        recv_endpoints.len(),
                        timeout_ns,
                        &raw mut msg,
                        &raw mut badge,
                        &raw mut recv_source,
                    )
                }
            }
        } else {
            // Send reply and receive next message atomically.
            if timeout_ns == u64::MAX {
                unsafe {
                    trona_kernel::ipc::reply_recv_any_ctx(
                        ctx,
                        recv_endpoints.as_ptr(),
                        recv_endpoints.len(),
                        &raw const reply,
                        &raw mut msg,
                        &raw mut badge,
                        &raw mut recv_source,
                    )
                }
            } else {
                unsafe {
                    trona_kernel::ipc::reply_recv_any_timed_ctx(
                        ctx,
                        recv_endpoints.as_ptr(),
                        recv_endpoints.len(),
                        timeout_ns,
                        &raw const reply,
                        &raw mut msg,
                        &raw mut badge,
                        &raw mut recv_source,
                    )
                }
            }
        };

        have_message = err == 0;
        if err != 0 && err != TRONA_CANCELLED as i32 && err != TRONA_TIMED_OUT as i32 {
            // IPC error — continue looping.
            have_message = false;
        }
    }
}
