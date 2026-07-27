// SPDX-License-Identifier: GPL-2.0-only
//! VFS worker-pool bootstrap.
//!
//! The new VFS keeps a fixed worker pool, but workers are execution
//! engines only. They do not own VFS state, do not complete client IPC
//! directly, and do not carry structural namespace links.
//!
//! Each worker owns:
//! - a real kernel thread
//! - a private receive slot
//! - a futex-backed idle loop

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use trona_kernel::core_types::*;
use trona_kernel::syscall;
use trona_runtime::thread::thread;

/// Fixed data-plane worker count for the rebuilt VFS.
pub(crate) const MAX_WORKERS: usize = 4;

static WORKERS_SPAWNED: AtomicUsize = AtomicUsize::new(0);
static WORKER_WAKE: [AtomicU32; MAX_WORKERS] = [const { AtomicU32::new(0) }; MAX_WORKERS];
static WORKER_RECV_SLOTS: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];
/// Round-robin counter for `wake_one_worker` so successive owner pushes
/// fan out across the worker pool instead of always slamming worker 0.
static NEXT_WAKE: AtomicU32 = AtomicU32::new(0);

/// Publish a worker's reserved receive slot before the thread starts.
pub(crate) fn set_worker_recv_slot(idx: usize, slot: Cap) {
    if idx >= MAX_WORKERS {
        return;
    }
    WORKER_RECV_SLOTS[idx].store(slot, Ordering::Release);
}

/// Spawn the fixed worker pool. Returns the number of threads actually
/// brought online; the owner may continue in a degraded single-thread
/// mode if spawning partially fails.
pub(crate) unsafe fn spawn_workers(config: thread::SpawnConfig) -> usize {
    if WORKERS_SPAWNED.load(Ordering::Acquire) != 0 {
        return 0;
    }

    let mut spawned = 0usize;
    for idx in 0..MAX_WORKERS {
        let entry: unsafe extern "C" fn(*mut u8) = worker_entry;
        let arg = idx as *mut u8;
        match unsafe { thread::spawn_fn(entry, arg, &config) } {
            Ok(_) => {
                spawned += 1;
            }
            Err(err) => {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[VFS] worker spawn failed idx=");
                    _lb.dec(idx as u64);
                    _lb.str(b" err=");
                    _lb.dec(err.as_i32() as u64);
                    _lb.str(b"\n");
                });
                break;
            }
        }
    }

    WORKERS_SPAWNED.store(spawned, Ordering::Release);
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] workers spawned count=");
        _lb.dec(spawned as u64);
        _lb.str(b"/");
        _lb.dec(MAX_WORKERS as u64);
        _lb.str(b" dataplane=workers blocking_backend_rpc=enabled");
        _lb.str(b"\n");
    });
    spawned
}

/// Owner-side: bump worker `idx`'s wake word and post a futex_wake.
/// Caller must have already pushed the job onto the backend ring;
/// otherwise the wake is harmless (worker drains, finds nothing,
/// goes back to sleep).
pub(crate) fn wake_worker(idx: usize) {
    if idx >= MAX_WORKERS {
        return;
    }
    let wake = &WORKER_WAKE[idx];
    wake.fetch_add(1, Ordering::Release);
    let _ = trona_kernel::syscall::futex_wake(wake.as_ptr(), 1);
}

/// Owner-side: wake one worker chosen round-robin across the spawned
/// pool. Returns false if no workers are alive (degraded mode — caller
/// should fall back to a synchronous backend call inline).
pub(crate) fn wake_one_worker() -> bool {
    let count = WORKERS_SPAWNED.load(Ordering::Acquire);
    if count == 0 {
        return false;
    }
    let idx = (NEXT_WAKE.fetch_add(1, Ordering::Relaxed) as usize) % count;
    wake_worker(idx);
    true
}

/// Owner-side: number of workers brought online. Zero means deferral
/// is unavailable and callers must fall back to inline sync RPC.
pub(crate) fn worker_count() -> usize {
    WORKERS_SPAWNED.load(Ordering::Acquire)
}

unsafe fn run_one_backend_job(idx: usize, job: super::backend_rpc::PendingBackendJob) {
    use super::pending_ops::{self, PendingOpId};

    let op_id = PendingOpId::from_raw(job.op_id);

    // The owner may cancel an op between push_job and pickup. mark_running
    // races with `cancel_for_badge` via `state.compare_exchange`. A failure
    // here means the owner has already routed the cancellation through
    // `drain_cancelled`; the reply slot is owner-side and we must not push.
    if !pending_ops::mark_running(op_id) {
        return;
    }

    pending_ops::worker_enter(idx, op_id);

    let mut backend_reply = TronaMsg::zeroed();
    let err = unsafe {
        trona_kernel::ipc::call_ctx(
            crate::ipc_ctx(),
            job.target_ep,
            &raw const job.request,
            &raw mut backend_reply,
        )
    };

    pending_ops::worker_leave(idx);

    // Cancellation observed between RPC return and completion push: drop
    // the result. The owner-side cancel walk owns the reply slot.
    if !pending_ops::try_complete(op_id) {
        return;
    }

    let mut completion = super::backend_rpc::PendingBackendCompletion {
        op_kind: job.op_kind,
        payload_len: 0,
        op_id: op_id.raw(),
        backend_err: err as u64,
        backend_reply,
        ctx: job.ctx,
        payload: [0u8; super::backend_rpc::BACKEND_PAYLOAD_MAX],
    };

    if err == 0 && job.payload_out_bytes > 0 {
        let copy_len =
            (job.payload_out_bytes as usize).min(super::backend_rpc::BACKEND_PAYLOAD_MAX);
        unsafe {
            let ctx_ptr = crate::ipc_ctx();
            if !ctx_ptr.is_null() && !(*ctx_ptr).ipc_buffer.is_null() {
                let src = (*(*ctx_ptr).ipc_buffer).reserved.as_ptr() as *const u8;
                core::ptr::copy_nonoverlapping(src, completion.payload.as_mut_ptr(), copy_len);
                completion.payload_len = copy_len as u32;
            }
        }
    }

    // Completion drops would leak the saved reply cap and hang the
    // client forever. Retry with yield until the owner drains.
    let mut spins: u32 = 0;
    while !super::backend_rpc::push_completion(completion) {
        super::backend_rpc::signal_owner_completion();
        let _ = trona_kernel::syscall::syscall(uapi::SYS_YIELD, 0, 0, 0, 0, 0, 0);
        spins = spins.saturating_add(1);
        if spins == 1 || spins.is_power_of_two() {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] completion ring full, retrying op_kind=");
                _lb.dec(job.op_kind as u64);
                _lb.str(b" spins=");
                _lb.dec(spins as u64);
                _lb.str(b"\n");
            });
        }
    }
}

/// Worker thread entry.
///
/// The worker installs its private receive slot and then sleeps on its
/// futex-backed wake word. Namespace state remains owner-thread-only;
/// workers are isolated execution contexts.
unsafe extern "C" fn worker_entry(arg: *mut u8) {
    let idx = arg as usize;
    if idx >= MAX_WORKERS {
        thread::thread_exit();
    }

    let recv_slot = WORKER_RECV_SLOTS[idx].load(Ordering::Acquire);
    if recv_slot != 0 {
        unsafe {
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(
                crate::ipc_ctx(),
                uapi::CAP_SELF_CSPACE,
                recv_slot,
                0,
            );
        }
    }

    let wake = &WORKER_WAKE[idx];
    let mut observed = wake.load(Ordering::Acquire);
    loop {
        // Drain whatever is already queued before sleeping. This
        // prevents a missed wake when `push_job` + `futex_wake` races
        // with the worker observing the wake counter.
        let mut completed_any = false;
        while let Some(job) = super::backend_rpc::pop_job() {
            unsafe {
                run_one_backend_job(idx, job);
            }
            completed_any = true;
        }
        if completed_any {
            super::backend_rpc::signal_owner_completion();
        }

        // Re-check the wake word after draining. If the owner bumped
        // it while we were running a backend call, re-loop without
        // sleeping.
        let new_observed = wake.load(Ordering::Acquire);
        if new_observed != observed {
            observed = new_observed;
            continue;
        }

        // No new work — block until the owner bumps the wake word.
        let _ = syscall::futex_wait(wake.as_ptr(), observed);
        observed = wake.load(Ordering::Acquire);
    }
}
