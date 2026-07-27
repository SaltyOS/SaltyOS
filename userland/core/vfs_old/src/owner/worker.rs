// SPDX-License-Identifier: GPL-2.0-only
//! VFS worker dispatch — types, SPSC submit ring, MPSC completion ring,
//! and a single-worker bring-up path.
//!
//! ## Architecture
//!
//! - The **owner** thread holds `&mut VfsState`, recv's every VFS service
//!   request, dispatches `VopMetaOps` inline, and pre-builds `WorkItem`s
//!   for blocking backend data-plane work.
//! - The **worker** thread pops `WorkItem`s from the submit ring, runs
//!   the blocking call (SaltyFS IPC, netsrv bridge, device read), and
//!   pushes a `Completion` onto the completion ring.
//! - The worker **never touches** `VfsState`. Every `WorkerIoCtx` handed
//!   to a worker has its `state` raw pointer nulled via
//!   `WorkerIoCtx::into_worker_ctx()`.
//! - The owner drains completions at the top of every loop iteration via
//!   [`worker_drain_completions`], before accepting new client requests.
//!
//! ## Ring synchronisation
//!
//! - Submit ring: one producer (owner) + one consumer (the single
//!   Stage-1 worker). SPSC semantics; only owner writes `SUBMIT_HEAD`,
//!   only worker writes `SUBMIT_TAIL`.
//! - Completion ring: up to N producers (workers) + one consumer
//!   (owner). The Stage-1 single-worker case is a degenerate SPSC but
//!   the ring uses the MPSC head-CAS pattern so Stage-3 can scale to
//!   N workers without edit.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use trona_kernel::core_types::TronaMsg;
use trona_kernel::syscall::syscall;
use trona_runtime::thread::thread;
use uapi::{FUTEX_WAIT, FUTEX_WAKE, SYS_FUTEX, SYS_YIELD};

use crate::owner::op::{OpCore, OwnerPostOp};
use crate::vfs_core::error::VfsResult;
use crate::vfs_core::mount::MountHandle;
use crate::vfs_core::vnode::VnodeHandle;
use crate::vfs_core::vop_context::WorkerIoCtx;

// =========================================================================
// Ring capacity
// =========================================================================

/// Submit queue depth. Owner → worker. Matches the saltyfs server loop
/// capacity — 64 outstanding items is enough to cover the typical
/// VFS-stress-mt burst without falling back to inline dispatch.
pub(crate) const SUBMIT_RING_CAP: usize = 64;

/// Completion queue depth. Worker(s) → owner. Sized larger than the
/// submit ring so a burst of completions arriving while the owner is
/// mid-loop cannot block a worker.
pub(crate) const COMPLETION_RING_CAP: usize = 128;

// =========================================================================
// WorkItem — owner → worker
// =========================================================================

/// A unit of blocking work dispatched from the owner loop to a worker.
pub(crate) enum WorkItem {
    /// Empty sentinel for uninitialised ring slots. Head/tail counters
    /// are the authoritative busy/empty indicator; this variant exists
    /// only so the array is `Copy`-initialisable.
    Sentinel,

    /// File read via VopDataOps::read.
    Read {
        op: OpCore,
        client: crate::server::types::ClientHandle,
        fd: i32,
        update_fd_offset: bool,
        data_ctx: WorkerIoCtx,
        offset: u64,
        len: u64,
    },

    /// File write via VopDataOps::write.
    Write {
        op: OpCore,
        client: crate::server::types::ClientHandle,
        fd: i32,
        old_size: u64,
        update_fd_offset: bool,
        data_ctx: WorkerIoCtx,
        offset: u64,
        len: u64,
        data: [u8; crate::server::consts::VFS_INLINE_WRITE_MAX],
    },

    /// SaltyFS remote lookup (cache miss).
    RemoteLookup {
        op: OpCore,
        mount_data: *mut u8,
        parent_ino: u64,
        name: [u8; 255],
        name_len: u8,
    },

    /// Readdir streaming for remote backends.
    Readdir {
        op: OpCore,
        client: crate::server::types::ClientHandle,
        fd: i32,
        data_ctx: WorkerIoCtx,
        cookie: u64,
    },

    /// Bulk read via SHM transport.
    BulkRead {
        op: OpCore,
        client: crate::server::types::ClientHandle,
        fd: i32,
        data_ctx: WorkerIoCtx,
        offset: u64,
        shm_dst: *mut u8,
        len: u64,
    },

    /// Bulk write via SHM transport.
    BulkWrite {
        op: OpCore,
        client: crate::server::types::ClientHandle,
        fd: i32,
        old_size: u64,
        data_ctx: WorkerIoCtx,
        offset: u64,
        shm_src: *const u8,
        len: u64,
    },

    /// Netsrv blocking IPC bridge (TCP/UDP send).
    NetBridge { op: OpCore, net_msg: TronaMsg },

    /// Fsync to remote backend.
    Fsync { op: OpCore, data_ctx: WorkerIoCtx },
}

// SAFETY: Raw pointers in `WorkItem` variants point into non-moving
// arena segments whose slots are flight-counted for the duration of
// the work-item's round-trip (owner → worker → completion → owner).
// Inline write payloads are copied by value into the work item before
// handoff, so workers never borrow the owner's IPC receive buffer.
// `WorkerIoCtx::into_worker_ctx()` nulls the embedded `state` pointer
// before handoff so the worker cannot reach `VfsState`.
unsafe impl Send for WorkItem {}

// =========================================================================
// RemoteInodeInfo — result payload for remote lookups
// =========================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RemoteInodeInfo {
    pub(crate) ino: u64,
    pub(crate) mode: u32,
    pub(crate) size: u64,
    pub(crate) nlink: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) mtime: u64,
    pub(crate) dir_type: u8,
    pub(crate) blocks: u64,
}

// =========================================================================
// Completion — worker → owner
// =========================================================================

#[derive(Clone, Copy)]
pub(crate) enum Completion {
    /// Empty sentinel for uninitialised slots.
    Sentinel,

    /// A data operation completed (read/write/fsync/bulk).
    DataResult {
        op: OpCore,
        vnode_handle: VnodeHandle,
        result: VfsResult<u64>,
        reply_msg: TronaMsg,
        owner_post: OwnerPostOp,
    },

    /// A remote lookup completed.
    RemoteLookupResult {
        op: OpCore,
        mount_handle: MountHandle,
        parent_ino: u64,
        name: [u8; 255],
        name_len: u8,
        result: Result<RemoteInodeInfo, crate::vfs_core::error::VfsError>,
    },

    /// Worker finished — decrement flight count on these handles.
    FlightRelease {
        handles: [VnodeHandle; 4],
        count: u8,
    },
}

unsafe impl Send for Completion {}

// =========================================================================
// Ring storage — per-worker SPSC submit rings + shared MPSC completion
// =========================================================================

// Rust cannot `[SUBMIT_SENTINEL; N]` for a non-Copy enum at const
// context, so each slot is reborrowed from a `MaybeUninit` seed array.
type SubmitRingStorage = [WorkItem; SUBMIT_RING_CAP];

const fn empty_submit_ring() -> SubmitRingStorage {
    let arr: [core::mem::MaybeUninit<WorkItem>; SUBMIT_RING_CAP] =
        [const { core::mem::MaybeUninit::new(WorkItem::Sentinel) }; SUBMIT_RING_CAP];
    // SAFETY: every slot was initialised with `WorkItem::Sentinel`
    // above; reinterpret the `MaybeUninit` array as an initialised
    // `WorkItem` array.
    unsafe {
        let ptr = &arr as *const _ as *const SubmitRingStorage;
        let out = core::ptr::read(ptr);
        core::mem::forget(arr);
        out
    }
}

#[allow(non_upper_case_globals)]
static mut SUBMIT_SLOTS: [SubmitRingStorage; MAX_WORKERS] =
    [const { empty_submit_ring() }; MAX_WORKERS];

// Per-worker head (owner writes) / tail (worker reads) pair.
static SUBMIT_HEAD: [AtomicUsize; MAX_WORKERS] = [const { AtomicUsize::new(0) }; MAX_WORKERS];
static SUBMIT_TAIL: [AtomicUsize; MAX_WORKERS] = [const { AtomicUsize::new(0) }; MAX_WORKERS];

const COMPLETION_SENTINEL: Completion = Completion::Sentinel;

type CompletionRingStorage = [Completion; COMPLETION_RING_CAP];

// Per-worker SPSC completion ring. Owner reads from every ring in
// `worker_drain_completions`; each worker writes only to its own ring.
// SPSC avoids the "head-advanced-before-slot-written" race a naive
// MPSC implementation would have — owner sees a new head only after
// the writing worker has released its slot write.
#[allow(non_upper_case_globals)]
static mut COMPLETION_SLOTS: [CompletionRingStorage; MAX_WORKERS] =
    [[COMPLETION_SENTINEL; COMPLETION_RING_CAP]; MAX_WORKERS];
static COMPLETION_HEAD: [AtomicUsize; MAX_WORKERS] = [const { AtomicUsize::new(0) }; MAX_WORKERS];
static COMPLETION_TAIL: [AtomicUsize; MAX_WORKERS] = [const { AtomicUsize::new(0) }; MAX_WORKERS];

// Worker index is threaded through `run_item_on_worker` / `post_completion`
// as an explicit argument since `#[thread_local]` is nightly-only and
// the spawn-time `worker_idx` is stable for the thread's lifetime anyway.

// =========================================================================
// Worker liveness + wake signalling
// =========================================================================

static WORKERS_SPAWNED: AtomicUsize = AtomicUsize::new(0);
static WORKER_WAKE: [AtomicU32; MAX_WORKERS] = [const { AtomicU32::new(0) }; MAX_WORKERS];

/// How many workers have successfully spawned. Used by `worker_running`
/// / `try_submit` to decide between worker dispatch and inline fallback.
#[inline]
pub(crate) fn workers_spawned() -> usize {
    WORKERS_SPAWNED.load(Ordering::Acquire)
}

/// Is at least one worker live?
#[inline]
pub(crate) fn worker_running() -> bool {
    workers_spawned() > 0
}

/// Maximum number of workers the VFS can spawn. The runtime spawn
/// count may be lower on platforms where thread creation fails partway
/// through. Per-backend-session affinity pinning (see [`route_work`])
/// guarantees no credit-accounting races across workers even at N > 1.
pub(crate) const MAX_WORKERS: usize = 4;

/// Map a `WorkItem` to a target worker index so the worker fan-out can
/// preserve per-session single-writer invariants on
/// `BackendSessionSlot.inflight_now` / the waiter ring. With a single
/// worker this returns 0 unconditionally. The routing priority
/// (when [`MAX_WORKERS`] > 1) is:
///
/// 1. Hash `fs_instance_id` so every op against the same backend
///    session lands on the same worker. Load-bearing: the session's
///    credit / wait-queue accounting lives on
///    [`crate::owner::session::BackendSessionSlot`] and is single-
///    threaded by construction today; routing against the session id
///    preserves that without introducing locks.
/// 2. Fall back to hashing `open_object` for items with no session
///    affinity (currently unused — every data-plane item today carries
///    a session).
/// 3. Finally hash `vnode_handle` as a last-resort tiebreaker.
pub(crate) fn route_work(item: &WorkItem) -> usize {
    if MAX_WORKERS <= 1 {
        return 0;
    }
    let fs_id = extract_fs_instance_id(item);
    if fs_id != 0 {
        return (fs_id as usize) % MAX_WORKERS;
    }
    let open_obj = extract_open_object(item);
    if open_obj != 0 {
        return (open_obj as usize) % MAX_WORKERS;
    }
    let vh = extract_vnode_handle(item);
    (vh as usize) % MAX_WORKERS
}

#[inline]
fn extract_fs_instance_id(item: &WorkItem) -> u64 {
    match item {
        WorkItem::Read { data_ctx, .. }
        | WorkItem::Write { data_ctx, .. }
        | WorkItem::Readdir { data_ctx, .. }
        | WorkItem::BulkRead { data_ctx, .. }
        | WorkItem::BulkWrite { data_ctx, .. }
        | WorkItem::Fsync { data_ctx, .. } => data_ctx.fs_instance_id.raw(),
        WorkItem::RemoteLookup { mount_data, .. } => *mount_data as u64,
        WorkItem::NetBridge { .. } | WorkItem::Sentinel => 0,
    }
}

#[inline]
fn extract_open_object(item: &WorkItem) -> u64 {
    match item {
        WorkItem::Read { data_ctx, .. }
        | WorkItem::Write { data_ctx, .. }
        | WorkItem::Readdir { data_ctx, .. }
        | WorkItem::BulkRead { data_ctx, .. }
        | WorkItem::BulkWrite { data_ctx, .. }
        | WorkItem::Fsync { data_ctx, .. } => {
            data_ctx.open_object.map(|h| h.slot() as u64).unwrap_or(0)
        }
        _ => 0,
    }
}

#[inline]
fn extract_vnode_handle(item: &WorkItem) -> u64 {
    match item {
        WorkItem::Read { data_ctx, .. }
        | WorkItem::Write { data_ctx, .. }
        | WorkItem::Readdir { data_ctx, .. }
        | WorkItem::BulkRead { data_ctx, .. }
        | WorkItem::BulkWrite { data_ctx, .. }
        | WorkItem::Fsync { data_ctx, .. } => data_ctx.vnode_handle.slot() as u64,
        _ => 0,
    }
}

// =========================================================================
// Spawn
// =========================================================================

/// Spawn up to [`MAX_WORKERS`] data-plane workers. Returns the number
/// actually spawned — the caller may proceed with a subset (including
/// zero, which falls back to inline dispatch on submit). Safe to call
/// at most once; subsequent calls return 0.
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
                    _lb.str(b"[vfs] worker spawn failed idx=");
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
        _lb.str(b"[vfs] data-plane workers spawned: ");
        _lb.dec(spawned as u64);
        _lb.str(b"/");
        _lb.dec(MAX_WORKERS as u64);
        _lb.str(b"\n");
    });
    spawned
}

// =========================================================================
// Submit ring API (owner side)
// =========================================================================

/// Try to enqueue a work item onto the worker selected by
/// [`route_work`]. Returns `Some(item)` on failure so the caller can
/// fall back to inline execution. Only the owner thread may call this.
pub(crate) unsafe fn try_submit(item: WorkItem) -> Option<WorkItem> {
    let live_workers = workers_spawned();
    if live_workers == 0 {
        return Some(item);
    }
    let idx = route_work(&item) % live_workers;
    let head = SUBMIT_HEAD[idx].load(Ordering::Relaxed);
    let tail = SUBMIT_TAIL[idx].load(Ordering::Acquire);
    if head.wrapping_sub(tail) >= SUBMIT_RING_CAP {
        return Some(item);
    }
    unsafe {
        let slot = &raw mut SUBMIT_SLOTS[idx][head % SUBMIT_RING_CAP];
        core::ptr::write(slot, item);
    }
    SUBMIT_HEAD[idx].store(head.wrapping_add(1), Ordering::Release);
    // Wake the target worker if it was parked on its futex.
    WORKER_WAKE[idx].fetch_add(1, Ordering::Release);
    let _ = syscall(
        SYS_FUTEX,
        FUTEX_WAKE as u64,
        WORKER_WAKE[idx].as_ptr() as u64,
        1,
        0,
        0,
        0,
    );
    None
}

// =========================================================================
// Completion ring API (owner side)
// =========================================================================

/// Pop one completion from worker `idx`'s SPSC ring. Only the owner
/// thread may call this.
#[inline]
unsafe fn try_pop_completion(idx: usize) -> Option<Completion> {
    if idx >= MAX_WORKERS {
        return None;
    }
    let tail = COMPLETION_TAIL[idx].load(Ordering::Relaxed);
    let head = COMPLETION_HEAD[idx].load(Ordering::Acquire);
    if head == tail {
        return None;
    }
    let comp = unsafe {
        let slot = &raw mut COMPLETION_SLOTS[idx][tail % COMPLETION_RING_CAP];
        core::ptr::replace(slot, Completion::Sentinel)
    };
    COMPLETION_TAIL[idx].store(tail.wrapping_add(1), Ordering::Release);
    Some(comp)
}

/// Drain every completion every worker has posted. Called by the owner
/// loop at the top of each iteration, before accepting new client
/// requests. The owner holds `&mut VfsState` exclusively during this
/// call, so each completion's owner-side side effects (reply emission,
/// resume dispatch, flight-count decrement) run without contention.
///
/// Per-worker rings are polled round-robin so starvation cannot happen
/// when one worker's ring is persistently busy.
pub(crate) unsafe fn worker_drain_completions(state: &mut crate::owner::VfsState) {
    let live = workers_spawned();
    if live == 0 {
        return;
    }
    for idx in 0..live {
        loop {
            let Some(comp) = (unsafe { try_pop_completion(idx) }) else {
                break;
            };
            match comp {
                Completion::Sentinel => {}
                Completion::DataResult {
                    op,
                    vnode_handle: _,
                    result: _,
                    reply_msg,
                    owner_post,
                } => {
                    state.complete_worker_op(op, owner_post, &raw const reply_msg);
                }
                Completion::RemoteLookupResult { .. } => {
                    // Reserved for 2-phase remote lookup (worker fetches
                    // BACKEND_LOOKUP, owner commits vnode + cache).
                    // Not wired today — backend callback EP still
                    // delivers these via `dispatch_pending_reply`.
                }
                Completion::FlightRelease { .. } => {
                    // Reserved for worker-held vnode pins when a
                    // long-running item bumps the flight count. Not
                    // wired today.
                }
            }
        }
    }
}

// =========================================================================
// Worker thread entry
// =========================================================================

/// Worker-thread entry point. `arg` carries the worker index (passed
/// as `worker_idx as *mut u8` at spawn time). Each worker drains its
/// own SPSC submit ring; parks on its own futex when the ring is
/// empty.
#[unsafe(no_mangle)]
unsafe extern "C" fn worker_entry(arg: *mut u8) {
    let worker_idx = arg as usize;
    if worker_idx >= MAX_WORKERS {
        // Should never happen — spawn_workers caps the index. Bail
        // cleanly rather than address out-of-bounds statics.
        return;
    }
    loop {
        let wake_snapshot = WORKER_WAKE[worker_idx].load(Ordering::Acquire);
        // Drain this worker's submit ring.
        loop {
            let tail = SUBMIT_TAIL[worker_idx].load(Ordering::Relaxed);
            let head = SUBMIT_HEAD[worker_idx].load(Ordering::Acquire);
            if head == tail {
                break;
            }
            let item = unsafe {
                let slot = &raw mut SUBMIT_SLOTS[worker_idx][tail % SUBMIT_RING_CAP];
                core::ptr::replace(slot, WorkItem::Sentinel)
            };
            SUBMIT_TAIL[worker_idx].store(tail.wrapping_add(1), Ordering::Release);
            run_item_on_worker(worker_idx, item);
        }
        // Park on this worker's futex until the owner bumps it.
        let _ = unsafe {
            syscall(
                SYS_FUTEX,
                FUTEX_WAIT as u64,
                WORKER_WAKE[worker_idx].as_ptr() as u64,
                wake_snapshot as u64,
                0,
                0,
                0,
            )
        };
    }
}

/// Execute one `WorkItem` on the worker thread. Each arm invokes the
/// backend's `VopDataOps` method against the ctx (which has
/// `state == null` — the worker cannot reach `VfsState`) and posts a
/// `Completion::DataResult` carrying the reply back to the owner's
/// drain loop.
fn run_item_on_worker(worker_idx: usize, item: WorkItem) {
    match item {
        WorkItem::Sentinel => {}
        WorkItem::Fsync { op, data_ctx } => {
            // SAFETY: `data_ctx.vnode_data` / `mount_data` point into
            // non-moving arena segments whose slots are flight-counted
            // for this item's lifetime; the ctx's `state` field is
            // null (owner stripped it via `into_worker_ctx`), so the
            // backend cannot reach `VfsState`.
            let result = unsafe {
                if data_ctx.ops.is_null() {
                    crate::vfs_core::error::VfsResult::<u64>::Err(
                        crate::vfs_core::error::VfsError::Io,
                    )
                } else {
                    match ((*data_ctx.ops).data.fsync)(&data_ctx) {
                        Ok(crate::vfs_core::outcome::VopControl::Ready(())) => Ok(0u64),
                        Ok(crate::vfs_core::outcome::VopControl::Parked(_)) => {
                            Err(crate::vfs_core::error::VfsError::Busy)
                        }
                        Err(e) => Err(e),
                    }
                }
            };
            let mut reply_msg = trona_kernel::core_types::core::TronaMsg::zeroed();
            match result {
                Ok(_) => {
                    reply_msg.label = uapi::TRONA_OK;
                    reply_msg.length = 0;
                }
                Err(e) => {
                    reply_msg.label = e.to_trona();
                }
            }
            post_completion(
                worker_idx,
                Completion::DataResult {
                    op,
                    vnode_handle: data_ctx.vnode_handle,
                    result,
                    reply_msg,
                    owner_post: OwnerPostOp::None,
                },
            );
        }
        WorkItem::Read {
            op,
            client,
            fd,
            update_fd_offset,
            data_ctx,
            offset,
            len,
        } => {
            run_read_on_worker(
                worker_idx,
                op,
                client,
                fd,
                update_fd_offset,
                data_ctx,
                offset,
                len,
            );
        }
        WorkItem::Write {
            op,
            client,
            fd,
            old_size,
            update_fd_offset,
            data_ctx,
            offset,
            len,
            data,
        } => {
            run_write_on_worker(
                worker_idx,
                op,
                client,
                fd,
                old_size,
                update_fd_offset,
                data_ctx,
                offset,
                len,
                &data,
            );
        }
        WorkItem::BulkRead {
            op,
            client,
            fd,
            data_ctx,
            offset,
            shm_dst,
            len,
        } => {
            run_bulk_read_on_worker(worker_idx, op, client, fd, data_ctx, offset, shm_dst, len);
        }
        WorkItem::BulkWrite {
            op,
            client,
            fd,
            old_size,
            data_ctx,
            offset,
            shm_src,
            len,
        } => {
            run_bulk_write_on_worker(
                worker_idx, op, client, fd, old_size, data_ctx, offset, shm_src, len,
            );
        }
        WorkItem::Readdir {
            op,
            client,
            fd,
            data_ctx,
            cookie,
        } => {
            run_readdir_on_worker(worker_idx, op, client, fd, data_ctx, cookie);
        }
        WorkItem::RemoteLookup {
            op,
            mount_data: _,
            parent_ino,
            name,
            name_len,
        } => {
            // Remote lookup is owner-issued today (see
            // `saltyfs_ipc_lookup_issue`); a worker-side variant will
            // materialise with the worker-issued lookup migration. For
            // now, reject the submission so the owner's completion
            // drain surfaces `NotSupported` to any test that probes
            // this path directly, rather than wedging.
            post_completion(
                worker_idx,
                Completion::RemoteLookupResult {
                    op,
                    mount_handle: crate::vfs_core::mount::MountHandle::INVALID,
                    parent_ino,
                    name,
                    name_len,
                    result: Err(crate::vfs_core::error::VfsError::NotSupported),
                },
            );
        }
        WorkItem::NetBridge { op, net_msg: _ } => {
            // Netsrv bridge is owner-issued on the current wire. The
            // worker arm is reserved for a future netsrv migration
            // that moves the blocking round-trip off the owner loop.
            let mut reply_msg = trona_kernel::core_types::core::TronaMsg::zeroed();
            reply_msg.label = crate::vfs_core::error::VfsError::NotSupported.to_trona();
            post_completion(
                worker_idx,
                Completion::DataResult {
                    op,
                    vnode_handle: VnodeHandle::INVALID,
                    result: Err(crate::vfs_core::error::VfsError::NotSupported),
                    reply_msg,
                    owner_post: OwnerPostOp::None,
                },
            );
        }
    }
}

/// Execute a `VopDataOps::read` on the worker. See the `Fsync` arm for
/// the `state == null` invariant. The `len` argument bounds the
/// number of bytes the backend should return; the actual byte count
/// arrives in `reply_msg.regs[0]`.
fn run_read_on_worker(
    worker_idx: usize,
    op: OpCore,
    client: crate::server::types::ClientHandle,
    fd: i32,
    update_fd_offset: bool,
    data_ctx: WorkerIoCtx,
    offset: u64,
    len: u64,
) {
    let (result, reply_msg) = dispatch_data_read_inline(&data_ctx, offset, len);
    let owner_post = match (update_fd_offset, result) {
        (true, Ok(actual)) => OwnerPostOp::SetFileOffset {
            client,
            fd,
            new_offset: offset.saturating_add(actual),
        },
        _ => OwnerPostOp::None,
    };
    post_completion(
        worker_idx,
        Completion::DataResult {
            op,
            vnode_handle: data_ctx.vnode_handle,
            result,
            reply_msg,
            owner_post,
        },
    );
}

fn run_write_on_worker(
    worker_idx: usize,
    op: OpCore,
    client: crate::server::types::ClientHandle,
    fd: i32,
    old_size: u64,
    update_fd_offset: bool,
    data_ctx: WorkerIoCtx,
    offset: u64,
    len: u64,
    data: &[u8; crate::server::consts::VFS_INLINE_WRITE_MAX],
) {
    let result = unsafe { dispatch_data_write(&data_ctx, offset, data.as_ptr(), len) };
    let mut reply_msg = trona_kernel::core_types::core::TronaMsg::zeroed();
    stamp_data_reply_msg(&mut reply_msg, &result);
    let owner_post = match result {
        Ok(written) => {
            let new_offset = offset.saturating_add(written);
            let new_size = core::cmp::max(old_size, new_offset);
            OwnerPostOp::CompleteWrite {
                client,
                fd,
                update_fd_offset,
                write_offset: offset,
                new_offset,
                written,
                old_size,
                new_size,
            }
        }
        Err(_) => OwnerPostOp::None,
    };
    post_completion(
        worker_idx,
        Completion::DataResult {
            op,
            vnode_handle: data_ctx.vnode_handle,
            result,
            reply_msg,
            owner_post,
        },
    );
}

fn run_bulk_read_on_worker(
    worker_idx: usize,
    op: OpCore,
    client: crate::server::types::ClientHandle,
    fd: i32,
    data_ctx: WorkerIoCtx,
    offset: u64,
    shm_dst: *mut u8,
    len: u64,
) {
    let result = unsafe { dispatch_data_bulk_read(&data_ctx, offset, shm_dst, len) };
    let mut reply_msg = trona_kernel::core_types::core::TronaMsg::zeroed();
    stamp_data_reply_msg(&mut reply_msg, &result);
    let owner_post = match result {
        Ok(actual) => OwnerPostOp::SetFileOffset {
            client,
            fd,
            new_offset: offset.saturating_add(actual),
        },
        Err(_) => OwnerPostOp::None,
    };
    post_completion(
        worker_idx,
        Completion::DataResult {
            op,
            vnode_handle: data_ctx.vnode_handle,
            result,
            reply_msg,
            owner_post,
        },
    );
}

fn run_bulk_write_on_worker(
    worker_idx: usize,
    op: OpCore,
    client: crate::server::types::ClientHandle,
    fd: i32,
    old_size: u64,
    data_ctx: WorkerIoCtx,
    offset: u64,
    shm_src: *const u8,
    len: u64,
) {
    let result = unsafe { dispatch_data_bulk_write(&data_ctx, offset, shm_src, len) };
    let mut reply_msg = trona_kernel::core_types::core::TronaMsg::zeroed();
    stamp_data_reply_msg(&mut reply_msg, &result);
    let owner_post = match result {
        Ok(written) => {
            let new_offset = offset.saturating_add(written);
            let new_size = core::cmp::max(old_size, new_offset);
            OwnerPostOp::CompleteWrite {
                client,
                fd,
                update_fd_offset: false,
                write_offset: offset,
                new_offset,
                written,
                old_size,
                new_size,
            }
        }
        Err(_) => OwnerPostOp::None,
    };
    post_completion(
        worker_idx,
        Completion::DataResult {
            op,
            vnode_handle: data_ctx.vnode_handle,
            result,
            reply_msg,
            owner_post,
        },
    );
}

fn run_readdir_on_worker(
    worker_idx: usize,
    op: OpCore,
    client: crate::server::types::ClientHandle,
    fd: i32,
    data_ctx: WorkerIoCtx,
    cookie: u64,
) {
    let (result, reply_msg, next_cookie) = unsafe { dispatch_data_readdir(&data_ctx, cookie) };
    let owner_post = match next_cookie {
        Some(new_cookie) => OwnerPostOp::SetDirCursor {
            client,
            fd,
            new_cursor: new_cookie as u32,
        },
        None => OwnerPostOp::None,
    };
    post_completion(
        worker_idx,
        Completion::DataResult {
            op,
            vnode_handle: data_ctx.vnode_handle,
            result,
            reply_msg,
            owner_post,
        },
    );
}

// ---------------------------------------------------------------------
// Inline dispatch helpers — invoke the backend's `VopDataOps` method.
//
// The worker owns no `&mut VfsState`; these helpers read the ctx's
// vtable pointer (`ctx.ops`) and invoke the backend's registered
// function. Current VFS backends route these through their
// `VopDataOps` surface; any backend that would genuinely block on an
// internal kernel call lives inside this single worker-side dispatch
// path. Owner-side inline fallback uses the same helpers.
// ---------------------------------------------------------------------

fn dispatch_data_read_inline(
    ctx: &WorkerIoCtx,
    offset: u64,
    len: u64,
) -> (VfsResult<u64>, TronaMsg) {
    let mut reply_msg = trona_kernel::core_types::core::TronaMsg::zeroed();
    if ctx.ops.is_null() {
        reply_msg.label = crate::vfs_core::error::VfsError::Io.to_trona();
        return (Err(crate::vfs_core::error::VfsError::Io), reply_msg);
    }
    let dst = &raw mut reply_msg.regs[1] as *mut u8;
    let result = unsafe {
        match ((*ctx.ops).data.read)(ctx, offset, dst, len) {
            Ok(crate::vfs_core::outcome::VopControl::Ready(actual)) => Ok(actual),
            Ok(crate::vfs_core::outcome::VopControl::Parked(_)) => {
                Err(crate::vfs_core::error::VfsError::Busy)
            }
            Err(e) => Err(e),
        }
    };
    stamp_read_reply_msg(&mut reply_msg, &result);
    (result, reply_msg)
}

unsafe fn dispatch_data_write(
    ctx: &WorkerIoCtx,
    offset: u64,
    data_ptr: *const u8,
    len: u64,
) -> VfsResult<u64> {
    if ctx.ops.is_null() {
        return Err(crate::vfs_core::error::VfsError::Io);
    }
    match unsafe { ((*ctx.ops).data.write)(ctx, offset, data_ptr, len) } {
        Ok(crate::vfs_core::outcome::VopControl::Ready(written)) => Ok(written),
        Ok(crate::vfs_core::outcome::VopControl::Parked(_)) => {
            Err(crate::vfs_core::error::VfsError::Busy)
        }
        Err(e) => Err(e),
    }
}

unsafe fn dispatch_data_bulk_read(
    ctx: &WorkerIoCtx,
    offset: u64,
    shm_dst: *mut u8,
    len: u64,
) -> VfsResult<u64> {
    if ctx.ops.is_null() {
        return Err(crate::vfs_core::error::VfsError::Io);
    }
    match unsafe { ((*ctx.ops).data.read)(ctx, offset, shm_dst, len) } {
        Ok(crate::vfs_core::outcome::VopControl::Ready(actual)) => Ok(actual),
        Ok(crate::vfs_core::outcome::VopControl::Parked(_)) => {
            Err(crate::vfs_core::error::VfsError::Busy)
        }
        Err(e) => Err(e),
    }
}

unsafe fn dispatch_data_bulk_write(
    ctx: &WorkerIoCtx,
    offset: u64,
    shm_src: *const u8,
    len: u64,
) -> VfsResult<u64> {
    if ctx.ops.is_null() {
        return Err(crate::vfs_core::error::VfsError::Io);
    }
    match unsafe { ((*ctx.ops).data.write)(ctx, offset, shm_src, len) } {
        Ok(crate::vfs_core::outcome::VopControl::Ready(written)) => Ok(written),
        Ok(crate::vfs_core::outcome::VopControl::Parked(_)) => {
            Err(crate::vfs_core::error::VfsError::Busy)
        }
        Err(e) => Err(e),
    }
}

unsafe fn dispatch_data_readdir(
    ctx: &WorkerIoCtx,
    cookie: u64,
) -> (VfsResult<u64>, TronaMsg, Option<u64>) {
    let mut reply_msg = trona_kernel::core_types::core::TronaMsg::zeroed();
    if ctx.ops.is_null() {
        reply_msg.label = crate::vfs_core::error::VfsError::Io.to_trona();
        return (Err(crate::vfs_core::error::VfsError::Io), reply_msg, None);
    }

    let mut cookie_mut = cookie;
    let mut got_entry = false;
    let emit_fn = &mut |ino: u64,
                        name: *const u8,
                        name_len: u8,
                        d_type: u8,
                        _attr: &crate::vfs_core::file::VAttr|
     -> bool {
        reply_msg.label = uapi::TRONA_OK;
        reply_msg.length = 5 + ((name_len as u64 + 7) / 8);
        reply_msg.regs[0] = name_len as u64;
        reply_msg.regs[1] = 0;
        reply_msg.regs[2] = ino;
        reply_msg.regs[3] = d_type as u64;
        for reg in 4..20 {
            reply_msg.regs[reg] = 0;
        }
        let dst = &raw mut reply_msg.regs[4] as *mut u8;
        for idx in 0..name_len as usize {
            *dst.add(idx) = *name.add(idx);
        }
        got_entry = true;
        false
    };

    match unsafe { ((*ctx.ops).data.readdir)(ctx, &raw mut cookie_mut, emit_fn) } {
        Ok(crate::vfs_core::outcome::VopControl::Ready(())) => {
            if !got_entry {
                reply_msg.label = uapi::TRONA_OK;
                reply_msg.length = 1;
                reply_msg.regs[0] = 0;
            }
            (Ok(0), reply_msg, Some(cookie_mut))
        }
        Ok(crate::vfs_core::outcome::VopControl::Parked(_)) => {
            reply_msg.label = crate::vfs_core::error::VfsError::Busy.to_trona();
            (Err(crate::vfs_core::error::VfsError::Busy), reply_msg, None)
        }
        Err(e) => {
            if !got_entry {
                reply_msg.label = e.to_trona();
            }
            (Err(e), reply_msg, None)
        }
    }
}

fn stamp_data_reply_msg(reply_msg: &mut TronaMsg, result: &VfsResult<u64>) {
    match result {
        Ok(n) => {
            reply_msg.label = uapi::TRONA_OK;
            reply_msg.length = 1;
            reply_msg.regs[0] = *n;
        }
        Err(e) => {
            reply_msg.label = e.to_trona();
        }
    }
}

fn stamp_read_reply_msg(reply_msg: &mut TronaMsg, result: &VfsResult<u64>) {
    match result {
        Ok(n) => {
            reply_msg.label = uapi::TRONA_OK;
            reply_msg.length = 1 + (*n + 7) / 8;
            reply_msg.regs[0] = *n;
        }
        Err(e) => {
            reply_msg.label = e.to_trona();
        }
    }
}

// (helper retired — `WorkerIoCtx.ops` now carries the backend vtable
// pointer directly.)

/// Post a completion onto worker `idx`'s SPSC ring. Called from the
/// worker thread that owns that ring. SPSC-correct: head is advanced
/// only after the slot write has released — owner observes the new
/// head only after the slot contents are visible (Release/Acquire
/// pairing on the tail-side).
fn post_completion(idx: usize, comp: Completion) {
    if idx >= MAX_WORKERS {
        return;
    }
    loop {
        let head = COMPLETION_HEAD[idx].load(Ordering::Relaxed);
        let tail = COMPLETION_TAIL[idx].load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= COMPLETION_RING_CAP {
            // Ring full — spin until the owner drains.
            let _ = unsafe { syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0) };
            continue;
        }
        // SPSC: this worker is the only writer for ring `idx`.
        // Write the slot BEFORE advancing head so the consumer sees
        // a populated slot for every head increment it observes.
        unsafe {
            let slot = &raw mut COMPLETION_SLOTS[idx][head % COMPLETION_RING_CAP];
            core::ptr::write(slot, comp);
        }
        COMPLETION_HEAD[idx].store(head.wrapping_add(1), Ordering::Release);
        if head == tail {
            notify_owner_completion_ready();
        }
        return;
    }
}

fn notify_owner_completion_ready() {
    let ep = crate::backend::backend_callback_ep();
    if ep == 0 {
        return;
    }
    let mut msg = TronaMsg::zeroed();
    msg.label = crate::server::consts::VFS_OWNER_WORKER_KICK;
    unsafe {
        trona_kernel::ipc::clear_send_caps_ctx(crate::ipc_ctx());
        let _ = trona_kernel::ipc::send_ctx(crate::ipc_ctx(), ep, &raw const msg);
    }
}
