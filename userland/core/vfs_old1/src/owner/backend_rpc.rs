// SPDX-License-Identifier: GPL-2.0-only
//! Backend-RPC dataplane: jobs flow `owner → workers → completion → owner`.
//!
//! The owner places a `PendingBackendJob` on the job ring and wakes a
//! worker via `WORKER_WAKE`. The worker performs the blocking
//! `ipc::call_ctx`, pushes a `PendingBackendCompletion` onto the
//! completion ring, and signals `WORKER_COMPLETION_NTFN` so the owner
//! returns from `recv_any_ctx` and runs the per-op state-commit
//! followed by `send_saved_reply` to the original client.
//!
//! Both rings live as module-level statics behind their own
//! `SpinLock` + `UnsafeCell`. They are intentionally not part of
//! `VfsState` — workers must not dereference owner-only state, but
//! they need access to the rings.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use trona_kernel::core_types::*;
use trona_runtime::thread::worker::SpinLock;

pub(crate) const BACKEND_JOB_RING_CAP: usize = 16;
pub(crate) const BACKEND_COMPLETION_RING_CAP: usize = 16;

/// Routing tag the owner uses to dispatch a completion back to the
/// right per-op state-commit handler.
pub(crate) type BackendOpKind = u32;
pub(crate) const BACKEND_OP_NONE: BackendOpKind = 0;
/// `POSIX_TTYSRV_PTY_OPEN_SLAVE` — input pty_id/generation via
/// `ctx.data0/data1`, output success in `backend_reply.label`.
pub(crate) const BACKEND_OP_TTYSRV_OPEN_SLAVE: BackendOpKind = 6;
/// `POSIX_TTYSRV_PTY_GET_GENERATION` — input pty_id via `ctx.data0`,
/// output generation in `backend_reply.regs[0]`.
pub(crate) const BACKEND_OP_TTYSRV_GET_GENERATION: BackendOpKind = 7;
/// procfs PidStatus read — fetches `KinfoProc` and formats the
/// `Name:`/`State:`/`Pid:`/... text into the saved reply.
pub(crate) const BACKEND_OP_PROCFS_READ_PID_STATUS: BackendOpKind = 8;
/// procfs PidComm read — fetches `KinfoProc` and writes `comm\n`.
pub(crate) const BACKEND_OP_PROCFS_READ_PID_COMM: BackendOpKind = 9;
/// procfs PidStatm read — fetches `TronaProcMemSnapshot` and writes
/// the seven-field statm line.
pub(crate) const BACKEND_OP_PROCFS_READ_PID_STATM: BackendOpKind = 10;
/// procfs PidCmdline read — fetches argv bytes from init.
pub(crate) const BACKEND_OP_PROCFS_READ_PID_CMDLINE: BackendOpKind = 11;
/// procfs PidStat stage 0 — fetches `KinfoProc`. Completion enqueues
/// stage 1 (`PROCFS_READ_PID_STAT_STAGE1`) with the `KinfoProc` packed
/// into the next job's `request.regs[2..]` so the second stage carries
/// the data forward.
pub(crate) const BACKEND_OP_PROCFS_READ_PID_STAT_STAGE0: BackendOpKind = 12;
/// procfs PidStat stage 1 — fetches `proc_times`, formats the final
/// stat line using the `KinfoProc` saved in `ctx.data` and the times
/// returned in `backend_reply.regs[0..4]`.
pub(crate) const BACKEND_OP_PROCFS_READ_PID_STAT_STAGE1: BackendOpKind = 13;
/// procfs PidExe readlink — fetches exe path bytes from init via
/// `INIT_GET_EXE_PATH`. Output bytes inline in `backend_reply.regs[1..]`.
pub(crate) const BACKEND_OP_PROCFS_READLINK_PID_EXE: BackendOpKind = 14;
/// procfs root readdir — fetches one pid via `INIT_LIST_PIDS_BUF`.
/// Completion installs the resulting name into the readdir reply.
pub(crate) const BACKEND_OP_PROCFS_READDIR_PIDS: BackendOpKind = 15;
/// procfs RootStat read — fetches `pm_get_system_stats`. Completion
/// runs `sys_sysinfo` (pure syscall) on the owner side and formats the
/// `/proc/stat` text.
pub(crate) const BACKEND_OP_PROCFS_READ_ROOT_STAT: BackendOpKind = 16;
/// procfs RootLoadavg read — fetches `pm_get_system_stats`. Completion
/// formats the `/proc/loadavg` text directly from the reply regs.
pub(crate) const BACKEND_OP_PROCFS_READ_ROOT_LOADAVG: BackendOpKind = 17;

/// saltyfs disk-IO RPCs to blkdrv. The saltyfs vop encodes its
/// per-op scratch (vnode id, offset, length, leaf-name slice, …) in
/// `ctx.data` and the request `TronaMsg`; the worker performs
/// `call_ctx(blkdrv_ep, request, reply)` and the completion
/// dispatcher in `fs/saltyfs.rs::complete_saltyfs_op` interprets
/// `backend_reply` per kind.
pub(crate) const BACKEND_OP_SALTYFS_LOOKUP_CHILD: BackendOpKind = 18;
pub(crate) const BACKEND_OP_SALTYFS_READ: BackendOpKind = 19;
pub(crate) const BACKEND_OP_SALTYFS_WRITE: BackendOpKind = 20;
pub(crate) const BACKEND_OP_SALTYFS_MKDIR: BackendOpKind = 21;
pub(crate) const BACKEND_OP_SALTYFS_CREATE: BackendOpKind = 22;
pub(crate) const BACKEND_OP_SALTYFS_TRUNCATE: BackendOpKind = 23;
pub(crate) const BACKEND_OP_SALTYFS_UNLINK: BackendOpKind = 24;
pub(crate) const BACKEND_OP_SALTYFS_SYMLINK: BackendOpKind = 25;
pub(crate) const BACKEND_OP_SALTYFS_LINK: BackendOpKind = 26;
pub(crate) const BACKEND_OP_SALTYFS_RENAME: BackendOpKind = 27;
pub(crate) const BACKEND_OP_SALTYFS_SETMODE: BackendOpKind = 28;
pub(crate) const BACKEND_OP_SALTYFS_SETOWNER: BackendOpKind = 29;
pub(crate) const BACKEND_OP_SALTYFS_SETTIMES: BackendOpKind = 30;
pub(crate) const BACKEND_OP_SALTYFS_READLINK: BackendOpKind = 31;

/// ttysrv RPCs deferred via the worker pool. Each kind maps 1:1 to a
/// `POSIX_TTYSRV_*` IPC label; the completion handler in
/// `fileops/device.rs::complete_device_op` matches on this kind to
/// dispatch state mutation + reply shipping. `OPEN_SLAVE` (=6) and
/// `GET_GENERATION` (=7) above are reused by the multi-stage
/// stdio-provisioning chain.
pub(crate) const BACKEND_OP_TTYSRV_PROVISION_STDIO: BackendOpKind = 32;
pub(crate) const BACKEND_OP_TTYSRV_PTY_LOOKUP: BackendOpKind = 33;
pub(crate) const BACKEND_OP_TTYSRV_PTY_READ: BackendOpKind = 34;

/// mmsrv shm RPCs deferred via the worker pool. The completion
/// handler in `fileops/shm.rs::complete_shm_op` interprets the reply
/// per kind (CREATE returns shm_id; DESTROY/MAP/UNMAP return label only).
pub(crate) const BACKEND_OP_MMSRV_SHM_CREATE: BackendOpKind = 35;
pub(crate) const BACKEND_OP_MMSRV_SHM_DESTROY: BackendOpKind = 36;
pub(crate) const BACKEND_OP_MMSRV_SHM_MAP: BackendOpKind = 37;
pub(crate) const BACKEND_OP_MMSRV_SHM_UNMAP: BackendOpKind = 38;

/// netsrv RPCs deferred via the worker pool. `NET_*_WAIT` kinds stay
/// on the existing `INET_WAIT` waiter path (`fileops/inet_wait.rs`);
/// these are the *non-wait* sync RPCs that the owner used to
/// `call_ctx` on directly. Completion handler in
/// `fileops/socket.rs::complete_netsrv_op`.
pub(crate) const BACKEND_OP_NETSRV_OPEN: BackendOpKind = 39;
pub(crate) const BACKEND_OP_NETSRV_CONNECT: BackendOpKind = 40;
pub(crate) const BACKEND_OP_NETSRV_LISTEN: BackendOpKind = 41;
pub(crate) const BACKEND_OP_NETSRV_BIND: BackendOpKind = 42;
pub(crate) const BACKEND_OP_NETSRV_SEND: BackendOpKind = 43;
pub(crate) const BACKEND_OP_NETSRV_SENDTO: BackendOpKind = 44;
pub(crate) const BACKEND_OP_NETSRV_GET_SOCKNAME: BackendOpKind = 45;
pub(crate) const BACKEND_OP_NETSRV_GET_PEERNAME: BackendOpKind = 46;

/// Maximum `reserved`-area payload bytes copied from worker
/// `call_ctx` into the completion. Sized to fit the largest
/// `init`/`procmgr` reply struct used by procfs (`TronaProcMemSnapshot`
/// + `KinfoProc` are well under 512 B). Larger payloads truncate.
pub(crate) const BACKEND_PAYLOAD_MAX: usize = 512;

/// Op-specific scratch shared between owner and worker. Worker copies
/// this verbatim from job to completion; owner reinterprets per
/// `op_kind`. Multi-stage chains (e.g. tty stdio provisioning that
/// performs `lookup_generation` then three `open_slave` calls) keep
/// per-stage state in `data[]` and bump `stage` on every completion.
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct BackendOpCtx {
    pub(crate) badge: u64,
    pub(crate) client_handle_raw: u64,
    pub(crate) stage: u32,
    pub(crate) _pad0: u32,
    pub(crate) data: [u64; 6],
}

impl BackendOpCtx {
    pub(crate) const fn zeroed() -> Self {
        Self {
            badge: 0,
            client_handle_raw: 0,
            stage: 0,
            _pad0: 0,
            data: [0; 6],
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct PendingBackendJob {
    pub(crate) target_ep: Cap,
    pub(crate) op_kind: BackendOpKind,
    /// Number of bytes the worker should copy from `ipc_buffer.reserved`
    /// after `call_ctx` returns. Zero means the worker only forwards
    /// `backend_reply` (label + regs).
    pub(crate) payload_out_bytes: u32,
    /// `PendingOpId` (raw u64). The reply continuation lives in the
    /// `PendingOp` table — workers never touch the reply slot
    /// directly; the owner takes it via
    /// `pending_ops::take_reply_slot` when it commits the
    /// completion.
    pub(crate) op_id: u64,
    pub(crate) request: TronaMsg,
    pub(crate) ctx: BackendOpCtx,
}

impl PendingBackendJob {
    pub(crate) const fn zeroed() -> Self {
        Self {
            target_ep: 0,
            op_kind: BACKEND_OP_NONE,
            payload_out_bytes: 0,
            op_id: 0,
            request: TronaMsg::zeroed(),
            ctx: BackendOpCtx::zeroed(),
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct PendingBackendCompletion {
    pub(crate) op_kind: BackendOpKind,
    pub(crate) payload_len: u32,
    /// `PendingOpId` raw value (carried verbatim from the originating
    /// job). Owner uses this to take the saved reply continuation and
    /// to validate generation on stale completions.
    pub(crate) op_id: u64,
    pub(crate) backend_err: u64,
    pub(crate) backend_reply: TronaMsg,
    pub(crate) ctx: BackendOpCtx,
    /// Verbatim copy of the leading `payload_len` bytes of the
    /// worker's `ipc_buffer.reserved` after `call_ctx`. Owners of
    /// payload-bearing ops reinterpret this as the relevant struct
    /// (e.g. `KinfoProc`, `TronaProcMemSnapshot`).
    pub(crate) payload: [u8; BACKEND_PAYLOAD_MAX],
}

impl PendingBackendCompletion {
    pub(crate) const fn zeroed() -> Self {
        Self {
            op_kind: BACKEND_OP_NONE,
            payload_len: 0,
            op_id: 0,
            backend_err: 0,
            backend_reply: TronaMsg::zeroed(),
            ctx: BackendOpCtx::zeroed(),
            payload: [0; BACKEND_PAYLOAD_MAX],
        }
    }
}

struct JobRingInner {
    head: u32,
    tail: u32,
    slots: [PendingBackendJob; BACKEND_JOB_RING_CAP],
}

impl JobRingInner {
    const fn new() -> Self {
        Self {
            head: 0,
            tail: 0,
            slots: [const { PendingBackendJob::zeroed() }; BACKEND_JOB_RING_CAP],
        }
    }
}

struct CompletionRingInner {
    head: u32,
    tail: u32,
    slots: [PendingBackendCompletion; BACKEND_COMPLETION_RING_CAP],
}

impl CompletionRingInner {
    const fn new() -> Self {
        Self {
            head: 0,
            tail: 0,
            slots: [const { PendingBackendCompletion::zeroed() }; BACKEND_COMPLETION_RING_CAP],
        }
    }
}

struct LockedJobRing {
    lock: SpinLock,
    inner: UnsafeCell<JobRingInner>,
}

// SAFETY: every access to `inner` happens with `lock` held.
unsafe impl Sync for LockedJobRing {}

impl LockedJobRing {
    const fn new() -> Self {
        Self {
            lock: SpinLock::new(),
            inner: UnsafeCell::new(JobRingInner::new()),
        }
    }
}

struct LockedCompletionRing {
    lock: SpinLock,
    inner: UnsafeCell<CompletionRingInner>,
}

// SAFETY: every access to `inner` happens with `lock` held.
unsafe impl Sync for LockedCompletionRing {}

impl LockedCompletionRing {
    const fn new() -> Self {
        Self {
            lock: SpinLock::new(),
            inner: UnsafeCell::new(CompletionRingInner::new()),
        }
    }
}

static JOB_RING: LockedJobRing = LockedJobRing::new();
static COMPLETION_RING: LockedCompletionRing = LockedCompletionRing::new();

/// Bit reserved on the VFS owner bound notification for worker-pool
/// completions. Low bits are owned by PTY wakeups (`1 << pty_id`), so
/// worker wakeups live in a high bit and are demuxed before the
/// remaining notification word is handed to tty_wait.
pub(crate) const WORKER_COMPLETION_NTFN_BIT: u64 = 1u64 << 63;

/// Notification cap workers signal to wake the owner when they have
/// pushed a completion. Set by `main` once the cap is allocated.
static WORKER_COMPLETION_NTFN: AtomicU64 = AtomicU64::new(0);
static WORKER_COMPLETION_SIGNAL_BITS: AtomicU64 = AtomicU64::new(WORKER_COMPLETION_NTFN_BIT);

pub(crate) fn set_worker_completion_ntfn(cap: Cap, signal_bits: u64) {
    WORKER_COMPLETION_NTFN.store(cap, Ordering::Release);
    WORKER_COMPLETION_SIGNAL_BITS.store(signal_bits, Ordering::Release);
}

pub(crate) fn worker_completion_ntfn() -> Cap {
    WORKER_COMPLETION_NTFN.load(Ordering::Acquire)
}

pub(crate) fn worker_completion_signal_bits() -> u64 {
    WORKER_COMPLETION_SIGNAL_BITS.load(Ordering::Acquire)
}

/// Owner-side: enqueue a job for a worker. Returns `false` if the
/// ring is full — caller should fall back to a direct synchronous
/// backend call (degraded mode preserves request liveness even when
/// workers are saturated).
pub(crate) fn push_job(job: PendingBackendJob) -> bool {
    JOB_RING.lock.acquire();
    let result = unsafe {
        let r = &mut *JOB_RING.inner.get();
        let next = (r.tail + 1) % (BACKEND_JOB_RING_CAP as u32);
        if next == r.head {
            false
        } else {
            r.slots[r.tail as usize] = job;
            r.tail = next;
            true
        }
    };
    JOB_RING.lock.release();
    result
}

/// Worker-side: dequeue the next job. Returns `None` if the ring is
/// empty.
pub(crate) fn pop_job() -> Option<PendingBackendJob> {
    JOB_RING.lock.acquire();
    let result = unsafe {
        let r = &mut *JOB_RING.inner.get();
        if r.head == r.tail {
            None
        } else {
            let job = r.slots[r.head as usize];
            r.head = (r.head + 1) % (BACKEND_JOB_RING_CAP as u32);
            Some(job)
        }
    };
    JOB_RING.lock.release();
    result
}

/// Worker-side: enqueue a completion for the owner. Returns `false`
/// if the ring is full — should not happen in normal operation since
/// job and completion rings share the same depth and the owner drains
/// on every notification tick.
pub(crate) fn push_completion(completion: PendingBackendCompletion) -> bool {
    COMPLETION_RING.lock.acquire();
    let result = unsafe {
        let r = &mut *COMPLETION_RING.inner.get();
        let next = (r.tail + 1) % (BACKEND_COMPLETION_RING_CAP as u32);
        if next == r.head {
            false
        } else {
            r.slots[r.tail as usize] = completion;
            r.tail = next;
            true
        }
    };
    COMPLETION_RING.lock.release();
    result
}

/// Owner-side: dequeue the next completion. Returns `None` if the
/// ring is empty.
pub(crate) fn pop_completion() -> Option<PendingBackendCompletion> {
    COMPLETION_RING.lock.acquire();
    let result = unsafe {
        let r = &mut *COMPLETION_RING.inner.get();
        if r.head == r.tail {
            None
        } else {
            let c = r.slots[r.head as usize];
            r.head = (r.head + 1) % (BACKEND_COMPLETION_RING_CAP as u32);
            Some(c)
        }
    };
    COMPLETION_RING.lock.release();
    result
}

/// Worker-side: signal the owner that completions are ready. No-op
/// when the cap has not been set yet (boot ordering).
pub(crate) fn signal_owner_completion() {
    let cap = worker_completion_ntfn();
    if cap == 0 {
        return;
    }
    let _ = trona_kernel::syscall::syscall(
        uapi::SYS_SIGNAL,
        cap,
        worker_completion_signal_bits(),
        0,
        0,
        0,
        0,
    );
}

/// Owner-side: enqueue a job and wake a worker atomically with the
/// no-worker degraded-mode check. Returns false when there are no
/// workers OR the ring is full — caller must fall back to a sync
/// backend call to avoid leaking the saved reply slot.
pub(crate) fn try_enqueue_job(job: PendingBackendJob) -> bool {
    if crate::owner::worker::worker_count() == 0 {
        return false;
    }
    if !push_job(job) {
        return false;
    }
    if !crate::owner::worker::wake_one_worker() {
        return false;
    }
    true
}

/// Enqueue a saltyfs disk-IO RPC on the worker pool. The caller
/// (saltyfs vop) is responsible for:
///   1. Allocating the `op_id` with kind `PO_KIND_BACKEND_RPC` via
///      `pending_ops::alloc(...)`.
///   2. Allocating its payload via `pending_ops::alloc_payload()` and
///      writing a placeholder `NameiResumeState` (resume_step =
///      `NAMEI_STEP_DONE`, aux_kind = `NAMEI_AUX_NONE`, aux =
///      `namei_aux_none()`). The continuation framework requires a
///      valid payload before the op can adopt-or-transition.
///   3. Filling `request` with the saltyfs IPC label and regs, and
///      `ctx_data` with per-op scratch (inode, offset, …) that the
///      saltyfs completion handler in
///      `fs/saltyfs.rs::complete_saltyfs_op` will read on reply.
///
/// `target_ep` is the saltyfs *server* endpoint cap (typically
/// `MountData.fs_cap`); VFS talks to the saltyfs server, which in
/// turn drives blkdrv. VFS itself never holds a blkdrv cap.
///
/// Returns `false` when the worker pool is degraded (no workers) or
/// the job ring is full. Client-request callers must treat this as a
/// hard failure (release `op_id` via `pending_ops::free` and reply
/// with `TRONA_OUT_OF_MEMORY` synchronously). Never sync-fallback in
/// a client path. Bootstrap-phase callers may bypass this enqueue
/// and use saltyfs's internal `*_sync` helpers directly.
///
/// # Safety
///
/// Owner-thread only. Caller has already populated the PendingOp's
/// reply slot (zero is fine for non-syscall-replying saltyfs ops —
/// the syscall handler that adopts the op via
/// `adopt_deferred_op_for_continuation` overwrites it later).
pub(crate) unsafe fn enqueue_saltyfs_op(
    op_id: super::pending_ops::PendingOpId,
    backend_op: BackendOpKind,
    target_ep: Cap,
    request: TronaMsg,
    ctx_data: [u64; 6],
) -> bool {
    let job = PendingBackendJob {
        target_ep,
        op_kind: backend_op,
        payload_out_bytes: 0,
        op_id: op_id.raw(),
        request,
        ctx: BackendOpCtx {
            badge: 0,
            client_handle_raw: 0,
            stage: 0,
            _pad0: 0,
            data: ctx_data,
        },
    };
    try_enqueue_job(job)
}

/// Generic backend-RPC enqueue used by `device.rs` (ttysrv),
/// `shm.rs` (mmsrv), and `socket.rs` (netsrv non-wait sync RPCs).
/// Same caller invariants as `enqueue_saltyfs_op` (alloc `op_id`,
/// alloc + init payload as a placeholder `NameiResumeState` if the op
/// participates in any continuation/cancel walk that reads the
/// payload, populate caller context). `payload_out_bytes` requests
/// the worker copy that many leading bytes from
/// `ipc_buffer.reserved` after `call_ctx` returns — set to 0 unless
/// the backend returns a typed payload struct.
///
/// Returns `false` when the worker pool is degraded (no workers) or
/// the job ring is full. Client-request callers must treat this as a
/// hard failure (release `op_id` via `pending_ops::free` and reply
/// with `TRONA_OUT_OF_MEMORY` synchronously). Never sync-fallback in
/// a client path. Bootstrap-phase callers may bypass this enqueue
/// and use the backend's internal `*_sync` helpers directly.
///
/// # Safety
///
/// Owner-thread only. Caller has populated the PendingOp's reply slot
/// (zero is OK if the op is adopted into a `*_CONT` later via
/// `adopt_deferred_op_for_continuation`).
pub(crate) unsafe fn enqueue_backend_op(
    op_id: super::pending_ops::PendingOpId,
    backend_op: BackendOpKind,
    target_ep: Cap,
    request: TronaMsg,
    ctx_data: [u64; 6],
    payload_out_bytes: u32,
) -> bool {
    let job = PendingBackendJob {
        target_ep,
        op_kind: backend_op,
        payload_out_bytes,
        op_id: op_id.raw(),
        request,
        ctx: BackendOpCtx {
            badge: 0,
            client_handle_raw: 0,
            stage: 0,
            _pad0: 0,
            data: ctx_data,
        },
    };
    try_enqueue_job(job)
}
