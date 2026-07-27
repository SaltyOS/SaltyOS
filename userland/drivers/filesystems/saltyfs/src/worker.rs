//! SaltyFS writeback worker thread.
//!
//! The saltyfs owner thread retains metadata authority (B-tree walk,
//! inode allocation, transaction commit ordering) and every
//! request/reply path. Writeback of dirty cache blocks, superblock
//! flushes, and future checksum verification run on this worker
//! instead, so the owner loop never blocks on a `blkdrv` IPC call
//! while waiting for the next VFS request.
//!
//! # Serialisation with [`BLOCK_LOCK`]
//!
//! Every mutation of the process-global `block::*` state — the block
//! cache, `CACHE_DIRTY`, `BITMAP_*`, the in-memory superblock plus
//! `SB_DIRTY`, and the shared blkdrv SHM scratch region used by
//! `write_block` / `read_block` — must happen while [`BLOCK_LOCK`] is
//! held. Owner and worker are distinct threads sharing the same
//! address space; without this mutex, owner-side synchronous I/O
//! (B-tree walk, inode alloc, dirty-cache population) could race the
//! worker's writeback path and corrupt the on-disk image or the
//! in-memory caches.
//!
//! The lock is released on the owner side before the outer IPC wait
//! (`mp_write_reply_read_ctx` / the initial `mp_read_ctx`), so the worker can
//! drain its submit ring while the owner is parked waiting for the
//! next client request. `submit_or_run`'s inline fallback assumes the
//! caller already holds the lock (it does — the server-loop dispatch
//! block always owns it when submitting jobs); the inline path does
//! not re-enter the lock.
//!
//! Communication is a bounded SPSC submit ring plus a small owner-facing
//! status ring:
//!
//! - `submit_ring` — owner → worker. Holds [`WorkerJob`] records with a
//!   monotonic `tx_id` and a kind enum. The ring is bounded; the owner
//!   spins briefly on full, then falls through to a synchronous flush
//!   as backpressure. A counting semaphore tracks the number of queued
//!   items, so the worker never sleeps past a published job.
//! - `completion_ring` — worker → owner. Holds status-only flush
//!   results for writeback accounting. Jobs
//!   that already carry a fully built client reply (`ReadBlocks`,
//!   `OpenSession`) are sent directly by the worker after it drops
//!   [`BLOCK_LOCK`].
//!
//! All shared state is plain `static mut` + atomics — this module is
//! the single-owner / single-worker synchronisation surface.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use trona_kernel::core_types::TronaMsg;
use trona_kernel::ipc;
use trona_kernel::uapi;
use trona_protocol::common::{
    TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION, TRONA_IO_ERROR, TRONA_OK, TRONA_OUT_OF_MEMORY,
    TRONA_OUT_OF_RANGE,
};
use trona_protocol::correlation::{
    CORRELATION_HEADER_REG_START, CORRELATION_KIND_COMPLETION, CorrelationHeader,
    ensure_correlation_wire_length,
};
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::thread::sync::{Mutex, Semaphore};
use trona_runtime::thread::thread;

use crate::block;
use crate::consts::{MO_STAGING_SIZE, MO_STAGING_VADDR};

/// Submit queue depth. Owner → worker.
pub(crate) const SUBMIT_RING_CAP: usize = 64;
/// Completion queue depth. Worker → owner.
pub(crate) const COMPLETION_RING_CAP: usize = 64;

/// Single-writer global lock protecting every `block::*` accessor —
/// cache + bitmap + superblock + blkdrv SHM scratch. Owner acquires
/// it at the top of each server-loop iteration (after the initial
/// `mp_read_ctx`) and releases it before the outer IPC wait. Worker
/// acquires it per-job. See the module-level doc for the ownership
/// discipline. `pub(crate)` so `main.rs` can bracket the dispatch
/// block with `BLOCK_LOCK.lock()` / `BLOCK_LOCK.unlock()` calls.
pub(crate) static BLOCK_LOCK: Mutex = Mutex::new();

/// Hybrid-1 BACKEND_WRITE payload kinds. Lives in the submit ring via
/// `ptr::read` (move-out) and `ptr::write` (move-in) so the ring
/// entry is never aliased while the worker holds the job. `ptr::write`
/// is mandatory on the push side: slots may hold moved-out (stale)
/// bits from a prior pop, and an assignment (`*slot = job`) would run
/// Drop on those bits — a double-free for any `OwnedCap` inside.
pub(crate) enum WritePayload {
    /// Payload bytes packed inline in the IPC buffer. The owner
    /// copies them off the buffer before submitting so the worker
    /// can read directly from `bytes`.
    Inline {
        len: u64,
        bytes: [u8; 160], // == INLINE_TRANSFER_WIRE_MAX
    },
    /// Payload lives at `(slot.shm_vaddr + offset, len)` in the
    /// session's SHM ring. The slot the offset belongs to is
    /// resolved off the job's `correlation_words.session`.
    Ring { offset: u64, len: u64 },
    /// Payload lives in a caller-allocated MO. Worker maps it,
    /// reads, then unmaps. Drop calls `delete_and_free`
    /// so suppressed jobs (session-gen diverged) release the cap
    /// without a manual `cnode_delete`.
    Mo { cap: OwnedCap, len: u64 },
}

/// Backend-private worker job kinds. The worker handles each kind
/// via a plain function call in [`run_worker`].
pub(crate) enum WorkerJobKind {
    /// Flush every dirty slot in the owner's block cache.
    FlushCache,
    /// Flush the in-memory superblock if `SB_DIRTY` is set.
    FlushSuperblock,
    /// Verify CRC32c for a specific cache slot. Not yet wired into any
    /// caller — reserved for the integrity surface.
    #[allow(dead_code)]
    VerifyChecksum { block_nr: u64 },
    /// Off-owner `BACKEND_READ`. The owner snapshots the current backend
    /// callback endpoint into `reply_ep`; the worker reads blocks from
    /// disk, builds the correlated reply, drops [`BLOCK_LOCK`], and
    /// sends it directly.
    ReadBlocks {
        reply_ep: u64,
        ino: u64,
        file_offset: u64,
        transfer_kind: u64,
        transfer_offset: u64,
        transfer_length: u64,
        correlation_words: [u64; 4],
    },
    /// Off-owner `BACKEND_OPEN_SESSION`. The mount path's superblock
    /// read + bitmap scan + feature negotiation runs on the worker so
    /// the saltyfs owner can accept other traffic while a large
    /// volume's mount is in flight. The worker builds the correlated
    /// reply, drops [`BLOCK_LOCK`], and sends it directly via `reply_ep`
    /// using the same completion pattern as `ReadBlocks`.
    OpenSession {
        reply_ep: u64,
        mount_flags: u64,
        correlation_words: [u64; 4],
    },
    /// Off-owner `BACKEND_WRITE`. Hybrid-1 dispatch: `payload`
    /// carries the bytes (Inline) or a reference to where they
    /// live (Ring / Mo). The worker calls
    /// `handlers::execute_write_locked`, then performs cache +
    /// superblock flush so direct completion send marks a real
    /// commit boundary. `slot_idx` + `live_gen` are captured at
    /// submit time; the worker compares against the current slot
    /// generation under `BLOCK_LOCK` and suppresses the completion
    /// if the session has since closed.
    WriteBlocks {
        reply_ep: u64,
        slot_idx: u32,
        live_gen: u64,
        ino: u64,
        file_offset: u64,
        payload: WritePayload,
        correlation_words: [u64; 4],
    },
}

/// One entry in the submit ring.
///
/// `tx_id` is a **saltyfs-local** transaction id assigned by
/// [`next_tx_id`] — it identifies the owner↔worker round-trip within
/// saltyfs and has no relation to the VFS-supplied correlation token
/// carried inside [`WorkerJobKind::ReadBlocks::correlation_words`]. The
/// two id spaces are deliberately independent so a crash-recovery
/// audit can reconstruct ordering on both the VFS-client wire and the
/// saltyfs-worker ring without tangling the two.
pub(crate) struct WorkerJob {
    /// Saltyfs-local transaction id. Distinct from any VFS
    /// correlation token.
    pub(crate) tx_id: u64,
    pub(crate) kind: WorkerJobKind,
}

/// One owner-facing status record. `status == 0` means the worker
/// completed the job successfully; non-zero encodes the errno-style
/// failure the owner surfaces to waiting clients during
/// [`drain_pending`].
#[derive(Clone, Copy)]
pub(crate) struct WorkerStatus {
    pub(crate) status: i32,
}

#[derive(Clone, Copy)]
struct DirectCompletion {
    tx_id: u64,
    reply_ep: u64,
    reply_msg: trona_kernel::core_types::TronaMsg,
}

enum WorkerOutcome {
    Status(WorkerStatus),
    Direct(DirectCompletion),
}

// -------------------------------------------------------------------------
// Submit ring — owner writes, worker reads
// -------------------------------------------------------------------------

/// Sentinel for uninitialised ring slots. The enum discriminant is
/// irrelevant while the slot is empty — we always check the index
/// counters before reading an entry.
const SUBMIT_SENTINEL: WorkerJob = WorkerJob {
    tx_id: 0,
    kind: WorkerJobKind::FlushCache,
};
const COMPLETION_SENTINEL: WorkerStatus = WorkerStatus { status: 0 };

static mut SUBMIT_SLOTS: [WorkerJob; SUBMIT_RING_CAP] =
    [const { SUBMIT_SENTINEL }; SUBMIT_RING_CAP];
static SUBMIT_HEAD: AtomicUsize = AtomicUsize::new(0); // owner writes
static SUBMIT_TAIL: AtomicUsize = AtomicUsize::new(0); // worker reads

static mut COMPLETION_SLOTS: [WorkerStatus; COMPLETION_RING_CAP] =
    [COMPLETION_SENTINEL; COMPLETION_RING_CAP];
static COMPLETION_HEAD: AtomicUsize = AtomicUsize::new(0); // worker writes
static COMPLETION_TAIL: AtomicUsize = AtomicUsize::new(0); // owner reads

// -------------------------------------------------------------------------
// Transaction id allocator
// -------------------------------------------------------------------------

static NEXT_TX_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a fresh transaction id. `0` is reserved as "no transaction".
pub(crate) fn next_tx_id() -> u64 {
    NEXT_TX_ID.fetch_add(1, Ordering::Relaxed)
}

// -------------------------------------------------------------------------
// Worker liveness
// -------------------------------------------------------------------------

static WORKER_STARTED: AtomicBool = AtomicBool::new(false);
/// Counting semaphore that tracks publish-visible jobs in
/// `submit_ring`. One successful enqueue posts one token.
static WORKER_ITEMS: Semaphore = Semaphore::new(0);
/// Jobs currently executing on the worker thread. This keeps
/// `drain_pending()` from returning while a direct-send read/mount
/// completion is still being built or emitted after the worker has
/// already advanced `SUBMIT_TAIL`.
static JOBS_INFLIGHT: AtomicU32 = AtomicU32::new(0);
/// Worst non-zero writeback status already drained by the owner loop but
/// not yet consumed by `drain_pending()`.
static RECORDED_STATUS: AtomicI32 = AtomicI32::new(0);

/// Spawn the writeback worker. Safe to call at most once (guarded by
/// [`WORKER_STARTED`]). Returns true on successful spawn; the owner may
/// continue to operate as a single thread if spawning fails (the
/// submit-ring full path falls back to a synchronous flush, so the
/// system stays correct if degraded).
pub(crate) unsafe fn spawn_worker(config: thread::SpawnConfig) -> bool {
    if WORKER_STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    unsafe {
        match thread::spawn_fn(worker_entry, core::ptr::null_mut(), &config) {
            Ok(_) => {
                trona_runtime::uinfo!(|_lb| {
                    _lb.str(b"[saltyfs] writeback worker spawned\n");
                });
                true
            }
            Err(err) => {
                WORKER_STARTED.store(false, Ordering::Release);
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[saltyfs] worker spawn failed err=");
                    _lb.dec(err.as_i32() as u64);
                    _lb.str(b"\n");
                });
                false
            }
        }
    }
}

/// Is the worker live? Used by `submit_job` to decide between
/// enqueue-and-signal vs synchronous fallback.
#[inline]
pub(crate) fn worker_running() -> bool {
    WORKER_STARTED.load(Ordering::Acquire)
}

// -------------------------------------------------------------------------
// Submit ring API (owner side)
// -------------------------------------------------------------------------

/// Try to enqueue a job for the worker. Returns `None` when the job
/// was accepted (ownership transferred to the ring). Returns `Some(job)`
/// when the ring is full — the caller retains ownership and may retry
/// or fall back to an inline run.
///
/// # Safety
/// Only the owner thread may call this.
pub(crate) unsafe fn try_submit(job: WorkerJob) -> Option<WorkerJob> {
    let head = SUBMIT_HEAD.load(Ordering::Relaxed);
    let tail = SUBMIT_TAIL.load(Ordering::Acquire);
    if head.wrapping_sub(tail) >= SUBMIT_RING_CAP {
        return Some(job);
    }
    unsafe {
        let slot = &raw mut SUBMIT_SLOTS[head % SUBMIT_RING_CAP];
        // SAFETY: slot may contain moved-out bits from a prior pop
        // (ptr::read leaves stale bytes). Use ptr::write to overwrite
        // without running Drop on those stale bits. `job` is consumed
        // here — ownership transfers to the ring.
        core::ptr::write(slot, job);
    }
    SUBMIT_HEAD.store(head.wrapping_add(1), Ordering::Release);
    let post_err = WORKER_ITEMS.post();
    debug_assert!(post_err == 0);
    None
}

/// Submit a job, blocking until the worker drains enough capacity. Used
/// by code paths that must enqueue but can tolerate a short stall.
/// Degrades to a synchronous fallback if the worker never started.
pub(crate) unsafe fn submit_or_run(job: WorkerJob) {
    if !worker_running() {
        run_job_inline(job);
        return;
    }
    let mut pending = job;
    for _ in 0..4096 {
        match unsafe { try_submit(pending) } {
            None => return, // accepted
            Some(returned) => {
                pending = returned;
                let _ = trona_kernel::syscall::yield_now();
            }
        }
    }
    // Ring stayed full past the spin budget — run the job inline so the
    // owner's overall forward progress is preserved.
    run_job_inline(pending);
}

// -------------------------------------------------------------------------
// Completion ring API (owner side)
// -------------------------------------------------------------------------

/// Try to dequeue one completion. Returns `Some(completion)` if any
/// was available. Owner calls this on each server-loop iteration.
///
/// # Safety
/// Only the owner thread may call this.
pub(crate) unsafe fn try_pop_completion() -> Option<WorkerStatus> {
    let tail = COMPLETION_TAIL.load(Ordering::Relaxed);
    let head = COMPLETION_HEAD.load(Ordering::Acquire);
    if head == tail {
        return None;
    }
    let comp = unsafe {
        let slot = &raw const COMPLETION_SLOTS[tail % COMPLETION_RING_CAP];
        *slot
    };
    COMPLETION_TAIL.store(tail.wrapping_add(1), Ordering::Release);
    Some(comp)
}

#[inline]
fn merge_status(current: i32, new: i32) -> i32 {
    if current == 0 {
        new
    } else if new == 0 {
        current
    } else {
        core::cmp::min(current, new)
    }
}

fn record_completion_status(status: i32) {
    if status == 0 {
        return;
    }
    loop {
        let current = RECORDED_STATUS.load(Ordering::Acquire);
        let merged = merge_status(current, status);
        if merged == current {
            return;
        }
        if RECORDED_STATUS
            .compare_exchange_weak(current, merged, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

fn take_recorded_status() -> i32 {
    RECORDED_STATUS.swap(0, Ordering::AcqRel)
}

unsafe fn drain_completion_statuses_inner() -> i32 {
    let mut worst = 0;
    while let Some(comp) = unsafe { try_pop_completion() } {
        worst = merge_status(worst, comp.status);
    }
    worst
}

/// Drain any worker-posted status completions and accumulate failures for
/// a later `close_session`.
pub(crate) unsafe fn drain_completion_statuses() -> i32 {
    let worst = unsafe { drain_completion_statuses_inner() };
    record_completion_status(worst);
    worst
}

/// Block until every job the owner has submitted so far has been
/// completed by the worker and every completion has been drained.
/// Used by the `close_session` handler so a post-close flush cannot
/// strand dirty state in the cache.
///
/// Returns the worst status observed across the drained completions
/// (0 = all ok). The caller may use the returned status to refuse a
/// clean close on write failure.
///
/// # Safety
/// Only the owner thread may call this. The owner must have released
/// [`BLOCK_LOCK`] before entering this call (the worker needs the lock
/// to make progress); the function reacquires no lock itself.
pub(crate) unsafe fn drain_pending() -> i32 {
    if !worker_running() {
        return 0;
    }
    let mut worst: i32 = take_recorded_status();
    loop {
        // Absorb any already-posted completions.
        worst = merge_status(worst, unsafe { drain_completion_statuses_inner() });
        // Are any submits or worker-side executions still in flight?
        let submit_head = SUBMIT_HEAD.load(Ordering::Acquire);
        let submit_tail = SUBMIT_TAIL.load(Ordering::Acquire);
        let jobs_inflight = JOBS_INFLIGHT.load(Ordering::Acquire);
        let completion_head = COMPLETION_HEAD.load(Ordering::Acquire);
        let completion_tail = COMPLETION_TAIL.load(Ordering::Acquire);
        let submits_outstanding = submit_head != submit_tail;
        let completions_outstanding = completion_head != completion_tail;
        if !submits_outstanding && jobs_inflight == 0 && !completions_outstanding {
            return worst;
        }
        // Yield to the worker — it needs BLOCK_LOCK to run a job, and
        // since we are not holding it the worker can make progress.
        let _ = trona_kernel::syscall::yield_now();
    }
}

// -------------------------------------------------------------------------
// Worker entry + loop
// -------------------------------------------------------------------------

/// C-ABI entry for the worker thread. `_arg` is unused today; it exists
/// so the signature matches `thread::spawn_fn`'s expected shape for
/// future state-carrying spawns.
pub(crate) unsafe extern "C" fn worker_entry(_arg: *mut u8) {
    unsafe {
        run_worker();
    }
}

unsafe fn run_worker() -> ! {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[saltyfs] worker loop entering\n");
    });
    loop {
        WORKER_ITEMS.wait();
        if let Some(job) = unsafe { pop_submit() } {
            unsafe {
                run_job(job);
            }
        }
        while WORKER_ITEMS.try_wait() {
            if let Some(job) = unsafe { pop_submit() } {
                unsafe {
                    run_job(job);
                }
            }
        }
    }
}

unsafe fn run_job(job: WorkerJob) {
    JOBS_INFLIGHT.fetch_add(1, Ordering::AcqRel);
    BLOCK_LOCK.lock();
    let outcome = run_job_and_completion(job);
    BLOCK_LOCK.unlock();
    match outcome {
        WorkerOutcome::Direct(completion) => {
            let _ = send_direct_completion(&completion);
        }
        WorkerOutcome::Status(status) => unsafe {
            push_completion(status);
        },
    }
    JOBS_INFLIGHT.fetch_sub(1, Ordering::AcqRel);
}

unsafe fn pop_submit() -> Option<WorkerJob> {
    let tail = SUBMIT_TAIL.load(Ordering::Relaxed);
    let head = SUBMIT_HEAD.load(Ordering::Acquire);
    if head == tail {
        return None;
    }
    let job = unsafe {
        let slot = &raw const SUBMIT_SLOTS[tail % SUBMIT_RING_CAP];
        // SAFETY: slot is exclusively owned by the worker while tail
        // hasn't advanced (SPSC ring). `ptr::read` moves the value out
        // without requiring `Copy`; the slot is overwritten by the
        // owner before it's read again (head > tail invariant).
        core::ptr::read(slot)
    };
    SUBMIT_TAIL.store(tail.wrapping_add(1), Ordering::Release);
    Some(job)
}

unsafe fn push_completion(comp: WorkerStatus) {
    loop {
        let head = COMPLETION_HEAD.load(Ordering::Relaxed);
        let tail = COMPLETION_TAIL.load(Ordering::Acquire);
        if head.wrapping_sub(tail) < COMPLETION_RING_CAP {
            unsafe {
                let slot = &raw mut COMPLETION_SLOTS[head % COMPLETION_RING_CAP];
                *slot = comp;
            }
            COMPLETION_HEAD.store(head.wrapping_add(1), Ordering::Release);
            return;
        }
        // Completion ring full — owner is behind. Yield and retry.
        let _ = trona_kernel::syscall::yield_now();
    }
}

// -------------------------------------------------------------------------
// Job execution
// -------------------------------------------------------------------------

/// Run a job and return either a direct-send completion or an
/// owner-facing status record. Consumes the job so that move-only
/// fields (e.g. `WritePayload::Mo { cap: OwnedCap }`) can be moved
/// into the handler without a borrow-of-moved-value error.
fn run_job_and_completion(job: WorkerJob) -> WorkerOutcome {
    let tx_id = job.tx_id;
    match job.kind {
        WorkerJobKind::FlushCache => {
            let ok = block::cache_flush_all();
            WorkerOutcome::Status(WorkerStatus {
                status: if ok { 0 } else { -1 },
            })
        }
        WorkerJobKind::FlushSuperblock => {
            let ok = block::flush_superblock_if_dirty();
            WorkerOutcome::Status(WorkerStatus {
                status: if ok { 0 } else { -1 },
            })
        }
        WorkerJobKind::VerifyChecksum { block_nr: _ } => {
            WorkerOutcome::Status(WorkerStatus { status: 0 })
        }
        WorkerJobKind::ReadBlocks {
            reply_ep,
            ino,
            file_offset,
            transfer_kind,
            transfer_offset,
            transfer_length,
            correlation_words,
        } => WorkerOutcome::Direct(build_read_blocks_completion(
            tx_id,
            reply_ep,
            ino,
            file_offset,
            transfer_kind,
            transfer_offset,
            transfer_length,
            correlation_words,
        )),
        WorkerJobKind::OpenSession {
            reply_ep,
            mount_flags,
            correlation_words,
        } => WorkerOutcome::Direct(build_open_session_completion(
            tx_id,
            reply_ep,
            mount_flags,
            correlation_words,
        )),
        WorkerJobKind::WriteBlocks {
            reply_ep,
            slot_idx,
            live_gen,
            ino,
            file_offset,
            payload,
            correlation_words,
        } => match build_write_blocks_outcome(
            tx_id,
            reply_ep,
            slot_idx,
            live_gen,
            ino,
            file_offset,
            payload,
            correlation_words,
        ) {
            Some(direct) => WorkerOutcome::Direct(direct),
            // Slot generation diverged (session closed mid-flight)
            // — suppress the completion entirely. Cap on `payload`
            // (if MO) was released before this branch returned.
            None => WorkerOutcome::Status(WorkerStatus { status: 0 }),
        },
    }
}

/// Owner-side fallback for when the worker is missing or the submit
/// ring stays full. Runs the job on the current thread and emits any
/// client-facing reply directly to the backend callback endpoint (no
/// completion ring hop — the owner is already on the reply path).
/// Kept in sync with the worker-side `run_job_and_completion` so both
/// paths produce identical replies.
fn run_job_inline(job: WorkerJob) -> bool {
    match run_job_and_completion(job) {
        WorkerOutcome::Status(status) => status.status == 0,
        WorkerOutcome::Direct(completion) => {
            // `submit_or_run` is only called while the owner already
            // holds `BLOCK_LOCK`; drop it before the potentially
            // blocking completion send, then restore the lock state
            // expected by the caller.
            BLOCK_LOCK.unlock();
            let ok = send_direct_completion(&completion);
            BLOCK_LOCK.lock();
            ok
        }
    }
}

fn send_direct_completion(completion: &DirectCompletion) -> bool {
    if completion.reply_ep == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[saltyfs] deferred completion missing reply_ep tx=");
            _lb.dec(completion.tx_id);
            _lb.str(b"\n");
        });
        return false;
    }
    unsafe {
        let err = trona_kernel::ipc::mp_write_ctx(
            trona_runtime::current_ipc_ctx(),
            completion.reply_ep,
            &raw const completion.reply_msg,
        );
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[saltyfs] deferred completion send failed tx=");
                _lb.dec(completion.tx_id);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b" ep=");
                _lb.hex(completion.reply_ep);
                _lb.str(b"\n");
            });
            return false;
        }
    }
    true
}

/// Build the completion payload for a deferred `BACKEND_OPEN_SESSION`.
/// Runs the mount logic (superblock read + bitmap scan + feature
/// negotiation) and stamps a completion correlation header onto the
/// reply. The worker sends the stamped reply through `reply_ep` after it
/// drops [`BLOCK_LOCK`].
fn build_open_session_completion(
    tx_id: u64,
    reply_ep: u64,
    mount_flags: u64,
    correlation_words: [u64; 4],
) -> DirectCompletion {
    use trona_protocol::posix::{
        CORRELATION_HEADER_REG_START, CORRELATION_KIND_COMPLETION, CorrelationHeader,
        ensure_correlation_wire_length,
    };

    let mut req = trona_kernel::core_types::TronaMsg::zeroed();
    req.regs[0] = mount_flags;
    req.length = 1;

    let mut reply = crate::handlers::handle_mount(&req);

    let req_header = CorrelationHeader::decode_words(correlation_words);
    let completion_header = CorrelationHeader {
        kind: CORRELATION_KIND_COMPLETION,
        ..req_header
    };
    let cw = completion_header.encode_words();
    reply.regs[CORRELATION_HEADER_REG_START] = cw[0];
    reply.regs[CORRELATION_HEADER_REG_START + 1] = cw[1];
    reply.regs[CORRELATION_HEADER_REG_START + 2] = cw[2];
    reply.regs[CORRELATION_HEADER_REG_START + 3] = cw[3];
    // `handle_mount` set `reply.length` to the OPEN_SESSION reply
    // register count (the metadata-only block in regs[0..=5]); raise
    // it past MR31 so the correlation header in regs[28..=31] also
    // survives the kernel's length-bounded register copy into the
    // callback EP.
    ensure_correlation_wire_length(&mut reply.length);

    DirectCompletion {
        tx_id,
        reply_ep,
        reply_msg: reply,
    }
}

/// Build the completion payload for a deferred `BACKEND_READ`. Reads
/// file blocks via `crate::handlers::read_file_data`, packs the reply
/// (inline payload or SHM bounds-checked), and stamps the completion
/// correlation header into MR28..=MR31. The worker sends the stamped
/// reply through `reply_ep` after it drops [`BLOCK_LOCK`].
fn build_read_blocks_completion(
    tx_id: u64,
    reply_ep: u64,
    ino: u64,
    file_offset: u64,
    transfer_kind: u64,
    transfer_offset: u64,
    transfer_length: u64,
    correlation_words: [u64; 4],
) -> DirectCompletion {
    use trona_protocol::common::{TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION, TRONA_OK};
    use trona_protocol::correlation::{
        CORRELATION_HEADER_REG_START, CORRELATION_KIND_COMPLETION, CorrelationHeader,
        ensure_correlation_wire_length,
    };
    use trona_protocol::vfs::backend::{
        BACKEND_READ, BACKEND_READ_INLINE_PAYLOAD_REG, INLINE_TRANSFER_WIRE_MAX,
        TRANSFER_KIND_INLINE, TRANSFER_KIND_SHM,
    };

    let _ = BACKEND_READ;

    let mut reply = trona_kernel::core_types::TronaMsg::zeroed();

    if !unsafe { *(&raw const crate::MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
    } else {
        match transfer_kind {
            t if t == TRANSFER_KIND_INLINE => {
                if transfer_length > INLINE_TRANSFER_WIRE_MAX {
                    reply.label = TRONA_INVALID_ARGUMENT;
                } else {
                    let bytes_read = crate::handlers::read_file_data(
                        ino,
                        file_offset,
                        transfer_length,
                        crate::consts::SHM_VADDR,
                    );
                    reply.label = TRONA_OK;
                    reply.length = 1 + (bytes_read + 7) / 8;
                    reply.regs[0] = bytes_read;
                    if bytes_read > 0 {
                        unsafe {
                            let src = crate::consts::SHM_VADDR as *const u8;
                            let dst =
                                &raw mut reply.regs[BACKEND_READ_INLINE_PAYLOAD_REG] as *mut u8;
                            for i in 0..bytes_read as usize {
                                *dst.add(i) = *src.add(i);
                            }
                        }
                    }
                }
            }
            t if t == TRANSFER_KIND_SHM => {
                // Decode the session id off the job's correlation
                // words and resolve to that session's SHM region.
                // Fall back to the daemon's blkdrv scratch window
                // when SHM has not been negotiated yet.
                let req_header = CorrelationHeader::decode_words(correlation_words);
                let region = if req_header.session != 0 {
                    crate::session::find_live_by_id(req_header.session)
                        .or_else(crate::session::current_live)
                        .and_then(crate::session::slot)
                        .filter(|s| s.shm_vaddr != 0 && s.shm_bytes != 0)
                        .map(|s| (s.shm_vaddr, s.shm_bytes))
                } else {
                    crate::session::live_shm_region()
                };
                let (dest_base_addr, shm_size) = match region {
                    Some((vaddr, bytes)) => (vaddr, bytes),
                    None => (crate::consts::SHM_VADDR, crate::consts::SHM_SIZE),
                };
                if transfer_offset >= shm_size || transfer_length > shm_size - transfer_offset {
                    reply.label = TRONA_INVALID_ARGUMENT;
                } else {
                    let dest_base = dest_base_addr + transfer_offset;
                    let bytes_read = crate::handlers::read_file_data(
                        ino,
                        file_offset,
                        transfer_length,
                        dest_base,
                    );
                    reply.label = TRONA_OK;
                    reply.length = 1;
                    reply.regs[0] = bytes_read;
                }
            }
            _ => {
                reply.label = TRONA_INVALID_ARGUMENT;
            }
        }
    }

    // Stamp a COMPLETION correlation header onto the reply. We decode
    // the request header the owner captured, flip `kind`, and re-encode.
    let req_header = CorrelationHeader::decode_words(correlation_words);
    let completion_header = CorrelationHeader {
        kind: CORRELATION_KIND_COMPLETION,
        ..req_header
    };
    let cw = completion_header.encode_words();
    reply.regs[CORRELATION_HEADER_REG_START] = cw[0];
    reply.regs[CORRELATION_HEADER_REG_START + 1] = cw[1];
    reply.regs[CORRELATION_HEADER_REG_START + 2] = cw[2];
    reply.regs[CORRELATION_HEADER_REG_START + 3] = cw[3];
    // Raise reply.length past MR31 so the correlation header survives
    // the kernel's length-bounded register copy into the callback EP.
    // The inline-payload branch above already baked the payload into
    // the reply; raising the length only extends the tail of zeros
    // past the header, harmless for inline and SHM alike.
    ensure_correlation_wire_length(&mut reply.length);

    DirectCompletion {
        tx_id,
        reply_ep,
        reply_msg: reply,
    }
}

/// Build the completion payload for a deferred `BACKEND_WRITE`.
///
/// Resolves `payload` to a contiguous byte source, calls
/// `handlers::execute_write_locked` to perform the actual file
/// mutation, then drains cache + superblock so the direct
/// completion send marks a real commit boundary. Returns `None`
/// when the session's `live_gen` has advanced past the value
/// captured at submit time — the worker silently suppresses the
/// completion in that case (the cap on the receive side is about
/// to be released, and any ring slot the request occupied is
/// freed by the close path's drain).
fn build_write_blocks_outcome(
    tx_id: u64,
    reply_ep: u64,
    slot_idx: u32,
    live_gen: u64,
    ino: u64,
    file_offset: u64,
    payload: WritePayload,
    correlation_words: [u64; 4],
) -> Option<DirectCompletion> {
    // BLOCK_LOCK is already held by the caller (run_job /
    // run_job_inline). Validate slot generation under the same
    // lock so a concurrent close_session that bumped live_gen has
    // already taken effect when we test.
    let mut suppress = false;
    if let Some(slot) = crate::session::slot(slot_idx as usize) {
        if slot.live_gen != live_gen {
            suppress = true;
        }
    }
    if suppress {
        // Dropping `payload` here releases any OwnedCap it carries
        // (OwnedCap::drop calls delete_and_free). No manual
        // cnode_delete needed.
        drop(payload);
        return None;
    }

    // Resolve `payload` to a `(ptr, len)` pair the executor can
    // read from. Inline / Ring need no setup; Mo maps the cap into
    // the daemon's VA at the slot-reserved window.
    let (data_ptr, data_len, mo_cleanup) = match payload {
        WritePayload::Inline { len, ref bytes } => (bytes.as_ptr(), len, None),
        WritePayload::Ring { offset, len } => {
            let region = crate::session::slot(slot_idx as usize)
                .filter(|s| s.shm_vaddr != 0 && s.shm_bytes != 0)
                .map(|s| (s.shm_vaddr, s.shm_bytes));
            let (vaddr, bytes_total) = match region {
                Some(r) => r,
                None => {
                    return Some(make_write_error_reply(
                        tx_id,
                        reply_ep,
                        correlation_words,
                        TRONA_INVALID_OPERATION,
                    ));
                }
            };
            if offset >= bytes_total || len > bytes_total - offset {
                return Some(make_write_error_reply(
                    tx_id,
                    reply_ep,
                    correlation_words,
                    TRONA_INVALID_ARGUMENT,
                ));
            }
            ((vaddr + offset) as *const u8, len, None)
        }
        WritePayload::Mo { cap, len } => {
            // Reject the request before touching mmsrv when the
            // wire promised a cap but none arrived, when the
            // payload is empty, or when the request exceeds the
            // daemon's staging-window cap (`MO_STAGING_SIZE`,
            // currently 1 MiB). The null-cap branch can fire
            // when a sender signalled `TRANSFER_KIND_MO` but
            // forgot to attach `caps[0]`; the size cap forces
            // VFS frontends to chunk over-large writes across
            // multiple BACKEND_WRITEs.
            if cap.as_raw() == 0 || len == 0 || len > MO_STAGING_SIZE {
                // `cap` drops here — OwnedCap::drop calls
                // delete_and_free; delete on a null slot
                // returns NOT_FOUND, silently discarded.
                return Some(make_write_error_reply(
                    tx_id,
                    reply_ep,
                    correlation_words,
                    TRONA_OUT_OF_RANGE,
                ));
            }
            // Page-align the map length. The MO must already be a
            // whole-page region (mmsrv only retypes page-granular
            // MOs); aligning the request length keeps mmsrv's
            // input validator happy when the wire `length` is the
            // exact byte count.
            let page_bytes = uapi::KERNITE_PAGE_BYTES as u64;
            let aligned_len = (len + page_bytes - 1) & !(page_bytes - 1);
            let raw_cap = cap.as_raw();
            if !mo_staging_map(raw_cap, aligned_len) {
                // Map failed — mmsrv may or may not have already taken
                // the slot via cnode_move. `cap` drops here;
                // OwnedCap::drop issues cnode_delete which returns
                // NOT_FOUND on an already-moved slot (ignored).
                return Some(make_write_error_reply(
                    tx_id,
                    reply_ep,
                    correlation_words,
                    TRONA_OUT_OF_MEMORY,
                ));
            }
            // mmsrv took the cap via cnode_move; our slot is now
            // empty. `cap` drops here — OwnedCap::drop issues
            // cnode_delete which returns NOT_FOUND on the vacated
            // slot, silently discarded. If mmsrv ever stops moving
            // the cap (e.g. zero-copy share), the drop reclaims
            // the slot correctly instead.
            drop(cap);
            (
                MO_STAGING_VADDR as *const u8,
                len,
                Some(MoCleanup { aligned_len }),
            )
        }
    };

    let data_slice = unsafe { core::slice::from_raw_parts(data_ptr, data_len as usize) };
    let (label, bytes_written) =
        match crate::handlers::execute_write_locked(ino, file_offset, data_slice) {
            Ok(n) => (TRONA_OK, n),
            Err(label) => (label, 0),
        };

    // Commit boundary: flush the cache + superblock the executor
    // dirtied so the direct completion send only goes out after a
    // durable on-disk state. Failures roll the wire label down to
    // `TRONA_IO_ERROR` in the userland status namespace.
    let cache_ok = block::cache_flush_all();
    let sb_ok = block::flush_superblock_if_dirty();

    // Unmap the MO staging window after the executor + flush
    // sequence finishes reading from it. A failed unmap leaks a
    // VA window but does not corrupt on-disk state — the bytes
    // are already flushed.
    if let Some(cleanup) = mo_cleanup {
        let _ = mo_staging_unmap(cleanup.aligned_len);
    }

    let final_label = if label == TRONA_OK && (!cache_ok || !sb_ok) {
        TRONA_IO_ERROR
    } else {
        label
    };

    let mut reply = trona_kernel::core_types::TronaMsg::zeroed();
    reply.label = final_label;
    reply.regs[0] = if final_label == TRONA_OK {
        bytes_written
    } else {
        0
    };
    reply.length = 1;

    let req_header = CorrelationHeader::decode_words(correlation_words);
    let completion_header = CorrelationHeader {
        kind: CORRELATION_KIND_COMPLETION,
        ..req_header
    };
    let cw = completion_header.encode_words();
    reply.regs[CORRELATION_HEADER_REG_START] = cw[0];
    reply.regs[CORRELATION_HEADER_REG_START + 1] = cw[1];
    reply.regs[CORRELATION_HEADER_REG_START + 2] = cw[2];
    reply.regs[CORRELATION_HEADER_REG_START + 3] = cw[3];
    ensure_correlation_wire_length(&mut reply.length);

    Some(DirectCompletion {
        tx_id,
        reply_ep,
        reply_msg: reply,
    })
}

/// Cleanup record for an MO that was mapped into the staging
/// window for the duration of a `WritePayload::Mo` job. Carries
/// the page-aligned length so the post-write `MM_MUNMAP` covers
/// exactly the window the map call installed. Allocated on the
/// stack of `build_write_blocks_outcome` and consumed once at
/// the unmap site.
struct MoCleanup {
    aligned_len: u64,
}

/// Map an inbound MO cap into the daemon's staging window so the
/// worker can read the payload as a plain byte slice. The cap is
/// taken via `KERNITE_INV_CNODE_MOVE` by mmsrv on success, so the
/// saltyfs source slot is left empty regardless of whether the
/// caller subsequently `cnode_delete`s it. Returns `false` on any
/// IPC or kernel-level failure — the caller must arrange for the
/// cap to be released and surface a wire error.
fn mo_staging_map(cap: u64, aligned_len: u64) -> bool {
    let ctx = trona_runtime::current_ipc_ctx();
    if ctx.is_null() {
        return false;
    }
    unsafe {
        ipc::set_send_cap_ctx(ctx, 0, cap);
    }
    let mut msg = TronaMsg::zeroed();
    msg.label = trona_protocol::mm::MM_MMAP;
    msg.length = 6;
    msg.regs[0] = trona_protocol::mm::MMAP_KIND_MO;
    msg.regs[1] = MO_STAGING_VADDR;
    msg.regs[2] = aligned_len;
    msg.regs[3] = 0x1; // PROT_READ
    msg.regs[4] = 0x1; // FLAG_FIXED — staging window is a fixed VA.
    msg.regs[5] = 0;
    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        ipc::mp_call_ctx(
            ctx,
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    err == 0 && reply.label == 0
}

/// Tear down the staging-window mapping installed by a prior
/// successful `mo_staging_map`. A failure here only leaks a VA
/// window — the on-disk write has already flushed by the time
/// this is called, so the caller does not need to roll back.
fn mo_staging_unmap(aligned_len: u64) -> bool {
    let ctx = trona_runtime::current_ipc_ctx();
    if ctx.is_null() {
        return false;
    }
    let mut msg = TronaMsg::zeroed();
    msg.label = trona_protocol::mm::MM_MUNMAP;
    msg.length = 2;
    msg.regs[0] = MO_STAGING_VADDR;
    msg.regs[1] = aligned_len;
    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        ipc::mp_call_ctx(
            ctx,
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    err == 0 && reply.label == 0
}

fn make_write_error_reply(
    tx_id: u64,
    reply_ep: u64,
    correlation_words: [u64; 4],
    label: u64,
) -> DirectCompletion {
    let mut reply = trona_kernel::core_types::TronaMsg::zeroed();
    reply.label = label;
    reply.length = 0;
    let req_header = CorrelationHeader::decode_words(correlation_words);
    let completion_header = CorrelationHeader {
        kind: CORRELATION_KIND_COMPLETION,
        ..req_header
    };
    let cw = completion_header.encode_words();
    reply.regs[CORRELATION_HEADER_REG_START] = cw[0];
    reply.regs[CORRELATION_HEADER_REG_START + 1] = cw[1];
    reply.regs[CORRELATION_HEADER_REG_START + 2] = cw[2];
    reply.regs[CORRELATION_HEADER_REG_START + 3] = cw[3];
    ensure_correlation_wire_length(&mut reply.length);
    DirectCompletion {
        tx_id,
        reply_ep,
        reply_msg: reply,
    }
}
