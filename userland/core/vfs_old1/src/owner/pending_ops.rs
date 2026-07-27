// SPDX-License-Identifier: GPL-2.0-only
//! Owner-side pending-op table.
//!
//! Every deferred backend RPC reserves a `PendingOp` slot here. The
//! slot owns the kernel reply continuation, a small inline scratch
//! buffer for op-specific state, and an optional reference into the
//! typed payload pool for larger state (e.g. resumable namei walk
//! state). Workers never write the table; they only read `state` to
//! detect mid-RPC cancellation, and update `WORKER_INFLIGHT[]` so the
//! owner's cancel walk can find them.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use trona_kernel::core_types::TronaMsg;

use crate::owner::worker::MAX_WORKERS;
use crate::server::types::ClientHandle;

pub(crate) const MAX_PENDING_OPS: usize = 256;
pub(crate) const MAX_PAYLOAD_BUFS: usize = 128;
pub(crate) const PAYLOAD_BUF_BYTES: usize = 384;

pub(crate) const INVALID_PAYLOAD_REF: u32 = u32::MAX;

/// Opaque pending-op identifier with embedded generation. Slot in the
/// low 32 bits, generation in the high 32 bits. `PendingOpId(0)` is
/// the sentinel "no op".
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PendingOpId(pub(crate) u64);

impl PendingOpId {
    pub(crate) const NONE: Self = Self(0);

    #[inline]
    pub(crate) const fn pack(slot: u32, generation: u32) -> Self {
        Self((slot as u64) | ((generation as u64) << 32))
    }

    #[inline]
    pub(crate) const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub(crate) const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub(crate) const fn slot(self) -> u32 {
        (self.0 & 0xFFFF_FFFF) as u32
    }

    #[inline]
    pub(crate) const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    #[inline]
    pub(crate) const fn is_none(self) -> bool {
        self.0 == 0
    }
}

/// Lifecycle states. `state` is `AtomicU8` so workers can observe a
/// late cancellation without taking any owner-side lock.
pub(crate) const PO_STATE_FREE: u8 = 0;
pub(crate) const PO_STATE_QUEUED: u8 = 1;
pub(crate) const PO_STATE_RUNNING: u8 = 2;
pub(crate) const PO_STATE_COMPLETING: u8 = 3;
pub(crate) const PO_STATE_CANCELLED: u8 = 4;

pub(crate) type PendingOpKind = u8;
pub(crate) const PO_KIND_NONE: PendingOpKind = 0;
pub(crate) const PO_KIND_TTY_STDIO: PendingOpKind = 1;
pub(crate) const PO_KIND_TTY_GET_GEN: PendingOpKind = 2;
pub(crate) const PO_KIND_TTY_OPEN_SLAVE: PendingOpKind = 3;
pub(crate) const PO_KIND_PROCFS_READ: PendingOpKind = 4;
pub(crate) const PO_KIND_PROCFS_PID_STAT: PendingOpKind = 5;
pub(crate) const PO_KIND_PROCFS_READLINK: PendingOpKind = 6;
pub(crate) const PO_KIND_PROCFS_READDIR: PendingOpKind = 7;
pub(crate) const PO_KIND_NAMEI_RESUME: PendingOpKind = 8;
pub(crate) const PO_KIND_DEVICE: PendingOpKind = 9;
pub(crate) const PO_KIND_SHM: PendingOpKind = 10;
pub(crate) const PO_KIND_NET: PendingOpKind = 11;
/// Backend RPC umbrella kind. Owner allocates a PendingOp with this
/// kind when the op is driven by `enqueue_saltyfs_op` /
/// `enqueue_backend_op`; the actual per-op routing is decided by the
/// completion's `BACKEND_OP_*` discriminator at cascade dispatch.
pub(crate) const PO_KIND_BACKEND_RPC: PendingOpKind = 12;

// Syscall continuation kinds — once namei finishes and the syscall
// handler needs tail-work on the owner thread after a deferred backend
// RPC, the PendingOp's `kind` is set to one of these. Each value has a
// matching `complete_*_continuation` cascade entry in `loop_.rs`.
pub(crate) const PO_KIND_OPEN_CONT: PendingOpKind = 13;
pub(crate) const PO_KIND_STAT_CONT: PendingOpKind = 14;
pub(crate) const PO_KIND_ACCESS_CONT: PendingOpKind = 15;
pub(crate) const PO_KIND_CHMOD_CONT: PendingOpKind = 16;
pub(crate) const PO_KIND_CHOWN_CONT: PendingOpKind = 17;
pub(crate) const PO_KIND_UTIMES_CONT: PendingOpKind = 18;
pub(crate) const PO_KIND_TRUNCATE_CONT: PendingOpKind = 19;
pub(crate) const PO_KIND_READLINK_CONT: PendingOpKind = 20;
pub(crate) const PO_KIND_UNLINK_CONT: PendingOpKind = 21;
pub(crate) const PO_KIND_MKDIR_CONT: PendingOpKind = 22;
pub(crate) const PO_KIND_RENAME_CONT: PendingOpKind = 23;
pub(crate) const PO_KIND_SYMLINK_CONT: PendingOpKind = 24;
pub(crate) const PO_KIND_LINK_CONT: PendingOpKind = 25;
pub(crate) const PO_KIND_MKNOD_CONT: PendingOpKind = 26;
pub(crate) const PO_KIND_CHDIR_CONT: PendingOpKind = 27;
pub(crate) const PO_KIND_STATVFS_CONT: PendingOpKind = 28;
pub(crate) const PO_KIND_MOUNT_CONT: PendingOpKind = 29;
pub(crate) const PO_KIND_UMOUNT_CONT: PendingOpKind = 30;
pub(crate) const PO_KIND_RESOLVE_PATH_BACKING_CONT: PendingOpKind = 31;

// Waiter kinds. Each former `*_wait` table in owner state lives as a
// `PendingOp + op_id`, so the cancel walk unifies through
// `pending_ops::cancel_for_badge` instead of N per-table sweeps. The
// reply slot lives on the PendingOp itself.
pub(crate) const PO_KIND_TTY_WAIT: PendingOpKind = 45;
pub(crate) const PO_KIND_INET_WAIT: PendingOpKind = 46;
pub(crate) const PO_KIND_SOCKET_WAIT: PendingOpKind = 47;
pub(crate) const PO_KIND_FIFO_OPEN: PendingOpKind = 48;
pub(crate) const PO_KIND_POLL_WAIT: PendingOpKind = 49;
pub(crate) const PO_KIND_EPOLL_WAIT: PendingOpKind = 50;
pub(crate) const PO_KIND_PIPE_READ_WAIT: PendingOpKind = 51;
pub(crate) const PO_KIND_PIPE_WRITE_WAIT: PendingOpKind = 52;

/// Disposition for a cancelled op — controls whether the saved reply
/// slot is dropped silently or used to ship a specific error label.
pub(crate) type CancelDisposition = u8;
pub(crate) const CANCEL_DROP: CancelDisposition = 0;
pub(crate) const CANCEL_CANCELLED: CancelDisposition = 1;
pub(crate) const CANCEL_SERVER_DIED: CancelDisposition = 2;

#[repr(C)]
pub(crate) struct PendingOp {
    pub(crate) state: AtomicU8,
    pub(crate) kind: PendingOpKind,
    pub(crate) cancel_disposition: CancelDisposition,
    pub(crate) _pad: u8,
    pub(crate) generation: u32,
    pub(crate) reply_slot: u64,
    pub(crate) badge: u64,
    pub(crate) client_handle_raw: u64,
    pub(crate) stage: u32,
    pub(crate) payload_ref: u32,
    pub(crate) args_payload_ref: u32,
    pub(crate) scratch: [u64; 8],
}

const PENDING_OP_INIT: PendingOp = PendingOp {
    state: AtomicU8::new(PO_STATE_FREE),
    kind: PO_KIND_NONE,
    cancel_disposition: CANCEL_DROP,
    _pad: 0,
    generation: 0,
    reply_slot: 0,
    badge: 0,
    client_handle_raw: 0,
    stage: 0,
    payload_ref: INVALID_PAYLOAD_REF,
    args_payload_ref: INVALID_PAYLOAD_REF,
    scratch: [0; 8],
};

#[repr(C)]
struct PayloadSlot {
    in_use: AtomicU8,
    _pad: [u8; 7],
    bytes: [u8; PAYLOAD_BUF_BYTES],
}

const PAYLOAD_SLOT_INIT: PayloadSlot = PayloadSlot {
    in_use: AtomicU8::new(0),
    _pad: [0; 7],
    bytes: [0; PAYLOAD_BUF_BYTES],
};

struct OwnerPool {
    slots: UnsafeCell<[PendingOp; MAX_PENDING_OPS]>,
    next_alloc_hint: UnsafeCell<u32>,
    payloads: UnsafeCell<[PayloadSlot; MAX_PAYLOAD_BUFS]>,
    next_payload_hint: UnsafeCell<u32>,
}

// SAFETY: the slot/payload arrays are mutated only by the owner
// thread; cross-thread reads use the `state`/`in_use` atomics.
unsafe impl Sync for OwnerPool {}

impl OwnerPool {
    const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([const { PENDING_OP_INIT }; MAX_PENDING_OPS]),
            next_alloc_hint: UnsafeCell::new(0),
            payloads: UnsafeCell::new([const { PAYLOAD_SLOT_INIT }; MAX_PAYLOAD_BUFS]),
            next_payload_hint: UnsafeCell::new(0),
        }
    }
}

static POOL: OwnerPool = OwnerPool::new();

/// In-flight op id per worker. `0` means the worker is idle. Workers
/// publish an op id before entering `ipc::call_ctx` and clear it
/// after pushing the completion. The owner's cancel walk reads this
/// to flag ops whose worker is currently blocked in the backend.
static WORKER_INFLIGHT: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];

#[inline]
pub(crate) fn pack_client_handle(h: ClientHandle) -> u64 {
    ((h.epoch() as u64) << 32) | (h.slot() as u64)
}

#[inline]
pub(crate) fn unpack_client_handle(v: u64) -> ClientHandle {
    ClientHandle::new((v & 0xFFFF_FFFF) as u32, (v >> 32) as u32)
}

/// Reserve a pending-op slot. Caller is responsible for populating
/// any op-kind specific state (`stage`, `scratch`, `payload_ref`,
/// `args_payload_ref`)
/// before pushing the backend job.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn alloc(
    kind: PendingOpKind,
    badge: u64,
    cli_handle: ClientHandle,
    reply_slot: u64,
) -> Option<PendingOpId> {
    unsafe {
        let slots = &mut *POOL.slots.get();
        let hint_ptr = POOL.next_alloc_hint.get();
        let mut idx = (*hint_ptr) as usize;
        for _ in 0..MAX_PENDING_OPS {
            if idx >= MAX_PENDING_OPS {
                idx = 0;
            }
            if slots[idx].state.load(Ordering::Acquire) == PO_STATE_FREE {
                let next_gen = match slots[idx].generation.checked_add(1) {
                    Some(g) if g != 0 => g,
                    _ => 1,
                };
                slots[idx].kind = kind;
                slots[idx].cancel_disposition = CANCEL_DROP;
                slots[idx]._pad = 0;
                slots[idx].generation = next_gen;
                slots[idx].reply_slot = reply_slot;
                slots[idx].badge = badge;
                slots[idx].client_handle_raw = pack_client_handle(cli_handle);
                slots[idx].stage = 0;
                slots[idx].payload_ref = INVALID_PAYLOAD_REF;
                slots[idx].args_payload_ref = INVALID_PAYLOAD_REF;
                for s in slots[idx].scratch.iter_mut() {
                    *s = 0;
                }
                slots[idx].state.store(PO_STATE_QUEUED, Ordering::Release);
                *hint_ptr = ((idx + 1) % MAX_PENDING_OPS) as u32;
                return Some(PendingOpId::pack(idx as u32, next_gen));
            }
            idx += 1;
        }
        None
    }
}

/// Release a pending-op slot back to the pool. Frees the associated
/// payload buffer (if any). Reply slot ownership is *not* released
/// here — call `take_reply_slot` first or the slot will leak.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn free(op_id: PendingOpId) {
    unsafe {
        if op_id.is_none() {
            return;
        }
        let idx = op_id.slot() as usize;
        if idx >= MAX_PENDING_OPS {
            return;
        }
        let slots = &mut *POOL.slots.get();
        if slots[idx].generation != op_id.generation() {
            return;
        }
        if slots[idx].payload_ref != INVALID_PAYLOAD_REF {
            release_payload(slots[idx].payload_ref);
            slots[idx].payload_ref = INVALID_PAYLOAD_REF;
        }
        if slots[idx].args_payload_ref != INVALID_PAYLOAD_REF {
            release_payload(slots[idx].args_payload_ref);
            slots[idx].args_payload_ref = INVALID_PAYLOAD_REF;
        }
        slots[idx].kind = PO_KIND_NONE;
        slots[idx].reply_slot = 0;
        slots[idx].badge = 0;
        slots[idx].client_handle_raw = 0;
        slots[idx].stage = 0;
        for s in slots[idx].scratch.iter_mut() {
            *s = 0;
        }
        slots[idx].state.store(PO_STATE_FREE, Ordering::Release);
    }
}

/// Mutable lookup. Returns `None` if the slot is free, cancelled into
/// a different op, or the generation has rolled past the caller's id.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn get_mut(op_id: PendingOpId) -> Option<&'static mut PendingOp> {
    unsafe {
        if op_id.is_none() {
            return None;
        }
        let idx = op_id.slot() as usize;
        if idx >= MAX_PENDING_OPS {
            return None;
        }
        let slots = &mut *POOL.slots.get();
        if slots[idx].state.load(Ordering::Acquire) == PO_STATE_FREE {
            return None;
        }
        if slots[idx].generation != op_id.generation() {
            return None;
        }
        Some(&mut slots[idx])
    }
}

/// Read-only lookup; same staleness rules as `get_mut`.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn get(op_id: PendingOpId) -> Option<&'static PendingOp> {
    unsafe {
        if op_id.is_none() {
            return None;
        }
        let idx = op_id.slot() as usize;
        if idx >= MAX_PENDING_OPS {
            return None;
        }
        let slots = &*POOL.slots.get();
        if slots[idx].state.load(Ordering::Acquire) == PO_STATE_FREE {
            return None;
        }
        if slots[idx].generation != op_id.generation() {
            return None;
        }
        Some(&slots[idx])
    }
}

/// Hand the saved reply continuation to the caller, transferring
/// ownership. Returns `0` if the slot has already been released or
/// cancelled.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn take_reply_slot(op_id: PendingOpId) -> u64 {
    unsafe {
        let Some(op) = get_mut(op_id) else {
            return 0;
        };
        let slot = op.reply_slot;
        op.reply_slot = 0;
        slot
    }
}

/// Convenience for terminal completions: take the reply slot and free
/// the op in one go. Caller must then use the returned slot (e.g.
/// `send_saved_reply` or `release_reply_slot`).
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn take_reply_and_free(op_id: PendingOpId) -> u64 {
    unsafe {
        let slot = take_reply_slot(op_id);
        free(op_id);
        slot
    }
}

/// Iterate every active (non-FREE, non-CANCELLED) `PendingOp` whose
/// `kind` matches `target_kind`, applying `f` to each. Used by the
/// `drive_*_waiters` paths after the wait-table migration: they no
/// longer keep per-kind owner-state arrays, so the scan walks the
/// full pool filtered by kind. The callback receives the
/// re-packed `PendingOpId` and a mutable reference to the slot, so
/// the caller can mutate scratch / payload / state inline.
///
/// # Safety
///
/// Owner-thread only. The callback `f` must not call back into
/// `pending_ops` mutators (alloc / free / requeue) for the slot it
/// is currently inspecting; use the returned `PendingOpId` after
/// `f` returns instead.
pub(crate) unsafe fn for_each_active_kind<F: FnMut(PendingOpId, &mut PendingOp)>(
    target_kind: PendingOpKind,
    mut f: F,
) {
    unsafe {
        let slots = &mut *POOL.slots.get();
        for idx in 0..MAX_PENDING_OPS {
            let state = slots[idx].state.load(Ordering::Acquire);
            if state == PO_STATE_FREE || state == PO_STATE_CANCELLED {
                continue;
            }
            if slots[idx].kind != target_kind {
                continue;
            }
            let op_id = PendingOpId::pack(idx as u32, slots[idx].generation);
            f(op_id, &mut slots[idx]);
        }
    }
}

/// Worker-side: announce that worker `idx` is about to enter
/// `ipc::call_ctx` for `op_id`.
pub(crate) fn worker_enter(idx: usize, op_id: PendingOpId) {
    if idx >= MAX_WORKERS {
        return;
    }
    WORKER_INFLIGHT[idx].store(op_id.raw(), Ordering::Release);
}

/// Worker-side: clear the in-flight slot.
pub(crate) fn worker_leave(idx: usize) {
    if idx >= MAX_WORKERS {
        return;
    }
    WORKER_INFLIGHT[idx].store(0, Ordering::Release);
}

/// Worker-side: transition `QUEUED -> RUNNING`. Returns `false` if
/// the op has already been cancelled or freed before the worker
/// picked it up.
pub(crate) fn mark_running(op_id: PendingOpId) -> bool {
    let Some(op) = (unsafe { get(op_id) }) else {
        return false;
    };
    op.state
        .compare_exchange(
            PO_STATE_QUEUED,
            PO_STATE_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// Worker-side: transition `RUNNING -> COMPLETING` after the backend
/// reply has been received. Returns `false` if the owner has marked
/// the op cancelled in the meantime — caller must drop the
/// completion and not push it onto the ring.
pub(crate) fn try_complete(op_id: PendingOpId) -> bool {
    let Some(op) = (unsafe { get(op_id) }) else {
        return false;
    };
    op.state
        .compare_exchange(
            PO_STATE_RUNNING,
            PO_STATE_COMPLETING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// Owner-side: transition `COMPLETING -> QUEUED` so the same `op_id`
/// can chain into another backend RPC stage. Must be called between a
/// completion handler observing the previous stage's reply and pushing
/// the next `PendingBackendJob`. Returns `false` if the op was
/// cancelled in the meantime — caller must abort the chain and let
/// `drain_cancelled` release the reply slot.
pub(crate) fn requeue(op_id: PendingOpId) -> bool {
    let Some(op) = (unsafe { get(op_id) }) else {
        return false;
    };
    op.state
        .compare_exchange(
            PO_STATE_COMPLETING,
            PO_STATE_QUEUED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
}

/// Owner-side cancel walk. Marks every live op with matching `badge`
/// as cancelled. Workers currently in `ipc::call_ctx` will observe
/// the cancellation when they call `try_complete`. Ops that are
/// still `QUEUED` (worker has not picked them up yet) are deferred to
/// `drain_cancelled`.
///
/// Returns the number of ops that were live before this call.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn cancel_for_badge(badge: u64, disposition: CancelDisposition) -> usize {
    unsafe {
        let slots = &mut *POOL.slots.get();
        let mut count = 0usize;
        for slot in slots.iter_mut() {
            let state = slot.state.load(Ordering::Acquire);
            if state == PO_STATE_FREE || state == PO_STATE_CANCELLED {
                continue;
            }
            if slot.badge != badge {
                continue;
            }
            slot.cancel_disposition = disposition;
            slot.state.store(PO_STATE_CANCELLED, Ordering::Release);
            count += 1;
        }
        count
    }
}

/// Drain ops that were cancelled while still queued (worker never
/// picked them up) — releases their reply slots and frees them.
/// Should be called by the owner after `cancel_for_badge` and during
/// the idle tick.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn drain_cancelled() {
    unsafe {
        let slots = &mut *POOL.slots.get();
        for idx in 0..MAX_PENDING_OPS {
            if slots[idx].state.load(Ordering::Acquire) != PO_STATE_CANCELLED {
                continue;
            }
            let disposition = slots[idx].cancel_disposition;
            let reply_slot = slots[idx].reply_slot;
            slots[idx].reply_slot = 0;
            apply_cancel_reply(reply_slot, disposition);
            let op_id = PendingOpId::pack(idx as u32, slots[idx].generation);
            free(op_id);
        }
    }
}

unsafe fn apply_cancel_reply(reply_slot: u64, disposition: CancelDisposition) {
    if reply_slot == 0 {
        return;
    }
    match disposition {
        CANCEL_CANCELLED => unsafe {
            send_disposition_reply(reply_slot, uapi::TRONA_CANCELLED);
        },
        CANCEL_SERVER_DIED => unsafe {
            send_disposition_reply(reply_slot, uapi::TRONA_SERVER_DIED);
        },
        _ => unsafe {
            crate::fileops::tty_wait::release_reply_slot(reply_slot);
        },
    }
}

unsafe fn send_disposition_reply(reply_slot: u64, label: u64) {
    let mut reply = TronaMsg::zeroed();
    reply.label = label;
    unsafe {
        crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
    }
}

/// Reserve a payload slot from the typed payload pool. Returns
/// `None` if the pool is exhausted.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn alloc_payload() -> Option<u32> {
    unsafe {
        let payloads = &mut *POOL.payloads.get();
        let hint_ptr = POOL.next_payload_hint.get();
        let mut idx = (*hint_ptr) as usize;
        for _ in 0..MAX_PAYLOAD_BUFS {
            if idx >= MAX_PAYLOAD_BUFS {
                idx = 0;
            }
            if payloads[idx].in_use.load(Ordering::Acquire) == 0 {
                payloads[idx].in_use.store(1, Ordering::Release);
                for byte in payloads[idx].bytes.iter_mut() {
                    *byte = 0;
                }
                *hint_ptr = ((idx + 1) % MAX_PAYLOAD_BUFS) as u32;
                return Some(idx as u32);
            }
            idx += 1;
        }
        None
    }
}

/// Release a payload slot.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn release_payload(payload_ref: u32) {
    unsafe {
        if payload_ref == INVALID_PAYLOAD_REF {
            return;
        }
        let idx = payload_ref as usize;
        if idx >= MAX_PAYLOAD_BUFS {
            return;
        }
        let payloads = &mut *POOL.payloads.get();
        payloads[idx].in_use.store(0, Ordering::Release);
    }
}

/// Mutable view of a payload buffer.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn payload_bytes_mut(
    payload_ref: u32,
) -> Option<&'static mut [u8; PAYLOAD_BUF_BYTES]> {
    unsafe {
        if payload_ref == INVALID_PAYLOAD_REF {
            return None;
        }
        let idx = payload_ref as usize;
        if idx >= MAX_PAYLOAD_BUFS {
            return None;
        }
        let payloads = &mut *POOL.payloads.get();
        Some(&mut payloads[idx].bytes)
    }
}

/// Read-only view of a payload buffer.
///
/// # Safety
///
/// Owner-thread only.
pub(crate) unsafe fn payload_bytes(payload_ref: u32) -> Option<&'static [u8; PAYLOAD_BUF_BYTES]> {
    unsafe {
        if payload_ref == INVALID_PAYLOAD_REF {
            return None;
        }
        let idx = payload_ref as usize;
        if idx >= MAX_PAYLOAD_BUFS {
            return None;
        }
        let payloads = &*POOL.payloads.get();
        Some(&payloads[idx].bytes)
    }
}
