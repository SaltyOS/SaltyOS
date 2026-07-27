// SPDX-License-Identifier: GPL-2.0-only
//! Per-backend session slots — inflight credit + deferred-issue waiter ring.
//!
//! Every mount bound to an async-capable backend (currently SaltyFS) claims a
//! [`BackendSessionSlot`] in [`crate::owner::VfsState::backend_sessions`]. The
//! slot tracks the backend's advertised inflight credit cap and the running
//! count of live `PendingOp`s charged against it, along with a bounded FIFO
//! ring of deferred issues waiting for credit.
//!
//! The slot table is a fixed-size array keyed by array index. Lookup from a
//! `FsInstanceId` is a linear scan, matching the pattern already used for the
//! mount arena. Each slot carries a `live_gen` counter set on allocate and
//! reset on release so late completions / abandoned deferred issues can be
//! rejected via a generation mismatch instead of racing the free-and-reuse
//! window.

use crate::owner::op::OpCore;
use crate::owner::pending::{PendingKindPayload, PendingOpHandle, TxId};
use crate::owner::resume::Resume;
use crate::vfs_core::identity::FsInstanceId;

/// Function-pointer signature for a per-backend deferred-issue drain
/// hook. Backends that use the inflight-credit machinery register
/// a drain implementation at mount time via
/// [`crate::owner::VfsState::alloc_backend_session_slot`]. Every
/// successful `backend_credit_release` then invokes the hook so
/// parked waiters observe newly-available credit without a cross-
/// cutting call in the common `fileops` path.
///
/// The hook is free to pop entries from the session's waiter ring,
/// rebuild and re-fire backend-specific RPCs, and stamp resume
/// contexts — the generic owner layer never needs to know the
/// wire format. A backend that does not use the credit machinery
/// (e.g. ramfs, tmpfs, devfs) simply omits registration; the slot's
/// `drain_fn` defaults to [`no_op_drain`].
pub(crate) type DrainFn = unsafe fn(&mut crate::owner::VfsState, FsInstanceId);

/// Function-pointer signature for a per-backend readdir-EOF hook.
/// Invoked by `fileops::dir::resume_fill_bulk_readdir_reply` when the
/// backend reports zero new entries (EOF). Backends that hold per-
/// mount SHM ownership for in-flight readdir batches use this hook
/// to release the flag so a concurrent readdir on a different
/// `OpenObject` can reissue. Defaults to [`no_op_readdir_eof`] for
/// backends that don't need this (ramfs, tmpfs, devfs).
pub(crate) type ReaddirEofFn = unsafe fn(
    &mut crate::owner::VfsState,
    FsInstanceId,
    crate::server::open_object::OpenObjectHandle,
);

/// Default readdir-EOF implementation — no-op. Backends that hold
/// per-session readdir SHM ownership override this to drop the flag
/// when the batch drains.
pub(crate) unsafe fn no_op_readdir_eof(
    _state: &mut crate::owner::VfsState,
    _fs_id: FsInstanceId,
    _open_handle: crate::server::open_object::OpenObjectHandle,
) {
}

/// Function-pointer signature for a per-backend completion router.
/// Invoked by [`crate::owner::pending::dispatch_pending_reply`] once
/// the generic session-gate / stale-mount checks have passed. The
/// backend is handed its opaque [`PendingKindPayload`] — which it
/// `unpack`s to recover its own op-kind enum — along with the parked
/// [`Resume`], the saved reply op, and the inbound completion
/// message. It is responsible for parsing the reply payload, copying
/// any SHM-resident data into the appropriate location, releasing one
/// inflight credit against the session, and emitting the client
/// reply via the saved caller cap carried by [`OpCore`].
///
/// Registered at mount time alongside [`DrainFn`] / [`PushFn`];
/// defaults to [`no_op_completion`] for backends that do not park
/// requests (in which case no completions should ever arrive).
pub(crate) type CompletionFn = unsafe fn(
    state: &mut crate::owner::VfsState,
    fs_id: FsInstanceId,
    tx_id: TxId,
    kind: &PendingKindPayload,
    resume_ctx: Resume,
    reply_op: OpCore,
    reply_msg: &trona_kernel::core_types::core::TronaMsg,
);

/// Default completion implementation — used by backends that do not
/// park requests. Releases any saved reply slot and returns; a
/// completion arriving against such a session indicates a wire-level
/// protocol violation and is otherwise ignored.
pub(crate) unsafe fn no_op_completion(
    state: &mut crate::owner::VfsState,
    _fs_id: FsInstanceId,
    _tx_id: TxId,
    _kind: &PendingKindPayload,
    _resume_ctx: Resume,
    reply_op: OpCore,
    _reply_msg: &trona_kernel::core_types::core::TronaMsg,
) {
    unsafe {
        if reply_op.reply_slot != 0 {
            state.release_saved_reply_slot(reply_op.reply_slot);
        }
    }
}

/// Default drain implementation — used when a backend does not
/// register its own. No-op so the generic release path never has to
/// null-check.
pub(crate) unsafe fn no_op_drain(_state: &mut crate::owner::VfsState, _fs_id: FsInstanceId) {}

/// Opaque bundle of per-op arguments for a deferred-issue push.
/// Carries the primitives the fileops layer has on hand when it
/// detects credit exhaustion; the backend-specific `push_fn`
/// interprets the variant and reconstructs its own op record
/// (e.g. building a backend-private op-kind enum + a `FsResume`
/// variant from the raw vnode / mount data pointers). `vnode_data`
/// / `mount_data` are the backend's untyped state pointers — the
/// fileops layer never dereferences them, so no backend-specific
/// knowledge leaks out.
///
/// Xattr variants ship the inline name (and, for SetXattr, the value)
/// bytes with the args so the backend can stash them in its own
/// op-kind payload for later replay — the VFS↔backend SHM region is
/// the very lock the parked op is waiting on, so the payload cannot
/// live there at park time.
#[derive(Clone, Copy)]
pub(crate) enum DeferArgs {
    Read {
        vnode_data: *mut u8,
        mount_data: *mut u8,
        file_offset: u64,
        len: u64,
        fd: i32,
        shm_offset: u64,
        client: crate::server::types::ClientHandle,
        vkey: crate::vfs_core::identity::VnodeKey,
    },
    Readdir {
        vnode_data: *mut u8,
        mount_data: *mut u8,
        fd: i32,
        client: crate::server::types::ClientHandle,
        open_handle: crate::server::open_object::OpenObjectHandle,
        start_cursor: u64,
        vkey: crate::vfs_core::identity::VnodeKey,
    },
    XattrGet {
        vnode_data: *mut u8,
        mount_data: *mut u8,
        client: crate::server::types::ClientHandle,
        vkey: crate::vfs_core::identity::VnodeKey,
        name: [u8; crate::owner::pending::WALK_NAME_MAX],
        name_len: u8,
    },
    XattrList {
        vnode_data: *mut u8,
        mount_data: *mut u8,
        client: crate::server::types::ClientHandle,
        vkey: crate::vfs_core::identity::VnodeKey,
    },
    XattrSet {
        vnode_data: *mut u8,
        mount_data: *mut u8,
        client: crate::server::types::ClientHandle,
        vkey: crate::vfs_core::identity::VnodeKey,
        name: [u8; crate::owner::pending::WALK_NAME_MAX],
        value: [u8; crate::owner::pending::WALK_NAME_MAX],
        name_len: u8,
        value_len: u16,
        flags: u32,
    },
}

/// Function-pointer signature for a per-backend push-on-exhaustion
/// hook. Registered at mount time alongside [`DrainFn`]; the
/// generic fileops path calls it when the session's credit is
/// exhausted and the caller has already allocated a reply slot and
/// saved the client's caller cap. The backend builds a
/// [`crate::owner::deferred::DeferredIssue`] record and pushes it
/// onto the session's waiter ring. Returns `true` on successful
/// park, `false` when the ring is full (fileops surfaces
/// `TRONA_BUSY` in that case).
///
/// Backends that do not park (ramfs, tmpfs, devfs — no credit
/// machinery) register [`no_op_push`] by default.
pub(crate) type PushFn = unsafe fn(
    state: &mut crate::owner::VfsState,
    fs_id: FsInstanceId,
    args: DeferArgs,
    client_badge: u64,
    reply_op: OpCore,
) -> bool;

/// Default push implementation — used by synchronous backends that
/// never exercise the credit machinery. Always returns `false` so
/// the caller surfaces `TRONA_BUSY` if it ever reaches the push
/// path unexpectedly.
pub(crate) unsafe fn no_op_push(
    _state: &mut crate::owner::VfsState,
    _fs_id: FsInstanceId,
    _args: DeferArgs,
    _client_badge: u64,
    _reply_op: OpCore,
) -> bool {
    false
}

/// Maximum simultaneous backend sessions. Matches the VFS mount arena
/// capacity so every live mount can own at most one session slot.
pub(crate) const MAX_BACKEND_SESSIONS: usize = 16;

/// Bounded FIFO depth per-session for deferred issues waiting on credit.
/// Beyond this the session surfaces `TRONA_AGAIN` to the originating client.
pub(crate) const WAIT_Q_DEPTH: usize = 16;

/// Sentinel value used to mark an unoccupied entry in the waiter ring.
/// `Handle::INVALID` carries `slot = u32::MAX` which no arena ever allocates.
pub(crate) const WAIT_Q_EMPTY: PendingOpHandle = PendingOpHandle::INVALID;

/// Per-session credit + waiter state.
///
/// `live_gen == 0` marks an unoccupied slot. Allocation sets the counter
/// to a non-zero locally-monotonic value; release resets it to `0`.
/// Deferred-issue promotion snapshots this counter so a waiter parked
/// on an old session slot cannot resurrect after teardown + reuse.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BackendSessionSlot {
    /// Local session-generation counter. `0` → slot is free. Non-zero
    /// → slot is live. Named `live_gen` rather than `gen` because `gen`
    /// is a reserved keyword in Rust 2024.
    pub(crate) live_gen: u32,
    /// Monotonic session id assigned at mount time (distinct from the slot
    /// index — `FsInstanceId` is the source of truth, `session_id` is the
    /// wire-level identifier echoed by the backend on every completion).
    pub(crate) session_id: u32,
    /// Identity of the mount this session is bound to.
    pub(crate) fs_instance_id: FsInstanceId,
    /// Inflight credit cap advertised by the backend via
    /// [`trona_protocol::BackendOpenSessionReply::max_inflight`].
    pub(crate) inflight_max: u16,
    /// Number of `PendingOp`s currently charged against this session.
    pub(crate) inflight_now: u16,
    /// Bounded FIFO of deferred issues. Entries are `PendingOpHandle`
    /// values pointing into `VfsState.pending_ops`, where the slot is
    /// parked in `PendingOpState::DeferredFs`. `WAIT_Q_EMPTY` marks a
    /// free slot within the ring.
    pub(crate) wait_q: [PendingOpHandle; WAIT_Q_DEPTH],
    /// Head of the ring — next entry to dequeue.
    pub(crate) wait_head: u8,
    /// Tail of the ring — next slot to enqueue into.
    pub(crate) wait_tail: u8,
    /// Count of live entries. Kept explicit (rather than derived from
    /// `(tail - head) mod cap`) so a full ring is distinguishable from an
    /// empty one.
    pub(crate) wait_count: u8,
    _pad: [u8; 1],
    /// Per-backend drain hook. Invoked by
    /// [`crate::owner::VfsState::backend_credit_release`] after every
    /// credit return so backends that park requests on credit
    /// exhaustion can promote the oldest waiter without the generic
    /// fileops path having to know which backend the session belongs
    /// to. Defaults to [`no_op_drain`] for backends that never park.
    pub(crate) drain_fn: DrainFn,
    /// Per-backend push hook. Invoked by
    /// [`crate::owner::VfsState::session_defer_push`] when the generic
    /// fileops path observes credit exhaustion and wants to park
    /// a request without knowing which backend owns the mount.
    /// Defaults to [`no_op_push`].
    pub(crate) push_fn: PushFn,
    /// Per-backend completion router. Invoked by
    /// [`crate::owner::pending::dispatch_pending_reply`] after the
    /// session-gate / stale-mount checks have passed. The backend
    /// unpacks [`PendingKindPayload`], parses the reply, releases
    /// one inflight credit, and emits the client reply. Defaults to
    /// [`no_op_completion`].
    pub(crate) completion_fn: CompletionFn,
    /// Per-backend readdir-EOF hook. Invoked by
    /// [`crate::fileops::dir::resume_fill_bulk_readdir_reply`] when
    /// the backend reports zero new entries. Defaults to
    /// [`no_op_readdir_eof`].
    pub(crate) readdir_eof_fn: ReaddirEofFn,
    /// Backend's callback endpoint cap. Retained on the session so a
    /// future revocation detector can consult it when classifying a
    /// notification as session-scoped cap loss. `0` when the backend
    /// did not advertise one. Populated by
    /// [`crate::owner::VfsState::set_backend_callback_ep`] at mount
    /// time; zeroed on `free_backend_session_slot`.
    pub(crate) callback_ep: u64,
    /// Reply slot reserved for the backend's cap-revocation
    /// notification. `0` when no watcher is armed. The revocation
    /// detector (future work — kernel notification wiring not yet in
    /// place) will consult this slot when a session cap is revoked so
    /// the owner can synthesise `SessionTornDown` replies for every
    /// in-flight `PendingOp` scoped to `fs_instance_id`.
    pub(crate) revocation_slot: u64,
}

impl BackendSessionSlot {
    pub(crate) const fn zeroed() -> Self {
        BackendSessionSlot {
            live_gen: 0,
            session_id: 0,
            fs_instance_id: FsInstanceId::INVALID,
            inflight_max: 0,
            inflight_now: 0,
            wait_q: [WAIT_Q_EMPTY; WAIT_Q_DEPTH],
            wait_head: 0,
            wait_tail: 0,
            wait_count: 0,
            _pad: [0],
            drain_fn: no_op_drain,
            push_fn: no_op_push,
            completion_fn: no_op_completion,
            readdir_eof_fn: no_op_readdir_eof,
            callback_ep: 0,
            revocation_slot: 0,
        }
    }

    /// True when the slot is live (allocated, not yet released).
    #[inline]
    pub(crate) const fn is_live(&self) -> bool {
        self.live_gen != 0
    }

    /// True when a new inflight issue would exceed the credit cap. Callers
    /// must park via the deferred queue when this returns `true`.
    #[inline]
    pub(crate) const fn credit_exhausted(&self) -> bool {
        self.inflight_max != 0 && self.inflight_now >= self.inflight_max
    }

    /// True when the waiter ring has no capacity left. Callers must surface
    /// [`uapi::TRONA_AGAIN`] to the client instead of parking.
    #[inline]
    pub(crate) const fn wait_q_full(&self) -> bool {
        self.wait_count as usize >= WAIT_Q_DEPTH
    }

    /// Push a deferred-issue handle onto the ring. Returns `false` when the
    /// ring is full.
    pub(crate) fn wait_q_push(&mut self, handle: PendingOpHandle) -> bool {
        if self.wait_q_full() {
            return false;
        }
        let idx = self.wait_tail as usize;
        self.wait_q[idx] = handle;
        self.wait_tail = ((self.wait_tail as usize + 1) % WAIT_Q_DEPTH) as u8;
        self.wait_count += 1;
        true
    }

    /// Pop the oldest deferred-issue handle from the ring. Returns `None`
    /// when the ring is empty.
    pub(crate) fn wait_q_pop(&mut self) -> Option<PendingOpHandle> {
        if self.wait_count == 0 {
            return None;
        }
        let idx = self.wait_head as usize;
        let handle = self.wait_q[idx];
        self.wait_q[idx] = WAIT_Q_EMPTY;
        self.wait_head = ((self.wait_head as usize + 1) % WAIT_Q_DEPTH) as u8;
        self.wait_count -= 1;
        Some(handle)
    }

    /// Remove one deferred handle from the waiter ring. O(n) over the
    /// tiny bounded ring, which is acceptable for client-exit and
    /// cancellation cleanup.
    pub(crate) fn wait_q_remove(&mut self, target: PendingOpHandle) -> bool {
        if self.wait_count == 0 || !target.is_valid() {
            return false;
        }
        let mut new_q = [WAIT_Q_EMPTY; WAIT_Q_DEPTH];
        let mut removed = false;
        let mut write = 0usize;
        let count = self.wait_count as usize;
        for i in 0..count {
            let idx = (self.wait_head as usize + i) % WAIT_Q_DEPTH;
            let handle = self.wait_q[idx];
            if handle == target {
                removed = true;
                continue;
            }
            new_q[write] = handle;
            write += 1;
        }
        if removed {
            self.wait_q = new_q;
            self.wait_head = 0;
            self.wait_tail = write as u8;
            self.wait_count = write as u8;
        }
        removed
    }
}

impl Default for BackendSessionSlot {
    fn default() -> Self {
        BackendSessionSlot::zeroed()
    }
}
