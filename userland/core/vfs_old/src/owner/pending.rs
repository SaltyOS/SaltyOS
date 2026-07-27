// SPDX-License-Identifier: GPL-2.0-only
//! Async RPC correlation — `TxId` + `PendingOp` arena.
//!
//! Converts owner-path backend calls from blocking `ipc::call_ctx`
//! (which monopolises the owner loop while the backend services the
//! request) to a park-and-wake pattern: fire `send_ctx`, record a
//! `PendingOp`, yield to the multi-endpoint `recv_any_ctx`, then match
//! the reply back to the waiting client on callback.
//!
//! `TxId` is a monotonic per-VFS identifier allocated on each outbound
//! RPC. The zero value is the reserved `INVALID` sentinel so zeroed
//! `PendingOp` slots are trivially recognisable as empty. Allocation
//! wraps around past `INVALID` like `FsInstanceId`.
//!
//! `PendingOp` captures what the owner must remember to resume the
//! client: the caller's reply slot and badge (to restart the RPC
//! response), plus `PendingOpState` describing which RPC is pending.
//! The state payload must reference VFS-stable identities only —
//! `VnodeKey`, `FsInstanceId`, badge ids, or plain scalars — never
//! `VnodeHandle` / `MountHandle`, whose arena slots can recycle before
//! the backend replies.

use crate::arena::{Arena, Handle};
use crate::owner::op::{BeginOpError, OpCore, OpKind};
use crate::owner::resume::Resume;
use crate::server::types::ClientHandle;
use crate::vfs_core::identity::{FsInstanceId, VnodeKey};

/// Monotonic transaction id for a pending backend RPC. Allocated via
/// [`VfsState::alloc_tx_id`] on each outbound call; never reused.
///
/// `INVALID` is the reserved sentinel for "no transaction" / zeroed
/// slot and equals the bit pattern produced by zero-initialisation.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(crate) struct TxId(pub u64);

impl TxId {
    pub(crate) const INVALID: TxId = TxId(0);

    #[inline]
    pub(crate) const fn new(value: u64) -> Self {
        TxId(value)
    }

    #[inline]
    pub(crate) const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub(crate) const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

impl Default for TxId {
    #[inline]
    fn default() -> Self {
        TxId::INVALID
    }
}

/// Maximum component name length accepted by the path-walk state
/// machine. Mirrors `server::consts::MAX_NAME_LEN` but lives here so
/// path-walk cursors can embed the name inline without pulling the
/// server layer into `owner/pending.rs`.
pub(crate) const WALK_NAME_MAX: usize = 255;

/// Maximum symlink-target length copied into the per-op target
/// buffer on READLINK reply. Requests exceeding this produce
/// `VfsError::NameTooLong` at resume time.
pub(crate) const WALK_SYMLINK_TARGET_MAX: usize = 4096;

/// Backend-opaque inline payload accompanying a parked `PendingOp`.
///
/// The generic pending / session / fileops layers do not interpret
/// these bytes. Each filesystem backend defines its own op-kind enum
/// in its private module and provides `pack` / `unpack` helpers that
/// memcpy into / out of this buffer. Completions are routed through
/// `BackendSessionSlot::completion_fn`, and only the backend's
/// registered handler is permitted to read the payload.
///
/// Size is bounded at [`PENDING_KIND_PAYLOAD_WORDS`] `u64` words; each
/// backend's `pack` implementation carries a compile-time assertion
/// that its op-kind enum fits. Growing a backend's op-kind without
/// adjusting the global bound surfaces as a build error, not a silent
/// truncation.
///
/// The current bound is sized for a backend's widest compound
/// mutation variant (two inline name buffers of
/// `WALK_NAME_MAX = 255` bytes each plus op metadata). The raw
/// `u64` backing keeps memcpy-safe pack/unpack while staying
/// alignment-stable.
pub(crate) const PENDING_KIND_PAYLOAD_WORDS: usize = 72;

/// Byte size of [`PendingKindPayload`]; kept as a separate constant so
/// backend `pack` helpers can assert their struct fits without
/// depending on `core::mem::size_of::<PendingKindPayload>()` at
/// const-eval time.
pub(crate) const PENDING_KIND_PAYLOAD_BYTES: usize = PENDING_KIND_PAYLOAD_WORDS * 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PendingKindPayload {
    pub(crate) words: [u64; PENDING_KIND_PAYLOAD_WORDS],
}

impl PendingKindPayload {
    pub(crate) const fn zeroed() -> Self {
        PendingKindPayload {
            words: [0; PENDING_KIND_PAYLOAD_WORDS],
        }
    }
}

impl Default for PendingKindPayload {
    #[inline]
    fn default() -> Self {
        PendingKindPayload::zeroed()
    }
}

/// Maximum embeddable path length in a parked namei walk cursor.
/// Matches `server::consts::MAX_PATH_LEN` by construction; kept as a
/// local constant so the pending layer does not depend on the
/// server namespace.
pub(crate) const WALK_PATH_MAX: usize = 128;

/// Terminal-step policy encoding `NAMEI_CREATE` / `NAMEI_WANTPARENT`
/// semantics explicitly. Resume handlers MUST consult this variant
/// rather than inferring intent from the cursor's position, per the
/// async-walker invariant documented in `namei_common.rs`.
#[derive(Clone, Copy)]
pub(crate) enum WalkPolicy {
    /// Standard walk — resolve every component including the final
    /// one. Used by `stat` / `open` (without O_CREAT) / `readlink`.
    Continue,
    /// Resolve every component including the final one. When the
    /// final lookup misses, return the parent directory plus the
    /// final component bytes so callers can materialise `O_CREAT`
    /// style behaviour without re-running path resolution.
    CreateOrOpen {
        final_name: [u8; WALK_NAME_MAX],
        final_name_len: u8,
        final_missing: bool,
    },
    /// Walk up to the parent of `final_name`, return dvp + the
    /// trailing component without resolving it. Used by `mkdir` /
    /// `symlink` / `unlink` / `rename` source+dest style flows
    /// that need the parent directory as their terminal hand-off.
    StopAtParent {
        final_name: [u8; WALK_NAME_MAX],
        final_name_len: u8,
    },
    /// Standard walk but the final component MUST exist. Distinct
    /// from `Continue` where the caller tolerates `ENOENT` via a
    /// fallback; this variant guarantees the resume helper produces
    /// `VfsError::NotFound` on missing final.
    FinalMustExist,
}

/// Identity-stable snapshot of in-flight path-walk state. All fields
/// are scalars, inline byte arrays, or identity keys — no handles,
/// no pointers, no `'static`-or-shorter borrows. See the "Async
/// path-walk" docblock in `vfs_core/namei_common.rs` for the walk
/// resume contract and cursor field semantics.
#[derive(Clone, Copy)]
pub(crate) struct WalkCursor {
    /// Current walk position. Re-resolved to a live `VnodeHandle`
    /// via `lookup_resolve_cache` at resume time; a miss surfaces as
    /// `TRONA_INVALID_OPERATION` to the client (ESTALE semantics).
    pub(crate) cwd_vkey: VnodeKey,
    /// Namespace root for `..` containment and absolute-path
    /// interpretation. Snapshotted once at walk start and preserved
    /// across resumes so mount-namespace changes mid-walk don't
    /// silently reinterpret the path.
    pub(crate) root_vkey: VnodeKey,
    /// Remaining bytes to walk. Components are consumed from the
    /// front by the walk loop; the cursor advances by rewriting
    /// `remaining_len` (no allocation). Byte layout matches the
    /// per-personality `namei` grammar (POSIX: `/`-separated).
    pub(crate) remaining_path: [u8; WALK_PATH_MAX],
    pub(crate) remaining_len: u16,
    /// Symlink-follow depth counter. Monotonic across resumes;
    /// incremented each time a symlink target is spliced in and
    /// capped at `NAMEI_SYMLINK_MAX_DEPTH` (= 8) before returning
    /// `VfsError::Loop`.
    pub(crate) follow_depth: u8,
    /// Credential snapshot at walk dispatch time. Required for
    /// permission-sensitive terminal steps such as `readlink`
    /// across park/resume boundaries.
    pub(crate) cred: crate::vfs_core::cred::VfsCred,
    /// Effective `NAMEI_*` flag mask at walk start. Resume handlers
    /// treat this as immutable — changing flags mid-walk would
    /// violate POSIX semantics.
    pub(crate) flags: u32,
    /// Terminal-step disposition. See [`WalkPolicy`].
    pub(crate) policy: WalkPolicy,
}

/// Which backend RPC boundary the walk is parked on. The variant
/// determines which generic resume helper the backend completion
/// router invokes after it has translated the wire reply.
#[derive(Clone, Copy)]
pub(crate) enum WalkPhase {
    /// Parked on a child-component lookup RPC. The backend
    /// completion router materialises the child vnode (or clean
    /// ENOENT) and hands the generic outcome back to the walker.
    Lookup,
    /// Parked on a readlink RPC for an intermediate symlink.
    /// The translated target bytes are spliced into
    /// `target + '/' + old_remaining` into `remaining_path`,
    /// bumps `follow_depth`, and re-enters the walk loop at the
    /// containing directory. The target buffer reservation lives
    /// alongside the `PendingOp`.
    Readlink,
    /// Parked on a covering-mount `VGET` when crossing into a newly
    /// discovered mount whose root vnode is not yet materialised.
    /// The backend completion router materialises the covering
    /// root vnode before the walk continues.
    CrossMountVget,
    /// Parked on the terminal mutation RPC (`CREATE` / `MKDIR` /
    /// `SYMLINK` / `UNLINK` / `RENAME` / `RMDIR`) when the walk's
    /// `WalkPolicy::StopAtParent` has already resolved the parent
    /// and the final op is itself async. Reply carries the
    /// operation's success/failure label + any returned inode id
    /// so the syscall handler can format its client reply.
    FinalOp,
}

/// Which RPC a `PendingOp` is waiting on, plus the identity-stable
/// payload the owner needs to finish the client response when the
/// backend replies.
///
/// Variants store only VFS-stable identities and scalars. Handles
/// (`VnodeHandle`, `MountHandle`) are forbidden here — arena slots can
/// recycle between outbound send and inbound reply, at which point a
/// cached handle would silently point at unrelated state. Resolve
/// handles freshly on completion via the identity.
#[derive(Clone, Copy)]
pub(crate) enum PendingOpState {
    /// Slot is free. Initial state of a zeroed arena entry.
    Empty,
    /// Parked backend RPC. `fs_instance_id` detects mount teardown
    /// during flight (stale reply → drop with `TRONA_INVALID_OPERATION`).
    /// `kind` is a backend-opaque payload that the registered
    /// `BackendSessionSlot::completion_fn` interprets. `resume_ctx`
    /// is the fileops caller's continuation.
    Fs {
        fs_instance_id: FsInstanceId,
        kind: PendingKindPayload,
        resume_ctx: Resume,
    },
    /// Parked backend RPC that has not yet been issued because the
    /// target session has no inflight credit available. The same
    /// `PendingOp` handle lives in the session waiter ring and is
    /// promoted in place once credit becomes available.
    DeferredFs {
        fs_instance_id: FsInstanceId,
        session_id: u32,
        session_gen: u32,
        kind: PendingKindPayload,
        resume_ctx: Resume,
        target_seq: u32,
    },
    /// Parked netsrv RPC. Completion comes in via the backend
    /// callback EP on the netsrv wire. `netsrv_gen` carries the
    /// registration generation at issue time — a reply whose
    /// generation pre-dates the current
    /// `VfsState::next_netsrv_gen` is dropped silently (netsrv
    /// restarted between issue and reply). `conn_id` + `op_type`
    /// index into the netsrv side's view of the parked op so the
    /// reply can be correlated without re-reading the inet table.
    Net {
        netsrv_gen: u32,
        conn_id: u32,
        op_type: u8,
        resume_ctx: Resume,
    },
}

impl Default for PendingOpState {
    #[inline]
    fn default() -> Self {
        PendingOpState::Empty
    }
}

/// A single outstanding backend RPC awaiting reply. Stored in
/// [`VfsState::pending_ops`] and matched on `tx_id` when a reply
/// arrives on the multi-endpoint receive path.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PendingOp {
    /// Transaction identifier echoed by the backend in its reply.
    /// `INVALID` means the slot is free.
    pub(crate) tx_id: TxId,
    /// Client's IPC badge — used to locate the `ClientState` so the
    /// reply can be routed back after the backend completes.
    pub(crate) client_badge: u64,
    /// Owner-side continuation core for the parked client reply.
    /// `reply_slot == 0` means no saved caller cap is held.
    pub(crate) reply_op: OpCore,
    /// What the owner is waiting on. `Empty` marks a free slot.
    pub(crate) op_state: PendingOpState,
    /// Non-zero if the client disconnected or otherwise cancelled the
    /// outstanding operation; the reply (when it arrives) is dropped
    /// instead of forwarded.
    pub(crate) cancelled: u8,
    /// Non-zero if this op reserved an inflight credit at issue time
    /// (read / readdir / the compound-mutation + xattr families) and
    /// non-zero cancellation therefore must release one credit back
    /// to the session. Zero for ops that never reserve credit
    /// (`stat` / `lookup` / `readlink` / `getinfo`); those paths
    /// would otherwise under-decrement `inflight_now` on cancel and
    /// let the session over-issue.
    pub(crate) credited: u8,
    /// Lookup-coalescing secondary marker. `INVALID` means this op is
    /// independent (or the primary); a valid `TxId` means the op is a
    /// secondary waiter piggybacking on the primary lookup carrying
    /// that transaction id.
    pub(crate) coalesce_primary_tx: TxId,
}

impl Default for PendingOp {
    fn default() -> Self {
        PendingOp {
            tx_id: TxId::INVALID,
            client_badge: 0,
            reply_op: OpCore::INVALID,
            op_state: PendingOpState::Empty,
            cancelled: 0,
            credited: 0,
            coalesce_primary_tx: TxId::INVALID,
        }
    }
}

/// Arena handle for a `PendingOp` entry. Used by senders to locate
/// their slot if they need to peek at / cancel the pending state
/// without scanning by `TxId`.
pub(crate) type PendingOpHandle = Handle<PendingOp>;

const MAX_COALESCED_FANOUT: usize = INITIAL_PENDING_OPS as usize;

/// Decode a correlation header from MR28..=MR31 and accept it if it
/// is a valid `CLASS_FS` completion. Any backend id is accepted —
/// routing happens via `BackendSessionSlot::completion_fn` keyed by
/// the owning `FsInstanceId` once the `PendingOp` has been located.
pub(crate) fn decode_fs_completion_header(
    msg: &trona_kernel::core_types::core::TronaMsg,
) -> Option<trona_protocol::correlation::CorrelationHeader> {
    let words = [
        msg.regs[trona_protocol::correlation::CORRELATION_HEADER_REG_START],
        msg.regs[trona_protocol::correlation::CORRELATION_HEADER_REG_START + 1],
        msg.regs[trona_protocol::correlation::CORRELATION_HEADER_REG_START + 2],
        msg.regs[trona_protocol::correlation::CORRELATION_HEADER_REG_START + 3],
    ];
    let header = trona_protocol::correlation::CorrelationHeader::decode_words(words);
    if header.class != trona_protocol::correlation::CORRELATION_CLASS_FS
        || header.kind != trona_protocol::correlation::CORRELATION_KIND_COMPLETION
        || header.token == 0
    {
        return None;
    }
    Some(header)
}

unsafe fn broadcast_coalesced_lookup_replies(
    state: &mut super::VfsState,
    header: &trona_protocol::correlation::CorrelationHeader,
    msg: &trona_kernel::core_types::core::TronaMsg,
    primary_tx: TxId,
) {
    unsafe {
        if !primary_tx.is_valid() {
            return;
        }
        let mut waiters: [PendingOpHandle; MAX_COALESCED_FANOUT] =
            [PendingOpHandle::INVALID; MAX_COALESCED_FANOUT];
        let mut waiter_count = 0usize;
        state.pending_ops.for_each_active(|h, op| {
            if waiter_count >= waiters.len() {
                return false;
            }
            if op.coalesce_primary_tx == primary_tx {
                waiters[waiter_count] = h;
                waiter_count += 1;
            }
            true
        });
        for slot in 0..waiter_count {
            let waiter = waiters[slot];
            let waiter_tx_id = match state.pending_ops.get(waiter) {
                Some(op) => op.tx_id,
                None => continue,
            };
            let mut synth = *msg;
            let mut synth_header = *header;
            synth_header.token = waiter_tx_id.raw();
            let words = synth_header.encode_words();
            for i in 0..trona_protocol::correlation::CORRELATION_HEADER_REG_COUNT {
                synth.regs[trona_protocol::correlation::CORRELATION_HEADER_REG_START + i] =
                    words[i];
            }
            dispatch_pending_reply(state, &synth);
        }
    }
}

/// Dispatch a backend reply to the matching `PendingOp`. Reads
/// the correlation-header token as the parked transaction identifier,
/// looks up the `PendingOp`, validates the mount session is still
/// alive, and hands the parked continuation to the backend-registered
/// completion router.
///
/// Drops (with a log) when:
/// - `tx_id` is `INVALID` or does not match any live `PendingOp`.
/// - `session` field on the completion header does not match the live
///   session id for the owning mount (session retired or remounted).
/// - `cancelled` is set (client exited mid-RPC, or fileops aborted
///   after the RPC left the wire). Credit still gets returned so the
///   session cap is honoured.
/// - `fs_instance_id` no longer resolves (mount was unmounted during
///   the in-flight RPC); replies `TRONA_INVALID_OPERATION` to the
///   saved reply slot so the client sees a stable error instead of
///   hanging.
/// - No completion router is registered for the session (should never
///   happen for a live session, but handled defensively).
pub(crate) unsafe fn dispatch_pending_reply(
    state: &mut super::VfsState,
    msg: &trona_kernel::core_types::core::TronaMsg,
) {
    unsafe {
        let Some(header) = decode_fs_completion_header(msg) else {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[vfs] completion dropped: not a valid FS-completion header\n");
            });
            return;
        };
        let tx_id = TxId::new(header.token);
        let Some(handle) = state.find_pending_op(tx_id) else {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[vfs] completion dropped: unknown token=");
                _lb.hex(tx_id.raw());
                _lb.str(b" session=");
                _lb.dec(header.session as u64);
                _lb.str(b" opcode=");
                _lb.dec(header.opcode as u64);
                _lb.str(b"\n");
            });
            return;
        };

        // Snapshot the slot, release it, then dispatch the resume
        // callback. Holding a live borrow across the resume callback
        // would conflict with `VfsState` aliasing rules.
        let snapshot = match state.pending_ops.get(handle) {
            Some(op) => *op,
            None => return,
        };
        let _ = state.pending_ops.release(handle);
        let primary_tx = snapshot.tx_id;

        // Stale-session gate: drop completions whose `session` field no
        // longer matches any live backend session slot. Without this
        // check a completion racing against unmount/remount of the same
        // mount point could resurface against a fresh session and
        // corrupt credit accounting / resume routing.
        let fs_instance_id = match snapshot.op_state {
            PendingOpState::Fs { fs_instance_id, .. } => fs_instance_id,
            PendingOpState::DeferredFs { .. } => {
                if snapshot.reply_op.reply_slot != 0 {
                    state.release_saved_reply_slot(snapshot.reply_op.reply_slot);
                }
                return;
            }
            PendingOpState::Net { .. } => {
                // Net-class pending op reached the FS completion path:
                // the correlation header's class says FS but the slot
                // was reserved for a netsrv op. Drop with a log; the
                // netsrv dispatch path (future) will pick up the
                // correct completion via its own wire class.
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[VFS] completion dropped: FS class on Net slot\n");
                });
                if snapshot.reply_op.reply_slot != 0 {
                    state.release_saved_reply_slot(snapshot.reply_op.reply_slot);
                }
                return;
            }
            PendingOpState::Empty => {
                if snapshot.reply_op.reply_slot != 0 {
                    state.release_saved_reply_slot(snapshot.reply_op.reply_slot);
                }
                return;
            }
        };
        let live_session_id = state
            .backend_session_slot_index(fs_instance_id)
            .map(|idx| state.backend_sessions[idx].session_id)
            .unwrap_or(0);
        if live_session_id == 0 || live_session_id != header.session {
            // Session retired or reused — credit accounting for the
            // previous generation is moot (the session slot was zeroed
            // on tear-down), so we only need to release the saved
            // reply slot if any.
            if snapshot.reply_op.reply_slot != 0 {
                state.release_saved_reply_slot(snapshot.reply_op.reply_slot);
            }
            broadcast_coalesced_lookup_replies(state, &header, msg, primary_tx);
            return;
        }

        if snapshot.cancelled != 0 {
            // The client disconnected or fileops aborted after the RPC
            // left the wire. If this op had reserved a credit at issue
            // time, release it now that the completion has landed —
            // the backend spent the inflight slot regardless of the
            // client-side cancellation. Ops that never reserved credit
            // (`stat` / `lookup` / `readlink` / `getinfo`) leave the
            // `credited` flag at zero so we don't under-decrement
            // `inflight_now` and allow the session to over-issue. No
            // reply is forwarded — the saved caller cap (if any) was
            // released at cancellation time.
            if snapshot.credited != 0 {
                state.backend_credit_release(fs_instance_id);
            }
            broadcast_coalesced_lookup_replies(state, &header, msg, primary_tx);
            return;
        }

        let (kind, resume_ctx) = match snapshot.op_state {
            PendingOpState::Fs {
                kind, resume_ctx, ..
            } => (kind, resume_ctx),
            PendingOpState::DeferredFs { .. }
            | PendingOpState::Net { .. }
            | PendingOpState::Empty => return,
        };

        // Stale-incarnation is checked FIRST (before the mount-vanished
        // arm below) because a stale reply that arrives during an
        // unmount race should surface as `TRONA_STALE` to the client,
        // not as a generic `TRONA_INVALID_OPERATION`. The backend's
        // `seq` bumped between request issue and completion, meaning
        // the inode the caller thought it held a handle to has since
        // been freed and recycled. Credit is still released so the
        // session's in-flight accounting stays correct.
        if header.flags & trona_protocol::correlation::CORRELATION_F_STALE_INCARNATION != 0 {
            if snapshot.credited != 0 {
                state.backend_credit_release(fs_instance_id);
            }
            if snapshot.reply_op.reply_slot != 0 {
                let mut err_reply = trona_kernel::core_types::core::TronaMsg::zeroed();
                err_reply.label = trona_runtime::core::server_consts::server::TRONA_STALE;
                state.send_saved_reply(snapshot.reply_op.reply_slot, &raw const err_reply);
            }
            broadcast_coalesced_lookup_replies(state, &header, msg, primary_tx);
            return;
        }

        if state.mount_by_fs_instance_id(fs_instance_id).is_none() {
            // Mount disappeared between session gate and here; inform
            // client with a fresh error reply so it unblocks, then
            // return without resuming the fileops state. Credit tied
            // to this session vanished with the session slot, so no
            // release is needed.
            if snapshot.reply_op.reply_slot != 0 {
                let mut err_reply = trona_kernel::core_types::core::TronaMsg::zeroed();
                err_reply.label = uapi::TRONA_INVALID_OPERATION;
                state.send_saved_reply(snapshot.reply_op.reply_slot, &raw const err_reply);
            }
            broadcast_coalesced_lookup_replies(state, &header, msg, primary_tx);
            return;
        }

        let completion = state
            .backend_session_slot_index(fs_instance_id)
            .map(|idx| state.backend_sessions[idx].completion_fn);
        let Some(completion_fn) = completion else {
            if snapshot.reply_op.reply_slot != 0 {
                state.release_saved_reply_slot(snapshot.reply_op.reply_slot);
            }
            broadcast_coalesced_lookup_replies(state, &header, msg, primary_tx);
            return;
        };
        // SAFETY: `completion_fn` was installed at
        // `alloc_backend_session_slot`; owner-loop single-thread
        // discipline keeps `&mut self` uniquely held across the call.
        completion_fn(
            state,
            fs_instance_id,
            tx_id,
            &kind,
            resume_ctx,
            snapshot.reply_op,
            msg,
        );
        broadcast_coalesced_lookup_replies(state, &header, msg, primary_tx);
    }
}

/// Initial `PendingOp` arena capacity. Sized to the expected
/// concurrent-RPC load (one outstanding backend call per active
/// in-flight client op).
pub(crate) const INITIAL_PENDING_OPS: u32 = 128;

impl super::VfsState {
    /// Allocate a fresh [`TxId`]. Monotonic; never reused. Skips past
    /// `INVALID` on the (astronomical) `u64` wraparound.
    pub(crate) fn alloc_tx_id(&mut self) -> TxId {
        let id = self.next_tx_id;
        self.next_tx_id = self.next_tx_id.wrapping_add(1);
        if self.next_tx_id == 0 {
            self.next_tx_id = 1;
        }
        TxId::new(id)
    }

    /// Reserve a `PendingOp` slot. Returns the handle on success,
    /// `None` if the arena is exhausted. Caller populates the slot
    /// before dropping the returned handle.
    pub(crate) fn alloc_pending_op(&mut self) -> Option<PendingOpHandle> {
        self.pending_ops.alloc()
    }

    /// Locate a live `PendingOp` by `TxId`. Linear scan over the
    /// arena; adequate while the concurrent-RPC count stays modest.
    pub(crate) fn find_pending_op(&self, tx_id: TxId) -> Option<PendingOpHandle> {
        if !tx_id.is_valid() {
            return None;
        }
        let mut found: Option<PendingOpHandle> = None;
        self.pending_ops.for_each_active(|h, op| {
            if op.tx_id == tx_id {
                found = Some(h);
                return false;
            }
            true
        });
        found
    }

    /// Reserve a `PendingOp` slot for a backend RPC parked by a VOP.
    /// Populates `tx_id`, `fs_instance_id`, and the opaque `kind`
    /// payload; installs `Resume::Placeholder` which the caller
    /// above the VOP (fileops) is expected to overwrite via
    /// `stamp_resume_ctx` before returning control to the owner
    /// loop. Leaves `reply_op` / `client_badge` unset — fileops
    /// sets those at stamp time along with the resume context.
    pub(crate) fn reserve_fs_pending(
        &mut self,
        fs_instance_id: FsInstanceId,
        kind: PendingKindPayload,
    ) -> Option<(PendingOpHandle, TxId)> {
        let handle = self.alloc_pending_op()?;
        let tx = self.alloc_tx_id();
        let slot = self.pending_ops.get_mut(handle)?;
        slot.tx_id = tx;
        slot.reply_op = OpCore::INVALID;
        slot.op_state = PendingOpState::Fs {
            fs_instance_id,
            kind,
            resume_ctx: Resume::Placeholder,
        };
        slot.cancelled = 0;
        slot.credited = 0;
        slot.coalesce_primary_tx = TxId::INVALID;
        Some((handle, tx))
    }

    /// Reserve a `PendingOp` slot and flag it as having charged one
    /// inflight credit against its owning session, so a subsequent
    /// cancellation releases the credit on the way out. Thin wrapper
    /// over [`reserve_fs_pending`] for the (majority) call sites that
    /// bracket `backend_credit_reserve` / `_release` around the
    /// reservation — `stat` / `lookup` / `readlink` / `getinfo` call
    /// `reserve_fs_pending` directly instead, leaving `credited` at
    /// zero so cancel does not under-decrement `inflight_now`.
    pub(crate) fn reserve_fs_pending_credited(
        &mut self,
        fs_instance_id: FsInstanceId,
        kind: PendingKindPayload,
    ) -> Option<(PendingOpHandle, TxId)> {
        let (handle, tx) = self.reserve_fs_pending(fs_instance_id, kind)?;
        if let Some(slot) = self.pending_ops.get_mut(handle) {
            slot.credited = 1;
        }
        Some((handle, tx))
    }

    /// Overwrite the placeholder `resume_ctx` on a backend `PendingOp`
    /// that a VOP just reserved. Also records `reply_op` +
    /// `client_badge` so `dispatch_pending_reply` can route the reply.
    /// Returns `false` if the handle no longer resolves (slot
    /// recycled) or the state isn't `Fs` — both are bugs on the
    /// fileops caller's side.
    pub(crate) fn stamp_resume_ctx_op(
        &mut self,
        handle: PendingOpHandle,
        client_badge: u64,
        reply_op: OpCore,
        resume_ctx: Resume,
    ) -> bool {
        let Some(slot) = self.pending_ops.get_mut(handle) else {
            return false;
        };
        match slot.op_state {
            PendingOpState::Fs {
                fs_instance_id,
                kind,
                ..
            } => {
                slot.op_state = PendingOpState::Fs {
                    fs_instance_id,
                    kind,
                    resume_ctx,
                };
                slot.client_badge = client_badge;
                slot.reply_op = reply_op;
                true
            }
            PendingOpState::DeferredFs { .. }
            | PendingOpState::Net { .. }
            | PendingOpState::Empty => false,
        }
    }

    pub(crate) fn stamp_resume_ctx(
        &mut self,
        handle: PendingOpHandle,
        client_badge: u64,
        reply_slot: u64,
        resume_ctx: Resume,
    ) -> bool {
        self.stamp_resume_ctx_op(
            handle,
            client_badge,
            OpCore {
                request_id: 0,
                reply_slot,
                kind: OpKind::FsAsync,
            },
            resume_ctx,
        )
    }

    /// Reserve a `PendingOp` slot for a parked netsrv RPC. The net-class
    /// pending state captures the netsrv generation at reservation time
    /// so the callback-arrival gate can drop replies stamped with a
    /// pre-re-registration generation. Resume sites stamp a proper
    /// `Resume::Net(NetResume { .. })` via [`stamp_net_resume_ctx`]
    /// before returning control to the owner loop.
    pub(crate) fn reserve_net_pending(
        &mut self,
        conn_id: u32,
        op_type: u8,
    ) -> Option<(PendingOpHandle, TxId)> {
        let handle = self.alloc_pending_op()?;
        let tx = self.alloc_tx_id();
        let slot = self.pending_ops.get_mut(handle)?;
        slot.tx_id = tx;
        slot.reply_op = OpCore::INVALID;
        slot.op_state = PendingOpState::Net {
            netsrv_gen: self.next_netsrv_gen,
            conn_id,
            op_type,
            resume_ctx: Resume::Placeholder,
        };
        slot.cancelled = 0;
        slot.credited = 0;
        slot.coalesce_primary_tx = TxId::INVALID;
        Some((handle, tx))
    }

    /// Overwrite the placeholder `resume_ctx` on a netsrv `PendingOp`.
    /// Mirrors [`stamp_resume_ctx`] for the net-class slot. Returns
    /// `false` if the slot no longer resolves or the state is not
    /// `Net` — both indicate a caller bug.
    pub(crate) fn stamp_net_resume_ctx_op(
        &mut self,
        handle: PendingOpHandle,
        client_badge: u64,
        reply_op: OpCore,
        resume_ctx: Resume,
    ) -> bool {
        let Some(slot) = self.pending_ops.get_mut(handle) else {
            return false;
        };
        match slot.op_state {
            PendingOpState::Net {
                netsrv_gen,
                conn_id,
                op_type,
                ..
            } => {
                slot.op_state = PendingOpState::Net {
                    netsrv_gen,
                    conn_id,
                    op_type,
                    resume_ctx,
                };
                slot.client_badge = client_badge;
                slot.reply_op = reply_op;
                true
            }
            PendingOpState::DeferredFs { .. }
            | PendingOpState::Fs { .. }
            | PendingOpState::Empty => false,
        }
    }

    pub(crate) fn reserve_deferred_fs_pending(
        &mut self,
        fs_instance_id: FsInstanceId,
        session_id: u32,
        session_gen: u32,
        client_badge: u64,
        reply_op: OpCore,
        kind: PendingKindPayload,
        resume_ctx: Resume,
        target_seq: u32,
    ) -> Option<PendingOpHandle> {
        let handle = self.alloc_pending_op()?;
        let slot = self.pending_ops.get_mut(handle)?;
        slot.tx_id = TxId::INVALID;
        slot.client_badge = client_badge;
        slot.reply_op = reply_op;
        slot.op_state = PendingOpState::DeferredFs {
            fs_instance_id,
            session_id,
            session_gen,
            kind,
            resume_ctx,
            target_seq,
        };
        slot.cancelled = 0;
        slot.credited = 0;
        slot.coalesce_primary_tx = TxId::INVALID;
        Some(handle)
    }

    pub(crate) fn mark_lookup_coalesced_secondary(
        &mut self,
        handle: PendingOpHandle,
        primary_tx: TxId,
    ) -> bool {
        if !primary_tx.is_valid() {
            return false;
        }
        let Some(slot) = self.pending_ops.get_mut(handle) else {
            return false;
        };
        slot.coalesce_primary_tx = primary_tx;
        true
    }

    pub(crate) fn stamp_net_resume_ctx(
        &mut self,
        handle: PendingOpHandle,
        client_badge: u64,
        reply_slot: u64,
        resume_ctx: Resume,
    ) -> bool {
        self.stamp_net_resume_ctx_op(
            handle,
            client_badge,
            OpCore {
                request_id: 0,
                reply_slot,
                kind: OpKind::NetAsync,
            },
            resume_ctx,
        )
    }

    pub(crate) fn arm_pending_fs_reply_for_client(
        &mut self,
        handle: PendingOpHandle,
        client: ClientHandle,
        resume_ctx: Resume,
    ) -> Result<(), BeginOpError> {
        let badge = self.clients.get(client).map(|c| c.badge).unwrap_or(0);
        let reply_op = match self.begin_op_for_badge(badge, OpKind::FsAsync) {
            Ok(op) => op,
            Err(err) => {
                self.cancel_pending_op(handle);
                return Err(err);
            }
        };
        if !self.stamp_resume_ctx_op(handle, badge, reply_op, resume_ctx) {
            self.cancel_op(reply_op);
            self.cancel_pending_op(handle);
            return Err(BeginOpError::InvalidOperation);
        }
        Ok(())
    }
}

/// Construct a fresh `Arena<PendingOp>` sized for initial use. Kept
/// here so `VfsState::new` does not need to know the capacity.
pub(crate) fn new_pending_arena() -> Option<Arena<PendingOp>> {
    Arena::new(INITIAL_PENDING_OPS)
}
