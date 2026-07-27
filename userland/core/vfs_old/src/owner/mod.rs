// SPDX-License-Identifier: GPL-2.0-only
//! `VfsState` — the single owner of all mutable VFS state.
//!
//! Every `static mut` global from the old `server/state.rs` is absorbed
//! into this struct. The VFS main loop holds the sole `&mut VfsState`
//! reference. Workers never touch it.

pub(crate) mod deferred;
pub(crate) mod dispatch;
pub(crate) mod loop_;
pub(crate) mod op;
pub(crate) mod pending;
pub(crate) mod reclaim;
pub(crate) mod resume;
pub(crate) mod session;
pub(crate) mod worker;

use crate::arena::{Arena, BadgeMap};
use crate::personality::posix::consts::*;
use crate::personality::posix::types::*;
use crate::server::consts::*;
use crate::server::open_object::{OpenObject, OpenObjectHandle};
use crate::server::types::*;
use crate::vfs_core::identity::FsInstanceId;
use crate::vfs_core::mount::Mount;
use crate::vfs_core::mount_ns::MountNamespace;
use crate::vfs_core::vnode::Vnode;

use crate::vfs_core::mount::MountHandle;
use crate::vfs_core::mount_ns::MountNsHandle;
use crate::vfs_core::vnode::VnodeHandle;

use crate::owner::op::OpCore;
use deferred::DeferredIssue;
pub(crate) use session::DeferArgs;
use session::{
    BackendSessionSlot, CompletionFn, DrainFn, MAX_BACKEND_SESSIONS, PushFn, no_op_completion,
    no_op_drain, no_op_push,
};

use trona_kernel::core_types::TronaMsg;
use uapi::CAP_SELF_CSPACE;

// =========================================================================
// VfsState
// =========================================================================

/// All mutable VFS state, owned exclusively by the main loop.
///
/// Replaces every `static mut` global from the old pool-based architecture.
/// No global mutable statics remain after this struct is introduced.
pub(crate) struct VfsState {
    // -----------------------------------------------------------------
    // Core arenas
    // -----------------------------------------------------------------
    pub(crate) vnodes: Arena<Vnode>,
    pub(crate) mounts: Arena<Mount>,
    pub(crate) clients: Arena<ClientState>,
    pub(crate) mount_ns: Arena<MountNamespace>,

    // -----------------------------------------------------------------
    // Subsystem arenas (were global pools)
    // -----------------------------------------------------------------
    pub(crate) sockets: Arena<SocketState>,
    pub(crate) pipes: Arena<PipeState>,
    pub(crate) poll_waiters: Arena<PollWaiter>,
    pub(crate) epolls: Arena<EpollInstance>,
    pub(crate) shm_data: Arena<ShmData>,
    /// Open-object arena — one entry per live open instance. Referenced
    /// from `ClientState.slots[*].open_object`. Personality-neutral:
    /// POSIX's dup-sharing and Win32's `DuplicateHandle` both layer on
    /// top of this arena. In commit 1 each slot owns a dedicated
    /// `OpenObject` (refcount = 1); commit 2 introduces sharing across
    /// duplicated slots.
    pub(crate) open_objects: Arena<OpenObject>,

    // -----------------------------------------------------------------
    // Mount tree
    // -----------------------------------------------------------------
    /// Root mount of the VFS namespace. Set during bootstrap.
    pub(crate) root_mount: MountHandle,
    /// Default mount namespace shared by all processes.
    pub(crate) global_ns: MountNsHandle,

    // -----------------------------------------------------------------
    // Client lookup
    // -----------------------------------------------------------------
    /// O(1) badge → ClientHandle hash map.
    pub(crate) badge_map: BadgeMap,

    // -----------------------------------------------------------------
    // Worker dispatch — the submit / completion rings are module-level
    // `static mut` in `crate::owner::worker` because they cross the
    // owner↔worker thread boundary. `VfsState` itself carries no
    // worker-ring fields.
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // ID counters
    // -----------------------------------------------------------------
    pub(crate) next_sock_id: u32,
    /// Monotonic `FsInstanceId` allocator. Assigned to every `Mount`
    /// created via `mount_ctl::do_mount` (including the bind-mount
    /// paths in `boot/pivot_root.rs`). Starts at 1 so `FsInstanceId(0)`
    /// continues to serve as the zero-initialised `INVALID` sentinel.
    /// Never reused — `Arena<Mount>` slot recycling is not observed by
    /// structural references (see `vfs_core::identity`).
    pub(crate) next_fs_instance_id: u64,
    /// Monotonic `TxId` allocator for async backend RPCs. Starts at 1
    /// so `TxId(0)` serves as the `INVALID` sentinel. Never reused —
    /// wraps past zero on the (astronomical) `u64` overflow.
    pub(crate) next_tx_id: u64,

    // -----------------------------------------------------------------
    // Pending backend RPCs
    // -----------------------------------------------------------------
    /// Live `PendingOp` entries — one per outstanding async backend
    /// RPC. Populated when the owner fires `send_ctx` to a backend
    /// and drained when the matching reply arrives on the multi-
    /// endpoint receive path. See [`pending`].
    pub(crate) pending_ops: Arena<pending::PendingOp>,

    // -----------------------------------------------------------------
    // Per-backend session table (inflight credit + deferred-issue ring)
    // -----------------------------------------------------------------
    /// Per-backend session slots. One entry per live async-capable
    /// mount. Fixed-size array keyed by slot
    /// index; lookup from `FsInstanceId` is a linear scan. Generation
    /// counter on each slot distinguishes an abandoned stale
    /// completion from a fresh session that happens to reuse the
    /// same slot index. See [`session`].
    pub(crate) backend_sessions: [BackendSessionSlot; MAX_BACKEND_SESSIONS],
    /// netsrv async callback table — moved off `static mut` onto owner
    /// state. Each entry tracks an in-flight `NET_*` operation whose
    /// reply arrives on the backend callback EP. See
    /// [`crate::personality::posix::inet`].
    // `inet_pending` field retired: net-class parks now flow through
    // the unified `pending_ops` arena as `PendingOpState::Net`. The
    // inet callback helpers `alloc_pending` / `find_pending` /
    // `clear_pending_badge` / `dump_pending_inet` sit on top of that
    // arena directly.
    /// `true` once the VFS owner has registered its callback EP with
    /// netsrv. Moved off `static mut`.
    pub(crate) netsrv_callback_registered: bool,
    /// Monotonic generation for netsrv re-registrations. Bumped each
    /// time `ensure_inet_callback_registered` successfully round-trips
    /// `NET_REGISTER_VFS`. Used by a future netsrv wire migration to
    /// drop stale callbacks whose generation predates a netsrv
    /// restart. Never reused within a VFS process lifetime. Zero is
    /// reserved for "no registration yet".
    pub(crate) next_netsrv_gen: u32,
    /// `true` once `prepare_backend_callback_endpoint` has minted the
    /// shared backend callback cap (the one saltyfs / netsrv / mmsrv
    /// push correlated completions to). Moved off the former
    /// `backend::callback::BACKEND_CALLBACK_EP_PREPARED` static so
    /// backend bootstrap flags all live on owner state.
    pub(crate) backend_callback_prepared: bool,
    /// `true` once the VFS owner has registered its pager callback
    /// endpoint with mmsrv. Moved off the former
    /// `backend::pager::MMSRV_PAGER_CALLBACK_REGISTERED` static.
    pub(crate) mmsrv_pager_registered: bool,
    /// Rate-limit counters for the inet callback path — moved off the
    /// former `LOGGED_INET_*` statics in
    /// `personality::posix::inet::callback`. Each counter saturates at
    /// a small cap so log flooding on repeated errors stays bounded
    /// without a separate suppression helper.
    pub(crate) logged_inet_ops: u8,
    pub(crate) logged_inet_callbacks: u8,
    pub(crate) logged_inet_recv_results: u8,
    /// Monotonic per-process session id allocator. Stamped on every
    /// successful [`alloc_backend_session_slot`] call and echoed
    /// back by the backend on every completion via
    /// [`trona_protocol::correlation::CorrelationHeader::session`]. Never
    /// reused across process lifetime — a completion carrying a
    /// `session` id that does not match a live
    /// [`BackendSessionSlot::session_id`] is dropped with a log.
    /// Starts at 1 so 0 serves as the `INVALID` sentinel.
    pub(crate) next_session_id: u32,

    // -----------------------------------------------------------------
    // Identity-keyed lookup tables
    // -----------------------------------------------------------------
    /// `(FsInstanceId, BackendNodeId) → VnodeHandle` resolve cache. Populated
    /// on successful identity-based lookup; a miss walks the mount's
    /// `vget` to re-materialise the vnode and installs the new handle.
    /// Direct-mapped on the backend node id hash; entries with a stale
    /// handle (arena epoch mismatch) are overwritten on the next install.
    /// Lookup of `FsInstanceId → MountHandle` is served by linear scan of
    /// the `Arena<Mount>` matching on `Mount::fs_instance_id`, which is
    /// adequate while the arena holds < 32 live mounts.
    pub(crate) vnode_resolve_cache: [crate::vfs_core::identity::VnodeResolveCacheEntry;
        crate::vfs_core::identity::VNODE_RESOLVE_CACHE_CAP],

    // -----------------------------------------------------------------
    // Deferred reply slot allocator
    // -----------------------------------------------------------------
    pub(crate) reply_slot_free: [u64; REPLY_SLOT_COUNT],
    pub(crate) reply_slot_free_len: usize,
    pub(crate) reply_slot_in_use: [u8; REPLY_SLOT_COUNT],
    pub(crate) reply_slot_owner_badges: [u64; REPLY_SLOT_COUNT],

    // -----------------------------------------------------------------
    // PTY pending readers
    // -----------------------------------------------------------------
    pub(crate) pty_pending: [[PtyPendingReader; MAX_PTY_WAITERS]; MAX_PTYS],
    pub(crate) pty_pending_count: [usize; MAX_PTYS],

    // -----------------------------------------------------------------
    // Urandom CSPRNG state
    // -----------------------------------------------------------------
    pub(crate) urandom_key: [u8; 32],
    pub(crate) urandom_ctr: u64,
    pub(crate) urandom_buf: [u8; 64],
    pub(crate) urandom_buf_pos: usize,
    pub(crate) urandom_counter: u64,

    // -----------------------------------------------------------------
    // Framebuffer info
    // -----------------------------------------------------------------
    pub(crate) fb_width: u32,
    pub(crate) fb_height: u32,
    pub(crate) fb_pitch: u32,
    pub(crate) fb_bpp: u8,
    pub(crate) fb_red_pos: u8,
    pub(crate) fb_red_size: u8,
    pub(crate) fb_green_pos: u8,
    pub(crate) fb_green_size: u8,
    pub(crate) fb_blue_pos: u8,
    pub(crate) fb_blue_size: u8,

    // -----------------------------------------------------------------
    // Misc
    // -----------------------------------------------------------------
    /// Procfs root inode id.
    pub(crate) proc_root_ino: u32,
    /// Dispatch cycle counter (for periodic sweep).
    pub(crate) dispatch_count: u64,

    // -----------------------------------------------------------------
    // Receive slot tracking
    // -----------------------------------------------------------------
    pub(crate) current_recv_slot: u64,
    pub(crate) worker_recv_slots: [u64; MAX_VFS_WORKERS],
    pub(crate) worker_recv_slot_count: usize,

    // -----------------------------------------------------------------
    // Boot / late-mount sidecars
    // -----------------------------------------------------------------
    /// Owner-loop state for the async late-pivot scaffold builder.
    pub(crate) late_pivot: crate::boot::late_mount::LatePivotState,

    // -----------------------------------------------------------------
    // Personality sidecars
    // -----------------------------------------------------------------
    /// Win32 personality per-client current drive + per-drive CWD
    /// sidecar. Keyed by [`ClientHandle`]. POSIX clients never
    /// touch this table; Win32 clients register on spawn and
    /// deregister on exit.
    pub(crate) win32_cwd: crate::personality::win32::cwd_table::Win32CwdTable,
}

const MAX_VFS_WORKERS: usize = 32;
const REPLY_SLOT_COUNT: usize = (CAP_REPLY_LIMIT - CAP_REPLY_BASE) as usize;

#[inline]
fn reply_slot_index(slot: u64) -> Option<usize> {
    if !(CAP_REPLY_BASE..CAP_REPLY_LIMIT).contains(&slot) {
        return None;
    }
    Some((slot - CAP_REPLY_BASE) as usize)
}

impl VfsState {
    /// Create and initialize a new VfsState. Allocates all arenas.
    /// Returns `None` if any arena allocation fails.
    pub(crate) fn new() -> Option<Self> {
        let mut reply_slot_free = [0u64; REPLY_SLOT_COUNT];
        let mut i = 0usize;
        while i < REPLY_SLOT_COUNT {
            reply_slot_free[i] = (CAP_REPLY_LIMIT - 1).saturating_sub(i as u64);
            i += 1;
        }

        Some(VfsState {
            vnodes: Arena::new(256)?,
            mounts: Arena::new(16)?,
            clients: Arena::new(INITIAL_CLIENTS as u32)?,
            mount_ns: Arena::new(8)?,

            sockets: Arena::new(INITIAL_SOCKETS as u32)?,
            pipes: Arena::new(INITIAL_PIPES as u32)?,
            poll_waiters: Arena::new(INITIAL_POLL_WAITERS as u32)?,
            epolls: Arena::new(INITIAL_EPOLLS as u32)?,
            shm_data: Arena::new(INITIAL_SHM as u32)?,
            open_objects: Arena::new(INITIAL_CLIENTS as u32 * 8)?,

            root_mount: MountHandle::INVALID,
            global_ns: MountNsHandle::INVALID,

            badge_map: BadgeMap::new(256)?,

            next_sock_id: 1,
            next_fs_instance_id: 1,
            next_tx_id: 1,
            pending_ops: pending::new_pending_arena()?,

            backend_sessions: [BackendSessionSlot::zeroed(); MAX_BACKEND_SESSIONS],
            // `inet_pending` field retired: net-class parks now flow
            // through `pending_ops` with `PendingOpState::Net`.
            netsrv_callback_registered: false,
            next_netsrv_gen: 0,
            backend_callback_prepared: false,
            mmsrv_pager_registered: false,
            logged_inet_ops: 0,
            logged_inet_callbacks: 0,
            logged_inet_recv_results: 0,
            next_session_id: 1,

            vnode_resolve_cache: [crate::vfs_core::identity::VnodeResolveCacheEntry::EMPTY;
                crate::vfs_core::identity::VNODE_RESOLVE_CACHE_CAP],

            reply_slot_free,
            reply_slot_free_len: REPLY_SLOT_COUNT,
            reply_slot_in_use: [0; REPLY_SLOT_COUNT],
            reply_slot_owner_badges: [0; REPLY_SLOT_COUNT],

            pty_pending: [[PtyPendingReader::zeroed(); MAX_PTY_WAITERS]; MAX_PTYS],
            pty_pending_count: [0; MAX_PTYS],

            urandom_key: [0; 32],
            urandom_ctr: 0,
            urandom_buf: [0; 64],
            urandom_buf_pos: 64,
            urandom_counter: 0,

            fb_width: 0,
            fb_height: 0,
            fb_pitch: 0,
            fb_bpp: 0,
            fb_red_pos: 0,
            fb_red_size: 0,
            fb_green_pos: 0,
            fb_green_size: 0,
            fb_blue_pos: 0,
            fb_blue_size: 0,

            proc_root_ino: 0,
            dispatch_count: 0,

            current_recv_slot: 0,
            worker_recv_slots: [0; MAX_VFS_WORKERS],
            worker_recv_slot_count: 1,

            late_pivot: crate::boot::late_mount::LatePivotState::zeroed(),

            win32_cwd: crate::personality::win32::cwd_table::Win32CwdTable::zeroed(),
        })
    }

    /// Allocate a fresh `FsInstanceId`. Monotonic; never reused.
    /// Panic-free wraparound — in practice `u64` does not exhaust.
    pub(crate) fn alloc_fs_instance_id(&mut self) -> crate::vfs_core::identity::FsInstanceId {
        let id = self.next_fs_instance_id;
        self.next_fs_instance_id = self.next_fs_instance_id.wrapping_add(1);
        if self.next_fs_instance_id == 0 {
            // Skip back past the INVALID sentinel on the (astronomical)
            // wraparound to preserve the zero-is-invalid invariant.
            self.next_fs_instance_id = 1;
        }
        crate::vfs_core::identity::FsInstanceId::new(id)
    }

    /// Allocate a fresh monotonic session id. Zero is never produced
    /// so it remains the `INVALID` sentinel; on (astronomical) `u32`
    /// wraparound the counter skips back to 1.
    pub(crate) fn alloc_session_id(&mut self) -> u32 {
        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);
        if self.next_session_id == 0 {
            self.next_session_id = 1;
        }
        id
    }

    /// Claim a free `BackendSessionSlot` for a newly mounted async
    /// backend. Stamps the slot with `fs_id`, the backend's
    /// advertised `session_id` (or a local fallback when the backend
    /// returns zero), the backend's advertised `inflight_max`, and
    /// the backend's `drain_fn` / `push_fn` / `completion_fn`
    /// callbacks (or `no_op_*` if the backend does not park
    /// requests / does not produce correlated completions). Returns
    /// the stored `session_id` on success, `None` when the table is
    /// full (all [`MAX_BACKEND_SESSIONS`] slots occupied) or a slot
    /// for `fs_id` is already live.
    pub(crate) fn alloc_backend_session_slot(
        &mut self,
        fs_id: FsInstanceId,
        advertised_session_id: u32,
        inflight_max: u16,
        drain_fn: DrainFn,
        push_fn: PushFn,
        completion_fn: CompletionFn,
        readdir_eof_fn: crate::owner::session::ReaddirEofFn,
    ) -> Option<u32> {
        if !fs_id.is_valid() {
            return None;
        }
        if self.backend_session_slot_index(fs_id).is_some() {
            return None;
        }
        let session_id = if advertised_session_id != 0 {
            advertised_session_id
        } else {
            self.alloc_session_id()
        };
        let live_gen = self.alloc_session_id();
        let mut i = 0usize;
        while i < MAX_BACKEND_SESSIONS {
            if !self.backend_sessions[i].is_live() {
                let slot = &mut self.backend_sessions[i];
                *slot = BackendSessionSlot::zeroed();
                slot.live_gen = live_gen;
                slot.session_id = session_id;
                slot.fs_instance_id = fs_id;
                slot.inflight_max = inflight_max;
                slot.inflight_now = 0;
                slot.drain_fn = drain_fn;
                slot.push_fn = push_fn;
                slot.completion_fn = completion_fn;
                slot.readdir_eof_fn = readdir_eof_fn;
                return Some(session_id);
            }
            i += 1;
        }
        None
    }

    /// Dispatch a deferred-issue push through the session's
    /// registered `push_fn`. Invoked by the generic fileops path
    /// when credit is exhausted; the backend-specific callback
    /// builds a `DeferredIssue` and pushes it onto the waiter
    /// ring. Returns `true` when the request was successfully
    /// parked; `false` when the session is unknown, the ring is
    /// full, or the backend does not support parking.
    pub(crate) fn session_defer_push(
        &mut self,
        fs_id: FsInstanceId,
        args: DeferArgs,
        client_badge: u64,
        reply_op: OpCore,
    ) -> bool {
        let push = {
            let Some(idx) = self.backend_session_slot_index(fs_id) else {
                return false;
            };
            self.backend_sessions[idx].push_fn
        };
        // SAFETY: `push_fn` was installed at
        // `alloc_backend_session_slot` and the owner-loop guarantees
        // single-threaded ownership of `&mut self` across the call.
        unsafe { push(self, fs_id, args, client_badge, reply_op) }
    }

    /// Linear-scan lookup: find the `backend_sessions` slot index
    /// whose `fs_instance_id` matches. Returns `None` if no live
    /// slot carries the id.
    #[inline]
    pub(crate) fn backend_session_slot_index(&self, fs_id: FsInstanceId) -> Option<usize> {
        if !fs_id.is_valid() {
            return None;
        }
        let mut i = 0usize;
        while i < MAX_BACKEND_SESSIONS {
            let slot = &self.backend_sessions[i];
            if slot.is_live() && slot.fs_instance_id == fs_id {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Reserve one inflight credit against the session bound to
    /// `fs_id`. Returns `true` when credit was available and
    /// `inflight_now` was incremented; returns `false` when the
    /// session is unknown or the cap is already reached. Callers
    /// that observe `false` must park via the deferred-issue queue
    /// instead of issuing the backend RPC.
    pub(crate) fn backend_credit_reserve(&mut self, fs_id: FsInstanceId) -> bool {
        let Some(idx) = self.backend_session_slot_index(fs_id) else {
            return false;
        };
        let slot = &mut self.backend_sessions[idx];
        if slot.credit_exhausted() {
            return false;
        }
        slot.inflight_now = slot.inflight_now.saturating_add(1);
        true
    }

    /// Probe whether a credit reservation would succeed on the
    /// session bound to `fs_id` without taking the credit. Used by
    /// the fileops layer to decide between issuing and parking
    /// *before* building the request, so a parked issue never
    /// allocates a pending slot it won't need.
    #[inline]
    pub(crate) fn backend_credit_available(&self, fs_id: FsInstanceId) -> bool {
        let Some(idx) = self.backend_session_slot_index(fs_id) else {
            return false;
        };
        !self.backend_sessions[idx].credit_exhausted()
    }

    /// Release one inflight credit back to the session bound to
    /// `fs_id` and invoke the session's registered `drain_fn` so
    /// any parked waiters observe the newly-available slot without
    /// a backend-specific call in the generic fileops path. No-op
    /// when the session is unknown or `inflight_now` is already
    /// zero — keeping the count saturating at zero means a
    /// spurious double-release cannot corrupt the cap invariant.
    pub(crate) fn backend_credit_release(&mut self, fs_id: FsInstanceId) {
        let drain = {
            let Some(idx) = self.backend_session_slot_index(fs_id) else {
                return;
            };
            let slot = &mut self.backend_sessions[idx];
            slot.inflight_now = slot.inflight_now.saturating_sub(1);
            slot.drain_fn
        };
        // SAFETY: `drain_fn` was installed by the backend at
        // `alloc_backend_session_slot`; owner-loop single-thread
        // discipline keeps `&mut self` uniquely held across the
        // callback.
        unsafe {
            drain(self, fs_id);
        }
    }

    /// Release one inflight credit **without** invoking the
    /// session's drain hook. Used by the drain hook itself during
    /// promotion-failure unwind, where a nested call to
    /// [`Self::backend_credit_release`] would re-enter the same
    /// drain loop that is already in progress — deepening the
    /// stack frame by one level per failed promotion. The outer
    /// drain loop observes the credit that this call freed on its
    /// next iteration, preserving the flat FIFO semantics every
    /// waiter relies on.
    pub(crate) fn backend_credit_release_no_drain(&mut self, fs_id: FsInstanceId) {
        let Some(idx) = self.backend_session_slot_index(fs_id) else {
            return;
        };
        let slot = &mut self.backend_sessions[idx];
        slot.inflight_now = slot.inflight_now.saturating_sub(1);
    }

    /// Tear down the session bound to `fs_id` on unmount or backend
    /// crash detection. Zeroes the slot so subsequent completions
    /// carrying the torn-down `session_id` fail the lookup and are
    /// dropped. Does **not** drain the waiter ring — callers that
    /// need to synthesise `SessionTornDown` completions for parked
    /// waiters must do so via the deferred arena before calling
    /// this.
    ///
    /// Stale-completion detection relies on the monotonic
    /// `session_id` allocated by [`alloc_backend_session_slot`];
    /// a reply whose `CorrelationHeader.session` does not match any
    /// live slot's `session_id` is dropped, even if the slot index
    /// has since been reused by a fresh mount.
    /// Tear down the session bound to `fs_id`. In order:
    /// 1. Synthesise `SessionTornDown` failure replies for every
    ///    in-flight `PendingOp` scoped to `fs_id`, releasing each
    ///    op's saved caller cap so the client unblocks with
    ///    `TRONA_NOT_CONNECTED` instead of hanging.
    /// 2. Drain the session's waiter ring — every parked
    ///    `DeferredIssue` likewise gets a synthesised error reply.
    /// 3. Evict every resolve-cache entry whose `VnodeKey` names the
    ///    torn-down `fs_id` so a future lookup cannot surface a
    ///    handle into a dead mount.
    /// 4. Zero the session slot — subsequent completions echoing
    ///    the old `session_id` are dropped at the session gate.
    ///
    /// Callers: saltyfs `unmount` (graceful), and the (future)
    /// counterparty-revocation detector that observes the backend's
    /// process cap go away.
    pub(crate) fn free_backend_session_slot(&mut self, fs_id: FsInstanceId) {
        self.cancel_pending_ops_for_session(fs_id);
        self.drain_deferred_issues_for_session(fs_id);
        self.invalidate_resolve_cache_by_fs_id(fs_id);
        let Some(idx) = self.backend_session_slot_index(fs_id) else {
            return;
        };
        // Release the revocation watcher's reply slot (if armed) so
        // the saved caller cap is reclaimed before the slot zeroes.
        let revocation_slot = self.backend_sessions[idx].revocation_slot;
        if revocation_slot != 0 {
            self.release_reply_slot(revocation_slot);
        }
        self.backend_sessions[idx] = BackendSessionSlot::zeroed();
    }

    /// Attach the backend's callback endpoint cap to the session
    /// slot. Used by the future revocation detector to correlate a
    /// kernel cap-loss notification back to a session. Idempotent.
    /// No-op when the session slot is not live.
    pub(crate) fn set_backend_callback_ep(&mut self, fs_id: FsInstanceId, cap: u64) {
        if let Some(idx) = self.backend_session_slot_index(fs_id) {
            if self.backend_sessions[idx].is_live() {
                self.backend_sessions[idx].callback_ep = cap;
            }
        }
    }

    /// Reactive revocation-detector entry point. Call this with the
    /// raw `trona_kernel::ipc::send_ctx` error code produced by a backend
    /// RPC send. Non-zero terminal errors (cap revoked, remote TCB
    /// gone) trigger a full session teardown — every in-flight
    /// `PendingOp` scoped to `fs_id` is cancelled with
    /// `TRONA_NOT_CONNECTED`, waiters are drained, and the session
    /// slot is zeroed so subsequent ops fail fast. Transient errors
    /// like `TRONA_PENDING` do not trigger teardown.
    ///
    /// Returns the original `send_err` unchanged so call sites can
    /// drive their own error handling in addition to the teardown.
    ///
    /// This is the userspace-side "revocation detector" — a kernel
    /// cap-revocation notification channel would let us detect loss
    /// proactively; until that lands, every outbound backend RPC is
    /// the detection point.
    pub(crate) fn observe_backend_send(&mut self, fs_id: FsInstanceId, send_err: i32) -> i32 {
        if send_err == 0 || send_err as u64 == uapi::TRONA_PENDING {
            return send_err;
        }
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[VFS] backend RPC send failed fs=");
            _lb.dec(fs_id.raw());
            _lb.str(b" err=");
            _lb.dec(send_err as u64);
            _lb.str(b" - tearing down session\n");
        });
        self.free_backend_session_slot(fs_id);
        send_err
    }

    /// Arm the revocation watcher for `fs_id` by stashing a saved
    /// reply slot that the future detector will consume when the
    /// backend's session cap is revoked. Returns `true` when the
    /// slot was installed, `false` when the session is not live.
    #[allow(dead_code)]
    pub(crate) fn set_backend_revocation_slot(
        &mut self,
        fs_id: FsInstanceId,
        reply_slot: u64,
    ) -> bool {
        match self.backend_session_slot_index(fs_id) {
            Some(idx) if self.backend_sessions[idx].is_live() => {
                self.backend_sessions[idx].revocation_slot = reply_slot;
                true
            }
            _ => false,
        }
    }

    /// Synthesise `TRONA_NOT_CONNECTED` replies for every live
    /// `PendingOp` whose opaque state is scoped to `fs_id`, then
    /// release each op's pending-arena slot. Reply slots tied to
    /// each op are also released so the client's saved caller cap
    /// is freed. No-op for sessions that hold no in-flight ops.
    pub(crate) fn cancel_pending_ops_for_session(&mut self, fs_id: FsInstanceId) {
        use crate::owner::pending::{PendingOpHandle, PendingOpState};
        // Collect victim handles first — the arena's
        // `for_each_active_mut` gives a mutable slot reference but
        // we need to release the slot after synthesising the reply,
        // which re-enters the arena via `pending_ops.release`.
        const MAX_VICTIMS: usize = 256;
        let mut victims: [PendingOpHandle; MAX_VICTIMS] = [PendingOpHandle::INVALID; MAX_VICTIMS];
        let mut count = 0usize;
        self.pending_ops.for_each_active(|h, op| {
            if count >= MAX_VICTIMS {
                return false;
            }
            if let PendingOpState::Fs { fs_instance_id, .. } = op.op_state {
                if fs_instance_id == fs_id {
                    victims[count] = h;
                    count += 1;
                }
            }
            true
        });
        for i in 0..count {
            let handle = victims[i];
            let (reply_op, credited) = match self.pending_ops.get(handle) {
                Some(op) => (op.reply_op, op.credited != 0),
                None => continue,
            };
            if reply_op.reply_slot != 0 {
                let mut out = trona_kernel::core_types::core::TronaMsg::zeroed();
                // Route through the typed error so wire label + future
                // personality-side extension (structured audit fields)
                // share one code path. `to_trona()` yields
                // `TRONA_NOT_CONNECTED` — bit-identical to the prior
                // raw constant but anchored on the error surface.
                out.label = crate::vfs_core::error::VfsError::SessionTornDown.to_trona();
                out.length = 1;
                unsafe {
                    self.send_saved_reply(reply_op.reply_slot, &raw const out);
                }
            }
            if credited {
                self.backend_credit_release_no_drain(fs_id);
            }
            let _ = self.pending_ops.release(handle);
        }
    }

    /// Drain every parked `DeferredIssue` on the session's waiter
    /// ring and synthesise a `SessionTornDown` reply for each.
    /// Companion to [`cancel_pending_ops_for_session`] — ops that
    /// never left `VfsState` also need their saved caller caps
    /// released.
    pub(crate) fn drain_deferred_issues_for_session(&mut self, fs_id: FsInstanceId) {
        while let Some((h, snapshot)) = self.pop_deferred_issue(fs_id) {
            self.release_deferred_issue(h);
            if snapshot.reply_op.reply_slot != 0 {
                let mut out = trona_kernel::core_types::core::TronaMsg::zeroed();
                out.label = crate::vfs_core::error::VfsError::SessionTornDown.to_trona();
                out.length = 1;
                unsafe {
                    self.send_saved_reply(snapshot.reply_op.reply_slot, &raw const out);
                }
            }
        }
    }

    /// Evict every resolve-cache entry whose `VnodeKey` is scoped to
    /// `fs_id`. Linear sweep over the 128-slot direct-mapped cache;
    /// cheap compared to the cost of stale lookups surfacing a
    /// handle into a torn-down mount.
    pub(crate) fn invalidate_resolve_cache_by_fs_id(&mut self, fs_id: FsInstanceId) {
        for entry in self.vnode_resolve_cache.iter_mut() {
            if entry.key.fs_instance_id == fs_id {
                *entry = crate::vfs_core::identity::VnodeResolveCacheEntry::EMPTY;
            }
        }
    }

    /// Invoke the backend's registered `readdir_eof_fn` hook for the
    /// session bound to `fs_id`. Generic `fileops::dir` helpers call
    /// this on EOF completion to let the backend clean up any
    /// session-scoped readdir SHM ownership it may be holding.
    /// Falls back to a no-op when the session has already torn down.
    pub(crate) fn session_readdir_eof(
        &mut self,
        fs_id: FsInstanceId,
        open_handle: crate::server::open_object::OpenObjectHandle,
    ) {
        let hook = {
            let Some(idx) = self.backend_session_slot_index(fs_id) else {
                return;
            };
            self.backend_sessions[idx].readdir_eof_fn
        };
        // SAFETY: hook installed at mount time; owner-loop single-
        // thread discipline keeps `&mut self` uniquely held across
        // the callback.
        unsafe {
            hook(self, fs_id, open_handle);
        }
    }

    /// Push a deferred issue onto the waiter ring of the session
    /// bound to `fs_id`. Returns the arena handle on success;
    /// returns `None` when the session is unknown, its ring is
    /// full, or the arena is exhausted. Callers that observe `None`
    /// must surface `TRONA_AGAIN` (or the personality's equivalent)
    /// to the client instead of parking.
    pub(crate) fn push_deferred_issue(
        &mut self,
        fs_id: FsInstanceId,
        issue: DeferredIssue,
    ) -> Option<pending::PendingOpHandle> {
        let idx = self.backend_session_slot_index(fs_id)?;
        if self.backend_sessions[idx].wait_q_full() {
            return None;
        }
        let handle = self.reserve_deferred_fs_pending(
            fs_id,
            issue.session_id,
            issue.session_gen,
            issue.client_badge,
            issue.reply_op,
            issue.op,
            issue.resume,
            issue.target_seq,
        )?;
        if !self.backend_sessions[idx].wait_q_push(handle) {
            // Ring changed between probe and push (single-threaded
            // owner loop — should be impossible, but the ring's
            // saturating semantics require a rollback path).
            let _ = self.pending_ops.release(handle);
            return None;
        }
        Some(handle)
    }

    /// Pop the oldest deferred issue from the waiter ring of the
    /// session bound to `fs_id` and return its snapshot alongside
    /// the arena handle. Caller releases the arena entry via
    /// `release_deferred_issue` after consuming the snapshot.
    /// Returns `None` if the session is unknown, its ring is
    /// empty, or the popped handle no longer resolves.
    pub(crate) fn pop_deferred_issue(
        &mut self,
        fs_id: FsInstanceId,
    ) -> Option<(pending::PendingOpHandle, DeferredIssue)> {
        let idx = self.backend_session_slot_index(fs_id)?;
        loop {
            let handle = self.backend_sessions[idx].wait_q_pop()?;
            let snapshot = *self.pending_ops.get(handle)?;
            match snapshot.op_state {
                pending::PendingOpState::DeferredFs {
                    fs_instance_id,
                    session_id,
                    session_gen,
                    kind,
                    resume_ctx,
                    target_seq,
                } if fs_instance_id == fs_id => {
                    return Some((
                        handle,
                        DeferredIssue {
                            session_id,
                            session_gen,
                            client_badge: snapshot.client_badge,
                            reply_op: snapshot.reply_op,
                            resume: resume_ctx,
                            op: kind,
                            target_seq,
                            _pad: 0,
                        },
                    ));
                }
                _ => {
                    let _ = self.pending_ops.release(handle);
                }
            }
        }
    }

    /// Release a deferred-issue arena entry. Counterpart to
    /// `push_deferred_issue` / `pop_deferred_issue`.
    #[inline]
    pub(crate) fn release_deferred_issue(&mut self, handle: pending::PendingOpHandle) {
        let _ = self.pending_ops.release(handle);
    }

    /// Mark a `PendingOp` as cancelled and release its saved caller cap,
    /// but leave the slot in the arena so the eventual completion still
    /// matches by `TxId`. The completion dispatcher is responsible for
    /// releasing the inflight credit (and finally the arena entry) when
    /// the backend's reply lands — see
    /// [`crate::owner::pending::dispatch_pending_reply`].
    ///
    /// Cancellation MUST NOT eagerly release backend credit: the RPC is
    /// still in flight and the backend will eventually produce a reply
    /// that must be matched back to the slot (so its credit can be
    /// returned exactly once). Pre-releasing credit here lets a fresh
    /// issue reserve the same credit slot while the original request is
    /// still consuming backend bandwidth, violating the per-session
    /// inflight cap.
    ///
    /// Used by:
    /// - `dispatch::cancel_pending_ops_for_badge` on client exit.
    /// - `fileops::{bulk, dir}` post-issue failures (stamp / reply-slot
    ///   allocation / caller-save errors) where the RPC has already been
    ///   sent but the client-side delivery machinery could not complete.
    pub(crate) fn cancel_pending_op(&mut self, handle: pending::PendingOpHandle) {
        let (reply_op, deferred_fs) = match self.pending_ops.get_mut(handle) {
            Some(op) => {
                let deferred_fs = matches!(op.op_state, pending::PendingOpState::DeferredFs { .. });
                op.cancelled = 1;
                op.client_badge = 0;
                let reply_op = op.reply_op;
                op.reply_op = OpCore::INVALID;
                (reply_op, deferred_fs)
            }
            None => return,
        };
        if reply_op.reply_slot != 0 {
            self.release_reply_slot(reply_op.reply_slot);
        }
        if deferred_fs {
            for idx in 0..MAX_BACKEND_SESSIONS {
                if self.backend_sessions[idx].is_live() {
                    self.backend_sessions[idx].wait_q_remove(handle);
                }
            }
            let _ = self.pending_ops.release(handle);
        }
    }

    /// Look up `FsInstanceId → MountHandle` via linear scan over
    /// active mounts. Returns `None` if no mount carries the id.
    pub(crate) fn mount_by_fs_instance_id(
        &self,
        fs_id: crate::vfs_core::identity::FsInstanceId,
    ) -> Option<MountHandle> {
        if !fs_id.is_valid() {
            return None;
        }
        let mut found: Option<MountHandle> = None;
        self.mounts.for_each_active(|mh, mp| {
            if mp.fs_instance_id == fs_id {
                found = Some(mh);
                return false;
            }
            true
        });
        found
    }
}

// =========================================================================
// ResolveByIdentity implementations
// =========================================================================
//
// Each identity-addressable domain `CachedRef` depends on lands here
// as a `ResolveByIdentity<Id, Handle>` impl on `VfsState`. A single
// authoritative resolver per domain means call sites can keep using
// the generic [`crate::vfs_core::cached_ref::CachedRef::resolve`]
// without knowing which arena backs the lookup.

impl
    crate::vfs_core::cached_ref::ResolveByIdentity<
        crate::vfs_core::identity::FsInstanceId,
        MountHandle,
    > for VfsState
{
    #[inline]
    fn resolve(&self, id: crate::vfs_core::identity::FsInstanceId) -> Option<MountHandle> {
        self.mount_by_fs_instance_id(id)
    }

    #[inline]
    fn handle_still_matches(
        &self,
        id: crate::vfs_core::identity::FsInstanceId,
        handle: MountHandle,
    ) -> bool {
        match self.mounts.get(handle) {
            Some(mount) => mount.fs_instance_id == id,
            None => false,
        }
    }
}

impl
    crate::vfs_core::cached_ref::ResolveByIdentity<
        crate::vfs_core::identity::VnodeKey,
        crate::vfs_core::vnode::VnodeHandle,
    > for VfsState
{
    #[inline]
    fn resolve(
        &self,
        id: crate::vfs_core::identity::VnodeKey,
    ) -> Option<crate::vfs_core::vnode::VnodeHandle> {
        // Fast path via the resolve cache; the lookup helper also
        // verifies the slot's stored identity matches `id`.
        self.lookup_resolve_cache(id)
    }

    #[inline]
    fn handle_still_matches(
        &self,
        id: crate::vfs_core::identity::VnodeKey,
        handle: crate::vfs_core::vnode::VnodeHandle,
    ) -> bool {
        match self.vnodes.get(handle) {
            Some(vn) => vn.vnode_key() == id,
            None => false,
        }
    }
}

// Re-open the `impl VfsState` block so the remaining inherent
// methods keep their existing ordering below.
impl VfsState {
    /// Resolve a vnode's owning mount. Routes through the
    /// `CachedRef<FsInstanceId, MountHandle>` stored on `Vnode::mount`:
    /// the cached handle hint is verified against the authoritative
    /// `FsInstanceId`, and a stale hint falls through to the identity
    /// walk. Returns `None` when the mount has been retired.
    pub(crate) fn resolve_vnode_mount(&self, vh: VnodeHandle) -> Option<MountHandle> {
        let vnode = self.vnodes.get(vh)?;
        vnode.mount.resolve_ro(self)
    }

    /// Resolve a `VnodeKey` to a live `VnodeHandle`. Consults the
    /// resolve cache first; a cache hit that survives the epoch check
    /// is returned directly. A miss returns `None` — the caller is
    /// expected to walk the backend `vget` path and re-install via
    /// `install_resolve_cache`.
    pub(crate) fn lookup_resolve_cache(
        &self,
        key: crate::vfs_core::identity::VnodeKey,
    ) -> Option<VnodeHandle> {
        if !key.is_valid() {
            return None;
        }
        let idx = crate::vfs_core::identity::resolve_cache_index(key);
        let entry = &self.vnode_resolve_cache[idx];
        if entry.key != key {
            return None;
        }
        let vn = self.vnodes.get(entry.handle)?;
        if vn.fs_instance_id != key.fs_instance_id || vn.backend_node_id() != key.backend_id {
            return None;
        }
        Some(entry.handle)
    }

    /// Install (or overwrite) a resolve cache entry for `key → handle`.
    pub(crate) fn install_resolve_cache(
        &mut self,
        key: crate::vfs_core::identity::VnodeKey,
        handle: VnodeHandle,
    ) {
        if !key.is_valid() {
            return;
        }
        let idx = crate::vfs_core::identity::resolve_cache_index(key);
        self.vnode_resolve_cache[idx] =
            crate::vfs_core::identity::VnodeResolveCacheEntry { key, handle };
    }

    /// Invalidate any resolve cache entry pointing at `handle`.
    /// Called when a vnode is explicitly released so a recycled slot
    /// does not surface as a false cache hit. Cheap direct-mapped scan.
    pub(crate) fn invalidate_resolve_cache_for(
        &mut self,
        key: crate::vfs_core::identity::VnodeKey,
    ) {
        if !key.is_valid() {
            return;
        }
        let idx = crate::vfs_core::identity::resolve_cache_index(key);
        let entry = &mut self.vnode_resolve_cache[idx];
        if entry.key == key {
            *entry = crate::vfs_core::identity::VnodeResolveCacheEntry::EMPTY;
        }
    }

    /// Invalidate every cached directory-content snapshot held by an
    /// open fd that points at `parent_vkey` (in addition to dropping
    /// `parent_vkey`'s own resolve-cache entry). Invoked by the
    /// compound-mutation success paths (`create` / `mkdir` / `symlink`
    /// / `unlink` / `rmdir` / `link` / `rename`) so concurrent
    /// `readdir` fds on the affected directory re-fetch their batch
    /// instead of draining stale records.
    ///
    /// Matching goes through each active OpenObject's
    /// `vnode_handle()` resolved against the vnode arena — *not* the
    /// 128-slot direct-mapped resolve cache. The resolve cache can
    /// evict the parent's entry when a freshly-installed child key
    /// collides on the same slot (create / mkdir / symlink install
    /// the child key before calling this helper), so depending on it
    /// would silently leave stale `readdir_batch` snapshots behind.
    ///
    /// Iterates every live OpenObject in place with an unbounded
    /// single-pass sweep (no `MAX_MATCH` bound) — arena segments can
    /// grow past the initial 128-slot cap, and a partial sweep would
    /// leave stale batches on the tail fds. Split-borrow pattern:
    /// `self.open_objects.for_each_active_mut` exclusively borrows
    /// `self.open_objects` while the closure retains a shared
    /// borrow of `self.vnodes` captured before the call.
    pub(crate) fn invalidate_parent_dir_caches(
        &mut self,
        parent_vkey: crate::vfs_core::identity::VnodeKey,
    ) {
        if !parent_vkey.is_valid() {
            return;
        }
        let vnodes = &self.vnodes;
        self.open_objects.for_each_active_mut(|_h, obj| {
            let vh = obj.vnode_handle();
            if let Some(vnode) = vnodes.get(vh) {
                if vnode.vnode_key() == parent_vkey {
                    obj.readdir_batch = crate::server::open_object::ReaddirBatch::zeroed();
                }
            }
            true
        });
        // Also drop the parent's resolve-cache entry — this is
        // best-effort because the entry may already have been evicted
        // by an unrelated key collision, but clearing it when present
        // prevents a pathological double-dispatch on the next lookup.
        self.invalidate_resolve_cache_for(parent_vkey);
    }

    /// Allocate a deferred reply slot and associate it with `badge`.
    /// Returns `None` when the reply-cap pool is exhausted.
    pub(crate) fn alloc_reply_slot_for(&mut self, badge: u64) -> Option<u64> {
        if self.reply_slot_free_len == 0 {
            return None;
        }
        self.reply_slot_free_len -= 1;
        let slot = self.reply_slot_free[self.reply_slot_free_len];
        let idx = reply_slot_index(slot)?;
        self.reply_slot_in_use[idx] = 1;
        self.reply_slot_owner_badges[idx] = badge;
        Some(slot)
    }

    /// Release a deferred reply slot back to the free-list.
    pub(crate) fn release_reply_slot(&mut self, slot: u64) {
        let Some(idx) = reply_slot_index(slot) else {
            return;
        };
        let _ = trona_kernel::invoke::cnode_delete(CAP_SELF_CSPACE, slot);
        if self.reply_slot_in_use[idx] == 0 {
            return;
        }
        self.reply_slot_in_use[idx] = 0;
        self.reply_slot_owner_badges[idx] = 0;
        if self.reply_slot_free_len < REPLY_SLOT_COUNT {
            self.reply_slot_free[self.reply_slot_free_len] = slot;
            self.reply_slot_free_len += 1;
        }
    }

    /// Bulk-release every deferred reply slot still owned by `badge`.
    pub(crate) fn release_reply_slots_for_badge(&mut self, badge: u64) {
        if badge == 0 {
            return;
        }
        let mut to_release = [0u64; REPLY_SLOT_COUNT];
        let mut count = 0usize;
        let mut idx = 0usize;
        while idx < REPLY_SLOT_COUNT {
            if self.reply_slot_in_use[idx] != 0 && self.reply_slot_owner_badges[idx] == badge {
                to_release[count] = CAP_REPLY_BASE + idx as u64;
                count += 1;
            }
            idx += 1;
        }
        let mut i = 0usize;
        while i < count {
            self.release_reply_slot(to_release[i]);
            i += 1;
        }
    }

    /// Allocate a fresh client arena slot. On the first allocation failure,
    /// run a targeted reclaim sweep and retry once before reporting OOM.
    pub(crate) fn alloc_client_slot(
        &mut self,
        context: &'static [u8],
    ) -> Option<crate::server::types::ClientHandle> {
        if let Some(h) = self.clients.alloc() {
            return Some(h);
        }

        let reclaimed = self.clients.sweep();
        if let Some(h) = self.clients.alloc() {
            return Some(h);
        }

        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[VFS] client arena alloc failed ctx=");
            _lb.str(context);
            _lb.str(b" free=");
            _lb.dec(self.clients.free_count() as u64);
            _lb.str(b" cap=");
            _lb.dec(self.clients.total_cap() as u64);
            _lb.str(b" reclaimed=");
            _lb.dec(reclaimed as u64);
            _lb.str(b" badge_map=");
            _lb.dec(self.badge_map.len() as u64);
            _lb.str(b"/");
            _lb.dec(self.badge_map.capacity() as u64);
            _lb.str(b"\n");
        });
        None
    }

    /// Allocate a fresh open-object arena slot. Mirrors
    /// [`alloc_client_slot`]: reclaim first, then treat a second failure
    /// as a real capacity/MM failure worth surfacing.
    pub(crate) fn alloc_open_object_slot(
        &mut self,
        context: &'static [u8],
    ) -> Option<OpenObjectHandle> {
        if let Some(h) = self.open_objects.alloc() {
            return Some(h);
        }

        let reclaimed = self.open_objects.sweep();
        if let Some(h) = self.open_objects.alloc() {
            return Some(h);
        }

        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[VFS] open-object arena alloc failed ctx=");
            _lb.str(context);
            _lb.str(b" free=");
            _lb.dec(self.open_objects.free_count() as u64);
            _lb.str(b" cap=");
            _lb.dec(self.open_objects.total_cap() as u64);
            _lb.str(b" reclaimed=");
            _lb.dec(reclaimed as u64);
            _lb.str(b"\n");
        });
        None
    }

    /// Install an `OpenObject` value at `(cli_h, idx)`, allocating a fresh
    /// arena entry in `self.open_objects` and pointing the client's
    /// `slots[idx]` at it. `cloexec` is stored on the per-slot `ObjectRef`;
    /// `value.refcount` is ignored — the installed entry always starts with
    /// `refcount = 1`.
    ///
    /// If `slots[idx]` already references a live `OpenObject` (reserved by
    /// a prior `reserve_fd_owned`, or occupied because POSIX `dup2` targets
    /// an open fd) its arena entry is recycled. `obj_count` is bumped exactly
    /// once per installed slot; if the slot was already accounted for
    /// (reservation), the increment is suppressed.
    ///
    /// Returns `None` if `cli_h` is stale, `idx` is out of range, or the
    /// `open_objects` arena is exhausted; in that case no side effects occur.
    pub(crate) fn slot_install(
        &mut self,
        cli_h: crate::server::types::ClientHandle,
        idx: usize,
        value: crate::server::open_object::OpenObject,
        cloexec: u8,
    ) -> Option<()> {
        if idx >= crate::server::types::MAX_CLIENT_OBJECTS {
            return None;
        }
        let handle = self.alloc_open_object_slot(b"slot_install")?;
        {
            let obj = self.open_objects.get_mut(handle)?;
            *obj = value;
            obj.refcount = 1;
        }
        let stale_handle = match self.clients.get_mut(cli_h) {
            Some(cli) => {
                let was_free = cli.slots[idx].is_free();
                let stale = cli.slots[idx].open_object;
                cli.slots[idx] = crate::server::open_object::ObjectRef::new(handle, cloexec);
                if was_free {
                    cli.obj_count = cli.obj_count.saturating_add(1);
                }
                stale
            }
            None => {
                // Roll back arena allocation so we do not leak a slot.
                self.open_objects.release(handle);
                return None;
            }
        };
        if stale_handle.is_valid() {
            self.open_objects.release(stale_handle);
        }
        Some(())
    }

    /// Resolve `(cli_h, idx)` to the `OpenObject` it references.
    /// Returns `None` if the client is unknown, `idx` is out of range,
    /// the slot is free, or the `OpenObject` arena entry has been
    /// reclaimed. Read-only view.
    pub(crate) fn open_object_at(
        &self,
        cli_h: crate::server::types::ClientHandle,
        idx: usize,
    ) -> Option<&crate::server::open_object::OpenObject> {
        if idx >= crate::server::types::MAX_CLIENT_OBJECTS {
            return None;
        }
        let handle = self.clients.get(cli_h)?.slots[idx].open_object;
        self.open_objects.get(handle)
    }

    /// Mutable view of the `OpenObject` at `(cli_h, idx)`.
    pub(crate) fn open_object_at_mut(
        &mut self,
        cli_h: crate::server::types::ClientHandle,
        idx: usize,
    ) -> Option<&mut crate::server::open_object::OpenObject> {
        if idx >= crate::server::types::MAX_CLIENT_OBJECTS {
            return None;
        }
        let handle = self.clients.get(cli_h)?.slots[idx].open_object;
        self.open_objects.get_mut(handle)
    }

    /// Reserve a free slot index for the given client, allocating a
    /// placeholder `OpenObject` (backing = `Reserved`) in the arena
    /// and linking `slots[idx]` to it. Callers populate the slot by
    /// mutating the returned `OpenObject` via `open_object_at_mut`
    /// and calling one of its `set_XXX` methods, which replaces the
    /// `Reserved` backing. Rollback is `slot_release`.
    ///
    /// Multi-fd writers (e.g. `pipe`, `socketpair`) call this twice
    /// to reserve both indices before populating either, which is
    /// why the reservation needs to be visible to subsequent
    /// `reserve_fd_owned` calls.
    pub(crate) fn reserve_fd_owned(
        &mut self,
        cli_h: crate::server::types::ClientHandle,
    ) -> Option<i32> {
        let idx = {
            let cli = self.clients.get(cli_h)?;
            let mut found = None;
            for i in 0..crate::server::types::MAX_CLIENT_OBJECTS {
                if cli.slots[i].is_free() {
                    found = Some(i);
                    break;
                }
            }
            found?
        };
        let handle = self.alloc_open_object_slot(b"reserve_fd_owned")?;
        {
            let obj = self.open_objects.get_mut(handle)?;
            *obj = crate::server::open_object::OpenObject::zeroed();
            obj.refcount = 1;
            obj.backing = crate::server::types::ObjectBacking::Reserved;
        }
        let cli = match self.clients.get_mut(cli_h) {
            Some(c) => c,
            None => {
                self.open_objects.release(handle);
                return None;
            }
        };
        cli.slots[idx] = crate::server::open_object::ObjectRef::new(handle, 0);
        cli.obj_count = cli.obj_count.saturating_add(1);
        Some(idx as i32)
    }

    /// Release `(cli_h, idx)` — clears `slots[idx]` and releases the
    /// referenced `OpenObject` arena entry. Decrements `obj_count`
    /// when the slot was occupied.
    ///
    /// Low-level primitive used by rollback / reservation paths;
    /// production close paths go through
    /// [`VfsState::close_open_object`] which decrements the shared
    /// refcount and routes teardown through
    /// `server::release::release_backing`.
    pub(crate) fn slot_release(&mut self, cli_h: crate::server::types::ClientHandle, idx: usize) {
        if idx >= crate::server::types::MAX_CLIENT_OBJECTS {
            return;
        }
        let handle = match self.clients.get_mut(cli_h) {
            Some(cli) => {
                let was_live = !cli.slots[idx].is_free();
                let handle = cli.slots[idx].open_object;
                cli.slots[idx] = crate::server::open_object::ObjectRef::empty();
                if was_live {
                    cli.obj_count = cli.obj_count.saturating_sub(1);
                }
                handle
            }
            None => return,
        };
        if handle.is_valid() {
            self.open_objects.release(handle);
        }
    }

    /// Share an existing `OpenObject` into `(cli_h, idx)`, bumping its
    /// refcount by exactly one. No new arena entry is allocated.
    ///
    /// Used by POSIX `dup` / `dup2` / `dup3` / `F_DUPFD` /
    /// `F_DUPFD_CLOEXEC` / `clone_fds` / SCM_RIGHTS — every site that
    /// historically deep-copied an `OpenObject` now points a second
    /// `ObjectRef` at the same arena entry.
    ///
    /// If `slots[idx]` already references a live `OpenObject`, that
    /// previous reference is dropped via
    /// [`VfsState::close_open_object`] *before* the new reference is
    /// installed — i.e. the POSIX `dup2`/`dup3` contract of
    /// "atomically close newfd, then point it at oldfd" is preserved.
    /// Callers must short-circuit the `dup2(fd, fd)` no-op case before
    /// reaching here.
    ///
    /// `prev_close_badge` is the badge passed to `close_open_object`
    /// when evicting the previous occupant — should be the calling
    /// client's own badge for interactive dup sites and `0` for exit
    /// sweeps.
    ///
    /// Returns `None` on refcount overflow, stale `cli_h`, stale
    /// `src_handle`, or out-of-range `idx`; on failure no side
    /// effects occur.
    pub(crate) fn slot_share(
        &mut self,
        cli_h: crate::server::types::ClientHandle,
        idx: usize,
        src_handle: crate::server::open_object::OpenObjectHandle,
        cloexec: u8,
        prev_close_badge: u64,
    ) -> Option<()> {
        if idx >= crate::server::types::MAX_CLIENT_OBJECTS {
            return None;
        }
        if !src_handle.is_valid() {
            return None;
        }

        // Pre-check: refcount overflow (u16) must fail hard, not wrap.
        match self.open_objects.get(src_handle) {
            Some(obj) => {
                if obj.refcount.checked_add(1).is_none() {
                    return None;
                }
            }
            None => return None,
        }

        // Close the previous occupant of `slots[idx]`, if any. This
        // decrements its OpenObject refcount and runs release_backing
        // on last reference. Distinct from `slot_release` because
        // POSIX dup2/dup3 require per-kind teardown of the evicted fd.
        let prev_live = self
            .clients
            .get(cli_h)
            .map(|cli| !cli.slots[idx].is_free())
            .unwrap_or(false);
        if prev_live {
            let _ = self.close_open_object(cli_h, idx, prev_close_badge);
        }

        // Commit refcount++. The pre-check already confirmed no
        // overflow, but the arena entry could have been reclaimed by
        // a recursive close path above — reject that.
        match self.open_objects.get_mut(src_handle) {
            Some(obj) => obj.refcount = obj.refcount.saturating_add(1),
            None => return None,
        }

        // Install the new reference.
        let cli = match self.clients.get_mut(cli_h) {
            Some(c) => c,
            None => {
                // Client vanished between close and install. Roll back
                // the refcount bump.
                if let Some(obj) = self.open_objects.get_mut(src_handle) {
                    obj.refcount = obj.refcount.saturating_sub(1);
                }
                return None;
            }
        };
        let was_free = cli.slots[idx].is_free();
        cli.slots[idx] = crate::server::open_object::ObjectRef::new(src_handle, cloexec);
        if was_free {
            cli.obj_count = cli.obj_count.saturating_add(1);
        }
        Some(())
    }

    /// Close the object referenced by `(cli_h, idx)` following shared
    /// `OpenObject` semantics: decrement the refcount, clear the slot,
    /// and on last reference run
    /// [`crate::server::release::release_backing`] and release the
    /// arena entry.
    ///
    /// `badge` is the owning client badge at the time of close — used
    /// by the SHM arm of `release_backing` to call `MM_SHM_UNMAP`.
    /// Pass `0` from exit sweeps where the client badge is already
    /// gone; `release_backing` skips SHM unmap for unbadged releases.
    ///
    /// Returns `Err(())` when `cli_h`/`idx` does not resolve to a live
    /// slot; returns `Ok(())` otherwise.
    pub(crate) fn close_open_object(
        &mut self,
        cli_h: crate::server::types::ClientHandle,
        idx: usize,
        badge: u64,
    ) -> Result<(), ()> {
        if idx >= crate::server::types::MAX_CLIENT_OBJECTS {
            return Err(());
        }

        let Some(cli) = self.clients.get(cli_h) else {
            return Err(());
        };
        if cli.slots[idx].is_free() {
            return Err(());
        }
        let handle = cli.slots[idx].open_object;
        let Some(obj) = self.open_objects.get(handle) else {
            return Err(());
        };
        let backing_snapshot = obj.backing;
        let aux = crate::server::release::ReleaseAux {
            badge,
            flags: obj.flags,
            held_access: obj.held_access,
            held_deny: obj.held_deny,
            rights: obj.rights,
            offset: obj.offset,
            inode: obj.inode(),
        };

        // Descriptor-local close seam. Runs on **every** close,
        // regardless of whether this is the last OFD reference. Fires
        // before the slot is cleared so helpers can still resolve the
        // `(cli_h, idx)` pair. No callers today — kept as a design
        // anchor so future per-fd state (epoll interest, poll waiter,
        // audit tag, …) has an obvious insertion point without
        // relitigating the pre-close-hook layering that ws:2 removed.
        descriptor_local_close_hook(self, cli_h, idx, handle);

        // Clear the client slot first so any recursive release path
        // (e.g. peer wake-ups walking slot tables) no longer observes
        // this reference.
        if let Some(cli_mut) = self.clients.get_mut(cli_h) {
            cli_mut.slots[idx] = crate::server::open_object::ObjectRef::empty();
            cli_mut.obj_count = cli_mut.obj_count.saturating_sub(1);
        }

        // Refcount--. Non-zero → other slots still reference this
        // OpenObject; no teardown, no arena release.
        let refcount_after = match self.open_objects.get_mut(handle) {
            Some(obj) => {
                obj.refcount = obj.refcount.saturating_sub(1);
                obj.refcount
            }
            None => 0,
        };
        if refcount_after > 0 {
            return Ok(());
        }

        // Last reference — run backing teardown then release the arena
        // entry. Teardown uses the stack-local snapshot; the arena
        // slot itself is reclaimed afterwards.
        unsafe {
            crate::server::release::release_backing(self, backing_snapshot, aux);
        }
        let _ = self.open_objects.release(handle);
        Ok(())
    }
}

impl VfsState {
    /// Release a deferred reply slot and return it to the free list.
    pub(crate) unsafe fn release_saved_reply_slot(&mut self, reply_slot: u64) {
        if reply_slot == 0 {
            return;
        }
        self.release_reply_slot(reply_slot);
    }

    /// Send a reply through a saved caller cap and release the slot immediately.
    pub(crate) unsafe fn send_saved_reply(&mut self, reply_slot: u64, msg: *const TronaMsg) {
        if reply_slot == 0 {
            return;
        }
        unsafe {
            trona_kernel::ipc::send_ctx(crate::ipc_ctx(), reply_slot, msg);
        }
        self.release_reply_slot(reply_slot);
    }
}

/// Descriptor-local close hook — the per-fd seam that runs on every
/// `close_open_object` invocation, independent of `OpenObject` refcount.
///
/// Deliberately a no-op today: every teardown observed so far is
/// backing-scoped (VOP_CLOSE, pipe/socket refcount, PTY_CLOSE,
/// NET_CLOSE, arena release for epoll/pipe/socket/vnode) and those all
/// live in `server::release::release_backing`. The previous generation
/// of `pre_close_*` hooks was deleted entirely in ws:2.
///
/// **Extend this function** when genuinely descriptor-local state
/// gets added: per-fd `epoll_ctl` interest, a per-fd `poll` waiter,
/// audit tags, `F_NOTIFY` / `fanotify` subscriptions, anything that
/// cannot be shared across dups. Do **not** recreate the old pre-close
/// hook layer in `personality/*/dispatch.rs`.
#[inline]
fn descriptor_local_close_hook(
    _state: &mut VfsState,
    _cli_h: crate::server::types::ClientHandle,
    _idx: usize,
    _open_object: crate::server::open_object::OpenObjectHandle,
) {
    // Intentionally empty. See doc comment above.
}
