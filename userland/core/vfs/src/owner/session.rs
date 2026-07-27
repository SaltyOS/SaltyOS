// SPDX-License-Identifier: GPL-2.0-only
//
//! `BackendSessionSlot` — per-mount-instance bookkeeping.
//!
//! One slot per saltyfs daemon instance, netsrv mount, posix_ttysrv
//! pty pair, etc. The slot's `live_gen` is the truth source for
//! "this session is still serving traffic"; teardown advances it
//! and any in-flight reply that quotes the old epoch is dropped at
//! the completion 5-tuple check.
//!
//! Teardown order (race-free):
//!   1. `live_gen += 2` (advance past the current epoch, keeping
//!      0 reserved as the empty-slot sentinel).
//!   2. `WATCH_CANCEL` over the callback EP, plus an
//!      `EventQueue::purge_matching` so any already-queued record
//!      for the cookie is dropped.
//!   3. Cancel every PendingOp that quoted this session — synth a
//!      `SessionTornDown` reply, drop the reply lease.
//!   4. Release the callback / readdir-shm caps held by the
//!      session.
//!
//! Stepping out of order leaks completions or wedges the reactor;
//! `BackendSessionSlot::tear_down` drives the four steps in
//! sequence; missing one leaks completions or wedges the reactor.
//!
//! The full slot — credit, deferred FIFO, push / drain / completion
//! / readdir_eof hooks — lands alongside the saltyfs client
//! mining. The skeleton here defines the 5-tuple validation
//! identity (`fs_instance_id`, `mount_handle_raw`, `session_id`,
//! `live_gen`) plus the empty-slot sentinel so the dispatcher can
//! cross-check incoming completions today.

use trona_kernel::core_types::Cap;
use trona_runtime::core::slot_alloc::OwnedCap;

use crate::arena::handle::Handle;
use crate::arena::segmented_array::{MmapAllocator, SegmentedArray};
use crate::core::error::VfsError;
use crate::core::identity::FsInstanceId;
use crate::core::mount::{Mount, MountHandle, MountKind};
use crate::owner::deferred::DeferredIssue;

/// Generation-validated handle into `VfsState.backend_sessions`.
/// Issued by `attach_session` and consumed by every backend issue
/// site; cross-checked against the slot's `live_gen` on every
/// completion so a re-attached slot does not silently absorb stale
/// replies routed against the previous incarnation.
pub(crate) type BackendSessionHandle = Handle<BackendSessionSlot>;

/// Raw slot index — used by the dispatcher's 5-tuple validation
/// path where the epoch check is done explicitly via the cookie.
pub(crate) type BackendSessionIdx = u32;

/// Drain hook signature. Called from completion processing once
/// `inflight_now` has been decremented; pops up to `freed_credit`
/// entries off `wait_q` and re-issues each via the backend's
/// per-kind `push_fn`. The hook is registered when the session
/// opens (saltyfs / netsrv / posix_ttysrv install their own).
pub(crate) type DrainFn =
    fn(state: &mut crate::owner::VfsState, slot_idx: BackendSessionIdx, freed_credit: u32);

/// Per-deferred-entry re-issue hook. Called from `DrainFn` once
/// the entry is selected to re-issue. Returns the new state for
/// the underlying PendingOp (`true` = issued, `false` = drop).
pub(crate) type PushFn = fn(
    state: &mut crate::owner::VfsState,
    slot_idx: BackendSessionIdx,
    entry: &DeferredIssue,
) -> bool;

/// Inbound-completion router signature. Called from
/// [`crate::ipc::dispatch::dispatch_backend`] once the dispatcher
/// has decoded the correlation header, looked up the originating
/// `PendingOp`, validated the 5-tuple
/// `(fs_instance_id, mount_handle, session_id, live_gen, tx_id)`,
/// and snapshotted the per-op state. The hook owns the saved
/// reply lease — a debug-build `Drop` panic surfaces a leak if
/// it is not consumed / cancelled / parked / disarmed before the
/// hook returns — and is responsible for sending the typed reply,
/// cancelling the caller, or parking the lease for a later
/// resume.
pub(crate) type CompletionFn = unsafe fn(
    state: &mut crate::owner::VfsState,
    fs_id: crate::core::identity::FsInstanceId,
    tx_id: crate::owner::pending::TxId,
    kind_payload: &crate::owner::pending::PendingKindPayload,
    resume_ctx: crate::owner::resume::Resume,
    backend_session_idx: BackendSessionIdx,
    reply_lease: Option<trona_server::ReplyLease>,
    reply_msg: &trona_kernel::core_types::TronaMsg,
    personality: crate::personality::Personality,
);

/// readdir bulk-batch terminator. Called when `BACKEND_READDIR`
/// returns the final batch in a sequence so the session can
/// release its read-side ownership of the SHM ring.
pub(crate) type ReaddirEofFn = fn(state: &mut crate::owner::VfsState, slot_idx: BackendSessionIdx);

#[repr(C)]
pub(crate) struct BackendSessionSlot {
    /// Mount-instance id; matches `Mount.fs_instance_id`.
    /// `FsInstanceId::INVALID` means "slot is empty".
    pub fs_instance_id: FsInstanceId,
    /// Raw mount-handle bits (slot + epoch packed) of the
    /// associated `Mount`. Stored as `u64` so the completion check
    /// can compare without re-resolving the typed handle.
    pub mount_handle_raw: u64,
    /// Per-VFS monotonic session id. Distinguishes successive
    /// sessions to the same backend (e.g. saltyfs daemon restart
    /// reuses the same `fs_instance_id` with a fresh session id).
    pub session_id: u32,
    _pad: u32,
    /// Liveness counter — advanced (+= 2) on teardown so the
    /// even/odd parity is preserved and 0 stays the sentinel.
    pub live_gen: u32,
    /// Cap held by vfs to send requests into the backend.
    pub send_cap: OwnedCap,
    /// Backend → vfs callback recv end. Watched on the owner EQ.
    pub callback_recv: OwnedCap,
    /// Watch object armed over `callback_recv`'s `STATE_READABLE`.
    pub callback_watch: OwnedCap,
    /// Cookie returned by `arm_watch` for the callback Watch.
    pub callback_cookie: u64,
    /// rsrcsrv record ids for the callback MP-pair core + the callback
    /// Watch, captured at attach. Freed via `free_record` in
    /// `tear_down` so vfs does not accumulate per-session rsrcsrv
    /// records under its owner id across mount/unmount cycles. `0`
    /// while the slot is empty / reset.
    pub callback_mp_record_id: u64,
    pub callback_watch_record_id: u64,
    /// Inflight credit ceiling negotiated at `BACKEND_OPEN_SESSION`.
    pub inflight_max: u32,
    /// Currently in-flight requests against this session.
    pub inflight_now: u32,
    /// Monotonic enqueue counter for `wait_q` ordering.
    pub next_target_seq: u32,
    /// Deferred re-issue queue. Grows segment-by-segment as the
    /// backlog deepens; teardown drains every entry through the
    /// `SessionTornDown` reply path.
    pub wait_q: SegmentedArray<DeferredIssue>,
    /// Allocator backing `wait_q`'s grow.
    pub wait_q_allocator: MmapAllocator,
    /// SHM ring descriptor for backend bulk results (READDIR
    /// batches today; future bulk reads). 0 = no ring.
    pub readdir_shm_region_mo: OwnedCap,
    pub readdir_shm_region_va: u64,
    pub readdir_shm_region_bytes: u64,
    /// Hooks installed by the backend module on `OPEN_SESSION`.
    pub drain_fn: Option<DrainFn>,
    pub push_fn: Option<PushFn>,
    pub completion_fn: Option<CompletionFn>,
    pub readdir_eof_fn: Option<ReaddirEofFn>,
}

impl BackendSessionSlot {
    pub(crate) const EMPTY: Self = Self {
        fs_instance_id: FsInstanceId::INVALID,
        mount_handle_raw: 0,
        session_id: 0,
        _pad: 0,
        live_gen: 0,
        send_cap: OwnedCap::null(),
        callback_recv: OwnedCap::null(),
        callback_watch: OwnedCap::null(),
        callback_cookie: 0,
        callback_mp_record_id: 0,
        callback_watch_record_id: 0,
        inflight_max: 0,
        inflight_now: 0,
        next_target_seq: 0,
        wait_q: SegmentedArray::new_empty(),
        wait_q_allocator: MmapAllocator::new(),
        readdir_shm_region_mo: OwnedCap::null(),
        readdir_shm_region_va: 0,
        readdir_shm_region_bytes: 0,
        drain_fn: None,
        push_fn: None,
        completion_fn: None,
        readdir_eof_fn: None,
    };

    /// `true` when this slot is logically unused. `live_gen` is
    /// intentionally not part of the predicate: teardown preserves
    /// it so a reused active slot keeps a monotonically advancing
    /// generation while stale completion dispatch still short-circuits
    /// on the invalid fs id.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        !self.fs_instance_id.is_valid()
    }

    /// Available credit (`inflight_max - inflight_now`). 0 means
    /// the next caller has to defer — push to `wait_q` and let
    /// `drain_fn` re-issue once a completion lands.
    #[inline]
    pub(crate) fn credit_available(&self) -> u32 {
        self.inflight_max.saturating_sub(self.inflight_now)
    }

    /// Allocate the next monotonic enqueue seq for this session.
    #[inline]
    pub(crate) fn alloc_target_seq(&mut self) -> u32 {
        let seq = self.next_target_seq;
        self.next_target_seq = seq.wrapping_add(1);
        seq
    }
}

/// Tear down a session in race-free four-step order. The owner
/// must hold an exclusive `&mut VfsState` for the duration —
/// every step mutates state and no inbound IPC can fire while we
/// run.
///
/// Steps:
///   1. Advance `live_gen` (`+= 2`) so any reply currently in
///      flight against the old epoch mismatches at the 5-tuple
///      check and gets dropped.
///   2. Cancel both armed watches via the kernite WATCH_CANCEL
///      hygiene primitive (purges the bound EQ ring of any
///      record carrying these cookies — generation already
///      protects correctness, this just keeps the ring clean).
///   3. Cancel every PendingOp whose `backend_session_idx`
///      matches: synth a `SessionTornDown` reply, drop the
///      reply lease. Also drain the deferred wait_q.
///   4. Release the cap slots — callback recv / Watch / pager
///      recv / pager Watch / SHM ring MO. Each `cnode_delete` is
///      best-effort; failures log but do not abort.
pub(crate) fn tear_down(state: &mut crate::owner::VfsState, slot_idx: u32) {
    use trona_kernel::invoke;

    // Step 1: advance live_gen and snapshot raw cap values for watch
    // cancel + step 4 free. The fields are disarmed here (replaced with
    // null) so the eventual Drop on the arena slot is a no-op; the
    // explicit `drop()` calls in step 4 below fire the single free.
    let (
        callback_watch_raw,
        callback_recv_cap,
        shm_mo_cap,
        send_cap_cap,
        watch_disarm,
        callback_mp_record_id,
        callback_watch_record_id,
    ) = {
        let Some(slot) = state.backend_sessions.handle_from_slot(slot_idx) else {
            return;
        };
        let Some(s) = state.backend_sessions.get_mut(slot) else {
            return;
        };
        s.live_gen = s.live_gen.wrapping_add(2);
        let callback_watch_raw = s.callback_watch.as_raw();
        let callback_recv_cap = core::mem::replace(&mut s.callback_recv, OwnedCap::null());
        let shm_mo_cap = core::mem::replace(&mut s.readdir_shm_region_mo, OwnedCap::null());
        let send_cap_cap = core::mem::replace(&mut s.send_cap, OwnedCap::null());
        // Hold the watch OwnedCap until AFTER watch_cancel in step 2 so the
        // kernel cancel runs while the cap slot is still valid.
        let watch_disarm = core::mem::replace(&mut s.callback_watch, OwnedCap::null());
        (
            callback_watch_raw,
            callback_recv_cap,
            shm_mo_cap,
            send_cap_cap,
            watch_disarm,
            s.callback_mp_record_id,
            s.callback_watch_record_id,
        )
    };

    // Step 2: WATCH_CANCEL the armed watches, then release the cap slot.
    // The cap must be valid during the cancel — drop AFTER the kernel call.
    if callback_watch_raw != 0 {
        let _ = invoke::watch_cancel(trona_runtime::core::slot_alloc::resolved_cap_ref(
            callback_watch_raw,
        ));
    }
    drop(watch_disarm);

    // Step 3: cancel PendingOps + drain wait_q. Iterate in waves
    // to avoid both long borrows over `pending_ops` and recursion
    // (advisor feedback — the previous tail-call form re-advanced
    // `live_gen` and re-ran step 2 / step 4 unnecessarily).
    loop {
        let mut victims: [PendingOpVictim; 32] = [PendingOpVictim::EMPTY; 32];
        let mut count = 0usize;
        state.pending_ops.for_each_active(|h, op| {
            if count == victims.len() {
                return false;
            }
            if op.core.backend_session_idx == slot_idx {
                victims[count] = PendingOpVictim {
                    handle: h,
                    _filler: 0,
                };
                count += 1;
            }
            true
        });
        if count == 0 {
            break;
        }
        for v in victims.iter().take(count).copied() {
            crate::owner::pending::cancel_op_handle(
                state,
                v.handle,
                crate::owner::op::CancelDisposition::ServerDied,
            );
        }
        if count < victims.len() {
            break;
        }
        // count == victims.len() — there may be more to cancel,
        // re-scan with another wave.
    }

    // Drain wait_q deferred entries. They reference PendingOps we
    // just cancelled; the entries themselves can stay until the
    // logical clear below resets `len = 0`.
    if let Some(slot) = state.backend_sessions.handle_from_slot(slot_idx) {
        if let Some(s) = state.backend_sessions.get_mut(slot) {
            s.wait_q.clear();
            s.inflight_now = 0;
            s.next_target_seq = 0;
        }
    }

    // Step 4: drop the cap slots extracted in step 1. Each OwnedCap
    // Drop fires delete_and_free exactly once; the null guard
    // inside OwnedCap::drop makes zero-slot drops a no-op. The fields
    // were already replaced with null in step 1, so the arena slot's
    // eventual Drop is a no-op regardless.
    drop(callback_recv_cap);
    drop(shm_mo_cap);
    drop(send_cap_cap);
    // callback_watch_raw was already disarmed in step 1 (the OwnedCap
    // was moved into _watch_disarm and dropped there); no second free.

    // Vacate the rsrcsrv ObjectTable records (owned by vfs's badge)
    // backing the callback Watch + callback MP pair. The cap deletes
    // above only drop vfs's copies; without these `free_record` calls
    // rsrcsrv's records accumulate under vfs's owner id across
    // mount/unmount cycles. The MP-pair core id frees all three group
    // records; both ids are 0 (no-op) for an already-reset slot.
    let _ = trona_runtime::core::slot_alloc::free_record(callback_watch_record_id);
    let _ = trona_runtime::core::slot_alloc::free_record(callback_mp_record_id);

    // Finalise: reset the slot's data fields without overwriting
    // `wait_q` (the SegmentedArray header — overwriting with a
    // fresh `EMPTY` would orphan every segment in its chain).
    // Keep the arena slot Active-but-logically-empty so the next
    // attach can reuse the same wait_q segment chain and continue
    // advancing live_gen from the torn-down incarnation.
    if let Some(slot) = state.backend_sessions.handle_from_slot(slot_idx) {
        if let Some(s) = state.backend_sessions.get_mut(slot) {
            reset_backend_session_after_teardown(s);
        }
    }
}

#[derive(Clone, Copy)]
struct PendingOpVictim {
    handle: crate::owner::pending::PendingOpHandle,
    _filler: u32,
}

impl PendingOpVictim {
    const EMPTY: Self = Self {
        handle: crate::owner::pending::PendingOpHandle::INVALID,
        _filler: 0,
    };
}

/// Spec for the identity + hooks portion of a backend session at
/// allocation time. Caps that arrive later (pager callback, SHM
/// region) feed in via the `set_*` helpers below.
#[derive(Clone, Copy)]
pub(crate) struct BackendSessionAttach {
    pub fs_instance_id: FsInstanceId,
    pub mount_handle_raw: u64,
    pub send_cap: Cap,
    pub callback_recv: Cap,
    pub callback_watch: Cap,
    pub callback_mp_record_id: u64,
    pub callback_watch_record_id: u64,
    pub inflight_max: u32,
    pub completion_fn: CompletionFn,
    pub drain_fn: Option<DrainFn>,
    pub push_fn: Option<PushFn>,
    pub readdir_eof_fn: Option<ReaddirEofFn>,
}

fn find_reusable_backend_session_slot(
    state: &crate::owner::VfsState,
) -> Option<BackendSessionHandle> {
    let mut found = None;
    state.backend_sessions.for_each_active(|h, slot| {
        if slot.is_empty() {
            found = Some(h);
            false
        } else {
            true
        }
    });
    found
}

fn allocate_or_reuse_backend_session_slot(
    state: &mut crate::owner::VfsState,
) -> Option<BackendSessionHandle> {
    if let Some(handle) = find_reusable_backend_session_slot(state) {
        return Some(handle);
    }
    let handle = state.backend_sessions.alloc()?;
    if let Some(slot) = state.backend_sessions.get_mut(handle) {
        *slot = BackendSessionSlot::EMPTY;
    }
    Some(handle)
}

fn reset_backend_session_after_teardown(slot: &mut BackendSessionSlot) {
    slot.fs_instance_id = FsInstanceId::INVALID;
    slot.mount_handle_raw = 0;
    slot.session_id = 0;
    // live_gen is deliberately preserved across logical reuse.
    //
    // All four cap fields were already disarmed (replaced with null) in
    // tear_down's step 1; these assignments are null-to-null writes that
    // confirm the clean state. OwnedCap::null() is a const fn so no
    // drop side-effects fire here.
    slot.send_cap = OwnedCap::null();
    slot.callback_recv = OwnedCap::null();
    slot.callback_watch = OwnedCap::null();
    slot.callback_cookie = 0;
    slot.callback_mp_record_id = 0;
    slot.callback_watch_record_id = 0;
    slot.inflight_max = 0;
    slot.inflight_now = 0;
    slot.next_target_seq = 0;
    slot.readdir_shm_region_mo = OwnedCap::null();
    slot.readdir_shm_region_va = 0;
    slot.readdir_shm_region_bytes = 0;
    slot.drain_fn = None;
    slot.push_fn = None;
    slot.completion_fn = None;
    slot.readdir_eof_fn = None;
    slot.wait_q.clear();
}

fn attach_backend_session_slot(
    slot: &mut BackendSessionSlot,
    attach: BackendSessionAttach,
    session_id: u32,
    slot_idx: u32,
) -> u64 {
    // Live_gen advances by 2 to preserve odd/even parity and to
    // keep 0 reserved for the never-used sentinel.
    let new_gen = slot.live_gen.wrapping_add(2);
    let new_gen = if new_gen == 0 { 2 } else { new_gen };
    slot.wait_q.clear();
    slot.fs_instance_id = attach.fs_instance_id;
    slot.mount_handle_raw = attach.mount_handle_raw;
    slot.session_id = session_id;
    slot.live_gen = new_gen;
    // SAFETY: send_cap/callback_recv/callback_watch were transferred into this
    // session (forget-moved by the caller), each landing in a global slot now
    // solely owned by this session slot.
    unsafe {
        slot.send_cap = OwnedCap::adopt_received(attach.send_cap);
        slot.callback_recv = OwnedCap::adopt_received(attach.callback_recv);
        slot.callback_watch = OwnedCap::adopt_received(attach.callback_watch);
    }
    slot.callback_mp_record_id = attach.callback_mp_record_id;
    slot.callback_watch_record_id = attach.callback_watch_record_id;
    slot.callback_cookie = crate::ipc::cookie::encode_cookie(
        crate::ipc::cookie::KIND_BACKEND_SESSION,
        slot_idx,
        new_gen,
    );
    slot.inflight_max = attach.inflight_max;
    slot.inflight_now = 0;
    slot.next_target_seq = 0;
    slot.readdir_shm_region_mo = OwnedCap::null();
    slot.readdir_shm_region_va = 0;
    slot.readdir_shm_region_bytes = 0;
    slot.drain_fn = attach.drain_fn;
    slot.push_fn = attach.push_fn;
    slot.completion_fn = Some(attach.completion_fn);
    slot.readdir_eof_fn = attach.readdir_eof_fn;
    slot.callback_cookie
}

/// Allocate a fresh session slot, fill in identity + hooks, advance
/// the per-session `live_gen` counter, store the caller-supplied
/// `session_id` (the same id forwarded to the backend in
/// `BACKEND_OPEN_SESSION` so completion correlation headers match),
/// and arm the callback Watch on the owner EQ.
///
/// Returns `None` if the arena allocator is exhausted or the
/// kernel `WATCH_REGISTER` invocation fails. On failure every cap
/// `attach` owns (`callback_recv`, `callback_watch`, `send_cap`) is
/// freed here, so the caller must NOT double-free them and only
/// retains responsibility for releasing the rsrcsrv record IDs.
///
/// SHM bulk-region wiring lands via [`set_backend_session_shm_region`].
pub(crate) unsafe fn alloc_backend_session_slot(
    state: &mut crate::owner::VfsState,
    attach: BackendSessionAttach,
    session_id: u32,
) -> Option<u32> {
    // Helper: free the raw caps inside `attach` that have been
    // `forget`-transferred to us but not yet adopted into an OwnedCap.
    // All three (`callback_recv`, `callback_watch`, `send_cap`) are owned by
    // `attach` once `attach_backend_session` hands it over, so an early failure
    // (before the slot adopts them) frees all three here.
    #[inline(always)]
    unsafe fn free_attach_caps(attach: &BackendSessionAttach) {
        unsafe {
            trona_runtime::core::slot_alloc::delete_and_free(attach.callback_recv);
            trona_runtime::core::slot_alloc::delete_and_free(attach.callback_watch);
            trona_runtime::core::slot_alloc::delete_and_free(attach.send_cap);
        }
    }

    if state.owner_eq.as_raw() == 0 {
        unsafe { free_attach_caps(&attach) };
        return None;
    }
    let handle = match allocate_or_reuse_backend_session_slot(state) {
        Some(h) => h,
        None => {
            unsafe { free_attach_caps(&attach) };
            return None;
        }
    };
    let slot_idx = handle.slot();

    let cookie = {
        let slot = match state.backend_sessions.get_mut(handle) {
            Some(s) => s,
            None => {
                unsafe { free_attach_caps(&attach) };
                return None;
            }
        };
        attach_backend_session_slot(slot, attach, session_id, slot_idx)
    };

    // Arm the callback Watch on the owner EQ. The kernel publishes
    // `STATE_READABLE` records on every inbound MP_READ; the
    // dispatcher's cookie-decode step routes them to
    // `dispatch_backend`.
    if attach.callback_watch != 0 && attach.callback_recv != 0 {
        let watch_err = trona_kernel::invoke::watch_register(
            trona_kernel::core_types::CapRef::flat(attach.callback_watch),
            trona_kernel::core_types::CapRef::flat(attach.callback_recv),
            trona_kernel::core_types::CapRef::flat(state.owner_eq.as_raw()),
            uapi::KERNITE_STATE_READABLE as u64,
            cookie,
        );
        if watch_err != 0 {
            // Watch arming failed — keep the arena slot reusable
            // and preserve its wait_q allocation. No completion
            // can quote this epoch yet because the callback watch
            // never armed.
            //
            // send_cap (backend_ep) is owned by the session now: take it out of
            // the slot BEFORE reset_backend_session_after_teardown and drop it
            // here so the cap is freed exactly once on this watch-arm failure.
            if let Some(slot) = state.backend_sessions.get_mut(handle) {
                let send = core::mem::replace(&mut slot.send_cap, OwnedCap::null());
                drop(send);
                reset_backend_session_after_teardown(slot);
            }
            return None;
        }
    }
    Some(slot_idx)
}

/// Stamp the per-mount-instance SHM region descriptors onto the
/// slot. Pure metadata — no kernel call. Caller is responsible for
/// the MO cap lifetime; on session tear_down the slot's MO field
/// is `cnode_delete`d in step 4.
pub(crate) fn set_backend_session_shm_region(
    state: &mut crate::owner::VfsState,
    slot_idx: u32,
    region_mo: Cap,
    region_va: u64,
    region_bytes: u64,
) -> bool {
    let Some(handle) = state.backend_sessions.handle_from_slot(slot_idx) else {
        return false;
    };
    let Some(slot) = state.backend_sessions.get_mut(handle) else {
        return false;
    };
    // SAFETY: region_mo is the readdir SHM region MO cap received into a global
    // slot, solely owned by this session slot.
    slot.readdir_shm_region_mo = unsafe { OwnedCap::adopt_received(region_mo) };
    slot.readdir_shm_region_va = region_va;
    slot.readdir_shm_region_bytes = region_bytes;
    true
}

// ---------------------------------------------------------------------------
// Default-mount session lookups
// ---------------------------------------------------------------------------
//
// The path-less syscalls (`socket(2)` for AF_INET / AF_INET6, the
// pty open for /dev/ptmx, the framebuffer ioctl path) cannot
// resolve a backend session through the namei walker — the call
// has no path to walk. Instead they consult a *default mount*
// stamped onto `VfsState` either by an explicit mount call or by
// the lazy first-use attach below:
//
//   * `default_inet_mount` — mount handle owning AF_INET /
//     AF_INET6 sockets. Set when init mounts an `inet` provider.
//   * `default_pty_mount` — mount handle owning /dev/pts.
//   * `default_fb_mount` — mount handle owning the framebuffer.
//
// Each helper resolves the matching mount entry's
// `backend_session_idx`, validates the slot's `live_gen`, and
// returns the typed `BackendSessionHandle`. A missing or torn-down
// session is reattached via namesrv lookup when the backend is
// available; otherwise callers see `VfsError::SessionTornDown` and
// route the matching POSIX errno (`EAFNOSUPPORT` / `ENXIO` /
// `ENODEV`).

fn session_handle_for_mount(
    state: &crate::owner::VfsState,
    mount_h: MountHandle,
) -> Result<BackendSessionHandle, VfsError> {
    if !mount_h.is_valid() {
        return Err(VfsError::SessionTornDown);
    }
    let session_idx = state
        .mounts
        .get(mount_h)
        .map(|m| m.backend_session_idx)
        .ok_or(VfsError::SessionTornDown)?;
    if session_idx == u32::MAX {
        return Err(VfsError::SessionTornDown);
    }
    state
        .backend_sessions
        .handle_from_slot(session_idx)
        .and_then(|handle| {
            state
                .backend_sessions
                .get(handle)
                .filter(|slot| !slot.is_empty())
                .map(|_| handle)
        })
        .ok_or(VfsError::SessionTornDown)
}

#[inline]
fn mount_handle_to_raw(mh: MountHandle) -> u64 {
    ((mh.slot() as u64) << 32) | (mh.epoch() as u64)
}

fn ensure_default_backend_session(
    state: &mut crate::owner::VfsState,
    current: MountHandle,
    kind: MountKind,
    backend_name: &[u8],
    completion_fn: CompletionFn,
) -> Result<(MountHandle, BackendSessionHandle), VfsError> {
    if let Ok(session) = session_handle_for_mount(state, current) {
        return Ok((current, session));
    }

    let Some(backend_ep) =
        trona_runtime::client::lazy_resolve::namesrv_lookup_blocking(backend_name)
    else {
        return Err(VfsError::SessionTornDown);
    };

    let fs_id = state.next_fs_instance_id();
    let Some(mount_h) = state.mounts.alloc() else {
        // `backend_ep` (OwnedCap) drops here, freeing the cap.
        return Err(VfsError::NoMem);
    };
    if let Some(mount) = state.mounts.get_mut(mount_h) {
        *mount = Mount::EMPTY;
        mount.kind = kind;
        mount.fs_instance_id = fs_id;
        mount.mount_flags = 0;
    }

    let mount_handle_raw = mount_handle_to_raw(mount_h);
    let outcome = match unsafe {
        attach_backend_session(
            state,
            backend_ep,
            fs_id,
            mount_handle_raw,
            0,
            completion_fn,
            None,
            None,
            None,
        )
    } {
        Ok(o) => o,
        Err(e) => {
            // `backend_ep` was moved into attach_backend_session, which frees it
            // on its own failure paths; nothing to release here.
            state.mounts.release(mount_h);
            return Err(e);
        }
    };

    if let Some(mount) = state.mounts.get_mut(mount_h) {
        mount.backend_session_idx = outcome.slot_idx;
    }
    let Some(session) = state.backend_sessions.handle_from_slot(outcome.slot_idx) else {
        tear_down(state, outcome.slot_idx);
        state.mounts.release(mount_h);
        return Err(VfsError::SessionTornDown);
    };
    Ok((mount_h, session))
}

/// Resolve or lazily attach the inet default backend session.
pub(crate) fn default_inet_session(
    state: &mut crate::owner::VfsState,
) -> Result<BackendSessionHandle, VfsError> {
    let current = state.default_inet_mount;
    let (mount_h, session) = ensure_default_backend_session(
        state,
        current,
        MountKind::Inet,
        b"netsrv",
        crate::owner::net_completion::netsrv_completion,
    )?;
    state.default_inet_mount = mount_h;
    Ok(session)
}

/// Resolve or lazily attach the PTY default backend session.
pub(crate) fn default_pty_session(
    state: &mut crate::owner::VfsState,
) -> Result<BackendSessionHandle, VfsError> {
    let current = state.default_pty_mount;
    let (mount_h, session) = ensure_default_backend_session(
        state,
        current,
        MountKind::Pty,
        b"posix_ttysrv",
        crate::owner::pty_completion::pty_completion,
    )?;
    state.default_pty_mount = mount_h;
    Ok(session)
}

/// Return the default pty backend session **only if it is already
/// established + live**; never establishes one (no blocking namesrv
/// lookup / `BACKEND_OPEN_SESSION`). Best-effort consumers — the ctty
/// binding dump for `/proc` / `kern.proc.*` reads — must use this rather
/// than [`default_pty_session`]: establishing posix_ttysrv synchronously
/// from an enrichment read would block the VFS reactor during boot (the
/// first such read, before any real pty op, while ttysrv is itself still
/// coming up). Session lifecycle stays driven by real pty I/O; the dump
/// is a passive consumer of a live session.
pub(crate) fn existing_default_pty_session(
    state: &crate::owner::VfsState,
) -> Option<BackendSessionHandle> {
    session_handle_for_mount(state, state.default_pty_mount).ok()
}

/// Resolve or lazily attach the framebuffer default backend session.
pub(crate) fn default_fb_session(
    state: &mut crate::owner::VfsState,
) -> Result<BackendSessionHandle, VfsError> {
    let current = state.default_fb_mount;
    let (mount_h, session) = ensure_default_backend_session(
        state,
        current,
        MountKind::Fb,
        b"dispdrv",
        crate::owner::fb_completion::fb_completion,
    )?;
    state.default_fb_mount = mount_h;
    Ok(session)
}

// ---------------------------------------------------------------------------
// BACKEND_OPEN_SESSION negotiation
// ---------------------------------------------------------------------------

/// VFS-side cap on the negotiated `inflight_max`. Caps the backend's
/// requested ceiling so a misbehaving (or hostile) daemon cannot drive
/// vfs's per-session credit beyond a sane bound. Sized for typical
/// mixed metadata + bulk traffic — saltyfs daemon advertises 32-64 in
/// practice.
pub(crate) const BACKEND_INFLIGHT_CEILING: u32 = 64;

/// Outcome of a successful [`attach_backend_session`] negotiation.
/// Carries the slot index for the caller to stamp onto the mount entry
/// plus the backend-advertised feature bits so the caller can issue
/// SHM / pager follow-ups when the backend declares those capabilities.
/// `session_id` is the vfs-chosen id that was forwarded to the backend
/// in the `BACKEND_OPEN_SESSION` request and stamped on the slot —
/// callers that maintain a per-mount mirror (`SaltyfsMountData`,
/// per-backend bookkeeping) copy this into their own state so
/// completion correlation headers stay consistent across both sides.
/// `inflight_max` is the post-cap value (the smaller of the backend's
/// advertised ceiling and the vfs-side limit).
#[derive(Clone, Copy, Debug)]
pub(crate) struct BackendAttachOutcome {
    pub slot_idx: u32,
    pub feature_bits: u64,
    pub session_id: u32,
    pub inflight_max: u32,
    /// Reply regs[2] — backend-specific session token (saltyfs uses
    /// this slot for `root_node_low`, netsrv leaves it 0). Opaque
    /// to attach itself; the caller interprets per backend.
    pub session_token: u64,
    /// Reply regs[3] — saltyfs uses for `root_ino`, netsrv / pty / fb
    /// leave 0. Opaque to attach.
    pub aux0: u64,
    /// Reply regs[4..=5] — backend-specific scalars. SHM region
    /// size hint when `BACKEND_FEATURE_SHM_TRANSFER` is set; ignored
    /// otherwise.
    pub aux1: u64,
    pub aux2: u64,
}

/// Negotiate a fresh backend session over `BACKEND_OPEN_SESSION` and
/// install it into [`VfsState::backend_sessions`].
///
/// Steps:
///   1. Allocate a `Watch` cap via the substrate `alloc_object`
///      (rsrcsrv-backed `RSRC_ALLOC(OBJ_WATCH)`).
///   2. Allocate a single CSpace slot to receive the backend's
///      `callback_recv` cap.
///   3. Arm that slot as the IPC receive destination.
///   4. `mp_call_ctx` `BACKEND_OPEN_SESSION(mount_flags)` against
///      `backend_ep`.
///   5. Validate the reply label, parse `(max_inflight, feature_bits,
///      session_token, shm_region_va_hint, shm_region_bytes)`, and
///      verify the kernel reports the carrier cap was transferred.
///   6. Cap `max_inflight` at [`BACKEND_INFLIGHT_CEILING`] so the
///      vfs-side credit budget stays bounded regardless of what the
///      backend asked for.
///   7. Build [`BackendSessionAttach`], call
///      [`alloc_backend_session_slot`], and stamp the SHM-region hint
///      if `BACKEND_FEATURE_SHM_TRANSFER` is set (the SHM region MO
///      itself arrives later via `BACKEND_SHM_SETUP`).
///
/// On any failure the helper releases every cap it allocated
/// (`callback_watch`, the receive slot, and any cap the kernel
/// installed there) plus the caller-supplied `backend_ep`, and
/// returns a typed `VfsError`. `backend_ep` is taken **by value**
/// (an `OwnedCap`): on success it is moved into the session slot and
/// freed at session tear-down; on every failure path it is freed
/// here, so the caller neither double-frees nor leaks it.
///
/// # Safety
///
/// Must run on the owner thread (the only `&mut VfsState` holder).
/// The ipc context (`crate::ipc_ctx()`) must be initialised. The
/// caller must hold `backend_ep` as a freshly-transferred cap whose
/// only outstanding reference is in vfs's CSpace at that index.
pub(crate) unsafe fn attach_backend_session(
    state: &mut crate::owner::VfsState,
    backend_ep: OwnedCap,
    fs_id: FsInstanceId,
    mount_handle_raw: u64,
    mount_flags: u64,
    completion_fn: CompletionFn,
    drain_fn: Option<DrainFn>,
    push_fn: Option<PushFn>,
    readdir_eof_fn: Option<ReaddirEofFn>,
) -> Result<BackendAttachOutcome, VfsError> {
    use trona_kernel::core_types::TronaMsg;

    let ctx = crate::ipc_ctx();
    if ctx.is_null() {
        return Err(VfsError::Io);
    }
    if backend_ep.as_raw() == 0 {
        return Err(VfsError::Inval);
    }

    // Step 0: pre-allocate the session id. The id is forwarded to
    // the backend in the OPEN_SESSION request so the daemon stores
    // it on its session record and echoes it on every completion's
    // correlation header. Without that handshake the daemon would
    // mint its own id and vfs's `BackendSessionSlot.session_id` →
    // dispatcher session-id check would mismatch the daemon's
    // header on every reply.
    let session_id = {
        let id = state.next_session_id;
        state.next_session_id = id.wrapping_add(1);
        if state.next_session_id == 0 {
            state.next_session_id = 1;
        }
        if id == 0 { 1 } else { id }
    };

    // Step 1: allocate the callback MP pair. vfs keeps the recv
    // side and transfers the send side to the backend so the
    // daemon can `MP_WRITE` async replies / events back to vfs.
    // Both sides land in vfs's CSpace at consecutive slot
    // indices; the owned wrapper ensures the rsrcsrv record is
    // freed in every error branch without manual `free_record`
    // calls.
    let mut mp = match trona_runtime::core::slot_alloc::alloc_mp_pair_owned() {
        Ok(p) => p,
        Err(_) => return Err(VfsError::NoMem),
    };

    // Step 2: allocate a fresh Watch object from rsrcsrv. The slot
    // returned holds a Watch cap with no current registration; the
    // session-slot allocator arms it over `callback_recv` once the
    // OPEN_SESSION exchange succeeds.
    let watch = match trona_runtime::core::slot_alloc::alloc_object_owned(
        uapi::KERNITE_OBJ_WATCH as u64,
        0,
    ) {
        Ok(w) => w,
        Err(_) => {
            let _ = mp.release();
            return Err(VfsError::NoMem);
        }
    };

    // Step 3: stage `callback_send` into the outbound caps[0] slot
    // so the kernel transfers it to the daemon's receive slot at
    // MP_CALL time. The daemon stores it as its callback EP and
    // uses `MP_WRITE` against it for every subsequent async reply.
    let callback_send_raw = mp.send().map(|r| r.addr()).unwrap_or(0);
    unsafe {
        trona_kernel::ipc::set_send_cap_ctx(ctx, 0, callback_send_raw);
    }

    // Step 4: BACKEND_OPEN_SESSION round-trip. regs[0] = mount
    // flags, regs[1] = session id (vfs-chosen, daemon stores it).
    let mut req = TronaMsg::default();
    req.label = trona_protocol::vfs::backend::VFS_BACKEND_OPEN_SESSION;
    req.regs[0] = mount_flags;
    req.regs[1] = session_id as u64;
    req.length = 2;
    let mut resp = TronaMsg::default();
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ctx,
            backend_ep.as_raw(),
            &raw const req,
            &raw mut resp,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    // Clear the send-cap staging slot so the next outbound IPC
    // does not accidentally re-transfer the now-consumed send cap.
    unsafe {
        trona_kernel::ipc::clear_send_caps_ctx(ctx);
    }
    if err != 0 {
        let _ = watch.release();
        let _ = mp.release();
        return Err(VfsError::Io);
    }

    // Step 5: validate reply.
    if resp.label != trona_protocol::vfs::backend::VFS_BACKEND_REPLY_OK {
        let _ = watch.release();
        let _ = mp.release();
        return Err(VfsError::from_backend_reply(resp.label));
    }
    let backend_max_inflight = resp.regs[0] as u32;
    let feature_bits = resp.regs[1];
    let session_token = resp.regs[2];
    let aux0 = resp.regs[3];
    let aux1 = resp.regs[4];
    let aux2 = resp.regs[5];

    // Step 6: cap inflight budget at vfs ceiling.
    let inflight_max = backend_max_inflight.min(BACKEND_INFLIGHT_CEILING).max(1);

    // After cap transfer the send cap belongs to the daemon's CSpace;
    // vfs's callback_send slot is empty (kernel moved the cap out on
    // MP_CALL). Take the send side out of the pair — TransferCap::drop
    // fires delete_and_free on the (now-empty) slot, which
    // is the single correct reclaim. No manual slot_free here.
    let _ = mp.take_send();

    // Extract raw values for the slot fields then forget the owned
    // wrappers — the BackendSessionSlot takes over lifetime via its
    // explicit tear_down path (which frees the record_ids).
    let callback_recv = mp.recv().map(|r| r.addr()).unwrap_or(0);
    let callback_mp_record_id = mp.record_id();
    core::mem::forget(mp);

    let callback_watch = watch.borrow().map(|r| r.addr()).unwrap_or(0);
    let callback_watch_record_id = watch.record_id();
    core::mem::forget(watch);

    // Step 7: build attach + alloc slot. Ownership of callback_recv,
    // callback_watch (raw values after the forget() calls above) and
    // send_cap (backend_ep, consumed here via into_raw) transfers to
    // alloc_backend_session_slot, which frees them on every failure path
    // (early or watch-arm) and adopts them into the slot on success.
    // record_ids are plain integers; the caller retains responsibility for
    // them.
    let attach = BackendSessionAttach {
        fs_instance_id: fs_id,
        mount_handle_raw,
        send_cap: backend_ep.into_raw(),
        callback_recv,
        callback_watch,
        callback_mp_record_id,
        callback_watch_record_id,
        inflight_max,
        completion_fn,
        drain_fn,
        push_fn,
        readdir_eof_fn,
    };
    let slot_idx = match unsafe { alloc_backend_session_slot(state, attach, session_id) } {
        Some(i) => i,
        None => {
            // alloc_backend_session_slot freed callback_recv, callback_watch,
            // and send_cap on every failure path. Only the rsrcsrv record IDs
            // (plain integers, not caps) remain here.
            let _ = trona_runtime::core::slot_alloc::free_record(callback_watch_record_id);
            let _ = trona_runtime::core::slot_alloc::free_record(callback_mp_record_id);
            return Err(VfsError::NoMem);
        }
    };

    Ok(BackendAttachOutcome {
        slot_idx,
        feature_bits,
        session_id,
        inflight_max,
        session_token,
        aux0,
        aux1,
        aux2,
    })
}

/// Tell the backend about a SHM region the caller has already
/// allocated through mmsrv (`MM_SHM_CREATE` + `MM_SHM_MAP` into
/// vfs's own vspace). The daemon receives the `shm_idx` plus a cap
/// copy and runs its own self-tier `MM_SHM_MAP` so both sides of
/// the wire end up looking at the same backing.
///
/// The reply is a typed ack — `VFS_BACKEND_REPLY_OK` on success.
/// The cap is the authority; the numeric index is only the mmsrv
/// registry selector used for bounds and lifecycle accounting.
///
/// vfs's own SHM lifecycle (the master `shm_id`, the vfs-side
/// vaddr) lives on the per-mount data structure (e.g.
/// `SaltyfsMountData.shm_vaddr`), not on `BackendSessionSlot`;
/// session-level teardown leaves SHM destruction to the per-mount
/// teardown helper so a backend kind that does not use SHM does
/// not pay the ID-tracking cost.
pub(crate) unsafe fn attach_session_shm_setup(
    state: &mut crate::owner::VfsState,
    slot_idx: u32,
    shm_id: u64,
    cap: trona_runtime::core::slot_alloc::TransferCap,
    shm_vaddr: u64,
    shm_size: u64,
) -> Result<(), VfsError> {
    use trona_kernel::core_types::TronaMsg;

    if shm_id == 0 || shm_size == 0 {
        return Err(VfsError::Inval);
    }
    let send_cap = state
        .backend_sessions
        .handle_from_slot(slot_idx)
        .and_then(|h| state.backend_sessions.get(h))
        .map(|s| s.send_cap.as_raw())
        .ok_or(VfsError::SessionTornDown)?;
    if send_cap == 0 {
        return Err(VfsError::SessionTornDown);
    }
    let ctx = crate::ipc_ctx();
    if ctx.is_null() {
        return Err(VfsError::Io);
    }

    let mut req = TronaMsg::default();
    req.label = trona_protocol::vfs::backend::VFS_BACKEND_SHM_SETUP;
    req.regs[0] = shm_id;
    req.regs[1] = shm_size;
    req.length = 2;
    let mut resp = TronaMsg::default();
    // `cap` is consumed by the send (moved to the daemon); its drop at
    // the end of this function reclaims the staged slot. The caller keeps
    // the master `shm_cap` (passing a `dup_for_transfer`) for release.
    unsafe {
        trona_kernel::ipc::set_send_cap_ctx(ctx, 0, cap.slot());
    }
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ctx,
            send_cap,
            &raw const req,
            &raw mut resp,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        return Err(VfsError::Io);
    }
    if resp.label != trona_protocol::vfs::backend::VFS_BACKEND_REPLY_OK {
        return Err(VfsError::from_backend_reply(resp.label));
    }

    // Stamp the vfs-side vaddr / size on the session slot as a hint
    // for completion routers; the MO cap field stays zero since the
    // SHM region is identified by `shm_id` rather than a transferable
    // capability.
    let _ = set_backend_session_shm_region(state, slot_idx, 0, shm_vaddr, shm_size);
    Ok(())
}
