// SPDX-License-Identifier: GPL-2.0-only
//
//! `ClientState` — per-client bookkeeping.
//!
//! One `ClientState` per registered process. Stored in
//! `VfsState.clients` (an `Arena<ClientState>`). Identity is the
//! 32-bit `client_id` minted into the lower half of the master
//! service-EP send-cap badge by namesrv. The full 64-bit badge is
//! retained too; the upper 32 bits encode publisher class +
//! policy id and are never inspected by vfs (the personality layer
//! doesn't care).
//!
//! The fd-table lives in [`SegmentedSlotTable`] so the table grows
//! without a fixed cap as the client opens more files.

use crate::arena::segmented_slot_table::SegmentedSlotTable;
use crate::core::cred::VfsCred;
use crate::owner::client_shm::ClientShmHandle;
use crate::personality::Personality;
use crate::server::open_object::OpenObject;
use trona_protocol::control;
use trona_runtime::core::slot_alloc::{OwnedMpPair, OwnedRecordedCap};

/// Client lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientLifeState {
    /// Slot has not been populated yet.
    Empty = 0,
    /// Live — accepting requests.
    Active = 1,
    /// `PEER_CLOSED` arrived; no new requests, drain in-flight ops
    /// then teardown.
    Closing = 2,
}

#[repr(C)]
pub(crate) struct ClientState {
    pub state: ClientLifeState,
    /// `client_id` from the badge lower 32 bit. Stable for the
    /// life of the client process.
    pub client_id: u32,
    /// Full 64-bit badge as observed on the inbound MP record.
    /// Used by the cancel-on-PEER_CLOSED sweep to find every
    /// PendingOp whose `client_badge` matches.
    pub client_badge: u64,
    /// Control-cap epoch assigned at init-driven register — the dedicated
    /// per-slot reuse counter's value at that time, carried so
    /// [`resolve_control`] can match a presented control-cap badge. `0`
    /// means this client is not control-registered (a lazily-bound client
    /// init never registered), so no control cap resolves against it.
    pub control_epoch: u64,
    /// Per-client request MessagePipe pair owned by vfs.
    /// `send` is retained for re-bind; `recv` is the watched endpoint.
    /// `None` until the client calls `VFS_BIND_CLIENT_SELF`.
    pub request_mp: Option<OwnedMpPair>,
    /// EQ Watch armed over `request_mp.recv`'s `STATE_READABLE`,
    /// keyed by the cookie that the main reactor populated.
    /// `None` until bound.
    pub watch: Option<OwnedRecordedCap>,
    pub watch_cookie: u64,
    /// Client arena slot encoded into `watch_cookie`, retained for
    /// diagnostics and explicit teardown.
    pub cookie_slot: u32,
    /// fd-table. Grows segment-by-segment as the client allocates
    /// fds; no fixed cap.
    pub slot_table: SegmentedSlotTable<OpenObject>,
    /// Owner mount-namespace handle (set when `register_client`
    /// pulls the inherited namespace from init's spawn-time wire).
    /// `0` = uninitialised.
    pub mount_ns_slot: u32,
    /// Process working-directory vnode slot — populated via
    /// `chdir` / `fork` inheritance.
    pub cwd_vnode_slot: u32,
    pub cwd_vnode_epoch: u32,
    /// Cached absolute path string for the cwd. Backs `getcwd(2)`
    /// without requiring a backend reverse-walk: every `chdir`
    /// canonicalises its argument against the previous cwd path
    /// and writes the result here. The buffer is bounded by
    /// `WALK_PATH_MAX` to fit a single `regs[]` payload on the
    /// `getcwd` reply.
    pub cwd_path: [u8; crate::owner::pending::WALK_PATH_MAX],
    pub cwd_path_len: u16,
    /// Bulk-transfer SHM region handle. `INVALID` until the
    /// client calls `VFS_REGISTER_BULK_SHM`; thereafter the
    /// region is shared between vfs and the client and serves
    /// every read / write in SHM mode. Released on
    /// `VFS_RELEASE_BULK_SHM` or on client teardown.
    pub bulk_shm: ClientShmHandle,
    /// Credential snapshot known to vfs for this client. The badge
    /// registration path currently starts at root; init/exec will
    /// stamp process credentials here once the lifecycle wire grows
    /// an explicit credential handoff.
    pub cred: VfsCred,
    /// Personality discriminator stamped at register time. The
    /// frontend dispatcher routes inbound labels through the
    /// matching personality entry — POSIX (`personality::posix`)
    /// for labels in `0x500..=0x53F`, Win32 (`personality::win32`)
    /// for `0x540..=0x57F`, neutral posix for
    /// `0x580..=0x5BF`. A label whose range does not match this
    /// field is rejected with `EINVAL`.
    pub personality: Personality,
}

impl ClientState {
    pub(crate) const EMPTY: Self = Self {
        state: ClientLifeState::Empty,
        client_id: 0,
        client_badge: 0,
        control_epoch: 0,
        request_mp: None,
        watch: None,
        watch_cookie: 0,
        cookie_slot: u32::MAX,
        slot_table: SegmentedSlotTable::new(),
        mount_ns_slot: u32::MAX,
        cwd_vnode_slot: u32::MAX,
        cwd_vnode_epoch: 0,
        cwd_path: [0u8; crate::owner::pending::WALK_PATH_MAX],
        cwd_path_len: 0,
        bulk_shm: ClientShmHandle::INVALID,
        cred: VfsCred::root(),
        personality: Personality::DEFAULT,
    };

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        matches!(self.state, ClientLifeState::Empty)
    }

    #[inline]
    pub(crate) fn is_active(&self) -> bool {
        matches!(self.state, ClientLifeState::Active)
    }

    /// Raw slot address of the request-MP recv side, or `0` if not yet bound.
    #[inline]
    pub(crate) fn request_mp_recv_addr(&self) -> u64 {
        self.request_mp
            .as_ref()
            .and_then(|p| p.recv())
            .map(|r| r.addr())
            .unwrap_or(0)
    }

    /// Raw slot address of the request-MP send side, or `0` if not yet bound.
    #[inline]
    pub(crate) fn request_mp_send_addr(&self) -> u64 {
        self.request_mp
            .as_ref()
            .and_then(|p| p.send())
            .map(|s| s.addr())
            .unwrap_or(0)
    }

    /// Raw slot address of the watch cap, or `0` if not yet bound.
    #[inline]
    pub(crate) fn watch_cap_addr(&self) -> u64 {
        self.watch
            .as_ref()
            .and_then(|w| w.borrow())
            .map(|r| r.addr())
            .unwrap_or(0)
    }
}

use crate::owner::VfsState;
use crate::server::types::ClientHandle;

/// Resolve `badge` to a live `ClientHandle`, lazily inserting a
/// new `ClientState` slot if this is the caller's first observed
/// RPC. Returns `None` only on arena exhaustion or BadgeMap
/// failure — both of which collapse the dispatcher's reply path
/// into an Io error to the caller.
///
/// The resolution path:
/// 1. `BadgeMap::get(badge)` — O(1) lookup by full 64-bit badge.
///    Hits skip the arena scan entirely.
/// 2. On miss, allocate a fresh `ClientState` slot, populate
///    `client_id` / `client_badge`, and register
///    `(badge → handle)` into the BadgeMap.
///
/// fd-table / mount-namespace / cwd remain at their `EMPTY`
/// sentinels until the first explicit chdir / register_client
/// path populates them.
pub(crate) fn ensure_client(
    state: &mut VfsState,
    badge: u64,
    client_id: u32,
) -> Option<ClientHandle> {
    if let Some((slot, epoch)) = state.badge_map.lookup(badge) {
        let handle = ClientHandle::new(slot, epoch);
        if state
            .clients
            .get(handle)
            .map(|c| !c.is_empty() && c.is_active())
            .unwrap_or(false)
        {
            return Some(handle);
        }
        state.badge_map.remove(badge);
    }
    let handle = state.clients.alloc()?;
    if let Some(slot) = state.clients.get_mut(handle) {
        *slot = ClientState::EMPTY;
        slot.state = ClientLifeState::Active;
        slot.client_id = client_id;
        slot.client_badge = badge;
        slot.cred = VfsCred::zeroed();
    }
    if state
        .badge_map
        .insert(badge, handle.slot(), handle.epoch())
        .is_err()
    {
        // BadgeMap insertion only fails on grow exhaustion. Roll back
        // the arena allocation so the slot remains free for the next
        // attempt — leaking it would slowly bleed the client arena
        // across stress testing.
        state.clients.release(handle);
        return None;
    }
    Some(handle)
}

/// Tear down a client whose master MP receive side has signalled
/// `PEER_CLOSED`. Cancels every PendingOp whose saved
/// `client_badge` matches, releases the fd-table, drops the
/// BadgeMap entry, marks the slot Empty for arena recycling.
///
/// PendingOp cancellation is non-destructive — the kernel reply
/// token is dropped (so the absent caller's reply path no longer
/// races with the queued handler) but in-flight backend ops
/// continue to completion so credit / ordering invariants hold.
/// The completion router observes `cancelled = 1` and skips the
/// reply send while still releasing the credit + slot.
pub(crate) fn remove_client(state: &mut VfsState, handle: ClientHandle) {
    // Capture whether this is a control-registered client before teardown
    // zeroes its state, so its dedicated per-slot control epoch is bumped
    // afterwards (a stale control cap then fails the epoch check on reuse).
    let control_slot = state
        .clients
        .get(handle)
        .filter(|c| c.control_epoch != 0)
        .map(|_| handle.slot());
    cancel_for_client(state, handle);
    crate::personality::win32::lifecycle::drop_client_state(state, handle);
    // Release the bulk SHM region — mmsrv backing destroy + arena
    // slot reclaim + ClientState handle reset all run under the
    // same teardown sweep so no SHM book-keeping survives client
    // disconnect.
    unsafe {
        crate::owner::client_shm::release_for_client(state, handle);
    }
    crate::ops::close::release_all_fds(state, handle);
    if let Some(cli) = state.clients.get_mut(handle) {
        let badge = cli.client_badge;
        cli.state = ClientLifeState::Closing;
        // Tombstone the BadgeMap entry first so concurrent badge
        // resolves return None (and the dispatcher rejects the
        // reused badge as stale).
        state.badge_map.remove(badge);
        // Cancel the watch before releasing the MP pair — the kernel
        // deregisters the watch from the EQ so no stale STATE_READABLE
        // record for this client can land in the reactor after teardown.
        if let Some(w) = cli.watch.as_ref().and_then(|w| w.borrow()) {
            let _ = trona_kernel::invoke::watch_cancel(w);
        }
        // release_in_place frees each OwnedCap and the rsrcsrv records.
        if let Some(w) = cli.watch.as_mut() {
            let _ = w.release_in_place();
        }
        if let Some(mp) = cli.request_mp.as_mut() {
            let _ = mp.release_in_place();
        }
        // Reset non-zero sentinels (`fd_table.free_list_head`,
        // `bulk_shm`, cwd slots, etc.) before the arena recycles
        // the slot. `Arena::alloc` zeroes raw memory, so the
        // typed empty state must be restored explicitly.
        *cli = ClientState::EMPTY;
        cli.state = ClientLifeState::Empty;
    }
    state.clients.release(handle);
    // Bump the dedicated per-slot control epoch and drop any pending clone
    // naming this slot, so a stale control cap and a half-driven two-step
    // transaction both fail closed once the slot is reused.
    if let Some(slot) = control_slot {
        bump_control_epoch_for_slot(state, slot);
        clear_admin_partner_naming(state, slot);
    }
}

/// Walk every active PendingOp for `client_handle` and cancel it
/// terminally — `pending::cancel_for_badge` unparks each saved
/// reply lease, drops it through the kernel finaliser, and
/// releases the arena slot. Backend in-flight ops still settle
/// against credit / ordering through their session callback, but
/// any reply that lands after cancellation finds the arena slot
/// gone and is dropped by `dispatch_pending_reply`'s
/// `find_pending_op` miss.
///
/// Called from `remove_client` (PEER_CLOSED) and from explicit
/// teardown paths (e.g. an exec replacing the address space and
/// discarding the previous fd-table's in-flight reads). For
/// callers that hold the badge but not the handle (the deferred-
/// issue teardown path), invoke `crate::owner::pending::
/// cancel_for_badge` directly.
pub(crate) fn cancel_for_client(state: &mut VfsState, client_handle: ClientHandle) {
    let badge = match state.clients.get(client_handle) {
        Some(c) => c.client_badge,
        None => return,
    };
    crate::owner::pending::cancel_for_badge(state, badge);
}

// ===========================================================================
// Control-capability authorization (init-driven admin verbs).
// ===========================================================================

/// Single-slot pending secondary operand for the two-step admin clone: the
/// child is pinned by `VFS_ADMIN_CLONE_SET_PARTNER`, then the parent drives
/// `VFS_ADMIN_CLONE_FDS`. init is the sole serial driver, so one slot
/// suffices.
#[derive(Clone, Copy)]
pub(crate) struct ControlPending {
    pub active: bool,
    pub secondary_slot: u32,
    pub secondary_epoch: u64,
    pub nonce: u64,
}

impl ControlPending {
    pub(crate) const EMPTY: Self = Self {
        active: false,
        secondary_slot: 0,
        secondary_epoch: 0,
        nonce: 0,
    };
}

/// Read the control-cap epoch to assign to a fresh init-driven registration
/// at arena `slot`, extending the dedicated side table to cover the slot if
/// needed. Returns `0` only on allocation failure (the caller fails the
/// register). The side table persists across slot reuse — distinct from the
/// `ClientState` the arena zeroes — so consecutive registrations at one slot
/// mint strictly different epochs.
pub(crate) fn control_epoch_for_slot(state: &mut VfsState, slot: u32) -> u64 {
    while state.client_control_epochs.len() <= slot {
        let mut alloc = crate::arena::segmented_array::MmapAllocator::new();
        if unsafe { state.client_control_epochs.push(1u64, &mut alloc) }.is_err() {
            return 0;
        }
    }
    state.client_control_epochs.get(slot).copied().unwrap_or(1)
}

/// Bump the per-slot control-cap epoch so the next registration at `slot`
/// mints a fresh badge — called when a control-registered client is torn
/// down, so a stale control cap fails the epoch check once the slot reuses.
pub(crate) fn bump_control_epoch_for_slot(state: &mut VfsState, slot: u32) {
    if let Some(e) = state.client_control_epochs.get_mut(slot) {
        *e = control::next_epoch(*e);
    }
}

/// Resolve a presented control-cap badge to the live `ClientHandle` it names,
/// or `None` if the tag is wrong, it is the ROOT cap, the slot is not a live
/// Active client, or the client's `control_epoch` no longer matches. This is
/// both the authorization (only init holds control caps) and the target
/// identity for every per-client VFS admin verb — no trusted `client_id`
/// argument is consulted. `handle_from_slot` only reconstructs the handle;
/// the subsequent `get` is the gate (it rejects a non-Active arena slot, so a
/// released-but-unswept or retired slot fails closed), and the
/// `control_epoch` match is the ABA guard.
pub(crate) fn resolve_control(state: &VfsState, badge: u64) -> Option<ClientHandle> {
    if !control::tag_matches(badge) || control::is_root(badge) {
        return None;
    }
    let slot = control::slot_of(badge) as u32;
    let handle = state.clients.handle_from_slot(slot)?;
    let c = state.clients.get(handle)?;
    if c.control_epoch == 0 || c.control_epoch != control::epoch_of(badge) || !c.is_active() {
        return None;
    }
    Some(handle)
}

/// Record the child (secondary) operand of the two-step clone, capturing its
/// control epoch for the consume-time ABA re-check. Overwrites any stale
/// pending — a fresh transaction supersedes an orphaned one.
pub(crate) fn set_admin_partner(state: &mut VfsState, secondary: ClientHandle, nonce: u64) {
    let control_epoch = state
        .clients
        .get(secondary)
        .map(|c| c.control_epoch)
        .unwrap_or(0);
    state.admin_clone_pending = ControlPending {
        active: true,
        secondary_slot: secondary.slot(),
        secondary_epoch: control_epoch,
        nonce,
    };
}

/// Consume the pending child for `nonce`. Always clears the pending slot
/// (consume-once = replay guard). Returns the child's live handle only if the
/// pending is active, the nonce matches, and the child is still a live control
/// client at its captured epoch (ABA guard).
pub(crate) fn consume_admin_partner(state: &mut VfsState, nonce: u64) -> Option<ClientHandle> {
    let pending = core::mem::replace(&mut state.admin_clone_pending, ControlPending::EMPTY);
    if !pending.active || pending.nonce != nonce {
        return None;
    }
    let handle = state.clients.handle_from_slot(pending.secondary_slot)?;
    let c = state.clients.get(handle)?;
    if c.control_epoch == 0 || c.control_epoch != pending.secondary_epoch || !c.is_active() {
        return None;
    }
    Some(handle)
}

/// Clear any pending child naming `slot` — called when that client is torn
/// down so a later operate step cannot consume a dead operand.
pub(crate) fn clear_admin_partner_naming(state: &mut VfsState, slot: u32) {
    if state.admin_clone_pending.active && state.admin_clone_pending.secondary_slot == slot {
        state.admin_clone_pending = ControlPending::EMPTY;
    }
}

/// Create the pre-bound `ClientState` for an init-driven registration: a live
/// Active entry keyed by `client_id` with the badge unset and absent from the
/// badge map (the child inserts it later when it self-binds), carrying a fresh
/// control epoch. Returns the handle so the caller can mint the control cap;
/// `None` on arena or side-table exhaustion.
pub(crate) fn create_control_client(
    state: &mut VfsState,
    client_id: u32,
    pid: u32,
) -> Option<ClientHandle> {
    let handle = state.clients.alloc()?;
    let epoch = control_epoch_for_slot(state, handle.slot());
    if epoch == 0 {
        state.clients.release(handle);
        return None;
    }
    if let Some(slot) = state.clients.get_mut(handle) {
        *slot = ClientState::EMPTY;
        slot.state = ClientLifeState::Active;
        slot.client_id = client_id;
        slot.control_epoch = epoch;
        slot.cred = VfsCred::zeroed();
        slot.cred.pid = pid;
    }
    Some(handle)
}

/// Bind-adoption: find an init-pre-created, not-yet-bound control client whose
/// `client_id` matches the badge low bits and adopt it — stamp the real badge
/// and insert it into the badge map so the pre-created entry (already carrying
/// any cloned FD table) and the child's self-bind converge on one slot.
/// Returns the adopted handle, or `None` when there is no such entry (the
/// caller falls back to the lazy first-bind path).
pub(crate) fn adopt_precreated_by_client_id(
    state: &mut VfsState,
    badge: u64,
    client_id: u32,
) -> Option<ClientHandle> {
    let mut found = None;
    state.clients.for_each_active(|h, c| {
        if c.control_epoch != 0 && c.client_badge == 0 && c.client_id == client_id {
            found = Some(h);
            false
        } else {
            true
        }
    });
    let handle = found?;
    if let Some(c) = state.clients.get_mut(handle) {
        c.client_badge = badge;
    }
    if state
        .badge_map
        .insert(badge, handle.slot(), handle.epoch())
        .is_err()
    {
        // Roll back the badge stamp so the entry stays pre-created + unbound
        // and a later retry can adopt it again.
        if let Some(c) = state.clients.get_mut(handle) {
            c.client_badge = 0;
        }
        return None;
    }
    Some(handle)
}
