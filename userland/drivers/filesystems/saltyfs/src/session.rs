// SPDX-License-Identifier: GPL-2.0-only
//
//! Multi-mount session table.
//!
//! Every `BACKEND_OPEN_SESSION` produces a [`SessionSlot`] in
//! [`SESSION_TABLE`]. Each slot owns the per-session state that
//! used to live as singletons:
//!
//! * `callback_ep` — the vfs-side `backend_callback` cap that the
//!   daemon sends correlated completions through.
//! * `shm_id` / `shm_vaddr` / `shm_bytes` — the per-session SHM
//!   ring set up by `BACKEND_SHM_SETUP`. Distinct sessions get
//!   distinct SHM regions so `TRANSFER_KIND_SHM` payloads from
//!   one session never alias another's.
//! * `session_id` — the vfs-stamped 32-bit id echoed on every
//!   correlated completion's session field.
//! * `live_gen` — bumped (`+= 2`) at session-close acceptance so
//!   queued worker jobs that captured the pre-close gen can be
//!   detected and skip side effects without sending stale
//!   completions.
//! * `max_inflight` — per-session ceiling for outstanding worker
//!   jobs; the daemon advertises `SALTYFS_MAX_INFLIGHT` today and
//!   may negotiate lower in the future.
//!
//! The daemon's superblock / cache / bitmap remain singleton —
//! a saltyfs daemon process backs exactly one disk image, so
//! multi-mount means multiple vfs sessions attached to the same
//! disk. Per-session state is the wire-facing surface only.

use trona_runtime::core::slot_alloc::OwnedCap;

/// Maximum live `BACKEND_OPEN_SESSION` slots in this saltyfs daemon.
/// Sized so that a heavily-multiplexed vfs (e.g. one frontend per
/// container, all sharing one rootfs) does not exhaust slots before
/// the underlying disk's quotas would.
pub const SALTYFS_SESSION_SLOTS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Empty,
    Live,
    Closing,
}

pub struct SessionSlot {
    pub state: SessionState,
    pub session_id: u32,
    pub live_gen: u64,
    /// vfs `backend_callback` cap. Worker direct-completion path
    /// addresses this for correlated replies. `None` when slot is
    /// `Empty`; `Some` only while `Live`. Drop calls
    /// `delete_and_free` so the slot is reclaimed on
    /// rebind (replace) and on teardown (`*slot = SessionSlot::empty()`).
    pub callback_ep: Option<OwnedCap>,
    /// Watch cookie associated with the per-session callback Watch,
    /// set at OPEN_SESSION and cancelled (`WATCH_CANCEL`) at the
    /// teardown 4-step's step 2. Zero if no watcher armed.
    #[allow(dead_code)]
    pub callback_watch: u64,
    /// Cookie passed into `WATCH_ARM` for the callback Watch.
    #[allow(dead_code)]
    pub callback_cookie: u64,
    /// mmsrv SHM id from the most recent `BACKEND_SHM_SETUP` for
    /// this session. Owned by the daemon while `state == Live`;
    /// dropped at finalize.
    pub shm_id: u64,
    /// Future MO cap for the SHM region. Zero today (the SHM is
    /// addressed via `shm_id` + `MM_SHM_MAP`); reserved for the
    /// path where `BACKEND_SHM_SETUP` transfers an MO cap directly.
    #[allow(dead_code)]
    pub shm_region_mo: u64,
    /// Daemon-side mapped VA of the SHM region. Set by
    /// `BACKEND_SHM_SETUP` after `MM_SHM_MAP`.
    pub shm_vaddr: u64,
    /// Size of the mapped SHM region in bytes.
    pub shm_bytes: u64,
    /// Per-session in-flight ceiling negotiated at OPEN_SESSION.
    pub max_inflight: u32,
}

impl SessionSlot {
    pub const fn empty() -> Self {
        Self {
            state: SessionState::Empty,
            session_id: 0,
            live_gen: 0,
            callback_ep: None,
            callback_watch: 0,
            callback_cookie: 0,
            shm_id: 0,
            shm_region_mo: 0,
            shm_vaddr: 0,
            shm_bytes: 0,
            max_inflight: 0,
        }
    }
}

pub static mut SESSION_TABLE: [SessionSlot; SALTYFS_SESSION_SLOTS] =
    [const { SessionSlot::empty() }; SALTYFS_SESSION_SLOTS];

/// Find a slot by `session_id` (only `Live` slots match).
pub fn find_live_by_id(session_id: u32) -> Option<usize> {
    if session_id == 0 {
        return None;
    }
    for i in 0..SALTYFS_SESSION_SLOTS {
        let s = unsafe { &(*(&raw const SESSION_TABLE))[i] };
        if s.state == SessionState::Live && s.session_id == session_id {
            return Some(i);
        }
    }
    None
}

/// Allocate a fresh `Empty` slot. Returns `None` if all slots are
/// `Live` or `Closing`.
pub fn alloc_slot() -> Option<usize> {
    for i in 0..SALTYFS_SESSION_SLOTS {
        let s = unsafe { &(*(&raw const SESSION_TABLE))[i] };
        if s.state == SessionState::Empty {
            return Some(i);
        }
    }
    None
}

/// Borrow a live slot mutably for handler use.
///
/// # Safety
/// Caller must hold `BLOCK_LOCK` while the returned reference is
/// live; SESSION_TABLE is shared with worker direct-completion
/// path, which does the same.
pub unsafe fn slot_mut(idx: usize) -> Option<&'static mut SessionSlot> {
    if idx >= SALTYFS_SESSION_SLOTS {
        return None;
    }
    Some(unsafe { &mut (*(&raw mut SESSION_TABLE))[idx] })
}

/// Read-only borrow.
pub fn slot(idx: usize) -> Option<&'static SessionSlot> {
    if idx >= SALTYFS_SESSION_SLOTS {
        return None;
    }
    Some(unsafe { &(*(&raw const SESSION_TABLE))[idx] })
}

/// Convenience: the single live session in capacity-1 transitional
/// mode. Returns the first `Live` slot encountered. Once multi-slot
/// is enabled, callers must pass the resolved slot index instead.
pub fn current_live() -> Option<usize> {
    for i in 0..SALTYFS_SESSION_SLOTS {
        let s = unsafe { &(*(&raw const SESSION_TABLE))[i] };
        if s.state == SessionState::Live {
            return Some(i);
        }
    }
    None
}

/// Compute the daemon-side mapped VA reserved for slot `idx`. The
/// daemon partitions its VA pool starting at the legacy
/// `VFS_SHM_VADDR` base (kept for ABI continuity), giving each slot
/// a `SALTYFS_SHM_REGION_BYTES` window. Slot 0's region matches the
/// pre-multi-slot single-region location so existing vfs frontends
/// keep working through the transition.
pub fn slot_shm_vaddr(idx: usize) -> u64 {
    crate::consts::VFS_SHM_VADDR + (idx as u64) * (crate::consts::SALTYFS_SHM_REGION_BYTES)
}

/// Resolve the live session's mapped SHM region (`(vaddr, bytes)`).
/// Returns `None` if no session is `Live` or if the slot is `Live`
/// but has not yet completed `BACKEND_SHM_SETUP` (`shm_bytes ==
/// 0`). Replaces the legacy `VFS_SHM_VADDR` / `VFS_SHM_MAPPED` /
/// `VFS_SHM_PAGES` globals — the only authoritative source of the
/// per-session SHM mapping.
pub fn live_shm_region() -> Option<(u64, u64)> {
    let idx = current_live()?;
    let s = slot(idx)?;
    if s.shm_vaddr == 0 || s.shm_bytes == 0 {
        return None;
    }
    Some((s.shm_vaddr, s.shm_bytes))
}

/// Per-message variant of [`live_shm_region`]: decode the
/// `CorrelationHeader.session` from the inbound message and resolve
/// to that session's slot. Falls back to [`current_live`] when the
/// caller did not stamp a header (legacy zero-session-id path).
pub fn live_shm_region_for_msg(msg: &trona_kernel::core_types::TronaMsg) -> Option<(u64, u64)> {
    let idx = slot_idx_for_msg(msg)?;
    let s = slot(idx)?;
    if s.shm_vaddr == 0 || s.shm_bytes == 0 {
        return None;
    }
    Some((s.shm_vaddr, s.shm_bytes))
}

/// Resolve the slot index for an inbound backend RPC message. Reads
/// the `CorrelationHeader.session` field stamped at
/// `regs[CORRELATION_HEADER_REG_START..]` and looks the matching
/// `Live` slot up in `SESSION_TABLE`. Falls back to [`current_live`]
/// for legacy zero-session callers.
pub fn slot_idx_for_msg(msg: &trona_kernel::core_types::TronaMsg) -> Option<usize> {
    use trona_protocol::correlation::{
        CORRELATION_HEADER_REG_COUNT, CORRELATION_HEADER_REG_START, CorrelationHeader,
    };
    if (msg.length as usize) < CORRELATION_HEADER_REG_START + CORRELATION_HEADER_REG_COUNT {
        return current_live();
    }
    let words = [
        msg.regs[CORRELATION_HEADER_REG_START],
        msg.regs[CORRELATION_HEADER_REG_START + 1],
        msg.regs[CORRELATION_HEADER_REG_START + 2],
        msg.regs[CORRELATION_HEADER_REG_START + 3],
    ];
    let header = CorrelationHeader::decode_words(words);
    if header.session == 0 {
        return current_live();
    }
    find_live_by_id(header.session).or_else(current_live)
}

/// Stash a freshly-captured `callback_ep` onto the current live
/// slot. Called from `BACKEND_OPEN_SESSION`'s cap-capture path
/// after `handle_mount` has installed the slot. If the slot
/// already held a callback cap (vfs restart rebind), the previous
/// cap is `cnode_delete`-d so saltyfs does not leak a dead
/// endpoint into its CSpace. Returns `true` if the slot was found
/// and updated.
/// Install a freshly-captured callback cap onto the current live slot.
/// Takes ownership of the slot identified by `raw_slot`; the old cap (if
/// any) is dropped automatically, which calls `delete_and_free`.
pub fn set_live_callback_ep(raw_slot: u64) -> bool {
    if let Some(idx) = current_live() {
        unsafe {
            if let Some(slot) = slot_mut(idx) {
                let new_cap = OwnedCap::adopt_received(raw_slot);
                // Drop old cap (cnode_delete + slot_free) before installing new one.
                slot.callback_ep = Some(new_cap);
                return true;
            }
        }
    }
    false
}
