// SPDX-License-Identifier: GPL-2.0-only
//! Win32 per-client current-drive + per-drive CWD sidecar.
//!
//! Keeps Win32-specific state out of `server::types::ClientState`.
//! The generic `ClientState` used to carry `win32_current_drive: u8`
//! plus `win32_drive_cwd: [VnodeKey; 26]` directly; this module owns
//! those fields and exposes a per-`ClientHandle` accessor so the
//! generic server layer no longer needs to know about Win32 drive
//! letters.
//!
//! Shape: a fixed-size linear-scan table keyed by
//! [`crate::server::types::ClientHandle`]. Clients register an entry
//! on spawn (Win32 personality only) and deregister on exit; lookups
//! cost an O(MAX_WIN32_CLIENTS) compare-against-slot scan, which is
//! trivial given the cap. No heap allocation.

use crate::server::types::ClientHandle;
use crate::vfs_core::identity::VnodeKey;

/// Maximum simultaneous Win32 clients. Sized above the initial
/// `INITIAL_CLIENTS = 16` cap so short-lived connection churn
/// doesn't evict live sessions; Win32 on SaltyOS is not expected to
/// sustain large client pools.
pub(crate) const MAX_WIN32_CLIENTS: usize = 64;

/// Per-client Win32 CWD state. All-`INVALID` `drive_cwd` entries
/// mean "no cwd set for that drive letter" — path resolution falls
/// back to the drive's mount root in that case.
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct Win32CwdEntry {
    /// Owning client. `ClientHandle::INVALID` marks a free slot in
    /// the surrounding table.
    pub(crate) client: ClientHandle,
    /// Currently-active drive letter index (0 = A, 25 = Z).
    pub(crate) current_drive: u8,
    _pad: [u8; 7],
    /// Per-drive CWD as a stable `VnodeKey`. 26 entries indexed by
    /// drive letter. Stored by identity rather than handle so arena
    /// churn does not invalidate the reference.
    pub(crate) drive_cwd: [VnodeKey; 26],
}

impl Win32CwdEntry {
    const fn empty() -> Self {
        Win32CwdEntry {
            client: ClientHandle::INVALID,
            current_drive: 0,
            _pad: [0; 7],
            drive_cwd: [VnodeKey::INVALID; 26],
        }
    }
}

/// Fixed-size sidecar table.
#[repr(C)]
pub(crate) struct Win32CwdTable {
    entries: [Win32CwdEntry; MAX_WIN32_CLIENTS],
}

impl Win32CwdTable {
    /// Build an all-empty table. Used by `VfsState::new`.
    pub(crate) const fn zeroed() -> Self {
        Win32CwdTable {
            entries: [Win32CwdEntry::empty(); MAX_WIN32_CLIENTS],
        }
    }

    /// Register a freshly-spawned Win32 client. Idempotent — calling
    /// twice for the same client is a no-op (returns `Ok` the second
    /// time). Returns `Err(())` only when the table is full, in
    /// which case the caller should log and let the client fall
    /// back to drive-letter-free POSIX-style resolution.
    pub(crate) fn register(&mut self, client: ClientHandle) -> Result<(), ()> {
        if !client.is_valid() {
            return Err(());
        }
        // Idempotent — scan first.
        if self.find_slot(client).is_some() {
            return Ok(());
        }
        for slot in self.entries.iter_mut() {
            if !slot.client.is_valid() {
                *slot = Win32CwdEntry::empty();
                slot.client = client;
                return Ok(());
            }
        }
        Err(())
    }

    /// Drop the entry for a torn-down client. No-op if the client
    /// was not Win32 (and therefore not registered).
    pub(crate) fn deregister(&mut self, client: ClientHandle) {
        if let Some(idx) = self.find_slot(client) {
            self.entries[idx] = Win32CwdEntry::empty();
        }
    }

    /// Locate an entry by client handle. Linear scan; the table is
    /// small by construction.
    #[inline]
    fn find_slot(&self, client: ClientHandle) -> Option<usize> {
        if !client.is_valid() {
            return None;
        }
        for (i, slot) in self.entries.iter().enumerate() {
            if slot.client == client {
                return Some(i);
            }
        }
        None
    }

    /// Shared reference to a client's CWD state; `None` when the
    /// client is not Win32 / not registered.
    pub(crate) fn get(&self, client: ClientHandle) -> Option<&Win32CwdEntry> {
        self.find_slot(client).map(|i| &self.entries[i])
    }

    /// Exclusive reference to a client's CWD state.
    pub(crate) fn get_mut(&mut self, client: ClientHandle) -> Option<&mut Win32CwdEntry> {
        let idx = self.find_slot(client)?;
        Some(&mut self.entries[idx])
    }

    /// Clear every `drive_cwd` entry for a client without changing
    /// `current_drive` — used by `chroot` / `pivot_root` semantics
    /// where the per-drive CWDs become meaningless under the new
    /// root but the current drive letter is preserved.
    pub(crate) fn reset_drive_cwds(&mut self, client: ClientHandle) {
        if let Some(slot) = self.get_mut(client) {
            slot.drive_cwd = [VnodeKey::INVALID; 26];
        }
    }
}

unsafe impl Sync for Win32CwdTable {}
