// SPDX-License-Identifier: GPL-2.0-only
//
//! `NameEntry` — the registry's per-name record. Lives inline in the
//! `NameRegistry` open-addressed table; the cap itself lives in
//! namesrv's CSpace at `cap_slot`.

use crate::wire::MAX_NAME_BYTES;

/// Sentinel for `NameEntry::cookie_slot` meaning "no cookie-table
/// entry has been registered for this name". Set at install time
/// and after eviction; the reactor's `CookieTable::lookup`
/// rejects any cookie that decodes to this slot via the
/// `live_gen` mismatch path even if a stale cookie were to leak.
pub const COOKIE_SLOT_NONE: u32 = u32::MAX;

#[derive(Clone, Copy)]
pub struct NameEntry {
    pub name: [u8; MAX_NAME_BYTES],
    pub name_len: u8,
    pub cap_slot: u64,
    pub owner_tcb: u32,
    pub policy_id: u32,
    pub flags: u32,
    /// Index into the WatchSlab for the owner-cap close watch.
    /// `u8::MAX` when no watch has been armed yet.
    pub watch_idx: u8,
    /// Slot index in the reactor's `CookieTable` for the owner-cap
    /// close Watch's cookie. `COOKIE_SLOT_NONE` when no cookie
    /// entry exists (the WatchSlab was saturated at REGISTER time
    /// and no Watch was armed). Used by `eviction::evict_one` to
    /// route the cancel call back into the cookie table.
    pub cookie_slot: u32,
    pub generation: u32,
    pub active: u8,
}

impl NameEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_BYTES],
            name_len: 0,
            cap_slot: 0,
            owner_tcb: 0,
            policy_id: 0,
            flags: 0,
            watch_idx: u8::MAX,
            cookie_slot: COOKIE_SLOT_NONE,
            generation: 0,
            active: 0,
        }
    }

    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Pack a `(generation, idx)` pair into the 64-bit `entry_id` returned
/// to clients. Generation rotates per slot reuse so a stale `entry_id`
/// from before a re-register reliably mismatches.
pub const fn pack_entry_id(generation: u32, idx: u32) -> u64 {
    ((generation as u64) << 32) | (idx as u64)
}

pub const fn unpack_entry_id(entry_id: u64) -> (u32, u32) {
    ((entry_id >> 32) as u32, (entry_id & 0xFFFF_FFFF) as u32)
}
