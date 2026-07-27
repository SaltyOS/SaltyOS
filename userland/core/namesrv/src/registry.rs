// SPDX-License-Identifier: GPL-2.0-only
//
//! `NameRegistry` — fixed-capacity open-addressed name → `NameEntry`
//! table. Single-threaded reactor owns it, so all access is via
//! `&mut self`; no locks.

use crate::entry::NameEntry;
use crate::wire::MAX_NAME_BYTES;

pub const MAX_NAMES: usize = 256;

pub struct NameRegistry {
    entries: [NameEntry; MAX_NAMES],
    used: usize,
}

impl NameRegistry {
    pub const fn new() -> Self {
        Self {
            entries: [NameEntry::empty(); MAX_NAMES],
            used: 0,
        }
    }

    /// Linear scan for `name`. The registry caps out at 256 entries and
    /// the typical population (one publisher per service plus per-alias
    /// entries) sits well under 32 — linear scan is simpler than hash
    /// at this size.
    pub fn find_idx(&self, name: &[u8]) -> Option<usize> {
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return None;
        }
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.active == 0 {
                continue;
            }
            if entry.name_bytes() == name {
                return Some(idx);
            }
        }
        None
    }

    /// Reserve a free slot. Returns `None` when the table is full.
    pub fn alloc_slot(&mut self) -> Option<usize> {
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.active == 0 {
                return Some(idx);
            }
        }
        None
    }

    pub fn entry(&self, idx: usize) -> &NameEntry {
        &self.entries[idx]
    }

    pub fn entry_mut(&mut self, idx: usize) -> &mut NameEntry {
        &mut self.entries[idx]
    }

    /// Install a fresh entry into the slot at `idx`. Caller must have
    /// verified the slot is free (`active == 0`).
    pub fn install(
        &mut self,
        idx: usize,
        name: &[u8],
        cap_slot: u64,
        owner_tcb: u32,
        policy_id: u32,
        flags: u32,
    ) {
        let entry = &mut self.entries[idx];
        entry.name_len = name.len() as u8;
        entry.name[..name.len()].copy_from_slice(name);
        entry.cap_slot = cap_slot;
        entry.owner_tcb = owner_tcb;
        entry.policy_id = policy_id;
        entry.flags = flags;
        entry.generation = entry.generation.wrapping_add(1);
        entry.active = 1;
        // `watch_idx` left at the caller's discretion — eviction sets it.
        self.used += 1;
    }

    /// Mark slot as free without touching `generation` (the next
    /// `install` increments it). Returns the freed entry's `(name_len,
    /// cap_slot, owner_tcb, watch_idx)` so the caller can run cap
    /// teardown and watch disarm.
    pub fn vacate(&mut self, idx: usize) -> (u8, u64, u32, u8) {
        let entry = &mut self.entries[idx];
        let saved = (
            entry.name_len,
            entry.cap_slot,
            entry.owner_tcb,
            entry.watch_idx,
        );
        entry.name_len = 0;
        entry.cap_slot = 0;
        entry.owner_tcb = 0;
        entry.policy_id = 0;
        entry.flags = 0;
        entry.watch_idx = u8::MAX;
        entry.active = 0;
        self.used = self.used.saturating_sub(1);
        saved
    }

    pub fn iter_active(&self) -> impl Iterator<Item = (usize, &NameEntry)> + '_ {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.active != 0)
    }
}
