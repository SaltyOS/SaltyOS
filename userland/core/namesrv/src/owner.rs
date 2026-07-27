// SPDX-License-Identifier: GPL-2.0-only
//
//! `OwnerTable` — tracks which `NameRegistry` indices each publisher
//! process owns, so `OWNER_EXITED` can mass-evict in one pass. The key
//! is the publisher process's `client_id` (== its main TCB `trace_id`,
//! packed into the publisher cap badge by init when the cap was
//! minted). Stored field name `tcb_id` reflects the kernel-side origin
//! of the value but the userland identity is the caller's `client_id`.

pub const MAX_OWNERS: usize = 64;
pub const MAX_NAMES_PER_OWNER: usize = 8;

#[derive(Clone, Copy)]
pub struct OwnerEntry {
    pub tcb_id: u32,
    pub registry_indices: [u8; MAX_NAMES_PER_OWNER],
    pub used: u8,
    pub active: u8,
}

impl OwnerEntry {
    const fn empty() -> Self {
        Self {
            tcb_id: 0,
            registry_indices: [0u8; MAX_NAMES_PER_OWNER],
            used: 0,
            active: 0,
        }
    }
}

pub struct OwnerTable {
    entries: [OwnerEntry; MAX_OWNERS],
}

impl OwnerTable {
    pub const fn new() -> Self {
        Self {
            entries: [OwnerEntry::empty(); MAX_OWNERS],
        }
    }

    fn find_slot(&mut self, tcb_id: u32, allocate: bool) -> Option<usize> {
        let mut empty: Option<usize> = None;
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.active != 0 && entry.tcb_id == tcb_id {
                return Some(idx);
            }
            if entry.active == 0 && empty.is_none() {
                empty = Some(idx);
            }
        }
        if allocate {
            if let Some(idx) = empty {
                self.entries[idx].tcb_id = tcb_id;
                self.entries[idx].used = 0;
                self.entries[idx].active = 1;
                return Some(idx);
            }
        }
        None
    }

    /// Record that `tcb_id` owns the registry slot `registry_idx`.
    /// Returns `false` when the per-owner limit is hit (caller should
    /// surface `INSUFFICIENT_RESOURCES`) or the OwnerTable itself is
    /// full.
    pub fn register(&mut self, tcb_id: u32, registry_idx: u8) -> bool {
        let Some(slot) = self.find_slot(tcb_id, true) else {
            return false;
        };
        let owner = &mut self.entries[slot];
        if (owner.used as usize) >= MAX_NAMES_PER_OWNER {
            return false;
        }
        owner.registry_indices[owner.used as usize] = registry_idx;
        owner.used += 1;
        true
    }

    /// Drop a single ownership record. Used after an UNREGISTER.
    pub fn forget(&mut self, tcb_id: u32, registry_idx: u8) {
        let Some(slot) = self.find_slot(tcb_id, false) else {
            return;
        };
        let owner = &mut self.entries[slot];
        let mut write = 0u8;
        for read in 0..(owner.used as usize) {
            if owner.registry_indices[read] != registry_idx {
                owner.registry_indices[write as usize] = owner.registry_indices[read];
                write += 1;
            }
        }
        owner.used = write;
        if owner.used == 0 {
            owner.active = 0;
        }
    }

    /// Drain all registry indices owned by `tcb_id`. Caller iterates
    /// the returned slice and tears each entry down. After this call
    /// the owner slot is free.
    pub fn drain(&mut self, tcb_id: u32, dest: &mut [u8; MAX_NAMES_PER_OWNER]) -> usize {
        let Some(slot) = self.find_slot(tcb_id, false) else {
            return 0;
        };
        let owner = &mut self.entries[slot];
        let n = owner.used as usize;
        for i in 0..n {
            dest[i] = owner.registry_indices[i];
        }
        owner.used = 0;
        owner.active = 0;
        n
    }
}
