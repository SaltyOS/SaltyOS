// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-owner aggregate byte cap + per-class count cap. Hard quota,
//! no borrow-from-pool. Pre-increment counters on alloc admit; roll
//! back on kernel error.
//!
//! OwnerTable entries are keyed by `client_id` (u32, badge low 32 bits)
//! parsed via `authz::BadgeFields`. Admin-class callers do NOT enter
//! the OwnerTable — they bypass quota checks at dispatch time.

use crate::objects::NUM_OBJ_CLASSES;

pub const MAX_OWNERS: usize = 64;

#[derive(Clone, Copy)]
pub struct OwnerEntry {
    pub owner_id: u32,
    pub bytes_used: u64,
    pub bytes_max: u64,
    pub per_class_used: [u32; NUM_OBJ_CLASSES],
    pub per_class_max: [u32; NUM_OBJ_CLASSES],
    pub privileged: bool,
    pub active: u8,
}

impl OwnerEntry {
    const fn empty() -> Self {
        Self {
            owner_id: 0,
            bytes_used: 0,
            bytes_max: 0,
            per_class_used: [0; NUM_OBJ_CLASSES],
            per_class_max: [0; NUM_OBJ_CLASSES],
            privileged: false,
            active: 0,
        }
    }
}

pub struct OwnerTable {
    entries: [OwnerEntry; MAX_OWNERS],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitErr {
    InsufficientResources,
    OwnerTableFull,
}

impl OwnerTable {
    pub const fn new() -> Self {
        Self {
            entries: [OwnerEntry::empty(); MAX_OWNERS],
        }
    }

    fn slot(&mut self, owner_id: u32, allocate: bool) -> Option<usize> {
        let mut empty: Option<usize> = None;
        for (i, e) in self.entries.iter().enumerate() {
            if e.active != 0 && e.owner_id == owner_id {
                return Some(i);
            }
            if e.active == 0 && empty.is_none() {
                empty = Some(i);
            }
        }
        if !allocate {
            return None;
        }
        let i = empty?;
        let e = &mut self.entries[i];
        *e = OwnerEntry::empty();
        e.owner_id = owner_id;
        e.active = 1;
        Some(i)
    }

    pub fn ensure(&mut self, owner_id: u32) -> Result<usize, AdmitErr> {
        self.slot(owner_id, true).ok_or(AdmitErr::OwnerTableFull)
    }

    pub fn find(&self, owner_id: u32) -> Option<&OwnerEntry> {
        self.entries
            .iter()
            .find(|e| e.active != 0 && e.owner_id == owner_id)
    }

    pub fn set_quota(
        &mut self,
        owner_id: u32,
        bytes_max: u64,
        per_class_max: [u32; NUM_OBJ_CLASSES],
        privileged: bool,
    ) -> Result<(), AdmitErr> {
        let i = self.ensure(owner_id)?;
        let e = &mut self.entries[i];
        e.bytes_max = bytes_max;
        e.per_class_max = per_class_max;
        e.privileged = privileged;
        Ok(())
    }

    pub fn admit(&mut self, owner_id: u32, class: usize, bytes: u64) -> Result<(), AdmitErr> {
        let i = self.ensure(owner_id)?;
        let e = &mut self.entries[i];
        if e.bytes_max != 0 && e.bytes_used.saturating_add(bytes) > e.bytes_max {
            return Err(AdmitErr::InsufficientResources);
        }
        if e.per_class_max[class] != 0
            && e.per_class_used[class].saturating_add(1) > e.per_class_max[class]
        {
            return Err(AdmitErr::InsufficientResources);
        }
        e.bytes_used += bytes;
        e.per_class_used[class] += 1;
        Ok(())
    }

    pub fn release(&mut self, owner_id: u32, class: usize, bytes: u64) {
        if let Some(i) = self.slot(owner_id, false) {
            let e = &mut self.entries[i];
            e.bytes_used = e.bytes_used.saturating_sub(bytes);
            if class < NUM_OBJ_CLASSES {
                e.per_class_used[class] = e.per_class_used[class].saturating_sub(1);
            }
        }
    }

    pub fn drop_owner(&mut self, owner_id: u32) {
        if let Some(i) = self.slot(owner_id, false) {
            self.entries[i] = OwnerEntry::empty();
        }
    }

    pub fn iter_used(&self) -> impl Iterator<Item = &OwnerEntry> + '_ {
        self.entries.iter().filter(|e| e.active != 0)
    }
}
