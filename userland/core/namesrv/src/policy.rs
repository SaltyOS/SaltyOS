// SPDX-License-Identifier: GPL-2.0-only
//
//! `PublisherPolicy` — `policy_id → prefix` table consulted on every
//! REGISTER. Init populates this once via `NAMESRV_GRANT_PUBLISHER` per
//! `.service`'s `Exports=` entry; never modified afterwards (stable
//! across service restarts so the same publisher cap continues to
//! authorize the same prefix).

use crate::wire::MAX_PREFIX_BYTES;

pub const MAX_POLICIES: usize = 32;

#[derive(Clone, Copy)]
struct PolicyEntry {
    policy_id: u32,
    prefix: [u8; MAX_PREFIX_BYTES],
    prefix_len: u8,
    active: u8,
}

impl PolicyEntry {
    const fn empty() -> Self {
        Self {
            policy_id: 0,
            prefix: [0u8; MAX_PREFIX_BYTES],
            prefix_len: 0,
            active: 0,
        }
    }
}

pub struct PublisherPolicy {
    entries: [PolicyEntry; MAX_POLICIES],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantErr {
    Full,
    PrefixTooLong,
    Duplicate,
}

impl PublisherPolicy {
    pub const fn new() -> Self {
        Self {
            entries: [PolicyEntry::empty(); MAX_POLICIES],
        }
    }

    pub fn grant(&mut self, policy_id: u32, prefix: &[u8]) -> Result<(), GrantErr> {
        if prefix.len() > MAX_PREFIX_BYTES {
            return Err(GrantErr::PrefixTooLong);
        }
        let mut empty: Option<usize> = None;
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.active != 0 && entry.policy_id == policy_id {
                return Err(GrantErr::Duplicate);
            }
            if entry.active == 0 && empty.is_none() {
                empty = Some(idx);
            }
        }
        let Some(idx) = empty else {
            return Err(GrantErr::Full);
        };
        let entry = &mut self.entries[idx];
        entry.policy_id = policy_id;
        entry.prefix_len = prefix.len() as u8;
        entry.prefix[..prefix.len()].copy_from_slice(prefix);
        entry.active = 1;
        Ok(())
    }

    /// Returns `true` if `name` matches the prefix authorized for
    /// `policy_id`. An empty prefix matches everything (reserved for
    /// init's own publisher when it needs to publish system-name caps).
    pub fn allows(&self, policy_id: u32, name: &[u8]) -> bool {
        for entry in self.entries.iter() {
            if entry.active == 0 || entry.policy_id != policy_id {
                continue;
            }
            let prefix = &entry.prefix[..entry.prefix_len as usize];
            if prefix.is_empty() {
                return true;
            }
            return name.starts_with(prefix);
        }
        false
    }
}
