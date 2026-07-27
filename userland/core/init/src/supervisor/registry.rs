// SPDX-License-Identifier: GPL-2.0-only
//
//! Service-local interface registry. `INIT_REGISTER_INTERFACE` /
//! `INIT_RESOLVE_INTERFACE` allow services to publish their own MP
//! recv side under a name (provider:alias) and have other services
//! look them up. This is *not* the global namesrv (system-wide cap
//! broker); the namesrv handles cross-service global names. The
//! interface registry lives entirely inside init for service-local
//! roles populated from `.service` `Provides=`/`Requires=` lines.

use crate::supervisor::manifest::IfaceKey;

const MAX_INTERFACES: usize = 256;

#[derive(Clone, Copy)]
pub struct InterfaceEntry {
    pub key: IfaceKey,
    /// Slot in init's CSpace holding the provider-side MP send cap.
    /// Resolution mints a child of this cap (with whatever badge the
    /// requesting client gets) into the caller's CSpace.
    pub provider_mp_send: u64,
    /// Process id that registered this interface. When the provider
    /// exits, init scans this table and evicts every entry it owned.
    pub provider_pid: u32,
    pub in_use: bool,
}

impl InterfaceEntry {
    pub const fn empty() -> Self {
        Self {
            key: IfaceKey::empty(),
            provider_mp_send: 0,
            provider_pid: 0,
            in_use: false,
        }
    }
}

pub struct InterfaceRegistry {
    entries: [InterfaceEntry; MAX_INTERFACES],
    count: usize,
}

impl InterfaceRegistry {
    pub const fn new() -> Self {
        Self {
            entries: [InterfaceEntry::empty(); MAX_INTERFACES],
            count: 0,
        }
    }

    pub fn register(
        &mut self,
        key: IfaceKey,
        provider_mp_send: u64,
        provider_pid: u32,
    ) -> Result<usize, RegistryErr> {
        if self.find_index(&key).is_some() {
            return Err(RegistryErr::AlreadyExists);
        }
        for (i, e) in self.entries.iter_mut().enumerate() {
            if !e.in_use {
                *e = InterfaceEntry {
                    key,
                    provider_mp_send,
                    provider_pid,
                    in_use: true,
                };
                if i + 1 > self.count {
                    self.count = i + 1;
                }
                return Ok(i);
            }
        }
        Err(RegistryErr::TableFull)
    }

    pub fn find_index(&self, key: &IfaceKey) -> Option<usize> {
        for (i, e) in self.entries.iter().enumerate() {
            if e.in_use && e.key == *key {
                return Some(i);
            }
        }
        None
    }

    pub fn lookup(&self, key: &IfaceKey) -> Option<&InterfaceEntry> {
        let idx = self.find_index(key)?;
        Some(&self.entries[idx])
    }

    /// Drop every entry owned by `pid`. Returned count is for the
    /// caller's logging.
    pub fn evict_by_pid(&mut self, pid: u32) -> usize {
        let mut evicted = 0;
        for e in self.entries.iter_mut() {
            if e.in_use && e.provider_pid == pid {
                *e = InterfaceEntry::empty();
                evicted += 1;
            }
        }
        evicted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryErr {
    AlreadyExists,
    TableFull,
}
