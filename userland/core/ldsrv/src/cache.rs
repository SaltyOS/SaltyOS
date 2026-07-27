// SPDX-License-Identifier: GPL-2.0-only
//
//! ldsrv code-object cache — two tables:
//!
//! * **identity → code MO**, keyed by the 128-bit content digest (canonical),
//!   one entry per distinct object, pinned for the system lifetime. Each entry
//!   owns a CSpace slot holding the `READ|EXECUTE|GRANT|TRANSFER` code MO.
//! * **soname → identity** — the resolution namespace, rootfs-authoritative
//!   once mounted, with the adopted initrd set as bootstrap + fallback. A
//!   `mount_epoch` bump retires stale soname bindings so a rootfs object
//!   supersedes the initrd one for *new* resolutions, while already-running
//!   processes keep their pinned MO (lifetime = the pin).
//!
//! Both tables are fixed arrays living in BSS (no heap in this environment);
//! the cache never evicts — code objects are immortal.

use trona_protocol::ldsrv::ContentDigest;

pub const MAX_CODE_OBJECTS: usize = 256;
pub const MAX_SONAME_BINDINGS: usize = 256;
pub const MAX_SONAME_BYTES: usize = 48;

/// 128-bit content identity — the canonical cache key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub lo: u64,
    pub hi: u64,
}

impl Identity {
    pub const ZERO: Identity = Identity { lo: 0, hi: 0 };

    /// Identity of a fully-resident byte image.
    pub fn of_bytes(bytes: &[u8]) -> Identity {
        let mut d = ContentDigest::new();
        d.update(bytes);
        let (lo, hi) = d.finish();
        Identity { lo, hi }
    }
}

/// A pinned, canonical code object. `mo_slot` holds the
/// `READ|EXECUTE|GRANT|TRANSFER` code MO for the system lifetime; the header
/// summary is cached so a resolve reply needs no re-read of the image.
#[derive(Clone, Copy)]
pub struct CodeObject {
    pub identity: Identity,
    pub mo_slot: u64,
    pub mo_size: u64,
    pub format: u64,
    pub entry: u64,
    pub phoff: u64,
    pub phnum: u64,
    used: bool,
}

impl CodeObject {
    const EMPTY: CodeObject = CodeObject {
        identity: Identity::ZERO,
        mo_slot: 0,
        mo_size: 0,
        format: 0,
        entry: 0,
        phoff: 0,
        phnum: 0,
        used: false,
    };

    /// Construct a live code object pinned at `mo_slot`.
    pub fn new(
        identity: Identity,
        mo_slot: u64,
        mo_size: u64,
        format: u64,
        entry: u64,
        phoff: u64,
        phnum: u64,
    ) -> Self {
        Self {
            identity,
            mo_slot,
            mo_size,
            format,
            entry,
            phoff,
            phnum,
            used: true,
        }
    }
}

#[derive(Clone, Copy)]
struct SonameBinding {
    name: [u8; MAX_SONAME_BYTES],
    name_len: u8,
    identity: Identity,
    epoch: u32,
    used: bool,
}

impl SonameBinding {
    const EMPTY: SonameBinding = SonameBinding {
        name: [0; MAX_SONAME_BYTES],
        name_len: 0,
        identity: Identity::ZERO,
        epoch: 0,
        used: false,
    };
}

pub struct Cache {
    objects: [CodeObject; MAX_CODE_OBJECTS],
    object_count: usize,
    sonames: [SonameBinding; MAX_SONAME_BINDINGS],
    /// Current mount-namespace epoch. A soname binding from an earlier epoch
    /// is stale and re-resolved, so the rootfs supersedes the initrd fallback
    /// after a mount.
    epoch: u32,
}

impl Cache {
    pub const fn new() -> Self {
        Self {
            objects: [CodeObject::EMPTY; MAX_CODE_OBJECTS],
            object_count: 0,
            sonames: [SonameBinding::EMPTY; MAX_SONAME_BINDINGS],
            epoch: 0,
        }
    }

    /// Bump the mount epoch — existing soname bindings become stale and are
    /// re-resolved on next use. Call when the rootfs mounts.
    pub fn bump_epoch(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// Look up a code object by content identity, returning its entry index.
    pub fn find_object(&self, id: Identity) -> Option<usize> {
        self.objects[..self.object_count]
            .iter()
            .position(|o| o.used && o.identity == id)
    }

    pub fn object(&self, idx: usize) -> Option<&CodeObject> {
        self.objects.get(idx).filter(|o| o.used)
    }

    /// Insert a code object, idempotent by identity: a second insert of an
    /// already-present identity returns the existing entry (single-identity
    /// reuse, R5) and the caller must release the duplicate `mo_slot` it was
    /// about to hand in. On a new identity the entry takes ownership of
    /// `obj.mo_slot`. Returns the entry index, or `None` when the table is
    /// full.
    pub fn insert_object(&mut self, obj: CodeObject) -> Option<usize> {
        if let Some(idx) = self.find_object(obj.identity) {
            return Some(idx);
        }
        if self.object_count >= MAX_CODE_OBJECTS {
            return None;
        }
        let idx = self.object_count;
        self.objects[idx] = CodeObject { used: true, ..obj };
        self.object_count += 1;
        Some(idx)
    }

    /// Resolve a soname to a code-object index, honoring the current epoch.
    pub fn find_soname(&self, name: &[u8]) -> Option<usize> {
        let id = self.sonames.iter().find_map(|b| {
            if b.used
                && b.epoch == self.epoch
                && b.name_len as usize == name.len()
                && b.name[..name.len()] == *name
            {
                Some(b.identity)
            } else {
                None
            }
        })?;
        self.find_object(id)
    }

    /// Bind a soname to a content identity at the current epoch, overwriting a
    /// prior binding for the same name. Returns `false` when the name is empty
    /// or too long, or when the fixed binding table is full.
    pub fn bind_soname(&mut self, name: &[u8], id: Identity) -> bool {
        if name.is_empty() || name.len() > MAX_SONAME_BYTES {
            return false;
        }
        let slot = self
            .sonames
            .iter()
            .position(|b| {
                b.used && b.name_len as usize == name.len() && b.name[..name.len()] == *name
            })
            .or_else(|| self.sonames.iter().position(|b| !b.used));
        let Some(slot) = slot else {
            return false;
        };
        let mut entry = SonameBinding::EMPTY;
        entry.name[..name.len()].copy_from_slice(name);
        entry.name_len = name.len() as u8;
        entry.identity = id;
        entry.epoch = self.epoch;
        entry.used = true;
        self.sonames[slot] = entry;
        true
    }
}
