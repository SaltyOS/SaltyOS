// SPDX-License-Identifier: GPL-2.0-only
//
//! File-backed MO registry — `(vnode_slot, vnode_epoch)` →
//! `(mo_cap, mo_id, file_handle, file_offset, length)`.
//!
//! Populated by `handle_file_mmap` when vfs requests a fresh
//! file-backed MO; consulted by client-deregistration sweeps and
//! teardown paths that need to walk every MO bound to a given
//! vnode or client. The kernel-issued `mo_id` (from
//! `MO_ATTACH_PAGER`) lets the registry double as a reverse index
//! when a `PAGER_DETACH` cascade arrives. The lookup is a linear
//! scan because the entry count stays small (capped at
//! `MAX_FILE_BACKED`) and the call sites are not on the page-fault
//! hot path — file-backed faults flow kernel → vfs directly via
//! `KERNITE_EVENT_TYPE_PAGER_REQUEST`, never through mmsrv.

/// Per-file-mapping record. `mo_idx` is the `MoRegistry` index
/// (domain handle); the registry owns the kernel cap. Not `Copy`
/// because future fields may carry owned resources; use
/// `[const { FileBackedEntry::empty() }; N]` for array init.
#[derive(Clone)]
pub struct FileBackedEntry {
    /// `MoRegistry` index for the file-backed MO. The registry is
    /// the sole cap owner; callers resolve the raw cap via
    /// `MoRegistry::entry(mo_idx).mo_cap.as_raw()`.
    pub mo_idx: u32,
    /// vfs vnode handle's slot index.
    pub vnode_slot: u32,
    /// vfs vnode handle's epoch — protects against stale
    /// registrations when a slot is recycled.
    pub vnode_epoch: u32,
    /// Kernel-issued pager identifier returned by
    /// `MO_ATTACH_PAGER`. Echoed by the kernel on every
    /// `KERNITE_EVENT_TYPE_PAGER_REQUEST` event delivered to vfs;
    /// stored here so reverse paths (teardown / pager-detach
    /// cascade) can recover the vnode binding.
    pub mo_id: u64,
    /// Backend file handle — opaque to mmsrv. vfs receives a copy
    /// at `MM_FILE_MMAP` reply time so it can resolve back to the
    /// originating mount + inode.
    pub file_handle: u64,
    /// File-relative offset of the registered region.
    pub file_offset: u64,
    /// Region length in bytes (page-aligned multiple).
    pub length: u64,
    /// 0 = free slot, 1 = active.
    pub active: u8,
}

impl FileBackedEntry {
    pub const fn empty() -> Self {
        Self {
            mo_idx: 0,
            vnode_slot: 0,
            vnode_epoch: 0,
            mo_id: 0,
            file_handle: 0,
            file_offset: 0,
            length: 0,
            active: 0,
        }
    }
}

/// Sized to absorb a moderate set of mapped files without forcing
/// an LRU eviction layer. Linear scan stays cheap up to a few
/// hundred entries; revisit when workloads exceed.
pub const MAX_FILE_BACKED: usize = 256;

pub struct FileBackedRegistry {
    entries: [FileBackedEntry; MAX_FILE_BACKED],
}

impl FileBackedRegistry {
    pub const fn new() -> Self {
        Self {
            entries: [const { FileBackedEntry::empty() }; MAX_FILE_BACKED],
        }
    }

    /// Find a free slot. Returns `None` if every slot is taken.
    pub fn alloc_slot(&mut self) -> Option<u32> {
        for (idx, e) in self.entries.iter().enumerate() {
            if e.active == 0 {
                return Some(idx as u32);
            }
        }
        None
    }

    /// Install an entry at `idx`. Marks it `active`.
    pub fn install(&mut self, idx: u32, mut entry: FileBackedEntry) {
        entry.active = 1;
        self.entries[idx as usize] = entry;
    }

    pub fn vacate(&mut self, idx: u32) {
        if let Some(entry) = self.entries.get_mut(idx as usize) {
            *entry = FileBackedEntry::empty();
        }
    }

    /// Linear lookup by `(vnode_slot, vnode_epoch)`. Returns
    /// `None` if no active entry matches.
    pub fn lookup(&self, vnode_slot: u32, vnode_epoch: u32) -> Option<FileBackedEntry> {
        for e in self.entries.iter() {
            if e.active != 0 && e.vnode_slot == vnode_slot && e.vnode_epoch == vnode_epoch {
                return Some(e.clone());
            }
        }
        None
    }
}
