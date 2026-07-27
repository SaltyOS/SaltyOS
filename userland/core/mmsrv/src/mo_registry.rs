// SPDX-License-Identifier: GPL-2.0-only
//
//! `MoRegistry` — every MemoryObject mmsrv creates is recorded with
//! its kind, size, owner client, and refcount. The header itself is
//! retyped directly out of mmsrv's untyped pool.

use uapi::{
    KERNITE_MO_HEADER_BYTES, KERNITE_OBJ_MEMORY_OBJECT,
    KERNITE_PAGE_BYTES as KERNITE_PAGE_BYTES_U32,
};

use trona_runtime::core::slot_alloc::OwnedCap;
use trona_server::frame_alloc::FrameAllocator;

const KERNITE_PAGE_BYTES: u64 = KERNITE_PAGE_BYTES_U32 as u64;
const MO_KIND_SHIFT: u64 = 8;
const MO_KIND_ANON: u64 = 0;
const MO_KIND_FILE_BACKED: u64 = 2;
const MO_KIND_SHM: u64 = 3;

#[derive(Clone, Copy, Debug)]
pub enum MoKind {
    Anon,
    /// File-backed MO bound to a vfs `OBJ_PAGER` via
    /// `MO_ATTACH_PAGER`. `mo_id` is the kernel-issued identifier
    /// returned from the attach call; the kernel echoes it on every
    /// `KERNITE_EVENT_TYPE_PAGER_REQUEST` so vfs can resolve back
    /// to its vnode-key table without re-routing through mmsrv.
    FileBacked,
    Shm {
        name_hash: u64,
    },
}

impl MoKind {
    #[inline]
    fn kernel_retype_selector(self) -> u64 {
        let kind = match self {
            MoKind::Anon => MO_KIND_ANON,
            MoKind::FileBacked => MO_KIND_FILE_BACKED,
            MoKind::Shm { .. } => MO_KIND_SHM,
        };
        (KERNITE_OBJ_MEMORY_OBJECT as u64) | (kind << MO_KIND_SHIFT)
    }
}

/// Per-MO registry record. Not `Copy` because `mo_cap` is an
/// [`OwnedCap`]: the registry is the sole owner of the kernel cap and
/// must call `frames.release_child` before dropping the entry (see
/// [`MoRegistry::vacate`]).
pub struct MoEntry {
    /// Cap slot of the kernel MemoryObject. Owned by this entry; the
    /// cap is deleted when the entry is vacated (after `release_child`
    /// notifies the frame allocator).
    pub mo_cap: OwnedCap,
    pub size_bytes: u64,
    pub owner_client_id: u32,
    pub map_count: u32,
    pub refcount: u32,
    pub source_chunk_idx: usize,
    pub kind: MoKind,
    pub active: u8,
}

impl MoEntry {
    pub const fn empty() -> Self {
        Self {
            mo_cap: OwnedCap::null(),
            size_bytes: 0,
            owner_client_id: 0,
            map_count: 0,
            refcount: 0,
            source_chunk_idx: usize::MAX,
            kind: MoKind::Anon,
            active: 0,
        }
    }
}

pub const MAX_MOS: usize = 8192;

pub struct MoRegistry {
    entries: [MoEntry; MAX_MOS],
    used: u32,
}

impl MoRegistry {
    pub const fn new() -> Self {
        Self {
            entries: [const { MoEntry::empty() }; MAX_MOS],
            used: 0,
        }
    }

    pub fn alloc_slot(&mut self) -> Option<usize> {
        for (idx, e) in self.entries.iter().enumerate() {
            if e.active == 0 {
                return Some(idx);
            }
        }
        None
    }

    pub fn entry(&self, idx: usize) -> Option<&MoEntry> {
        self.entries.get(idx).filter(|e| e.active != 0)
    }

    pub fn find_shm_by_name(&self, name_hash: u64) -> Option<usize> {
        self.entries.iter().enumerate().find_map(|(idx, e)| {
            if e.active != 0 && matches!(e.kind, MoKind::Shm { name_hash: h } if h == name_hash) {
                Some(idx)
            } else {
                None
            }
        })
    }

    pub fn find_by_cap(&self, mo_cap_raw: u64) -> Option<usize> {
        self.entries.iter().enumerate().find_map(|(idx, e)| {
            if e.active != 0 && e.mo_cap.as_raw() == mo_cap_raw {
                Some(idx)
            } else {
                None
            }
        })
    }

    pub fn retain_by_cap(&mut self, mo_cap_raw: u64) -> bool {
        let Some(idx) = self.find_by_cap(mo_cap_raw) else {
            return false;
        };
        let e = &mut self.entries[idx];
        e.refcount = e.refcount.saturating_add(1);
        true
    }

    pub fn retain_by_handle(&mut self, idx: usize) -> bool {
        let Some(e) = self.entries.get_mut(idx) else {
            return false;
        };
        if e.active == 0 {
            return false;
        }
        e.refcount = e.refcount.saturating_add(1);
        true
    }

    pub fn release_by_cap(&mut self, mo_cap_raw: u64, frames: &mut FrameAllocator) -> bool {
        let Some(idx) = self.find_by_cap(mo_cap_raw) else {
            return false;
        };
        if self.entries[idx].refcount > 1 {
            self.entries[idx].refcount -= 1;
            return true;
        }
        self.vacate(idx, frames);
        true
    }

    pub fn release_by_handle(&mut self, idx: usize, frames: &mut FrameAllocator) -> bool {
        let Some(e) = self.entries.get(idx) else {
            return false;
        };
        if e.active == 0 {
            return false;
        }
        if self.entries[idx].refcount > 1 {
            self.entries[idx].refcount -= 1;
            return true;
        }
        self.vacate(idx, frames);
        true
    }

    pub fn inc_map_count(&mut self, idx: usize) -> bool {
        let Some(e) = self.entries.get_mut(idx) else {
            return false;
        };
        if e.active == 0 {
            return false;
        }
        e.map_count = e.map_count.saturating_add(1);
        true
    }

    pub fn dec_map_count(&mut self, idx: usize, frames: &mut FrameAllocator) -> bool {
        let Some(e) = self.entries.get_mut(idx) else {
            return false;
        };
        if e.active == 0 {
            return false;
        }
        e.map_count = e.map_count.saturating_sub(1);
        if matches!(e.kind, MoKind::Shm { .. }) && e.map_count == 0 && e.refcount == 0 {
            self.vacate(idx, frames);
        }
        true
    }

    pub fn shm_index_for_key(&self, key: u64) -> Option<usize> {
        if let Ok(idx) = usize::try_from(key) {
            if self
                .entries
                .get(idx)
                .is_some_and(|e| e.active != 0 && matches!(e.kind, MoKind::Shm { .. }))
            {
                return Some(idx);
            }
        }
        self.find_shm_by_name(key)
    }

    pub fn request_destroy_shm(&mut self, idx: usize, frames: &mut FrameAllocator) -> bool {
        let Some(e) = self.entries.get_mut(idx) else {
            return false;
        };
        if e.active == 0 || !matches!(e.kind, MoKind::Shm { .. }) {
            return false;
        }
        if e.map_count == 0 {
            self.vacate(idx, frames);
        } else {
            // Mark destroy requested. The final `dec_map_count`
            // releases the MO header once the last self-tier mapping
            // disappears.
            e.refcount = 0;
        }
        true
    }

    /// Retype a fresh MO header out of the FrameAllocator's pool and
    /// install it at `idx`. The cap slot is allocated from mmsrv's
    /// normal CSpace allocator and adopted into an [`OwnedCap`];
    /// `vacate` releases it through the destructor after notifying
    /// the frame allocator via `release_child`.
    ///
    /// Returns the raw cap slot on success so callers can pass it to
    /// kernel invocations (e.g. `VSPACE_MAP_MO`).
    pub fn install(
        &mut self,
        idx: usize,
        size_bytes: u64,
        owner_client_id: u32,
        kind: MoKind,
        frames: &mut FrameAllocator,
    ) -> Option<u64> {
        let Some(size_bits) = mo_size_bits_for_length(size_bytes) else {
            return None;
        };
        let slot = trona_runtime::core::slot_alloc::alloc_slot()?;
        let Some(source_chunk_idx) =
            frames.retype_child(kind.kernel_retype_selector(), size_bits, slot.addr())
        else {
            // retype failed: `slot` (OwnedSlot) Drop frees the empty slot.
            return None;
        };
        // The MO cap now occupies the slot; adopt it as the entry's OwnedCap.
        let mo = slot.assume_filled();
        let raw = mo.as_raw();
        let e = &mut self.entries[idx];
        e.mo_cap = mo;
        e.size_bytes = size_bytes;
        e.owner_client_id = owner_client_id;
        e.map_count = 0;
        e.refcount = 1;
        e.source_chunk_idx = source_chunk_idx;
        e.kind = kind;
        e.active = 1;
        self.used += 1;
        Some(raw)
    }

    pub fn vacate(&mut self, idx: usize, frames: &mut FrameAllocator) {
        let e = match self.entries.get_mut(idx) {
            Some(e) if e.active != 0 => e,
            _ => return,
        };
        // Notify the frame allocator BEFORE the OwnedCap destructor
        // deletes the kernel object: `release_child` may attempt to
        // reset the untyped chunk (UNTYPED_RESET), which requires the
        // cap to still name a live object.
        let cap_slot_raw = e.mo_cap.as_raw();
        let source_chunk_idx = e.source_chunk_idx;
        e.active = 0;
        e.size_bytes = 0;
        e.owner_client_id = 0;
        e.map_count = 0;
        e.refcount = 0;
        e.source_chunk_idx = usize::MAX;
        self.used = self.used.saturating_sub(1);
        // `release_child` first, then drop the OwnedCap.
        frames.release_child(cap_slot_raw, source_chunk_idx);
        // Replace with a null OwnedCap so the old cap is dropped here.
        let old_cap = core::mem::replace(&mut e.mo_cap, OwnedCap::null());
        drop(old_cap);
    }

    pub fn bytes_by_kind(&self) -> (u64, u64, u64) {
        let mut anon = 0u64;
        let mut shm = 0u64;
        let mut file = 0u64;
        for e in self.entries.iter().filter(|e| e.active != 0) {
            match e.kind {
                MoKind::Anon => anon = anon.saturating_add(e.size_bytes),
                MoKind::FileBacked => file = file.saturating_add(e.size_bytes),
                MoKind::Shm { name_hash } => {
                    let _ = name_hash;
                    shm = shm.saturating_add(e.size_bytes);
                }
            }
        }
        (anon, shm, file)
    }

    pub fn slab_bytes(&self) -> u64 {
        self.used as u64 * (KERNITE_MO_HEADER_BYTES as u64)
    }
}

fn mo_size_bits_for_length(size_bytes: u64) -> Option<u64> {
    if size_bytes == 0 || size_bytes % KERNITE_PAGE_BYTES != 0 {
        return None;
    }
    let pages = size_bytes / KERNITE_PAGE_BYTES;
    let rounded = pages.checked_next_power_of_two()?;
    let bits = rounded.trailing_zeros() as u64;
    if bits > 31 { None } else { Some(bits) }
}
