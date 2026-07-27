// SPDX-License-Identifier: GPL-2.0-only
//
//! Shared-memory descriptor backing.

/// Shared-memory descriptor. The actual page backing lives in
/// mmsrv as a file-backed MO; this struct records the size and MO
/// cap so multi-mappers see consistent state.
pub(crate) struct ShmData {
    pub(crate) active: u8,
    pub(crate) size: u64,
    /// Owning reference to the MO cap. `OwnedCap::null()` on an empty slot;
    /// `drop_shm_open_ref` / `handle_unlink` extract the cap via
    /// `core::mem::replace` before firing any release IPC so the field is
    /// null when the arena slot's eventual Drop runs.
    pub(crate) mo_cap: trona_runtime::core::slot_alloc::OwnedCap,
    pub(crate) refcount: u32,
}

impl ShmData {
    pub(crate) const fn zeroed() -> Self {
        ShmData {
            active: 0,
            size: 0,
            mo_cap: trona_runtime::core::slot_alloc::OwnedCap::null(),
            refcount: 0,
        }
    }
}

// SAFETY: Shared-memory descriptors are mutated by the VFS owner
// thread and referenced by handle.
unsafe impl Sync for ShmData {}
