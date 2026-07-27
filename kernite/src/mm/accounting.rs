//! Global memory accounting snapshot.
//!
//! Reads the packed per-tag / per-subkind counters from the frame
//! allocator under FRAME_LOCK and packages them into a plain struct
//! for kernel consumers (the `SysMemInfo` syscall path) and future
//! debug dumps. Lives outside `frame.rs` so that consumers can import
//! the snapshot type without pulling in the allocator internals.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::frame::{FrameAllocator, KernelMetaKind, MoMetaKind, OwnerTag};
use crate::cap::memory_object::MoKind;

/// Snapshot of global PMM accounting. Every page-valued field is in
/// 4 KiB units. `reserve_pool_depth` is the count of frames currently
/// parked in the emergency reserve array (not the per-tag counter).
///
/// The snapshot is eventually-consistent: reads take FRAME_LOCK long
/// enough to copy the fields out, so callers see a coherent view at
/// one instant, but counters may have advanced by the time the caller
/// looks at the struct.
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobalMemCounts {
    pub pages_total: usize,
    pub pages_free: usize,
    pub pages_untyped_reserved: usize,
    pub pages_mo_data: usize,
    pub pages_mo_meta: usize,
    pub pages_page_cache: usize,
    pub pages_kernel_private: usize,
    pub pages_emergency_reserve: usize,
    pub kmeta_pagetable: usize,
    pub kmeta_kernel_stack: usize,
    pub kmeta_maple_node: usize,
    pub kmeta_general: usize,
    pub kmeta_cow_pool: usize,
    pub mo_meta_radix: usize,
    pub mo_meta_rmap: usize,
    /// Frames carrying MoData whose owning MO is `MoKind::Anon`.
    pub pages_anon_private: usize,
    /// Frames carrying MoData whose owning MO is `MoKind::CowChild`.
    pub pages_anon_cow: usize,
    /// Frames carrying MoData whose owning MO is `MoKind::FileBacked`.
    pub pages_file: usize,
    /// Frames carrying MoData whose owning MO is `MoKind::Shm`.
    pub pages_anon_shared: usize,
    /// File-backed frames carrying `FRAME_FLAG_DIRTY`.
    pub pages_dirty_file: usize,
    /// File-backed frames carrying `FRAME_FLAG_WRITEBACK`.
    pub pages_writeback_file: usize,
    /// LRU-eligible pages in the active set.
    pub pages_active: usize,
    /// LRU-eligible pages in the inactive set.
    pub pages_inactive: usize,
    pub reserve_pool_depth: usize,
}

impl GlobalMemCounts {
    /// Copy the allocator-side counters out. Caller must hold FRAME_LOCK.
    pub fn from_allocator(allocator: &FrameAllocator) -> Self {
        Self {
            pages_total: allocator.total_count(),
            pages_free: allocator.free_count(),
            pages_untyped_reserved: allocator.tag_count(OwnerTag::UntypedReserved),
            pages_mo_data: allocator.tag_count(OwnerTag::MoData),
            pages_mo_meta: allocator.tag_count(OwnerTag::MoMeta),
            pages_page_cache: allocator.tag_count(OwnerTag::PageCache),
            pages_kernel_private: allocator.tag_count(OwnerTag::KernelPrivate),
            pages_emergency_reserve: allocator.tag_count(OwnerTag::EmergencyReserve),
            kmeta_pagetable: allocator.kmeta_count(KernelMetaKind::PageTable),
            kmeta_kernel_stack: allocator.kmeta_count(KernelMetaKind::KernelStack),
            kmeta_maple_node: allocator.kmeta_count(KernelMetaKind::MapleNode),
            kmeta_general: allocator.kmeta_count(KernelMetaKind::General),
            kmeta_cow_pool: allocator.kmeta_count(KernelMetaKind::CowPool),
            mo_meta_radix: allocator.mo_meta_count(MoMetaKind::Radix),
            mo_meta_rmap: allocator.mo_meta_count(MoMetaKind::Rmap),
            pages_anon_private: allocator.mo_kind_count(MoKind::Anon),
            pages_anon_cow: allocator.mo_kind_count(MoKind::CowChild),
            pages_file: allocator.mo_kind_count(MoKind::FileBacked),
            pages_anon_shared: allocator.mo_kind_count(MoKind::Shm),
            pages_dirty_file: allocator.dirty_file_count(),
            pages_writeback_file: allocator.writeback_file_count(),
            pages_active: allocator.active_lru_count(),
            pages_inactive: allocator.inactive_lru_count(),
            reserve_pool_depth: allocator.reserve_level(),
        }
    }
}
