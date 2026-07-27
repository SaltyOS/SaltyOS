//! mmsrv kernel-VM layer.
//!
//! Thin wrappers over `trona_kernel::invoke::*` plus the MemoryObject
//! page-commit helper. mmsrv's private slab page-backing lives in
//! `self_vm.rs`, which retypes and maps its MemoryObjects through these
//! wrappers and `FrameAllocator`. Every kernel call mmsrv issues
//! flows through this module so the policy layer
//! (`mmap.rs` / `client.rs` / `region.rs`) and the transaction layer
//! (`txn.rs`) never reach `invoke::vspace_*` /
//! `invoke::mo_*` / `invoke::cnode_copy` directly. The same boundary
//! is enforced mechanically by `just layering-check` (see S6b).
//!
//! This is also the single boundary where mmsrv's raw `u64` slot indices
//! are resolved into the depth-carrying [`CapRef`] the kernel invoke API
//! takes. Object caps mmsrv holds (client vspaces, frames, MOs) can live
//! in an expanded sub-CNode, so they are resolved with
//! [`resolved_cap_ref`]; the self-CSpace root is a flat root slot and
//! resolves with [`CapRef::flat`].
//!
//! Symbols here cannot reference policy-layer types (region records,
//! client records). Anything that needs to consult policy state
//! belongs in the policy layer or the transaction layer.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::{Cap, CapRef};
use trona_kernel::invoke;
use trona_protocol::init::TronaVSpaceRangeStats;
use trona_runtime::core::slot_alloc::resolved_cap_ref;

// ---------------------------------------------------------------------------
// Thin wrappers — vspace_*
// ---------------------------------------------------------------------------

#[inline]
pub(crate) fn vspace_map(vspace: Cap, frame: Cap, vaddr: u64, flags: u64) -> i32 {
    invoke::vspace_map(
        resolved_cap_ref(vspace),
        resolved_cap_ref(frame),
        vaddr,
        flags,
    )
}

#[inline]
pub(crate) fn vspace_unmap(vspace: Cap, vaddr: u64) -> i32 {
    invoke::vspace_unmap(resolved_cap_ref(vspace), vaddr)
}

#[inline]
pub(crate) fn vspace_protect_range(vspace: Cap, vaddr: u64, count: u64, flags: u64) -> (i32, u64) {
    invoke::vspace_protect_range(resolved_cap_ref(vspace), vaddr, count, flags)
}

#[inline]
pub(crate) fn vspace_map_mo_with_count(
    vspace: Cap,
    mo_cap: u64,
    vaddr: u64,
    mo_offset: u64,
    count_and_flags: u64,
) -> (i32, u64) {
    invoke::vspace_map_mo_with_count(
        resolved_cap_ref(vspace),
        mo_cap,
        vaddr,
        mo_offset,
        count_and_flags,
    )
}

#[inline]
pub(crate) fn vspace_map_device_range(
    vspace: Cap,
    device_untyped: Cap,
    offset_start: u64,
    vaddr_start: u64,
    num_pages: u64,
    flags: u64,
) -> (i32, u64) {
    invoke::vspace_map_device_range(
        resolved_cap_ref(vspace),
        resolved_cap_ref(device_untyped),
        offset_start,
        vaddr_start,
        num_pages,
        flags,
    )
}

#[inline]
pub(crate) fn vspace_fork_range(
    parent_vspace: Cap,
    child_vspace: Cap,
    state: Cap,
    parent_shadow_mo: Cap,
    child_mo: Cap,
    vaddr: u64,
    rollback_buffer_uaddr: u64,
) -> (i32, u64) {
    invoke::vspace_fork_range(
        resolved_cap_ref(parent_vspace),
        resolved_cap_ref(child_vspace),
        resolved_cap_ref(state),
        resolved_cap_ref(parent_shadow_mo),
        resolved_cap_ref(child_mo),
        vaddr,
        rollback_buffer_uaddr,
    )
}

#[inline]
pub(crate) fn vspace_get_range_stats(
    vspace: Cap,
    start_vaddr: u64,
    page_count: u64,
    out: *mut TronaVSpaceRangeStats,
) -> u64 {
    invoke::vspace_get_range_stats_raw(
        resolved_cap_ref(vspace),
        start_vaddr,
        page_count,
        out as u64,
    )
}

#[inline]
pub(crate) fn vspace_get_mem_stats(
    vspace: Cap,
    out: *mut trona_protocol::init::TronaVSpaceMemStats,
) -> u64 {
    invoke::vspace_get_mem_stats_raw(resolved_cap_ref(vspace), out as u64)
}

// ---------------------------------------------------------------------------
// Thin wrappers — cnode_*
// ---------------------------------------------------------------------------

/// Capability copy `src_cnode[src] → dest_cnode[dest]`, each slot named by a
/// depth-carrying [`CapRef`]. The CNode caps are passed as raw self-CSpace
/// slots (flat root slots); the per-slot invoke depth rides in `src` / `dest`,
/// resolved once by the caller via [`resolved_cap_ref`] rather than recomputed
/// here.
#[inline]
pub(crate) fn cnode_copy_ref(
    src_cnode: Cap,
    src: CapRef,
    dest_cnode: Cap,
    dest: CapRef,
    rights: u64,
) -> i32 {
    invoke::cnode_copy_ref(
        CapRef::flat(src_cnode),
        src,
        CapRef::flat(dest_cnode),
        dest,
        rights,
    )
}

/// Depth-resolved capability delete `cnode[slot]`.
#[inline]
pub(crate) fn cnode_delete_depth(cnode: Cap, slot: u64, depth: u8) -> i32 {
    invoke::cnode_delete_depth(CapRef::flat(cnode), slot, depth)
}

// ---------------------------------------------------------------------------
// Higher-level helper — MemoryObject page commit.
//
// mmsrv's private slab page-backing lives in `self_vm.rs`; it retypes
// and maps its MemoryObjects through the thin wrappers above plus
// `FrameAllocator`. The only shared higher-level helper that remains
// here is the PMM-backed page commit those paths call.
// ---------------------------------------------------------------------------

/// Commit `count` pages starting at `offset` in a MemoryObject. mmsrv
/// owns no untyped of its own — every commit goes through the kernel
/// PMM path (`ut_cap = 0`).
///
/// # Safety
/// `mo_cap` must be a valid MO capability.
pub(crate) unsafe fn commit_mo_pages(mo_cap: Cap, offset: u64, count: u64) -> i32 {
    invoke::mo_commit(resolved_cap_ref(mo_cap), offset, count, 0)
}
