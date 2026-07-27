// SPDX-License-Identifier: GPL-2.0-only
//
//! rsrcsrv-internal self-storage. rsrcsrv carves FRAME pages directly
//! from its untyped pool and maps them into its own VSpace at a fixed
//! VA window. Used to back ObjectTable / OwnerTable rows that live
//! beyond the static `.bss` allotment, without going through mmsrv
//! (which doesn't exist yet at rsrcsrv-spawn time).

use trona_kernel::syscall;
use uapi::{
    KERNITE_CAP_SELF_VSPACE, KERNITE_INV_VSPACE_MAP, KERNITE_OBJ_FRAME, KERNITE_PAGE_BYTES,
    KERNITE_PAGE_FLAG_USER, KERNITE_PAGE_FLAG_WRITABLE,
};

use crate::untyped::FreeList;

/// Fixed VA at which self-storage starts. Sized far above the static
/// image; rsrcsrv links no shared library that would clash.
pub const SELF_STORAGE_BASE: u64 = 0x0000_0000_0080_0000;
/// Hard ceiling on self-storage growth. Refuse pagein past this point.
pub const SELF_STORAGE_LIMIT: u64 = SELF_STORAGE_BASE + (64 * 1024 * 1024);

static mut NEXT_VA: u64 = SELF_STORAGE_BASE;

/// Allocate one FRAME from the untyped pool and map it at the next
/// self-storage VA. Returns the mapped VA on success or `None` when
/// the pool / VA window is exhausted.
pub fn map_one_page(freelist: &mut FreeList) -> Option<u64> {
    let next = unsafe { core::ptr::read_volatile(&raw const NEXT_VA) };
    if next + KERNITE_PAGE_BYTES > SELF_STORAGE_LIMIT {
        return None;
    }
    let dest = trona_runtime::core::slot_alloc::alloc_slot_no_expand()?;
    if freelist
        .try_retype(KERNITE_OBJ_FRAME, 12, dest.addr())
        .is_none()
    {
        // retype failed: `dest` (OwnedSlot, empty) Drop frees the slot.
        return None;
    }
    let dest_slot = dest.into_raw();
    let flags = (KERNITE_PAGE_FLAG_USER | KERNITE_PAGE_FLAG_WRITABLE) as u64;
    let r = syscall::invoke(
        KERNITE_CAP_SELF_VSPACE as u64,
        KERNITE_INV_VSPACE_MAP as u64,
        dest_slot,
        next,
        flags,
        0,
    );
    if r.error != 0 {
        // SAFETY: dest_slot is the page-frame cap just retyped for this bump-map,
        // solely owned here; torn down + freed once on this map-failure path.
        unsafe { trona_runtime::core::slot_alloc::delete_and_free(dest_slot) };
        return None;
    }
    unsafe {
        core::ptr::write_volatile(&raw mut NEXT_VA, next + KERNITE_PAGE_BYTES);
    }
    Some(next)
}

pub fn current_high_watermark() -> u64 {
    unsafe { core::ptr::read_volatile(&raw const NEXT_VA) }
}
