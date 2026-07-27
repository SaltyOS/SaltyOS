// SPDX-License-Identifier: GPL-2.0-only
//
//! Untyped pool allocation helpers backed by `mm::map_anon`. Used by
//! synthetic filesystems (ramfs / tmpfs / devfs / pipefs / procfs /
//! sysctlfs) for their per-mount data pools — vnode-data arrays,
//! writable block chains, symlink target pools, and dirent arrays.
//!
//! Each allocation rounds up to a 4 KiB page and zero-initialises the
//! returned region. Growth is geometric (doubling under 128 entries,
//! 1.5× under 1024 entries, +256 above) with an explicit `_with_min`
//! variant for callers that need to satisfy a specific high-water
//! mark in one step.
//!
//! The owner thread is the sole mutator — these helpers are not
//! thread-safe by themselves and rely on the single-owner invariant
//! the synthetic filesystems already preserve.

/// Allocate a zero-initialised array of `count` `T`s, page-aligned.
/// Returns `::core::ptr::null_mut()` on a 0-byte request, on
/// arithmetic overflow, or when the underlying `map_anon` fails.
///
/// # Safety
///
/// Caller owns the returned region until paired with a matching
/// `unmap` (or freed implicitly by `vfs_grow_array` which releases
/// the old buffer).
pub(crate) unsafe fn vfs_alloc_array<T>(count: usize) -> *mut T {
    unsafe {
        let bytes = ::core::mem::size_of::<T>().checked_mul(count).unwrap_or(0);
        if bytes == 0 {
            return ::core::ptr::null_mut();
        }
        let pages = (bytes + 4095) / 4096;
        let ptr = super::mem::map_anon((pages * 4096) as u64);
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return ::core::ptr::null_mut();
        }
        ::core::ptr::write_bytes(ptr, 0, pages * 4096);
        ptr as *mut T
    }
}

/// Grow a `*mut T` array geometrically, copying the old contents
/// across and unmapping the previous region. Returns the new
/// `(ptr, capacity)` pair, or `(null, 0)` on failure.
///
/// # Safety
///
/// `old_ptr` / `old_cap` must come from a prior `vfs_alloc_array` /
/// `vfs_grow_array` against this server. After return the caller
/// must use the new pointer; the old pointer is no longer valid.
pub(crate) unsafe fn vfs_grow_array<T>(old_ptr: *mut T, old_cap: usize) -> (*mut T, usize) {
    unsafe { vfs_grow_array_with_min(old_ptr, old_cap, 0) }
}

/// `vfs_grow_array` variant that ensures at least `min_required`
/// capacity after growth. Used when a single call must satisfy a
/// known high-water mark (e.g. growing a dirent table to fit a
/// pre-counted entry batch).
pub(crate) unsafe fn vfs_grow_array_with_min<T>(
    old_ptr: *mut T,
    old_cap: usize,
    min_required: usize,
) -> (*mut T, usize) {
    if old_cap == 0 || old_ptr.is_null() {
        return (::core::ptr::null_mut(), 0);
    }
    let growth = if old_cap < 128 {
        old_cap
    } else if old_cap < 1024 {
        old_cap / 2
    } else {
        256
    };
    let new_cap = ::core::cmp::max(min_required, old_cap + growth);
    let new_ptr = unsafe { vfs_alloc_array::<T>(new_cap) };
    if new_ptr.is_null() {
        return (::core::ptr::null_mut(), 0);
    }
    // Bitwise copy is sound: the synthetic-fs pools are owner-thread
    // mutators only, so no concurrent reader sees the storage between
    // grow start and grow finish.
    unsafe {
        ::core::ptr::copy_nonoverlapping(old_ptr, new_ptr, old_cap);
    }
    let old_bytes = old_cap * ::core::mem::size_of::<T>();
    let old_pages = (old_bytes + 4095) / 4096;
    unsafe {
        super::mem::unmap(old_ptr as *mut u8, (old_pages * 4096) as u64);
    }
    (new_ptr, new_cap)
}

/// Type-erased grow for pools whose element type is not `Copy` /
/// not naturally typed in the caller (`u8`-blob backed dirent
/// arrays, raw byte chains). Updates `*ptr_loc` and `*cap_loc`
/// in-place. Returns 0 on success, -1 on failure.
///
/// # Safety
///
/// `ptr_loc` / `cap_loc` must point to a `*mut u8` / `usize` pair
/// owned by the caller; `item_size` must match the element size
/// already stored at the indicated capacity.
pub(crate) unsafe fn vfs_grow_pool(
    ptr_loc: *mut *mut u8,
    cap_loc: *mut usize,
    item_size: usize,
) -> i32 {
    unsafe { vfs_grow_pool_with_min(ptr_loc, cap_loc, item_size, 0) }
}

/// `vfs_grow_pool` variant with a minimum-capacity floor — see
/// [`vfs_grow_array_with_min`].
pub(crate) unsafe fn vfs_grow_pool_with_min(
    ptr_loc: *mut *mut u8,
    cap_loc: *mut usize,
    item_size: usize,
    min_required: usize,
) -> i32 {
    let old_ptr = unsafe { *ptr_loc };
    let old_cap = unsafe { *cap_loc };
    if old_cap == 0 {
        return -1;
    }
    let growth = if old_cap < 128 {
        old_cap
    } else if old_cap < 1024 {
        old_cap / 2
    } else {
        256
    };
    let new_cap = ::core::cmp::max(min_required, old_cap + growth);
    let new_bytes = match new_cap.checked_mul(item_size) {
        Some(b) if b > 0 => b,
        _ => return -1,
    };
    let new_pages = (new_bytes + 4095) / 4096;
    let new_ptr = unsafe { super::mem::map_anon((new_pages * 4096) as u64) };
    if new_ptr.is_null() || new_ptr == usize::MAX as *mut u8 {
        return -1;
    }
    let old_bytes = old_cap * item_size;
    unsafe {
        ::core::ptr::copy_nonoverlapping(old_ptr, new_ptr, old_bytes);
        ::core::ptr::write_bytes(new_ptr.add(old_bytes), 0, new_pages * 4096 - old_bytes);
    }
    if !old_ptr.is_null() {
        let old_pages = (old_bytes + 4095) / 4096;
        unsafe {
            super::mem::unmap(old_ptr, (old_pages * 4096) as u64);
        }
    }
    unsafe {
        *ptr_loc = new_ptr;
        *cap_loc = new_cap;
    }
    0
}
