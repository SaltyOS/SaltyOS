// SPDX-License-Identifier: GPL-2.0-only
//! VFS global state: pools, macros, and allocator helpers.

use crate::personality::posix::consts::MAX_SHM_PAGES;
use crate::server::consts::*;

// ======================================================================
// Global state
// ======================================================================

pub(crate) static mut FB_WIDTH: u32 = 0;
pub(crate) static mut FB_HEIGHT: u32 = 0;
pub(crate) static mut FB_PITCH: u32 = 0;
pub(crate) static mut FB_BPP: u8 = 0;
pub(crate) static mut FB_RED_POS: u8 = 0;
pub(crate) static mut FB_RED_SIZE: u8 = 0;
pub(crate) static mut FB_GREEN_POS: u8 = 0;
pub(crate) static mut FB_GREEN_SIZE: u8 = 0;
pub(crate) static mut FB_BLUE_POS: u8 = 0;
pub(crate) static mut FB_BLUE_SIZE: u8 = 0;

pub(crate) static mut CURRENT_RECV_SLOT: u64 = 0;
pub(crate) static mut WORKER_RECV_SLOTS: [u64; MAX_VFS_WORKERS] = [0; MAX_VFS_WORKERS];
pub(crate) static mut WORKER_RECV_SLOT_COUNT: usize = 1;

pub(crate) static mut VFS_SHM_ACTIVE: bool = false;

pub(crate) static mut URANDOM_KEY: [u8; 32] = [0u8; 32];
pub(crate) static mut URANDOM_CTR: u64 = 0;
pub(crate) static mut URANDOM_BUF: [u8; 64] = [0u8; 64];
pub(crate) static mut URANDOM_BUF_POS: usize = 64;
pub(crate) static mut URANDOM_COUNTER: u64 = 0;
pub(crate) const URANDOM_RESEED_INTERVAL: u64 = 1024;

pub(crate) static mut PROC_ROOT_INO: u32 = 0;
pub(crate) const MAX_VFS_WORKERS: usize = 32;

pub(crate) fn max_shm_pages() -> usize {
    MAX_SHM_PAGES
}

pub(crate) unsafe fn current_recv_slot() -> u64 {
    unsafe {
        let worker_idx = trona_runtime::thread::worker::current_worker_index();
        if worker_idx < MAX_VFS_WORKERS {
            let slot = WORKER_RECV_SLOTS[worker_idx];
            if slot != 0 {
                return slot;
            }
        }
        CURRENT_RECV_SLOT
    }
}

pub(crate) unsafe fn set_worker_recv_slot(worker_idx: usize, slot: u64) {
    unsafe {
        if worker_idx < MAX_VFS_WORKERS {
            WORKER_RECV_SLOTS[worker_idx] = slot;
        }
    }
}

// ======================================================================
// Pool allocation functions
// ======================================================================

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
    let new_cap = core::cmp::max(min_required, old_cap + growth);
    let new_bytes = match new_cap.checked_mul(item_size) {
        Some(b) if b > 0 => b,
        _ => return -1,
    };
    let new_pages = (new_bytes + 4095) / 4096;
    let new_ptr = unsafe { crate::server::mem::map_anon((new_pages * 4096) as u64) };
    if new_ptr.is_null() || new_ptr == usize::MAX as *mut u8 {
        return -1;
    }
    let old_bytes = old_cap * item_size;
    unsafe {
        core::ptr::copy_nonoverlapping(old_ptr, new_ptr, old_bytes);
        core::ptr::write_bytes(new_ptr.add(old_bytes), 0, new_pages * 4096 - old_bytes);
    }
    if !old_ptr.is_null() {
        let old_pages = (old_bytes + 4095) / 4096;
        unsafe {
            crate::server::mem::unmap(old_ptr, (old_pages * 4096) as u64);
        }
    }
    unsafe {
        *ptr_loc = new_ptr;
        *cap_loc = new_cap;
    }
    0
}

pub(crate) unsafe fn vfs_grow_pool(
    ptr_loc: *mut *mut u8,
    cap_loc: *mut usize,
    item_size: usize,
) -> i32 {
    unsafe { vfs_grow_pool_with_min(ptr_loc, cap_loc, item_size, 0) }
}

pub(crate) unsafe fn vfs_alloc_array<T>(count: usize) -> *mut T {
    unsafe {
        let bytes = core::mem::size_of::<T>().checked_mul(count).unwrap_or(0);
        if bytes == 0 {
            return core::ptr::null_mut();
        }
        let pages = (bytes + 4095) / 4096;
        let ptr = crate::server::mem::map_anon((pages * 4096) as u64);
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return core::ptr::null_mut();
        }
        core::ptr::write_bytes(ptr, 0, pages * 4096);
        ptr as *mut T
    }
}

pub(crate) unsafe fn vfs_grow_array_with_min<T>(
    old_ptr: *mut T,
    old_cap: usize,
    min_required: usize,
) -> (*mut T, usize) {
    if old_cap == 0 || old_ptr.is_null() {
        return (core::ptr::null_mut(), 0);
    }
    let growth = if old_cap < 128 {
        old_cap
    } else if old_cap < 1024 {
        old_cap / 2
    } else {
        256
    };
    let new_cap = core::cmp::max(min_required, old_cap + growth);
    let new_ptr = unsafe { vfs_alloc_array::<T>(new_cap) };
    if new_ptr.is_null() {
        return (core::ptr::null_mut(), 0);
    }
    // SAFETY: pool grow is only called from a single owner context (the VFS
    // server loop or bootstrap). No concurrent access to these slots occurs
    // during the copy, so bitwise copy via copy_nonoverlapping is safe even
    // for types containing AtomicU32 or Mutex.
    unsafe {
        core::ptr::copy_nonoverlapping(old_ptr, new_ptr, old_cap);
    }
    let old_bytes = old_cap * core::mem::size_of::<T>();
    let old_pages = (old_bytes + 4095) / 4096;
    unsafe {
        crate::server::mem::unmap(old_ptr as *mut u8, (old_pages * 4096) as u64);
    }
    (new_ptr, new_cap)
}

pub(crate) unsafe fn vfs_grow_array<T>(old_ptr: *mut T, old_cap: usize) -> (*mut T, usize) {
    unsafe { vfs_grow_array_with_min(old_ptr, old_cap, 0) }
}

pub(crate) unsafe fn init_dynamic_state_storage() -> i32 {
    0
}
