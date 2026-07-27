// SPDX-License-Identifier: GPL-2.0-only
//! Pool management for ramfs: vnode-data allocation, writable block chains,
//! symlink targets, and directory entry arrays.
//!
//! All pools are per-mount — accessed through `RamfsMountData` via
//! `Mount.data`. Growth is handled by `vfs_alloc_array` / `vfs_grow_pool`
//! / `vfs_grow_array` which delegate to mmsrv.
//!
//! Vnode allocation is handled by the central arena (via `VopContext.alloc`).
//! This module manages only backend-private data pools.

use crate::server::consts::*;
use crate::{vfs_alloc_array, vfs_grow_array, vfs_grow_pool};

use super::types::{Dirent, RamfsMountData, RamfsVnodeData};

// =========================================================================
// Vnode data pool
// =========================================================================

/// Initial vnode-data pool capacity.
pub(super) const INITIAL_VDATA: usize = 128;

/// Allocate a fresh `RamfsVnodeData` slot.
pub(super) unsafe fn alloc_vdata(md: *mut RamfsMountData) -> *mut RamfsVnodeData {
    unsafe {
        for i in 0..(*md).vdata_cap {
            let d = (*md).vdata_ptr.add(i);
            if (*d).active == 0 {
                *d = RamfsVnodeData::zeroed();
                (*d).active = 1;
                return d;
            }
        }
        // Grow (RamfsVnodeData is not Copy — use byte-level vfs_grow_pool)
        let old_cap = (*md).vdata_cap;
        if vfs_grow_pool(
            &raw mut (*md).vdata_ptr as *mut *mut u8,
            &raw mut (*md).vdata_cap,
            core::mem::size_of::<RamfsVnodeData>(),
        ) != 0
        {
            return core::ptr::null_mut();
        }
        let d = (*md).vdata_ptr.add(old_cap);
        *d = RamfsVnodeData::zeroed();
        (*d).active = 1;
        d
    }
}

/// Find vnode data by id.
pub(crate) unsafe fn find_vdata(md: *mut RamfsMountData, id: u64) -> *mut RamfsVnodeData {
    unsafe {
        for i in 0..(*md).vdata_cap {
            let d = (*md).vdata_ptr.add(i);
            if (*d).active != 0 && (*d).id == id {
                return d;
            }
        }
        core::ptr::null_mut()
    }
}

/// Assign a new unique id from the mount's counter.
pub(super) unsafe fn next_id(md: *mut RamfsMountData) -> u64 {
    unsafe {
        let id = (*md).next_id;
        (*md).next_id += 1;
        id
    }
}

// =========================================================================
// Writable block chain pool
// =========================================================================

/// Allocate a writable block slot. Returns the slot index, or
/// `INVALID_WRITABLE_SLOT` on failure.
pub(super) unsafe fn alloc_writable(md: *mut RamfsMountData) -> u32 {
    unsafe {
        for i in 0..(*md).writable_cap {
            if *(*md).writable_used_ptr.add(i) == 0 {
                *(*md).writable_used_ptr.add(i) = 1;
                *(*md).writable_next_ptr.add(i) = u32::MAX;
                let slot = writable_slot_ptr(md, i as u32);
                core::ptr::write_bytes(slot, 0, WRITABLE_SIZE);
                return i as u32;
            }
        }
        // Grow and retry
        if grow_writable_pool(md) != 0 {
            return INVALID_WRITABLE_SLOT;
        }
        alloc_writable(md)
    }
}

/// Get a raw pointer to the data of writable slot `idx`.
#[inline]
unsafe fn writable_slot_ptr(md: *mut RamfsMountData, idx: u32) -> *mut u8 {
    unsafe {
        if idx == INVALID_WRITABLE_SLOT || (idx as usize) >= (*md).writable_cap {
            return core::ptr::null_mut();
        }
        (*md).writable_pool_ptr.add(idx as usize) as *mut u8
    }
}

/// Free an entire chain of writable slots starting from `head_slot`.
pub(super) unsafe fn free_chain(md: *mut RamfsMountData, head_slot: u32) {
    unsafe {
        if head_slot == INVALID_WRITABLE_SLOT {
            return;
        }
        let mut idx = head_slot;
        while (idx as usize) < (*md).writable_cap {
            *(*md).writable_used_ptr.add(idx as usize) = 0;
            let next = *(*md).writable_next_ptr.add(idx as usize);
            *(*md).writable_next_ptr.add(idx as usize) = u32::MAX;
            if next == u32::MAX {
                break;
            }
            idx = next;
        }
    }
}

/// Read bytes from a writable block chain.
pub(super) unsafe fn chain_read(
    md: *mut RamfsMountData,
    head_slot: u32,
    offset: u64,
    dst: *mut u8,
    count: u64,
) -> u64 {
    unsafe {
        if head_slot == INVALID_WRITABLE_SLOT || count == 0 {
            return 0;
        }
        let mut slot_idx = head_slot;
        // Skip slots to reach offset
        let mut skip = (offset as usize) / WRITABLE_SIZE;
        while skip > 0 && slot_idx != u32::MAX && (slot_idx as usize) < (*md).writable_cap {
            slot_idx = *(*md).writable_next_ptr.add(slot_idx as usize);
            skip -= 1;
        }
        if slot_idx == u32::MAX || (slot_idx as usize) >= (*md).writable_cap {
            return 0;
        }
        let mut slot_off = (offset as usize) % WRITABLE_SIZE;
        let mut total: u64 = 0;
        while total < count && slot_idx != u32::MAX && (slot_idx as usize) < (*md).writable_cap {
            let avail = WRITABLE_SIZE - slot_off;
            let want = (count - total) as usize;
            let n = if want < avail { want } else { avail };
            let src = writable_slot_ptr(md, slot_idx).add(slot_off);
            core::ptr::copy_nonoverlapping(src, dst.add(total as usize), n);
            total += n as u64;
            slot_off = 0;
            slot_idx = *(*md).writable_next_ptr.add(slot_idx as usize);
        }
        total
    }
}

/// Write bytes to a writable block chain, extending the chain as needed.
pub(super) unsafe fn chain_write(
    md: *mut RamfsMountData,
    head_slot: u32,
    offset: u64,
    src: *const u8,
    count: u64,
) -> u64 {
    unsafe {
        if head_slot == INVALID_WRITABLE_SLOT || count == 0 {
            return 0;
        }
        let target_slot_num = (offset as usize) / WRITABLE_SIZE;
        let mut slot_idx = head_slot;
        for _ in 0..target_slot_num {
            let next = *(*md).writable_next_ptr.add(slot_idx as usize);
            if next == u32::MAX || (next as usize) >= (*md).writable_cap {
                let new_slot = alloc_writable(md);
                if new_slot == INVALID_WRITABLE_SLOT {
                    return 0;
                }
                *(*md).writable_next_ptr.add(slot_idx as usize) = new_slot;
                slot_idx = new_slot;
            } else {
                slot_idx = next;
            }
        }
        let mut slot_off = (offset as usize) % WRITABLE_SIZE;
        let mut total: u64 = 0;
        while total < count {
            if (slot_idx as usize) >= (*md).writable_cap {
                break;
            }
            let avail = WRITABLE_SIZE - slot_off;
            let want = (count - total) as usize;
            let n = if want < avail { want } else { avail };
            let dst_ptr = writable_slot_ptr(md, slot_idx).add(slot_off);
            core::ptr::copy_nonoverlapping(src.add(total as usize), dst_ptr, n);
            total += n as u64;
            slot_off = 0;
            if total < count {
                let next = *(*md).writable_next_ptr.add(slot_idx as usize);
                if next == u32::MAX || (next as usize) >= (*md).writable_cap {
                    let new_slot = alloc_writable(md);
                    if new_slot == INVALID_WRITABLE_SLOT {
                        break;
                    }
                    *(*md).writable_next_ptr.add(slot_idx as usize) = new_slot;
                    slot_idx = new_slot;
                } else {
                    slot_idx = next;
                }
            }
        }
        total
    }
}

/// Truncate a block chain: free slots beyond `new_size` bytes.
pub(super) unsafe fn chain_truncate(md: *mut RamfsMountData, head_slot: u32, new_size: u64) {
    unsafe {
        if head_slot == INVALID_WRITABLE_SLOT {
            return;
        }
        let keep_slots = if new_size == 0 {
            1
        } else {
            ((new_size as usize) + WRITABLE_SIZE - 1) / WRITABLE_SIZE
        };
        let mut slot_idx = head_slot;
        let mut count = 1usize;
        while count < keep_slots && slot_idx != u32::MAX && (slot_idx as usize) < (*md).writable_cap
        {
            let next = *(*md).writable_next_ptr.add(slot_idx as usize);
            if next == u32::MAX {
                return;
            }
            slot_idx = next;
            count += 1;
        }
        // Free everything after this slot
        let tail = *(*md).writable_next_ptr.add(slot_idx as usize);
        *(*md).writable_next_ptr.add(slot_idx as usize) = u32::MAX;
        if tail != u32::MAX {
            let mut idx = tail;
            while idx != u32::MAX && (idx as usize) < (*md).writable_cap {
                *(*md).writable_used_ptr.add(idx as usize) = 0;
                let next = *(*md).writable_next_ptr.add(idx as usize);
                *(*md).writable_next_ptr.add(idx as usize) = u32::MAX;
                idx = next;
            }
        }
        // Zero data beyond new_size in the last kept slot
        let off_in_slot = (new_size as usize) % WRITABLE_SIZE;
        if off_in_slot > 0 {
            let p = writable_slot_ptr(md, slot_idx).add(off_in_slot);
            core::ptr::write_bytes(p, 0, WRITABLE_SIZE - off_in_slot);
        }
    }
}

/// Grow all three writable pool arrays in lock-step.
unsafe fn grow_writable_pool(md: *mut RamfsMountData) -> i32 {
    unsafe {
        let old_cap = (*md).writable_cap;
        if old_cap == 0 {
            return -1;
        }

        // Grow WRITABLE_POOL
        let (new_pool, new_cap) = vfs_grow_array((*md).writable_pool_ptr, old_cap);
        if new_pool.is_null() {
            return -1;
        }
        (*md).writable_pool_ptr = new_pool;

        // Grow WRITABLE_USED
        let new_used: *mut u8 = vfs_alloc_array::<u8>(new_cap);
        if new_used.is_null() {
            return -1;
        }
        core::ptr::copy_nonoverlapping((*md).writable_used_ptr, new_used, old_cap);
        core::ptr::write_bytes(new_used.add(old_cap), 0, new_cap - old_cap);
        if !(*md).writable_used_ptr.is_null() {
            let old_pages = (old_cap + 4095) / 4096;
            crate::server::mem::unmap((*md).writable_used_ptr, (old_pages * 4096) as u64);
        }
        (*md).writable_used_ptr = new_used;

        // Grow WRITABLE_NEXT
        let new_next: *mut u32 = vfs_alloc_array::<u32>(new_cap);
        if new_next.is_null() {
            return -1;
        }
        core::ptr::copy_nonoverlapping((*md).writable_next_ptr, new_next, old_cap);
        for i in old_cap..new_cap {
            *new_next.add(i) = u32::MAX;
        }
        if !(*md).writable_next_ptr.is_null() {
            let old_bytes = old_cap * core::mem::size_of::<u32>();
            let old_pages = (old_bytes + 4095) / 4096;
            crate::server::mem::unmap(
                (*md).writable_next_ptr as *mut u8,
                (old_pages * 4096) as u64,
            );
        }
        (*md).writable_next_ptr = new_next;

        (*md).writable_cap = new_cap;
        0
    }
}

// =========================================================================
// Symlink pool
// =========================================================================

/// Allocate a symlink target slot and copy `target[..target_len]` into it.
pub(super) unsafe fn alloc_symlink(
    md: *mut RamfsMountData,
    target: *const u8,
    target_len: u8,
) -> *mut u8 {
    unsafe {
        for i in 0..(*md).symlink_cap {
            if *(*md).symlink_used_ptr.add(i) == 0 {
                *(*md).symlink_used_ptr.add(i) = 1;
                let slot = (*md).symlink_pool_ptr.add(i) as *mut u8;
                core::ptr::write_bytes(slot, 0, MAX_PATH_LEN);
                for j in 0..target_len as usize {
                    *slot.add(j) = *target.add(j);
                }
                return slot;
            }
        }
        core::ptr::null_mut()
    }
}

/// Free a symlink target slot.
pub(super) unsafe fn free_symlink(md: *mut RamfsMountData, ptr: *mut u8) {
    unsafe {
        if ptr.is_null() {
            return;
        }
        if (*md).symlink_pool_ptr.is_null() {
            return;
        }
        let base = (*md).symlink_pool_ptr as *mut u8;
        let offset = ptr as usize - base as usize;
        let idx = offset / MAX_PATH_LEN;
        if idx < (*md).symlink_cap {
            *(*md).symlink_used_ptr.add(idx) = 0;
        }
    }
}

// =========================================================================
// Directory entry helpers
// =========================================================================

/// Add a directory entry to a vnode-data's dirent array.
pub(super) unsafe fn dir_add_entry(
    vd: *mut RamfsVnodeData,
    name: *const u8,
    name_len: u8,
    child_id: u64,
) -> i32 {
    unsafe {
        for i in 0..(*vd).dirents_cap as usize {
            if (*(*vd).dirents.add(i)).active == 0 {
                let ent = (*vd).dirents.add(i);
                (*ent).active = 1;
                (*ent).ino = child_id as u32;
                (*ent).name_len = name_len;
                let n = if (name_len as usize) < MAX_NAME_LEN {
                    name_len as usize
                } else {
                    MAX_NAME_LEN
                };
                for j in 0..n {
                    (*ent).name[j] = *name.add(j);
                }
                return 0;
            }
        }
        // Grow
        let (new_ptr, new_cap) = vfs_grow_array((*vd).dirents, (*vd).dirents_cap as usize);
        if new_ptr.is_null() {
            return -1;
        }
        (*vd).dirents = new_ptr;
        (*vd).dirents_cap = new_cap as u16;
        dir_add_entry(vd, name, name_len, child_id)
    }
}

/// Find a directory entry by name.
pub(super) unsafe fn dir_find_entry(
    vd: *mut RamfsVnodeData,
    name: *const u8,
    name_len: u8,
) -> *mut Dirent {
    unsafe {
        for i in 0..(*vd).dirents_cap as usize {
            let ent = (*vd).dirents.add(i);
            if (*ent).active != 0
                && (*ent).name_len == name_len
                && str_eq((*ent).name.as_ptr(), name, name_len as usize)
            {
                return ent;
            }
        }
        core::ptr::null_mut()
    }
}

/// Remove a directory entry by name.
pub(super) unsafe fn dir_remove_entry(
    vd: *mut RamfsVnodeData,
    name: *const u8,
    name_len: u8,
) -> i32 {
    unsafe {
        for i in 0..(*vd).dirents_cap as usize {
            let ent = (*vd).dirents.add(i);
            if (*ent).active != 0
                && (*ent).name_len == name_len
                && str_eq((*ent).name.as_ptr(), name, name_len as usize)
            {
                (*ent).active = 0;
                return 0;
            }
        }
        -1
    }
}

/// Byte-compare two equal-length slices given as raw pointers.
#[inline]
fn str_eq(a: *const u8, b: *const u8, len: usize) -> bool {
    for i in 0..len {
        if unsafe { *a.add(i) != *b.add(i) } {
            return false;
        }
    }
    true
}

// =========================================================================
// Pool initialization (called from VfsOps::mount)
// =========================================================================

/// Allocate all pools for a fresh ramfs mount. Returns 0 on success.
pub(super) unsafe fn init_pools(md: *mut RamfsMountData) -> i32 {
    unsafe {
        // Vnode data pool
        let vdata: *mut RamfsVnodeData = vfs_alloc_array(INITIAL_VDATA);
        if vdata.is_null() {
            return -1;
        }
        (*md).vdata_ptr = vdata;
        (*md).vdata_cap = INITIAL_VDATA;

        // Writable block pool
        let writable_pool: *mut [u8; WRITABLE_SIZE] = vfs_alloc_array(INITIAL_WRITABLE);
        if writable_pool.is_null() {
            return -1;
        }
        (*md).writable_pool_ptr = writable_pool;

        let writable_used: *mut u8 = vfs_alloc_array(INITIAL_WRITABLE);
        if writable_used.is_null() {
            return -1;
        }
        (*md).writable_used_ptr = writable_used;

        let writable_next: *mut u32 = vfs_alloc_array(INITIAL_WRITABLE);
        if writable_next.is_null() {
            return -1;
        }
        for i in 0..INITIAL_WRITABLE {
            *writable_next.add(i) = u32::MAX;
        }
        (*md).writable_next_ptr = writable_next;
        (*md).writable_cap = INITIAL_WRITABLE;

        // Symlink pool
        let sym_pool: *mut [u8; MAX_PATH_LEN] = vfs_alloc_array(INITIAL_SYMLINKS);
        if sym_pool.is_null() {
            return -1;
        }
        (*md).symlink_pool_ptr = sym_pool;

        let sym_used: *mut u8 = vfs_alloc_array(INITIAL_SYMLINKS);
        if sym_used.is_null() {
            return -1;
        }
        (*md).symlink_used_ptr = sym_used;
        (*md).symlink_cap = INITIAL_SYMLINKS;

        (*md).next_id = 1;
        0
    }
}
