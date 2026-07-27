// SPDX-License-Identifier: GPL-2.0-only
//
//! Tmpfs per-mount pools.
//!
//! Same three-pool layout as ramfs (vnode-data / writable chain /
//! symlink) plus quota accounting (`max_bytes`, `max_inodes`).
//! Quota is enforced before each allocation; backing storage on
//! release is returned to the pool but not to mmsrv (a future page-
//! cache sweep will pair the `map_anon` calls with `unmap`).

use crate::core::vnode::VT_LNK;
use crate::server::alloc::{vfs_alloc_array, vfs_grow_array};
use crate::server::consts::{
    INITIAL_SYMLINKS, INITIAL_VDATA, INITIAL_WRITABLE, INVALID_WRITABLE_SLOT, MAX_NAME_LEN,
    MAX_PATH_LEN, WRITABLE_SIZE,
};

use super::types::{Dirent, TmpfsMountData, TmpfsVnodeData};

// =========================================================================
// Vnode data pool
// =========================================================================

pub(crate) unsafe fn alloc_vdata(md: *mut TmpfsMountData) -> *mut TmpfsVnodeData {
    unsafe {
        for i in 0..(*md).vdata_cap {
            let d = (*md).vdata_ptr.add(i);
            if (*d).active == 0 {
                *d = TmpfsVnodeData::zeroed();
                (*d).active = 1;
                return d;
            }
        }
        let old_ptr = (*md).vdata_ptr;
        let old_cap = (*md).vdata_cap;
        let (new_ptr, new_cap) = vfs_grow_array(old_ptr, old_cap);
        if new_ptr.is_null() {
            return ::core::ptr::null_mut();
        }
        (*md).vdata_ptr = new_ptr;
        (*md).vdata_cap = new_cap;
        let d = new_ptr.add(old_cap);
        *d = TmpfsVnodeData::zeroed();
        (*d).active = 1;
        d
    }
}

pub(crate) unsafe fn find_vdata(md: *mut TmpfsMountData, id: u64) -> *mut TmpfsVnodeData {
    unsafe {
        for i in 0..(*md).vdata_cap {
            let d = (*md).vdata_ptr.add(i);
            if (*d).active != 0 && (*d).id == id {
                return d;
            }
        }
        ::core::ptr::null_mut()
    }
}

pub(crate) unsafe fn next_id(md: *mut TmpfsMountData) -> u64 {
    unsafe {
        let id = (*md).next_id;
        (*md).next_id += 1;
        id
    }
}

// =========================================================================
// Quota accounting
// =========================================================================

/// True when `bytes` more data fits within the mount's quota
/// (or the mount has no quota).
pub(crate) unsafe fn check_bytes(md: *mut TmpfsMountData, bytes: u64) -> bool {
    unsafe {
        if (*md).max_bytes == 0 {
            return true;
        }
        (*md).used_bytes + bytes <= (*md).max_bytes
    }
}

pub(crate) unsafe fn account_bytes_add(md: *mut TmpfsMountData, bytes: u64) {
    unsafe {
        (*md).used_bytes += bytes;
    }
}

pub(crate) unsafe fn account_bytes_sub(md: *mut TmpfsMountData, bytes: u64) {
    unsafe {
        if (*md).used_bytes >= bytes {
            (*md).used_bytes -= bytes;
        } else {
            (*md).used_bytes = 0;
        }
    }
}

pub(crate) unsafe fn check_inodes(md: *mut TmpfsMountData) -> bool {
    unsafe {
        if (*md).max_inodes == 0 {
            return true;
        }
        (*md).used_inodes < (*md).max_inodes
    }
}

pub(crate) unsafe fn account_inode_add(md: *mut TmpfsMountData) {
    unsafe {
        (*md).used_inodes += 1;
    }
}

pub(crate) unsafe fn account_inode_sub(md: *mut TmpfsMountData) {
    unsafe {
        if (*md).used_inodes > 0 {
            (*md).used_inodes -= 1;
        }
    }
}

// =========================================================================
// Writable block chain pool
// =========================================================================

pub(crate) unsafe fn alloc_writable(md: *mut TmpfsMountData) -> u32 {
    unsafe {
        if (*md).writable_cap == 0 && init_writable_pool(md) != 0 {
            return INVALID_WRITABLE_SLOT;
        }
        for i in 0..(*md).writable_cap {
            if *(*md).writable_used_ptr.add(i) == 0 {
                *(*md).writable_used_ptr.add(i) = 1;
                *(*md).writable_next_ptr.add(i) = u32::MAX;
                let slot = writable_slot_ptr(md, i as u32);
                ::core::ptr::write_bytes(slot, 0, WRITABLE_SIZE);
                return i as u32;
            }
        }
        if grow_writable_pool(md) != 0 {
            return INVALID_WRITABLE_SLOT;
        }
        alloc_writable(md)
    }
}

#[inline]
unsafe fn writable_slot_ptr(md: *mut TmpfsMountData, idx: u32) -> *mut u8 {
    unsafe {
        if idx == INVALID_WRITABLE_SLOT || (idx as usize) >= (*md).writable_cap {
            return ::core::ptr::null_mut();
        }
        (*md).writable_pool_ptr.add(idx as usize) as *mut u8
    }
}

pub(crate) unsafe fn free_chain(md: *mut TmpfsMountData, head_slot: u32) {
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

pub(crate) unsafe fn chain_read(
    md: *mut TmpfsMountData,
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
            ::core::ptr::copy_nonoverlapping(src, dst.add(total as usize), n);
            total += n as u64;
            slot_off = 0;
            slot_idx = *(*md).writable_next_ptr.add(slot_idx as usize);
        }
        total
    }
}

pub(crate) unsafe fn chain_write(
    md: *mut TmpfsMountData,
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
            ::core::ptr::copy_nonoverlapping(src.add(total as usize), dst_ptr, n);
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

pub(crate) unsafe fn chain_truncate(md: *mut TmpfsMountData, head_slot: u32, new_size: u64) {
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
        let off_in_slot = (new_size as usize) % WRITABLE_SIZE;
        if off_in_slot > 0 {
            let p = writable_slot_ptr(md, slot_idx).add(off_in_slot);
            ::core::ptr::write_bytes(p, 0, WRITABLE_SIZE - off_in_slot);
        }
    }
}

/// Number of writable slots used by a given chain.
pub(crate) unsafe fn chain_slot_count(md: *mut TmpfsMountData, head_slot: u32) -> u64 {
    unsafe {
        if head_slot == INVALID_WRITABLE_SLOT {
            return 0;
        }
        let mut count: u64 = 0;
        let mut idx = head_slot;
        while idx != u32::MAX && (idx as usize) < (*md).writable_cap {
            count += 1;
            idx = *(*md).writable_next_ptr.add(idx as usize);
        }
        count
    }
}

/// Count writable slots still reachable from active tmpfs file
/// vnodes. This is the statfs view of allocated data blocks; it is
/// intentionally derived from vnode chains rather than the freelist
/// bitmap so leaked or stale pool entries do not masquerade as live
/// file data.
pub(crate) unsafe fn allocated_file_slot_count(md: *mut TmpfsMountData) -> u64 {
    unsafe {
        let mut count = 0;
        for i in 0..(*md).vdata_cap {
            let vd = (*md).vdata_ptr.add(i);
            if (*vd).active == 0 || (*vd).ftype == VT_LNK {
                continue;
            }
            count += chain_slot_count(md, (*vd).writable_head);
        }
        count
    }
}

unsafe fn grow_writable_pool(md: *mut TmpfsMountData) -> i32 {
    unsafe {
        let old_cap = (*md).writable_cap;
        if old_cap == 0 {
            return -1;
        }

        let (new_pool, new_cap) = vfs_grow_array((*md).writable_pool_ptr, old_cap);
        if new_pool.is_null() {
            return -1;
        }
        (*md).writable_pool_ptr = new_pool;

        let new_used: *mut u8 = vfs_alloc_array::<u8>(new_cap);
        if new_used.is_null() {
            return -1;
        }
        ::core::ptr::copy_nonoverlapping((*md).writable_used_ptr, new_used, old_cap);
        ::core::ptr::write_bytes(new_used.add(old_cap), 0, new_cap - old_cap);
        if !(*md).writable_used_ptr.is_null() {
            let old_pages = (old_cap + 4095) / 4096;
            crate::server::mem::unmap((*md).writable_used_ptr, (old_pages * 4096) as u64);
        }
        (*md).writable_used_ptr = new_used;

        let new_next: *mut u32 = vfs_alloc_array::<u32>(new_cap);
        if new_next.is_null() {
            return -1;
        }
        ::core::ptr::copy_nonoverlapping((*md).writable_next_ptr, new_next, old_cap);
        for i in old_cap..new_cap {
            *new_next.add(i) = u32::MAX;
        }
        if !(*md).writable_next_ptr.is_null() {
            let old_bytes = old_cap * ::core::mem::size_of::<u32>();
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

pub(crate) unsafe fn alloc_symlink(
    md: *mut TmpfsMountData,
    target: *const u8,
    target_len: u8,
) -> *mut u8 {
    unsafe {
        if (*md).symlink_cap == 0 && init_symlink_pool(md) != 0 {
            return ::core::ptr::null_mut();
        }
        for i in 0..(*md).symlink_cap {
            if *(*md).symlink_used_ptr.add(i) == 0 {
                *(*md).symlink_used_ptr.add(i) = 1;
                let slot = (*md).symlink_pool_ptr.add(i) as *mut u8;
                ::core::ptr::write_bytes(slot, 0, MAX_PATH_LEN);
                for j in 0..target_len as usize {
                    *slot.add(j) = *target.add(j);
                }
                return slot;
            }
        }
        ::core::ptr::null_mut()
    }
}

pub(crate) unsafe fn free_symlink(md: *mut TmpfsMountData, ptr: *mut u8) {
    unsafe {
        if ptr.is_null() || (*md).symlink_pool_ptr.is_null() {
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

pub(crate) unsafe fn dir_add_entry(
    vdata: *mut TmpfsVnodeData,
    name: *const u8,
    name_len: u8,
    child_id: u64,
) -> i32 {
    unsafe {
        for i in 0..(*vdata).dirents_cap as usize {
            if (*(*vdata).dirents.add(i)).active == 0 {
                let ent = (*vdata).dirents.add(i);
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
        let (new_ptr, new_cap) = vfs_grow_array((*vdata).dirents, (*vdata).dirents_cap as usize);
        if new_ptr.is_null() {
            return -1;
        }
        (*vdata).dirents = new_ptr;
        (*vdata).dirents_cap = new_cap as u16;
        dir_add_entry(vdata, name, name_len, child_id)
    }
}

pub(crate) unsafe fn dir_find_entry(
    vdata: *mut TmpfsVnodeData,
    name: *const u8,
    name_len: u8,
) -> *mut Dirent {
    unsafe {
        for i in 0..(*vdata).dirents_cap as usize {
            let ent = (*vdata).dirents.add(i);
            if (*ent).active != 0
                && (*ent).name_len == name_len
                && str_eq((*ent).name.as_ptr(), name, name_len as usize)
            {
                return ent;
            }
        }
        ::core::ptr::null_mut()
    }
}

/// Case-insensitive preserving lookup used by Win32-style walks.
/// The dirent keeps its original casing; the comparison folds only
/// ASCII bytes.
pub(crate) unsafe fn dir_find_entry_ci(
    vdata: *mut TmpfsVnodeData,
    name: *const u8,
    name_len: u8,
) -> *mut Dirent {
    unsafe {
        let requested = ::core::slice::from_raw_parts(name, name_len as usize);
        for i in 0..(*vdata).dirents_cap as usize {
            let ent = (*vdata).dirents.add(i);
            if (*ent).active == 0 || (*ent).name_len != name_len {
                continue;
            }
            let candidate = ::core::slice::from_raw_parts((*ent).name.as_ptr(), name_len as usize);
            if crate::ops::CaseFoldPolicy::InsensitivePreserving.names_equal(candidate, requested) {
                return ent;
            }
        }
        ::core::ptr::null_mut()
    }
}

pub(crate) unsafe fn dir_remove_entry(
    vdata: *mut TmpfsVnodeData,
    name: *const u8,
    name_len: u8,
) -> i32 {
    unsafe {
        for i in 0..(*vdata).dirents_cap as usize {
            let ent = (*vdata).dirents.add(i);
            if (*ent).active != 0
                && (*ent).name_len == name_len
                && str_eq((*ent).name.as_ptr(), name, name_len as usize)
            {
                *ent = Dirent::zeroed();
                return 0;
            }
        }
        -1
    }
}

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
// Pool initialization
// =========================================================================

pub(crate) unsafe fn init_pools(md: *mut TmpfsMountData) -> i32 {
    unsafe {
        let vdata: *mut TmpfsVnodeData = vfs_alloc_array(INITIAL_VDATA);
        if vdata.is_null() {
            return -1;
        }
        (*md).vdata_ptr = vdata;
        (*md).vdata_cap = INITIAL_VDATA;

        (*md).next_id = 1;
        0
    }
}

unsafe fn init_writable_pool(md: *mut TmpfsMountData) -> i32 {
    unsafe {
        if (*md).writable_cap != 0 {
            return 0;
        }
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

        0
    }
}

unsafe fn init_symlink_pool(md: *mut TmpfsMountData) -> i32 {
    unsafe {
        if (*md).symlink_cap != 0 {
            return 0;
        }
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

        0
    }
}
