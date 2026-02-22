// SPDX-License-Identifier: GPL-2.0-only
//! In-memory filesystem: inode allocation, directory operations, and initrd mounting.

use salty::consts::*;
use salty::cpio;
use salty::serial::LineBuf;
use salty::types::*;

use crate::consts::*;
use crate::types::*;
use crate::{
    puts, str_equal_raw,
    max_inodes, max_writable,
    vfs_alloc_array, vfs_grow_pool, vfs_grow_array,
    INODES, WRITABLE_POOL, WRITABLE_USED,
};

pub(crate) fn read_boot_info_initrd_size() -> usize {
    unsafe {
        let page = BOOTINFO_VADDR as *const u64;
        let magic = core::ptr::read_volatile(page);
        if magic != BOOTINFO_MAGIC {
            return 0;
        }
        core::ptr::read_volatile(page.add(2)) as usize
    }
}

pub(crate) unsafe fn inode_by_ino(ino: u32) -> *mut RamfsInode {
    unsafe {
        for i in 0..max_inodes() {
            if INODES!()[i].active != 0 && INODES!()[i].ino == ino {
                return &raw mut INODES!()[i];
            }
        }
        core::ptr::null_mut()
    }
}

pub(crate) unsafe fn alloc_inode() -> *mut RamfsInode {
    unsafe {
        for i in 0..max_inodes() {
            if INODES!()[i].active == 0 {
                let n = &raw mut INODES!()[i];
                (*n).active = 1;
                (*n).ino = *(&raw const crate::NEXT_INO);
                *(&raw mut crate::NEXT_INO) += 1;
                (*n).readonly = 0;
                (*n).nlink = 1;
                (*n).size = 0;
                (*n).mtime = 0;
                (*n).parent_ino = 0;
                (*n).ro_data = core::ptr::null();
                (*n).rw_data = core::ptr::null_mut();
                (*n).open_count = 0;
                // Allocate dirents array if not yet allocated
                if (*n).dirents.is_null() {
                    let ptr = vfs_alloc_array::<RamfsDirent>(INITIAL_DIRENTS);
                    if ptr.is_null() {
                        (*n).active = 0;
                        return core::ptr::null_mut();
                    }
                    (*n).dirents = ptr;
                    (*n).dirents_cap = INITIAL_DIRENTS as u16;
                }
                for j in 0..(*n).dirents_cap as usize {
                    (*(*n).dirents.add(j)).active = 0;
                }
                return n;
            }
        }
        // No free slot: grow the pool and retry
        if vfs_grow_pool(
            &raw mut crate::INODES_PTR as *mut *mut u8,
            &raw mut crate::INODES_CAP,
            core::mem::size_of::<RamfsInode>(),
        ) != 0 {
            return core::ptr::null_mut();
        }
        alloc_inode()  // Tail-recursive retry
    }
}

pub(crate) unsafe fn alloc_writable() -> *mut u8 {
    unsafe {
        for i in 0..max_writable() {
            if WRITABLE_USED!()[i] == 0 {
                WRITABLE_USED!()[i] = 1;
                *crate::WRITABLE_NEXT_PTR.add(i) = u32::MAX;
                for j in 0..WRITABLE_SIZE {
                    WRITABLE_POOL!()[i][j] = 0;
                }
                return WRITABLE_POOL!()[i].as_mut_ptr();
            }
        }
        // No free slot: grow both arrays and retry
        if grow_writable_pool() != 0 {
            return core::ptr::null_mut();
        }
        alloc_writable()
    }
}

/// Get the slot index for a writable data pointer.
pub(crate) unsafe fn slot_index_of(rw_data: *const u8) -> u32 {
    unsafe {
        let base = crate::WRITABLE_POOL_PTR as *const u8;
        let offset = rw_data as usize - base as usize;
        (offset / WRITABLE_SIZE) as u32
    }
}

/// Free an entire chain of writable slots starting from `rw_data`.
pub(crate) unsafe fn free_chain(rw_data: *const u8) {
    unsafe {
        if rw_data.is_null() {
            return;
        }
        let mut idx = slot_index_of(rw_data);
        while (idx as usize) < max_writable() {
            WRITABLE_USED!()[idx as usize] = 0;
            let next = *crate::WRITABLE_NEXT_PTR.add(idx as usize);
            *crate::WRITABLE_NEXT_PTR.add(idx as usize) = u32::MAX;
            if next == u32::MAX {
                break;
            }
            idx = next;
        }
    }
}

/// Free an inode and its associated storage (chain or symlink target).
pub(crate) unsafe fn free_inode(inode: *mut RamfsInode) {
    unsafe {
        if (*inode).ftype == FTYPE_SYMLINK {
            free_symlink_target((*inode).rw_data);
        } else {
            free_chain((*inode).rw_data);
        }
        (*inode).rw_data = core::ptr::null_mut();
        (*inode).active = 0;
    }
}

/// Increment the open reference count on an inode.
pub(crate) unsafe fn inode_open(ino: u32) {
    unsafe {
        let inode = inode_by_ino(ino);
        if !inode.is_null() {
            (*inode).open_count += 1;
        }
    }
}

/// Decrement the open reference count on an inode.
/// If nlink==0 and open_count drops to 0, free the inode storage.
pub(crate) unsafe fn inode_close(ino: u32) {
    unsafe {
        let inode = inode_by_ino(ino);
        if !inode.is_null() && (*inode).open_count > 0 {
            (*inode).open_count -= 1;
            if (*inode).nlink == 0 && (*inode).open_count == 0 {
                free_inode(inode);
            }
        }
    }
}

/// Read from a chain of writable slots.
/// Returns number of bytes actually read.
pub(crate) unsafe fn chain_read(rw_data: *const u8, offset: u64, dst: *mut u8, count: u64) -> u64 {
    unsafe {
        if rw_data.is_null() || count == 0 {
            return 0;
        }
        let mut slot_idx = slot_index_of(rw_data);
        // Skip slots to reach the right offset
        let mut skip_slots = (offset as usize) / WRITABLE_SIZE;
        while skip_slots > 0 && slot_idx != u32::MAX && (slot_idx as usize) < max_writable() {
            slot_idx = *crate::WRITABLE_NEXT_PTR.add(slot_idx as usize);
            skip_slots -= 1;
        }
        if slot_idx == u32::MAX || (slot_idx as usize) >= max_writable() {
            return 0;
        }
        let mut slot_off = (offset as usize) % WRITABLE_SIZE;
        let mut total: u64 = 0;
        while total < count && slot_idx != u32::MAX && (slot_idx as usize) < max_writable() {
            let avail = WRITABLE_SIZE - slot_off;
            let want = (count - total) as usize;
            let n = if want < avail { want } else { avail };
            let src = WRITABLE_POOL!()[slot_idx as usize].as_ptr().add(slot_off);
            core::ptr::copy_nonoverlapping(src, dst.add(total as usize), n);
            total += n as u64;
            slot_off = 0;
            slot_idx = *crate::WRITABLE_NEXT_PTR.add(slot_idx as usize);
        }
        total
    }
}

/// Write to a chain of writable slots, extending the chain as needed.
/// Returns number of bytes actually written, or 0 on allocation failure.
pub(crate) unsafe fn chain_write(rw_data: *mut u8, offset: u64, src: *const u8, count: u64) -> u64 {
    unsafe {
        if rw_data.is_null() || count == 0 {
            return 0;
        }
        let first_idx = slot_index_of(rw_data);
        // Navigate to the slot containing `offset`, extending if needed
        let target_slot_num = (offset as usize) / WRITABLE_SIZE;
        let mut slot_idx = first_idx;
        for _ in 0..target_slot_num {
            let next = *crate::WRITABLE_NEXT_PTR.add(slot_idx as usize);
            if next == u32::MAX || (next as usize) >= max_writable() {
                // Need to extend
                let new_slot = alloc_writable();
                if new_slot.is_null() {
                    return 0;
                }
                let new_idx = slot_index_of(new_slot);
                *crate::WRITABLE_NEXT_PTR.add(slot_idx as usize) = new_idx;
                slot_idx = new_idx;
            } else {
                slot_idx = next;
            }
        }
        let mut slot_off = (offset as usize) % WRITABLE_SIZE;
        let mut total: u64 = 0;
        while total < count {
            if (slot_idx as usize) >= max_writable() {
                break;
            }
            let avail = WRITABLE_SIZE - slot_off;
            let want = (count - total) as usize;
            let n = if want < avail { want } else { avail };
            let dst_ptr = WRITABLE_POOL!()[slot_idx as usize].as_mut_ptr().add(slot_off);
            core::ptr::copy_nonoverlapping(src.add(total as usize), dst_ptr, n);
            total += n as u64;
            slot_off = 0;
            if total < count {
                let next = *crate::WRITABLE_NEXT_PTR.add(slot_idx as usize);
                if next == u32::MAX || (next as usize) >= max_writable() {
                    let new_slot = alloc_writable();
                    if new_slot.is_null() {
                        break;
                    }
                    let new_idx = slot_index_of(new_slot);
                    *crate::WRITABLE_NEXT_PTR.add(slot_idx as usize) = new_idx;
                    slot_idx = new_idx;
                } else {
                    slot_idx = next;
                }
            }
        }
        total
    }
}

/// Truncate a chain: free slots beyond `new_size` bytes.
pub(crate) unsafe fn chain_truncate(rw_data: *mut u8, new_size: u64) {
    unsafe {
        if rw_data.is_null() {
            return;
        }
        let keep_slots = if new_size == 0 { 1 } else { ((new_size as usize) + WRITABLE_SIZE - 1) / WRITABLE_SIZE };
        let mut slot_idx = slot_index_of(rw_data);
        let mut count = 1usize;
        // Walk to the last slot we want to keep
        while count < keep_slots && slot_idx != u32::MAX && (slot_idx as usize) < max_writable() {
            let next = *crate::WRITABLE_NEXT_PTR.add(slot_idx as usize);
            if next == u32::MAX {
                return; // Chain is already shorter
            }
            slot_idx = next;
            count += 1;
        }
        // Free everything after this slot
        let tail = *crate::WRITABLE_NEXT_PTR.add(slot_idx as usize);
        *crate::WRITABLE_NEXT_PTR.add(slot_idx as usize) = u32::MAX;
        if tail != u32::MAX {
            // Walk and free the tail chain
            let mut idx = tail;
            while idx != u32::MAX && (idx as usize) < max_writable() {
                WRITABLE_USED!()[idx as usize] = 0;
                let next = *crate::WRITABLE_NEXT_PTR.add(idx as usize);
                *crate::WRITABLE_NEXT_PTR.add(idx as usize) = u32::MAX;
                idx = next;
            }
        }
        // Zero out data beyond new_size in the last kept slot
        let off_in_slot = (new_size as usize) % WRITABLE_SIZE;
        if off_in_slot > 0 {
            let p = WRITABLE_POOL!()[slot_idx as usize].as_mut_ptr().add(off_in_slot);
            core::ptr::write_bytes(p, 0, WRITABLE_SIZE - off_in_slot);
        }
    }
}

/// Grow WRITABLE_POOL, WRITABLE_USED, and WRITABLE_NEXT arrays in lock-step.
pub(crate) unsafe fn grow_writable_pool() -> i32 {
    unsafe {
        let old_cap = crate::WRITABLE_CAP;
        if old_cap == 0 {
            return -1;
        }
        let new_cap = old_cap * 2;
        // Grow WRITABLE_POOL
        if vfs_grow_pool(
            &raw mut crate::WRITABLE_POOL_PTR as *mut *mut u8,
            &raw mut crate::WRITABLE_CAP,
            core::mem::size_of::<[u8; WRITABLE_SIZE]>(),
        ) != 0 {
            return -1;
        }
        // Grow WRITABLE_USED (WRITABLE_CAP was updated by vfs_grow_pool above)
        let used_bytes = new_cap;
        let used_pages = (used_bytes + 4095) / 4096;
        let new_used_ptr = salty::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            (used_pages * 4096) as u64,
            0x3, 0x22, -1, 0,
        );
        if new_used_ptr.is_null() || new_used_ptr == usize::MAX as *mut u8 {
            return -1;
        }
        let old_used_ptr = crate::WRITABLE_USED_PTR;
        core::ptr::copy_nonoverlapping(old_used_ptr, new_used_ptr, old_cap);
        core::ptr::write_bytes(new_used_ptr.add(old_cap), 0, new_cap - old_cap);
        if !old_used_ptr.is_null() {
            let old_used_pages = (old_cap + 4095) / 4096;
            salty::posix_mm::posix_munmap(old_used_ptr, (old_used_pages * 4096) as u64);
        }
        crate::WRITABLE_USED_PTR = new_used_ptr;

        // Grow WRITABLE_NEXT
        let next_bytes = new_cap * core::mem::size_of::<u32>();
        let next_pages = (next_bytes + 4095) / 4096;
        let new_next_ptr = salty::posix_mm::posix_mmap(
            core::ptr::null_mut(),
            (next_pages * 4096) as u64,
            0x3, 0x22, -1, 0,
        );
        if new_next_ptr.is_null() || new_next_ptr == usize::MAX as *mut u8 {
            return -1;
        }
        let new_next = new_next_ptr as *mut u32;
        let old_next_ptr = crate::WRITABLE_NEXT_PTR;
        core::ptr::copy_nonoverlapping(old_next_ptr, new_next, old_cap);
        // Initialize new entries to u32::MAX
        for i in old_cap..new_cap {
            *new_next.add(i) = u32::MAX;
        }
        if !old_next_ptr.is_null() {
            let old_next_bytes = old_cap * core::mem::size_of::<u32>();
            let old_next_pages = (old_next_bytes + 4095) / 4096;
            salty::posix_mm::posix_munmap(old_next_ptr as *mut u8, (old_next_pages * 4096) as u64);
        }
        crate::WRITABLE_NEXT_PTR = new_next;
        0
    }
}

/// Allocate a symlink pool slot and store the target path.
/// Returns a pointer to the pool entry, or null on failure.
pub(crate) unsafe fn alloc_symlink_target(target: *const u8, target_len: u8) -> *mut u8 {
    unsafe {
        for i in 0..crate::SYMLINK_CAP {
            if *crate::SYMLINK_USED_PTR.add(i) == 0 {
                *crate::SYMLINK_USED_PTR.add(i) = 1;
                let slot = &raw mut (*crate::SYMLINK_POOL_PTR.add(i));
                let dst = slot as *mut u8;
                core::ptr::write_bytes(dst, 0, MAX_PATH_LEN);
                for j in 0..target_len as usize {
                    *dst.add(j) = *target.add(j);
                }
                return dst;
            }
        }
        core::ptr::null_mut()
    }
}

/// Free a symlink pool slot given the pointer into the pool.
pub(crate) unsafe fn free_symlink_target(ptr: *mut u8) {
    unsafe {
        if ptr.is_null() || crate::SYMLINK_POOL_PTR.is_null() {
            return;
        }
        let base = crate::SYMLINK_POOL_PTR as *mut u8;
        let offset = ptr as usize - base as usize;
        let idx = offset / MAX_PATH_LEN;
        if idx < crate::SYMLINK_CAP {
            *crate::SYMLINK_USED_PTR.add(idx) = 0;
        }
    }
}

pub(crate) unsafe fn dir_add_entry(dir: *mut RamfsInode, name: *const u8, name_len: u8, child_ino: u32) -> i32 {
    unsafe {
        for i in 0..(*dir).dirents_cap as usize {
            if (*(*dir).dirents.add(i)).active == 0 {
                (*(*dir).dirents.add(i)).active = 1;
                (*(*dir).dirents.add(i)).ino = child_ino;
                (*(*dir).dirents.add(i)).name_len = name_len;
                let n = if (name_len as usize) < MAX_NAME_LEN {
                    name_len as usize
                } else {
                    MAX_NAME_LEN
                };
                for j in 0..n {
                    (*(*dir).dirents.add(i)).name[j] = *name.add(j);
                }
                return 0;
            }
        }
        // No free slot: grow dirents array and retry
        let (new_ptr, new_cap) = vfs_grow_array((*dir).dirents, (*dir).dirents_cap as usize);
        if new_ptr.is_null() {
            return -1;
        }
        (*dir).dirents = new_ptr;
        (*dir).dirents_cap = new_cap as u16;
        // Retry: first free slot is at old_cap (now active=0 from zero-init)
        dir_add_entry(dir, name, name_len, child_ino)
    }
}

pub(crate) unsafe fn dir_find_entry(dir: *mut RamfsInode, name: *const u8, name_len: u8) -> *mut RamfsDirent {
    unsafe {
        for i in 0..(*dir).dirents_cap as usize {
            if (*(*dir).dirents.add(i)).active != 0
                && str_equal_raw(
                    (*(*dir).dirents.add(i)).name.as_ptr(),
                    (*(*dir).dirents.add(i)).name_len as usize,
                    name,
                    name_len as usize,
                )
            {
                return (*dir).dirents.add(i);
            }
        }
        core::ptr::null_mut()
    }
}

pub(crate) unsafe fn dir_remove_entry(dir: *mut RamfsInode, name: *const u8, name_len: u8) -> i32 {
    unsafe {
        for i in 0..(*dir).dirents_cap as usize {
            if (*(*dir).dirents.add(i)).active != 0
                && str_equal_raw(
                    (*(*dir).dirents.add(i)).name.as_ptr(),
                    (*(*dir).dirents.add(i)).name_len as usize,
                    name,
                    name_len as usize,
                )
            {
                (*(*dir).dirents.add(i)).active = 0;
                return 0;
            }
        }
        -1
    }
}

pub(crate) unsafe fn ensure_readonly_dir(parent: *mut RamfsInode, name: *const u8, name_len: u8) -> *mut RamfsInode {
    unsafe {
        let existing = dir_find_entry(parent, name, name_len);
        if !existing.is_null() {
            let inode = inode_by_ino((*existing).ino);
            if inode.is_null() || (*inode).ftype != FTYPE_DIRECTORY {
                return core::ptr::null_mut();
            }
            return inode;
        }

        let dir = alloc_inode();
        if dir.is_null() {
            return core::ptr::null_mut();
        }

        (*dir).ftype = FTYPE_DIRECTORY;
        (*dir).mode = S_IFDIR_L | 0o555;
        (*dir).readonly = 1;
        (*dir).nlink = 2;
        (*dir).parent_ino = (*parent).ino;

        if dir_add_entry(parent, name, name_len, (*dir).ino) != 0 {
            (*dir).active = 0;
            return core::ptr::null_mut();
        }
        dir
    }
}

pub(crate) unsafe fn mount_initrd_entry(root: *mut RamfsInode, entry: &CpioEntryExt) -> bool {
    unsafe {
        if root.is_null() || entry.name.is_null() || entry.name_len == 0 {
            return false;
        }

        // Normalize CPIO path:
        // - drop leading '/'
        // - drop leading "./"
        // - strip trailing '/'
        let mut start = 0usize;
        let mut end = entry.name_len;

        while start < end && *entry.name.add(start) == b'/' {
            start += 1;
        }
        while start + 1 < end && *entry.name.add(start) == b'.' && *entry.name.add(start + 1) == b'/' {
            start += 2;
        }
        while end > start && *entry.name.add(end - 1) == b'/' {
            end -= 1;
        }

        if start >= end {
            return true;
        }

        let mut current = root;
        let mut pos = start;

        while pos < end {
            while pos < end && *entry.name.add(pos) == b'/' {
                pos += 1;
            }
            if pos >= end {
                break;
            }

            let comp_start = pos;
            while pos < end && *entry.name.add(pos) != b'/' {
                pos += 1;
            }
            let comp_len = pos - comp_start;
            if comp_len == 0 || comp_len >= MAX_NAME_LEN {
                return false;
            }

            let mut next = pos;
            while next < end && *entry.name.add(next) == b'/' {
                next += 1;
            }
            let is_leaf = next >= end;

            if !is_leaf {
                let dir = ensure_readonly_dir(current, entry.name.add(comp_start), comp_len as u8);
                if dir.is_null() {
                    return false;
                }
                current = dir;
                continue;
            }

            let leaf_name = entry.name.add(comp_start);
            let leaf_len = comp_len as u8;
            let leaf_mode = if entry.mode != 0 { entry.mode } else { S_IFREG_L | 0o444 };
            let leaf_is_dir = (leaf_mode & S_IFMT_L) == S_IFDIR_L;
            let leaf_is_symlink = (leaf_mode & S_IFMT_L) == S_IFLNK_L;

            let existing = dir_find_entry(current, leaf_name, leaf_len);
            if !existing.is_null() {
                let inode = inode_by_ino((*existing).ino);
                if inode.is_null() {
                    return false;
                }
                if leaf_is_dir && (*inode).ftype == FTYPE_DIRECTORY {
                    (*inode).mode = leaf_mode;
                    (*inode).readonly = 1;
                    (*inode).nlink = if entry.nlink != 0 { entry.nlink } else { 2 };
                    (*inode).mtime = entry.mtime;
                    (*inode).parent_ino = (*current).ino;
                    return true;
                }
                if !leaf_is_dir && (*inode).ftype == FTYPE_REGULAR {
                    (*inode).mode = leaf_mode;
                    (*inode).readonly = 1;
                    (*inode).nlink = if entry.nlink != 0 { entry.nlink } else { 1 };
                    (*inode).mtime = entry.mtime;
                    (*inode).size = entry.data_len as u64;
                    (*inode).ro_data = entry.data;
                    (*inode).rw_data = core::ptr::null_mut();
                    (*inode).parent_ino = (*current).ino;
                    return true;
                }
                return false;
            }

            let inode = alloc_inode();
            if inode.is_null() {
                return false;
            }

            (*inode).readonly = 1;
            (*inode).mode = leaf_mode;
            (*inode).mtime = entry.mtime;
            (*inode).parent_ino = (*current).ino;
            (*inode).nlink = if entry.nlink != 0 {
                entry.nlink
            } else if leaf_is_dir {
                2
            } else {
                1
            };

            if leaf_is_dir {
                (*inode).ftype = FTYPE_DIRECTORY;
                (*inode).size = 0;
            } else if leaf_is_symlink {
                (*inode).ftype = FTYPE_SYMLINK;
                (*inode).size = entry.data_len as u64;
                (*inode).ro_data = entry.data;
            } else {
                (*inode).ftype = FTYPE_REGULAR;
                (*inode).size = entry.data_len as u64;
                (*inode).ro_data = entry.data;
            }

            if dir_add_entry(current, leaf_name, leaf_len, (*inode).ino) != 0 {
                (*inode).active = 0;
                return false;
            }
            return true;
        }

        true
    }
}

pub(crate) unsafe fn init_fb_info() {
    unsafe {
        let bootinfo = BOOTINFO_VADDR as *const u8;
        let magic = (bootinfo as *const u64).read();
        if magic != BOOTINFO_MAGIC {
            return;
        }
        let p32 = bootinfo.add(32) as *const u32;
        crate::FB_WIDTH = p32.read();
        crate::FB_HEIGHT = p32.add(1).read();
        crate::FB_PITCH = p32.add(2).read();
        crate::FB_BPP = *bootinfo.add(44);
        crate::FB_RED_POS = *bootinfo.add(45);
        crate::FB_RED_SIZE = *bootinfo.add(46);
        crate::FB_GREEN_POS = *bootinfo.add(47);
        crate::FB_GREEN_SIZE = *bootinfo.add(48);
        crate::FB_BLUE_POS = *bootinfo.add(49);
        crate::FB_BLUE_SIZE = *bootinfo.add(50);
    }
}

pub(crate) unsafe fn init_ramfs() {
    unsafe {
        for i in 0..max_inodes() {
            INODES!()[i].active = 0;
        }
        for i in 0..max_writable() {
            WRITABLE_USED!()[i] = 0;
        }

        // Create root directory (ino 1)
        let root = alloc_inode();
        (*root).ftype = FTYPE_DIRECTORY;
        (*root).mode = S_IFDIR_L | 0o755;
        (*root).nlink = 2;

        // Create /dev directory
        let dev_dir = alloc_inode();
        (*dev_dir).ftype = FTYPE_DIRECTORY;
        (*dev_dir).mode = S_IFDIR_L | 0o755;
        (*dev_dir).nlink = 2;
        (*dev_dir).parent_ino = (*root).ino;
        dir_add_entry(root, b"dev".as_ptr(), 3, (*dev_dir).ino);

        // Create /dev/console
        let console = alloc_inode();
        (*console).ftype = FTYPE_CHAR_DEVICE;
        (*console).mode = S_IFCHR_L | 0o666;
        (*console).dev_type = DEV_CONSOLE;
        (*console).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"console".as_ptr(), 7, (*console).ino);

        // Create /dev/null
        let null_dev = alloc_inode();
        (*null_dev).ftype = FTYPE_CHAR_DEVICE;
        (*null_dev).mode = S_IFCHR_L | 0o666;
        (*null_dev).dev_type = DEV_NULL;
        (*null_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"null".as_ptr(), 4, (*null_dev).ino);

        // Create /dev/zero
        let zero_dev = alloc_inode();
        (*zero_dev).ftype = FTYPE_CHAR_DEVICE;
        (*zero_dev).mode = S_IFCHR_L | 0o666;
        (*zero_dev).dev_type = DEV_ZERO;
        (*zero_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"zero".as_ptr(), 4, (*zero_dev).ino);

        // Create /dev/fb0
        let fb0_dev = alloc_inode();
        (*fb0_dev).ftype = FTYPE_CHAR_DEVICE;
        (*fb0_dev).mode = S_IFCHR_L | 0o666;
        (*fb0_dev).dev_type = DEV_FB0;
        (*fb0_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"fb0".as_ptr(), 3, (*fb0_dev).ino);

        // Create /dev/pts directory
        let pts_dir = alloc_inode();
        (*pts_dir).ftype = FTYPE_DIRECTORY;
        (*pts_dir).mode = S_IFDIR_L | 0o755;
        (*pts_dir).nlink = 2;
        (*pts_dir).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"pts".as_ptr(), 3, (*pts_dir).ino);

        // Create /dev/pts/0 — PTY slave device
        let pts0 = alloc_inode();
        (*pts0).ftype = FTYPE_CHAR_DEVICE;
        (*pts0).mode = S_IFCHR_L | 0o666;
        (*pts0).dev_type = DEV_PTY_SLAVE;
        (*pts0).size = 0; // pty_id = 0
        (*pts0).parent_ino = (*pts_dir).ino;
        dir_add_entry(pts_dir, b"0".as_ptr(), 1, (*pts0).ino);

        // Create /dev/tty (resolves to PTY slave for single-terminal system)
        let tty_dev = alloc_inode();
        (*tty_dev).ftype = FTYPE_CHAR_DEVICE;
        (*tty_dev).mode = S_IFCHR_L | 0o666;
        (*tty_dev).dev_type = DEV_PTY_SLAVE;
        (*tty_dev).size = 0; // pty_id = 0
        (*tty_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"tty".as_ptr(), 3, (*tty_dev).ino);

        // Create /dev/urandom
        let urandom_dev = alloc_inode();
        (*urandom_dev).ftype = FTYPE_CHAR_DEVICE;
        (*urandom_dev).mode = S_IFCHR_L | 0o666;
        (*urandom_dev).dev_type = DEV_URANDOM;
        (*urandom_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"urandom".as_ptr(), 7, (*urandom_dev).ino);

        // Create /dev/random (alias for urandom)
        let random_dev = alloc_inode();
        (*random_dev).ftype = FTYPE_CHAR_DEVICE;
        (*random_dev).mode = S_IFCHR_L | 0o666;
        (*random_dev).dev_type = DEV_URANDOM;
        (*random_dev).parent_ino = (*dev_dir).ino;
        dir_add_entry(dev_dir, b"random".as_ptr(), 6, (*random_dev).ino);

        // Create /proc directory (virtual, dynamic content)
        let proc_dir = alloc_inode();
        (*proc_dir).ftype = FTYPE_PROC_FILE;
        (*proc_dir).dev_type = PROC_FILE_ROOT;
        (*proc_dir).mode = S_IFDIR_L | 0o555;
        (*proc_dir).readonly = 1;
        (*proc_dir).nlink = 2;
        (*proc_dir).parent_ino = (*root).ino;
        dir_add_entry(root, b"proc".as_ptr(), 4, (*proc_dir).ino);
        crate::PROC_ROOT_INO = (*proc_dir).ino;

        // Create /mnt directory
        let mnt_dir = alloc_inode();
        (*mnt_dir).ftype = FTYPE_DIRECTORY;
        (*mnt_dir).mode = S_IFDIR_L | 0o755;
        (*mnt_dir).nlink = 2;
        (*mnt_dir).parent_ino = (*root).ino;
        dir_add_entry(root, b"mnt".as_ptr(), 3, (*mnt_dir).ino);

        // Create /mnt/data as mount point directory
        let mnt_data = alloc_inode();
        (*mnt_data).ftype = FTYPE_MOUNT_POINT;
        (*mnt_data).mode = S_IFDIR_L | 0o555;
        (*mnt_data).readonly = 1;
        (*mnt_data).nlink = 2;
        (*mnt_data).parent_ino = (*mnt_dir).ino;
        dir_add_entry(mnt_dir, b"data".as_ptr(), 4, (*mnt_data).ino);
        crate::MOUNT_DATA_INO = (*mnt_data).ino;

        // Create /initrd directory
        let initrd_dir = alloc_inode();
        (*initrd_dir).ftype = FTYPE_DIRECTORY;
        (*initrd_dir).mode = S_IFDIR_L | 0o555;
        (*initrd_dir).readonly = 1;
        (*initrd_dir).nlink = 2;
        (*initrd_dir).parent_ino = (*root).ino;
        dir_add_entry(root, b"initrd".as_ptr(), 6, (*initrd_dir).ino);

        // Mount initrd CPIO
        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = read_boot_info_initrd_size();

        { let mut lb = LineBuf::new(); lb.str(b"[VFS] Initrd size: "); lb.hex(initrd_size as u64); lb.str(b" bytes\n"); lb.flush(); }

        let mut offset: usize = 0;
        let mut entry = CpioEntryExt::zeroed();
        let mut file_count: u32 = 0;

        while cpio::cpio_next_ext(initrd, initrd_size, &raw mut offset, &raw mut entry) != 0 {
            // Skip "."
            if entry.name_len == 1 && *entry.name == b'.' {
                continue;
            }
            if mount_initrd_entry(initrd_dir, &entry) {
                file_count += 1;
            }
        }

        { let mut lb = LineBuf::new(); lb.str(b"[VFS] Mounted "); lb.hex(file_count as u64); lb.str(b" initrd files\n"); lb.flush(); }
    }
}
