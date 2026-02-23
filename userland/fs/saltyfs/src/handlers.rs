// SPDX-License-Identifier: GPL-2.0-only
//! IPC request handlers for file operations.

use salty::consts::*;
use salty::serial::LineBuf;
use salty::types::*;

use crate::alloc::{alloc_block, free_block, bitmap_flush};
use crate::block::{read_block, write_block, read_superblock};
use crate::btree::{btree_search, btree_find_item, btree_leaf_find_all, btree_find_all_for_ino, btree_cow_insert, btree_cow_delete, btree_cow_update};
use crate::consts::*;
use crate::types::*;
use crate::{puts, SB, BLOCK_SIZE, MOUNTED, NEXT_INO};

/// Look up a directory entry by name within a directory inode.
pub(crate) fn lookup_in_dir(dir_ino: u64, name: *const u8, name_len: u8) -> Option<u64> {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };

    // Search for DIR_ITEM entries under dir_ino
    let search_key = BTreeKey {
        object_id: dir_ino,
        item_type: SALTY_DIR_ITEM,
        offset: 0,
    };

    let leaf = btree_search(root_tree, &search_key);
    if leaf.is_null() {
        return None;
    }

    unsafe {
        let hdr = &*(leaf as *const BTreeNodeHeader);
        let items_start = leaf.add(core::mem::size_of::<BTreeNodeHeader>());
        let item_size = core::mem::size_of::<BTreeItem>();

        for i in 0..hdr.num_items as usize {
            let item = core::ptr::read_unaligned(items_start.add(i * item_size) as *const BTreeItem);
            if item.key.object_id != dir_ino || item.key.item_type != SALTY_DIR_ITEM {
                continue;
            }

            let data_ptr = leaf.add(item.offset as usize);
            let (child_ino, entry_name_len, _dir_type) = parse_dir_item_header(data_ptr);

            if entry_name_len as u8 == name_len {
                let entry_name = data_ptr.add(DIR_ITEM_HEADER_SIZE);
                let mut match_found = true;
                for j in 0..name_len as usize {
                    if *entry_name.add(j) != *name.add(j) {
                        match_found = false;
                        break;
                    }
                }
                if match_found {
                    return Some(child_ino);
                }
            }
        }
    }

    None
}

/// Get inode info for a given inode number.
pub(crate) fn get_inode(ino: u64) -> Option<SaltyInode> {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let key = BTreeKey {
        object_id: ino,
        item_type: SALTY_INODE_ITEM,
        offset: 0,
    };

    match btree_find_item(root_tree, &key) {
        Some((data, size)) => {
            if size < core::mem::size_of::<SaltyInode>() as u32 {
                return None;
            }
            Some(unsafe { *(data as *const SaltyInode) })
        }
        None => None,
    }
}

/// Read file data into memory at `dest_base`.
/// Returns bytes actually read. Uses cross-leaf B-tree iteration to support
/// multi-block files with extents spanning multiple leaves.
fn read_file_data(ino: u64, file_offset: u64, count: u64, dest_base: u64) -> u64 {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let bs = unsafe { *(&raw const BLOCK_SIZE) };

    let inode = match get_inode(ino) {
        Some(i) => i,
        None => return 0,
    };

    if file_offset >= inode.size {
        return 0;
    }

    let actual_count = if file_offset + count > inode.size {
        inode.size - file_offset
    } else {
        count
    };

    let read_end = file_offset + actual_count;
    let mut bytes_read = 0u64;

    btree_find_all_for_ino(root_tree, ino, SALTY_EXTENT_DATA, |key, data_ptr, item_size| {
        if bytes_read >= actual_count {
            return false;
        }

        let extent = unsafe { &*(data_ptr as *const ExtentData) };
        let extent_file_offset = key.offset;

        if extent.extent_type == EXTENT_INLINE {
            let inline_data = unsafe { data_ptr.add(core::mem::size_of::<ExtentData>()) };
            let inline_len = extent.ram_bytes;
            let extent_end = extent_file_offset + inline_len;

            if file_offset < extent_end && read_end > extent_file_offset {
                let start_in_extent = if file_offset > extent_file_offset {
                    file_offset - extent_file_offset
                } else {
                    0
                };
                let end_in_extent = if read_end < extent_end {
                    read_end - extent_file_offset
                } else {
                    inline_len
                };
                let copy_len = end_in_extent - start_in_extent;

                unsafe {
                    let dst = (dest_base + bytes_read) as *mut u8;
                    let src = inline_data.add(start_in_extent as usize);
                    for j in 0..copy_len as usize {
                        *dst.add(j) = *src.add(j);
                    }
                }
                bytes_read += copy_len;
            }
        } else if extent.extent_type == EXTENT_REGULAR {
            let disk_byte = extent.disk_bytenr;
            let extent_offset = extent.offset;
            let num_bytes = extent.num_bytes;

            let abs_start = extent_file_offset + extent_offset;
            let abs_end = abs_start + num_bytes;

            if file_offset < abs_end && read_end > abs_start {
                let start_in_extent = if file_offset > abs_start {
                    file_offset - abs_start
                } else {
                    0
                };
                let end_in_extent = if read_end < abs_end {
                    read_end - abs_start
                } else {
                    num_bytes
                };

                let disk_start = disk_byte + start_in_extent;
                let read_len = end_in_extent - start_in_extent;

                let mut pos = 0u64;
                while pos < read_len {
                    let abs_pos = disk_start + pos;
                    let block_nr = abs_pos / bs;
                    let off_in_block = abs_pos % bs;
                    let can_read = (bs - off_in_block).min(read_len - pos);

                    let block_data = read_block(block_nr);
                    if block_data.is_null() {
                        return false;
                    }

                    unsafe {
                        let dst = (dest_base + bytes_read + pos) as *mut u8;
                        for j in 0..can_read as usize {
                            *dst.add(j) = *block_data.add(off_in_block as usize + j);
                        }
                    }

                    pos += can_read;
                }
                bytes_read += read_len;
            }
        }

        bytes_read < actual_count
    });

    bytes_read
}

/// Read directory entries from a directory inode, using cross-leaf iteration.
/// Returns up to 4 entries per call via MR registers.
/// `cursor` is the entry index among matching DIR_ITEM keys.
fn readdir_entries(
    dir_ino: u64,
    cursor: u64,
    reply: &mut SaltyMsg,
) {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };

    let mut entry_idx = 0u64;
    let mut out_idx = 0usize;
    let mut has_more = false;

    // MR0 = next_cursor, then repeated groups of 6:
    // (ino, type, name_0, name_1, name_2, name_3) — 32-byte names, 3 entries max
    btree_find_all_for_ino(root_tree, dir_ino, SALTY_DIR_ITEM, |_key, data_ptr, _size| {
        if entry_idx < cursor {
            entry_idx += 1;
            return true;
        }

        if out_idx >= 3 {
            has_more = true;
            return false;
        }

        unsafe {
            let (child_ino, entry_name_len, entry_dir_type) = parse_dir_item_header(data_ptr);
            let name_ptr = data_ptr.add(DIR_ITEM_HEADER_SIZE);

            let base = 1 + out_idx * 6;
            reply.regs[base] = child_ino;
            reply.regs[base + 1] = entry_dir_type as u64;

            let nlen = (entry_name_len as usize).min(32);
            let mut name_regs = [0u64; 4];
            for j in 0..nlen {
                let reg_idx = j / 8;
                let bit_pos = (j % 8) * 8;
                name_regs[reg_idx] |= (*name_ptr.add(j) as u64) << bit_pos;
            }
            reply.regs[base + 2] = name_regs[0];
            reply.regs[base + 3] = name_regs[1];
            reply.regs[base + 4] = name_regs[2];
            reply.regs[base + 5] = name_regs[3];
        }

        out_idx += 1;
        entry_idx += 1;
        true
    });

    if out_idx == 0 {
        reply.regs[0] = 0;
        reply.label = 0;
        reply.length = 1;
        return;
    }

    reply.regs[0] = if has_more { cursor + out_idx as u64 } else { 0 };
    reply.label = 0;
    reply.length = 1 + (out_idx as u64) * 6;
}

/// Serialize a SaltyInode to bytes.
fn inode_to_bytes(inode: &SaltyInode) -> [u8; 128] {
    let mut buf = [0u8; 128];
    unsafe {
        core::ptr::write_unaligned(buf.as_mut_ptr() as *mut SaltyInode, *inode);
    }
    buf
}

/// Build inode bytes for a new file or directory.
fn build_inode_bytes(size: u64, blocks: u64, nlink: u32, mode: u32) -> [u8; 128] {
    let ngen =unsafe { (*(&raw const SB)).generation + 1 };
    let inode = SaltyInode {
        generation: ngen,
        size,
        blocks,
        block_group: 0,
        nlink,
        uid: 0,
        gid: 0,
        mode,
        atime: 0,
        mtime: 0,
        ctime: 0,
        crtime: 0,
        flags: 0,
        sequence: 0,
        reserved: [0; 32],
    };
    inode_to_bytes(&inode)
}

/// Build a directory item: header (12 bytes) + name.
fn build_dir_item(child_ino: u64, name: &[u8], dir_type: u8, out: &mut [u8; 256]) -> usize {
    unsafe {
        core::ptr::write_unaligned(out.as_mut_ptr() as *mut u64, child_ino);
        core::ptr::write_unaligned(out.as_mut_ptr().add(8) as *mut u16, name.len() as u16);
        *out.as_mut_ptr().add(10) = dir_type;
        *out.as_mut_ptr().add(11) = 0; // pad
    }
    for i in 0..name.len() {
        out[DIR_ITEM_HEADER_SIZE + i] = name[i];
    }
    DIR_ITEM_HEADER_SIZE + name.len()
}

/// Build an inline extent: ExtentData header (48 bytes) + inline data.
fn build_extent_inline(out: &mut [u8; 304], size: u64, data: &[u8]) {
    let ngen =unsafe { (*(&raw const SB)).generation + 1 };
    let ext = ExtentData {
        generation: ngen,
        ram_bytes: size,
        compression: 0,
        encryption: 0,
        other_encoding: 0,
        extent_type: EXTENT_INLINE,
        reserved: [0; 3],
        disk_bytenr: 0,
        disk_num_bytes: 0,
        offset: 0,
        num_bytes: 0,
    };
    unsafe {
        core::ptr::write_unaligned(out.as_mut_ptr() as *mut ExtentData, ext);
    }
    let hdr_size = core::mem::size_of::<ExtentData>();
    for i in 0..data.len() {
        out[hdr_size + i] = data[i];
    }
}

/// Build a regular extent header (48 bytes, no inline data).
fn build_extent_regular(out: &mut [u8; 304], size: u64, disk_bytenr: u64, disk_num_bytes: u64, offset: u64, num_bytes: u64) {
    let ngen =unsafe { (*(&raw const SB)).generation + 1 };
    let ext = ExtentData {
        generation: ngen,
        ram_bytes: size,
        compression: 0,
        encryption: 0,
        other_encoding: 0,
        extent_type: EXTENT_REGULAR,
        reserved: [0; 3],
        disk_bytenr,
        disk_num_bytes,
        offset,
        num_bytes,
    };
    unsafe {
        core::ptr::write_unaligned(out.as_mut_ptr() as *mut ExtentData, ext);
    }
}

/// Delete all extent data items for an inode, freeing data blocks for regular extents.
fn delete_all_extents(ino: u64) {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let bs = unsafe { *(&raw const BLOCK_SIZE) };

    // Collect all extent offsets first (can't delete while iterating)
    let mut offsets = [0u64; 128];
    let mut types = [0u8; 128];
    let mut disk_addrs = [0u64; 128];
    let mut disk_sizes = [0u64; 128];
    let mut count = 0usize;

    btree_find_all_for_ino(root_tree, ino, SALTY_EXTENT_DATA, |key, data_ptr, _size| {
        if count < 128 {
            let ext = unsafe { &*(data_ptr as *const ExtentData) };
            offsets[count] = key.offset;
            types[count] = ext.extent_type;
            disk_addrs[count] = ext.disk_bytenr;
            disk_sizes[count] = ext.disk_num_bytes;
            count += 1;
        }
        true
    });

    for i in 0..count {
        // Free data blocks for regular extents
        if types[i] == EXTENT_REGULAR && disk_addrs[i] != 0 {
            let block_start = disk_addrs[i] / bs;
            let block_count = (disk_sizes[i] + bs - 1) / bs;
            for b in 0..block_count {
                free_block(block_start + b);
            }
        }
        let ext_key = BTreeKey {
            object_id: ino,
            item_type: SALTY_EXTENT_DATA,
            offset: offsets[i],
        };
        btree_cow_delete(&ext_key);
    }
}

/// Update the mtime of an inode (COW).
fn update_inode_mtime(ino: u64) -> bool {
    if let Some(mut inode) = get_inode(ino) {
        // We don't have a reliable clock, so just increment generation
        inode.mtime = unsafe { (*(&raw const SB)).generation + 1 };
        let inode_key = BTreeKey {
            object_id: ino,
            item_type: SALTY_INODE_ITEM,
            offset: 0,
        };
        return btree_cow_update(&inode_key, &inode_to_bytes(&inode));
    }
    true
}

pub(crate) fn handle_mount() -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();

    if unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_ALREADY_EXISTS;
        reply.length = 1;
        reply.regs[0] = unsafe { (*(&raw const SB)).root_inode };
        return reply;
    }

    if !read_superblock() {
        reply.label = SALTY_NOT_FOUND;
        return reply;
    }

    unsafe { *(&raw mut MOUNTED) = true; }
    reply.label = 0;
    reply.length = 1;
    reply.regs[0] = unsafe { (*(&raw const SB)).root_inode };
    reply
}

pub(crate) fn handle_lookup(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();

    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let parent_ino = msg.regs[0];
    // Name packed in MR1..MR19 (up to 144 bytes)
    let name_len = msg.regs[1] as u8;
    if name_len == 0 || name_len > 144 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 144];
    let name_data = &msg.regs[2] as *const u64 as *const u8;
    unsafe {
        for i in 0..name_len as usize {
            name_buf[i] = *name_data.add(i);
        }
    }

    match lookup_in_dir(parent_ino, name_buf.as_ptr(), name_len) {
        Some(child_ino) => {
            reply.label = 0;
            reply.length = 1;
            reply.regs[0] = child_ino;
        }
        None => {
            reply.label = SALTY_NOT_FOUND;
        }
    }
    reply
}

pub(crate) fn handle_read(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();

    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];
    let offset = msg.regs[1];
    let count = msg.regs[2];
    let shm_offset = msg.regs[3];

    // Use VFS SHM if mapped, otherwise blkdrv SHM
    let dest_base = if unsafe { *(&raw const crate::VFS_SHM_MAPPED) } {
        VFS_SHM_VADDR + shm_offset
    } else {
        SHM_VADDR + shm_offset
    };
    let bytes_read = read_file_data(ino, offset, count, dest_base);
    reply.label = 0;
    reply.length = 1;
    reply.regs[0] = bytes_read;
    reply
}

pub(crate) fn handle_readdir(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();

    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let dir_ino = msg.regs[0];
    let cursor = msg.regs[1];

    readdir_entries(dir_ino, cursor, &mut reply);
    reply
}

pub(crate) fn handle_stat(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();

    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];

    match get_inode(ino) {
        Some(inode) => {
            reply.label = 0;
            reply.length = 6;
            reply.regs[0] = ino;
            reply.regs[1] = inode.size;
            reply.regs[2] = inode.mode as u64;
            reply.regs[3] = inode.nlink as u64;
            reply.regs[4] = inode.mtime;
            reply.regs[5] = inode.blocks;
        }
        None => {
            reply.label = SALTY_NOT_FOUND;
        }
    }
    reply
}

pub(crate) fn handle_getinfo() -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();

    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    unsafe {
        let sb = &*(&raw const SB);
        reply.label = 0;
        reply.length = 4;
        reply.regs[0] = sb.total_blocks;
        reply.regs[1] = sb.used_blocks;
        reply.regs[2] = sb.block_size;
        // Pack first 8 bytes of label
        let mut label_packed: u64 = 0;
        for i in 0..8 {
            if sb.label[i] == 0 {
                break;
            }
            label_packed |= (sb.label[i] as u64) << (i * 8);
        }
        reply.regs[3] = label_packed;
    }
    reply
}

/// Handle SALTYFS_READ_INLINE: read up to 152 bytes and return data in IPC registers.
/// Uses SHM offset 0 as scratch space, then copies into the reply.
pub(crate) fn handle_read_inline(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();

    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];
    let offset = msg.regs[1];
    let mut count = msg.regs[2];
    if count > 152 {
        count = 152;
    }

    // Use blkdrv SHM offset 0 as scratch
    let bytes_read = read_file_data(ino, offset, count, SHM_VADDR);

    reply.label = 0;
    reply.length = 1 + (bytes_read + 7) / 8;
    reply.regs[0] = bytes_read;

    if bytes_read > 0 {
        unsafe {
            let src = SHM_VADDR as *const u8;
            let dst = &raw mut reply.regs[1] as *mut u8;
            for i in 0..bytes_read as usize {
                *dst.add(i) = *src.add(i);
            }
        }
    }

    reply
}

/// Handle SALTYFS_CREATE: create a new regular file.
pub(crate) fn handle_create(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let parent_ino = msg.regs[0];
    let mode = msg.regs[1] as u32;
    let name_len = msg.regs[2] as u8;
    if name_len == 0 || name_len > 136 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 136];
    let name_data = &msg.regs[3] as *const u64 as *const u8;
    unsafe {
        for i in 0..name_len as usize {
            name_buf[i] = *name_data.add(i);
        }
    }

    // Check if already exists
    if lookup_in_dir(parent_ino, name_buf.as_ptr(), name_len).is_some() {
        reply.label = SALTY_ALREADY_EXISTS;
        return reply;
    }

    let new_ino = unsafe {
        let n = *(&raw const NEXT_INO);
        *(&raw mut NEXT_INO) = n + 1;
        n
    };

    // Insert INODE_ITEM
    let inode_data = build_inode_bytes(0, 0, 1, mode | 0o100000); // S_IFREG
    let inode_key = BTreeKey {
        object_id: new_ino,
        item_type: SALTY_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_insert(&inode_key, &inode_data) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    // Insert DIR_ITEM
    let mut dir_buf = [0u8; 256];
    let dir_len = build_dir_item(new_ino, &name_buf[..name_len as usize], 1, &mut dir_buf);
    let dir_key = BTreeKey {
        object_id: parent_ino,
        item_type: SALTY_DIR_ITEM,
        offset: new_ino,
    };
    if !btree_cow_insert(&dir_key, &dir_buf[..dir_len]) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    update_inode_mtime(parent_ino);

    {
        let mut lb = LineBuf::new();
        lb.str(b"[saltyfs] CREATE ino=");
        lb.dec(new_ino);
        lb.str(b" parent=");
        lb.dec(parent_ino);
        lb.putc(b'\n');
        lb.flush();
    }

    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = new_ino;
    reply
}

/// Handle SALTYFS_WRITE_INLINE: write up to 136 bytes of data at any offset.
/// Supports multi-block files: each 4KB block gets its own EXTENT_DATA item
/// keyed at (ino, SALTY_EXTENT_DATA, block_aligned_offset).
pub(crate) fn handle_write_inline(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];
    let offset = msg.regs[1];
    let mut count = msg.regs[2];
    if count > 136 {
        count = 136;
    }

    let mut data_buf = [0u8; 136];
    let src = &msg.regs[3] as *const u64 as *const u8;
    unsafe {
        for i in 0..count as usize {
            data_buf[i] = *src.add(i);
        }
    }

    let inode = match get_inode(ino) {
        Some(i) => i,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };

    let new_size = if offset + count > inode.size {
        offset + count
    } else {
        inode.size
    };

    let bs = unsafe { *(&raw const BLOCK_SIZE) };

    // Check if file is still small enough for inline extent
    if new_size <= 208 && offset < 208 {
        let extent_key = BTreeKey {
            object_id: ino,
            item_type: SALTY_EXTENT_DATA,
            offset: 0,
        };

        let mut full_data = [0u8; 208];
        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        let mut had_extent = false;

        if let Some((ext_ptr, ext_size)) = btree_find_item(root_tree, &extent_key) {
            had_extent = true;
            let ext = unsafe { &*(ext_ptr as *const ExtentData) };
            if ext.extent_type == EXTENT_INLINE {
                let ext_hdr_size = core::mem::size_of::<ExtentData>();
                let inline_len = (ext_size as usize).saturating_sub(ext_hdr_size);
                unsafe {
                    let inline_ptr = ext_ptr.add(ext_hdr_size);
                    for i in 0..inline_len.min(208) {
                        full_data[i] = *inline_ptr.add(i);
                    }
                }
            } else {
                // Existing regular extent at offset 0 — use regular path below
                return write_regular_extents(
                    ino, offset, count, &data_buf, &inode, new_size, bs, &mut reply,
                );
            }
        }

        for i in 0..count as usize {
            if offset as usize + i < 208 {
                full_data[offset as usize + i] = data_buf[i];
            }
        }

        let mut extent_buf = [0u8; 304];
        build_extent_inline(
            &mut extent_buf,
            new_size,
            &full_data[..new_size as usize],
        );
        let ext_total = core::mem::size_of::<ExtentData>() + new_size as usize;

        let ok = if had_extent {
            btree_cow_update(&extent_key, &extent_buf[..ext_total])
        } else {
            btree_cow_insert(&extent_key, &extent_buf[..ext_total])
        };
        if !ok {
            reply.label = SALTY_OUT_OF_MEMORY;
            return reply;
        }
    } else {
        // Regular extent path: per-block extent items
        return write_regular_extents(
            ino, offset, count, &data_buf, &inode, new_size, bs, &mut reply,
        );
    }

    // Update inode size
    let mut updated_inode = inode;
    updated_inode.size = new_size;
    updated_inode.mtime = unsafe { (*(&raw const SB)).generation + 1 };
    let inode_key = BTreeKey {
        object_id: ino,
        item_type: SALTY_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated_inode)) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = count;
    reply
}

/// Write data using per-block regular extents. Handles inline→regular promotion
/// and writing across multiple 4KB block boundaries.
fn write_regular_extents(
    ino: u64,
    offset: u64,
    count: u64,
    data_buf: &[u8; 136],
    inode: &SaltyInode,
    new_size: u64,
    bs: u64,
    reply: &mut SaltyMsg,
) -> SaltyMsg {
    let ext_hdr_size = core::mem::size_of::<ExtentData>();

    // Check for inline→regular promotion: if there's an inline extent at offset 0,
    // convert it to a regular extent first.
    let inline_key = BTreeKey {
        object_id: ino,
        item_type: SALTY_EXTENT_DATA,
        offset: 0,
    };
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    if let Some((ext_ptr, ext_size)) = btree_find_item(root_tree, &inline_key) {
        let ext = unsafe { &*(ext_ptr as *const ExtentData) };
        if ext.extent_type == EXTENT_INLINE {
            let inline_len = (ext_size as usize).saturating_sub(ext_hdr_size);
            let promo_block = match alloc_block() {
                Some(b) => b,
                None => {
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return *reply;
                }
            };
            let mut promo_buf = [0u8; 4096];
            unsafe {
                let inline_ptr = ext_ptr.add(ext_hdr_size);
                for i in 0..inline_len.min(4096) {
                    promo_buf[i] = *inline_ptr.add(i);
                }
            }
            if !write_block(promo_block, promo_buf.as_ptr()) {
                free_block(promo_block);
                reply.label = SALTY_OUT_OF_MEMORY;
                return *reply;
            }
            // Delete inline extent, insert regular at offset 0
            if !btree_cow_delete(&inline_key) {
                free_block(promo_block);
                reply.label = SALTY_OUT_OF_MEMORY;
                return *reply;
            }
            let mut ext_buf = [0u8; 304];
            build_extent_regular(&mut ext_buf, bs, promo_block * bs, bs, 0, bs);
            if !btree_cow_insert(&inline_key, &ext_buf[..ext_hdr_size]) {
                free_block(promo_block);
                reply.label = SALTY_OUT_OF_MEMORY;
                return *reply;
            }
            bitmap_flush();
        }
    }

    // Write per-block extents for each 4KB block touched by [offset, offset+count)
    let write_end = offset + count;
    let first_block_off = (offset / bs) * bs;

    let mut block_off = first_block_off;
    while block_off < write_end {
        let extent_key = BTreeKey {
            object_id: ino,
            item_type: SALTY_EXTENT_DATA,
            offset: block_off,
        };

        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        let existing = btree_find_item(root_tree, &extent_key);

        let mut block_buf = [0u8; 4096];
        let mut old_data_block: u64 = 0;
        let mut had_extent = false;

        if let Some((ext_ptr, _)) = existing {
            had_extent = true;
            let ext = unsafe { &*(ext_ptr as *const ExtentData) };
            if ext.extent_type == EXTENT_REGULAR && ext.disk_bytenr != 0 {
                old_data_block = ext.disk_bytenr / bs;
                let existing_data = read_block(old_data_block);
                if !existing_data.is_null() {
                    unsafe {
                        for i in 0..bs as usize {
                            block_buf[i] = *existing_data.add(i);
                        }
                    }
                }
            }
        }

        // Overlay new data into this block
        let write_start = if offset > block_off { (offset - block_off) as usize } else { 0 };
        let write_end_in_block = if write_end < block_off + bs {
            (write_end - block_off) as usize
        } else {
            bs as usize
        };
        let data_start = if block_off > offset { (block_off - offset) as usize } else { 0 };

        for i in write_start..write_end_in_block {
            let buf_idx = data_start + i - write_start;
            if buf_idx < count as usize {
                block_buf[i] = data_buf[buf_idx];
            }
        }

        let data_block = match alloc_block() {
            Some(b) => b,
            None => {
                reply.label = SALTY_OUT_OF_MEMORY;
                return *reply;
            }
        };
        if !write_block(data_block, block_buf.as_ptr()) {
            free_block(data_block);
            reply.label = SALTY_OUT_OF_MEMORY;
            return *reply;
        }

        let mut ext_buf = [0u8; 304];
        build_extent_regular(&mut ext_buf, bs, data_block * bs, bs, 0, bs);

        let ok = if had_extent {
            btree_cow_update(&extent_key, &ext_buf[..ext_hdr_size])
        } else {
            btree_cow_insert(&extent_key, &ext_buf[..ext_hdr_size])
        };
        if !ok {
            free_block(data_block);
            reply.label = SALTY_OUT_OF_MEMORY;
            return *reply;
        }

        if old_data_block != 0 {
            free_block(old_data_block);
        }

        block_off += bs;
    }

    bitmap_flush();

    // Update inode size and blocks count
    let mut updated_inode = *inode;
    updated_inode.size = new_size;
    updated_inode.blocks = (new_size + bs - 1) / bs;
    updated_inode.mtime = unsafe { (*(&raw const SB)).generation + 1 };
    let inode_key = BTreeKey {
        object_id: ino,
        item_type: SALTY_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated_inode)) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return *reply;
    }

    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = count;
    *reply
}

/// Handle SALTYFS_MKDIR: create a new directory.
pub(crate) fn handle_mkdir_fs(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let parent_ino = msg.regs[0];
    let mode = msg.regs[1] as u32;
    let name_len = msg.regs[2] as u8;
    if name_len == 0 || name_len > 136 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 136];
    let name_data = &msg.regs[3] as *const u64 as *const u8;
    unsafe {
        for i in 0..name_len as usize {
            name_buf[i] = *name_data.add(i);
        }
    }

    if lookup_in_dir(parent_ino, name_buf.as_ptr(), name_len).is_some() {
        reply.label = SALTY_ALREADY_EXISTS;
        return reply;
    }

    let new_ino = unsafe {
        let n = *(&raw const NEXT_INO);
        *(&raw mut NEXT_INO) = n + 1;
        n
    };

    // Insert INODE_ITEM for directory (nlink=2, S_IFDIR)
    let inode_data = build_inode_bytes(0, 0, 2, mode | 0o040000);
    let inode_key = BTreeKey {
        object_id: new_ino,
        item_type: SALTY_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_insert(&inode_key, &inode_data) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    // Insert DIR_ITEM in parent
    let mut dir_buf = [0u8; 256];
    let dir_len = build_dir_item(new_ino, &name_buf[..name_len as usize], 4, &mut dir_buf); // type 4 = directory
    let dir_key = BTreeKey {
        object_id: parent_ino,
        item_type: SALTY_DIR_ITEM,
        offset: new_ino,
    };
    if !btree_cow_insert(&dir_key, &dir_buf[..dir_len]) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    update_inode_mtime(parent_ino);

    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = new_ino;
    reply
}

/// Handle SALTYFS_UNLINK: remove a file.
pub(crate) fn handle_unlink_fs(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let parent_ino = msg.regs[0];
    let name_len = msg.regs[1] as u8;
    if name_len == 0 || name_len > 144 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 144];
    let name_data = &msg.regs[2] as *const u64 as *const u8;
    unsafe {
        for i in 0..name_len as usize {
            name_buf[i] = *name_data.add(i);
        }
    }

    let child_ino = match lookup_in_dir(parent_ino, name_buf.as_ptr(), name_len) {
        Some(ino) => ino,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };

    let inode = match get_inode(child_ino) {
        Some(i) => i,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };

    // Don't unlink directories (use rmdir)
    if (inode.mode & 0o170000) == 0o040000 {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    // Delete DIR_ITEM
    let dir_key = BTreeKey {
        object_id: parent_ino,
        item_type: SALTY_DIR_ITEM,
        offset: child_ino,
    };
    if !btree_cow_delete(&dir_key) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    let new_nlink = inode.nlink.saturating_sub(1);
    if new_nlink == 0 {
        // Delete all extent data items (multi-block aware)
        delete_all_extents(child_ino);
        bitmap_flush();

        // Delete INODE_ITEM
        let inode_key = BTreeKey {
            object_id: child_ino,
            item_type: SALTY_INODE_ITEM,
            offset: 0,
        };
        if !btree_cow_delete(&inode_key) {
            reply.label = SALTY_OUT_OF_MEMORY;
            return reply;
        }
    } else {
        // Update nlink
        let mut updated = inode;
        updated.nlink = new_nlink;
        let inode_key = BTreeKey {
            object_id: child_ino,
            item_type: SALTY_INODE_ITEM,
            offset: 0,
        };
        if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
            reply.label = SALTY_OUT_OF_MEMORY;
            return reply;
        }
    }

    update_inode_mtime(parent_ino);

    reply.label = SALTY_OK;
    reply
}

/// Handle SALTYFS_RMDIR: remove an empty directory.
pub(crate) fn handle_rmdir_fs(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let parent_ino = msg.regs[0];
    let name_len = msg.regs[1] as u8;
    if name_len == 0 || name_len > 144 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 144];
    let name_data = &msg.regs[2] as *const u64 as *const u8;
    unsafe {
        for i in 0..name_len as usize {
            name_buf[i] = *name_data.add(i);
        }
    }

    let child_ino = match lookup_in_dir(parent_ino, name_buf.as_ptr(), name_len) {
        Some(ino) => ino,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };

    let inode = match get_inode(child_ino) {
        Some(i) => i,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };

    // Must be a directory
    if (inode.mode & 0o170000) != 0o040000 {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    // Check if directory is empty
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let search_key = BTreeKey {
        object_id: child_ino,
        item_type: SALTY_DIR_ITEM,
        offset: 0,
    };
    let leaf = btree_search(root_tree, &search_key);
    if !leaf.is_null() {
        let mut has_entries = false;
        btree_leaf_find_all(leaf, child_ino, SALTY_DIR_ITEM, |_, _, _| {
            has_entries = true;
        });
        if has_entries {
            reply.label = SALTY_INVALID_OPERATION;
            return reply;
        }
    }

    // Delete DIR_ITEM from parent
    let dir_key = BTreeKey {
        object_id: parent_ino,
        item_type: SALTY_DIR_ITEM,
        offset: child_ino,
    };
    if !btree_cow_delete(&dir_key) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    // Delete INODE_ITEM
    let inode_key = BTreeKey {
        object_id: child_ino,
        item_type: SALTY_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_delete(&inode_key) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    update_inode_mtime(parent_ino);

    reply.label = SALTY_OK;
    reply
}

/// Handle SALTYFS_RENAME: move/rename a file or directory.
pub(crate) fn handle_rename_fs(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let old_parent = msg.regs[0];
    let old_name_len = msg.regs[1] as u8;
    let new_parent = msg.regs[2];
    let new_name_len = msg.regs[3] as u8;
    if old_name_len == 0 || old_name_len > 64 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }
    if new_name_len == 0 || new_name_len > 64 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut old_name = [0u8; 64];
    let old_data = &msg.regs[4] as *const u64 as *const u8;
    unsafe {
        for i in 0..old_name_len as usize {
            old_name[i] = *old_data.add(i);
        }
    }

    let mut new_name = [0u8; 64];
    let new_data = &msg.regs[12] as *const u64 as *const u8;
    unsafe {
        for i in 0..new_name_len as usize {
            new_name[i] = *new_data.add(i);
        }
    }

    // Look up old entry
    let child_ino = match lookup_in_dir(old_parent, old_name.as_ptr(), old_name_len) {
        Some(ino) => ino,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };

    // If new name already exists, unlink it first (Bug #5: full cleanup)
    if let Some(existing_ino) = lookup_in_dir(new_parent, new_name.as_ptr(), new_name_len) {
        // No-op rename: old and new point to the same entry
        if existing_ino == child_ino {
            reply.label = SALTY_OK;
            return reply;
        }
        let existing_dir_key = BTreeKey {
            object_id: new_parent,
            item_type: SALTY_DIR_ITEM,
            offset: existing_ino,
        };
        if !btree_cow_delete(&existing_dir_key) {
            reply.label = SALTY_OUT_OF_MEMORY;
            return reply;
        }

        // Decrement nlink; if 0, clean up inode + extents
        if let Some(existing_inode) = get_inode(existing_ino) {
            let new_nlink = existing_inode.nlink.saturating_sub(1);
            if new_nlink == 0 {
                // Delete all extent data items (multi-block aware)
                delete_all_extents(existing_ino);
                bitmap_flush();
                // Delete INODE_ITEM
                let inode_key = BTreeKey {
                    object_id: existing_ino,
                    item_type: SALTY_INODE_ITEM,
                    offset: 0,
                };
                if !btree_cow_delete(&inode_key) {
                    puts(b"[saltyfs] rename: warning: orphan inode (delete failed)\n");
                }
            } else {
                // nlink > 0: just update inode
                let mut updated = existing_inode;
                updated.nlink = new_nlink;
                let inode_key = BTreeKey {
                    object_id: existing_ino,
                    item_type: SALTY_INODE_ITEM,
                    offset: 0,
                };
                if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
                    puts(b"[saltyfs] rename: warning: nlink update failed\n");
                }
            }
        }
    }

    // Delete old DIR_ITEM
    let old_dir_key = BTreeKey {
        object_id: old_parent,
        item_type: SALTY_DIR_ITEM,
        offset: child_ino,
    };
    if !btree_cow_delete(&old_dir_key) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    // Determine dir_type from inode
    let dir_type = match get_inode(child_ino) {
        Some(inode) => {
            if (inode.mode & 0o170000) == 0o040000 { 4u8 } else { 1u8 }
        }
        None => 1u8,
    };

    // Insert new DIR_ITEM
    let mut dir_buf = [0u8; 256];
    let dir_len = build_dir_item(child_ino, &new_name[..new_name_len as usize], dir_type, &mut dir_buf);
    let new_dir_key = BTreeKey {
        object_id: new_parent,
        item_type: SALTY_DIR_ITEM,
        offset: child_ino,
    };
    if !btree_cow_insert(&new_dir_key, &dir_buf[..dir_len]) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    update_inode_mtime(old_parent);
    if new_parent != old_parent {
        update_inode_mtime(new_parent);
    }

    reply.label = SALTY_OK;
    reply
}

/// Handle SALTYFS_TRUNCATE: change file size.
/// Supports multi-block files: deletes extent items beyond new_size.
pub(crate) fn handle_truncate_fs(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];
    let new_size = msg.regs[1];
    let bs = unsafe { *(&raw const BLOCK_SIZE) };

    let inode = match get_inode(ino) {
        Some(i) => i,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };

    let inode_key = BTreeKey {
        object_id: ino,
        item_type: SALTY_INODE_ITEM,
        offset: 0,
    };

    if new_size >= inode.size {
        // Extend: just update inode size
        let mut updated = inode;
        updated.size = new_size;
        updated.mtime = unsafe { (*(&raw const SB)).generation + 1 };
        if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
            reply.label = SALTY_OUT_OF_MEMORY;
            return reply;
        }
        reply.label = SALTY_OK;
        return reply;
    }

    // Collect all extent items for this inode
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let mut ext_offsets = [0u64; 128];
    let mut ext_types = [0u8; 128];
    let mut ext_disk_bytenr = [0u64; 128];
    let mut ext_disk_num = [0u64; 128];
    let mut ext_count = 0usize;

    btree_find_all_for_ino(root_tree, ino, SALTY_EXTENT_DATA, |key, data_ptr, size| {
        if ext_count < 128 {
            let ext = unsafe { &*(data_ptr as *const ExtentData) };
            ext_offsets[ext_count] = key.offset;
            ext_types[ext_count] = ext.extent_type;
            ext_disk_bytenr[ext_count] = ext.disk_bytenr;
            ext_disk_num[ext_count] = ext.disk_num_bytes;
            ext_count += 1;
        }
        true
    });

    // Process extents: delete those entirely beyond new_size
    for i in 0..ext_count {
        let ext_offset = ext_offsets[i];
        let ext_type = ext_types[i];

        if ext_type == EXTENT_INLINE && ext_offset == 0 {
            if new_size == 0 {
                let ext_key = BTreeKey {
                    object_id: ino,
                    item_type: SALTY_EXTENT_DATA,
                    offset: 0,
                };
                if !btree_cow_delete(&ext_key) {
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return reply;
                }
            } else {
                // Truncate inline data
                let ext_key = BTreeKey {
                    object_id: ino,
                    item_type: SALTY_EXTENT_DATA,
                    offset: 0,
                };
                let root_tree = unsafe { (*(&raw const SB)).root_tree };
                if let Some((ext_ptr, ext_size)) = btree_find_item(root_tree, &ext_key) {
                    let ext_hdr_size = core::mem::size_of::<ExtentData>();
                    let inline_len = (ext_size as usize).saturating_sub(ext_hdr_size);
                    let mut data = [0u8; 208];
                    unsafe {
                        let src = ext_ptr.add(ext_hdr_size);
                        for j in 0..inline_len.min(208) {
                            data[j] = *src.add(j);
                        }
                    }
                    if !btree_cow_delete(&ext_key) {
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return reply;
                    }
                    let mut extent_buf = [0u8; 304];
                    build_extent_inline(
                        &mut extent_buf,
                        new_size,
                        &data[..new_size as usize],
                    );
                    let ext_total = ext_hdr_size + new_size as usize;
                    if !btree_cow_insert(&ext_key, &extent_buf[..ext_total]) {
                        reply.label = SALTY_OUT_OF_MEMORY;
                        return reply;
                    }
                }
            }
        } else if ext_type == EXTENT_REGULAR {
            // Block-aligned extent at ext_offset; covers [ext_offset, ext_offset+bs)
            if ext_offset >= new_size {
                // Entirely beyond new_size — delete and free data block
                if ext_disk_bytenr[i] != 0 {
                    let block_start = ext_disk_bytenr[i] / bs;
                    let block_count = (ext_disk_num[i] + bs - 1) / bs;
                    for b in 0..block_count {
                        free_block(block_start + b);
                    }
                }
                let ext_key = BTreeKey {
                    object_id: ino,
                    item_type: SALTY_EXTENT_DATA,
                    offset: ext_offset,
                };
                btree_cow_delete(&ext_key);
            }
            // Extents partially within new_size keep their block; inode.size is authoritative
        }
    }

    bitmap_flush();

    let mut updated = inode;
    updated.size = new_size;
    updated.blocks = if new_size == 0 { 0 } else { (new_size + bs - 1) / bs };
    updated.mtime = unsafe { (*(&raw const SB)).generation + 1 };
    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    reply.label = SALTY_OK;
    reply
}

/// Handle SALTYFS_SHM_SETUP: map a VFS-shared SHM region for bulk data transport.
/// MR0 = SHM ID to map
pub(crate) fn handle_shm_setup(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    let shm_id = msg.regs[0];

    let ctx = crate::ipc_ctx();
    let mut mm_msg = SaltyMsg::zeroed();
    mm_msg.label = MM_SHM_MAP;
    mm_msg.length = 4;
    mm_msg.regs[0] = shm_id;
    mm_msg.regs[1] = 0;
    mm_msg.regs[2] = VFS_SHM_VADDR;
    mm_msg.regs[3] = 0x3; // RW

    let mut mm_reply = SaltyMsg::zeroed();
    let err = unsafe {
        salty::ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const mm_msg, &raw mut mm_reply)
    };
    if err != 0 || mm_reply.label != 0 {
        puts(b"[saltyfs] VFS SHM map failed\n");
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    unsafe { *(&raw mut crate::VFS_SHM_MAPPED) = true; }
    puts(b"[saltyfs] VFS SHM mapped for bulk transport\n");

    reply.label = SALTY_OK;
    reply
}

/// Handle SALTYFS_WRITE: SHM-based write for bulk data transport.
/// MR0 = ino, MR1 = offset, MR2 = count, MR3 = shm_offset
/// Data is read from VFS SHM at shm_offset.
pub(crate) fn handle_write_shm(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    if !unsafe { *(&raw const crate::VFS_SHM_MAPPED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];
    let offset = msg.regs[1];
    let count = msg.regs[2];
    let shm_offset = msg.regs[3];

    let inode = match get_inode(ino) {
        Some(i) => i,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };

    let new_size = if offset + count > inode.size {
        offset + count
    } else {
        inode.size
    };

    let bs = unsafe { *(&raw const BLOCK_SIZE) };
    let ext_hdr_size = core::mem::size_of::<ExtentData>();

    // Delete any existing inline extent and promote to regular
    let inline_key = BTreeKey {
        object_id: ino,
        item_type: SALTY_EXTENT_DATA,
        offset: 0,
    };
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    if let Some((ext_ptr, ext_size)) = btree_find_item(root_tree, &inline_key) {
        let ext = unsafe { &*(ext_ptr as *const ExtentData) };
        if ext.extent_type == EXTENT_INLINE {
            let inline_len = (ext_size as usize).saturating_sub(ext_hdr_size);
            let promo_block = match alloc_block() {
                Some(b) => b,
                None => {
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return reply;
                }
            };
            let mut promo_buf = [0u8; 4096];
            unsafe {
                let inline_ptr = ext_ptr.add(ext_hdr_size);
                for i in 0..inline_len.min(4096) {
                    promo_buf[i] = *inline_ptr.add(i);
                }
            }
            if !write_block(promo_block, promo_buf.as_ptr()) {
                free_block(promo_block);
                reply.label = SALTY_OUT_OF_MEMORY;
                return reply;
            }
            if !btree_cow_delete(&inline_key) {
                free_block(promo_block);
                reply.label = SALTY_OUT_OF_MEMORY;
                return reply;
            }
            let mut ext_buf = [0u8; 304];
            build_extent_regular(&mut ext_buf, bs, promo_block * bs, bs, 0, bs);
            if !btree_cow_insert(&inline_key, &ext_buf[..ext_hdr_size]) {
                free_block(promo_block);
                reply.label = SALTY_OUT_OF_MEMORY;
                return reply;
            }
            bitmap_flush();
        }
    }

    // Write per-block extents from VFS SHM
    let write_end = offset + count;
    let first_block_off = (offset / bs) * bs;

    let mut block_off = first_block_off;
    while block_off < write_end {
        let extent_key = BTreeKey {
            object_id: ino,
            item_type: SALTY_EXTENT_DATA,
            offset: block_off,
        };

        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        let existing = btree_find_item(root_tree, &extent_key);

        let mut block_buf = [0u8; 4096];
        let mut old_data_block: u64 = 0;
        let mut had_extent = false;

        if let Some((ext_ptr, _)) = existing {
            had_extent = true;
            let ext = unsafe { &*(ext_ptr as *const ExtentData) };
            if ext.extent_type == EXTENT_REGULAR && ext.disk_bytenr != 0 {
                old_data_block = ext.disk_bytenr / bs;
                let existing_data = read_block(old_data_block);
                if !existing_data.is_null() {
                    unsafe {
                        for i in 0..bs as usize {
                            block_buf[i] = *existing_data.add(i);
                        }
                    }
                }
            }
        }

        // Overlay data from VFS SHM
        let write_start = if offset > block_off { (offset - block_off) as usize } else { 0 };
        let write_end_in_block = if write_end < block_off + bs {
            (write_end - block_off) as usize
        } else {
            bs as usize
        };
        let data_offset_in_shm = if block_off > offset { block_off - offset } else { 0 };

        unsafe {
            let src = (VFS_SHM_VADDR + shm_offset + data_offset_in_shm) as *const u8;
            for i in write_start..write_end_in_block {
                block_buf[i] = *src.add(i - write_start);
            }
        }

        let data_block = match alloc_block() {
            Some(b) => b,
            None => {
                reply.label = SALTY_OUT_OF_MEMORY;
                return reply;
            }
        };
        if !write_block(data_block, block_buf.as_ptr()) {
            free_block(data_block);
            reply.label = SALTY_OUT_OF_MEMORY;
            return reply;
        }

        let mut ext_buf = [0u8; 304];
        build_extent_regular(&mut ext_buf, bs, data_block * bs, bs, 0, bs);

        let ok = if had_extent {
            btree_cow_update(&extent_key, &ext_buf[..ext_hdr_size])
        } else {
            btree_cow_insert(&extent_key, &ext_buf[..ext_hdr_size])
        };
        if !ok {
            free_block(data_block);
            reply.label = SALTY_OUT_OF_MEMORY;
            return reply;
        }

        if old_data_block != 0 {
            free_block(old_data_block);
        }

        block_off += bs;
    }

    bitmap_flush();

    // Update inode
    let mut updated_inode = inode;
    updated_inode.size = new_size;
    updated_inode.blocks = (new_size + bs - 1) / bs;
    updated_inode.mtime = unsafe { (*(&raw const SB)).generation + 1 };
    let inode_key = BTreeKey {
        object_id: ino,
        item_type: SALTY_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated_inode)) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = count;
    reply
}

// ======================================================================
// Symlink / Readlink / Hard Link handlers
// ======================================================================

/// Handle SALTYFS_SYMLINK: create a symbolic link.
/// MR0=parent_ino, MR1=link_name_len (max 72), MR2=target_len (max 64),
/// MR3..MR11=link_name (72 bytes), MR12..MR19=target (64 bytes)
pub(crate) fn handle_symlink(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let parent_ino = msg.regs[0];
    let name_len = msg.regs[1] as usize;
    let target_len = msg.regs[2] as usize;

    if name_len == 0 || name_len > 72 || target_len == 0 || target_len > 64 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    // Extract link name from MR3..MR11
    let mut name_buf = [0u8; 72];
    unsafe {
        let src = &raw const msg.regs[3] as *const u8;
        for i in 0..name_len {
            name_buf[i] = *src.add(i);
        }
    }

    // Extract target from MR12..MR19
    let mut target_buf = [0u8; 64];
    unsafe {
        let src = &raw const msg.regs[12] as *const u8;
        for i in 0..target_len {
            target_buf[i] = *src.add(i);
        }
    }

    // Check parent exists and is a directory
    let parent_inode = match get_inode(parent_ino) {
        Some(i) => i,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };
    if parent_inode.mode & 0o170000 != 0o040000 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    // Check name doesn't already exist
    if lookup_in_dir(parent_ino, name_buf.as_ptr(), name_len as u8).is_some() {
        reply.label = SALTY_ALREADY_EXISTS;
        return reply;
    }

    // Allocate inode number
    let new_ino = unsafe {
        let n = *(&raw const NEXT_INO);
        *(&raw mut NEXT_INO) = n + 1;
        n
    };

    // Insert INODE_ITEM with S_IFLNK mode, size = target length
    let inode_data = build_inode_bytes(target_len as u64, 0, 1, 0o120000 | 0o777);
    let inode_key = BTreeKey {
        object_id: new_ino,
        item_type: SALTY_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_insert(&inode_key, &inode_data) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    // Store target as inline extent
    let mut ext_buf = [0u8; 304];
    build_extent_inline(&mut ext_buf, target_len as u64, &target_buf[..target_len]);
    let ext_size = core::mem::size_of::<ExtentData>() + target_len;
    let extent_key = BTreeKey {
        object_id: new_ino,
        item_type: SALTY_EXTENT_DATA,
        offset: 0,
    };
    if !btree_cow_insert(&extent_key, &ext_buf[..ext_size]) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    // Insert DIR_ITEM with type 7 (symlink)
    let mut dir_buf = [0u8; 256];
    let dir_len = build_dir_item(new_ino, &name_buf[..name_len], 7, &mut dir_buf);
    let dir_key = BTreeKey {
        object_id: parent_ino,
        item_type: SALTY_DIR_ITEM,
        offset: new_ino,
    };
    if !btree_cow_insert(&dir_key, &dir_buf[..dir_len]) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = new_ino;
    reply
}

/// Handle SALTYFS_READLINK: read a symlink target.
/// MR0=ino -> MR0=target_len, MR1..MR19=target_data (up to 152 bytes)
pub(crate) fn handle_readlink(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];

    // Get inode and verify it's a symlink
    let inode = match get_inode(ino) {
        Some(i) => i,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };
    if inode.mode & 0o170000 != 0o120000 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    // Read inline extent data (symlink target)
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let extent_key = BTreeKey {
        object_id: ino,
        item_type: SALTY_EXTENT_DATA,
        offset: 0,
    };
    let (data_ptr, data_size) = match btree_find_item(root_tree, &extent_key) {
        Some((d, s)) => (d, s),
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };

    let ext_hdr_size = core::mem::size_of::<ExtentData>();
    if (data_size as usize) < ext_hdr_size {
        reply.label = SALTY_NOT_FOUND;
        return reply;
    }

    let ext = unsafe { core::ptr::read_unaligned(data_ptr as *const ExtentData) };
    if ext.extent_type != EXTENT_INLINE {
        reply.label = SALTY_NOT_FOUND;
        return reply;
    }

    let target_len = inode.size as usize;
    let inline_data = data_size as usize - ext_hdr_size;
    let copy_len = core::cmp::min(target_len, inline_data);
    let copy_len = core::cmp::min(copy_len, 152); // max IPC register space

    // Pack target into reply registers MR1..MR19
    reply.label = SALTY_OK;
    reply.regs[0] = copy_len as u64;
    unsafe {
        let src = (data_ptr as *const u8).add(ext_hdr_size);
        let dst = &raw mut reply.regs[1] as *mut u8;
        for i in 0..copy_len {
            *dst.add(i) = *src.add(i);
        }
    }
    reply.length = 1 + ((copy_len as u64 + 7) / 8);
    reply
}

/// Handle SALTYFS_LINK: create a hard link.
/// MR0=existing_ino, MR1=new_parent_ino, MR2=name_len (max 136),
/// MR3..MR19=name (136 bytes)
pub(crate) fn handle_link(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let existing_ino = msg.regs[0];
    let new_parent = msg.regs[1];
    let name_len = msg.regs[2] as usize;

    if name_len == 0 || name_len > 136 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    // Extract name from MR3..MR19
    let mut name_buf = [0u8; 136];
    unsafe {
        let src = &raw const msg.regs[3] as *const u8;
        for i in 0..name_len {
            name_buf[i] = *src.add(i);
        }
    }

    // Verify source inode exists and is not a directory
    let inode = match get_inode(existing_ino) {
        Some(i) => i,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };
    if inode.mode & 0o170000 == 0o040000 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    // Verify parent exists and is a directory
    let parent_inode = match get_inode(new_parent) {
        Some(i) => i,
        None => {
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };
    if parent_inode.mode & 0o170000 != 0o040000 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    // Check name doesn't already exist in parent
    if lookup_in_dir(new_parent, name_buf.as_ptr(), name_len as u8).is_some() {
        reply.label = SALTY_ALREADY_EXISTS;
        return reply;
    }

    // Insert DIR_ITEM (type 1 for regular file)
    let dir_type: u8 = if inode.mode & 0o170000 == 0o120000 { 7 } else { 1 };
    let mut dir_buf = [0u8; 256];
    let dir_len = build_dir_item(existing_ino, &name_buf[..name_len], dir_type, &mut dir_buf);
    let dir_key = BTreeKey {
        object_id: new_parent,
        item_type: SALTY_DIR_ITEM,
        offset: existing_ino,
    };
    if !btree_cow_insert(&dir_key, &dir_buf[..dir_len]) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    // Increment nlink on existing inode
    let mut updated_inode = inode;
    updated_inode.nlink += 1;
    updated_inode.ctime = unsafe { (*(&raw const SB)).generation + 1 };
    let inode_key = BTreeKey {
        object_id: existing_ino,
        item_type: SALTY_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated_inode)) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    reply.label = SALTY_OK;
    reply.length = 1;
    reply.regs[0] = existing_ino;
    reply
}
