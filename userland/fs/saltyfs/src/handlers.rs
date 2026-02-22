// SPDX-License-Identifier: GPL-2.0-only
//! IPC request handlers for file operations.

use salty::consts::*;
use salty::serial::LineBuf;
use salty::types::*;

use crate::alloc::{alloc_block, free_block, bitmap_flush};
use crate::block::{read_block, write_block, read_superblock};
use crate::btree::{btree_search, btree_find_item, btree_leaf_find_all, btree_cow_insert, btree_cow_delete, btree_cow_update};
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

/// Read file data into SHM at a given offset.
/// Returns bytes actually read.
fn read_file_data(ino: u64, file_offset: u64, count: u64, shm_offset: u64) -> u64 {
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

    // Find extent data for this file
    let search_key = BTreeKey {
        object_id: ino,
        item_type: SALTY_EXTENT_DATA,
        offset: 0,
    };

    let leaf = btree_search(root_tree, &search_key);
    if leaf.is_null() {
        return 0;
    }

    let mut bytes_read = 0u64;

    unsafe {
        let hdr = &*(leaf as *const BTreeNodeHeader);
        let items_start = leaf.add(core::mem::size_of::<BTreeNodeHeader>());
        let item_size = core::mem::size_of::<BTreeItem>();

        for i in 0..hdr.num_items as usize {
            if bytes_read >= actual_count {
                break;
            }

            let item = core::ptr::read_unaligned(items_start.add(i * item_size) as *const BTreeItem);
            if item.key.object_id != ino || item.key.item_type != SALTY_EXTENT_DATA {
                continue;
            }

            let data_ptr = leaf.add(item.offset as usize);
            let extent = &*(data_ptr as *const ExtentData);

            let extent_file_offset = item.key.offset;

            if extent.extent_type == EXTENT_INLINE {
                // Inline data follows the full ExtentData header
                let inline_data = data_ptr.add(core::mem::size_of::<ExtentData>());
                let inline_len = extent.ram_bytes;

                if file_offset < extent_file_offset + inline_len
                    && file_offset + actual_count > extent_file_offset
                {
                    let start_in_extent = if file_offset > extent_file_offset {
                        file_offset - extent_file_offset
                    } else {
                        0
                    };
                    let end_in_extent = if file_offset + actual_count
                        < extent_file_offset + inline_len
                    {
                        file_offset + actual_count - extent_file_offset
                    } else {
                        inline_len
                    };
                    let copy_len = end_in_extent - start_in_extent;

                    let dst = (SHM_VADDR + shm_offset + bytes_read) as *mut u8;
                    let src = inline_data.add(start_in_extent as usize);
                    for j in 0..copy_len as usize {
                        *dst.add(j) = *src.add(j);
                    }
                    bytes_read += copy_len;
                }
            } else if extent.extent_type == EXTENT_REGULAR {
                // Regular extent: data on disk
                let disk_byte = extent.disk_bytenr;
                let extent_offset = extent.offset;
                let num_bytes = extent.num_bytes;

                let abs_start = extent_file_offset + extent_offset;
                let abs_end = abs_start + num_bytes;

                if file_offset < abs_end && file_offset + actual_count > abs_start {
                    let start_in_extent = if file_offset > abs_start {
                        file_offset - abs_start
                    } else {
                        0
                    };
                    let end_in_extent = if file_offset + actual_count < abs_end {
                        file_offset + actual_count - abs_start
                    } else {
                        num_bytes
                    };

                    // Read blocks from disk
                    let disk_start = disk_byte + start_in_extent;
                    let read_len = end_in_extent - start_in_extent;

                    // Read via block cache, copy to SHM
                    let mut pos = 0u64;
                    while pos < read_len {
                        let abs_pos = disk_start + pos;
                        let block_nr = abs_pos / bs;
                        let off_in_block = abs_pos % bs;
                        let can_read = (bs - off_in_block).min(read_len - pos);

                        let block_data = read_block(block_nr);
                        if block_data.is_null() {
                            return bytes_read;
                        }

                        let dst = (SHM_VADDR + shm_offset + bytes_read + pos) as *mut u8;
                        for j in 0..can_read as usize {
                            *dst.add(j) = *block_data.add(off_in_block as usize + j);
                        }

                        pos += can_read;
                    }
                    bytes_read += read_len;
                }
            }
        }
    }

    bytes_read
}

/// Read directory entries from a directory inode.
/// Returns up to 4 entries per call via MR registers.
/// `cursor` is the entry index among matching DIR_ITEM keys.
fn readdir_entries(
    dir_ino: u64,
    cursor: u64,
    reply: &mut SaltyMsg,
) {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };

    let search_key = BTreeKey {
        object_id: dir_ino,
        item_type: SALTY_DIR_ITEM,
        offset: 0,
    };

    let leaf = btree_search(root_tree, &search_key);
    if leaf.is_null() {
        reply.label = SALTY_NOT_FOUND;
        return;
    }

    unsafe {
        let hdr = &*(leaf as *const BTreeNodeHeader);
        let items_start = leaf.add(core::mem::size_of::<BTreeNodeHeader>());
        let item_size = core::mem::size_of::<BTreeItem>();

        let mut entry_idx = 0u64;
        let mut out_idx = 0usize;
        let mut has_more = false;

        // MR0 = next_cursor, then repeated groups of 4:
        // (ino, type, name_lo, name_hi)
        for i in 0..hdr.num_items as usize {
            let item = core::ptr::read_unaligned(items_start.add(i * item_size) as *const BTreeItem);
            if item.key.object_id != dir_ino || item.key.item_type != SALTY_DIR_ITEM {
                continue;
            }

            if entry_idx < cursor {
                entry_idx += 1;
                continue;
            }

            if out_idx >= 4 {
                has_more = true;
                break;
            }

            let data_ptr = leaf.add(item.offset as usize);
            let (child_ino, entry_name_len, entry_dir_type) = parse_dir_item_header(data_ptr);
            let name_ptr = data_ptr.add(DIR_ITEM_HEADER_SIZE);

            let base = 1 + out_idx * 4;
            reply.regs[base] = child_ino;
            reply.regs[base + 1] = entry_dir_type as u64;

            // Pack name into two registers (up to 16 bytes)
            let nlen = (entry_name_len as usize).min(16);
            let mut name_lo: u64 = 0;
            let mut name_hi: u64 = 0;
            for j in 0..nlen.min(8) {
                name_lo |= (*name_ptr.add(j) as u64) << (j * 8);
            }
            for j in 8..nlen {
                name_hi |= (*name_ptr.add(j) as u64) << ((j - 8) * 8);
            }
            reply.regs[base + 2] = name_lo;
            reply.regs[base + 3] = name_hi;

            out_idx += 1;
            entry_idx += 1;
        }

        if out_idx == 0 {
            // No more entries at this cursor.
            reply.regs[0] = 0; // end-of-directory
            reply.label = 0;
            reply.length = 1;
            return;
        }

        // If we have more entries, advance by emitted count.
        // Otherwise mark end-of-directory.
        reply.regs[0] = if has_more { cursor + out_idx as u64 } else { 0 };
        reply.label = 0;
        reply.length = 1 + (out_idx as u64) * 4;
    }
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
    // Name packed in MR1..MR3 (up to 24 bytes)
    let name_len = msg.regs[1] as u8;
    if name_len == 0 || name_len > 24 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 24];
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

    let bytes_read = read_file_data(ino, offset, count, shm_offset);
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

    // Use SHM offset 0 as scratch
    let bytes_read = read_file_data(ino, offset, count, 0);

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
    if name_len == 0 || name_len > 24 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 24];
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

/// Handle SALTYFS_WRITE_INLINE: write up to 136 bytes of data.
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

    let mut new_size = if offset + count > inode.size {
        offset + count
    } else {
        inode.size
    };

    let extent_key = BTreeKey {
        object_id: ino,
        item_type: SALTY_EXTENT_DATA,
        offset: 0,
    };

    if new_size <= 208 {
        // Inline extent path (208 = 256 max LeafItem data - 48 ExtentData header)
        let mut full_data = [0u8; 208];
        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        let mut had_extent = false;

        if let Some((ext_ptr, ext_size)) = btree_find_item(root_tree, &extent_key) {
            had_extent = true;
            let ext_hdr_size = core::mem::size_of::<ExtentData>();
            let inline_len = (ext_size as usize).saturating_sub(ext_hdr_size);
            unsafe {
                let inline_ptr = ext_ptr.add(ext_hdr_size);
                for i in 0..inline_len.min(208) {
                    full_data[i] = *inline_ptr.add(i);
                }
            }
        }

        // Overwrite at offset
        for i in 0..count as usize {
            if offset as usize + i < 208 {
                full_data[offset as usize + i] = data_buf[i];
            }
        }

        // Build new inline extent data
        let mut extent_buf = [0u8; 304];
        build_extent_inline(
            &mut extent_buf,
            new_size,
            &full_data[..new_size as usize],
        );
        let ext_total = core::mem::size_of::<ExtentData>() + new_size as usize;

        // Use atomic update when replacing existing extent, insert for new
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
        // Regular extent path: single 4KiB block
        // Clamp: MVP limits file size to 4KiB
        if offset >= 4096 {
            reply.label = SALTY_OUT_OF_MEMORY;
            return reply;
        }
        if offset + count > 4096 {
            count = 4096 - offset;
        }
        new_size = if offset + count > inode.size {
            (offset + count).min(4096)
        } else {
            inode.size.min(4096)
        };

        let data_block = match alloc_block() {
            Some(b) => b,
            None => {
                reply.label = SALTY_OUT_OF_MEMORY;
                return reply;
            }
        };

        let mut block_buf = [0u8; 4096];
        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        let mut had_existing_extent = false;
        let mut old_data_block: u64 = 0;

        // Copy existing data if any
        if let Some((ext_ptr, ext_size)) = btree_find_item(root_tree, &extent_key) {
            had_existing_extent = true;
            let ext = unsafe { &*(ext_ptr as *const ExtentData) };
            if ext.extent_type == EXTENT_INLINE {
                let ext_hdr_size = core::mem::size_of::<ExtentData>();
                let inline_len = (ext_size as usize).saturating_sub(ext_hdr_size);
                unsafe {
                    let inline_ptr = ext_ptr.add(ext_hdr_size);
                    for i in 0..inline_len.min(4096) {
                        block_buf[i] = *inline_ptr.add(i);
                    }
                }
            } else if ext.extent_type == EXTENT_REGULAR && ext.disk_bytenr != 0 {
                old_data_block = ext.disk_bytenr / 4096;
                let existing_data = read_block(old_data_block);
                if !existing_data.is_null() {
                    unsafe {
                        for i in 0..4096 {
                            block_buf[i] = *existing_data.add(i);
                        }
                    }
                }
            }
        }

        // Write new data at offset
        for i in 0..count as usize {
            if offset as usize + i < 4096 {
                block_buf[offset as usize + i] = data_buf[i];
            }
        }

        // Write data block to disk
        if !write_block(data_block, block_buf.as_ptr()) {
            free_block(data_block);
            reply.label = SALTY_OUT_OF_MEMORY;
            return reply;
        }

        // Build EXTENT_REGULAR metadata
        let mut extent_buf = [0u8; 304];
        let ext_hdr_size = core::mem::size_of::<ExtentData>();
        build_extent_regular(
            &mut extent_buf,
            new_size,
            data_block * 4096,
            4096,
            0,
            new_size,
        );

        // Use atomic update when replacing existing extent, insert for new
        let ok = if had_existing_extent {
            btree_cow_update(&extent_key, &extent_buf[..ext_hdr_size])
        } else {
            btree_cow_insert(&extent_key, &extent_buf[..ext_hdr_size])
        };
        if !ok {
            free_block(data_block);
            reply.label = SALTY_OUT_OF_MEMORY;
            return reply;
        }

        // Free old data block only after successful tree update
        if old_data_block != 0 {
            free_block(old_data_block);
        }

        bitmap_flush();  // best-effort flush for data block allocation
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
    if name_len == 0 || name_len > 24 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 24];
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
    if name_len == 0 || name_len > 24 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 24];
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
        // Delete extent data
        let ext_key = BTreeKey {
            object_id: child_ino,
            item_type: SALTY_EXTENT_DATA,
            offset: 0,
        };
        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        if let Some((ext_ptr, _)) = btree_find_item(root_tree, &ext_key) {
            let ext = unsafe { &*(ext_ptr as *const ExtentData) };
            if ext.extent_type == EXTENT_REGULAR && ext.disk_bytenr != 0 {
                let block_start = ext.disk_bytenr / 4096;
                let block_count = (ext.disk_num_bytes + 4095) / 4096;
                for b in 0..block_count {
                    free_block(block_start + b);
                }
            }
            if !btree_cow_delete(&ext_key) {
                reply.label = SALTY_OUT_OF_MEMORY;
                return reply;
            }
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
    if name_len == 0 || name_len > 24 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 24];
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
    if old_name_len == 0 || old_name_len > 24 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut old_name = [0u8; 24];
    let old_data = &msg.regs[2] as *const u64 as *const u8;
    unsafe {
        for i in 0..old_name_len as usize {
            old_name[i] = *old_data.add(i);
        }
    }

    let new_parent = msg.regs[5];
    let new_name_len = msg.regs[6] as u8;
    if new_name_len == 0 || new_name_len > 24 {
        reply.label = SALTY_INVALID_ARGUMENT;
        return reply;
    }

    let mut new_name = [0u8; 24];
    let new_data = &msg.regs[7] as *const u64 as *const u8;
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
                // Free extent data blocks
                let ext_key = BTreeKey {
                    object_id: existing_ino,
                    item_type: SALTY_EXTENT_DATA,
                    offset: 0,
                };
                let root_tree = unsafe { (*(&raw const SB)).root_tree };
                if let Some((ext_ptr, _)) = btree_find_item(root_tree, &ext_key) {
                    let ext = unsafe { &*(ext_ptr as *const ExtentData) };
                    if ext.extent_type == EXTENT_REGULAR && ext.disk_bytenr != 0 {
                        let block_start = ext.disk_bytenr / 4096;
                        let block_count = (ext.disk_num_bytes + 4095) / 4096;
                        for b in 0..block_count {
                            free_block(block_start + b);
                        }
                    }
                    if !btree_cow_delete(&ext_key) {
                        puts(b"[saltyfs] rename: warning: orphan extent (delete failed)\n");
                    }
                }
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
pub(crate) fn handle_truncate_fs(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];
    let new_size = msg.regs[1];

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

    // Truncate
    let ext_key = BTreeKey {
        object_id: ino,
        item_type: SALTY_EXTENT_DATA,
        offset: 0,
    };
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    if let Some((ext_ptr, ext_size)) = btree_find_item(root_tree, &ext_key) {
        let ext = unsafe { &*(ext_ptr as *const ExtentData) };
        if ext.extent_type == EXTENT_INLINE {
            if new_size == 0 {
                if !btree_cow_delete(&ext_key) {
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return reply;
                }
            } else {
                // Truncate inline data
                let ext_hdr_size = core::mem::size_of::<ExtentData>();
                let inline_len = (ext_size as usize).saturating_sub(ext_hdr_size);
                let mut data = [0u8; 208];
                unsafe {
                    let src = ext_ptr.add(ext_hdr_size);
                    for i in 0..inline_len.min(208) {
                        data[i] = *src.add(i);
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
        } else if ext.extent_type == EXTENT_REGULAR {
            if new_size == 0 {
                if ext.disk_bytenr != 0 {
                    let block_start = ext.disk_bytenr / 4096;
                    let block_count = (ext.disk_num_bytes + 4095) / 4096;
                    for b in 0..block_count {
                        free_block(block_start + b);
                    }
                }
                if !btree_cow_delete(&ext_key) {
                    reply.label = SALTY_OUT_OF_MEMORY;
                    return reply;
                }
            }
            // For non-zero truncation of regular extents, just update the inode size;
            // the data block stays allocated but the inode reports the smaller size.
        }
    }

    let mut updated = inode;
    updated.size = new_size;
    updated.mtime = unsafe { (*(&raw const SB)).generation + 1 };
    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
        reply.label = SALTY_OUT_OF_MEMORY;
        return reply;
    }

    reply.label = SALTY_OK;
    reply
}
