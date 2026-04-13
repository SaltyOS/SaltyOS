// SPDX-License-Identifier: GPL-2.0-only
//! Extended attribute (xattr) handlers for SaltyFS.
//!
//! xattrs are stored as B-tree items with `item_type = TRONA_XATTR_ITEM`.
//! The item key offset is `fnv1a_hash(name)` with linear probing on
//! collision, mirroring the DIR_ITEM scheme so callers can reuse the same
//! mental model.
//!
//! Two on-disk value shapes share the 8-byte `XattrHeader`:
//!
//! - **INLINE** (`flags & XATTR_FLAG_INDIRECT == 0`) stores the value
//!   bytes directly after the name. Used when
//!   `8 + name_len + value_len ≤ SALTY_XATTR_INLINE_MAX`.
//!
//! - **INDIRECT** (`flags & XATTR_FLAG_INDIRECT != 0`) stores a 8-byte
//!   `ref_ino` field after the name. The hidden inode referenced by
//!   `ref_ino` (carrying `SALTY_INODE_HIDDEN`) holds the real value via
//!   regular EXTENT_DATA items, reusing the entire file-data write/read
//!   stack (btrfs+ZFS hybrid design — see docs/design/saltyfs.md).
//!
//! This module implements the inline path fully in stage 6; the indirect
//! path is layered on top in stage 7 without disturbing the inline format.

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::protocol::*;
use trona::types::core::*;

use crate::alloc::{alloc_block, free_block, bitmap_flush};
use crate::block::{read_block, write_block};
use crate::btree::{btree_find_all_for_ino, btree_cow_delete, btree_cow_insert, btree_cow_update};
use crate::consts::*;
use crate::handlers::get_inode;
use crate::types::*;
use crate::{SB, BLOCK_SIZE, MOUNTED, NEXT_INO, READONLY};

/// Local twin of `handlers::ro_reject_if_readonly`. Kept here so xattr.rs
/// does not depend on private helpers.
#[inline]
fn ro_reject() -> Option<TronaMsg> {
    if unsafe { *(&raw const READONLY) } {
        let mut reply = TronaMsg::zeroed();
        reply.label = TRONA_READONLY;
        Some(reply)
    } else {
        None
    }
}

// ======================================================================
// Namespace validation
// ======================================================================

/// POSIX-ish xattr namespaces. All other prefixes are rejected. capability
/// checks for `trusted.*` / `security.*` are deferred to a future multi-user
/// PR — see docs/design/saltyfs.md.
fn valid_xattr_namespace(name: &[u8]) -> bool {
    const PREFIXES: [&[u8]; 4] = [
        b"user.",
        b"trusted.",
        b"security.",
        b"system.",
    ];
    for p in PREFIXES.iter() {
        if name.len() > p.len() && &name[..p.len()] == *p {
            return true;
        }
    }
    false
}

// ======================================================================
// Packing / parsing helpers
// ======================================================================

/// Build an inline XATTR_ITEM payload into `out`, returning written length.
/// `out` must be at least `XATTR_HEADER_SIZE + name.len() + value.len()` long.
fn build_inline_xattr(name: &[u8], value: &[u8], out: &mut [u8]) -> usize {
    let header = XattrHeader {
        name_len: name.len() as u16,
        flags: 0,
        reserved0: 0,
        value_len: value.len() as u32,
    };
    unsafe {
        core::ptr::write_unaligned(out.as_mut_ptr() as *mut XattrHeader, header);
    }
    let name_off = XATTR_HEADER_SIZE;
    for i in 0..name.len() {
        out[name_off + i] = name[i];
    }
    let value_off = name_off + name.len();
    for i in 0..value.len() {
        out[value_off + i] = value[i];
    }
    value_off + value.len()
}

/// Build an indirect XATTR_ITEM payload into `out`: header + name + ref_ino.
fn build_indirect_xattr(name: &[u8], value_len: u32, ref_ino: u64, out: &mut [u8]) -> usize {
    let header = XattrHeader {
        name_len: name.len() as u16,
        flags: XATTR_FLAG_INDIRECT,
        reserved0: 0,
        value_len,
    };
    unsafe {
        core::ptr::write_unaligned(out.as_mut_ptr() as *mut XattrHeader, header);
    }
    let name_off = XATTR_HEADER_SIZE;
    for i in 0..name.len() {
        out[name_off + i] = name[i];
    }
    let ref_off = name_off + name.len();
    unsafe {
        core::ptr::write_unaligned(out.as_mut_ptr().add(ref_off) as *mut u64, ref_ino);
    }
    ref_off + 8
}

// ======================================================================
// B-tree traversal helpers
// ======================================================================

/// Search for an existing XATTR_ITEM on `ino` whose stored name equals
/// `name`. Uses hash + linear probing (max 16 slots) to match the DIR_ITEM
/// insertion pattern. Returns `(key, data_ptr, item_size)` on hit.
fn find_xattr_by_name(
    ino: u64,
    name: &[u8],
) -> Option<(BTreeKey, *const u8, u32)> {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let mut key = BTreeKey {
        object_id: ino,
        item_type: TRONA_XATTR_ITEM,
        offset: crate::name::fnv1a_bytes(name),
    };
    for _ in 0..16 {
        if let Some((data_ptr, size)) = crate::btree::btree_find_item(root_tree, &key) {
            unsafe {
                let hdr = read_xattr_header(data_ptr);
                let hdr_name_len = hdr.name_len as usize;
                if hdr_name_len == name.len() {
                    let name_ptr = data_ptr.add(XATTR_HEADER_SIZE);
                    let mut matched = true;
                    for i in 0..hdr_name_len {
                        if *name_ptr.add(i) != name[i] {
                            matched = false;
                            break;
                        }
                    }
                    if matched {
                        return Some((key, data_ptr, size));
                    }
                }
            }
        } else {
            break;
        }
        key.offset = key.offset.wrapping_add(1);
    }
    None
}

/// Return the first free XATTR_ITEM slot for `(ino, fnv1a_hash(name))`,
/// using linear probing. Returns `None` if 16 consecutive slots are full.
fn find_free_xattr_slot(ino: u64, name: &[u8]) -> Option<BTreeKey> {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let mut key = BTreeKey {
        object_id: ino,
        item_type: TRONA_XATTR_ITEM,
        offset: crate::name::fnv1a_bytes(name),
    };
    for _ in 0..16 {
        if crate::btree::btree_find_item(root_tree, &key).is_none() {
            return Some(key);
        }
        key.offset = key.offset.wrapping_add(1);
    }
    None
}

// ======================================================================
// Hidden inode helpers (indirect xattr storage — stage 7)
// ======================================================================

/// Allocate a new hidden inode carrying `SALTY_INODE_HIDDEN`. The inode is
/// not referenced by any directory entry; the only reference is the
/// XATTR_ITEM indirect payload that callers will write immediately after.
fn alloc_hidden_inode(value_len: u64, bs: u64) -> Option<u64> {
    let new_ino = unsafe {
        let n = *(&raw const NEXT_INO);
        *(&raw mut NEXT_INO) = n + 1;
        n
    };
    let inode = SaltyInodeItem {
        generation: unsafe { (*(&raw const SB)).generation + 1 },
        size: value_len,
        blocks: (value_len + bs - 1) / bs,
        block_group: 0,
        nlink: 1,
        uid: 0,
        gid: 0,
        mode: 0o100600, // S_IFREG | 0o600
        atime: 0,
        mtime: 0,
        ctime: 0,
        crtime: 0,
        flags: SALTY_INODE_HIDDEN,
        sequence: 0,
        reserved: [0; 32],
    };
    let mut buf = [0u8; 128];
    unsafe {
        core::ptr::write_unaligned(buf.as_mut_ptr() as *mut SaltyInodeItem, inode);
    }
    let key = BTreeKey {
        object_id: new_ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_insert(&key, &buf) {
        return None;
    }
    Some(new_ino)
}

/// Delete all EXTENT_DATA items belonging to a hidden inode, freeing any
/// backing blocks. Matches the `delete_all_extents` pattern in handlers.rs
/// but kept local to avoid circular visibility — hidden inodes are only
/// manipulated through xattr paths.
fn delete_hidden_inode_extents(ino: u64) {
    let bs = unsafe { *(&raw const BLOCK_SIZE) };
    loop {
        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        let mut offsets = [0u64; 128];
        let mut types = [0u8; 128];
        let mut disk_addrs = [0u64; 128];
        let mut disk_sizes = [0u64; 128];
        let mut count = 0usize;

        btree_find_all_for_ino(root_tree, ino, TRONA_EXTENT_DATA, |key, data_ptr, _size| {
            if count < 128 {
                let ext = unsafe { read_extent_data(data_ptr) };
                offsets[count] = key.offset;
                types[count] = ext.extent_type;
                disk_addrs[count] = ext.disk_bytenr;
                disk_sizes[count] = ext.disk_num_bytes;
                count += 1;
            }
            count < 128
        });

        if count == 0 {
            return;
        }

        for i in 0..count {
            if types[i] == EXTENT_REGULAR && disk_addrs[i] != 0 {
                let block_start = disk_addrs[i] / bs;
                let block_count = (disk_sizes[i] + bs - 1) / bs;
                for b in 0..block_count {
                    free_block(block_start + b);
                }
            }
            let key = BTreeKey {
                object_id: ino,
                item_type: TRONA_EXTENT_DATA,
                offset: offsets[i],
            };
            let _ = btree_cow_delete(&key);
        }
    }
}

/// Completely dispose of a hidden inode: delete its extents and its
/// INODE_ITEM. Used when overwriting/removing an indirect xattr.
fn destroy_hidden_inode(ino: u64) {
    delete_hidden_inode_extents(ino);
    let _ = bitmap_flush();
    let inode_key = BTreeKey {
        object_id: ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };
    let _ = btree_cow_delete(&inode_key);
}

/// Write `value` into hidden inode `ino`'s extent storage, one 4 KiB block
/// at a time. On failure, extents written so far are rolled back via
/// `delete_hidden_inode_extents`.
fn write_hidden_inode_value(ino: u64, value: &[u8]) -> bool {
    let bs = unsafe { *(&raw const BLOCK_SIZE) } as usize;
    let total = value.len();
    let mut pos = 0usize;
    let mut block_offset = 0u64;

    while pos < total {
        let chunk = core::cmp::min(bs, total - pos);
        let data_block = match alloc_block() {
            Some(b) => b,
            None => {
                delete_hidden_inode_extents(ino);
                return false;
            }
        };
        let mut block_buf = [0u8; 4096];
        for i in 0..chunk {
            block_buf[i] = value[pos + i];
        }
        if !write_block(data_block, block_buf.as_ptr()) {
            free_block(data_block);
            delete_hidden_inode_extents(ino);
            return false;
        }

        let mut ext_buf = [0u8; 304];
        let ext = ExtentData {
            generation: unsafe { (*(&raw const SB)).generation + 1 },
            ram_bytes: chunk as u64,
            compression: 0,
            encryption: 0,
            other_encoding: 0,
            extent_type: EXTENT_REGULAR,
            reserved: [0; 3],
            disk_bytenr: data_block * bs as u64,
            disk_num_bytes: bs as u64,
            offset: 0,
            num_bytes: chunk as u64,
        };
        unsafe {
            core::ptr::write_unaligned(ext_buf.as_mut_ptr() as *mut ExtentData, ext);
        }

        let ext_key = BTreeKey {
            object_id: ino,
            item_type: TRONA_EXTENT_DATA,
            offset: block_offset,
        };
        if !btree_cow_insert(&ext_key, &ext_buf[..core::mem::size_of::<ExtentData>()]) {
            free_block(data_block);
            delete_hidden_inode_extents(ino);
            return false;
        }

        pos += chunk;
        block_offset += bs as u64;
    }
    true
}

/// Read `count` bytes starting from file offset 0 of a hidden inode into
/// `dst`. Returns actual bytes read (may be less on short files).
/// Re-uses the extent iteration pattern from handlers.rs::read_file_data
/// but walks only EXTENT_DATA items for one inode.
fn read_hidden_inode_value(ino: u64, dst: *mut u8, count: u64) -> u64 {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let bs = unsafe { *(&raw const BLOCK_SIZE) };
    let mut bytes_written = 0u64;

    btree_find_all_for_ino(root_tree, ino, TRONA_EXTENT_DATA, |key, data_ptr, _size| {
        if bytes_written >= count {
            return false;
        }
        let extent = unsafe { read_extent_data(data_ptr) };
        let extent_file_offset = key.offset;

        if extent.extent_type == EXTENT_REGULAR {
            let disk_start = extent.disk_bytenr + extent.offset;
            let num_bytes = core::cmp::min(
                extent.num_bytes,
                count.saturating_sub(bytes_written),
            );

            let mut pos = 0u64;
            while pos < num_bytes {
                let abs_pos = disk_start + pos;
                let block_nr = abs_pos / bs;
                let off_in_block = abs_pos % bs;
                let can = (bs - off_in_block).min(num_bytes - pos);

                let block_data = read_block(block_nr);
                if block_data.is_null() {
                    return false;
                }
                unsafe {
                    let dst_ptr = dst.add((extent_file_offset + bytes_written) as usize + pos as usize);
                    for j in 0..can as usize {
                        *dst_ptr.add(j) = *block_data.add(off_in_block as usize + j);
                    }
                }
                pos += can;
            }
            bytes_written += num_bytes;
        } else if extent.extent_type == EXTENT_INLINE {
            // Hidden inode values we write always go via EXTENT_REGULAR above,
            // but if an older path created an inline extent we still honour it.
            let inline_data = unsafe { data_ptr.add(core::mem::size_of::<ExtentData>()) };
            let inline_len = core::cmp::min(
                extent.ram_bytes,
                count.saturating_sub(bytes_written),
            );
            unsafe {
                let dst_ptr = dst.add((extent_file_offset + bytes_written) as usize);
                for j in 0..inline_len as usize {
                    *dst_ptr.add(j) = *inline_data.add(j);
                }
            }
            bytes_written += inline_len;
        }
        true
    });

    bytes_written
}

// ======================================================================
// Public handlers
// ======================================================================

/// Handle SALTYFS_SETXATTR.
///
/// Request:
///   regs[0] = ino
///   regs[1] = flags (SALTYFS_XATTR_CREATE / SALTYFS_XATTR_REPLACE / 0)
///   regs[2] = shm_offset (into VFS SHM, name followed by value)
///   regs[3] = value_len
///   regs[4] = name_len (≤ SALTY_XATTR_NAME_MAX)
pub(crate) fn handle_setxattr(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject() { return r; }
    if !unsafe { *(&raw const crate::VFS_SHM_MAPPED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];
    let flags = msg.regs[1];
    let shm_offset = msg.regs[2];
    let value_len = msg.regs[3];
    let name_len = msg.regs[4] as usize;

    if name_len == 0 || name_len > SALTY_XATTR_NAME_MAX {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }
    let shm_size = VFS_SHM_PAGES * 4096;
    if shm_offset >= shm_size
        || (name_len as u64) + value_len > shm_size - shm_offset
    {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    // Read name + value from SHM.
    let name_ptr = (VFS_SHM_VADDR + shm_offset) as *const u8;
    let value_ptr = unsafe { name_ptr.add(name_len) };
    let name_slice = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    let value_slice = unsafe { core::slice::from_raw_parts(value_ptr, value_len as usize) };

    if !valid_xattr_namespace(name_slice) {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    // Ensure the inode actually exists before mutating anything.
    if get_inode(ino).is_none() {
        reply.label = TRONA_NOT_FOUND;
        return reply;
    }

    // Look for an existing entry under the same name.
    let existing = find_xattr_by_name(ino, name_slice);

    let create_only = (flags & SALTYFS_XATTR_CREATE) != 0;
    let replace_only = (flags & SALTYFS_XATTR_REPLACE) != 0;
    if create_only && existing.is_some() {
        reply.label = TRONA_ALREADY_EXISTS;
        return reply;
    }
    if replace_only && existing.is_none() {
        reply.label = TRONA_NOT_FOUND;
        return reply;
    }

    let use_inline = XATTR_HEADER_SIZE + name_len + (value_len as usize) <= SALTY_XATTR_INLINE_MAX;

    if !use_inline {
        // Indirect path: allocate a hidden inode and write the value via
        // the regular extent machinery.
        let bs = unsafe { *(&raw const BLOCK_SIZE) };
        let new_hidden = match alloc_hidden_inode(value_len, bs) {
            Some(x) => x,
            None => {
                reply.label = TRONA_OUT_OF_MEMORY;
                return reply;
            }
        };
        if !write_hidden_inode_value(new_hidden, value_slice) {
            // write_hidden_inode_value already cleaned up on failure.
            let inode_key = BTreeKey {
                object_id: new_hidden,
                item_type: TRONA_INODE_ITEM,
                offset: 0,
            };
            let _ = btree_cow_delete(&inode_key);
            let _ = bitmap_flush();
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }

        // Serialise indirect payload.
        let mut payload = [0u8; 256];
        let plen = build_indirect_xattr(name_slice, value_len as u32, new_hidden, &mut payload);

        // Commit the XATTR_ITEM: either overwrite existing slot (in-place key)
        // or allocate a fresh slot via linear probing.
        let result = if let Some((existing_key, _, _)) = existing {
            btree_cow_update(&existing_key, &payload[..plen])
        } else {
            match find_free_xattr_slot(ino, name_slice) {
                Some(key) => btree_cow_insert(&key, &payload[..plen]),
                None => false,
            }
        };
        if !result {
            // Roll back the hidden inode on XATTR_ITEM insert failure.
            destroy_hidden_inode(new_hidden);
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }

        // If we replaced a previous indirect entry, tear down the old hidden
        // inode. Previous inline entries don't need cleanup.
        if let Some((_, old_ptr, _)) = existing {
            let old_hdr = unsafe { read_xattr_header(old_ptr) };
            if (old_hdr.flags & XATTR_FLAG_INDIRECT) != 0 {
                let old_name_len = old_hdr.name_len as usize;
                let old_ref_ino = unsafe {
                    core::ptr::read_unaligned(
                        old_ptr.add(XATTR_HEADER_SIZE + old_name_len) as *const u64,
                    )
                };
                if old_ref_ino != new_hidden {
                    destroy_hidden_inode(old_ref_ino);
                }
            }
        }

        let _ = bitmap_flush();
        reply.label = TRONA_OK;
        return reply;
    }

    // Inline path: build payload and commit.
    let mut payload = [0u8; 256];
    let plen = build_inline_xattr(name_slice, value_slice, &mut payload);

    // Capture any old indirect reference so we can reclaim the hidden inode
    // after the XATTR_ITEM write succeeds.
    let old_indirect_ino: Option<u64> = if let Some((_, old_ptr, _)) = existing {
        let old_hdr = unsafe { read_xattr_header(old_ptr) };
        if (old_hdr.flags & XATTR_FLAG_INDIRECT) != 0 {
            let n = old_hdr.name_len as usize;
            let ino = unsafe {
                core::ptr::read_unaligned(old_ptr.add(XATTR_HEADER_SIZE + n) as *const u64)
            };
            Some(ino)
        } else {
            None
        }
    } else {
        None
    };

    let ok = if let Some((existing_key, _, _)) = existing {
        btree_cow_update(&existing_key, &payload[..plen])
    } else {
        match find_free_xattr_slot(ino, name_slice) {
            Some(key) => btree_cow_insert(&key, &payload[..plen]),
            None => false,
        }
    };
    if !ok {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    if let Some(old_ino) = old_indirect_ino {
        destroy_hidden_inode(old_ino);
    }

    let _ = bitmap_flush();
    reply.label = TRONA_OK;
    reply
}

/// Handle SALTYFS_GETXATTR.
///
/// Request:
///   regs[0] = ino
///   regs[1] = shm_offset  (name input + value output)
///   regs[2] = buf_bytes   (max value bytes to write into SHM; 0 = size query)
///   regs[3] = name_len    (≤ SALTY_XATTR_NAME_MAX)
///
/// Reply:
///   regs[0] = value_len (always the full length, regardless of buf_bytes)
///   label   = TRONA_OK | TRONA_NOT_FOUND | TRONA_OUT_OF_RANGE | TRONA_INVALID_ARGUMENT
pub(crate) fn handle_getxattr(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if !unsafe { *(&raw const crate::VFS_SHM_MAPPED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];
    let shm_offset = msg.regs[1];
    let buf_bytes = msg.regs[2];
    let name_len = msg.regs[3] as usize;

    if name_len == 0 || name_len > SALTY_XATTR_NAME_MAX {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }
    let shm_size = VFS_SHM_PAGES * 4096;
    if shm_offset >= shm_size
        || (name_len as u64) > shm_size - shm_offset
        || buf_bytes > shm_size - shm_offset
    {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    let name_ptr = (VFS_SHM_VADDR + shm_offset) as *const u8;
    let name_slice = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };

    let (_, data_ptr, _size) = match find_xattr_by_name(ino, name_slice) {
        Some(x) => x,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    let hdr = unsafe { read_xattr_header(data_ptr) };
    let value_len = hdr.value_len as u64;
    reply.length = 1;
    reply.regs[0] = value_len;

    if buf_bytes == 0 {
        // Size query mode.
        reply.label = TRONA_OK;
        return reply;
    }
    if buf_bytes < value_len {
        reply.label = TRONA_OUT_OF_RANGE;
        return reply;
    }

    let dst = (VFS_SHM_VADDR + shm_offset) as *mut u8;
    if (hdr.flags & XATTR_FLAG_INDIRECT) == 0 {
        // Inline: copy from the leaf payload.
        unsafe {
            let src = data_ptr.add(XATTR_HEADER_SIZE + hdr.name_len as usize);
            for i in 0..value_len as usize {
                *dst.add(i) = *src.add(i);
            }
        }
    } else {
        // Indirect: pull the value from the hidden inode's extents.
        let ref_ino = unsafe {
            core::ptr::read_unaligned(
                data_ptr.add(XATTR_HEADER_SIZE + hdr.name_len as usize) as *const u64,
            )
        };
        let got = read_hidden_inode_value(ref_ino, dst, value_len);
        if got != value_len {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
    }
    reply.label = TRONA_OK;
    reply
}

/// Handle SALTYFS_REMOVEXATTR.
///
/// Request:
///   regs[0] = ino
///   regs[1] = name_len
///   regs[2..] = name bytes (up to 144)
pub(crate) fn handle_removexattr(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject() { return r; }

    let ino = msg.regs[0];
    let name_len = msg.regs[1] as usize;
    if name_len == 0 || name_len > 144 || name_len > SALTY_XATTR_NAME_MAX {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 144];
    let name_data = &msg.regs[2] as *const u64 as *const u8;
    unsafe {
        for i in 0..name_len {
            name_buf[i] = *name_data.add(i);
        }
    }
    let name_slice = &name_buf[..name_len];

    let (key, data_ptr, _) = match find_xattr_by_name(ino, name_slice) {
        Some(x) => x,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    // Reclaim the hidden inode first on indirect entries so that a B-tree
    // delete failure leaves us with the old xattr still pointing at a
    // consistent (still-existing) hidden inode — insert-new / delete-old
    // ordering is preserved.
    let hdr = unsafe { read_xattr_header(data_ptr) };
    let indirect_ref: Option<u64> = if (hdr.flags & XATTR_FLAG_INDIRECT) != 0 {
        let n = hdr.name_len as usize;
        Some(unsafe {
            core::ptr::read_unaligned(data_ptr.add(XATTR_HEADER_SIZE + n) as *const u64)
        })
    } else {
        None
    };

    if !btree_cow_delete(&key) {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    if let Some(ref_ino) = indirect_ref {
        destroy_hidden_inode(ref_ino);
    }
    let _ = bitmap_flush();

    reply.label = TRONA_OK;
    reply
}

/// Handle SALTYFS_LISTXATTR.
///
/// Request:
///   regs[0] = ino
///   regs[1] = shm_offset
///   regs[2] = buf_bytes
///
/// Reply:
///   regs[0] = bytes_needed (full NUL-separated list length)
///   regs[1] = bytes_written (≤ buf_bytes)
///   label   = TRONA_OK | TRONA_OUT_OF_RANGE
pub(crate) fn handle_listxattr(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if !unsafe { *(&raw const crate::VFS_SHM_MAPPED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];
    let shm_offset = msg.regs[1];
    let buf_bytes = msg.regs[2];

    let shm_size = VFS_SHM_PAGES * 4096;
    if shm_offset > shm_size || buf_bytes > shm_size - shm_offset {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    let base = (VFS_SHM_VADDR + shm_offset) as *mut u8;
    let root_tree = unsafe { (*(&raw const SB)).root_tree };

    let mut bytes_needed = 0u64;
    let mut bytes_written = 0u64;

    btree_find_all_for_ino(root_tree, ino, TRONA_XATTR_ITEM, |_key, data_ptr, _size| {
        let hdr = unsafe { read_xattr_header(data_ptr) };
        let n = hdr.name_len as u64;
        let needed = n + 1; // name + NUL terminator
        bytes_needed += needed;

        if bytes_written + needed <= buf_bytes {
            unsafe {
                let src = data_ptr.add(XATTR_HEADER_SIZE);
                let dst = base.add(bytes_written as usize);
                for i in 0..n as usize {
                    *dst.add(i) = *src.add(i);
                }
                *dst.add(n as usize) = 0;
            }
            bytes_written += needed;
        }
        true
    });

    reply.length = 2;
    reply.regs[0] = bytes_needed;
    reply.regs[1] = bytes_written;
    reply.label = if bytes_written < bytes_needed && buf_bytes > 0 {
        TRONA_OUT_OF_RANGE
    } else {
        TRONA_OK
    };
    reply
}

/// Public entry point invoked from `handle_unlink_fs` / `handle_rename_fs`
/// whenever an inode drops to `nlink=0`. Deletes every XATTR_ITEM on the
/// inode, reclaiming hidden inode backing blocks for indirect entries.
pub(crate) fn delete_all_xattrs(ino: u64) {
    loop {
        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        let mut keys = [BTreeKey { object_id: 0, item_type: 0, offset: 0 }; 128];
        let mut refs = [0u64; 128];
        let mut kinds = [false; 128]; // true = indirect
        let mut count = 0usize;

        btree_find_all_for_ino(root_tree, ino, TRONA_XATTR_ITEM, |key, data_ptr, _size| {
            if count < 128 {
                keys[count] = *key;
                let hdr = unsafe { read_xattr_header(data_ptr) };
                if (hdr.flags & XATTR_FLAG_INDIRECT) != 0 {
                    let n = hdr.name_len as usize;
                    let ref_ino = unsafe {
                        core::ptr::read_unaligned(
                            data_ptr.add(XATTR_HEADER_SIZE + n) as *const u64,
                        )
                    };
                    refs[count] = ref_ino;
                    kinds[count] = true;
                }
                count += 1;
            }
            count < 128
        });

        if count == 0 {
            return;
        }

        for i in 0..count {
            let _ = btree_cow_delete(&keys[i]);
            if kinds[i] {
                destroy_hidden_inode(refs[i]);
            }
        }
        let _ = bitmap_flush();
    }
}
