// SPDX-License-Identifier: GPL-2.0-only
//! IPC request handlers for file operations.
//!
//! Name length limits are dictated by IPC message register packing:
//!
//! V1 inbound layout (legacy, uid/gid implied zero):
//!   - 136 bytes (MR3..MR19): create, mkdir, link name fields
//!   - 144 bytes (MR2..MR19): lookup, unlink, rmdir name fields
//!   - 72  bytes (MR3..MR11): symlink link name
//!   - 64  bytes (MR12..MR19): symlink target, rename new name
//!
//! V2 inbound layout (multi-user, bit 63 of MR0 set via `SALTYFS_PROTO_V2`):
//!   - 120 bytes (MR5..MR20): create, mkdir name fields (MR2=uid, MR3=gid, MR4=name_len)
//!   - 56  bytes (MR5..MR11): symlink link name (MR1=uid, MR2=gid, MR3=name_len, MR4=target_len)
//!   - 64  bytes (MR12..MR19): symlink target (unchanged between V1/V2)
//!
//! Outbound STAT-merged layouts:
//!   - `handle_lookup` reply carries 10 regs
//!     (ino/seq/mode/size/nlink/mtime/uid/gid/dir_type/blocks)
//!   - `handle_readdir` streams fixed 96B records into VFS SHM — see `READDIR_ENTRY_BYTES`
//!   - `handle_stat` reply carries 9 regs
//!     (ino/size/mode/nlink/mtime/blocks/uid/gid/seq)

use crate::alloc::{alloc_block, bitmap_flush, free_block};
use crate::block::{
    cache_flush_all, flush_superblock_if_dirty, read_block, read_superblock, write_block,
};
use crate::btree::{
    btree_cow_delete, btree_cow_insert, btree_cow_update, btree_find_all_for_ino, btree_find_item,
};
use crate::consts::*;
use crate::session::{self, SessionState};
use crate::types::*;
use crate::{BLOCK_SIZE, CURRENT_SESSION_ID, MOUNTED, NEXT_SESSION_ID, READONLY, SB};
use trona_kernel::core_types::*;
use trona_kernel::uapi::KERNITE_CAP_SELF_CSPACE;
use trona_protocol::common::{
    TRONA_ALREADY_EXISTS, TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION, TRONA_NOT_FOUND,
    TRONA_OK, TRONA_OUT_OF_MEMORY, TRONA_READONLY,
};
use trona_protocol::correlation::{
    CORRELATION_CLASS_FS, CORRELATION_F_LOOKUP_PARENT, CORRELATION_HEADER_REG_START,
    CorrelationHeader,
};
use trona_protocol::mm::MM_SHM_MAP;
use trona_protocol::vfs::backend::*;

/// Branch used by every mutating handler: returns an early reply carrying
/// `TRONA_READONLY` when the filesystem was mounted read-only. Callers must
/// return the produced message directly.
#[inline]
fn ro_reject_if_readonly() -> Option<TronaMsg> {
    if unsafe { *(&raw const READONLY) } {
        let mut reply = TronaMsg::zeroed();
        reply.label = TRONA_READONLY;
        Some(reply)
    } else {
        None
    }
}

/// Look up a directory's `SALTY_INODE_CASEFOLD` bit. Used by DIR_ITEM hash
/// and comparison helpers to pick between raw-byte and Unicode Simple
/// Case-Folding behaviour.
#[inline]
fn dir_is_casefold(parent_ino: u64) -> bool {
    match get_inode(parent_ino) {
        Some(p) => (p.flags & SALTY_INODE_CASEFOLD) != 0,
        None => false,
    }
}

/// Insert a DIR_ITEM with linear probing on hash collision. The hash uses
/// Simple Case-Folding when the parent directory has `SALTY_INODE_CASEFOLD`
/// set, so that `Hello.txt` and `hello.txt` collapse onto the same key.
///
/// Callers are expected to have already verified that no matching entry
/// exists (via `lookup_in_dir`) so that collisions here are genuine
/// hash collisions rather than duplicate names.
fn dir_item_insert(parent_ino: u64, name: &[u8], dir_buf: &[u8]) -> bool {
    let casefold = dir_is_casefold(parent_ino);
    let mut key = BTreeKey {
        object_id: parent_ino,
        item_type: TRONA_DIR_ITEM,
        offset: crate::name::dir_name_hash(name, casefold),
    };
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    for _ in 0..16 {
        if btree_find_item(root_tree, &key).is_none() {
            return btree_cow_insert(&key, dir_buf);
        }
        key.offset = key.offset.wrapping_add(1);
    }
    false
}

/// Find the actual BTreeKey for a DIR_ITEM entry by scanning for a matching
/// name. Falls through the full directory on old images where the key
/// offset is `child_ino` instead of the name hash. Casefold-aware: when the
/// parent directory has `SALTY_INODE_CASEFOLD`, names compare under Simple
/// Case-Folding.
fn find_dir_item_key(dir_ino: u64, name: *const u8, name_len: u8) -> Option<BTreeKey> {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let casefold = dir_is_casefold(dir_ino);
    let name_slice = unsafe { core::slice::from_raw_parts(name, name_len as usize) };
    let mut found_key: Option<BTreeKey> = None;

    btree_find_all_for_ino(
        root_tree,
        dir_ino,
        TRONA_DIR_ITEM,
        |key, data_ptr, _size| {
            unsafe {
                let (_, entry_name_len, _) = parse_dir_item_header(data_ptr);
                let entry_name_ptr = data_ptr.add(DIR_ITEM_HEADER_SIZE);
                let entry_name_slice =
                    core::slice::from_raw_parts(entry_name_ptr, entry_name_len as usize);
                if crate::name::dir_name_equal(entry_name_slice, name_slice, casefold) {
                    found_key = Some(*key);
                    return false;
                }
            }
            true
        },
    );

    found_key
}

/// Insert an INODE_REF item: key = (child_ino, TRONA_INODE_REF, parent_ino), data = name.
/// Idempotent: returns true if the item already exists.
fn inode_ref_insert(child_ino: u64, parent_ino: u64, name: &[u8]) -> bool {
    let key = BTreeKey {
        object_id: child_ino,
        item_type: TRONA_INODE_REF,
        offset: parent_ino,
    };
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    if btree_find_item(root_tree, &key).is_some() {
        return true; // already exists (idempotent)
    }
    btree_cow_insert(&key, name)
}

/// Delete an INODE_REF item for (child_ino, parent_ino).
/// Idempotent: returns true if the item was already absent.
/// Returns false only on B-tree structural errors (COW alloc/I/O failure).
fn inode_ref_delete(child_ino: u64, parent_ino: u64) -> bool {
    let key = BTreeKey {
        object_id: child_ino,
        item_type: TRONA_INODE_REF,
        offset: parent_ino,
    };
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    if btree_find_item(root_tree, &key).is_none() {
        return true; // already absent — idempotent
    }
    btree_cow_delete(&key)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DirEntryTxnError {
    /// The composite operation failed and rollback succeeded (or no rollback was needed).
    FailedClean,
    /// The composite operation failed and rollback also failed; metadata may be inconsistent.
    FailedDirty,
}

type DirEntryTxnResult = Result<(), DirEntryTxnError>;

#[inline]
fn dir_item_type_from_mode(mode: u32) -> u8 {
    if (mode & 0o170000) == 0o040000 {
        4 // directory
    } else if (mode & 0o170000) == 0o120000 {
        7 // symlink
    } else {
        1 // regular/other non-dir entries
    }
}

fn pack_lookup_snapshot_reply(reply: &mut TronaMsg, ino: u64, dir_type: u8) -> bool {
    let Some(inode) = get_inode(ino) else {
        reply.label = TRONA_NOT_FOUND;
        return false;
    };
    reply.label = TRONA_OK;
    reply.length = 10;
    reply.regs[0] = ino;
    reply.regs[1] = inode.sequence as u64;
    reply.regs[2] = inode.mode as u64;
    reply.regs[3] = inode.size;
    reply.regs[4] = inode.nlink as u64;
    reply.regs[5] = inode.mtime;
    reply.regs[6] = inode.uid as u64;
    reply.regs[7] = inode.gid as u64;
    reply.regs[8] = dir_type as u64;
    reply.regs[9] = inode.blocks;
    true
}

/// Insert a directory entry and its reverse INODE_REF as a single logical update.
/// Tries to rollback INODE_REF if DIR_ITEM insertion fails.
fn dir_entry_insert_with_ref(
    parent_ino: u64,
    child_ino: u64,
    name: &[u8],
    dir_type: u8,
) -> DirEntryTxnResult {
    if !inode_ref_insert(child_ino, parent_ino, name) {
        return Err(DirEntryTxnError::FailedClean);
    }

    let mut dir_buf = [0u8; 256];
    let dir_len = build_dir_item(child_ino, name, dir_type, &mut dir_buf);
    if dir_item_insert(parent_ino, name, &dir_buf[..dir_len]) {
        return Ok(());
    }

    if !inode_ref_delete(child_ino, parent_ino) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[saltyfs] CRIT: dir_entry_insert rollback (inode_ref_delete) failed\n");
        });
        return Err(DirEntryTxnError::FailedDirty);
    }
    Err(DirEntryTxnError::FailedClean)
}

/// Remove a directory entry and its reverse INODE_REF as a single logical update.
/// Deletes INODE_REF first; if DIR_ITEM deletion fails, attempts to reinsert INODE_REF.
fn dir_entry_remove_with_ref(parent_ino: u64, child_ino: u64, name: &[u8]) -> DirEntryTxnResult {
    if !inode_ref_delete(child_ino, parent_ino) {
        return Err(DirEntryTxnError::FailedClean);
    }

    let dir_key = match find_dir_item_key(parent_ino, name.as_ptr(), name.len() as u8) {
        Some(k) => k,
        None => {
            if !inode_ref_insert(child_ino, parent_ino, name) {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[saltyfs] CRIT: dir_entry_remove rollback (reinsert missing ref) failed\n");
                });
                return Err(DirEntryTxnError::FailedDirty);
            }
            return Err(DirEntryTxnError::FailedClean);
        }
    };

    if btree_cow_delete(&dir_key) {
        return Ok(());
    }

    if !inode_ref_insert(child_ino, parent_ino, name) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[saltyfs] CRIT: dir_entry_remove rollback (inode_ref_insert) failed\n");
        });
        return Err(DirEntryTxnError::FailedDirty);
    }
    Err(DirEntryTxnError::FailedClean)
}

/// Look up a directory entry by name within a directory inode.
///
/// Uses direct hash-based B-tree lookup with linear probing for collisions,
/// matching the insertion strategy in `dir_item_insert`. Falls back to a
/// full scan for old-style entries (offset != name hash). When the parent
/// directory has `SALTY_INODE_CASEFOLD`, both the hash and the per-entry
/// comparison use Unicode 15.1 Simple Case-Folding.
pub(crate) fn lookup_in_dir(dir_ino: u64, name: *const u8, name_len: u8) -> Option<(u64, u8)> {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };

    // Build a slice for hashing & comparison.
    let name_slice = unsafe { core::slice::from_raw_parts(name, name_len as usize) };
    let casefold = dir_is_casefold(dir_ino);
    let base_hash = crate::name::dir_name_hash(name_slice, casefold);

    // Direct hash lookup with linear probing (matches dir_item_insert).
    let mut key = BTreeKey {
        object_id: dir_ino,
        item_type: TRONA_DIR_ITEM,
        offset: base_hash,
    };
    for _ in 0..16 {
        if let Some((data_ptr, _size)) = btree_find_item(root_tree, &key) {
            // SAFETY: data_ptr points to a valid DIR_ITEM within a mapped B-tree leaf.
            unsafe {
                let (child_ino, entry_name_len, dir_type) = parse_dir_item_header(data_ptr);
                let entry_slice = core::slice::from_raw_parts(
                    data_ptr.add(DIR_ITEM_HEADER_SIZE),
                    entry_name_len as usize,
                );
                if crate::name::dir_name_equal(entry_slice, name_slice, casefold) {
                    return Some((child_ino, dir_type));
                }
            }
        } else {
            break; // No entry at this offset — no more probing needed.
        }
        key.offset = key.offset.wrapping_add(1);
    }

    // Fallback: full scan for old-style entries where offset is the child
    // inode number rather than the name hash. This covers images created
    // before hash-based keying, and also handles directories that mix old
    // entries with new ones.
    let mut result: Option<(u64, u8)> = None;
    btree_find_all_for_ino(
        root_tree,
        dir_ino,
        TRONA_DIR_ITEM,
        |_key, data_ptr, _size| {
            unsafe {
                let (child_ino, entry_name_len, dir_type) = parse_dir_item_header(data_ptr);
                let entry_slice = core::slice::from_raw_parts(
                    data_ptr.add(DIR_ITEM_HEADER_SIZE),
                    entry_name_len as usize,
                );
                if crate::name::dir_name_equal(entry_slice, name_slice, casefold) {
                    result = Some((child_ino, dir_type));
                    return false;
                }
            }
            true
        },
    );

    result
}

/// Get inode info for a given inode number.
pub(crate) fn get_inode(ino: u64) -> Option<SaltyInodeItem> {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let key = BTreeKey {
        object_id: ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };

    match btree_find_item(root_tree, &key) {
        Some((data, size)) => {
            if size < core::mem::size_of::<SaltyInodeItem>() as u32 {
                return None;
            }
            Some(unsafe { read_inode_item(data) })
        }
        None => None,
    }
}

/// Read file data into memory at `dest_base`.
/// Returns bytes actually read. Uses cross-leaf B-tree iteration to support
/// multi-block files with extents spanning multiple leaves.
pub(crate) fn read_file_data(ino: u64, file_offset: u64, count: u64, dest_base: u64) -> u64 {
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

    btree_find_all_for_ino(
        root_tree,
        ino,
        TRONA_EXTENT_DATA,
        |key, data_ptr, _item_size| {
            if bytes_read >= actual_count {
                return false;
            }

            let extent = unsafe { read_extent_data(data_ptr) };
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
        },
    );

    bytes_read
}

/// Fixed 96-byte per-entry record layout written into VFS SHM by `handle_readdir`.
///
/// Callers are expected to cast consecutive 96-byte spans into this struct.
/// `name` is NUL-padded up to 44 bytes; `name_len` gives the actual length.
pub(crate) const READDIR_ENTRY_BYTES: u64 = 96;
pub(crate) const READDIR_NAME_MAX: usize = 44;

/// Stream directory entries into VFS SHM as fixed-size records. Replaces the
/// old 3-entries-per-IPC inline scheme so that the reply also carries
/// stat-merged metadata (mode, size, blocks, mtime, uid, gid, nlink) without
/// forcing the caller to issue a follow-up STAT for every entry.
///
/// The caller pre-allocates `buf_bytes` in VFS SHM at `shm_offset`. Each
/// written entry is `READDIR_ENTRY_BYTES` bytes. Entries whose names exceed
/// `READDIR_NAME_MAX` are truncated at the record boundary; the IPC name
/// limits elsewhere already prevent DIR_ITEMs longer than 44 bytes from being
/// created from userland, so truncation is defensive.
fn readdir_stream_shm(
    dir_ino: u64,
    cursor: u64,
    shm_vaddr: u64,
    shm_offset: u64,
    buf_bytes: u64,
    reply: &mut TronaMsg,
) {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };

    let max_entries = (buf_bytes / READDIR_ENTRY_BYTES) as usize;
    if max_entries == 0 {
        reply.label = TRONA_OK;
        reply.length = 4;
        reply.regs[0] = cursor; // no progress
        reply.regs[1] = 0;
        reply.regs[2] = 0;
        reply.regs[3] = 0;
        return;
    }

    let base_ptr = (shm_vaddr + shm_offset) as *mut u8;

    let mut entry_idx = 0u64;
    let mut written = 0usize;
    let mut has_more = false;

    btree_find_all_for_ino(
        root_tree,
        dir_ino,
        TRONA_DIR_ITEM,
        |_key, data_ptr, _size| {
            if entry_idx < cursor {
                entry_idx += 1;
                return true;
            }

            if written >= max_entries {
                has_more = true;
                return false;
            }

            unsafe {
                let (child_ino, entry_name_len, entry_dir_type) = parse_dir_item_header(data_ptr);

                // Fetch child inode for stat metadata. Missing inode = stale dir
                // entry; skip it but keep scanning.
                let inode = match get_inode(child_ino) {
                    Some(i) => i,
                    None => {
                        entry_idx += 1;
                        return true;
                    }
                };

                let name_ptr = data_ptr.add(DIR_ITEM_HEADER_SIZE);
                let nlen_full = entry_name_len as usize;
                let nlen = nlen_full.min(READDIR_NAME_MAX);

                let rec = base_ptr.add(written * (READDIR_ENTRY_BYTES as usize));

                // +0..8   ino
                // +8..16  size
                // +16..24 blocks
                // +24..32 mtime
                // +32..36 mode
                // +36..40 uid
                // +40..44 gid
                // +44..48 nlink
                // +48     dir_type
                // +49     name_len (clamped)
                // +50..52 pad
                // +52..96 name (NUL-padded 44 bytes)
                core::ptr::write_unaligned(rec.add(0) as *mut u64, child_ino);
                core::ptr::write_unaligned(rec.add(8) as *mut u64, inode.size);
                core::ptr::write_unaligned(rec.add(16) as *mut u64, inode.blocks);
                core::ptr::write_unaligned(rec.add(24) as *mut u64, inode.mtime);
                core::ptr::write_unaligned(rec.add(32) as *mut u32, inode.mode);
                core::ptr::write_unaligned(rec.add(36) as *mut u32, inode.uid);
                core::ptr::write_unaligned(rec.add(40) as *mut u32, inode.gid);
                core::ptr::write_unaligned(rec.add(44) as *mut u32, inode.nlink);
                *rec.add(48) = entry_dir_type;
                *rec.add(49) = nlen as u8;
                *rec.add(50) = 0;
                *rec.add(51) = 0;
                for j in 0..READDIR_NAME_MAX {
                    if j < nlen {
                        *rec.add(52 + j) = *name_ptr.add(j);
                    } else {
                        *rec.add(52 + j) = 0;
                    }
                }
            }

            written += 1;
            entry_idx += 1;
            true
        },
    );

    reply.label = TRONA_OK;
    reply.length = 4;
    reply.regs[0] = entry_idx;
    reply.regs[1] = written as u64;
    reply.regs[2] = (written as u64) * READDIR_ENTRY_BYTES;
    reply.regs[3] = if has_more { 0 } else { BACKEND_READDIR_F_EOF };
}

/// Serialize a SaltyInodeItem to bytes.
fn inode_to_bytes(inode: &SaltyInodeItem) -> [u8; 128] {
    let mut buf = [0u8; 128];
    unsafe {
        core::ptr::write_unaligned(buf.as_mut_ptr() as *mut SaltyInodeItem, *inode);
    }
    buf
}

/// Build inode bytes for a new file or directory.
///
/// `uid`/`gid` carry the owning credentials (0/0 when the caller has no
/// identity context yet — see the IPC shim in create/mkdir/symlink handlers).
/// `flags` carries inheritable directory flags such as `SALTY_INODE_CASEFOLD`.
fn build_inode_bytes(
    size: u64,
    blocks: u64,
    nlink: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    flags: u32,
) -> [u8; 128] {
    let ngen = unsafe { (*(&raw const SB)).generation + 1 };
    let inode = SaltyInodeItem {
        generation: ngen,
        size,
        blocks,
        block_group: 0,
        nlink,
        uid,
        gid,
        mode,
        atime: 0,
        mtime: 0,
        ctime: 0,
        crtime: 0,
        flags,
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
    let ngen = unsafe { (*(&raw const SB)).generation + 1 };
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
fn build_extent_regular(
    out: &mut [u8; 304],
    size: u64,
    disk_bytenr: u64,
    disk_num_bytes: u64,
    offset: u64,
    num_bytes: u64,
) {
    let ngen = unsafe { (*(&raw const SB)).generation + 1 };
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
/// Processes in batches of 128 to handle files with arbitrarily many extents.
fn delete_all_extents(ino: u64) {
    let bs = unsafe { *(&raw const BLOCK_SIZE) };

    loop {
        // Re-read root_tree each iteration since COW mutations update it
        let root_tree = unsafe { (*(&raw const SB)).root_tree };

        // Collect up to 128 extents (can't delete while iterating)
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
            break;
        }

        for i in 0..count {
            if types[i] == EXTENT_REGULAR && disk_addrs[i] != 0 {
                let block_start = disk_addrs[i] / bs;
                let block_count = (disk_sizes[i] + bs - 1) / bs;
                for b in 0..block_count {
                    free_block(block_start + b);
                }
            }
            let ext_key = BTreeKey {
                object_id: ino,
                item_type: TRONA_EXTENT_DATA,
                offset: offsets[i],
            };
            if !btree_cow_delete(&ext_key) {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[saltyfs] WARN: extent delete failed during cleanup\n");
                });
            }
        }
    }
}

/// Update the mtime of an inode (COW).
fn update_inode_mtime(ino: u64) -> bool {
    if let Some(mut inode) = get_inode(ino) {
        // We don't have a reliable clock, so just increment generation
        inode.mtime = unsafe { (*(&raw const SB)).generation + 1 };
        let inode_key = BTreeKey {
            object_id: ino,
            item_type: TRONA_INODE_ITEM,
            offset: 0,
        };
        return btree_cow_update(&inode_key, &inode_to_bytes(&inode));
    }
    true
}

/// Handle `BACKEND_OPEN_SESSION`.
///
/// Request:
///   - `regs[0]` = mount_flags (bit 0 = `SALTYFS_MOUNT_RO`).
///   - `regs[1]` = vfs-chosen `session_id` — stored on the daemon's
///     session record and echoed on every correlated completion's
///     header so vfs's `dispatch_backend` session-id check matches.
///   - `caps[0]` (out-of-band) = vfs's `callback_send` cap — captured
///     by the dispatcher arm in `main.rs` before this handler runs
///     and stashed on `BACKEND_CALLBACK_EP`.
///
/// Reply (success):
///   - `label` = `VFS_BACKEND_REPLY_OK` (or `TRONA_ALREADY_EXISTS`
///     when the auto-mounted session is being rebound to a fresh
///     vfs).
///   - `regs[0]` = `max_inflight` — vfs caps further at its
///     `BACKEND_INFLIGHT_CEILING`.
///   - `regs[1]` = `feature_bits`.
///   - `regs[2]` = backend-private session token (0 on this saltyfs
///     daemon — the value is opaque to vfs, useful for daemons that
///     keep multiple session-private dispatch tables).
///   - `regs[3]` = root inode number.
///   - `regs[4]` = root inode incarnation sequence.
///   - `regs[5]` = SHM region size hint advertised in
///     `BACKEND_FEATURE_SHM_TRANSFER`. vfs allocates the SHM via
///     mmsrv at this size and forwards the id in the follow-up
///     `BACKEND_SHM_SETUP`.
pub(crate) fn handle_mount(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    let feature_bits = BACKEND_FEATURE_ASYNC_V1
        | BACKEND_FEATURE_INCARNATION_SEQ
        | BACKEND_FEATURE_INLINE_TRANSFER
        | BACKEND_FEATURE_SHM_TRANSFER;

    let vfs_session_id = if msg.length >= 2 {
        msg.regs[1] as u32
    } else {
        0
    };
    let mount_flags = if msg.length >= 1 { msg.regs[0] } else { 0 };
    let force_ro = (mount_flags & SALTYFS_MOUNT_RO) != 0;

    // Disk image mount is daemon-singleton (one disk per saltyfs
    // process). First OPEN_SESSION mounts; subsequent OPEN_SESSIONs
    // attach additional vfs sessions to the same disk image without
    // re-reading the superblock.
    if !unsafe { *(&raw const MOUNTED) } {
        if !read_superblock() {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
        if force_ro {
            unsafe {
                *(&raw mut READONLY) = true;
            }
            trona_runtime::uinfo!(|_lb| {
                _lb.str(b"[saltyfs] explicit read-only mount\n");
            });
        }
        unsafe {
            *(&raw mut MOUNTED) = true;
        }
    }

    // Resolve the wire-side session id. Prefer the vfs-supplied
    // value so the daemon's correlated replies match vfs's
    // session-attach handshake; fall back to a daemon-synthesised
    // monotone counter for legacy callers that omit the field.
    let session_id = if vfs_session_id != 0 {
        vfs_session_id
    } else {
        unsafe {
            let current = *(&raw const NEXT_SESSION_ID);
            let next = current.wrapping_add(1);
            *(&raw mut NEXT_SESSION_ID) = if next == 0 { 1 } else { next };
            current
        }
    };

    // Place the session in `SESSION_TABLE`. A vfs restart that
    // reuses the same `session_id` rebinds onto the existing Live
    // slot — preserving the SHM mapping and callback cap state
    // across the swap. Fresh sessions (different `session_id`, or
    // a vfs that did not supply one) get a new Empty slot.
    let slot_idx = if vfs_session_id != 0 {
        match session::find_live_by_id(vfs_session_id) {
            Some(idx) => idx,
            None => match session::alloc_slot() {
                Some(idx) => idx,
                None => {
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return reply;
                }
            },
        }
    } else if let Some(idx) = session::alloc_slot() {
        idx
    } else {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    };
    unsafe {
        if let Some(slot) = session::slot_mut(slot_idx) {
            slot.state = SessionState::Live;
            slot.session_id = session_id;
            slot.max_inflight = SALTYFS_MAX_INFLIGHT as u32;
        }
    }
    unsafe { *(&raw mut CURRENT_SESSION_ID) = session_id };

    let root_ino = unsafe { (*(&raw const SB)).root_inode };
    let root_seq = get_inode(root_ino).map(|inode| inode.sequence).unwrap_or(0);
    reply.label = TRONA_OK;
    reply.regs[0] = SALTYFS_MAX_INFLIGHT as u64;
    reply.regs[1] = feature_bits;
    reply.regs[2] = 0;
    reply.regs[3] = root_ino;
    reply.regs[4] = root_seq as u64;
    reply.regs[5] = SALTYFS_SHM_REGION_BYTES;
    reply.length = 6;
    reply
}

/// Handle BACKEND_CLOSE_SESSION.
///
/// Request:
///   regs[0] = session_id (VFS-side acknowledgement; informational
///             only, the backend trusts its own `CURRENT_SESSION_ID`).
///
/// Validates that a session is live and returns the wire reply. The
/// actual teardown runs after the owner drained every outstanding worker
/// job; otherwise a deferred read/mount could observe `MOUNTED=false` or
/// `CURRENT_SESSION_ID=0` midway through completion emission.
pub(crate) fn handle_close_session(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        // Double-close is benign; surface a distinct label so the
        // VFS log captures the sequence for debugging.
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    // Step 1 of the 4-step teardown: resolve the requesting session
    // and mark its slot Closing, bumping `live_gen` by 2 so any
    // worker job that captured the pre-close generation detects the
    // divergence at run-time and suppresses its completion (no
    // side-effects, no stale reply on the cap that is about to be
    // released).
    let slot_idx = session::slot_idx_for_msg(msg).or_else(|| {
        // `regs[0]` carries the session_id ack on legacy callers
        // that did not stamp a correlation header.
        let id = msg.regs[0] as u32;
        if id != 0 {
            session::find_live_by_id(id)
        } else {
            None
        }
    });
    if let Some(idx) = slot_idx {
        unsafe {
            if let Some(slot) = session::slot_mut(idx) {
                slot.state = SessionState::Closing;
                slot.live_gen = slot.live_gen.wrapping_add(2);
            }
        }
    }

    reply.label = TRONA_OK;
    reply.length = 0;
    reply
}

/// Final teardown for `BACKEND_CLOSE_SESSION`. Caller must already have
/// waited for every worker job to finish and must hold `BLOCK_LOCK`.
///
/// Returns 0 on success, -1 if either the cache or superblock flush
/// failed. Session state is dropped even on flush failure so the next
/// mount can start from a clean in-memory session slot.
pub(crate) fn finalize_close_session() -> i32 {
    let cache_ok = cache_flush_all();
    let sb_ok = flush_superblock_if_dirty();

    // Step 4 of the 4-step teardown: drop the slot. Drain (step 3)
    // already completed at the caller, so no in-flight worker job
    // observes the slot transition past Closing -> Empty. The
    // callback cap was set up in `BACKEND_OPEN_SESSION`'s capture
    // path; releasing it here cleans up the daemon's outbound side.
    if let Some(idx) = session::current_live().or_else(|| {
        // capacity-1: locate Closing slot directly.
        for i in 0..session::SALTYFS_SESSION_SLOTS {
            if let Some(s) = session::slot(i) {
                if s.state == SessionState::Closing {
                    return Some(i);
                }
            }
        }
        None
    }) {
        unsafe {
            if let Some(slot) = session::slot_mut(idx) {
                // Assigning empty() drops the old SessionSlot in place,
                // which fires OwnedCap::drop on callback_ep (cnode_delete
                // + slot_free). No manual deletion needed.
                *slot = crate::session::SessionSlot::empty();
            }
        }
    }

    unsafe {
        *(&raw mut MOUNTED) = false;
        *(&raw mut CURRENT_SESSION_ID) = 0;
    }
    if cache_ok && sb_ok { 0 } else { -1 }
}

/// Handle BACKEND_LOOKUP with stat-merged reply.
///
/// Request:
///   regs[0] = parent_ino
///   regs[1] = name_len (≤ 144)
///   regs[2..20] = name bytes (144 bytes)
///
/// When `CORRELATION_F_LOOKUP_PARENT` is set in the correlation header,
/// the request is a parent-lookup shortcut: regs[0] is the **child** inode
/// and the handler resolves the parent via `INODE_REF`, returning the
/// parent's stat-merged reply in the standard lookup format. The VFS
/// dotdot walk uses this so the completion shares `apply_lookup_reply`.
///
/// Reply (success, length = 10):
///   regs[0] = child_ino (or parent_ino when LOOKUP_PARENT)
///   regs[1] = child_seq
///   regs[2] = mode
///   regs[3] = size
///   regs[4] = nlink
///   regs[5] = mtime
///   regs[6] = uid
///   regs[7] = gid
///   regs[8] = dir_type
///   regs[9] = blocks
///
/// Merging stat into lookup eliminates a round-trip for every path resolution
/// and keeps uid/gid inline for the future multi-user aware VFS.
pub(crate) fn handle_lookup(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();

    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    // Check for the parent-lookup flag in the correlation header.
    let lookup_parent = {
        let words = [
            msg.regs[CORRELATION_HEADER_REG_START],
            msg.regs[CORRELATION_HEADER_REG_START + 1],
            msg.regs[CORRELATION_HEADER_REG_START + 2],
            msg.regs[CORRELATION_HEADER_REG_START + 3],
        ];
        let header = CorrelationHeader::decode_words(words);
        header.token != 0
            && header.class == CORRELATION_CLASS_FS
            && (header.flags & CORRELATION_F_LOOKUP_PARENT) != 0
    };

    if lookup_parent {
        // Parent-lookup shortcut: regs[0] is child_ino, resolve parent
        // via INODE_REF and return the parent's stat-merged lookup reply.
        let child_ino = msg.regs[0];
        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        let mut parent_ino: u64 = 0;
        let mut found = false;
        btree_find_all_for_ino(root_tree, child_ino, TRONA_INODE_REF, |key, _, _| {
            parent_ino = key.offset;
            found = true;
            false
        });
        if !found || parent_ino == 0 {
            // Root or orphan — return the child itself as its own parent.
            parent_ino = child_ino;
        }
        let inode = match get_inode(parent_ino) {
            Some(i) => i,
            None => {
                reply.label = TRONA_NOT_FOUND;
                return reply;
            }
        };
        reply.label = TRONA_OK;
        reply.length = 10;
        reply.regs[0] = parent_ino;
        reply.regs[1] = inode.sequence as u64;
        reply.regs[2] = inode.mode as u64;
        reply.regs[3] = inode.size;
        reply.regs[4] = inode.nlink as u64;
        reply.regs[5] = inode.mtime;
        reply.regs[6] = inode.uid as u64;
        reply.regs[7] = inode.gid as u64;
        reply.regs[8] = 4u64; // DT_DIR — parent is always a directory
        reply.regs[9] = inode.blocks;
        return reply;
    }

    let parent_ino = msg.regs[0];
    let name_len = msg.regs[1] as u8;
    if name_len == 0 || name_len > 144 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 144];
    let name_data = &msg.regs[2] as *const u64 as *const u8;
    unsafe {
        for i in 0..name_len as usize {
            name_buf[i] = *name_data.add(i);
        }
    }

    let (child_ino, dir_type) = match lookup_in_dir(parent_ino, name_buf.as_ptr(), name_len) {
        Some(x) => x,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    // Fetch the child inode so the reply carries stat metadata inline.
    // If the inode is missing (stale dir entry), report NOT_FOUND rather than
    // a half-populated entry.
    let inode = match get_inode(child_ino) {
        Some(i) => i,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    reply.label = TRONA_OK;
    reply.length = 10;
    reply.regs[0] = child_ino;
    reply.regs[1] = inode.sequence as u64;
    reply.regs[2] = inode.mode as u64;
    reply.regs[3] = inode.size;
    reply.regs[4] = inode.nlink as u64;
    reply.regs[5] = inode.mtime;
    reply.regs[6] = inode.uid as u64;
    reply.regs[7] = inode.gid as u64;
    reply.regs[8] = dir_type as u64;
    reply.regs[9] = inode.blocks;
    reply
}

/// Handle [`VFS_BACKEND_FSYNC`]: drain every in-flight writeback the
/// worker holds, then return the worst observed status.
///
/// Request:
///   regs[0]      = ino (informational; saltyfs flushes the whole
///                  block cache rather than per-inode today)
///   regs[1]      = flags (reserved)
///
/// Reply:
///   label        = `TRONA_OK` if every queued writeback completed
///                  without error, otherwise the first non-zero
///                  status observed by `worker::drain_pending`.
///
/// Ordering: vfs places `PRED_BARRIER` predecessor edges on every
/// in-flight `BACKEND_WRITE` / mutation against the same vnode before
/// dispatching `BACKEND_FSYNC`, so by the time the daemon's owner
/// thread reaches this handler every dirty record already sits in
/// the worker's submit ring.
pub(crate) fn handle_fsync(_msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    let worst = unsafe { crate::worker::drain_pending() };
    reply.length = 0;
    reply.label = if worst != 0 { worst as u64 } else { TRONA_OK };
    reply
}

/// Handle [`BACKEND_READ`]: read via inline payload or SHM.
///
/// Request:
///   regs[0]      = ino
///   regs[1]      = file_offset
///   regs[2..=4]  = TransferDescriptor (kind, flags, offset, length)
///
/// Reply:
///   regs[0]      = bytes_read
///   regs[1..]    = payload bytes (INLINE only, up to `INLINE_TRANSFER_WIRE_MAX`)
pub(crate) fn handle_read(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();

    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];
    let file_offset = msg.regs[1];
    let transfer = TransferDescriptor::decode_regs([
        msg.regs[BACKEND_RW_REQ_DESCRIPTOR_REG],
        msg.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 1],
        msg.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 2],
        msg.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 3],
    ]);

    match transfer.kind {
        TRANSFER_KIND_INLINE => {
            if transfer.length > INLINE_TRANSFER_WIRE_MAX {
                reply.label = TRONA_INVALID_ARGUMENT;
                return reply;
            }
            // Use blkdrv SHM offset 0 as scratch, then copy into reply regs.
            let bytes_read = read_file_data(ino, file_offset, transfer.length, SHM_VADDR);
            reply.label = TRONA_OK;
            reply.length = 1 + (bytes_read + 7) / 8;
            reply.regs[0] = bytes_read;
            if bytes_read > 0 {
                unsafe {
                    let src = SHM_VADDR as *const u8;
                    let dst = &raw mut reply.regs[BACKEND_READ_INLINE_PAYLOAD_REG] as *mut u8;
                    for i in 0..bytes_read as usize {
                        *dst.add(i) = *src.add(i);
                    }
                }
            }
            reply
        }
        TRANSFER_KIND_SHM => {
            // Validate SHM bounds against the message's session-
            // resolved per-session region. Sessions that have not
            // yet completed `BACKEND_SHM_SETUP` fall back to the
            // blkdrv scratch window so the client can still satisfy
            // small reads while SHM negotiation is pending.
            let (dest_base_addr, shm_size) = match session::live_shm_region_for_msg(msg) {
                Some((vaddr, bytes)) => (vaddr, bytes),
                None => (SHM_VADDR, SHM_SIZE),
            };
            if transfer.offset >= shm_size || transfer.length > shm_size - transfer.offset {
                reply.label = TRONA_INVALID_ARGUMENT;
                return reply;
            }
            let dest_base = dest_base_addr + transfer.offset;
            let bytes_read = read_file_data(ino, file_offset, transfer.length, dest_base);
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = bytes_read;
            reply
        }
        _ => {
            reply.label = TRONA_INVALID_ARGUMENT;
            reply
        }
    }
}

/// Handle BACKEND_READDIR.
///
/// Request:
///   regs[0] = dir_ino
///   regs[1] = cursor (opaque; 0 to start)
///   regs[2] = shm_offset (into VFS SHM)
///   regs[3] = buf_bytes  (maximum bytes to write in VFS SHM)
///
/// Reply:
///   regs[0] = next_cursor (opaque; 0 may be a valid cursor)
///   regs[1] = entries_written
///   regs[2] = bytes_written
///   regs[3] = flags (`BACKEND_READDIR_F_EOF` when no more entries remain)
///
/// Each entry is `READDIR_ENTRY_BYTES` (96) bytes of fixed layout containing
/// stat-merged metadata plus the (possibly truncated) name. See
/// `readdir_stream_shm` for the exact record layout.
pub(crate) fn handle_readdir(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();

    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    let Some((shm_vaddr, shm_size)) = session::live_shm_region_for_msg(msg) else {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    };

    let dir_ino = msg.regs[0];
    let cursor = msg.regs[1];
    let shm_offset = msg.regs[2];
    let buf_bytes = msg.regs[3];

    // Bound check: the request must fit entirely inside the
    // requesting session's SHM region.
    if shm_offset >= shm_size || buf_bytes > shm_size.saturating_sub(shm_offset) {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    readdir_stream_shm(
        dir_ino, cursor, shm_vaddr, shm_offset, buf_bytes, &mut reply,
    );
    reply
}

pub(crate) fn handle_stat(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();

    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];

    match get_inode(ino) {
        Some(inode) => {
            reply.label = 0;
            reply.length = 9;
            reply.regs[0] = ino;
            reply.regs[1] = inode.size;
            reply.regs[2] = inode.mode as u64;
            reply.regs[3] = inode.nlink as u64;
            reply.regs[4] = inode.mtime;
            reply.regs[5] = inode.blocks;
            reply.regs[6] = inode.uid as u64;
            reply.regs[7] = inode.gid as u64;
            reply.regs[8] = inode.sequence as u64;
        }
        None => {
            reply.label = TRONA_NOT_FOUND;
        }
    }
    reply
}

pub(crate) fn handle_getinfo() -> TronaMsg {
    let mut reply = TronaMsg::zeroed();

    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
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

/// Handle BACKEND_CREATE: create a new regular file.
///
/// Accepts both V1 (legacy) and V2 (multi-user) layouts; see `SALTYFS_PROTO_V2`
/// in consts.rs. V2 carries uid/gid and uses a 120-byte name slot, V1 uses the
/// historical 136-byte layout with uid/gid implicitly zero.
pub(crate) fn handle_create(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let raw_parent = msg.regs[0];
    let is_v2 = (raw_parent & SALTYFS_PROTO_V2) != 0;
    let parent_ino = raw_parent & !SALTYFS_PROTO_V2;
    let mode = msg.regs[1] as u32;

    let (uid, gid, name_len, name_off, name_cap) = if is_v2 {
        (
            msg.regs[2] as u32,
            msg.regs[3] as u32,
            msg.regs[4] as u8,
            5usize,
            120usize,
        )
    } else {
        (0u32, 0u32, msg.regs[2] as u8, 3usize, 136usize)
    };

    if name_len == 0 || (name_len as usize) > name_cap {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 136];
    let name_data = &msg.regs[name_off] as *const u64 as *const u8;
    unsafe {
        for i in 0..name_len as usize {
            name_buf[i] = *name_data.add(i);
        }
    }

    // Inherit parent directory flags (CASEFOLD) so that subordinate lookups
    // within a case-insensitive directory tree stay coherent.
    let inherit_flags = match get_inode(parent_ino) {
        Some(p) => p.flags & SALTY_INODE_CASEFOLD,
        None => 0,
    };

    // Casefold directories must only accept valid UTF-8 names so that the
    // table-driven fold function has a well-defined hash/compare key.
    if (inherit_flags & SALTY_INODE_CASEFOLD) != 0
        && !crate::name::is_valid_utf8(&name_buf[..name_len as usize])
    {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    // Check if already exists
    if lookup_in_dir(parent_ino, name_buf.as_ptr(), name_len).is_some() {
        reply.label = TRONA_ALREADY_EXISTS;
        return reply;
    }

    let new_ino = crate::block::allocate_next_inode();

    // Insert INODE_ITEM
    let inode_data = build_inode_bytes(0, 0, 1, mode | 0o100000, uid, gid, inherit_flags); // S_IFREG
    let inode_key = BTreeKey {
        object_id: new_ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_insert(&inode_key, &inode_data) {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    match dir_entry_insert_with_ref(parent_ino, new_ino, &name_buf[..name_len as usize], 1) {
        Ok(()) => {}
        Err(DirEntryTxnError::FailedClean) => {
            if !btree_cow_delete(&inode_key) {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[saltyfs] WARN: create rollback inode delete failed\n");
                });
            }
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
        Err(DirEntryTxnError::FailedDirty) => {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
    }

    update_inode_mtime(parent_ino);

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[saltyfs] CREATE ino=");
        _lb.dec(new_ino);
        _lb.str(b" parent=");
        _lb.dec(parent_ino);
        _lb.putc(b'\n');
    });

    let _ = pack_lookup_snapshot_reply(&mut reply, new_ino, 1);
    reply
}

/// Write data using per-block regular extents. Handles inline→regular promotion
/// and writing across multiple 4KB block boundaries. `data_src` points at the
/// first byte of the write payload; caller must guarantee at least `count`
/// bytes are readable.
unsafe fn write_regular_extents(
    ino: u64,
    offset: u64,
    count: u64,
    data_src: *const u8,
    inode: &SaltyInodeItem,
    new_size: u64,
    bs: u64,
    reply: &mut TronaMsg,
) -> TronaMsg {
    let ext_hdr_size = core::mem::size_of::<ExtentData>();

    // Check for inline→regular promotion: if there's an inline extent at offset 0,
    // convert it to a regular extent first.
    let inline_key = BTreeKey {
        object_id: ino,
        item_type: TRONA_EXTENT_DATA,
        offset: 0,
    };
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    if let Some((ext_ptr, ext_size)) = btree_find_item(root_tree, &inline_key) {
        let ext = unsafe { read_extent_data(ext_ptr) };
        if ext.extent_type == EXTENT_INLINE {
            let inline_len = (ext_size as usize).saturating_sub(ext_hdr_size);
            let promo_block = match alloc_block() {
                Some(b) => b,
                None => {
                    reply.label = TRONA_OUT_OF_MEMORY;
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
                reply.label = TRONA_OUT_OF_MEMORY;
                return *reply;
            }
            // Delete inline extent, insert regular at offset 0
            if !btree_cow_delete(&inline_key) {
                free_block(promo_block);
                reply.label = TRONA_OUT_OF_MEMORY;
                return *reply;
            }
            let mut ext_buf = [0u8; 304];
            build_extent_regular(&mut ext_buf, bs, promo_block * bs, bs, 0, bs);
            if !btree_cow_insert(&inline_key, &ext_buf[..ext_hdr_size]) {
                free_block(promo_block);
                reply.label = TRONA_OUT_OF_MEMORY;
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
            item_type: TRONA_EXTENT_DATA,
            offset: block_off,
        };

        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        let existing = btree_find_item(root_tree, &extent_key);

        let mut block_buf = [0u8; 4096];
        let mut old_data_block: u64 = 0;
        let mut had_extent = false;

        if let Some((ext_ptr, _)) = existing {
            had_extent = true;
            let ext = unsafe { read_extent_data(ext_ptr) };
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
        let write_start = if offset > block_off {
            (offset - block_off) as usize
        } else {
            0
        };
        let write_end_in_block = if write_end < block_off + bs {
            (write_end - block_off) as usize
        } else {
            bs as usize
        };
        let data_start = if block_off > offset {
            (block_off - offset) as usize
        } else {
            0
        };

        for i in write_start..write_end_in_block {
            let buf_idx = data_start + i - write_start;
            if buf_idx < count as usize {
                block_buf[i] = unsafe { *data_src.add(buf_idx) };
            }
        }

        let data_block = match alloc_block() {
            Some(b) => b,
            None => {
                reply.label = TRONA_OUT_OF_MEMORY;
                return *reply;
            }
        };
        if !write_block(data_block, block_buf.as_ptr()) {
            free_block(data_block);
            reply.label = TRONA_OUT_OF_MEMORY;
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
            reply.label = TRONA_OUT_OF_MEMORY;
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
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated_inode)) {
        reply.label = TRONA_OUT_OF_MEMORY;
        return *reply;
    }

    reply.label = TRONA_OK;
    reply.length = 1;
    reply.regs[0] = count;
    *reply
}

/// Handle BACKEND_MKDIR: create a new directory.
///
/// Accepts V1/V2 layouts — see `SALTYFS_PROTO_V2`. Inherits `SALTY_INODE_CASEFOLD`
/// from the parent directory so casefold coherence is preserved across subtrees.
pub(crate) fn handle_mkdir_fs(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let raw_parent = msg.regs[0];
    let is_v2 = (raw_parent & SALTYFS_PROTO_V2) != 0;
    let parent_ino = raw_parent & !SALTYFS_PROTO_V2;
    let mode = msg.regs[1] as u32;

    let (uid, gid, name_len, name_off, name_cap) = if is_v2 {
        (
            msg.regs[2] as u32,
            msg.regs[3] as u32,
            msg.regs[4] as u8,
            5usize,
            120usize,
        )
    } else {
        (0u32, 0u32, msg.regs[2] as u8, 3usize, 136usize)
    };

    if name_len == 0 || (name_len as usize) > name_cap {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    let mut name_buf = [0u8; 136];
    let name_data = &msg.regs[name_off] as *const u64 as *const u8;
    unsafe {
        for i in 0..name_len as usize {
            name_buf[i] = *name_data.add(i);
        }
    }

    // Inherit parent CASEFOLD flag into the new directory.
    let inherit_flags = match get_inode(parent_ino) {
        Some(p) => p.flags & SALTY_INODE_CASEFOLD,
        None => 0,
    };

    // Casefold parent: reject invalid UTF-8.
    if (inherit_flags & SALTY_INODE_CASEFOLD) != 0
        && !crate::name::is_valid_utf8(&name_buf[..name_len as usize])
    {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    if lookup_in_dir(parent_ino, name_buf.as_ptr(), name_len).is_some() {
        reply.label = TRONA_ALREADY_EXISTS;
        return reply;
    }

    let new_ino = crate::block::allocate_next_inode();

    // Insert INODE_ITEM for directory (nlink=2, S_IFDIR)
    let inode_data = build_inode_bytes(0, 0, 2, mode | 0o040000, uid, gid, inherit_flags);
    let inode_key = BTreeKey {
        object_id: new_ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_insert(&inode_key, &inode_data) {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    match dir_entry_insert_with_ref(parent_ino, new_ino, &name_buf[..name_len as usize], 4) {
        Ok(()) => {}
        Err(DirEntryTxnError::FailedClean) => {
            if !btree_cow_delete(&inode_key) {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[saltyfs] WARN: mkdir rollback inode delete failed\n");
                });
            }
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
        Err(DirEntryTxnError::FailedDirty) => {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
    }

    update_inode_mtime(parent_ino);

    let _ = pack_lookup_snapshot_reply(&mut reply, new_ino, 4);
    reply
}

/// Handle BACKEND_UNLINK: remove a file.
pub(crate) fn handle_unlink_fs(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let parent_ino = msg.regs[0];
    let name_len = msg.regs[1] as u8;
    if name_len == 0 || name_len > 144 {
        reply.label = TRONA_INVALID_ARGUMENT;
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
        Some((ino, _)) => ino,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    let inode = match get_inode(child_ino) {
        Some(i) => i,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    // Don't unlink directories (use rmdir)
    if (inode.mode & 0o170000) == 0o040000 {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    match dir_entry_remove_with_ref(parent_ino, child_ino, &name_buf[..name_len as usize]) {
        Ok(()) => {}
        Err(DirEntryTxnError::FailedClean) | Err(DirEntryTxnError::FailedDirty) => {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
    }

    let new_nlink = inode.nlink.saturating_sub(1);
    if new_nlink == 0 {
        // Drop all xattrs (including hidden-inode backed indirect entries)
        // before tearing down the file's own extents and INODE_ITEM.
        crate::xattr::delete_all_xattrs(child_ino);

        // Delete all extent data items (multi-block aware)
        delete_all_extents(child_ino);
        bitmap_flush();

        // Delete INODE_ITEM
        let inode_key = BTreeKey {
            object_id: child_ino,
            item_type: TRONA_INODE_ITEM,
            offset: 0,
        };
        if !btree_cow_delete(&inode_key) {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
    } else {
        // Update nlink
        let mut updated = inode;
        updated.nlink = new_nlink;
        let inode_key = BTreeKey {
            object_id: child_ino,
            item_type: TRONA_INODE_ITEM,
            offset: 0,
        };
        if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
    }

    update_inode_mtime(parent_ino);

    reply.label = TRONA_OK;
    reply
}

/// Handle BACKEND_RMDIR: remove an empty directory.
pub(crate) fn handle_rmdir_fs(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let parent_ino = msg.regs[0];
    let name_len = msg.regs[1] as u8;
    if name_len == 0 || name_len > 144 {
        reply.label = TRONA_INVALID_ARGUMENT;
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
        Some((ino, _)) => ino,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    let inode = match get_inode(child_ino) {
        Some(i) => i,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    // Must be a directory
    if (inode.mode & 0o170000) != 0o040000 {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    // Check if directory is empty (cross-leaf iteration)
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let mut has_entries = false;
    btree_find_all_for_ino(root_tree, child_ino, TRONA_DIR_ITEM, |_, _, _| {
        has_entries = true;
        false // stop on first entry found
    });
    if has_entries {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    match dir_entry_remove_with_ref(parent_ino, child_ino, &name_buf[..name_len as usize]) {
        Ok(()) => {}
        Err(DirEntryTxnError::FailedClean) | Err(DirEntryTxnError::FailedDirty) => {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
    }

    // Delete INODE_ITEM
    let inode_key = BTreeKey {
        object_id: child_ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_delete(&inode_key) {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    update_inode_mtime(parent_ino);

    reply.label = TRONA_OK;
    reply
}

/// Handle BACKEND_RENAME: move/rename a file or directory.
pub(crate) fn handle_rename_fs(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let old_parent = msg.regs[0];
    let old_name_len = msg.regs[1] as u8;
    let new_parent = msg.regs[2];
    let new_name_len = msg.regs[3] as u8;
    if old_name_len == 0 || old_name_len > 64 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }
    if new_name_len == 0 || new_name_len > 64 {
        reply.label = TRONA_INVALID_ARGUMENT;
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
        Some((ino, _)) => ino,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    // If new name already exists, unlink it first (Bug #5: full cleanup)
    if let Some((existing_ino, _)) = lookup_in_dir(new_parent, new_name.as_ptr(), new_name_len) {
        // No-op rename: old and new point to the same entry
        if existing_ino == child_ino {
            reply.label = TRONA_OK;
            return reply;
        }
        match dir_entry_remove_with_ref(
            new_parent,
            existing_ino,
            &new_name[..new_name_len as usize],
        ) {
            Ok(()) => {}
            Err(DirEntryTxnError::FailedClean) | Err(DirEntryTxnError::FailedDirty) => {
                reply.label = TRONA_OUT_OF_MEMORY;
                return reply;
            }
        }

        // Decrement nlink; if 0, clean up inode + extents + xattrs
        if let Some(existing_inode) = get_inode(existing_ino) {
            let new_nlink = existing_inode.nlink.saturating_sub(1);
            if new_nlink == 0 {
                // Reclaim xattrs (including hidden-inode indirect entries)
                // before tearing down extents and the INODE_ITEM.
                crate::xattr::delete_all_xattrs(existing_ino);

                // Delete all extent data items (multi-block aware)
                delete_all_extents(existing_ino);
                bitmap_flush();
                // Delete INODE_ITEM
                let inode_key = BTreeKey {
                    object_id: existing_ino,
                    item_type: TRONA_INODE_ITEM,
                    offset: 0,
                };
                if !btree_cow_delete(&inode_key) {
                    trona_runtime::uwarn!(|_lb| {
                        _lb.str(b"[saltyfs] rename: warning: orphan inode (delete failed)\n");
                    });
                }
            } else {
                // nlink > 0: just update inode
                let mut updated = existing_inode;
                updated.nlink = new_nlink;
                let inode_key = BTreeKey {
                    object_id: existing_ino,
                    item_type: TRONA_INODE_ITEM,
                    offset: 0,
                };
                if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
                    trona_runtime::uwarn!(|_lb| {
                        _lb.str(b"[saltyfs] rename: warning: nlink update failed\n");
                    });
                }
            }
        }
    }

    match dir_entry_remove_with_ref(old_parent, child_ino, &old_name[..old_name_len as usize]) {
        Ok(()) => {}
        Err(DirEntryTxnError::FailedClean) | Err(DirEntryTxnError::FailedDirty) => {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
    }

    // Determine dir_type from inode
    let dir_type = match get_inode(child_ino) {
        Some(inode) => dir_item_type_from_mode(inode.mode),
        None => 1u8,
    };

    match dir_entry_insert_with_ref(
        new_parent,
        child_ino,
        &new_name[..new_name_len as usize],
        dir_type,
    ) {
        Ok(()) => {}
        Err(DirEntryTxnError::FailedClean) | Err(DirEntryTxnError::FailedDirty) => {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
    }

    update_inode_mtime(old_parent);
    if new_parent != old_parent {
        update_inode_mtime(new_parent);
    }

    reply.label = TRONA_OK;
    reply
}

/// Handle BACKEND_TRUNCATE: change file size.
/// Supports multi-block files: deletes extent items beyond new_size.
pub(crate) fn handle_truncate_fs(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let ino = msg.regs[0];
    let new_size = msg.regs[1];
    let bs = unsafe { *(&raw const BLOCK_SIZE) };

    let inode = match get_inode(ino) {
        Some(i) => i,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    let inode_key = BTreeKey {
        object_id: ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };

    if new_size >= inode.size {
        // Extend: just update inode size
        let mut updated = inode;
        updated.size = new_size;
        updated.mtime = unsafe { (*(&raw const SB)).generation + 1 };
        if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
        reply.label = TRONA_OK;
        return reply;
    }

    // Handle inline extent at offset 0 if present (one-time, not batched)
    let ext_key_0 = BTreeKey {
        object_id: ino,
        item_type: TRONA_EXTENT_DATA,
        offset: 0,
    };
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    if let Some((ext_ptr, ext_size)) = btree_find_item(root_tree, &ext_key_0) {
        let ext = unsafe { read_extent_data(ext_ptr) };
        if ext.extent_type == EXTENT_INLINE {
            if new_size == 0 {
                if !btree_cow_delete(&ext_key_0) {
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return reply;
                }
            } else {
                let ext_hdr_size = core::mem::size_of::<ExtentData>();
                let inline_len = (ext_size as usize).saturating_sub(ext_hdr_size);
                let mut data = [0u8; 208];
                unsafe {
                    let src = ext_ptr.add(ext_hdr_size);
                    for j in 0..inline_len.min(208) {
                        data[j] = *src.add(j);
                    }
                }
                if !btree_cow_delete(&ext_key_0) {
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return reply;
                }
                let ext_hdr_size2 = core::mem::size_of::<ExtentData>();
                let mut extent_buf = [0u8; 304];
                build_extent_inline(&mut extent_buf, new_size, &data[..new_size as usize]);
                let ext_total = ext_hdr_size2 + new_size as usize;
                if !btree_cow_insert(&ext_key_0, &extent_buf[..ext_total]) {
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return reply;
                }
            }
        }
    }

    // Delete regular extents beyond new_size in batches of 128
    loop {
        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        let mut ext_offsets = [0u64; 128];
        let mut ext_disk_bytenr = [0u64; 128];
        let mut ext_disk_num = [0u64; 128];
        let mut ext_count = 0usize;

        btree_find_all_for_ino(root_tree, ino, TRONA_EXTENT_DATA, |key, data_ptr, _size| {
            let ext = unsafe { read_extent_data(data_ptr) };
            if ext.extent_type == EXTENT_REGULAR && key.offset >= new_size {
                if ext_count < 128 {
                    ext_offsets[ext_count] = key.offset;
                    ext_disk_bytenr[ext_count] = ext.disk_bytenr;
                    ext_disk_num[ext_count] = ext.disk_num_bytes;
                    ext_count += 1;
                }
                return ext_count < 128;
            }
            true
        });

        if ext_count == 0 {
            break;
        }

        for i in 0..ext_count {
            if ext_disk_bytenr[i] != 0 {
                let block_start = ext_disk_bytenr[i] / bs;
                let block_count = (ext_disk_num[i] + bs - 1) / bs;
                for b in 0..block_count {
                    free_block(block_start + b);
                }
            }
            let ext_key = BTreeKey {
                object_id: ino,
                item_type: TRONA_EXTENT_DATA,
                offset: ext_offsets[i],
            };
            btree_cow_delete(&ext_key);
        }
    }

    bitmap_flush();

    let mut updated = inode;
    updated.size = new_size;
    updated.blocks = if new_size == 0 {
        0
    } else {
        (new_size + bs - 1) / bs
    };
    updated.mtime = unsafe { (*(&raw const SB)).generation + 1 };
    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    reply.label = TRONA_OK;
    reply
}

/// Handle BACKEND_SHM_SETUP: map a VFS-shared SHM region for bulk
/// data transport into the calling session's reserved VA window.
///
/// Request:
///   regs[0] = mmsrv-issued shm_idx
///   regs[1] = bytes
///   caps[0] = SHM MO cap copy authorizing this daemon's
///             self-tier `MM_SHM_MAP`.
///
/// Each session's region is mapped at a disjoint VA computed from
/// the slot index by `session::slot_shm_vaddr` so multi-mount
/// sessions never alias each other's payloads. The daemon stamps
/// `shm_id` / `shm_vaddr` / `shm_bytes` onto the live slot;
/// `live_shm_region` / `live_shm_region_for_msg` resolve the right
/// region for the SHM-using handlers.
pub(crate) fn handle_shm_setup(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    let shm_id = msg.regs[0];
    let shm_bytes = msg.regs[1];
    let shm_cap = unsafe {
        let arena = &mut *(&raw mut crate::RECV_SLOTS);
        trona_server::recv_slot::capture_transferred_cap(crate::ipc_ctx(), arena).unwrap_or(0)
    };
    if shm_cap == 0 || shm_bytes == 0 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    let slot_idx = match session::slot_idx_for_msg(msg) {
        Some(i) => i,
        None => {
            let _ = trona_kernel::invoke::cnode_delete(
                CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64),
                shm_cap,
            );
            reply.label = TRONA_INVALID_OPERATION;
            return reply;
        }
    };
    let dest_vaddr = session::slot_shm_vaddr(slot_idx);

    let ctx = crate::ipc_ctx();
    let mut mm_msg = TronaMsg::zeroed();
    mm_msg.label = MM_SHM_MAP;
    mm_msg.length = 6;
    mm_msg.regs[0] = dest_vaddr;
    mm_msg.regs[1] = shm_id;
    mm_msg.regs[2] = 0;
    mm_msg.regs[3] = shm_bytes;
    mm_msg.regs[4] = 0x3; // RW
    mm_msg.regs[5] = 0;

    let mut mm_reply = TronaMsg::zeroed();
    unsafe {
        trona_kernel::ipc::set_send_cap_ctx(ctx, 0, shm_cap);
    }
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ctx,
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const mm_msg,
            &raw mut mm_reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    let _ =
        trona_kernel::invoke::cnode_delete(CapRef::flat(KERNITE_CAP_SELF_CSPACE as u64), shm_cap);
    if err != 0 || mm_reply.label != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[saltyfs] VFS SHM map failed\n");
        });
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    unsafe {
        if let Some(slot) = session::slot_mut(slot_idx) {
            slot.shm_id = shm_id;
            slot.shm_vaddr = dest_vaddr;
            slot.shm_bytes = shm_bytes;
        }
    }
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[saltyfs] VFS SHM mapped for bulk transport\n");
    });

    reply.label = TRONA_OK;
    reply
}

/// Handle [`BACKEND_WRITE`]: write via inline payload or SHM.
///
/// Request:
///   regs[0]      = ino
///   regs[1]      = file_offset
///   regs[2..=4]  = TransferDescriptor (kind, flags, offset, length)
///   regs[5..]    = payload bytes (INLINE only, up to `INLINE_TRANSFER_WIRE_MAX`)
///
/// Reply:
///   regs[0]      = bytes_written
pub(crate) fn handle_write(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let ino = msg.regs[0];
    let file_offset = msg.regs[1];
    let transfer = TransferDescriptor::decode_regs([
        msg.regs[BACKEND_RW_REQ_DESCRIPTOR_REG],
        msg.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 1],
        msg.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 2],
        msg.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 3],
    ]);

    let mut inline_buf = [0u8; INLINE_TRANSFER_WIRE_MAX as usize];
    let (data_src, count) = match transfer.kind {
        TRANSFER_KIND_INLINE => {
            if transfer.length > INLINE_TRANSFER_WIRE_MAX {
                reply.label = TRONA_INVALID_ARGUMENT;
                return reply;
            }
            unsafe {
                let src = &raw const msg.regs[BACKEND_WRITE_INLINE_PAYLOAD_REG] as *const u8;
                for i in 0..transfer.length as usize {
                    inline_buf[i] = *src.add(i);
                }
            }
            (inline_buf.as_ptr(), transfer.length)
        }
        TRANSFER_KIND_SHM => {
            let Some((shm_vaddr, shm_size)) = session::live_shm_region_for_msg(msg) else {
                reply.label = TRONA_INVALID_OPERATION;
                return reply;
            };
            if transfer.offset >= shm_size || transfer.length > shm_size - transfer.offset {
                reply.label = TRONA_INVALID_ARGUMENT;
                return reply;
            }
            let src = (shm_vaddr + transfer.offset) as *const u8;
            (src, transfer.length)
        }
        _ => {
            reply.label = TRONA_INVALID_ARGUMENT;
            return reply;
        }
    };

    let data_slice = unsafe { core::slice::from_raw_parts(data_src, count as usize) };
    match execute_write_locked(ino, file_offset, data_slice) {
        Ok(n) => {
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = n;
        }
        Err(label) => {
            reply.label = label;
        }
    }
    reply
}

/// Pure file-mutation executor for `BACKEND_WRITE`. Both the
/// owner-thread sync `handle_write` fallback and the worker
/// `WorkerJobKind::WriteBlocks` path call this — the only
/// difference between the two callers is *where* the bytes come
/// from (inline regs / SHM ring / MO mapping); the actual B-tree
/// + inode mutation discipline lives here, keeping a single
/// implementation of inline-extent fast path + regular-extent
/// path.
///
/// Caller must hold `worker::BLOCK_LOCK`. Returns the number of
/// bytes written on success, or a wire label on failure.
pub(crate) fn execute_write_locked(ino: u64, file_offset: u64, data: &[u8]) -> Result<u64, u64> {
    let count = data.len() as u64;
    let inode = match get_inode(ino) {
        Some(i) => i,
        None => return Err(TRONA_NOT_FOUND),
    };

    let new_size = if file_offset + count > inode.size {
        file_offset + count
    } else {
        inode.size
    };

    let bs = unsafe { *(&raw const BLOCK_SIZE) };
    let data_src = data.as_ptr();

    if new_size <= 208 && file_offset < 208 {
        let extent_key = BTreeKey {
            object_id: ino,
            item_type: TRONA_EXTENT_DATA,
            offset: 0,
        };

        let mut full_data = [0u8; 208];
        let root_tree = unsafe { (*(&raw const SB)).root_tree };
        let mut had_extent = false;

        if let Some((ext_ptr, ext_size)) = btree_find_item(root_tree, &extent_key) {
            had_extent = true;
            let ext = unsafe { read_extent_data(ext_ptr) };
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
                let mut tmp = TronaMsg::zeroed();
                unsafe {
                    write_regular_extents(
                        ino,
                        file_offset,
                        count,
                        data_src,
                        &inode,
                        new_size,
                        bs,
                        &mut tmp,
                    );
                }
                if tmp.label == TRONA_OK {
                    return Ok(if tmp.length >= 1 { tmp.regs[0] } else { count });
                }
                return Err(tmp.label);
            }
        }

        unsafe {
            for i in 0..count as usize {
                if file_offset as usize + i < 208 {
                    full_data[file_offset as usize + i] = *data_src.add(i);
                }
            }
        }

        let mut extent_buf = [0u8; 304];
        build_extent_inline(&mut extent_buf, new_size, &full_data[..new_size as usize]);
        let ext_total = core::mem::size_of::<ExtentData>() + new_size as usize;

        let ok = if had_extent {
            btree_cow_update(&extent_key, &extent_buf[..ext_total])
        } else {
            btree_cow_insert(&extent_key, &extent_buf[..ext_total])
        };
        if !ok {
            return Err(TRONA_OUT_OF_MEMORY);
        }
    } else {
        let mut tmp = TronaMsg::zeroed();
        unsafe {
            write_regular_extents(
                ino,
                file_offset,
                count,
                data_src,
                &inode,
                new_size,
                bs,
                &mut tmp,
            );
        }
        if tmp.label == TRONA_OK {
            return Ok(if tmp.length >= 1 { tmp.regs[0] } else { count });
        }
        return Err(tmp.label);
    }

    let mut updated_inode = inode;
    updated_inode.size = new_size;
    updated_inode.mtime = unsafe { (*(&raw const SB)).generation + 1 };
    let inode_key = BTreeKey {
        object_id: ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated_inode)) {
        return Err(TRONA_OUT_OF_MEMORY);
    }

    Ok(count)
}

// ======================================================================
// Symlink / Readlink / Hard Link handlers
// ======================================================================

/// Handle BACKEND_SYMLINK: create a symbolic link.
///
/// V1 layout: MR0=parent_ino, MR1=name_len (max 72), MR2=target_len (max 64),
///            MR3..MR11=name, MR12..MR19=target.
/// V2 layout (`SALTYFS_PROTO_V2` bit in MR0):
///            MR0=parent|V2, MR1=uid, MR2=gid, MR3=name_len (max 56),
///            MR4=target_len (max 64), MR5..MR11=name, MR12..MR19=target.
pub(crate) fn handle_symlink(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let raw_parent = msg.regs[0];
    let is_v2 = (raw_parent & SALTYFS_PROTO_V2) != 0;
    let parent_ino = raw_parent & !SALTYFS_PROTO_V2;

    let (uid, gid, name_len, target_len, name_off, name_cap) = if is_v2 {
        (
            msg.regs[1] as u32,
            msg.regs[2] as u32,
            msg.regs[3] as usize,
            msg.regs[4] as usize,
            5usize,
            56usize,
        )
    } else {
        (
            0u32,
            0u32,
            msg.regs[1] as usize,
            msg.regs[2] as usize,
            3usize,
            72usize,
        )
    };

    if name_len == 0 || name_len > name_cap || target_len == 0 || target_len > 64 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    // Extract link name from name_off..MR11
    let mut name_buf = [0u8; 72];
    unsafe {
        let src = &raw const msg.regs[name_off] as *const u8;
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
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };
    if parent_inode.mode & 0o170000 != 0o040000 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    // Casefold parent: the symlink's own name must be valid UTF-8. The
    // target bytes are opaque (they become file content) and are not
    // subject to name-level UTF-8 validation.
    if (parent_inode.flags & SALTY_INODE_CASEFOLD) != 0
        && !crate::name::is_valid_utf8(&name_buf[..name_len])
    {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    // Check name doesn't already exist
    if lookup_in_dir(parent_ino, name_buf.as_ptr(), name_len as u8).is_some() {
        reply.label = TRONA_ALREADY_EXISTS;
        return reply;
    }

    // Inherit CASEFOLD bit from parent for consistency with the directory.
    let inherit_flags = parent_inode.flags & SALTY_INODE_CASEFOLD;

    // Allocate inode number
    let new_ino = crate::block::allocate_next_inode();

    // Insert INODE_ITEM with S_IFLNK mode, size = target length
    let inode_data = build_inode_bytes(
        target_len as u64,
        0,
        1,
        0o120000 | 0o777,
        uid,
        gid,
        inherit_flags,
    );
    let inode_key = BTreeKey {
        object_id: new_ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_insert(&inode_key, &inode_data) {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    // Store target as inline extent
    let mut ext_buf = [0u8; 304];
    build_extent_inline(&mut ext_buf, target_len as u64, &target_buf[..target_len]);
    let ext_size = core::mem::size_of::<ExtentData>() + target_len;
    let extent_key = BTreeKey {
        object_id: new_ino,
        item_type: TRONA_EXTENT_DATA,
        offset: 0,
    };
    if !btree_cow_insert(&extent_key, &ext_buf[..ext_size]) {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    match dir_entry_insert_with_ref(parent_ino, new_ino, &name_buf[..name_len], 7) {
        Ok(()) => {}
        Err(DirEntryTxnError::FailedClean) => {
            delete_all_extents(new_ino);
            bitmap_flush();
            if !btree_cow_delete(&inode_key) {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[saltyfs] WARN: symlink rollback inode delete failed\n");
                });
            }
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
        Err(DirEntryTxnError::FailedDirty) => {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
    }

    update_inode_mtime(parent_ino);

    let _ = pack_lookup_snapshot_reply(&mut reply, new_ino, 7);
    reply
}

/// Handle BACKEND_READLINK: read a symlink target.
/// MR0=ino -> MR0=target_len, MR1..MR19=target_data (up to 152 bytes)
pub(crate) fn handle_readlink(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }

    let ino = msg.regs[0];

    // Get inode and verify it's a symlink
    let inode = match get_inode(ino) {
        Some(i) => i,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };
    if inode.mode & 0o170000 != 0o120000 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    // Read inline extent data (symlink target)
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let extent_key = BTreeKey {
        object_id: ino,
        item_type: TRONA_EXTENT_DATA,
        offset: 0,
    };
    let (data_ptr, data_size) = match btree_find_item(root_tree, &extent_key) {
        Some((d, s)) => (d, s),
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    let ext_hdr_size = core::mem::size_of::<ExtentData>();
    if (data_size as usize) < ext_hdr_size {
        reply.label = TRONA_NOT_FOUND;
        return reply;
    }

    let ext = unsafe { core::ptr::read_unaligned(data_ptr as *const ExtentData) };
    if ext.extent_type != EXTENT_INLINE {
        reply.label = TRONA_NOT_FOUND;
        return reply;
    }

    let target_len = inode.size as usize;
    let inline_data = data_size as usize - ext_hdr_size;
    let copy_len = core::cmp::min(target_len, inline_data);
    let copy_len = core::cmp::min(copy_len, 152); // max IPC register space

    // Pack target into reply registers MR1..MR19
    reply.label = TRONA_OK;
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

/// Handle BACKEND_LINK: create a hard link.
/// MR0=existing_ino, MR1=new_parent_ino, MR2=name_len (max 136),
/// MR3..MR19=name (136 bytes)
pub(crate) fn handle_link(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let existing_ino = msg.regs[0];
    let new_parent = msg.regs[1];
    let name_len = msg.regs[2] as usize;

    if name_len == 0 || name_len > 136 {
        reply.label = TRONA_INVALID_ARGUMENT;
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
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };
    if inode.mode & 0o170000 == 0o040000 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    // Verify parent exists and is a directory
    let parent_inode = match get_inode(new_parent) {
        Some(i) => i,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };
    if parent_inode.mode & 0o170000 != 0o040000 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    // Check name doesn't already exist in parent
    if lookup_in_dir(new_parent, name_buf.as_ptr(), name_len as u8).is_some() {
        reply.label = TRONA_ALREADY_EXISTS;
        return reply;
    }

    let dir_type: u8 = dir_item_type_from_mode(inode.mode);
    match dir_entry_insert_with_ref(new_parent, existing_ino, &name_buf[..name_len], dir_type) {
        Ok(()) => {}
        Err(DirEntryTxnError::FailedClean) | Err(DirEntryTxnError::FailedDirty) => {
            reply.label = TRONA_OUT_OF_MEMORY;
            return reply;
        }
    }

    // Increment nlink on existing inode
    let mut updated_inode = inode;
    updated_inode.nlink += 1;
    updated_inode.ctime = unsafe { (*(&raw const SB)).generation + 1 };
    let inode_key = BTreeKey {
        object_id: existing_ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };
    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated_inode)) {
        if dir_entry_remove_with_ref(new_parent, existing_ino, &name_buf[..name_len]).is_err() {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[saltyfs] CRIT: link rollback (remove dir+ref) failed\n");
            });
        }
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    update_inode_mtime(new_parent);

    let _ = pack_lookup_snapshot_reply(&mut reply, existing_ino, dir_type);
    reply
}

/// Handle BACKEND_SETATTR: bundled attribute-update with atomic commit and a
/// post-commit snapshot in the reply so the VFS cache refreshes in one round
/// trip instead of a follow-up `BACKEND_STAT`.
///
/// Request layout follows [`trona_protocol::vfs::backend::BACKEND_SETATTR_REG_COUNT`]:
/// ```text
///   regs[0] = ino
///   regs[1] = mask (bitwise OR of SETATTR_MASK_*)
///   regs[2] = mode
///   regs[3] = uid (low 32) | gid (high 32)
///   regs[4] = atime
///   regs[5] = mtime
///   regs[6] = size (0 when SETATTR_MASK_SIZE is clear)
/// ```
///
/// Reply layout (`BACKEND_SETATTR_REPLY_REG_COUNT`):
/// ```text
///   regs[0] = mode
///   regs[1] = uid
///   regs[2] = gid
///   regs[3] = size
///   regs[4] = nlink
///   regs[5] = atime
///   regs[6] = mtime
/// ```
///
/// Fields not selected by the mask are preserved. Truncate via
/// `SETATTR_MASK_SIZE` follows the same semantics as `BACKEND_TRUNCATE`
/// (extending is zero-filled; shrinking drops extents).
pub(crate) fn handle_setattr(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let ino = msg.regs[0];
    let mask = msg.regs[1] as u32;
    let mode_in = msg.regs[2] as u32;
    let uid_gid = msg.regs[3];
    let atime_in = msg.regs[4];
    let mtime_in = msg.regs[5];
    let size_in = msg.regs[6];

    let uid_in = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid_in = (uid_gid >> 32) as u32;

    // `BACKEND_SETATTR` is required to commit every masked field as a
    // single atomic inode mutation. A combined SIZE + mode/uid/gid/
    // atime/mtime mask would require two on-disk btree writes (the
    // truncate path writes the inode with new size/blocks, then the
    // final `btree_cow_update` below writes it again with the other
    // fields), so a crash between the two writes would leave the
    // inode partially mutated — not atomic from the client's view.
    // VFS never ships such a combined mask today (the saltyfs_client
    // `setattr` VOP deliberately excludes SIZE; size changes go
    // through `BACKEND_TRUNCATE`), so rejecting the combination here
    // is a defensive guard rather than a behaviour change. If a
    // future client needs atomic size + attr mutation, the handler
    // must be restructured to build a single `updated` inode and
    // call `truncate_ino_transaction` (or an equivalent single-btree
    // write helper) rather than the synthetic `BACKEND_TRUNCATE`
    // round-trip below.
    const SETATTR_NON_SIZE_MASK: u32 = SETATTR_MASK_MODE
        | SETATTR_MASK_UID
        | SETATTR_MASK_GID
        | SETATTR_MASK_ATIME
        | SETATTR_MASK_MTIME;
    if (mask & SETATTR_MASK_SIZE) != 0 && (mask & SETATTR_NON_SIZE_MASK) != 0 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return reply;
    }

    let inode = match get_inode(ino) {
        Some(i) => i,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    let inode_key = BTreeKey {
        object_id: ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };

    let mut updated = inode;
    if (mask & SETATTR_MASK_MODE) != 0 {
        // Preserve S_IFMT type bits; only the 0o7777 permission bits
        // are replaceable via setattr.
        updated.mode = (updated.mode & 0o170000) | (mode_in & 0o7777);
    }
    if (mask & SETATTR_MASK_UID) != 0 {
        updated.uid = uid_in;
    }
    if (mask & SETATTR_MASK_GID) != 0 {
        updated.gid = gid_in;
    }
    if (mask & SETATTR_MASK_ATIME) != 0 {
        updated.atime = atime_in;
    }
    if (mask & SETATTR_MASK_MTIME) != 0 {
        updated.mtime = mtime_in;
    }
    // SIZE mutation defers to the existing truncate path so the extent
    // B-tree stays consistent. `size_in` is honoured only when the
    // truncate succeeds — otherwise the snapshot reflects the pre-
    // truncate size.
    if (mask & SETATTR_MASK_SIZE) != 0 {
        let tr_reply = handle_truncate_ino(ino, size_in);
        if tr_reply.label != TRONA_OK {
            return tr_reply;
        }
        // Re-read inode to pick up size/blocks mutated by truncate.
        if let Some(fresh) = get_inode(ino) {
            updated.size = fresh.size;
            updated.blocks = fresh.blocks;
            updated.nlink = fresh.nlink;
        }
    }

    // Bump generation so readers see a coherent snapshot.
    updated.mtime = if (mask & SETATTR_MASK_MTIME) != 0 {
        updated.mtime
    } else {
        unsafe { (*(&raw const SB)).generation + 1 }
    };

    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    reply.label = TRONA_OK;
    reply.length = trona_protocol::vfs::backend::BACKEND_SETATTR_REPLY_REG_COUNT as u64;
    reply.regs[0] = updated.mode as u64;
    reply.regs[1] = updated.uid as u64;
    reply.regs[2] = updated.gid as u64;
    reply.regs[3] = updated.size;
    reply.regs[4] = updated.nlink as u64;
    reply.regs[5] = updated.atime;
    reply.regs[6] = updated.mtime;
    reply
}

/// Shared inner truncate path invoked from both `BACKEND_TRUNCATE` and
/// the `BACKEND_SETATTR` size-change branch. Kept on its own so the
/// setattr handler does not need to reconstruct a synthetic `TronaMsg`.
fn handle_truncate_ino(ino: u64, new_size: u64) -> TronaMsg {
    let mut synthetic = TronaMsg::zeroed();
    synthetic.label = BACKEND_TRUNCATE;
    synthetic.regs[0] = ino;
    synthetic.regs[1] = new_size;
    synthetic.length = 2;
    handle_truncate_fs(&synthetic)
}

/// Handle BACKEND_CHMOD: update inode mode, preserving file type bits.
/// regs[0] = ino, regs[1] = new_mode (permission bits only, 0o7777 mask)
pub(crate) fn handle_chmod(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let ino = msg.regs[0];
    let new_perm = msg.regs[1] as u32;

    let inode = match get_inode(ino) {
        Some(i) => i,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    let inode_key = BTreeKey {
        object_id: ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };

    // Preserve file type bits (S_IFMT = 0o170000), replace permission bits
    let mut updated = inode;
    updated.mode = (inode.mode & 0o170000) | (new_perm & 0o7777);
    updated.mtime = unsafe { (*(&raw const SB)).generation + 1 };

    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    reply.label = TRONA_OK;
    reply
}

/// Handle BACKEND_CHOWN: update inode uid/gid.
/// regs[0] = ino, regs[1] = new_uid (u32::MAX = no change), regs[2] = new_gid (u32::MAX = no change)
pub(crate) fn handle_chown(msg: &TronaMsg) -> TronaMsg {
    let mut reply = TronaMsg::zeroed();
    if !unsafe { *(&raw const MOUNTED) } {
        reply.label = TRONA_INVALID_OPERATION;
        return reply;
    }
    if let Some(r) = ro_reject_if_readonly() {
        return r;
    }

    let ino = msg.regs[0];
    let new_uid = msg.regs[1] as u32;
    let new_gid = msg.regs[2] as u32;

    let inode = match get_inode(ino) {
        Some(i) => i,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return reply;
        }
    };

    let inode_key = BTreeKey {
        object_id: ino,
        item_type: TRONA_INODE_ITEM,
        offset: 0,
    };

    let mut updated = inode;
    if new_uid != u32::MAX {
        updated.uid = new_uid;
    }
    if new_gid != u32::MAX {
        updated.gid = new_gid;
    }
    updated.mtime = unsafe { (*(&raw const SB)).generation + 1 };

    if !btree_cow_update(&inode_key, &inode_to_bytes(&updated)) {
        reply.label = TRONA_OUT_OF_MEMORY;
        return reply;
    }

    reply.label = TRONA_OK;
    reply
}
