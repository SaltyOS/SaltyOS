//! SaltyOS SaltyFS Server (Read-Only MVP)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Mounts a SaltyFS partition from blkdrv and serves file read/directory
//! traversal requests over IPC.
//!
//! On-disk format follows docs/design/saltyfs.md exactly.
//! Data transfer to/from blkdrv uses mmsrv SHM.
//!
//! IPC protocol:
//!   Label 1 = SALTYFS_MOUNT:   mount the filesystem
//!   Label 2 = SALTYFS_LOOKUP:  MR0=parent_ino, MR1..=name -> MR0=child_ino
//!   Label 3 = SALTYFS_READ:    MR0=ino, MR1=offset, MR2=count, MR3=shm_offset
//!   Label 4 = SALTYFS_READDIR: MR0=dir_ino, MR1=cursor -> entries
//!   Label 5 = SALTYFS_STAT:    MR0=ino -> stat info
//!   Label 6 = SALTYFS_GETINFO: -> total/free blocks, label
//!
//! Cap layout:
//!   0  = self TCB
//!   1  = self VSpace
//!   2  = self CSpace
//!   68 = server endpoint (pre-created service EP)
//!   14 = readiness notification
//!   64 = blkdrv endpoint
//!   5  = nameserv endpoint
//!   7  = mmsrv endpoint

#![no_std]
#![no_main]

extern crate salty;

use salty::consts::*;
use salty::ipc;
use salty::invoke;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

const CAP_SELF_TCB: u64 = 0;
const CAP_SERVER_EP: u64 = 68;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_BLKDRV_EP: u64 = 64;
const CAP_NAMESERV_EP: u64 = 5;
const CAP_MMSRV_EP: u64 = 7;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

/// SHM for saltyfs<->blkdrv data (mapped from blkdrv's SHM)
const SHM_VADDR: u64 = 0x0000_0000_5000_0000;
const SHM_SIZE: u64 = 256 * 1024; // 256KB (64 pages)

/// Block size (4KB default, read from superblock)
const DEFAULT_BLOCK_SIZE: u64 = 4096;
const SECTOR_SIZE: u64 = 512;

/// Block cache: 64 blocks cached in memory
const CACHE_VADDR: u64 = 0x0000_0000_5100_0000;
const CACHE_SLOTS: usize = 64;
/// Each cache slot is one block (4KB)
const CACHE_SLOT_SIZE: usize = 4096;
const CACHE_TOTAL_PAGES: u64 = (CACHE_SLOTS * CACHE_SLOT_SIZE / 4096) as u64;

// ======================================================================
// On-disk structures (docs/design/saltyfs.md)
// ======================================================================

const SALTYFS_MAGIC: [u8; 8] = *b"SALTYFS\0";
const BTREE_NODE_MAGIC: [u8; 4] = *b"BTND";

/// Item type constants (docs/design/saltyfs.md:154-160)
const SALTY_INODE_ITEM: u8 = 0x01;
const SALTY_INODE_REF: u8 = 0x02;
const SALTY_DIR_ITEM: u8 = 0x03;
const SALTY_DIR_INDEX: u8 = 0x04;
const SALTY_EXTENT_DATA: u8 = 0x05;

/// Extent types
const EXTENT_INLINE: u8 = 0;
const EXTENT_REGULAR: u8 = 1;

/// Superblock (4KB, docs/design/saltyfs.md:57-104)
#[repr(C)]
#[derive(Clone, Copy)]
struct Superblock {
    magic: [u8; 8],
    version: u32,
    flags: u32,
    fs_uuid: [u8; 16],
    device_uuid: [u8; 16],
    // Geometry (offset 0x030)
    block_size: u64,
    total_blocks: u64,
    used_blocks: u64,
    reserved_blocks: u64,
    // Tree roots (offset 0x050)
    root_tree: u64,
    extent_tree: u64,
    checksum_tree: u64,
    snapshot_tree: u64,
    // Log (offset 0x070)
    log_start: u64,
    log_size: u64,
    log_head: u64,
    log_tail: u64,
    // State (offset 0x090)
    generation: u64,
    last_mount_time: u64,
    last_write_time: u64,
    mount_count: u64,
    // Root inode (offset 0x0B0)
    root_inode: u64,
    // Checksums (offset 0x0B8)
    checksum_type: u32,
    reserved1: u32,
    // Label (offset 0x0C0)
    label: [u8; 64],
    // Padding to 4KB
    // 0x100 .. 0xFFC (3836 bytes), checksum is final 4 bytes at 0xFFC
    reserved: [u8; 3836],
    checksum: u32,
}

// On-disk superblock must be exactly one 4KB block.
const _: [u8; 4096] = [0; core::mem::size_of::<Superblock>()];

/// B-tree node header (64 bytes, docs/design/saltyfs.md:112-126)
#[repr(C)]
#[derive(Clone, Copy)]
struct BTreeNodeHeader {
    magic: [u8; 4],
    checksum: u32,
    owner: u64,
    generation: u64,
    block_nr: u64,
    num_items: u32,
    level: u16,
    flags: u16,
    reserved: [u8; 24],
}

/// B-tree key (packed, docs/design/saltyfs.md:129-133)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BTreeKey {
    object_id: u64,
    item_type: u8,
    offset: u64,
}

impl BTreeKey {
    fn cmp(&self, other: &BTreeKey) -> core::cmp::Ordering {
        let a_oid = self.object_id;
        let b_oid = other.object_id;
        match a_oid.cmp(&b_oid) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.item_type.cmp(&other.item_type) {
            core::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        let a_off = self.offset;
        let b_off = other.offset;
        a_off.cmp(&b_off)
    }
}

/// B-tree item (in leaf nodes, docs/design/saltyfs.md:136-140)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BTreeItem {
    key: BTreeKey,
    offset: u32,
    size: u32,
}

/// B-tree pointer (in internal nodes, docs/design/saltyfs.md:142-147)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct BTreePointer {
    key: BTreeKey,
    block_nr: u64,
    generation: u64,
}

/// Inode item (docs/design/saltyfs.md:162-183)
#[repr(C)]
#[derive(Clone, Copy)]
struct SaltyInode {
    generation: u64,
    size: u64,
    blocks: u64,
    block_group: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u32,
    atime: u64,
    mtime: u64,
    ctime: u64,
    crtime: u64,
    flags: u32,
    sequence: u32,
    reserved: [u8; 32],
}

/// Extent data item (docs/design/saltyfs.md:192-206)
#[repr(C)]
#[derive(Clone, Copy)]
struct ExtentData {
    generation: u64,
    ram_bytes: u64,
    compression: u8,
    encryption: u8,
    other_encoding: u16,
    extent_type: u8,
    reserved: [u8; 3],
    // For non-inline extents:
    disk_bytenr: u64,
    disk_num_bytes: u64,
    offset: u64,
    num_bytes: u64,
}

/// Directory item header is tightly packed on disk:
///   child_ino: u64, name_len: u16, dir_type: u8, pad: u8
/// Name bytes follow immediately after this 12-byte header.
const DIR_ITEM_HEADER_SIZE: usize = 12;

#[inline]
unsafe fn parse_dir_item_header(data_ptr: *const u8) -> (u64, u16, u8) {
    unsafe {
        let child_ino = core::ptr::read_unaligned(data_ptr as *const u64);
        let name_len = core::ptr::read_unaligned(data_ptr.add(8) as *const u16);
        let dir_type = *data_ptr.add(10);
        (child_ino, name_len, dir_type)
    }
}

// ======================================================================
// CRC32c implementation (table-based)
// ======================================================================

static CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

fn crc32c(data: *const u8, len: usize) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for i in 0..len {
        let byte = unsafe { *data.add(i) };
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

fn crc32c_superblock(sb: &Superblock) -> u32 {
    // Zero out the checksum field before computing
    let sb_ptr = sb as *const Superblock as *const u8;
    let sb_size = core::mem::size_of::<Superblock>();
    let cksum_offset = sb_size - 4; // checksum is last 4 bytes

    let mut crc = 0xFFFF_FFFFu32;
    for i in 0..cksum_offset {
        let byte = unsafe { *sb_ptr.add(i) };
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    // Process 4 zero bytes for the checksum field
    for _ in 0..4 {
        crc = CRC32C_TABLE[(crc & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

fn crc32c_btree_node(data: *const u8, block_size: usize) -> u32 {
    // checksum is at offset 4 (after 4-byte magic), 4 bytes
    let mut crc = 0xFFFF_FFFFu32;
    // magic (0..4)
    for i in 0..4 {
        let byte = unsafe { *data.add(i) };
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    // zero out checksum (4..8)
    for _ in 0..4 {
        crc = CRC32C_TABLE[(crc & 0xFF) as usize] ^ (crc >> 8);
    }
    // rest of block (8..block_size)
    for i in 8..block_size {
        let byte = unsafe { *data.add(i) };
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

// ======================================================================
// Global state
// ======================================================================

static mut MOUNTED: bool = false;
static mut SB: Superblock = unsafe { core::mem::zeroed() };
static mut BLOCK_SIZE: u64 = DEFAULT_BLOCK_SIZE;
static mut BLK_SHM_ID: u64 = 0;

/// Block cache: LRU-ish (just track block numbers, evict oldest)
static mut CACHE_BLOCK_NR: [u64; CACHE_SLOTS] = [u64::MAX; CACHE_SLOTS];
static mut CACHE_AGE: [u32; CACHE_SLOTS] = [0; CACHE_SLOTS];
static mut CACHE_TICK: u32 = 0;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

fn signal_ready() {
    let _ = salty::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

// ======================================================================
// Block I/O via blkdrv SHM
// ======================================================================

/// Read sectors from blkdrv into SHM at given offset.
fn blk_read_sectors(start_sector: u64, count: u64, shm_offset: u64) -> bool {
    let mut msg = SaltyMsg::zeroed();
    msg.label = BLK_READ;
    msg.length = 3;
    msg.regs[0] = start_sector;
    msg.regs[1] = count;
    msg.regs[2] = shm_offset;

    let mut reply = SaltyMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_BLKDRV_EP, &raw const msg, &raw mut reply) };
    err == 0 && reply.label == 0
}

/// Read a filesystem block into the block cache. Returns pointer to cached data.
fn read_block(block_nr: u64) -> *const u8 {
    unsafe {
        // Check cache first
        for i in 0..CACHE_SLOTS {
            if *(&raw const CACHE_BLOCK_NR[i]) == block_nr {
                *(&raw mut CACHE_AGE[i]) = *(&raw const CACHE_TICK);
                *(&raw mut CACHE_TICK) += 1;
                return (CACHE_VADDR + (i as u64) * CACHE_SLOT_SIZE as u64) as *const u8;
            }
        }

        // Cache miss: find LRU slot
        let mut oldest_idx = 0usize;
        let mut oldest_age = u32::MAX;
        for i in 0..CACHE_SLOTS {
            if *(&raw const CACHE_BLOCK_NR[i]) == u64::MAX {
                oldest_idx = i;
                break;
            }
            if *(&raw const CACHE_AGE[i]) < oldest_age {
                oldest_age = *(&raw const CACHE_AGE[i]);
                oldest_idx = i;
            }
        }

        // Read block from disk via blkdrv SHM
        let bs = *(&raw const BLOCK_SIZE);
        let sectors_per_block = bs / SECTOR_SIZE;
        let start_sector = block_nr * sectors_per_block;

        // Use SHM offset 0 as scratch for reading
        if !blk_read_sectors(start_sector, sectors_per_block, 0) {
            return core::ptr::null();
        }

        // Copy from SHM to cache slot
        let cache_ptr = (CACHE_VADDR + (oldest_idx as u64) * CACHE_SLOT_SIZE as u64) as *mut u8;
        let shm_ptr = SHM_VADDR as *const u8;
        for j in 0..bs as usize {
            *cache_ptr.add(j) = *shm_ptr.add(j);
        }

        *(&raw mut CACHE_BLOCK_NR[oldest_idx]) = block_nr;
        *(&raw mut CACHE_AGE[oldest_idx]) = *(&raw const CACHE_TICK);
        *(&raw mut CACHE_TICK) += 1;

        cache_ptr as *const u8
    }
}

// ======================================================================
// B-tree traversal
// ======================================================================

/// Search a leaf node for an item matching the given key.
/// Returns pointer to item data within the block, and its size.
fn btree_leaf_find(
    block_data: *const u8,
    key: &BTreeKey,
) -> Option<(*const u8, u32)> {
    unsafe {
        let hdr = &*(block_data as *const BTreeNodeHeader);
        if hdr.level != 0 {
            return None; // not a leaf
        }

        let items_start = block_data.add(core::mem::size_of::<BTreeNodeHeader>());
        let item_size = core::mem::size_of::<BTreeItem>();

        for i in 0..hdr.num_items as usize {
            let item_ptr = items_start.add(i * item_size) as *const BTreeItem;
            let item = core::ptr::read_unaligned(item_ptr);
            if item.key.cmp(key) == core::cmp::Ordering::Equal {
                let data_ptr = block_data.add(item.offset as usize);
                return Some((data_ptr, item.size));
            }
        }
        None
    }
}

/// Search a leaf node for all items with matching object_id and item_type.
/// Calls the callback for each match. Returns number found.
fn btree_leaf_find_all<F>(
    block_data: *const u8,
    object_id: u64,
    item_type: u8,
    mut callback: F,
) -> u32
where
    F: FnMut(&BTreeKey, *const u8, u32),
{
    unsafe {
        let hdr = &*(block_data as *const BTreeNodeHeader);
        if hdr.level != 0 {
            return 0;
        }

        let items_start = block_data.add(core::mem::size_of::<BTreeNodeHeader>());
        let item_size = core::mem::size_of::<BTreeItem>();
        let mut count = 0u32;

        for i in 0..hdr.num_items as usize {
            let item_ptr = items_start.add(i * item_size) as *const BTreeItem;
            let item = core::ptr::read_unaligned(item_ptr);
            if item.key.object_id == object_id && item.key.item_type == item_type {
                let data_ptr = block_data.add(item.offset as usize);
                callback(&item.key, data_ptr, item.size);
                count += 1;
            }
        }
        count
    }
}

/// Walk the B-tree from root to find the leaf containing the given key.
/// Returns pointer to the leaf block data, or null if not found.
fn btree_search(root_block: u64, key: &BTreeKey) -> *const u8 {
    let mut current_block = root_block;

    for _depth in 0..16 {
        let data = read_block(current_block);
        if data.is_null() {
            return core::ptr::null();
        }

        let hdr = unsafe { &*(data as *const BTreeNodeHeader) };

        // Verify magic
        if hdr.magic != BTREE_NODE_MAGIC {
            return core::ptr::null();
        }

        // Verify checksum
        let bs = unsafe { *(&raw const BLOCK_SIZE) } as usize;
        let computed = crc32c_btree_node(data, bs);
        if computed != hdr.checksum {
            return core::ptr::null();
        }

        // Leaf node: return it
        if hdr.level == 0 {
            return data;
        }

        // Internal node: binary search for child
        let ptrs_start = unsafe {
            data.add(core::mem::size_of::<BTreeNodeHeader>())
        };
        let ptr_size = core::mem::size_of::<BTreePointer>();
        let num_ptrs = hdr.num_items as usize;

        if num_ptrs == 0 {
            return core::ptr::null();
        }

        // Find the rightmost pointer whose key <= search key
        let mut child_block = unsafe {
            let p = core::ptr::read_unaligned(ptrs_start as *const BTreePointer);
            p.block_nr
        };

        for i in 0..num_ptrs {
            let p = unsafe {
                core::ptr::read_unaligned(ptrs_start.add(i * ptr_size) as *const BTreePointer)
            };
            if p.key.cmp(key) != core::cmp::Ordering::Greater {
                child_block = p.block_nr;
            } else {
                break;
            }
        }

        current_block = child_block;
    }

    core::ptr::null() // max depth exceeded
}

/// Search the B-tree for a specific item.
fn btree_find_item(root_block: u64, key: &BTreeKey) -> Option<(*const u8, u32)> {
    let leaf = btree_search(root_block, key);
    if leaf.is_null() {
        return None;
    }
    btree_leaf_find(leaf, key)
}

// ======================================================================
// Filesystem operations
// ======================================================================

/// Read the superblock from block 0.
fn read_superblock() -> bool {
    let data = read_block(0);
    if data.is_null() {
        puts(b"[saltyfs] Failed to read superblock\n");
        return false;
    }

    unsafe {
        let sb = &*(data as *const Superblock);

        // Verify magic
        if sb.magic != SALTYFS_MAGIC {
            puts(b"[saltyfs] Bad superblock magic\n");
            // Try backup superblock at block 1
            let data2 = read_block(1);
            if data2.is_null() {
                return false;
            }
            let sb2 = &*(data2 as *const Superblock);
            if sb2.magic != SALTYFS_MAGIC {
                puts(b"[saltyfs] Backup superblock also bad\n");
                return false;
            }
            *(&raw mut SB) = *sb2;
        } else {
            *(&raw mut SB) = *sb;
        }

        // Verify checksum
        let computed = crc32c_superblock(&*(&raw const SB));
        if computed != (*(&raw const SB)).checksum {
            let mut lb = LineBuf::new();
            lb.str(b"[saltyfs] Superblock checksum mismatch: expected=");
            lb.hex((*(&raw const SB)).checksum as u64);
            lb.str(b" computed=");
            lb.hex(computed as u64);
            lb.putc(b'\n');
            lb.flush();
            return false;
        }

        *(&raw mut BLOCK_SIZE) = (*(&raw const SB)).block_size;

        {
            let mut lb = LineBuf::new();
            lb.str(b"[saltyfs] Mounted: blocks=");
            lb.dec((*(&raw const SB)).total_blocks);
            lb.str(b" used=");
            lb.dec((*(&raw const SB)).used_blocks);
            lb.str(b" bs=");
            lb.dec((*(&raw const SB)).block_size);
            lb.str(b" root_tree=");
            lb.dec((*(&raw const SB)).root_tree);
            lb.str(b" root_ino=");
            lb.dec((*(&raw const SB)).root_inode);
            lb.putc(b'\n');
            lb.flush();
        }
    }

    true
}

/// Look up a directory entry by name within a directory inode.
fn lookup_in_dir(dir_ino: u64, name: *const u8, name_len: u8) -> Option<u64> {
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
fn get_inode(ino: u64) -> Option<SaltyInode> {
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

// ======================================================================
// SHM setup
// ======================================================================

fn setup_blk_shm() -> bool {
    let ctx = ipc_ctx();

    // Get SHM ID from blkdrv
    let mut msg = SaltyMsg::zeroed();
    msg.label = BLK_GET_SHM_ID;
    msg.length = 0;

    let mut reply = SaltyMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_BLKDRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        puts(b"[saltyfs] Failed to get SHM ID from blkdrv\n");
        return false;
    }

    unsafe { *(&raw mut BLK_SHM_ID) = reply.regs[0]; }

    // Map the SHM into our address space
    let mut msg = SaltyMsg::zeroed();
    msg.label = MM_SHM_MAP;
    msg.length = 4;
    msg.regs[0] = unsafe { *(&raw const BLK_SHM_ID) };
    msg.regs[1] = 0; // badge (self)
    msg.regs[2] = SHM_VADDR;
    msg.regs[3] = 0x3; // RW

    let mut reply = SaltyMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[saltyfs] SHM map failed: ");
        lb.dec(if err != 0 { err as u64 } else { reply.label });
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    puts(b"[saltyfs] SHM mapped from blkdrv\n");
    true
}

/// Allocate cache memory via mmsrv
fn setup_cache() -> bool {
    let ctx = ipc_ctx();

    // Allocate pages for block cache
    let mut msg = SaltyMsg::zeroed();
    msg.label = MM_SHM_CREATE;
    msg.length = 2;
    msg.regs[0] = 0x53465343; // "SFSC" - saltyfs cache
    msg.regs[1] = CACHE_TOTAL_PAGES;

    let mut reply = SaltyMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || (reply.label != 0 && reply.label != SALTY_ALREADY_EXISTS) {
        puts(b"[saltyfs] Cache SHM create failed\n");
        return false;
    }

    let mut msg = SaltyMsg::zeroed();
    msg.label = MM_SHM_MAP;
    msg.length = 4;
    msg.regs[0] = 0x53465343;
    msg.regs[1] = 0;
    msg.regs[2] = CACHE_VADDR;
    msg.regs[3] = 0x3; // RW

    let mut reply = SaltyMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        puts(b"[saltyfs] Cache SHM map failed\n");
        return false;
    }

    puts(b"[saltyfs] Block cache allocated\n");
    true
}

// ======================================================================
// IPC request handlers
// ======================================================================

fn handle_mount() -> SaltyMsg {
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

fn handle_lookup(msg: &SaltyMsg) -> SaltyMsg {
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

fn handle_read(msg: &SaltyMsg) -> SaltyMsg {
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

fn handle_readdir(msg: &SaltyMsg) -> SaltyMsg {
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

fn handle_stat(msg: &SaltyMsg) -> SaltyMsg {
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

fn handle_getinfo() -> SaltyMsg {
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
fn handle_read_inline(msg: &SaltyMsg) -> SaltyMsg {
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

// ======================================================================
// Name service registration
// ======================================================================

fn register_nameserv() {
    let name = b"saltyfs";
    let mut msg = SaltyMsg::zeroed();
    msg.label = POSIX_NS_REGISTER;
    msg.regs[0] = name.len() as u64;
    msg.length = 1 + (name.len() as u64 + 7) / 8;
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            *dst.add(i) = name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
        let mut reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), CAP_NAMESERV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
            puts(b"[saltyfs] nameserv registration failed\n");
        }
    }
}

// ======================================================================
// Server main loop
// ======================================================================

fn server_loop() -> ! {
    puts(b"[saltyfs] Entering server loop\n");

    let ctx = ipc_ctx();
    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;
    unsafe { ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge); }

    loop {
        let reply = match msg.label {
            SALTYFS_MOUNT => handle_mount(),
            SALTYFS_LOOKUP => handle_lookup(&msg),
            SALTYFS_READ => handle_read(&msg),
            SALTYFS_READDIR => handle_readdir(&msg),
            SALTYFS_STAT => handle_stat(&msg),
            SALTYFS_GETINFO => handle_getinfo(),
            SALTYFS_READ_INLINE => handle_read_inline(&msg),
            _ => {
                let mut r = SaltyMsg::zeroed();
                r.label = SALTY_INVALID_OPERATION;
                r
            }
        };

        msg = SaltyMsg::zeroed();
        badge = 0;
        unsafe {
            ipc::reply_recv_ctx(
                ctx, CAP_SERVER_EP, &raw const reply, &raw mut msg, &raw mut badge,
            );
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[saltyfs] SaltyFS Server starting\n");

    let _ = invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    unsafe {
        (*ipc_ctx()).ipc_buffer = IPC_BUF_VADDR as *mut IpcBuffer;
    }

    // Set up SHM from blkdrv
    if !setup_blk_shm() {
        puts(b"[saltyfs] Failed to set up blkdrv SHM -- cannot operate\n");
    }

    // Set up block cache
    if !setup_cache() {
        puts(b"[saltyfs] Failed to set up block cache\n");
    }

    // Auto-mount on startup
    if !read_superblock() {
        puts(b"[saltyfs] No SaltyFS partition found -- running without mount\n");
    } else {
        unsafe { *(&raw mut MOUNTED) = true; }
    }

    // Register with name service
    register_nameserv();

    // Signal readiness
    signal_ready();

    // Enter server loop
    server_loop()
}
