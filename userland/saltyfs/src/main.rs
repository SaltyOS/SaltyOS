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
static mut CACHE_DIRTY: [bool; CACHE_SLOTS] = [false; CACHE_SLOTS];

/// Next inode number to allocate
static mut NEXT_INO: u64 = 2;

/// Bitmap block allocator
const BITMAP_CACHE_SLOTS: usize = 4;
static mut BITMAP_CACHE: [[u8; 4096]; BITMAP_CACHE_SLOTS] = [[0; 4096]; BITMAP_CACHE_SLOTS];
static mut BITMAP_CACHE_BLOCK: [u64; BITMAP_CACHE_SLOTS] = [u64::MAX; BITMAP_CACHE_SLOTS];
static mut BITMAP_CACHE_DIRTY: [bool; BITMAP_CACHE_SLOTS] = [false; BITMAP_CACHE_SLOTS];
static mut BITMAP_BLOCK_COUNT: u64 = 0;
static mut ALLOC_HINT: u64 = 0;

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

/// Write sectors to blkdrv from SHM at given offset.
fn blk_write_sectors(start_sector: u64, count: u64, shm_offset: u64) -> bool {
    let mut msg = SaltyMsg::zeroed();
    msg.label = BLK_WRITE;
    msg.length = 3;
    msg.regs[0] = start_sector;
    msg.regs[1] = count;
    msg.regs[2] = shm_offset;

    let mut reply = SaltyMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_BLKDRV_EP, &raw const msg, &raw mut reply) };
    err == 0 && reply.label == 0
}

/// Write a 4KB block to disk.
fn write_block(block_nr: u64, data: *const u8) -> bool {
    unsafe {
        let bs = *(&raw const BLOCK_SIZE);
        let sectors_per_block = bs / SECTOR_SIZE;
        // Copy data to SHM offset 0
        let shm = SHM_VADDR as *mut u8;
        for i in 0..bs as usize {
            *shm.add(i) = *data.add(i);
        }
        blk_write_sectors(block_nr * sectors_per_block, sectors_per_block, 0)
    }
}

/// Get a mutable pointer to a cached block, marking it dirty.
fn read_block_mut(block_nr: u64) -> *mut u8 {
    let ptr = read_block(block_nr);
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        for i in 0..CACHE_SLOTS {
            if *(&raw const CACHE_BLOCK_NR[i]) == block_nr {
                *(&raw mut CACHE_DIRTY[i]) = true;
                return (CACHE_VADDR + (i as u64) * CACHE_SLOT_SIZE as u64) as *mut u8;
            }
        }
    }
    core::ptr::null_mut()
}

/// Flush a single dirty block from cache to disk.
fn cache_flush_block(block_nr: u64) -> bool {
    unsafe {
        for i in 0..CACHE_SLOTS {
            if *(&raw const CACHE_BLOCK_NR[i]) == block_nr && *(&raw const CACHE_DIRTY[i]) {
                let ptr = (CACHE_VADDR + (i as u64) * CACHE_SLOT_SIZE as u64) as *const u8;
                if !write_block(block_nr, ptr) {
                    return false;
                }
                *(&raw mut CACHE_DIRTY[i]) = false;
                return true;
            }
        }
    }
    true
}

/// Remove a block from the cache.
fn cache_invalidate(block_nr: u64) {
    unsafe {
        for i in 0..CACHE_SLOTS {
            if *(&raw const CACHE_BLOCK_NR[i]) == block_nr {
                *(&raw mut CACHE_BLOCK_NR[i]) = u64::MAX;
                *(&raw mut CACHE_DIRTY[i]) = false;
                break;
            }
        }
    }
}

/// Write the superblock to disk (primary + backup).
fn write_superblock() -> bool {
    unsafe {
        let sb = &mut *(&raw mut SB);
        sb.generation += 1;
        // CRC32c with checksum field zeroed
        sb.checksum = 0;
        sb.checksum = crc32c_superblock(sb);
        let sb_ptr = sb as *const Superblock as *const u8;
        if !write_block(0, sb_ptr) {
            return false;
        }
        cache_invalidate(0);
        if !write_block(1, sb_ptr) {
            return false;
        }
        cache_invalidate(1);
        true
    }
}

/// Scan a leaf node for the maximum inode number.
fn scan_leaf_for_max_ino(leaf: *const u8) {
    unsafe {
        let hdr = &*(leaf as *const BTreeNodeHeader);
        if hdr.magic != BTREE_NODE_MAGIC || hdr.level != 0 {
            return;
        }
        let items_start = leaf.add(core::mem::size_of::<BTreeNodeHeader>());
        let item_size = core::mem::size_of::<BTreeItem>();
        let mut max_ino: u64 = (*(&raw const NEXT_INO)).saturating_sub(1);
        for i in 0..hdr.num_items as usize {
            let item = core::ptr::read_unaligned(
                items_start.add(i * item_size) as *const BTreeItem,
            );
            if item.key.item_type == SALTY_INODE_ITEM && item.key.object_id > max_ino {
                max_ino = item.key.object_id;
            }
        }
        *(&raw mut NEXT_INO) = max_ino + 1;
    }
}

/// Scan the B-tree to find the maximum inode number and set NEXT_INO.
/// Uses btree_search with max key to find the last leaf in multi-level trees.
fn discover_max_inode() {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    // Search with the largest possible key to reach the last leaf
    let max_key = BTreeKey {
        object_id: u64::MAX,
        item_type: 0xFF,
        offset: u64::MAX,
    };
    let leaf = btree_search(root_tree, &max_key);
    if !leaf.is_null() {
        scan_leaf_for_max_ino(leaf);
        return;
    }
    // Fallback: try root block directly (single-leaf tree)
    let leaf = read_block(root_tree);
    if !leaf.is_null() {
        scan_leaf_for_max_ino(leaf);
    }
}

// ======================================================================
// Bitmap block allocator
// ======================================================================

/// Initialize bitmap allocator from superblock.
fn init_bitmap() {
    unsafe {
        let sb = &*(&raw const SB);
        *(&raw mut BITMAP_BLOCK_COUNT) = (sb.total_blocks + 32768 - 1) / 32768;
        *(&raw mut ALLOC_HINT) = sb.root_tree + 1;
    }
}

/// Load a bitmap block into the bitmap cache. Returns slot index.
fn bitmap_load(bitmap_block_idx: u64) -> Option<usize> {
    unsafe {
        // Cache hit
        for i in 0..BITMAP_CACHE_SLOTS {
            if *(&raw const BITMAP_CACHE_BLOCK[i]) == bitmap_block_idx {
                return Some(i);
            }
        }
        // Find free or LRU slot
        let mut slot = BITMAP_CACHE_SLOTS - 1;
        for i in 0..BITMAP_CACHE_SLOTS {
            if *(&raw const BITMAP_CACHE_BLOCK[i]) == u64::MAX {
                slot = i;
                break;
            }
        }
        // Flush dirty slot
        if *(&raw const BITMAP_CACHE_DIRTY[slot]) {
            let old_block = *(&raw const BITMAP_CACHE_BLOCK[slot]);
            let disk_block = 2 + old_block;
            write_block(disk_block, (*(&raw const BITMAP_CACHE[slot])).as_ptr());
            *(&raw mut BITMAP_CACHE_DIRTY[slot]) = false;
        }
        // Read from disk
        let disk_block = 2 + bitmap_block_idx;
        let data = read_block(disk_block);
        if data.is_null() {
            return None;
        }
        for j in 0..4096 {
            (*(&raw mut BITMAP_CACHE[slot]))[j] = *data.add(j);
        }
        *(&raw mut BITMAP_CACHE_BLOCK[slot]) = bitmap_block_idx;
        Some(slot)
    }
}

/// Allocate a free block. Returns block number.
fn alloc_block() -> Option<u64> {
    unsafe {
        let total = (*(&raw const SB)).total_blocks;
        let hint = *(&raw const ALLOC_HINT);
        for offset in 0..total {
            let block_nr = (hint + offset) % total;
            let bitmap_idx = block_nr / 32768;
            let bit_in_block = (block_nr % 32768) as usize;
            let byte_idx = bit_in_block / 8;
            let bit_idx = bit_in_block % 8;

            let slot = bitmap_load(bitmap_idx)?;
            if ((*(&raw const BITMAP_CACHE[slot]))[byte_idx] & (1 << bit_idx)) == 0 {
                (*(&raw mut BITMAP_CACHE[slot]))[byte_idx] |= 1 << bit_idx;
                *(&raw mut BITMAP_CACHE_DIRTY[slot]) = true;
                *(&raw mut ALLOC_HINT) = block_nr + 1;
                (*(&raw mut SB)).used_blocks += 1;
                return Some(block_nr);
            }
        }
        None
    }
}

/// Free a previously allocated block.
fn free_block(block_nr: u64) {
    unsafe {
        let bitmap_idx = block_nr / 32768;
        let bit_in_block = (block_nr % 32768) as usize;
        let byte_idx = bit_in_block / 8;
        let bit_idx = bit_in_block % 8;
        if let Some(slot) = bitmap_load(bitmap_idx) {
            (*(&raw mut BITMAP_CACHE[slot]))[byte_idx] &= !(1 << bit_idx);
            *(&raw mut BITMAP_CACHE_DIRTY[slot]) = true;
            (*(&raw mut SB)).used_blocks =
                (*(&raw const SB)).used_blocks.saturating_sub(1);
        }
    }
}

/// Flush all dirty bitmap cache entries to disk.
fn bitmap_flush() -> bool {
    unsafe {
        for i in 0..BITMAP_CACHE_SLOTS {
            if *(&raw const BITMAP_CACHE_DIRTY[i]) {
                let disk_block = 2 + *(&raw const BITMAP_CACHE_BLOCK[i]);
                if !write_block(disk_block, (*(&raw const BITMAP_CACHE[i])).as_ptr()) {
                    return false;
                }
                *(&raw mut BITMAP_CACHE_DIRTY[i]) = false;
            }
        }
    }
    true
}

// ======================================================================
// Block I/O (read_block)
// ======================================================================

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

        // Flush dirty block before eviction
        if *(&raw const CACHE_DIRTY[oldest_idx]) {
            let evict_block = *(&raw const CACHE_BLOCK_NR[oldest_idx]);
            let evict_ptr =
                (CACHE_VADDR + (oldest_idx as u64) * CACHE_SLOT_SIZE as u64) as *const u8;
            if !write_block(evict_block, evict_ptr) {
                return core::ptr::null();
            }
            *(&raw mut CACHE_DIRTY[oldest_idx]) = false;
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
// COW B-tree modification operations
// ======================================================================

const MAX_BTREE_DEPTH: usize = 8;

struct BTreePath {
    blocks: [u64; MAX_BTREE_DEPTH],
    indices: [u32; MAX_BTREE_DEPTH],
    depth: usize,
}

/// Walk the B-tree from root to leaf, recording the path for COW propagation.
fn btree_search_path(root_block: u64, key: &BTreeKey) -> Option<BTreePath> {
    let mut path = BTreePath {
        blocks: [0; MAX_BTREE_DEPTH],
        indices: [0; MAX_BTREE_DEPTH],
        depth: 0,
    };
    let mut current_block = root_block;
    let mut level = 0;

    loop {
        if level >= MAX_BTREE_DEPTH {
            return None;
        }
        path.blocks[level] = current_block;

        let data = read_block(current_block);
        if data.is_null() {
            return None;
        }
        let hdr = unsafe { &*(data as *const BTreeNodeHeader) };
        if hdr.magic != BTREE_NODE_MAGIC {
            return None;
        }

        if hdr.level == 0 {
            path.depth = level;
            return Some(path);
        }

        // Internal node: find child
        let ptrs_start = unsafe { data.add(core::mem::size_of::<BTreeNodeHeader>()) };
        let ptr_size = core::mem::size_of::<BTreePointer>();
        let num_ptrs = hdr.num_items as usize;
        if num_ptrs == 0 {
            return None;
        }

        let mut child_idx = 0u32;
        let mut child_block = unsafe {
            core::ptr::read_unaligned(ptrs_start as *const BTreePointer).block_nr
        };
        for i in 0..num_ptrs {
            let p = unsafe {
                core::ptr::read_unaligned(ptrs_start.add(i * ptr_size) as *const BTreePointer)
            };
            if p.key.cmp(key) != core::cmp::Ordering::Greater {
                child_block = p.block_nr;
                child_idx = i as u32;
            } else {
                break;
            }
        }
        path.indices[level] = child_idx;
        current_block = child_block;
        level += 1;
    }
}

/// Allocate a new block and copy the contents of an existing block into it.
fn cow_copy_block(old_block: u64) -> Option<u64> {
    let new_block = alloc_block()?;
    let old_data = read_block(old_block);
    if old_data.is_null() {
        free_block(new_block);
        return None;
    }

    let mut buf = [0u8; 4096];
    unsafe {
        for i in 0..4096 {
            buf[i] = *old_data.add(i);
        }
    }

    // Update header: block_nr and generation
    unsafe {
        let hdr = &mut *(buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.block_nr = new_block;
        hdr.generation = (*(&raw const SB)).generation + 1;
    }

    // Recompute CRC32c
    let bs = unsafe { *(&raw const BLOCK_SIZE) } as usize;
    unsafe {
        let hdr = &mut *(buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.checksum = 0;
    }
    let checksum = crc32c_btree_node(buf.as_ptr(), bs);
    unsafe {
        let hdr = &mut *(buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.checksum = checksum;
    }

    if !write_block(new_block, buf.as_ptr()) {
        free_block(new_block);
        return None;
    }
    Some(new_block)
}

/// COW propagate from a modified child up to the root.
/// Returns the new root block number.
fn cow_propagate_up(
    path: &BTreePath,
    start_level: usize,
    new_child_block: u64,
    freed: &mut [u64; MAX_BTREE_DEPTH],
    freed_count: &mut usize,
) -> Option<u64> {
    let mut child_block = new_child_block;

    if start_level == 0 {
        return Some(child_block);
    }

    let mut level = start_level - 1;
    loop {
        let old_parent = path.blocks[level];
        let child_idx = path.indices[level] as usize;

        let new_parent = cow_copy_block(old_parent)?;
        freed[*freed_count] = old_parent;
        *freed_count += 1;

        // Update child pointer in new parent
        let parent_data = read_block_mut(new_parent);
        if parent_data.is_null() {
            return None;
        }
        unsafe {
            let ptrs_start = parent_data.add(core::mem::size_of::<BTreeNodeHeader>());
            let ptr_size = core::mem::size_of::<BTreePointer>();
            let ptr_loc = ptrs_start.add(child_idx * ptr_size);
            // BTreePointer layout: key(17) + block_nr(8) + generation(8)
            let block_nr_offset = 17;
            core::ptr::write_unaligned(
                ptr_loc.add(block_nr_offset) as *mut u64,
                child_block,
            );
            let ngen = (*(&raw const SB)).generation + 1;
            core::ptr::write_unaligned(
                ptr_loc.add(block_nr_offset + 8) as *mut u64,
                ngen,
            );
        }

        // Recompute CRC32c
        let bs = unsafe { *(&raw const BLOCK_SIZE) } as usize;
        unsafe {
            let hdr = &mut *(parent_data as *mut BTreeNodeHeader);
            hdr.checksum = 0;
        }
        let checksum = crc32c_btree_node(parent_data as *const u8, bs);
        unsafe {
            let hdr = &mut *(parent_data as *mut BTreeNodeHeader);
            hdr.checksum = checksum;
        }
        cache_flush_block(new_parent);

        child_block = new_parent;

        if level == 0 {
            break;
        }
        level -= 1;
    }

    Some(child_block)
}

/// Max items we can handle during leaf rebuild.
const MAX_LEAF_ITEMS: usize = 128;

/// Collected item for leaf rebuild.
struct LeafItem {
    key: BTreeKey,
    data: [u8; 256],
    data_len: usize,
}

/// Rebuild a leaf block from a list of items.
fn rebuild_leaf(
    out_buf: &mut [u8; 4096],
    owner: u64,
    generation: u64,
    block_nr: u64,
    items: &[LeafItem],
    count: usize,
) -> bool {
    let hdr_size = core::mem::size_of::<BTreeNodeHeader>();
    let item_entry_size = core::mem::size_of::<BTreeItem>();

    let data_area_start = hdr_size + count * item_entry_size;
    let total_data: usize = items[..count].iter().map(|it| it.data_len).sum();
    if data_area_start + total_data > 4096 {
        return false;
    }

    for b in out_buf.iter_mut() {
        *b = 0;
    }

    unsafe {
        let hdr = &mut *(out_buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.magic = BTREE_NODE_MAGIC;
        hdr.checksum = 0;
        hdr.owner = owner;
        hdr.generation = generation;
        hdr.block_nr = block_nr;
        hdr.num_items = count as u32;
        hdr.level = 0;
        hdr.flags = 0;
    }

    let mut data_offset = data_area_start;
    for i in 0..count {
        let item = BTreeItem {
            key: items[i].key,
            offset: data_offset as u32,
            size: items[i].data_len as u32,
        };
        unsafe {
            core::ptr::write_unaligned(
                out_buf.as_mut_ptr().add(hdr_size + i * item_entry_size) as *mut BTreeItem,
                item,
            );
            for j in 0..items[i].data_len {
                out_buf[data_offset + j] = items[i].data[j];
            }
        }
        data_offset += items[i].data_len;
    }

    let checksum = crc32c_btree_node(out_buf.as_ptr(), 4096);
    unsafe {
        let hdr = &mut *(out_buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.checksum = checksum;
    }
    true
}

/// Collect all items from a leaf block into the items array.
/// Returns the number of items collected.
fn collect_leaf_items(
    leaf_data: *const u8,
    items: &mut [LeafItem; MAX_LEAF_ITEMS],
) -> usize {
    unsafe {
        let hdr = &*(leaf_data as *const BTreeNodeHeader);
        let items_start = leaf_data.add(core::mem::size_of::<BTreeNodeHeader>());
        let item_size = core::mem::size_of::<BTreeItem>();
        let count = (hdr.num_items as usize).min(MAX_LEAF_ITEMS);

        for i in 0..count {
            let item =
                core::ptr::read_unaligned(items_start.add(i * item_size) as *const BTreeItem);
            items[i].key = item.key;
            items[i].data_len = (item.size as usize).min(256);
            let src = leaf_data.add(item.offset as usize);
            for j in 0..items[i].data_len {
                items[i].data[j] = *src.add(j);
            }
        }
        count
    }
}

/// Insert an item into a sorted items array. Returns new count.
fn insert_into_items(
    items: &mut [LeafItem; MAX_LEAF_ITEMS],
    count: usize,
    key: &BTreeKey,
    data: &[u8],
) -> usize {
    if count >= MAX_LEAF_ITEMS {
        return count;
    }

    // Find insertion point
    let mut pos = count;
    for i in 0..count {
        if items[i].key.cmp(key) == core::cmp::Ordering::Greater {
            pos = i;
            break;
        }
    }

    // Shift items right
    let mut i = count;
    while i > pos {
        items[i].key = items[i - 1].key;
        items[i].data_len = items[i - 1].data_len;
        items[i].data = items[i - 1].data;
        i -= 1;
    }

    // Insert new item
    items[pos].key = *key;
    items[pos].data_len = data.len().min(256);
    for j in 0..items[pos].data_len {
        items[pos].data[j] = data[j];
    }

    count + 1
}

/// Remove an item from a sorted items array by key. Returns new count.
fn remove_from_items(
    items: &mut [LeafItem; MAX_LEAF_ITEMS],
    count: usize,
    key: &BTreeKey,
) -> usize {
    for i in 0..count {
        if items[i].key.cmp(key) == core::cmp::Ordering::Equal {
            // Shift left
            for j in i..count - 1 {
                items[j].key = items[j + 1].key;
                items[j].data_len = items[j + 1].data_len;
                items[j].data = items[j + 1].data;
            }
            return count - 1;
        }
    }
    count
}

/// Build a new internal (level>0) node with two children.
fn build_internal_node(
    out_buf: &mut [u8; 4096],
    generation: u64,
    block_nr: u64,
    level: u16,
    left_key: &BTreeKey,
    left_block: u64,
    right_key: &BTreeKey,
    right_block: u64,
) -> bool {
    for b in out_buf.iter_mut() {
        *b = 0;
    }

    unsafe {
        let hdr = &mut *(out_buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.magic = BTREE_NODE_MAGIC;
        hdr.checksum = 0;
        hdr.owner = 0;
        hdr.generation = generation;
        hdr.block_nr = block_nr;
        hdr.num_items = 2;
        hdr.level = level;
        hdr.flags = 0;
    }

    let hdr_size = core::mem::size_of::<BTreeNodeHeader>();
    let ptr_size = core::mem::size_of::<BTreePointer>();

    let left_ptr = BTreePointer {
        key: *left_key,
        block_nr: left_block,
        generation,
    };
    let right_ptr = BTreePointer {
        key: *right_key,
        block_nr: right_block,
        generation,
    };

    unsafe {
        core::ptr::write_unaligned(
            out_buf.as_mut_ptr().add(hdr_size) as *mut BTreePointer,
            left_ptr,
        );
        core::ptr::write_unaligned(
            out_buf.as_mut_ptr().add(hdr_size + ptr_size) as *mut BTreePointer,
            right_ptr,
        );
    }

    let checksum = crc32c_btree_node(out_buf.as_ptr(), 4096);
    unsafe {
        let hdr = &mut *(out_buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.checksum = checksum;
    }
    true
}

/// After a leaf split at non-root depth, insert right_block as a sibling
/// next to left_block in its parent internal node.
/// Walks from SB.root_tree to find the internal node containing left_block,
/// COW-inserts the right pointer, and propagates changes up to root.
fn insert_right_sibling(
    search_root: u64,
    left_block: u64,
    right_key: &BTreeKey,
    right_block: u64,
) -> Option<u64> {
    let ngen = unsafe { (*(&raw const SB)).generation + 1 };

    // Walk tree to find the internal node containing left_block as a child
    let mut path_blocks = [0u64; MAX_BTREE_DEPTH];
    let mut path_indices = [0u32; MAX_BTREE_DEPTH];
    let mut depth = 0usize;
    let mut current_block = search_root;

    let mut found_parent: u64 = 0;
    let mut found_child_idx: usize = 0;

    loop {
        if depth >= MAX_BTREE_DEPTH {
            return None;
        }
        let data = read_block(current_block);
        if data.is_null() {
            return None;
        }
        let hdr = unsafe { &*(data as *const BTreeNodeHeader) };
        if hdr.magic != BTREE_NODE_MAGIC || hdr.level == 0 {
            return None;
        }

        let ptrs_start = unsafe { data.add(core::mem::size_of::<BTreeNodeHeader>()) };
        let ptr_size = core::mem::size_of::<BTreePointer>();
        let num_ptrs = hdr.num_items as usize;

        // Search for left_block among children
        let mut found = false;
        for i in 0..num_ptrs {
            let p = unsafe {
                core::ptr::read_unaligned(ptrs_start.add(i * ptr_size) as *const BTreePointer)
            };
            if p.block_nr == left_block {
                found_parent = current_block;
                found_child_idx = i;
                found = true;
                break;
            }
        }
        if found {
            break;
        }

        // Descend using right_key to guide navigation
        path_blocks[depth] = current_block;
        let mut next_child_idx = 0u32;
        let mut next_child = unsafe {
            core::ptr::read_unaligned(ptrs_start as *const BTreePointer).block_nr
        };
        for i in 0..num_ptrs {
            let p = unsafe {
                core::ptr::read_unaligned(ptrs_start.add(i * ptr_size) as *const BTreePointer)
            };
            if p.key.cmp(right_key) != core::cmp::Ordering::Greater {
                next_child = p.block_nr;
                next_child_idx = i as u32;
            } else {
                break;
            }
        }
        path_indices[depth] = next_child_idx;
        current_block = next_child;
        depth += 1;
    }

    let parent_block = found_parent;
    let child_idx = found_child_idx;

    // Insert right_key/right_block at position child_idx + 1 in parent
    let parent_data = read_block(parent_block);
    if parent_data.is_null() {
        return None;
    }
    let parent_hdr = unsafe { &*(parent_data as *const BTreeNodeHeader) };
    let num_ptrs = parent_hdr.num_items as usize;
    let ptr_size = core::mem::size_of::<BTreePointer>();
    let hdr_size = core::mem::size_of::<BTreeNodeHeader>();
    let max_ptrs = (4096 - hdr_size) / ptr_size;

    if num_ptrs >= max_ptrs {
        // Internal node is full — extremely rare (>122 children). Fail gracefully.
        return None;
    }

    // COW the parent and insert the pointer
    let new_parent = match cow_copy_block(parent_block) {
        Some(b) => b,
        None => return None,
    };
    let new_parent_data = read_block_mut(new_parent);
    if new_parent_data.is_null() {
        free_block(new_parent);
        return None;
    }

    unsafe {
        let ptrs_start = new_parent_data.add(hdr_size);
        let insert_pos = child_idx + 1;
        // Shift pointers right to make room
        let mut i = num_ptrs;
        while i > insert_pos {
            let src = ptrs_start.add((i - 1) * ptr_size);
            let dst = ptrs_start.add(i * ptr_size) as *mut u8;
            for b in 0..ptr_size {
                *dst.add(b) = *src.add(b);
            }
            i -= 1;
        }
        // Write new pointer
        let new_ptr = BTreePointer {
            key: *right_key,
            block_nr: right_block,
            generation: ngen,
        };
        core::ptr::write_unaligned(
            ptrs_start.add(insert_pos * ptr_size) as *mut BTreePointer,
            new_ptr,
        );
        // Update header
        let hdr = &mut *(new_parent_data as *mut BTreeNodeHeader);
        hdr.num_items = (num_ptrs + 1) as u32;
        hdr.generation = ngen;
        hdr.checksum = 0;
    }
    let checksum = crc32c_btree_node(new_parent_data as *const u8, 4096);
    unsafe {
        let hdr = &mut *(new_parent_data as *mut BTreeNodeHeader);
        hdr.checksum = checksum;
    }
    cache_flush_block(new_parent);

    // Propagate new_parent up — returns the final root without touching SB
    if depth == 0 {
        // parent_block was the root — new_parent replaces it
        free_block(parent_block);
        Some(new_parent)
    } else {
        let prop_path = BTreePath {
            blocks: path_blocks,
            indices: path_indices,
            depth,
        };
        let mut freed = [0u64; MAX_BTREE_DEPTH];
        let mut freed_count = 0usize;
        let final_root = match cow_propagate_up(
            &prop_path, depth, new_parent, &mut freed, &mut freed_count,
        ) {
            Some(r) => r,
            None => return None,
        };
        free_block(parent_block);
        for i in 0..freed_count {
            free_block(freed[i]);
        }
        Some(final_root)
    }
}

/// COW B-tree insert with leaf split when leaf is full.
fn btree_cow_insert_split(
    path: &BTreePath,
    items: &mut [LeafItem; MAX_LEAF_ITEMS],
    total_count: usize,
) -> bool {
    let ngen =unsafe { (*(&raw const SB)).generation + 1 };
    let leaf_block = path.blocks[path.depth];

    // Split at midpoint
    let mid = total_count / 2;

    // Allocate two new leaf blocks
    let left_block = match alloc_block() {
        Some(b) => b,
        None => return false,
    };
    let right_block = match alloc_block() {
        Some(b) => b,
        None => {
            free_block(left_block);
            return false;
        }
    };

    // Build left leaf
    let mut left_buf = [0u8; 4096];
    if !rebuild_leaf(&mut left_buf, 0, ngen,left_block, items, mid) {
        free_block(left_block);
        free_block(right_block);
        return false;
    }
    if !write_block(left_block, left_buf.as_ptr()) {
        free_block(left_block);
        free_block(right_block);
        return false;
    }

    // Build right leaf (items[mid..total_count])
    let mut right_items: [LeafItem; MAX_LEAF_ITEMS] = unsafe { core::mem::zeroed() };
    let right_count = total_count - mid;
    for i in 0..right_count {
        right_items[i].key = items[mid + i].key;
        right_items[i].data_len = items[mid + i].data_len;
        right_items[i].data = items[mid + i].data;
    }
    let mut right_buf = [0u8; 4096];
    if !rebuild_leaf(&mut right_buf, 0, ngen,right_block, &right_items, right_count) {
        free_block(left_block);
        free_block(right_block);
        return false;
    }
    if !write_block(right_block, right_buf.as_ptr()) {
        free_block(left_block);
        free_block(right_block);
        return false;
    }

    let left_key = items[0].key;
    let right_key = items[mid].key;

    if path.depth == 0 {
        // Root was a leaf — create new internal root
        let new_root = match alloc_block() {
            Some(b) => b,
            None => {
                free_block(left_block);
                free_block(right_block);
                return false;
            }
        };
        let mut root_buf = [0u8; 4096];
        build_internal_node(
            &mut root_buf, ngen, new_root, 1,
            &left_key, left_block,
            &right_key, right_block,
        );
        if !write_block(new_root, root_buf.as_ptr()) {
            free_block(left_block);
            free_block(right_block);
            free_block(new_root);
            return false;
        }

        free_block(leaf_block);
        unsafe {
            (*(&raw mut SB)).root_tree = new_root;
        }
    } else {
        // Non-root leaf split: propagate left_block up, then insert right_block
        // Both steps must complete before SB is committed.

        // Step 1: Propagate left_block up (replaces old leaf pointer in parent)
        // Do NOT update SB yet — compute new_root only.
        let mut freed = [0u64; MAX_BTREE_DEPTH];
        let mut freed_count = 0usize;
        let new_root = match cow_propagate_up(
            path, path.depth, left_block, &mut freed, &mut freed_count,
        ) {
            Some(r) => r,
            None => {
                free_block(left_block);
                free_block(right_block);
                return false;
            }
        };

        // Step 2: Insert right_block into parent using the uncommitted new_root
        let final_root = match insert_right_sibling(new_root, left_block, &right_key, right_block) {
            Some(r) => r,
            None => {
                // Rollback: free new blocks, keep leaf_block intact
                free_block(left_block);
                free_block(right_block);
                free_block(new_root);
                for i in 0..freed_count {
                    free_block(freed[i]);
                }
                return false;
            }
        };

        // Both steps succeeded — now commit: update SB and free old blocks
        free_block(leaf_block);
        unsafe {
            (*(&raw mut SB)).root_tree = final_root;
        }
        for i in 0..freed_count {
            free_block(freed[i]);
        }
    }

    if !bitmap_flush() { return false; }
    write_superblock();
    true
}

/// Insert an item into the B-tree using COW.
fn btree_cow_insert(key: &BTreeKey, data: &[u8]) -> bool {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let path = match btree_search_path(root_tree, key) {
        Some(p) => p,
        None => return false,
    };

    let leaf_block = path.blocks[path.depth];
    let leaf_data = read_block(leaf_block);
    if leaf_data.is_null() {
        return false;
    }

    // Collect existing items + insert new one
    let mut items: [LeafItem; MAX_LEAF_ITEMS] = unsafe { core::mem::zeroed() };
    let count = collect_leaf_items(leaf_data, &mut items);
    let total_count = insert_into_items(&mut items, count, key, data);

    // Try to fit in a single leaf
    let new_leaf = match alloc_block() {
        Some(b) => b,
        None => return false,
    };

    let ngen =unsafe { (*(&raw const SB)).generation + 1 };
    let mut leaf_buf = [0u8; 4096];
    if !rebuild_leaf(&mut leaf_buf, 0, ngen,new_leaf, &items, total_count) {
        // Leaf is full — need to split
        free_block(new_leaf);
        return btree_cow_insert_split(&path, &mut items, total_count);
    }

    if !write_block(new_leaf, leaf_buf.as_ptr()) {
        free_block(new_leaf);
        return false;
    }

    // COW propagate up
    let mut freed = [0u64; MAX_BTREE_DEPTH];
    let mut freed_count = 0usize;
    let new_root = match cow_propagate_up(
        &path, path.depth, new_leaf, &mut freed, &mut freed_count,
    ) {
        Some(r) => r,
        None => return false,
    };

    unsafe {
        (*(&raw mut SB)).root_tree = new_root;
    }

    // Free old blocks
    free_block(leaf_block);
    for i in 0..freed_count {
        free_block(freed[i]);
    }

    if !bitmap_flush() { return false; }
    write_superblock();
    true
}

/// Delete an item from the B-tree using COW.
fn btree_cow_delete(key: &BTreeKey) -> bool {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let path = match btree_search_path(root_tree, key) {
        Some(p) => p,
        None => return false,
    };

    let leaf_block = path.blocks[path.depth];
    let leaf_data = read_block(leaf_block);
    if leaf_data.is_null() {
        return false;
    }

    let mut items: [LeafItem; MAX_LEAF_ITEMS] = unsafe { core::mem::zeroed() };
    let count = collect_leaf_items(leaf_data, &mut items);
    let new_count = remove_from_items(&mut items, count, key);
    if new_count == count {
        return false; // item not found
    }

    let new_leaf = match alloc_block() {
        Some(b) => b,
        None => return false,
    };

    let ngen =unsafe { (*(&raw const SB)).generation + 1 };
    let mut leaf_buf = [0u8; 4096];
    if !rebuild_leaf(&mut leaf_buf, 0, ngen,new_leaf, &items, new_count) {
        free_block(new_leaf);
        return false;
    }

    if !write_block(new_leaf, leaf_buf.as_ptr()) {
        free_block(new_leaf);
        return false;
    }

    let mut freed = [0u64; MAX_BTREE_DEPTH];
    let mut freed_count = 0usize;
    let new_root = match cow_propagate_up(
        &path, path.depth, new_leaf, &mut freed, &mut freed_count,
    ) {
        Some(r) => r,
        None => return false,
    };

    unsafe {
        (*(&raw mut SB)).root_tree = new_root;
    }

    free_block(leaf_block);
    for i in 0..freed_count {
        free_block(freed[i]);
    }

    if !bitmap_flush() { return false; }
    write_superblock();
    true
}

/// Update an existing item's data in the B-tree using COW.
fn btree_cow_update(key: &BTreeKey, data: &[u8]) -> bool {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let path = match btree_search_path(root_tree, key) {
        Some(p) => p,
        None => return false,
    };

    let leaf_block = path.blocks[path.depth];
    let leaf_data = read_block(leaf_block);
    if leaf_data.is_null() {
        return false;
    }

    let mut items: [LeafItem; MAX_LEAF_ITEMS] = unsafe { core::mem::zeroed() };
    let count = collect_leaf_items(leaf_data, &mut items);

    // Find and replace the matching item's data
    let mut found = false;
    for i in 0..count {
        if items[i].key.cmp(key) == core::cmp::Ordering::Equal {
            items[i].data_len = data.len().min(256);
            for j in 0..items[i].data_len {
                items[i].data[j] = data[j];
            }
            found = true;
            break;
        }
    }
    if !found {
        return false;
    }

    let new_leaf = match alloc_block() {
        Some(b) => b,
        None => return false,
    };

    let ngen =unsafe { (*(&raw const SB)).generation + 1 };
    let mut leaf_buf = [0u8; 4096];
    if !rebuild_leaf(&mut leaf_buf, 0, ngen,new_leaf, &items, count) {
        free_block(new_leaf);
        return false;
    }

    if !write_block(new_leaf, leaf_buf.as_ptr()) {
        free_block(new_leaf);
        return false;
    }

    let mut freed = [0u64; MAX_BTREE_DEPTH];
    let mut freed_count = 0usize;
    let new_root = match cow_propagate_up(
        &path, path.depth, new_leaf, &mut freed, &mut freed_count,
    ) {
        Some(r) => r,
        None => return false,
    };

    unsafe {
        (*(&raw mut SB)).root_tree = new_root;
    }

    free_block(leaf_block);
    for i in 0..freed_count {
        free_block(freed[i]);
    }

    if !bitmap_flush() { return false; }
    write_superblock();
    true
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
// Write operation helpers
// ======================================================================

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

// ======================================================================
// Write operation handlers
// ======================================================================

/// Handle SALTYFS_CREATE: create a new regular file.
fn handle_create(msg: &SaltyMsg) -> SaltyMsg {
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
fn handle_write_inline(msg: &SaltyMsg) -> SaltyMsg {
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
fn handle_mkdir_fs(msg: &SaltyMsg) -> SaltyMsg {
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
fn handle_unlink_fs(msg: &SaltyMsg) -> SaltyMsg {
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
fn handle_rmdir_fs(msg: &SaltyMsg) -> SaltyMsg {
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
fn handle_rename_fs(msg: &SaltyMsg) -> SaltyMsg {
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
fn handle_truncate_fs(msg: &SaltyMsg) -> SaltyMsg {
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
            SALTYFS_WRITE_INLINE => handle_write_inline(&msg),
            SALTYFS_CREATE => handle_create(&msg),
            SALTYFS_MKDIR => handle_mkdir_fs(&msg),
            SALTYFS_UNLINK => handle_unlink_fs(&msg),
            SALTYFS_RMDIR => handle_rmdir_fs(&msg),
            SALTYFS_RENAME => handle_rename_fs(&msg),
            SALTYFS_TRUNCATE => handle_truncate_fs(&msg),
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
        init_bitmap();
        discover_max_inode();
    }

    // Register with name service
    register_nameserv();

    // Signal readiness
    signal_ready();

    // Enter server loop
    server_loop()
}
