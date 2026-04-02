// SPDX-License-Identifier: GPL-2.0-only
//! Block I/O with caching and prefetching.

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use crate::consts::*;
use crate::crc::crc32c_superblock;
use crate::types::*;
use crate::{ipc_ctx, SB, BLOCK_SIZE, BLK_SHM_ID, CACHE_BLOCK_NR, CACHE_AGE, CACHE_TICK, CACHE_DIRTY, NEXT_INO};
use crate::btree::btree_search;

/// Filesystem block number 0 is read from this disk LBA offset.
/// `0` means the filesystem starts at the beginning of the block device (legacy raw image).
static mut PARTITION_BASE_LBA: u64 = 0;

const MBR_SIGNATURE_OFF: usize = 510;
const MBR_PART_TABLE_OFF: usize = 446;
const MBR_PART_ENTRY_SIZE: usize = 16;
const MBR_PART_COUNT: usize = 4;
const MBR_PART_TYPE_OFF: usize = 4;
const MBR_PART_START_LBA_OFF: usize = 8;
const MBR_PART_SECTOR_COUNT_OFF: usize = 12;
const MBR_PART_TYPE_PROTECTIVE_GPT: u8 = 0xEE;
// Until a SaltyFS-specific MBR type is standardized, use Linux filesystem type.
const MBR_PART_TYPE_LINUX_FS: u8 = 0x83;

const GPT_HEADER_LBA: u64 = 1;
const GPT_SIG: [u8; 8] = *b"EFI PART";
const GPT_SIG_OFF: usize = 0;
const GPT_HEADER_SIZE_OFF: usize = 12;
const GPT_HEADER_CRC32_OFF: usize = 16;
const GPT_ENTRIES_LBA_OFF: usize = 72;
const GPT_ENTRIES_COUNT_OFF: usize = 80;
const GPT_ENTRY_SIZE_OFF: usize = 84;
const GPT_ENTRIES_CRC32_OFF: usize = 88;
const GPT_MIN_HEADER_SIZE: u32 = 92;
const GPT_MIN_ENTRY_SIZE: u32 = 128;
const GPT_MAX_ENTRY_SIZE: u32 = 512;
const GPT_ENTRY_TYPE_GUID_OFF: usize = 0;
const GPT_ENTRY_FIRST_LBA_OFF: usize = 32;
const GPT_ENTRY_LAST_LBA_OFF: usize = 40;
// Linux filesystem data partition type GUID (bytes_le / on-disk GPT layout).
// 0FC63DAF-8483-4772-8E79-3D69D8477DE4
const GPT_PART_TYPE_LINUX_FS_LE: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
    0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
];

const PROBE_BLOCK_SIZE: u64 = DEFAULT_BLOCK_SIZE; // Superblock is always 4KB on disk.
// Defensive cap for malformed GPTs; far above normal GPT entry arrays.
const GPT_MAX_ENTRY_ARRAY_BYTES: u64 = 64 * 1024 * 1024;

#[inline]
fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[inline]
fn read_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

pub(crate) static CRC32_IEEE_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
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

#[inline]
fn crc32_ieee_update(mut crc: u32, data: &[u8]) -> u32 {
    for b in data {
        crc = CRC32_IEEE_TABLE[((crc ^ (*b as u32)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

#[inline]
fn crc32_ieee_bytes(data: &[u8]) -> u32 {
    crc32_ieee_update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF
}

fn validate_gpt_header_crc(hdr: &[u8], hdr_size: usize) -> bool {
    if hdr_size > SECTOR_SIZE as usize || GPT_HEADER_CRC32_OFF + 4 > hdr_size {
        return false;
    }

    let expected = read_u32_le(&hdr[GPT_HEADER_CRC32_OFF..GPT_HEADER_CRC32_OFF + 4]);
    let mut tmp = [0u8; SECTOR_SIZE as usize];
    for i in 0..hdr_size {
        tmp[i] = hdr[i];
    }
    for i in GPT_HEADER_CRC32_OFF..GPT_HEADER_CRC32_OFF + 4 {
        tmp[i] = 0;
    }

    crc32_ieee_bytes(&tmp[..hdr_size]) == expected
}

fn crc32_gpt_entries(entries_lba: u64, total_bytes: u64) -> Option<u32> {
    if total_bytes == 0 {
        return None;
    }
    if total_bytes > GPT_MAX_ENTRY_ARRAY_BYTES {
        return None;
    }

    let mut remaining = total_bytes;
    let mut lba = entries_lba;
    let mut crc = 0xFFFF_FFFFu32;
    let max_chunk_bytes = SHM_SIZE;

    while remaining > 0 {
        let chunk_bytes = if remaining > max_chunk_bytes {
            max_chunk_bytes
        } else {
            remaining
        };
        let chunk_sectors = (chunk_bytes + SECTOR_SIZE - 1) / SECTOR_SIZE;
        if !blk_read_sectors(lba, chunk_sectors, 0) {
            return None;
        }

        let shm = unsafe {
            core::slice::from_raw_parts(SHM_VADDR as *const u8, chunk_bytes as usize)
        };
        crc = crc32_ieee_update(crc, shm);

        lba += chunk_sectors;
        remaining -= chunk_bytes;
    }

    Some(crc ^ 0xFFFF_FFFF)
}

#[derive(Clone, Copy)]
struct PartitionProbeCandidate {
    base_lba: u64,
    sb: Superblock,
    typed: bool,
}

fn pick_partition_candidate(
    current: Option<PartitionProbeCandidate>,
    cand: PartitionProbeCandidate,
) -> Option<PartitionProbeCandidate> {
    if let Some(cur) = current {
        let cur_rootfs = superblock_label_eq(&cur.sb, b"rootfs");
        let cand_rootfs = superblock_label_eq(&cand.sb, b"rootfs");

        if cand.typed != cur.typed {
            if cand.typed {
                return Some(cand);
            }
            return Some(cur);
        }
        if cand_rootfs != cur_rootfs {
            if cand_rootfs {
                return Some(cand);
            }
            return Some(cur);
        }
        return Some(cur);
    }
    Some(cand)
}

fn cache_reset_all() {
    unsafe {
        for i in 0..CACHE_SLOTS {
            *(&raw mut CACHE_BLOCK_NR[i]) = u64::MAX;
            *(&raw mut CACHE_DIRTY[i]) = false;
            *(&raw mut CACHE_AGE[i]) = 0;
        }
        *(&raw mut CACHE_TICK) = 0;
    }
}

fn superblock_label_eq(sb: &Superblock, expected: &[u8]) -> bool {
    if expected.len() > sb.label.len() {
        return false;
    }
    for (i, b) in expected.iter().enumerate() {
        if sb.label[i] != *b {
            return false;
        }
    }
    // Require exact match (next byte must be NUL if buffer has room).
    if expected.len() < sb.label.len() && sb.label[expected.len()] != 0 {
        return false;
    }
    true
}

/// Probe a SaltyFS superblock at the given filesystem base LBA.
/// Checks both primary (block 0) and backup (block 1) superblocks.
fn probe_superblock_at_partition_lba(base_lba: u64) -> Option<Superblock> {
    let sectors_per_block = PROBE_BLOCK_SIZE / SECTOR_SIZE;
    let mut try_lba = [base_lba, base_lba + sectors_per_block];

    for disk_lba in &mut try_lba {
        if !blk_read_sectors(*disk_lba, sectors_per_block, 0) {
            continue;
        }

        let sb = unsafe { core::ptr::read_unaligned(SHM_VADDR as *const Superblock) };
        if sb.magic != SALTYFS_MAGIC {
            continue;
        }
        if sb.block_size != DEFAULT_BLOCK_SIZE {
            // Current cache implementation assumes 4KB blocks.
            continue;
        }
        if sb.block_size == 0 || sb.block_size % SECTOR_SIZE != 0 {
            continue;
        }
        let computed = crc32c_superblock(&sb);
        if computed != sb.checksum {
            continue;
        }
        return Some(sb);
    }

    None
}

/// Scan MBR primary partitions and return the first valid SaltyFS partition.
/// Prefer Linux filesystem partition type (0x83) and then label "rootfs".
fn scan_mbr_for_saltyfs_partition() -> Option<(u64, Superblock)> {
    if !blk_read_sectors(0, 1, 0) {
        return None;
    }

    let mbr = unsafe { core::slice::from_raw_parts(SHM_VADDR as *const u8, SECTOR_SIZE as usize) };
    if mbr[MBR_SIGNATURE_OFF] != 0x55 || mbr[MBR_SIGNATURE_OFF + 1] != 0xAA {
        return None;
    }

    let mut best: Option<PartitionProbeCandidate> = None;

    for idx in 0..MBR_PART_COUNT {
        let off = MBR_PART_TABLE_OFF + idx * MBR_PART_ENTRY_SIZE;
        let entry = &mbr[off..off + MBR_PART_ENTRY_SIZE];

        let ptype = entry[MBR_PART_TYPE_OFF];
        let start_lba = read_u32_le(&entry[MBR_PART_START_LBA_OFF..MBR_PART_START_LBA_OFF + 4]) as u64;
        let sectors = read_u32_le(
            &entry[MBR_PART_SECTOR_COUNT_OFF..MBR_PART_SECTOR_COUNT_OFF + 4],
        ) as u64;

        if ptype == 0 || start_lba == 0 || sectors == 0 {
            continue;
        }
        if ptype == MBR_PART_TYPE_PROTECTIVE_GPT {
            continue;
        }

        // Need at least one 4KB block to hold the superblock.
        if sectors < (PROBE_BLOCK_SIZE / SECTOR_SIZE) {
            continue;
        }

        if let Some(sb) = probe_superblock_at_partition_lba(start_lba) {
            let cand = PartitionProbeCandidate {
                base_lba: start_lba,
                sb,
                typed: ptype == MBR_PART_TYPE_LINUX_FS,
            };
            best = pick_partition_candidate(best, cand);
        }
    }

    best.map(|c| (c.base_lba, c.sb))
}

#[inline]
fn guid_is_zero(g: &[u8]) -> bool {
    for b in g {
        if *b != 0 {
            return false;
        }
    }
    true
}

#[inline]
fn guid_eq(a: &[u8], b: &[u8; 16]) -> bool {
    if a.len() != 16 {
        return false;
    }
    for i in 0..16 {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

/// Scan GPT partition entries and return the best SaltyFS partition candidate.
/// Prefers Linux filesystem type GUID, then label "rootfs".
fn scan_gpt_for_saltyfs_partition() -> Option<(u64, Superblock)> {
    if !blk_read_sectors(GPT_HEADER_LBA, 1, 0) {
        return None;
    }

    let hdr = unsafe { core::slice::from_raw_parts(SHM_VADDR as *const u8, SECTOR_SIZE as usize) };
    for i in 0..GPT_SIG.len() {
        if hdr[GPT_SIG_OFF + i] != GPT_SIG[i] {
            return None;
        }
    }

    let hdr_size = read_u32_le(&hdr[GPT_HEADER_SIZE_OFF..GPT_HEADER_SIZE_OFF + 4]);
    if hdr_size < GPT_MIN_HEADER_SIZE || hdr_size as usize > SECTOR_SIZE as usize {
        return None;
    }
    if !validate_gpt_header_crc(hdr, hdr_size as usize) {
        return None;
    }

    let entries_lba = read_u64_le(&hdr[GPT_ENTRIES_LBA_OFF..GPT_ENTRIES_LBA_OFF + 8]);
    let entry_count = read_u32_le(&hdr[GPT_ENTRIES_COUNT_OFF..GPT_ENTRIES_COUNT_OFF + 4]);
    let entry_size = read_u32_le(&hdr[GPT_ENTRY_SIZE_OFF..GPT_ENTRY_SIZE_OFF + 4]);
    let expected_entries_crc =
        read_u32_le(&hdr[GPT_ENTRIES_CRC32_OFF..GPT_ENTRIES_CRC32_OFF + 4]);

    if entries_lba == 0 || entry_count == 0 {
        return None;
    }
    if entry_size < GPT_MIN_ENTRY_SIZE || entry_size > GPT_MAX_ENTRY_SIZE {
        return None;
    }
    if (entry_size & 7) != 0 {
        return None;
    }

    let total_entry_bytes = (entry_count as u64).checked_mul(entry_size as u64)?;
    let computed_entries_crc = crc32_gpt_entries(entries_lba, total_entry_bytes)?;
    if computed_entries_crc != expected_entries_crc {
        return None;
    }

    let entry_size_usize = entry_size as usize;
    let mut scan_count = entry_count as usize;
    // Keep a conservative cap even though we read entries one-by-one.
    let max_scan_entries = (SHM_SIZE as usize) / entry_size_usize;
    if scan_count > max_scan_entries {
        scan_count = max_scan_entries;
    }
    if scan_count == 0 {
        return None;
    }
    let mut best: Option<PartitionProbeCandidate> = None;
    let mut entry_buf = [0u8; GPT_MAX_ENTRY_SIZE as usize];

    for idx in 0..scan_count {
        let entry_abs_off = idx * entry_size_usize;
        let sector_off = (entry_abs_off as u64) % SECTOR_SIZE;
        let sector_lba = entries_lba + ((entry_abs_off as u64) / SECTOR_SIZE);
        let bytes_needed = sector_off as usize + entry_size_usize;
        let sector_count = ((bytes_needed as u64) + SECTOR_SIZE - 1) / SECTOR_SIZE;
        if !blk_read_sectors(sector_lba, sector_count, 0) {
            continue;
        }

        let shm = unsafe {
            core::slice::from_raw_parts(
                SHM_VADDR as *const u8,
                (sector_count * SECTOR_SIZE) as usize,
            )
        };
        let start = sector_off as usize;
        for i in 0..entry_size_usize {
            entry_buf[i] = shm[start + i];
        }

        let ent = &entry_buf[..entry_size_usize];
        let type_guid = &ent[GPT_ENTRY_TYPE_GUID_OFF..GPT_ENTRY_TYPE_GUID_OFF + 16];
        if guid_is_zero(type_guid) {
            continue;
        }

        let first_lba = read_u64_le(&ent[GPT_ENTRY_FIRST_LBA_OFF..GPT_ENTRY_FIRST_LBA_OFF + 8]);
        let last_lba = read_u64_le(&ent[GPT_ENTRY_LAST_LBA_OFF..GPT_ENTRY_LAST_LBA_OFF + 8]);
        let typed = guid_eq(type_guid, &GPT_PART_TYPE_LINUX_FS_LE);
        if first_lba == 0 || last_lba < first_lba {
            continue;
        }
        let sectors = (last_lba - first_lba) + 1;
        if sectors < (PROBE_BLOCK_SIZE / SECTOR_SIZE) {
            continue;
        }

        if let Some(sb) = probe_superblock_at_partition_lba(first_lba) {
            let cand = PartitionProbeCandidate {
                base_lba: first_lba,
                sb,
                typed,
            };
            best = pick_partition_candidate(best, cand);
        }
    }

    best.map(|c| (c.base_lba, c.sb))
}

/// Read sectors from blkdrv into SHM at given offset.
pub(crate) fn blk_read_sectors(start_sector: u64, count: u64, shm_offset: u64) -> bool {
    let mut msg = TronaMsg::zeroed();
    msg.label = BLK_READ;
    msg.length = 3;
    msg.regs[0] = start_sector;
    msg.regs[1] = count;
    msg.regs[2] = shm_offset;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_BLKDRV_EP, &raw const msg, &raw mut reply) };
    err == 0 && reply.label == 0
}

/// Write sectors to blkdrv from SHM at given offset.
pub(crate) fn blk_write_sectors(start_sector: u64, count: u64, shm_offset: u64) -> bool {
    let mut msg = TronaMsg::zeroed();
    msg.label = BLK_WRITE;
    msg.length = 3;
    msg.regs[0] = start_sector;
    msg.regs[1] = count;
    msg.regs[2] = shm_offset;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_BLKDRV_EP, &raw const msg, &raw mut reply) };
    err == 0 && reply.label == 0
}

/// Write a 4KB block to disk.
pub(crate) fn write_block(block_nr: u64, data: *const u8) -> bool {
    unsafe {
        let bs = *(&raw const BLOCK_SIZE);
        let sectors_per_block = bs / SECTOR_SIZE;
        let start_sector = *(&raw const PARTITION_BASE_LBA) + block_nr * sectors_per_block;
        // Copy data to SHM offset 0
        let shm = SHM_VADDR as *mut u8;
        for i in 0..bs as usize {
            *shm.add(i) = *data.add(i);
        }
        blk_write_sectors(start_sector, sectors_per_block, 0)
    }
}

/// Get a mutable pointer to a cached block, marking it dirty.
pub(crate) fn read_block_mut(block_nr: u64) -> *mut u8 {
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
pub(crate) fn cache_flush_block(block_nr: u64) -> bool {
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

/// Flush all dirty blocks from the block cache to disk.
pub(crate) fn cache_flush_all() {
    unsafe {
        for i in 0..CACHE_SLOTS {
            if *(&raw const CACHE_DIRTY[i]) {
                let block_nr = *(&raw const CACHE_BLOCK_NR[i]);
                if block_nr != u64::MAX {
                    let ptr = (CACHE_VADDR + (i as u64) * CACHE_SLOT_SIZE as u64) as *const u8;
                    if write_block(block_nr, ptr) {
                        *(&raw mut CACHE_DIRTY[i]) = false;
                    }
                }
            }
        }
    }
}

/// Remove a block from the cache.
pub(crate) fn cache_invalidate(block_nr: u64) {
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
pub(crate) fn write_superblock() -> bool {
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
            if item.key.item_type == TRONA_INODE_ITEM && item.key.object_id > max_ino {
                max_ino = item.key.object_id;
            }
        }
        *(&raw mut NEXT_INO) = max_ino + 1;
    }
}

/// Scan the B-tree to find the maximum inode number and set NEXT_INO.
/// Uses btree_search with max key to find the last leaf in multi-level trees.
pub(crate) fn discover_max_inode() {
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

/// Read a filesystem block into the block cache. Returns pointer to cached data.
pub(crate) fn read_block(block_nr: u64) -> *const u8 {
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
        let start_sector = *(&raw const PARTITION_BASE_LBA) + block_nr * sectors_per_block;

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

pub(crate) fn setup_blk_shm() -> bool {
    let ctx = ipc_ctx();

    // Get SHM ID from blkdrv
    let mut msg = TronaMsg::zeroed();
    msg.label = BLK_GET_SHM_ID;
    msg.length = 0;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_BLKDRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        trona::uerror!(|_lb| { _lb.str(b"[saltyfs] Failed to get SHM ID from blkdrv\n"); });
        return false;
    }

    unsafe { *(&raw mut BLK_SHM_ID) = reply.regs[0]; }

    // Map the SHM into our address space
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_SHM_MAP;
    msg.length = 4;
    msg.regs[0] = unsafe { *(&raw const BLK_SHM_ID) };
    msg.regs[1] = 0; // badge (self)
    msg.regs[2] = SHM_VADDR;
    msg.regs[3] = 0x3; // RW

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[saltyfs] SHM map failed: ");
            _lb.dec(if err != 0 { err as u64 } else { reply.label });
            _lb.putc(b'\n');
        });
        return false;
    }

    trona::uinfo!(|_lb| { _lb.str(b"[saltyfs] SHM mapped from blkdrv\n"); });
    true
}

/// Allocate cache memory via mmsrv
pub(crate) fn setup_cache() -> bool {
    let ctx = ipc_ctx();

    // Allocate pages for block cache
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_SHM_CREATE;
    msg.length = 2;
    msg.regs[0] = 0x53465343; // "SFSC" - saltyfs cache
    msg.regs[1] = CACHE_TOTAL_PAGES;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || (reply.label != 0 && reply.label != TRONA_ALREADY_EXISTS) {
        trona::uerror!(|_lb| { _lb.str(b"[saltyfs] Cache SHM create failed\n"); });
        return false;
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = MM_SHM_MAP;
    msg.length = 4;
    msg.regs[0] = 0x53465343;
    msg.regs[1] = 0;
    msg.regs[2] = CACHE_VADDR;
    msg.regs[3] = 0x3; // RW

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        trona::uerror!(|_lb| { _lb.str(b"[saltyfs] Cache SHM map failed\n"); });
        return false;
    }

    trona::uinfo!(|_lb| { _lb.str(b"[saltyfs] Block cache allocated\n"); });
    true
}

/// Read the superblock from either:
///   1) raw device block 0 (legacy standalone SaltyFS image), or
///   2) a GPT partition (preferred for GPT disks), or
///   3) an MBR primary partition.
pub(crate) fn read_superblock() -> bool {
    // Mount probing must not reuse cache entries from a previous filesystem base.
    cache_reset_all();
    unsafe {
        *(&raw mut BLOCK_SIZE) = DEFAULT_BLOCK_SIZE;
        *(&raw mut PARTITION_BASE_LBA) = 0;
    }

    let (base_lba, probed_sb) = if let Some(sb) = probe_superblock_at_partition_lba(0) {
        (0, sb)
    } else if let Some((lba, sb)) = scan_gpt_for_saltyfs_partition() {
        (lba, sb)
    } else if let Some((lba, sb)) = scan_mbr_for_saltyfs_partition() {
        (lba, sb)
    } else {
        trona::uerror!(|_lb| { _lb.str(b"[saltyfs] Failed to find SaltyFS superblock (raw/GPT/MBR)\n"); });
        return false;
    };

    unsafe {
        *(&raw mut PARTITION_BASE_LBA) = base_lba;
        *(&raw mut SB) = probed_sb;
        *(&raw mut BLOCK_SIZE) = (*(&raw const SB)).block_size;

        trona::uinfo!(|_lb| {
            _lb.str(b"[saltyfs] Mounted: part_lba=");
            _lb.dec(*(&raw const PARTITION_BASE_LBA));
            _lb.str(b" blocks=");
            _lb.dec((*(&raw const SB)).total_blocks);
            _lb.str(b" used=");
            _lb.dec((*(&raw const SB)).used_blocks);
            _lb.str(b" bs=");
            _lb.dec((*(&raw const SB)).block_size);
            _lb.str(b" root_tree=");
            _lb.dec((*(&raw const SB)).root_tree);
            _lb.str(b" root_ino=");
            _lb.dec((*(&raw const SB)).root_inode);
            _lb.putc(b'\n');
        });
    }

    true
}
