// SPDX-License-Identifier: GPL-2.0-only
//! Block I/O with caching and prefetching.

use salty::consts::*;
use salty::ipc;
use salty::serial::LineBuf;
use salty::types::*;

use crate::consts::*;
use crate::crc::crc32c_superblock;
use crate::types::*;
use crate::{ipc_ctx, puts, SB, BLOCK_SIZE, BLK_SHM_ID, CACHE_BLOCK_NR, CACHE_AGE, CACHE_TICK, CACHE_DIRTY, NEXT_INO};
use crate::btree::btree_search;

/// Read sectors from blkdrv into SHM at given offset.
pub(crate) fn blk_read_sectors(start_sector: u64, count: u64, shm_offset: u64) -> bool {
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
pub(crate) fn blk_write_sectors(start_sector: u64, count: u64, shm_offset: u64) -> bool {
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
pub(crate) fn write_block(block_nr: u64, data: *const u8) -> bool {
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
            if item.key.item_type == SALTY_INODE_ITEM && item.key.object_id > max_ino {
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

pub(crate) fn setup_blk_shm() -> bool {
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
pub(crate) fn setup_cache() -> bool {
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

/// Read the superblock from block 0.
pub(crate) fn read_superblock() -> bool {
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
