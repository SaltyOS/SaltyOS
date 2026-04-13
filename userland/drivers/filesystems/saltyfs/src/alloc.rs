// SPDX-License-Identifier: GPL-2.0-only
//! Bitmap block allocator for free space management.

use crate::block::{read_block, write_block};
use crate::consts::BITMAP_CACHE_SLOTS;
use crate::{SB, BITMAP_CACHE, BITMAP_CACHE_BLOCK, BITMAP_CACHE_DIRTY, BITMAP_BLOCK_COUNT, ALLOC_HINT, READONLY};

/// Initialize bitmap allocator from superblock.
pub(crate) fn init_bitmap() {
    unsafe {
        let sb = &*(&raw const SB);
        *(&raw mut BITMAP_BLOCK_COUNT) = (sb.total_blocks + 32768 - 1) / 32768;
        *(&raw mut ALLOC_HINT) = sb.root_tree + 1;
    }
}

/// Load a bitmap block into the bitmap cache. Returns slot index.
pub(crate) fn bitmap_load(bitmap_block_idx: u64) -> Option<usize> {
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
/// Refuses on read-only mount.
pub(crate) fn alloc_block() -> Option<u64> {
    if unsafe { *(&raw const READONLY) } {
        return None;
    }
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

/// Free a previously allocated block. No-op on read-only mount.
pub(crate) fn free_block(block_nr: u64) {
    if unsafe { *(&raw const READONLY) } {
        return;
    }
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

/// Count actually-used blocks by scanning the entire bitmap.
pub(crate) fn count_used_blocks() -> u64 {
    unsafe {
        let total = (*(&raw const SB)).total_blocks;
        let mut used: u64 = 0;
        for block_nr in 0..total {
            let bitmap_idx = block_nr / 32768;
            let bit_in_block = (block_nr % 32768) as usize;
            let byte_idx = bit_in_block / 8;
            let bit_idx = bit_in_block % 8;
            if let Some(slot) = bitmap_load(bitmap_idx) {
                if ((*(&raw const BITMAP_CACHE[slot]))[byte_idx] & (1 << bit_idx)) != 0 {
                    used += 1;
                }
            }
        }
        used
    }
}

/// Flush all dirty bitmap cache entries to disk. No-op on read-only mount
/// (defensive — no dirty entries should exist in RO mode).
pub(crate) fn bitmap_flush() -> bool {
    if unsafe { *(&raw const READONLY) } {
        return true;
    }
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
