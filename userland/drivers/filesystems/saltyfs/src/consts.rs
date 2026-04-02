// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS on-disk format constants and configuration values.

pub(crate) const CAP_SERVER_EP: u64 = 68;
pub(crate) const CAP_READINESS_NTFN: u64 = 14;
pub(crate) const CAP_BLKDRV_EP: u64 = 64;
pub(crate) const CAP_NAMESRV_EP: u64 = 5;
pub(crate) const CAP_MMSRV_EP: u64 = 7;

/// SHM for saltyfs<->blkdrv data (mapped from blkdrv's SHM)
pub(crate) const SHM_VADDR: u64 = 0x0000_0000_5000_0000;
pub(crate) const SHM_SIZE: u64 = 256 * 1024; // 256KB (64 pages)

/// Block size (4KB default, read from superblock)
pub(crate) const DEFAULT_BLOCK_SIZE: u64 = 4096;
pub(crate) const SECTOR_SIZE: u64 = 512;

/// Block cache: 256 blocks cached in memory (1MB)
pub(crate) const CACHE_VADDR: u64 = 0x0000_0000_5100_0000;
pub(crate) const CACHE_SLOTS: usize = 256;
/// Each cache slot is one block (4KB)
pub(crate) const CACHE_SLOT_SIZE: usize = 4096;
pub(crate) const CACHE_TOTAL_PAGES: u64 = (CACHE_SLOTS * CACHE_SLOT_SIZE / 4096) as u64;

pub(crate) const SALTYFS_MAGIC: [u8; 8] = *b"SALTYFS\0";
pub(crate) const BTREE_NODE_MAGIC: [u8; 4] = *b"BTND";

/// Item type constants (docs/design/saltyfs.md:154-160)
pub(crate) const TRONA_INODE_ITEM: u8 = 0x01;
pub(crate) const TRONA_INODE_REF: u8 = 0x02;
pub(crate) const TRONA_DIR_ITEM: u8 = 0x03;
pub(crate) const TRONA_DIR_INDEX: u8 = 0x04;
pub(crate) const TRONA_EXTENT_DATA: u8 = 0x05;

/// Extent types
pub(crate) const EXTENT_INLINE: u8 = 0;
pub(crate) const EXTENT_REGULAR: u8 = 1;

/// VFS-SaltyFS shared memory for bulk data transport
pub(crate) const VFS_SHM_VADDR: u64 = 0x0000_0000_5200_0000;
pub(crate) const VFS_SHM_PAGES: u64 = 256; // 1MB

/// Bitmap block allocator
pub(crate) const BITMAP_CACHE_SLOTS: usize = 4;
