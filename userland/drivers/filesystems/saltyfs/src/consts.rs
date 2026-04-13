// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS on-disk format constants and configuration values.

// All cross-service caps flow through the role-based startup capability
// table. System roles (`namesrv`, `mmsrv`) come from the substrate
// `trona::caps::*` getters (backed by libtrona's `__trona_cap_*` weak
// symbols). The service-local `Require=blkdrv:blkdrv_ep` entry flows
// through the build-generated `svc_caps` crate.
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
pub(crate) const TRONA_EXTENT_REF: u8 = 0x06;
pub(crate) const TRONA_XATTR_ITEM: u8 = 0x07;

/// Extent types
pub(crate) const EXTENT_INLINE: u8 = 0;
pub(crate) const EXTENT_REGULAR: u8 = 1;

/// VFS-SaltyFS shared memory for bulk data transport
pub(crate) const VFS_SHM_VADDR: u64 = 0x0000_0000_5200_0000;
pub(crate) const VFS_SHM_PAGES: u64 = 256; // 1MB

/// Bitmap block allocator
pub(crate) const BITMAP_CACHE_SLOTS: usize = 4;

// ============================================================
// Feature flags (btrfs-style 3-field split)
// ============================================================

/// Incompatible feature flags stored in `Superblock.incompat_flags`.
/// Unknown bits cause mount to be refused.
pub(crate) const SALTYFS_INCOMPAT_XATTR: u32 = 1 << 0;
pub(crate) const SALTYFS_INCOMPAT_CASEFOLD: u32 = 1 << 1;
pub(crate) const SALTYFS_INCOMPAT_SUPPORTED: u32 =
    SALTYFS_INCOMPAT_XATTR | SALTYFS_INCOMPAT_CASEFOLD;

/// Compat_ro feature flags. Unknown bits force read-only mount.
pub(crate) const SALTYFS_COMPAT_RO_SUPPORTED: u32 = 0;

/// Compat feature flags. Unknown bits are silently ignored (hints only).
#[allow(dead_code)]
pub(crate) const SALTYFS_COMPAT_SUPPORTED: u32 = 0;

/// Unicode version used by the case-folding table. Stored in
/// `Superblock.casefold_version` on casefold-enabled images.
/// Encoded as major*1_000_000 + minor*1000 + patch.
pub(crate) const CASEFOLD_VERSION_UNICODE_15_1: u32 = 15_001_000;

// ============================================================
// Inode flag bits (stored in `SaltyInodeItem.flags`)
// ============================================================

/// Directory uses case-insensitive name lookup (Unicode Simple CF).
/// Inherited from parent on mkdir/create/symlink.
pub(crate) const SALTY_INODE_CASEFOLD: u32 = 1 << 0;

/// Inode is hidden from the directory namespace. Used for out-of-line
/// xattr value storage — referenced only by XATTR_ITEM indirect entries.
pub(crate) const SALTY_INODE_HIDDEN: u32 = 1 << 1;

// ============================================================
// Mount flags (`SALTYFS_MOUNT` request `regs[0]`)
// ============================================================

pub(crate) const SALTYFS_MOUNT_RO: u64 = 1 << 0;

// ============================================================
// Protocol version sentinel (create / mkdir / symlink)
// ============================================================

/// Bit 63 of `regs[0]` (parent_ino) distinguishes the V2 inbound layout that
/// carries uid/gid and inheritable flags. V1 callers leave bit 63 clear — no
/// real inode number ever reaches 2^63, so this is collision-free.
///
/// V2 layout for `SALTYFS_CREATE` / `SALTYFS_MKDIR`:
///   regs[0] = parent_ino | SALTYFS_PROTO_V2
///   regs[1] = mode
///   regs[2] = uid (u32)
///   regs[3] = gid (u32)
///   regs[4] = name_len (u8, ≤120)
///   regs[5..20] = name bytes (120 bytes)
///
/// V2 layout for `SALTYFS_SYMLINK`:
///   regs[0] = parent_ino | SALTYFS_PROTO_V2
///   regs[1] = uid (u32)
///   regs[2] = gid (u32)
///   regs[3] = name_len (u8, ≤56)
///   regs[4] = target_len (u8, ≤64)
///   regs[5..11] = name bytes (56 bytes)
///   regs[12..20] = target bytes (64 bytes)
///
/// The V1 layouts (uid/gid = 0) continue to be accepted unchanged so that
/// the current VFS can keep driving SaltyFS until the forthcoming VFS
/// redesign migrates to V2.
pub(crate) const SALTYFS_PROTO_V2: u64 = 1u64 << 63;

// ============================================================
// xattr constants
// ============================================================

/// setxattr flags (mirrors POSIX XATTR_CREATE/XATTR_REPLACE).
#[allow(dead_code)]
pub(crate) const SALTYFS_XATTR_CREATE: u64 = 1;
#[allow(dead_code)]
pub(crate) const SALTYFS_XATTR_REPLACE: u64 = 2;

/// Maximum xattr name length (bytes, excluding terminator).
pub(crate) const SALTY_XATTR_NAME_MAX: usize = 255;

/// Inline payload cap: XattrHeader(8) + name + value ≤ this.
/// Below LeafItem.data[256] with margin for leaf packing overhead.
pub(crate) const SALTY_XATTR_INLINE_MAX: usize = 200;

/// Single-block out-of-line xattr value cap (v1). Larger values spill
/// across multiple extents via the hidden-inode mechanism.
#[allow(dead_code)]
pub(crate) const SALTY_XATTR_VALUE_HARD_MAX: usize = 4 * 1024 * 1024;
