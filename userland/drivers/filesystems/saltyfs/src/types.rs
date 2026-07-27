// SPDX-License-Identifier: GPL-2.0-only
//! On-disk structures: superblock, B-tree nodes, and inodes.

/// Superblock (4KB, docs/design/saltyfs.md Feature flags section)
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Superblock {
    pub(crate) magic: [u8; 8],
    pub(crate) version: u32,
    /// Incompatible feature flags. Unknown bits cause mount to be refused.
    /// (Historically this field was named `flags`.)
    pub(crate) incompat_flags: u32,
    pub(crate) fs_uuid: [u8; 16],
    pub(crate) device_uuid: [u8; 16],
    // Geometry (offset 0x030)
    pub(crate) block_size: u64,
    pub(crate) total_blocks: u64,
    pub(crate) used_blocks: u64,
    pub(crate) reserved_blocks: u64,
    // Tree roots (offset 0x050)
    pub(crate) root_tree: u64,
    pub(crate) extent_tree: u64,
    pub(crate) checksum_tree: u64,
    pub(crate) snapshot_tree: u64,
    // Log (offset 0x070)
    pub(crate) log_start: u64,
    pub(crate) log_size: u64,
    pub(crate) log_head: u64,
    pub(crate) log_tail: u64,
    // State (offset 0x090)
    pub(crate) generation: u64,
    pub(crate) last_mount_time: u64,
    pub(crate) last_write_time: u64,
    pub(crate) mount_count: u64,
    // Root inode (offset 0x0B0)
    pub(crate) root_inode: u64,
    // Checksums (offset 0x0B8)
    pub(crate) checksum_type: u32,
    pub(crate) reserved1: u32,
    // Label (offset 0x0C0)
    pub(crate) label: [u8; 64],
    // Feature fields (offset 0x100). Added in the xattr/casefold/multi-user
    // revision; older images have zero here, which reads as "no new features".
    pub(crate) compat_flags: u32,     // 0x100
    pub(crate) compat_ro_flags: u32,  // 0x104
    pub(crate) casefold_version: u32, // 0x108
    pub(crate) reserved2: u32,        // 0x10C
    // Monotonic inode-number allocator (offset 0x110). The next inode number
    // ever to be allocated from this volume. Persisted across mount cycles so
    // ino reuse after umount/remount is impossible. Older images have zero
    // here and are upgraded on first mount via a one-time B-tree scan
    // (`legacy_upgrade_next_inode_seq`).
    pub(crate) next_inode_seq: u64, // 0x110
    // Padding to 4KB
    // 0x118 .. 0xFFC (3812 bytes), checksum is final 4 bytes at 0xFFC
    pub(crate) reserved: [u8; 3812],
    pub(crate) checksum: u32,
}

// On-disk superblock must be exactly one 4KB block.
const _: [u8; 4096] = [0; core::mem::size_of::<Superblock>()];

/// B-tree node header (64 bytes, docs/design/saltyfs.md:112-126)
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BTreeNodeHeader {
    pub(crate) magic: [u8; 4],
    pub(crate) checksum: u32,
    pub(crate) owner: u64,
    pub(crate) generation: u64,
    pub(crate) block_nr: u64,
    pub(crate) num_items: u32,
    pub(crate) level: u16,
    pub(crate) flags: u16,
    pub(crate) reserved: [u8; 24],
}

/// B-tree key (packed, docs/design/saltyfs.md:129-133)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct BTreeKey {
    pub(crate) object_id: u64,
    pub(crate) item_type: u8,
    pub(crate) offset: u64,
}

impl BTreeKey {
    pub(crate) fn cmp(&self, other: &BTreeKey) -> core::cmp::Ordering {
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
pub(crate) struct BTreeItem {
    pub(crate) key: BTreeKey,
    pub(crate) offset: u32,
    pub(crate) size: u32,
}

/// B-tree pointer (in internal nodes, docs/design/saltyfs.md:142-147)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct BTreePointer {
    pub(crate) key: BTreeKey,
    pub(crate) block_nr: u64,
    pub(crate) generation: u64,
}

/// Inode item (docs/design/saltyfs.md:162-183)
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct SaltyInodeItem {
    pub(crate) generation: u64,
    pub(crate) size: u64,
    pub(crate) blocks: u64,
    pub(crate) block_group: u64,
    pub(crate) nlink: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) mode: u32,
    pub(crate) atime: u64,
    pub(crate) mtime: u64,
    pub(crate) ctime: u64,
    pub(crate) crtime: u64,
    pub(crate) flags: u32,
    pub(crate) sequence: u32,
    pub(crate) reserved: [u8; 32],
}

/// Extent data item (docs/design/saltyfs.md:192-206)
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ExtentData {
    pub(crate) generation: u64,
    pub(crate) ram_bytes: u64,
    pub(crate) compression: u8,
    pub(crate) encryption: u8,
    pub(crate) other_encoding: u16,
    pub(crate) extent_type: u8,
    pub(crate) reserved: [u8; 3],
    // For non-inline extents:
    pub(crate) disk_bytenr: u64,
    pub(crate) disk_num_bytes: u64,
    pub(crate) offset: u64,
    pub(crate) num_bytes: u64,
}

#[inline]
pub(crate) unsafe fn read_inode_item(data_ptr: *const u8) -> SaltyInodeItem {
    unsafe { core::ptr::read_unaligned(data_ptr as *const SaltyInodeItem) }
}

#[inline]
pub(crate) unsafe fn read_extent_data(data_ptr: *const u8) -> ExtentData {
    unsafe { core::ptr::read_unaligned(data_ptr as *const ExtentData) }
}

/// Directory item header is tightly packed on disk:
///   child_ino: u64, name_len: u16, dir_type: u8, pad: u8
/// Name bytes follow immediately after this 12-byte header.
pub(crate) const DIR_ITEM_HEADER_SIZE: usize = 12;

#[inline]
pub(crate) unsafe fn parse_dir_item_header(data_ptr: *const u8) -> (u64, u16, u8) {
    unsafe {
        let child_ino = core::ptr::read_unaligned(data_ptr as *const u64);
        let name_len = core::ptr::read_unaligned(data_ptr.add(8) as *const u16);
        let dir_type = *data_ptr.add(10);
        (child_ino, name_len, dir_type)
    }
}

pub(crate) const MAX_BTREE_DEPTH: usize = 8;

pub(crate) struct BTreePath {
    pub(crate) blocks: [u64; MAX_BTREE_DEPTH],
    pub(crate) indices: [u32; MAX_BTREE_DEPTH],
    pub(crate) depth: usize,
}

/// Max items we can handle during leaf rebuild.
pub(crate) const MAX_LEAF_ITEMS: usize = 128;

/// Collected item for leaf rebuild.
pub(crate) struct LeafItem {
    pub(crate) key: BTreeKey,
    pub(crate) data: [u8; 256],
    pub(crate) data_len: usize,
}

/// On-disk header for `TRONA_XATTR_ITEM = 0x07` payloads.
///
/// Two variants share the 8-byte header:
///   - **INLINE** (`flags & 0x01 == 0`): payload is `[header | name | value]`
///     with `name_len + value_len + 8 <= SALTY_XATTR_INLINE_MAX`.
///   - **INDIRECT** (`flags & 0x01 == 1`): payload is `[header | name | ref_ino: u64]`,
///     where `ref_ino` is a hidden inode whose extent data holds the value.
///     `value_len` is the hidden inode's file size.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct XattrHeader {
    pub(crate) name_len: u16,
    pub(crate) flags: u8,
    pub(crate) reserved0: u8,
    pub(crate) value_len: u32,
}

/// `XattrHeader.flags` bit 0: 0 = INLINE, 1 = INDIRECT.
pub(crate) const XATTR_FLAG_INDIRECT: u8 = 1 << 0;

/// Byte-size of the packed XattrHeader.
pub(crate) const XATTR_HEADER_SIZE: usize = 8;

/// Read an XattrHeader from an unaligned pointer (B-tree leaves are packed).
#[inline]
pub(crate) unsafe fn read_xattr_header(ptr: *const u8) -> XattrHeader {
    unsafe { core::ptr::read_unaligned(ptr as *const XattrHeader) }
}
