// SPDX-License-Identifier: GPL-2.0-only
//! On-disk structures: superblock, B-tree nodes, and inodes.

/// Superblock (4KB, docs/design/saltyfs.md:57-104)
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Superblock {
    pub(crate) magic: [u8; 8],
    pub(crate) version: u32,
    pub(crate) flags: u32,
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
    // Padding to 4KB
    // 0x100 .. 0xFFC (3836 bytes), checksum is final 4 bytes at 0xFFC
    pub(crate) reserved: [u8; 3836],
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
