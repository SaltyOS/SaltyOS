// SPDX-License-Identifier: GPL-2.0-only
//! CRC32C implementation for data integrity verification.

use crate::types::Superblock;

pub(crate) static CRC32C_TABLE: [u32; 256] = {
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

pub(crate) fn crc32c(data: *const u8, len: usize) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for i in 0..len {
        let byte = unsafe { *data.add(i) };
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

pub(crate) fn crc32c_superblock(sb: &Superblock) -> u32 {
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

pub(crate) fn crc32c_btree_node(data: *const u8, block_size: usize) -> u32 {
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
