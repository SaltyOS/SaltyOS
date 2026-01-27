//! Initrd (cpio newc) parsing helpers.

#![no_std]

use saltyos_ska::{PhysAddr, DIRECT_MAP_OFFSET};

const CPIO_MAGIC: &[u8; 6] = b"070701";
const CPIO_MAGIC_CRC: &[u8; 6] = b"070702";

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn parse_hex_u32(bytes: &[u8]) -> Option<u32> {
    let mut val: u32 = 0;
    for &b in bytes {
        val <<= 4;
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u32,
            b'a'..=b'f' => (b - b'a' + 10) as u32,
            b'A'..=b'F' => (b - b'A' + 10) as u32,
            _ => return None,
        };
        val |= digit;
    }
    Some(val)
}

/// Locate `/init` payload inside an initrd (cpio newc).
pub fn find_init(initrd_phys: PhysAddr, initrd_size: u64) -> Result<Option<&'static [u8]>, &'static str> {
    if initrd_size == 0 {
        return Ok(None);
    }

    let base = (DIRECT_MAP_OFFSET + initrd_phys.as_u64()) as *const u8;
    let total = initrd_size as usize;
    let data = unsafe { core::slice::from_raw_parts(base, total) };

    let mut offset = 0usize;
    loop {
        if offset + 110 > total {
            return Err("cpio header out of bounds");
        }

        let header = &data[offset..offset + 110];
        let magic = &header[0..6];
        if magic != CPIO_MAGIC && magic != CPIO_MAGIC_CRC {
            return Err("cpio magic mismatch");
        }

        let namesize = parse_hex_u32(&header[94..102]).ok_or("cpio namesize parse")? as usize;
        let filesize = parse_hex_u32(&header[54..62]).ok_or("cpio filesize parse")? as usize;

        let name_start = offset + 110;
        let name_end = name_start + namesize;
        if name_end > total || namesize == 0 {
            return Err("cpio name out of bounds");
        }
        let name = &data[name_start..name_end - 1];
        if name == b"TRAILER!!!" {
            return Ok(None);
        }

        let data_start = align4(name_end);
        let data_end = data_start + filesize;
        if data_end > total {
            return Err("cpio data out of bounds");
        }

        if name == b"init" {
            return Ok(Some(&data[data_start..data_end]));
        }

        offset = align4(data_end);
    }
}
