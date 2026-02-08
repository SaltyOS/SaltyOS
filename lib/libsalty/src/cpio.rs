//! CPIO newc archive parser
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::CPIO_HEADER_SIZE;
use crate::types::{CpioEntry, CpioEntryExt};

fn parse_hex8(bytes: *const u8) -> usize {
    let mut val: usize = 0;
    for i in 0..8 {
        let b = unsafe { *bytes.add(i) };
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            b'A'..=b'F' => (b - b'A' + 10) as usize,
            _ => return 0,
        };
        val = (val << 4) | digit;
    }
    val
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn check_magic(header: *const u8) -> bool {
    unsafe {
        *header.add(0) == b'0'
            && *header.add(1) == b'7'
            && *header.add(2) == b'0'
            && *header.add(3) == b'7'
            && *header.add(4) == b'0'
            && *header.add(5) == b'1'
    }
}

fn is_trailer(name: *const u8, name_len: usize) -> bool {
    if name_len != 10 {
        return false;
    }
    let trailer = b"TRAILER!!!";
    for i in 0..10 {
        if unsafe { *name.add(i) } != trailer[i] {
            return false;
        }
    }
    true
}

pub unsafe fn cpio_find_file(
    archive: *const u8,
    archive_len: usize,
    name: *const u8,
    name_len: usize,
    entry: *mut CpioEntry,
) -> i32 {
    let mut offset: usize = 0;

    loop {
        if offset + CPIO_HEADER_SIZE > archive_len {
            return 0;
        }

        let header = unsafe { archive.add(offset) };

        if !check_magic(header) {
            return 0;
        }

        let namesize = parse_hex8(unsafe { header.add(94) });
        let filesize = parse_hex8(unsafe { header.add(54) });

        let name_start = offset + CPIO_HEADER_SIZE;
        if name_start + namesize > archive_len {
            return 0;
        }

        let entry_name = unsafe { archive.add(name_start) };
        let mut entry_name_len = namesize;
        if entry_name_len > 0 && unsafe { *entry_name.add(entry_name_len - 1) } == 0 {
            entry_name_len -= 1;
        }

        if is_trailer(entry_name, entry_name_len) {
            return 0;
        }

        let data_start = align4(offset + CPIO_HEADER_SIZE + namesize);
        let data_end = data_start + filesize;
        if data_end > archive_len {
            return 0;
        }

        // Compare names
        if entry_name_len == name_len {
            let mut match_found = true;
            for i in 0..entry_name_len {
                if unsafe { *entry_name.add(i) } != unsafe { *name.add(i) } {
                    match_found = false;
                    break;
                }
            }
            if match_found {
                unsafe {
                    (*entry).name = entry_name;
                    (*entry).name_len = entry_name_len;
                    (*entry).data = archive.add(data_start);
                    (*entry).data_len = filesize;
                }
                return 1;
            }
        }

        offset = align4(data_end);
    }
}

pub unsafe fn cpio_next(
    archive: *const u8,
    archive_len: usize,
    offset: *mut usize,
    entry: *mut CpioEntry,
) -> i32 {
    let off = unsafe { *offset };
    if off + CPIO_HEADER_SIZE > archive_len {
        return 0;
    }

    let header = unsafe { archive.add(off) };
    if !check_magic(header) {
        return 0;
    }

    let namesize = parse_hex8(unsafe { header.add(94) });
    let filesize = parse_hex8(unsafe { header.add(54) });

    let name_start = off + CPIO_HEADER_SIZE;
    if name_start + namesize > archive_len {
        return 0;
    }

    let entry_name = unsafe { archive.add(name_start) };
    let mut entry_name_len = namesize;
    if entry_name_len > 0 && unsafe { *entry_name.add(entry_name_len - 1) } == 0 {
        entry_name_len -= 1;
    }

    if is_trailer(entry_name, entry_name_len) {
        return 0;
    }

    let data_start = align4(off + CPIO_HEADER_SIZE + namesize);
    let data_end = data_start + filesize;
    if data_end > archive_len {
        return 0;
    }

    unsafe {
        (*entry).name = entry_name;
        (*entry).name_len = entry_name_len;
        (*entry).data = archive.add(data_start);
        (*entry).data_len = filesize;
        *offset = align4(data_end);
    }
    1
}

pub unsafe fn cpio_next_ext(
    archive: *const u8,
    archive_len: usize,
    offset: *mut usize,
    entry: *mut CpioEntryExt,
) -> i32 {
    let off = unsafe { *offset };
    if off + CPIO_HEADER_SIZE > archive_len {
        return 0;
    }

    let header = unsafe { archive.add(off) };
    if !check_magic(header) {
        return 0;
    }

    let namesize = parse_hex8(unsafe { header.add(94) });
    let filesize = parse_hex8(unsafe { header.add(54) });

    let name_start = off + CPIO_HEADER_SIZE;
    if name_start + namesize > archive_len {
        return 0;
    }

    let entry_name = unsafe { archive.add(name_start) };
    let mut entry_name_len = namesize;
    if entry_name_len > 0 && unsafe { *entry_name.add(entry_name_len - 1) } == 0 {
        entry_name_len -= 1;
    }

    if is_trailer(entry_name, entry_name_len) {
        return 0;
    }

    let data_start = align4(off + CPIO_HEADER_SIZE + namesize);
    let data_end = data_start + filesize;
    if data_end > archive_len {
        return 0;
    }

    unsafe {
        (*entry).name = entry_name;
        (*entry).name_len = entry_name_len;
        (*entry).data = archive.add(data_start);
        (*entry).data_len = filesize;
        (*entry).ino = parse_hex8(header.add(6)) as u32;
        (*entry).mode = parse_hex8(header.add(14)) as u32;
        (*entry).nlink = parse_hex8(header.add(38)) as u32;
        (*entry).mtime = parse_hex8(header.add(46)) as u32;
        *offset = align4(data_end);
    }
    1
}

pub unsafe fn cpio_archive_size(archive: *const u8, max_len: usize) -> usize {
    let mut offset: usize = 0;

    loop {
        if offset + CPIO_HEADER_SIZE > max_len {
            return max_len;
        }

        let header = unsafe { archive.add(offset) };
        if !check_magic(header) {
            return offset;
        }

        let namesize = parse_hex8(unsafe { header.add(94) });
        let filesize = parse_hex8(unsafe { header.add(54) });

        let name_start = offset + CPIO_HEADER_SIZE;
        if name_start + namesize > max_len {
            return max_len;
        }

        let entry_name = unsafe { archive.add(name_start) };
        let mut entry_name_len = namesize;
        if entry_name_len > 0 && unsafe { *entry_name.add(entry_name_len - 1) } == 0 {
            entry_name_len -= 1;
        }

        let data_start = align4(offset + CPIO_HEADER_SIZE + namesize);
        let data_end = data_start + filesize;
        let next_offset = align4(data_end);

        if is_trailer(entry_name, entry_name_len) {
            return next_offset;
        }

        if data_end > max_len {
            return max_len;
        }

        offset = next_offset;
    }
}
