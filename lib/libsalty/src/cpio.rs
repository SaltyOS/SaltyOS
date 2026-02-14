//! CPIO newc archive parser
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Parses CPIO "newc" (070701) format archives used for the SaltyOS initrd.
//! Provides three iteration styles: search by name (`cpio_find_file`),
//! sequential iteration (`cpio_next`), and sequential iteration with
//! extended metadata (`cpio_next_ext`). Also computes archive total size
//! via `cpio_archive_size`.
//!
//! All functions work on raw byte pointers (no_std compatible) and validate
//! the "070701" magic on each header.

use crate::consts::CPIO_HEADER_SIZE;
use crate::types::{CpioEntry, CpioEntryExt};

/// Parse an 8-character hexadecimal field from a CPIO header.
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

/// Round up to the next 4-byte alignment (CPIO newc requirement).
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Verify the "070701" magic bytes at the start of a CPIO header.
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

/// Check if the entry name is "TRAILER!!!" (end-of-archive sentinel).
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

/// Search for a file by name in a CPIO archive.
///
/// Scans the archive from the beginning for an entry matching
/// `name[0..name_len]`. On success, populates `*entry` with pointers
/// to the name and data within the archive and returns 1. Returns 0
/// if not found.
///
/// # Safety
/// `archive` must point to a valid CPIO archive of at least `archive_len`
/// bytes. `name` must be valid for `name_len` bytes.
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

/// Advance to the next entry in a CPIO archive.
///
/// Reads the entry at `*offset`, populates `*entry`, and advances
/// `*offset` past this entry. Returns 1 if an entry was read, 0 at
/// end-of-archive or on error.
///
/// # Safety
/// `archive` must point to a valid CPIO archive. `offset` and `entry`
/// must be valid pointers.
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

/// Advance to the next entry with extended metadata (ino, mode, nlink, mtime).
///
/// Like `cpio_next`, but also parses inode number, file mode, link count,
/// and modification time from the CPIO header into `*entry`.
///
/// # Safety
/// Same requirements as `cpio_next`.
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

/// Compute the total size of a CPIO archive (up to the TRAILER sentinel).
///
/// Scans headers until the trailer is found or `max_len` is reached.
/// Returns the byte offset just past the trailer, or `max_len` if the
/// archive is truncated.
///
/// # Safety
/// `archive` must point to a valid buffer of at least `max_len` bytes.
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
