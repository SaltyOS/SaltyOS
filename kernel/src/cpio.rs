//! CPIO newc Archive Parser
//!
//! Minimal read-only parser for CPIO newc format archives (initrd).
//! Finds files by name within a CPIO archive stored in memory.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// CPIO newc magic bytes
const CPIO_MAGIC: &[u8; 6] = b"070701";

/// Header size in bytes (110 = 6 magic + 13*8 hex fields)
const HEADER_SIZE: usize = 110;

/// A file entry found in a CPIO archive
pub struct CpioEntry<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
}

/// Parse an 8-character hex ASCII field from a CPIO header
fn parse_hex8(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 8 {
        return None;
    }
    let mut val: usize = 0;
    for &b in &bytes[..8] {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            b'A'..=b'F' => (b - b'A' + 10) as usize,
            _ => return None,
        };
        val = (val << 4) | digit;
    }
    Some(val)
}

/// Align up to 4-byte boundary
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Find a file by name in a CPIO newc archive
///
/// Returns the file's data slice if found, None otherwise.
/// The archive must be CPIO newc format ("070701" magic).
pub fn find_file<'a>(archive: &'a [u8], name: &str) -> Option<CpioEntry<'a>> {
    let name_bytes = name.as_bytes();
    let mut offset = 0;

    loop {
        // Need at least a header
        if offset + HEADER_SIZE > archive.len() {
            return None;
        }

        let header = &archive[offset..offset + HEADER_SIZE];

        // Verify magic
        if &header[0..6] != CPIO_MAGIC {
            return None;
        }

        // Parse namesize (offset 94, 8 hex chars)
        let namesize = parse_hex8(&header[94..102])?;

        // Parse filesize (offset 54, 8 hex chars)
        let filesize = parse_hex8(&header[54..62])?;

        // Filename starts right after header
        let name_start = offset + HEADER_SIZE;
        if name_start + namesize > archive.len() {
            return None;
        }

        // Name includes NUL terminator; compare without it
        let entry_name = if namesize > 0 && archive[name_start + namesize - 1] == 0 {
            &archive[name_start..name_start + namesize - 1]
        } else {
            &archive[name_start..name_start + namesize]
        };

        // Check for trailer
        if entry_name == b"TRAILER!!!" {
            return None;
        }

        // Data starts after name, aligned to 4 bytes
        let data_start = align4(offset + HEADER_SIZE + namesize);
        let data_end = data_start + filesize;

        if data_end > archive.len() {
            return None;
        }

        // Check if this is the file we're looking for
        if entry_name == name_bytes {
            return Some(CpioEntry {
                name: entry_name,
                data: &archive[data_start..data_end],
            });
        }

        // Move to next entry (data end, aligned to 4 bytes)
        offset = align4(data_end);
    }
}
