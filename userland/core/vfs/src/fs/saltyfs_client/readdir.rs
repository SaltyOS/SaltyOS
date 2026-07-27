// SPDX-License-Identifier: GPL-2.0-only
//
//! SHM-batch readdir helpers shared between the saltyfs vop
//! layer (issue side) and the completion router (parse side).
//!
//! SaltyFS encodes one readdir entry as 96 bytes laid out as:
//!
//! | offset | bytes | field            |
//! |-------:|------:|------------------|
//! |      0 |     8 | u64 ino          |
//! |      8 |    16 | reserved         |
//! |     24 |     8 | reserved         |
//! |     32 |     4 | u32 mode         |
//! |     36 |    12 | reserved         |
//! |     48 |     1 | u8 d_type (raw)  |
//! |     49 |     1 | u8 name_len      |
//! |     50 |     2 | reserved         |
//! |     52 |    44 | name bytes (utf8 |
//! |        |       |   no NUL pad)    |
//!
//! Layout is fixed per saltyfs ABI; do not refactor without
//! bumping the ABI tag the daemon negotiates at
//! `BACKEND_OPEN_SESSION`. The completion router copies
//! `bytes_written` bytes out of the SHM ring before releasing
//! credit; the daemon's drain hook must honour the same offset
//! / length contract.

use crate::core::vnode::{VT_DIR, VT_LNK, VT_REG};

const SALTYFS_DIR_TYPE_REG: u8 = 1;
const SALTYFS_DIR_TYPE_DIR: u8 = 4;
const SALTYFS_DIR_TYPE_LNK: u8 = 7;

/// Maximum readdir entry name length the saltyfs ABI allows.
pub(crate) const READDIR_NAME_MAX: usize = 44;

/// Bytes per readdir entry in the SHM ring layout described
/// above.
pub(crate) const READDIR_ENTRY_BYTES: usize = 96;

/// Translate a POSIX `mode` into a `d_type` byte for callers
/// whose backend left the `d_type` slot zero. Falls back to
/// regular-file when the type bits do not match a known
/// catalogue entry — this matches glibc's `getdents` behaviour
/// for filesystems that don't carry per-entry type bytes
/// (FAT family).
#[inline]
pub(crate) fn mode_to_dtype(mode: u32) -> u8 {
    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;
    const S_IFCHR: u32 = 0o020000;
    const S_IFBLK: u32 = 0o060000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;
    match mode & S_IFMT {
        S_IFREG => 8,
        S_IFDIR => 4,
        S_IFLNK => 10,
        S_IFCHR => 2,
        S_IFBLK => 6,
        S_IFIFO => 1,
        S_IFSOCK => 12,
        _ => 8,
    }
}

/// Translate the saltyfs ABI's `d_type` byte to a `VnodeKind`-
/// compatible byte. Used by `alloc_saltyfs_vnode_via_state` when
/// the backend provided a non-zero `d_type` and the cache wants
/// to skip the mode-bit derivation.
#[inline]
pub(crate) fn dtype_to_vtype(dtype: u8) -> u8 {
    match dtype {
        SALTYFS_DIR_TYPE_DIR => VT_DIR,
        SALTYFS_DIR_TYPE_LNK | 10 => VT_LNK,
        _ => VT_REG,
    }
}

/// Translate SaltyFS's compact on-disk dir_type encoding to the
/// POSIX d_type byte the public `getdents` reply exposes.
#[inline]
pub(crate) fn dir_type_to_dtype(dir_type: u8, mode: u32) -> u8 {
    match dir_type {
        SALTYFS_DIR_TYPE_REG => 8,
        SALTYFS_DIR_TYPE_DIR => 4,
        SALTYFS_DIR_TYPE_LNK => 10,
        _ => mode_to_dtype(mode),
    }
}
