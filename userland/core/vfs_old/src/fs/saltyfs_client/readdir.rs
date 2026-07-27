// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS readdir wire helpers — record layout constants and the
//! mode-to-dtype mapping shared between the async issue path in
//! `vops::saltyfs_readdir` and the resume handler in
//! `fileops::dir::resume_fill_bulk_readdir_reply`.

use crate::personality::posix::consts::*;

/// Size of one readdir entry in the SHM stream.
pub(crate) const READDIR_ENTRY_BYTES: usize = 96;

/// Maximum name length within a readdir entry on the SaltyFS wire.
/// Must not exceed the fileops-layer
/// [`crate::fileops::dir::READDIR_FIRST_ENTRY_NAME_MAX`] cap — the
/// fileops reply layout carries the first-entry name inline at that
/// bound, and a longer saltyfs entry would not survive the boundary
/// crossing. The compile-time assert below surfaces any future
/// divergence as a build error rather than silent truncation.
pub(crate) const READDIR_NAME_MAX: usize = 44;

const _: () = assert!(
    READDIR_NAME_MAX <= crate::fileops::dir::READDIR_FIRST_ENTRY_NAME_MAX,
    "saltyfs readdir name cap exceeds fileops first-entry inline cap",
);

/// Map POSIX mode bits to d_type for readdir.
#[inline]
pub(crate) fn mode_to_dtype(mode: u32) -> u8 {
    match mode & S_IFMT_L {
        S_IFDIR_L => 4,  // DT_DIR
        S_IFREG_L => 8,  // DT_REG
        S_IFLNK_L => 10, // DT_LNK
        S_IFCHR_L => 2,  // DT_CHR
        _ => 0,          // DT_UNKNOWN
    }
}
