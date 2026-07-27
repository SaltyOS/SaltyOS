// SPDX-License-Identifier: GPL-2.0-only
//
//! Shared POSIX wire decode helpers — path-bytes unpacking.

use trona_kernel::core_types::TronaMsg;

use crate::owner::pending::WALK_PATH_MAX;

/// Unpack `len` bytes from `msg.regs[word_start..]` (little-
/// endian, 8 per word) into `dst`. `dst` must be sized to
/// `WALK_PATH_MAX`. Bytes past `len` are left zero.
pub(crate) unsafe fn decode_path_bytes(
    msg: &TronaMsg,
    word_start: usize,
    len: usize,
    dst: &mut [u8; WALK_PATH_MAX],
) {
    let cap = len.min(WALK_PATH_MAX);
    let regs_len = msg.regs.len();
    let mut written = 0usize;
    let mut idx = word_start;
    while written < cap && idx < regs_len {
        let word = msg.regs[idx].to_le_bytes();
        let take = (cap - written).min(8);
        dst[written..written + take].copy_from_slice(&word[..take]);
        written += take;
        idx += 1;
    }
}
