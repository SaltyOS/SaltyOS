// SPDX-License-Identifier: GPL-2.0-only
//! Directory name hashing and comparison helpers, with optional Unicode
//! Simple Case-Folding for `SALTY_INODE_CASEFOLD` directories.
//!
//! The casefold table (`casefold_table::CASEFOLD_TABLE`) is generated from
//! Unicode 15.1.0 `CaseFolding.txt`, keeping only status `C` (Common) and
//! `S` (Simple) mappings. Full (`F`, 1→many) and Turkic (`T`, locale-
//! specific) mappings are deliberately excluded — see docs/design/saltyfs.md
//! for the rationale.
//!
//! Invalid UTF-8 names are rejected at the top of insert paths in
//! handlers.rs (see `is_valid_utf8`) when the parent directory is casefold;
//! lookup paths degrade gracefully to raw-byte comparison for robustness.

use crate::casefold_table::CASEFOLD_TABLE;

/// Maximum folded buffer size. Matches the IPC name cap (max 144 bytes) with
/// slack so that no legal SaltyFS filename can overflow the buffer after
/// Simple Case-Folding (which is 1:1 at the codepoint level).
pub(crate) const FOLD_BUF_MAX: usize = 256;

/// FNV-1a offset basis / prime — must match the dir_item hash in handlers.rs
/// so that V1 (non-casefold) directories stay bit-compatible.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

/// Basic FNV-1a over raw bytes. Kept here so casefold and non-casefold paths
/// share the same hashing math and can't drift apart.
#[inline]
pub(crate) fn fnv1a_bytes(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Fold a single Unicode codepoint using Simple Case-Folding.
/// ASCII fast path returns `b + 32` for `A..Z`; everything else goes through
/// a binary search over `CASEFOLD_TABLE`. Unmapped codepoints are returned
/// unchanged.
#[inline]
pub(crate) fn fold_codepoint(cp: u32) -> u32 {
    if cp < 0x80 {
        if cp >= b'A' as u32 && cp <= b'Z' as u32 {
            return cp + 32;
        }
        return cp;
    }
    let table = CASEFOLD_TABLE;
    let mut lo = 0usize;
    let mut hi = table.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (k, v) = table[mid];
        if k == cp {
            return v;
        } else if k < cp {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    cp
}

/// Check whether a byte slice is valid UTF-8 without allocating.
#[inline]
pub(crate) fn is_valid_utf8(name: &[u8]) -> bool {
    core::str::from_utf8(name).is_ok()
}

/// Decode UTF-8, fold each codepoint via Simple CF, re-encode UTF-8 into
/// `dst`. Returns the number of bytes written, or `None` on invalid UTF-8
/// or if the output would not fit.
pub(crate) fn fold_utf8(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    let s = core::str::from_utf8(src).ok()?;
    let mut pos = 0usize;
    for c in s.chars() {
        let folded_cp = fold_codepoint(c as u32);
        let folded_char = char::from_u32(folded_cp)?;
        let mut buf = [0u8; 4];
        let enc_len = folded_char.encode_utf8(&mut buf).len();
        if pos + enc_len > dst.len() {
            return None;
        }
        for i in 0..enc_len {
            dst[pos + i] = buf[i];
        }
        pos += enc_len;
    }
    Some(pos)
}

/// FNV-1a hash computed over the Simple Case-Folded representation of
/// `name`. Invalid UTF-8 falls back to raw-byte hashing so lookups don't
/// panic on legacy names — insert paths should have rejected such names
/// upstream when the parent directory is casefold.
#[inline]
pub(crate) fn casefold_hash(name: &[u8]) -> u64 {
    let mut buf = [0u8; FOLD_BUF_MAX];
    match fold_utf8(name, &mut buf) {
        Some(len) => fnv1a_bytes(&buf[..len]),
        None => fnv1a_bytes(name),
    }
}

/// Case-insensitive equality over UTF-8 names. Folds both sides into stack
/// buffers; invalid UTF-8 on either side falls back to raw byte compare.
pub(crate) fn casefold_equal(a: &[u8], b: &[u8]) -> bool {
    let mut ba = [0u8; FOLD_BUF_MAX];
    let mut bb = [0u8; FOLD_BUF_MAX];
    match (fold_utf8(a, &mut ba), fold_utf8(b, &mut bb)) {
        (Some(la), Some(lb)) => {
            if la != lb {
                return false;
            }
            ba[..la] == bb[..lb]
        }
        _ => {
            if a.len() != b.len() {
                return false;
            }
            for i in 0..a.len() {
                if a[i] != b[i] {
                    return false;
                }
            }
            true
        }
    }
}

/// Dispatch helper: returns a hash suitable for DIR_ITEM key offsets,
/// branching on the parent directory's `SALTY_INODE_CASEFOLD` flag.
#[inline]
pub(crate) fn dir_name_hash(name: &[u8], casefold: bool) -> u64 {
    if casefold {
        casefold_hash(name)
    } else {
        fnv1a_bytes(name)
    }
}

/// Dispatch helper: returns true if the two names match under the parent
/// directory's casefold policy.
#[inline]
pub(crate) fn dir_name_equal(a: &[u8], b: &[u8], casefold: bool) -> bool {
    if casefold {
        casefold_equal(a, b)
    } else {
        if a.len() != b.len() {
            return false;
        }
        for i in 0..a.len() {
            if a[i] != b[i] {
                return false;
            }
        }
        true
    }
}
