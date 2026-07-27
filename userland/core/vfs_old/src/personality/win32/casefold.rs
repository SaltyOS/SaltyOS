// SPDX-License-Identifier: GPL-2.0-only
//! Win32 VFS-side ASCII case-folding for path comparison.
//!
//! Win32 path resolution is case-insensitive. The actual Unicode Simple
//! Case-Folding lives in `trona_protocol::vfs::casefold` and is used by
//! `VopVector::lookup_ci` (the filesystem-side readdir scan fallback).
//!
//! This module provides a fast ASCII-only comparison used by the VFS layer
//! itself — drive letter matching, reserved device name detection, and
//! the initial exact-then-CI two-phase lookup in `namei_win32`.
//!
//! ASCII suffices at the VFS grammar level because all Win32 structural
//! tokens (drive letters, reserved names, path separators) are ASCII.
//! Non-ASCII filenames go through `lookup_ci` on the filesystem side.

/// Compare two byte slices for equality under ASCII case-folding.
///
/// Returns `true` if `a` and `b` have the same length and every
/// corresponding byte pair matches after mapping `A-Z` → `a-z`.
/// Non-ASCII bytes are compared as-is (they never appear in Win32
/// structural tokens).
pub(crate) fn ascii_fold_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if ascii_lower(a[i]) != ascii_lower(b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// Map a single byte to ASCII lowercase. Non-ASCII bytes pass through.
#[inline]
fn ascii_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' { b + 32 } else { b }
}

/// Check if a byte is an ASCII letter (A-Z or a-z).
#[inline]
pub(crate) fn is_ascii_alpha(b: u8) -> bool {
    (b >= b'A' && b <= b'Z') || (b >= b'a' && b <= b'z')
}

/// Convert a drive letter (A-Z or a-z) to a 0-based index (0..26).
/// Returns `None` if the byte is not an ASCII letter.
#[inline]
pub(crate) fn drive_letter_index(letter: u8) -> Option<usize> {
    if letter >= b'A' && letter <= b'Z' {
        Some((letter - b'A') as usize)
    } else if letter >= b'a' && letter <= b'z' {
        Some((letter - b'a') as usize)
    } else {
        None
    }
}
