// SPDX-License-Identifier: GPL-2.0-only
//! Generic case-folded name comparison.
//!
//! Backends call [`casefold_equal`] when their mount carries the
//! `MNT_CASEFOLD` flag; the function delegates to the trona substrate's
//! Unicode 15.1 Simple Case-Folding implementation. Invalid UTF-8
//! falls back to raw byte comparison so legacy / binary names still
//! round-trip predictably.

#[inline]
pub(crate) fn casefold_equal(a: &[u8], b: &[u8]) -> bool {
    trona_protocol::vfs::casefold::casefold_equal(a, b)
}

#[inline]
pub(crate) fn name_eq(a: &[u8], b: &[u8], casefold: bool) -> bool {
    if casefold {
        casefold_equal(a, b)
    } else {
        a == b
    }
}
