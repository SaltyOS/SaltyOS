// SPDX-License-Identifier: GPL-2.0-only
//! Win32 VFS-side ASCII case-folding helpers.

#[inline]
fn ascii_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' { b + 32 } else { b }
}

pub(crate) fn ascii_fold_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut idx = 0usize;
    while idx < a.len() {
        if ascii_lower(a[idx]) != ascii_lower(b[idx]) {
            return false;
        }
        idx += 1;
    }
    true
}
