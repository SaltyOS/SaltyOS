// SPDX-License-Identifier: GPL-2.0-only
//
//! initrd lookup wrapper. The CPIO archive bytes are mapped at
//! `state.caps.initrd_va` (length `state.caps.initrd_len`). This
//! module is a thin façade over `trona_loader::common::cpio` so the
//! rest of `loader/` can call into it without re-spelling the
//! pointer/length pair every time.

use trona_loader::common::cpio;

use crate::supervisor::SupervisorState;

/// Find the entry whose name matches `binary_name` exactly. Returns
/// the byte slice of the file's contents inside the CPIO image, or
/// `None` if absent. The slice is a borrow of the CPIO mapping —
/// callers must not retain it past the lifetime of the underlying
/// initrd VA.
pub fn find_file<'a>(state: &SupervisorState, binary_name: &[u8]) -> Option<&'a [u8]> {
    if state.caps.initrd_len == 0 {
        return None;
    }
    let entry = unsafe {
        cpio::cpio_find_file(
            state.caps.initrd_va as *const u8,
            state.caps.initrd_len,
            binary_name,
        )
    }?;
    Some(unsafe { core::slice::from_raw_parts(entry.data, entry.data_len) })
}
