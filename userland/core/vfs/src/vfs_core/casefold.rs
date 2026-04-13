// SPDX-License-Identifier: GPL-2.0-only
//! VFS-level case-insensitive lookup fallback.
//!
//! Provides `readdir_casefold_scan` — an O(n) readdir-based fallback for
//! `VopMetaOps::lookup_ci` that works with any filesystem that implements
//! `readdir` + `lookup`. Filesystems with a native case-folded index
//! (e.g. saltyfs with `SALTY_INODE_CASEFOLD`) override `lookup_ci`
//! directly for O(log n) lookups.

use super::error::{VfsError, VfsResult};
use super::file::VAttr;
use super::vnode::{Vnode, VnodeHandle};
use super::vop_context::{VopContext, VopDataContext};

/// Maximum filename length supported by the scan buffer.
const NAME_BUF_MAX: usize = 255;

/// Scan a directory via `VopDataOps::readdir`, comparing each entry name
/// against `name[..name_len]` using Unicode Simple Case-Folding. On the
/// first match, perform an exact `VopMetaOps::lookup` with the stored
/// on-disk name to obtain a handle.
///
/// Returns `Ok(VnodeHandle)` on match, `Ok(VnodeHandle::INVALID)` on no
/// match (ENOENT), or `Err(...)` on readdir/lookup failure.
///
/// # Context
///
/// `ctx` must be a valid VopContext for the directory vnode. The caller
/// builds a VopDataContext from the same vnode for the readdir call.
pub(crate) unsafe fn readdir_casefold_scan(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let vnode = &*ctx.vnode;
        let ops = vnode.ops;
        if ops.is_null() {
            return Err(VfsError::Io);
        }

        let needle = core::slice::from_raw_parts(name, name_len as usize);

        let mut matched_name = [0u8; NAME_BUF_MAX];
        let mut matched_len: u8 = 0;
        let mut found = false;

        let mut cookie: u64 = 0;

        // Build a VopDataContext from the same vnode for readdir.
        let data_ctx = VopDataContext::new(
            ctx.handle,
            ctx.mount_handle,
            ctx.data,
            ctx.mount_data,
            vnode.vtype,
            vnode.id,
        );

        loop {
            let prev_cookie = cookie;
            let result = {
                let mn = &mut matched_name;
                let ml = &mut matched_len;
                let f = &mut found;
                let mut emit = |_ino: u64,
                                entry_name: *const u8,
                                entry_len: u8,
                                _dtype: u8,
                                _attr: &VAttr|
                 -> bool {
                    if *f {
                        return false;
                    }
                    let entry = core::slice::from_raw_parts(entry_name, entry_len as usize);
                    if trona::casefold::casefold_equal(needle, entry) {
                        let copy_len = (entry_len as usize).min(NAME_BUF_MAX);
                        mn[..copy_len].copy_from_slice(&entry[..copy_len]);
                        *ml = copy_len as u8;
                        *f = true;
                        return false;
                    }
                    true
                };
                ((*ops).data.readdir)(&data_ctx, &mut cookie, &mut emit)
            };

            if found {
                return ((*ops).meta.lookup)(ctx, matched_name.as_ptr(), matched_len);
            }

            match result {
                Ok(()) => {
                    if cookie == prev_cookie {
                        return Ok(VnodeHandle::INVALID);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}
