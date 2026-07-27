// SPDX-License-Identifier: GPL-2.0-only
//! Shared regular-file data plane helpers.
//!
//! Inline read/write, bulk SHM transfer, and mmap pager callbacks should all
//! agree on how regular-file bytes are obtained. New backends must plug into
//! this layer instead of teaching each transport path about backend-specific
//! storage.

use uapi::*;

use crate::owner::VfsState;
use crate::server::types::ClientHandle;
use crate::vfs_core::vnode::{VT_DIR, VT_REG, VnodeHandle};

#[inline]
pub(crate) fn supports_pager_backing(state: &VfsState, vnode: VnodeHandle) -> bool {
    let Some(vn) = state.vnodes.get(vnode) else {
        return false;
    };
    if vn.vtype != VT_REG {
        return false;
    }
    crate::vfs_core::vops::supports_pager_backing(state, vnode)
}

pub(crate) unsafe fn read_into(
    state: &VfsState,
    cli_handle: Option<ClientHandle>,
    vnode: VnodeHandle,
    offset: u64,
    out: *mut u8,
    cap: usize,
) -> Result<usize, u64> {
    let Some(vn) = state.vnodes.get(vnode) else {
        return Err(TRONA_INVALID_ARGUMENT);
    };
    if vn.vtype != VT_REG {
        return Err(if vn.vtype == VT_DIR {
            TRONA_IS_DIRECTORY
        } else {
            TRONA_NOT_SUPPORTED
        });
    }

    if let Some(result) =
        unsafe { crate::vfs_core::vops::read_regular(state, cli_handle, vnode, offset, out, cap) }
    {
        return crate::vfs_core::vops::into_value_or_label(result);
    }

    let available = vn.size.saturating_sub(offset);
    let actual = core::cmp::min(cap as u64, available) as usize;
    if actual != 0 {
        let src = (vn.data as *const u8).wrapping_add(offset as usize);
        unsafe {
            core::ptr::copy_nonoverlapping(src, out, actual);
        }
    }
    Ok(actual)
}

pub(crate) unsafe fn write_from(
    state: &mut VfsState,
    vnode: VnodeHandle,
    offset: u64,
    src: *const u8,
    len: usize,
) -> Result<u64, u64> {
    let Some(vn) = state.vnodes.get(vnode) else {
        return Err(TRONA_INVALID_ARGUMENT);
    };
    if vn.vtype != VT_REG {
        return Err(if vn.vtype == VT_DIR {
            TRONA_IS_DIRECTORY
        } else {
            TRONA_NOT_SUPPORTED
        });
    }

    if let Some(result) =
        unsafe { crate::vfs_core::vops::write_regular(state, vnode, offset, src, len) }
    {
        return crate::vfs_core::vops::into_value_or_label(result);
    }

    state
        .bootstrap_write_file(vnode, offset, src, len)
        .ok_or(TRONA_OUT_OF_MEMORY)
}
