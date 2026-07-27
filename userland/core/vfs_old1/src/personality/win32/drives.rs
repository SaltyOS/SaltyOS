// SPDX-License-Identifier: GPL-2.0-only
//! Win32 drive-letter root mapping.
//!
//! Drive letters resolve through stable vnode identities so bootstrap
//! root swaps do not leave stale raw handles behind.

use crate::owner::VfsState;
use crate::vfs_core::identity::VnodeKey;
use crate::vfs_core::vnode::VnodeHandle;

pub(crate) static mut WIN32_DRIVE_ROOTS: [VnodeKey; 26] = [VnodeKey::INVALID; 26];

pub(crate) unsafe fn init_drives(state: &VfsState) {
    unsafe {
        let Some(root_vh) = state.root_vnode() else {
            return;
        };
        let Some(root_vnode) = state.vnodes.get(root_vh) else {
            return;
        };
        let root_key = root_vnode.vnode_key();
        WIN32_DRIVE_ROOTS[2] = root_key;
        WIN32_DRIVE_ROOTS[25] = root_key;
    }
}

pub(crate) unsafe fn resolve_drive_root(state: &VfsState, index: usize) -> Option<VnodeHandle> {
    if index >= 26 {
        return None;
    }
    unsafe {
        let key = WIN32_DRIVE_ROOTS[index];
        if key == VnodeKey::INVALID {
            None
        } else {
            state.vnode_by_key(key)
        }
    }
}
