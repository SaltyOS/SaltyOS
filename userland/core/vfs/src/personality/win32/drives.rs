// SPDX-License-Identifier: GPL-2.0-only
//! Win32 drive letter → vnode root mapping.
//!
//! Win32 paths may begin with a drive letter (`C:\foo`, `Z:\bar`). Each
//! letter maps to a root vnode that serves as the starting point for the
//! path walk. The mapping is stored in a static 26-element array indexed
//! by letter (A=0, B=1, ..., Z=25).
//!
//! During VFS bootstrap, `init_drives()` is called to set the default
//! mappings:
//! - `C:` → filesystem root (same as POSIX `/`)
//! - `Z:` → filesystem root (legacy compatibility)
//!
//! Additional drive letters can be mapped later via `mount_drive()`.

use crate::owner::VfsState;
use crate::vfs_core::vnode::VnodeHandle;

/// Drive root vnodes indexed by letter: A=0, B=1, ..., Z=25.
///
/// Each valid entry is a vnode handle used as the starting vnode for
/// `namei_win32` when a path begins with the corresponding drive letter.
pub(crate) static mut WIN32_DRIVE_ROOTS: [VnodeHandle; 26] = [VnodeHandle::INVALID; 26];

/// Initialize default drive letter mappings.
///
/// Must be called after the root mount is established. Sets:
/// - `C:` → root mount's root vnode
/// - `Z:` → root mount's root vnode
///
/// # Safety
///
/// Must be called after `state.root_mount` is established.
pub(crate) unsafe fn init_drives(state: &VfsState) {
    unsafe {
        if !state.root_mount.is_valid() {
            return;
        }
        let Some(root_mount) = state.mounts.get(state.root_mount) else {
            return;
        };
        let root_vh = root_mount.root_vnode;
        if !root_vh.is_valid() {
            return;
        }
        WIN32_DRIVE_ROOTS[2] = root_vh;
        WIN32_DRIVE_ROOTS[25] = root_vh;
    }
}

/// Resolve a drive letter index (0-25) to its root vnode.
///
/// Returns the vref'd vnode for the drive, or `None` if the drive is
/// not mapped.
///
/// # Safety
///
pub(crate) unsafe fn resolve_drive_root(index: usize) -> Option<VnodeHandle> {
    if index >= 26 {
        return None;
    }
    unsafe {
        let vh = core::ptr::addr_of!(WIN32_DRIVE_ROOTS).read()[index];
        if !vh.is_valid() {
            return None;
        }
        Some(vh)
    }
}
