// SPDX-License-Identifier: GPL-2.0-only
//! VFS_MOUNT / VFS_UMOUNT / VFS_PIVOT_ROOT IPC handlers.
//!
//! Routes to the centralized mount controller in `vfs_core::mount_ctl`.

use trona::consts::kernel::*;
use trona::types::core::*;

use crate::owner::VfsState;
use crate::vfs_core::mount_ctl;

const MAX_STR_LEN: usize = 128;

// =========================================================================
// VFS_MOUNT
// =========================================================================

/// Wire format:
///   regs[0] = source_len
///   regs[1] = target_len
///   regs[2] = fstype_len
///   regs[3] = flags
///   regs[4] = opts_len
///   Strings packed sequentially in regs[5..] / IPC buffer overflow.
pub(crate) unsafe fn handle_vfs_mount(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    _badge: u64,
) {
    unsafe {
        let source_len = (*msg).regs[0] as usize;
        let target_len = (*msg).regs[1] as usize;
        let fstype_len = (*msg).regs[2] as usize;
        let flags = (*msg).regs[3] as u32;
        let opts_len = (*msg).regs[4] as usize;

        if source_len > MAX_STR_LEN || target_len > MAX_STR_LEN || fstype_len > 16 || opts_len > 64
        {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let total = source_len + target_len + fstype_len + opts_len;
        if total > 96 {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        // Extract strings from regs[5..] area
        let payload = (&raw const (*msg).regs).cast::<u8>().add(5 * 8);
        let mut off = 0usize;

        let mut source_buf = [0u8; MAX_STR_LEN];
        copy_payload(payload, off, &mut source_buf, source_len);
        off += source_len;

        let mut target_buf = [0u8; MAX_STR_LEN];
        copy_payload(payload, off, &mut target_buf, target_len);
        off += target_len;

        let mut fstype_buf = [0u8; 16];
        copy_payload(payload, off, &mut fstype_buf, fstype_len);
        off += fstype_len;

        let mut opts_buf = [0u8; 64];
        copy_payload(payload, off, &mut opts_buf, opts_len);

        let target = &target_buf[..target_len];
        let fstype = &fstype_buf[..fstype_len];

        let target_vh = match mount_ctl::resolve_mount_path(state, target) {
            Ok(vh) => vh,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        match mount_ctl::do_mount(
            state,
            target_vh,
            fstype,
            target,
            0,
            flags,
            opts_buf.as_ptr(),
            opts_len as u8,
        ) {
            Ok(_mh) => {
                mount_ctl::refresh_global_ns(state);
                (*reply).label = TRONA_OK;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
    }
}

// =========================================================================
// VFS_UMOUNT
// =========================================================================

/// Wire format:
///   regs[0] = target_len
///   regs[1] = flags
///   Strings in regs[2..].
pub(crate) unsafe fn handle_vfs_umount(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    _badge: u64,
) {
    unsafe {
        let target_len = (*msg).regs[0] as usize;
        let flags = (*msg).regs[1] as u32;

        if target_len > MAX_STR_LEN {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let payload = (&raw const (*msg).regs).cast::<u8>().add(2 * 8);
        let mut target_buf = [0u8; MAX_STR_LEN];
        copy_payload(payload, 0, &mut target_buf, target_len);

        let target = &target_buf[..target_len];

        let target_vh = match mount_ctl::resolve_mount_path(state, target) {
            Ok(vh) => vh,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        match mount_ctl::do_umount(state, target_vh, flags) {
            Ok(()) => {
                mount_ctl::refresh_global_ns(state);
                (*reply).label = TRONA_OK;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
    }
}

// =========================================================================
// VFS_PIVOT_ROOT
// =========================================================================

/// Wire format:
///   regs[0] = new_root_len
///   regs[1] = put_old_len
///   Strings in regs[2..].
pub(crate) unsafe fn handle_vfs_pivot_root(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
    _badge: u64,
) {
    unsafe {
        let new_root_len = (*msg).regs[0] as usize;
        let put_old_len = (*msg).regs[1] as usize;

        if new_root_len > MAX_STR_LEN || put_old_len > MAX_STR_LEN {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let payload = (&raw const (*msg).regs).cast::<u8>().add(2 * 8);
        let mut new_root_buf = [0u8; MAX_STR_LEN];
        copy_payload(payload, 0, &mut new_root_buf, new_root_len);

        let mut put_old_buf = [0u8; MAX_STR_LEN];
        copy_payload(payload, new_root_len, &mut put_old_buf, put_old_len);

        let new_root = &new_root_buf[..new_root_len];
        let put_old = &put_old_buf[..put_old_len];

        let new_root_vh = match mount_ctl::resolve_mount_path(state, new_root) {
            Ok(vh) => vh,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        // Find the mount covering this vnode.
        let new_root_mh = match mount_ctl::covering_mount_for_vnode(state, new_root_vh) {
            Some(mh) => mh,
            None => {
                (*reply).label = TRONA_INVALID_OPERATION;
                return;
            }
        };

        if !new_root_mh.is_valid() {
            (*reply).label = TRONA_INVALID_OPERATION;
            return;
        }

        let put_old_vh = match mount_ctl::resolve_mount_path(state, put_old) {
            Ok(vh) => vh,
            Err(e) => {
                (*reply).label = e.to_trona();
                return;
            }
        };

        match mount_ctl::do_pivot_root(state, new_root_mh, put_old_vh) {
            Ok(()) => {
                (*reply).label = TRONA_OK;
            }
            Err(e) => {
                (*reply).label = e.to_trona();
            }
        }
    }
}

// =========================================================================
// Helpers
// =========================================================================

unsafe fn copy_payload(src: *const u8, offset: usize, dst: &mut [u8], len: usize) {
    unsafe {
        let cap = if len < dst.len() { len } else { dst.len() };
        for i in 0..cap {
            dst[i] = *src.add(offset + i);
        }
    }
}
