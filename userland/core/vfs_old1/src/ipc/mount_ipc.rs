// SPDX-License-Identifier: GPL-2.0-only
//! Minimal mount-control IPC handlers.
//!
//! The rebuilt VFS only exposes synchronous structural mount operations
//! for now. Backends are not opened asynchronously; mounts are owner-side
//! namespace objects that can be grafted and pivoted immediately.

use trona_kernel::core_types::*;
use uapi::*;

use crate::owner::VfsState;
use crate::vfs_core::mount_ctl;

const MAX_STR_LEN: usize = 128;
const MAX_FS_TYPE_LEN: usize = 16;
const MAX_OPTS_LEN: usize = 128;
const MAX_MOUNT_PAYLOAD: usize = 216;

pub(crate) unsafe fn handle_vfs_mount(
    state: &mut VfsState,
    badge: u64,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let source_len = (*msg).regs[0] as usize;
        let target_len = (*msg).regs[1] as usize;
        let fstype_len = (*msg).regs[2] as usize;
        let flags = (*msg).regs[3] as u32;
        let opts_len = (*msg).regs[4] as usize;

        if source_len > MAX_STR_LEN
            || target_len > MAX_STR_LEN
            || fstype_len == 0
            || fstype_len > MAX_FS_TYPE_LEN
            || opts_len > MAX_OPTS_LEN
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let total = source_len + target_len + fstype_len + opts_len;
        if total > MAX_MOUNT_PAYLOAD {
            (*reply).label = TRONA_TOO_LARGE;
            (*reply).length = 0;
            return;
        }

        let payload = (&raw const (*msg).regs).cast::<u8>().add(5 * 8);
        let target_off = source_len;
        let fstype_off = target_off + target_len;
        let opts_off = fstype_off + fstype_len;

        let mut target_buf = [0u8; MAX_STR_LEN];
        let mut fstype_buf = [0u8; MAX_FS_TYPE_LEN];
        let mut opts_buf = [0u8; MAX_OPTS_LEN];
        copy_payload(payload, target_off, &mut target_buf, target_len);
        copy_payload(payload, fstype_off, &mut fstype_buf, fstype_len);
        copy_payload(payload, opts_off, &mut opts_buf, opts_len);

        (*reply).label = mount_ctl::do_mount_for_badge(
            state,
            badge,
            &target_buf[..target_len],
            &fstype_buf[..fstype_len],
            flags,
            &opts_buf[..opts_len],
        );
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_vfs_remount(
    state: &mut VfsState,
    badge: u64,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let source_len = (*msg).regs[0] as usize;
        let target_len = (*msg).regs[1] as usize;
        let fstype_len = (*msg).regs[2] as usize;
        let new_flags = (*msg).regs[3] as u32;
        let opts_len = (*msg).regs[4] as usize;

        if target_len == 0
            || target_len > MAX_STR_LEN
            || source_len > MAX_STR_LEN
            || fstype_len > MAX_FS_TYPE_LEN
            || opts_len > MAX_OPTS_LEN
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }
        let total = source_len + target_len + fstype_len + opts_len;
        if total > MAX_MOUNT_PAYLOAD {
            (*reply).label = TRONA_TOO_LARGE;
            (*reply).length = 0;
            return;
        }

        let payload = (&raw const (*msg).regs).cast::<u8>().add(5 * 8);
        let target_off = source_len;
        let opts_off = target_off + target_len + fstype_len;

        let mut target_buf = [0u8; MAX_STR_LEN];
        let mut opts_buf = [0u8; MAX_OPTS_LEN];
        copy_payload(payload, target_off, &mut target_buf, target_len);
        copy_payload(payload, opts_off, &mut opts_buf, opts_len);

        (*reply).label = mount_ctl::do_remount_for_badge(
            state,
            badge,
            &target_buf[..target_len],
            new_flags,
            &opts_buf[..opts_len],
        );
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_vfs_umount(
    state: &mut VfsState,
    badge: u64,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let target_len = (*msg).regs[0] as usize;
        let flags = (*msg).regs[1] as u32;
        if target_len == 0 || target_len > MAX_STR_LEN {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let payload = (&raw const (*msg).regs).cast::<u8>().add(2 * 8);
        let mut target_buf = [0u8; MAX_STR_LEN];
        copy_payload(payload, 0, &mut target_buf, target_len);

        (*reply).label =
            mount_ctl::do_umount_for_badge(state, badge, &target_buf[..target_len], flags);
        (*reply).length = 0;
    }
}

pub(crate) unsafe fn handle_vfs_pivot_root(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let new_root_len = (*msg).regs[0] as usize;
        let put_old_len = (*msg).regs[1] as usize;
        if new_root_len == 0
            || new_root_len > MAX_STR_LEN
            || put_old_len == 0
            || put_old_len > MAX_STR_LEN
        {
            (*reply).label = TRONA_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let payload = (&raw const (*msg).regs).cast::<u8>().add(2 * 8);
        let mut new_root_buf = [0u8; MAX_STR_LEN];
        let mut put_old_buf = [0u8; MAX_STR_LEN];
        copy_payload(payload, 0, &mut new_root_buf, new_root_len);
        copy_payload(payload, new_root_len, &mut put_old_buf, put_old_len);

        (*reply).label = mount_ctl::do_pivot_root(
            state,
            &new_root_buf[..new_root_len],
            &put_old_buf[..put_old_len],
        );
        (*reply).length = 0;
    }
}

unsafe fn copy_payload(src: *const u8, offset: usize, dst: &mut [u8], len: usize) {
    unsafe {
        let count = core::cmp::min(len, dst.len());
        for i in 0..count {
            dst[i] = *src.add(offset + i);
        }
    }
}
