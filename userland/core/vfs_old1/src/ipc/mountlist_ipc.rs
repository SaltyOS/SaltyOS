// SPDX-License-Identifier: GPL-2.0-only
//! `VFS_MOUNT_LIST` handler — BSD `getfsstat` / `getmntinfo` source.
//!
//! Walks the global mount snapshot, fills a `TronaMountInfo` per entry
//! (including the backend's statvfs view), and packs the result into
//! the IPC buffer's reserved payload area. Truncation is reported via
//! `entries_available > entries_written` so callers can size up.

use trona_kernel::core_types::*;
use trona_posix::types::{
    TRONA_MOUNT_INFO_FS_TYPE_LEN, TRONA_MOUNT_INFO_OPTS_LEN, TRONA_MOUNT_INFO_PATH_LEN,
    TRONA_MOUNT_LIST_MAX_ENTRIES, TronaMountInfo, TronaStatvfs,
};
use uapi::*;

use crate::owner::VfsState;
use crate::vfs_core::mount::MountHandle;
use crate::vfs_core::vfsops::{self, StatfsSnapshot};

pub(crate) unsafe fn handle_vfs_mount_list(
    state: &mut VfsState,
    msg: *const TronaMsg,
    reply: *mut TronaMsg,
) {
    unsafe {
        let max_caller = (*msg).regs[0] as usize;
        let cap = max_caller.min(TRONA_MOUNT_LIST_MAX_ENTRIES);

        let ctx = &*crate::ipc_ctx();
        if ctx.ipc_buffer.is_null() || cap == 0 {
            (*reply).label = TRONA_OK;
            (*reply).length = 2;
            (*reply).regs[0] = 0;
            (*reply).regs[1] = mount_count(state) as u64;
            return;
        }

        let dst = (*ctx.ipc_buffer).reserved.as_mut_ptr().add(1) as *mut TronaMountInfo;
        let mut written = 0usize;
        let mut available = 0usize;

        // Walk the active mount-namespace snapshot rather than the
        // arena directly. This is the same view `getfsstat` /
        // `getmntinfo` callers expect: only mounts grafted into the
        // current namespace, in the order the namespace lists them.
        let snapshot = collect_global_mounts(state);
        for mh in snapshot.iter().copied() {
            if !mh.is_valid() {
                continue;
            }
            available += 1;
            if written >= cap {
                continue;
            }
            let mount = match state.mounts.get(mh) {
                Some(m) => m,
                None => continue,
            };
            let mut info = TronaMountInfo::zeroed();
            info.mount_id = mount.id as u64;
            info.flags = mount.flags;
            let fs_type = &mount.fs_type_name[..mount.fs_type_name_len as usize];
            let fs_type_len = fs_type.len().min(TRONA_MOUNT_INFO_FS_TYPE_LEN);
            info.fs_type[..fs_type_len].copy_from_slice(&fs_type[..fs_type_len]);
            info.fs_type_len = fs_type_len as u8;
            let mount_path = &mount.mount_path[..mount.mount_path_len as usize];
            let path_len = mount_path.len().min(TRONA_MOUNT_INFO_PATH_LEN);
            info.mount_path[..path_len].copy_from_slice(&mount_path[..path_len]);
            info.mount_path_len = path_len as u8;
            let opts = mount.opts_slice();
            let opts_len = opts.len().min(TRONA_MOUNT_INFO_OPTS_LEN);
            info.opts[..opts_len].copy_from_slice(&opts[..opts_len]);
            info.opts_len = opts_len as u8;
            info.statvfs = run_statfs(state, mh);
            core::ptr::write(dst.add(written), info);
            written += 1;
        }

        (*reply).label = TRONA_OK;
        (*reply).length = 2;
        (*reply).regs[0] = written as u64;
        (*reply).regs[1] = available as u64;
    }
}

/// Snapshot the mount handles visible inside the global namespace.
/// Returns an array sized to the namespace cap; trailing slots stay
/// `INVALID` when `mount_count` is below the cap.
fn collect_global_mounts(
    state: &VfsState,
) -> [MountHandle; crate::vfs_core::mount_ns::MAX_NS_MOUNTS] {
    let mut snapshot = [MountHandle::INVALID; crate::vfs_core::mount_ns::MAX_NS_MOUNTS];
    if let Some(ns) = state.mount_namespaces.get(state.global_ns) {
        let count = (ns.mount_count as usize).min(snapshot.len());
        snapshot[..count].copy_from_slice(&ns.mounts[..count]);
    }
    snapshot
}

fn mount_count(state: &VfsState) -> usize {
    state
        .mount_namespaces
        .get(state.global_ns)
        .map(|ns| ns.mount_count as usize)
        .unwrap_or(0)
}

fn run_statfs(state: &VfsState, mount: MountHandle) -> TronaStatvfs {
    let ops_ptr = state
        .mounts
        .get(mount)
        .map(|m| m.vfsops)
        .unwrap_or(core::ptr::null());
    let mut snapshot = StatfsSnapshot::zeroed();
    if let Some(ops) = vfsops::table_from_ptr(ops_ptr) {
        if let Some(callback) = ops.statfs {
            let _ = callback(state, mount, &mut snapshot);
        }
    }
    TronaStatvfs {
        f_bsize: snapshot.f_bsize,
        f_frsize: snapshot.f_frsize,
        f_blocks: snapshot.f_blocks,
        f_bfree: snapshot.f_bfree,
        f_bavail: snapshot.f_bavail,
        f_files: snapshot.f_files,
        f_ffree: snapshot.f_ffree,
        f_favail: snapshot.f_favail,
        f_fsid: snapshot.f_fsid,
        f_flag: snapshot.f_flag,
        f_namemax: snapshot.f_namemax,
    }
}
