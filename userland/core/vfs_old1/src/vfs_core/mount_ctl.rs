// SPDX-License-Identifier: GPL-2.0-only
//! Structural mount controller.
//!
//! The rebuilt VFS starts with a strictly synchronous mount model:
//! mount-tree mutations happen in the owner thread and complete before
//! the caller is replied to. This module owns the namespace-facing mount
//! operations needed by bootstrap and by the early `VFS_MOUNT` /
//! `VFS_PIVOT_ROOT` IPC surface.

use uapi::*;

use crate::fs::{devfs, pipefs, procfs, saltyfs, sysctlfs, tmpfs};
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

use super::bootstrap::BOOTSTRAP_PSEUDO_MOUNTS;
use super::cached_ref::CachedRef;
use super::mount::{MOUNT_FS_TYPE_MAX, Mount, MountHandle};
use super::mount_ns;
use super::mount_options;
use super::vnode::{VN_COVERED, Vnode, VnodeHandle};

/// Resolve the child mount currently covering `target_vh`, if any.
pub(crate) fn covering_mount_for_vnode(
    state: &VfsState,
    target_vh: VnodeHandle,
) -> Option<MountHandle> {
    let vnode = state.vnodes.get(target_vh)?;
    if vnode.covered_by.id != super::identity::FsInstanceId::INVALID {
        if let Some(mh) = state.mount_by_fs_instance_id(vnode.covered_by.id) {
            return Some(mh);
        }
    }

    let target_key = vnode.vnode_key();
    let mut found = MountHandle::INVALID;
    state.mounts.for_each_active(|mh, mount| {
        if mount.covered.id == target_key {
            found = mh;
            return false;
        }
        true
    });

    if found.is_valid() { Some(found) } else { None }
}

/// Refresh the global mount namespace snapshot after structural changes.
pub(crate) fn refresh_global_ns(state: &mut VfsState) {
    if !state.global_ns.is_valid() {
        return;
    }

    let mut handles = [MountHandle::INVALID; mount_ns::MAX_NS_MOUNTS];
    let mut count = 0usize;
    state.mounts.for_each_active(|mh, _| {
        if count >= handles.len() {
            return false;
        }
        handles[count] = mh;
        count += 1;
        true
    });

    if let Some(ns) = state.mount_namespaces.get_mut(state.global_ns) {
        ns.root_mount = state.root_mount;
        ns.mounts = [MountHandle::INVALID; mount_ns::MAX_NS_MOUNTS];
        ns.mounts[..count].copy_from_slice(&handles[..count]);
        ns.mount_count = count as u8;
    }
}

/// Resolve a bootstrap-visible absolute path.
pub(crate) fn resolve_bootstrap_mount_path(
    state: &VfsState,
    path: &[u8],
) -> Result<VnodeHandle, u64> {
    if path.is_empty() || path[0] != b'/' {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    state.bootstrap_lookup_path(path).ok_or(TRONA_NOT_FOUND)
}

fn mount_cover_target_for_root(state: &VfsState, root_vh: VnodeHandle) -> Option<VnodeHandle> {
    let mut found = VnodeHandle::INVALID;
    state.mounts.for_each_active(|_, mount| {
        if mount.root_vnode == root_vh && mount.covered.handle.is_valid() {
            found = mount.covered.handle;
            return false;
        }
        true
    });
    if found.is_valid() { Some(found) } else { None }
}

fn mountpoint_from_lookup_result(state: &VfsState, vh: VnodeHandle) -> VnodeHandle {
    mount_cover_target_for_root(state, vh).unwrap_or(vh)
}

fn resolve_runtime_mount_path(
    state: &mut VfsState,
    client: Option<ClientHandle>,
    path: &[u8],
) -> Result<VnodeHandle, u64> {
    if path.is_empty() || path[0] != b'/' {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    let lookup = match client {
        Some(cli) => state.lookup_path_dynamic_for_client(cli, path, false),
        None => state.lookup_path_dynamic_absolute(path, false),
    };
    let resolved = match lookup? {
        crate::vfs_core::vops::VfsOpResult::Complete(Some(vh)) => vh,
        crate::vfs_core::vops::VfsOpResult::Complete(None) => return Err(TRONA_NOT_FOUND),
        crate::vfs_core::vops::VfsOpResult::Deferred(op_id) => {
            unsafe {
                crate::owner::pending_ops::free(op_id);
            }
            return Err(TRONA_INVALID_OPERATION);
        }
    };
    Ok(mountpoint_from_lookup_result(state, resolved))
}

fn resolve_runtime_mount_path_for_badge(
    state: &mut VfsState,
    badge: u64,
    path: &[u8],
) -> Result<VnodeHandle, u64> {
    let client = state.lookup_client(badge);
    resolve_runtime_mount_path(state, client, path)
}

fn alloc_structural_mount(
    state: &mut VfsState,
    fs_type_name: &[u8],
    mount_path: &[u8],
    flags: u32,
    opts: &[u8],
) -> Option<MountHandle> {
    let _ = opts;
    if fs_type_name.is_empty() || fs_type_name.len() > MOUNT_FS_TYPE_MAX {
        return None;
    }

    let root_vh = state.vnodes.alloc()?;
    let mh = state.mounts.alloc()?;
    let fs_id = state.alloc_fs_instance_id();

    {
        let vnode = state.vnodes.get_mut(root_vh)?;
        *vnode = Vnode::new_mounted_root_dir(fs_id);
    }

    {
        let mount = state.mounts.get_mut(mh)?;
        *mount = Mount::new_structural(
            (mh.slot().saturating_add(1)) as u16,
            flags,
            fs_id,
            root_vh,
            fs_type_name,
            mount_path,
        );
    }

    {
        let vnode = state.vnodes.get_mut(root_vh)?;
        vnode.mount = CachedRef::new(fs_id, mh);
    }

    Some(mh)
}

fn alloc_mount_for_fs(
    state: &mut VfsState,
    fs_type_name: &[u8],
    mount_path: &[u8],
    flags: u32,
    opts: &[u8],
) -> Result<MountHandle, u64> {
    if fs_type_name == b"pipefs" {
        return pipefs::alloc_mount(state, mount_path, flags, opts).ok_or(TRONA_OUT_OF_MEMORY);
    }
    if fs_type_name == b"procfs" {
        return procfs::alloc_mount(state, mount_path, flags, opts).ok_or(TRONA_OUT_OF_MEMORY);
    }
    if fs_type_name == b"sysctlfs" {
        return sysctlfs::alloc_mount(state, mount_path, flags, opts).ok_or(TRONA_OUT_OF_MEMORY);
    }
    if fs_type_name == b"devfs" {
        return devfs::alloc_mount(state, mount_path, flags, opts).ok_or(TRONA_OUT_OF_MEMORY);
    }
    if fs_type_name == b"tmpfs" {
        return tmpfs::alloc_mount(state, mount_path, flags, opts).ok_or(TRONA_OUT_OF_MEMORY);
    }
    if fs_type_name == b"saltyfs" {
        return saltyfs::alloc_mount(state, mount_path, flags, opts);
    }
    alloc_structural_mount(state, fs_type_name, mount_path, flags, opts).ok_or(TRONA_OUT_OF_MEMORY)
}

fn drop_mount_instance(state: &mut VfsState, mh: MountHandle) -> bool {
    let (root_vh, is_pipefs, is_devfs, is_procfs, is_saltyfs, is_sysctlfs, is_tmpfs) =
        match state.mounts.get(mh) {
            Some(mount) => (
                mount.root_vnode,
                pipefs::mount_is_pipefs(mount),
                devfs::mount_is_devfs(mount),
                procfs::mount_is_procfs(mount),
                saltyfs::mount_is_saltyfs(mount),
                sysctlfs::mount_is_sysctlfs(mount),
                tmpfs::mount_is_tmpfs(mount),
            ),
            None => return false,
        };

    if !state.mounts.release(mh) {
        return false;
    }
    if is_pipefs && !pipefs::release_mount(state, mh) {
        return false;
    }
    if is_devfs && !devfs::release_mount(state, mh) {
        return false;
    }
    if is_procfs && !procfs::release_mount(state, mh) {
        return false;
    }
    if is_saltyfs && !saltyfs::release_mount(state, mh) {
        return false;
    }
    if is_sysctlfs && !sysctlfs::release_mount(state, mh) {
        return false;
    }
    if is_tmpfs && !tmpfs::release_mount(state, mh) {
        return false;
    }
    let _ = state.vnodes.release(root_vh);
    true
}

fn do_mount_at_vnode(
    state: &mut VfsState,
    target_vh: VnodeHandle,
    target_path: &[u8],
    fs_type_name: &[u8],
    flags: u32,
    opts: &[u8],
) -> u64 {
    if !target_vh.is_valid() {
        return TRONA_NOT_FOUND;
    }
    let target_type = match state.vnodes.get(target_vh) {
        Some(vnode) => vnode.vtype,
        None => return TRONA_NOT_FOUND,
    };
    if target_type != super::vnode::VT_DIR {
        return TRONA_NOT_DIRECTORY;
    }
    if covering_mount_for_vnode(state, target_vh).is_some() {
        return TRONA_ALREADY_EXISTS;
    }

    let effective_flags = flags | mount_options::parse_generic_flags(opts);

    let mh = match alloc_mount_for_fs(state, fs_type_name, target_path, effective_flags, opts) {
        Ok(mh) => mh,
        Err(err) => return err,
    };
    if let Some(mount) = state.mounts.get_mut(mh) {
        mount.set_opts(opts);
    }

    if !state.graft_mount_at_vnode(mh, target_vh, target_path) {
        let _ = drop_mount_instance(state, mh);
        return TRONA_INVALID_OPERATION;
    }

    refresh_global_ns(state);
    TRONA_OK
}

/// Graft one structural mount onto a mountpoint resolved in the current
/// namespace. Runtime callers should use this path rather than the
/// bootstrap tree.
pub(crate) fn do_mount(
    state: &mut VfsState,
    target_path: &[u8],
    fs_type_name: &[u8],
    flags: u32,
    opts: &[u8],
) -> u64 {
    let target_vh = match resolve_runtime_mount_path(state, None, target_path) {
        Ok(vh) => vh,
        Err(err) => return err,
    };
    do_mount_at_vnode(state, target_vh, target_path, fs_type_name, flags, opts)
}

pub(crate) fn do_mount_for_badge(
    state: &mut VfsState,
    badge: u64,
    target_path: &[u8],
    fs_type_name: &[u8],
    flags: u32,
    opts: &[u8],
) -> u64 {
    let target_vh = match resolve_runtime_mount_path_for_badge(state, badge, target_path) {
        Ok(vh) => vh,
        Err(err) => return err,
    };
    do_mount_at_vnode(state, target_vh, target_path, fs_type_name, flags, opts)
}

pub(crate) fn do_bootstrap_mount(
    state: &mut VfsState,
    target_path: &[u8],
    fs_type_name: &[u8],
    flags: u32,
    opts: &[u8],
) -> u64 {
    let target_vh = match resolve_bootstrap_mount_path(state, target_path) {
        Ok(vh) => vh,
        Err(err) => return err,
    };
    do_mount_at_vnode(state, target_vh, target_path, fs_type_name, flags, opts)
}

/// Re-apply flags / options to an already-mounted filesystem.
///
/// `new_flags` carries only the bits the caller wants to set
/// (`MS_REMOUNT` companion bits in BSD parlance). Bits the caller did
/// not name in either `new_flags` or the parsed `opts` token list keep
/// their pre-remount value — `mount -o remount,ro /foo` must not
/// silently clear `MNT_CASEFOLD`. The backend's `vfsops.remount`
/// callback then decides which transitions are actually honored;
/// backends that opt out keep their existing options.
pub(crate) fn do_remount(
    state: &mut VfsState,
    target_path: &[u8],
    new_flags: u32,
    opts: &[u8],
) -> u64 {
    let target_vh = match resolve_runtime_mount_path(state, None, target_path) {
        Ok(vh) => vh,
        Err(err) => return err,
    };
    do_remount_at_vnode(state, target_vh, new_flags, opts)
}

pub(crate) fn do_remount_for_badge(
    state: &mut VfsState,
    badge: u64,
    target_path: &[u8],
    new_flags: u32,
    opts: &[u8],
) -> u64 {
    let target_vh = match resolve_runtime_mount_path_for_badge(state, badge, target_path) {
        Ok(vh) => vh,
        Err(err) => return err,
    };
    do_remount_at_vnode(state, target_vh, new_flags, opts)
}

fn do_remount_at_vnode(
    state: &mut VfsState,
    target_vh: VnodeHandle,
    new_flags: u32,
    opts: &[u8],
) -> u64 {
    let mh = match covering_mount_for_vnode(state, target_vh) {
        Some(mh) => mh,
        None => return TRONA_NOT_FOUND,
    };
    if !mh.is_valid() {
        return TRONA_INVALID_OPERATION;
    }
    let current_flags = state.mounts.get(mh).map(|m| m.flags).unwrap_or(0);
    let opt_changes = super::mount_options::parse_generic_flag_changes(opts);
    let touched_mask = new_flags | opt_changes.touched_mask;
    let preserved = current_flags & !touched_mask;
    let added = (new_flags | opt_changes.set_mask) & !opt_changes.clear_mask;
    let effective_flags = preserved | added;
    let backend_label = run_backend_remount(state, mh, effective_flags, opts);
    if backend_label != TRONA_OK {
        return backend_label;
    }
    if let Some(mount) = state.mounts.get_mut(mh) {
        mount.flags = effective_flags;
        mount.set_opts(opts);
    }
    TRONA_OK
}

fn run_backend_remount(state: &mut VfsState, mh: MountHandle, new_flags: u32, opts: &[u8]) -> u64 {
    let ops_ptr = state
        .mounts
        .get(mh)
        .map(|m| m.vfsops)
        .unwrap_or(core::ptr::null());
    let Some(ops) = super::vfsops::table_from_ptr(ops_ptr) else {
        return TRONA_OK;
    };
    let Some(callback) = ops.remount else {
        return TRONA_OK;
    };
    callback(state, mh, new_flags, opts)
}

/// Detach a structural child mount from the namespace.
pub(crate) fn do_umount(state: &mut VfsState, target_path: &[u8], _flags: u32) -> u64 {
    let target_vh = match resolve_runtime_mount_path(state, None, target_path) {
        Ok(vh) => vh,
        Err(err) => return err,
    };
    do_umount_at_vnode(state, target_vh)
}

pub(crate) fn do_umount_for_badge(
    state: &mut VfsState,
    badge: u64,
    target_path: &[u8],
    _flags: u32,
) -> u64 {
    let target_vh = match resolve_runtime_mount_path_for_badge(state, badge, target_path) {
        Ok(vh) => vh,
        Err(err) => return err,
    };
    do_umount_at_vnode(state, target_vh)
}

fn do_umount_at_vnode(state: &mut VfsState, target_vh: VnodeHandle) -> u64 {
    let mh = match covering_mount_for_vnode(state, target_vh) {
        Some(mh) => mh,
        None => return TRONA_NOT_FOUND,
    };
    if !mh.is_valid() || mh == state.root_mount {
        return TRONA_BUSY;
    }

    if let Some(target) = state.vnodes.get_mut(target_vh) {
        target.flags &= !VN_COVERED;
        target.covered_by =
            CachedRef::<super::identity::FsInstanceId, super::mount::MountHandle>::INVALID;
        target.unpin();
    } else {
        return TRONA_INVALID_OPERATION;
    }

    if !drop_mount_instance(state, mh) {
        return TRONA_INVALID_OPERATION;
    }

    if state.bootstrap.real_root_mount == mh {
        state.bootstrap.real_root_mount = MountHandle::INVALID;
    }
    refresh_global_ns(state);
    TRONA_OK
}

/// Promote the mount covering `new_root_path` to `/`.
pub(crate) fn do_pivot_root(
    state: &mut VfsState,
    new_root_path: &[u8],
    put_old_path: &[u8],
) -> u64 {
    if put_old_path != b"/initramfs" {
        return TRONA_INVALID_ARGUMENT;
    }

    let new_root_vh = if new_root_path == b"/newroot" {
        state.bootstrap.new_root_dir
    } else {
        match resolve_bootstrap_mount_path(state, new_root_path) {
            Ok(vh) => vh,
            Err(err) => return err,
        }
    };
    let put_old_vh = if put_old_path == b"/initramfs" {
        state.bootstrap.put_old_dir
    } else {
        match resolve_bootstrap_mount_path(state, put_old_path) {
            Ok(vh) => vh,
            Err(err) => return err,
        }
    };
    if !new_root_vh.is_valid() || !put_old_vh.is_valid() {
        return TRONA_INVALID_OPERATION;
    }
    let new_root_mh = match covering_mount_for_vnode(state, new_root_vh) {
        Some(mh) => mh,
        None => return TRONA_INVALID_OPERATION,
    };

    state.bootstrap.real_root_mount = new_root_mh;
    if !state.graft_mount_at_bootstrap_path(new_root_mh, new_root_path) {
        return TRONA_INVALID_OPERATION;
    }
    if put_old_vh != state.bootstrap.put_old_dir {
        return TRONA_INVALID_OPERATION;
    }
    if !state.pivot_root_to_real_root() {
        return TRONA_INVALID_OPERATION;
    }

    refresh_global_ns(state);
    TRONA_OK
}

/// Populate `/dev`, `/proc`, `/tmp`, `/sys`, and `/pipe` as structural
/// child mounts of the bootstrap root.
pub(crate) fn mount_bootstrap_pseudo_filesystems(state: &mut VfsState) -> bool {
    for (path, fs_name, flags, opts) in BOOTSTRAP_PSEUDO_MOUNTS {
        let err = do_bootstrap_mount(state, path, fs_name, *flags, opts);
        if err != TRONA_OK {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] bootstrap mount failed path=");
                _lb.bytes(path);
                _lb.str(b" fstype=");
                _lb.bytes(fs_name);
                _lb.str(b" err=");
                _lb.hex(err);
                _lb.str(b"\n");
            });
            return false;
        }
    }
    true
}
