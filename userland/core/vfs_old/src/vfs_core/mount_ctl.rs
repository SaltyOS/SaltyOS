// SPDX-License-Identifier: GPL-2.0-only
//! Centralized mount controller — single authority for mount-tree mutations.
//!
//! All mount operations go through this module. Bootstrap, fstab processing,
//! IPC handlers, and late-mount retry all converge here. `VopMetaOps` /
//! `VfsOps` dispatch happens through `OwnerVopCtx<'_>` / `OwnerMountCtx<'_>`;
//! `VopDataOps` dispatch happens through `WorkerIoCtx` which carries the
//! owner-state raw pointer when invoked from the owner thread. No
//! module-level static trampolines remain.

use crate::owner::VfsState;

use super::error::{VfsError, VfsResult};
use super::mount::{MOUNT_PATH_MAX, Mount, MountHandle, VnodeHandle};
use super::outcome::{Parked, Ready};
use super::vfs::{self, VfsOps};
use super::vnode::{VN_COVERED, Vnode};
use super::vop::VopVector;
use super::vop_context::{OwnerMountCtx, OwnerVopCtx};

// =========================================================================
// Covering mount resolution
// =========================================================================

pub(crate) fn covering_mount_for_vnode(
    state: &VfsState,
    target_vh: VnodeHandle,
) -> Option<MountHandle> {
    let vnode = state.vnodes.get(target_vh)?;
    if vnode.covered_by.id().is_valid() {
        if let Some(mh) = vnode.covered_by.resolve_ro(state) {
            return Some(mh);
        }
    }

    let parent_fs_id = vnode.mount.id();
    if !parent_fs_id.is_valid() {
        return None;
    }
    let target_key = vnode.vnode_key();
    let mut found = None;

    state.mounts.for_each_active(|mh, mp| {
        if mp.parent.id() != parent_fs_id || !mp.covered.id().is_valid() {
            return true;
        }
        if mp.covered.id() == target_key {
            found = Some(mh);
            return false;
        }
        true
    });

    found
}

// =========================================================================
// Mount identity helper
// =========================================================================

pub(crate) fn set_mount_identity(mount: &mut Mount, fs_name: &[u8], path: &[u8]) {
    let name_len = core::cmp::min(fs_name.len(), 16);
    mount.fs_type_name[..name_len].copy_from_slice(&fs_name[..name_len]);
    mount.fs_type_name_len = name_len as u8;

    let path_len = core::cmp::min(path.len(), MOUNT_PATH_MAX - 1);
    mount.mount_path[..path_len].copy_from_slice(&path[..path_len]);
    mount.mount_path_len = path_len as u8;
}

// =========================================================================
// Mount operations
// =========================================================================

pub(crate) unsafe fn do_mount(
    state: &mut VfsState,
    target_vh: VnodeHandle,
    fstype: &[u8],
    mount_path: &[u8],
    source: u64,
    flags: u32,
    opts: *const u8,
    opts_len: u8,
    can_park: bool,
) -> crate::vfs_core::outcome::VopOutcome<MountHandle> {
    unsafe {
        let ft = vfs::find_fs_type(fstype).ok_or(VfsError::NotFound)?;
        do_mount_with_ops(
            state, target_vh, ft.vfsops, ft.vops, fstype, mount_path, source, flags, opts,
            opts_len, can_park,
        )
    }
}

pub(crate) unsafe fn do_mount_with_ops(
    state: &mut VfsState,
    target_vh: VnodeHandle,
    vfsops: *const VfsOps,
    vops: *const VopVector,
    fs_name: &[u8],
    mount_path: &[u8],
    source: u64,
    flags: u32,
    opts: *const u8,
    opts_len: u8,
    can_park: bool,
) -> crate::vfs_core::outcome::VopOutcome<MountHandle> {
    unsafe {
        let mh = state.mounts.alloc().ok_or(VfsError::NoSpace)?;
        let fs_id = state.alloc_fs_instance_id();
        let (covered_key, parent_mh, parent_fs_id) = if target_vh.is_valid() {
            let target_vnode = state.vnodes.get(target_vh).ok_or(VfsError::Io)?;
            (
                target_vnode.vnode_key(),
                target_vnode.mount.handle_hint(),
                target_vnode.mount.id(),
            )
        } else {
            (
                crate::vfs_core::identity::VnodeKey::INVALID,
                MountHandle::INVALID,
                crate::vfs_core::identity::FsInstanceId::INVALID,
            )
        };
        {
            let mp = state.mounts.get_mut(mh).ok_or(VfsError::Io)?;
            mp.vfsops = vfsops;
            mp.vops = vops;
            mp.covered.set(covered_key, target_vh);
            mp.parent.set(parent_fs_id, parent_mh);
            mp.flags = flags;
            mp.id = mh.slot() as u16;
            mp.fs_instance_id = fs_id;
            set_mount_identity(mp, fs_name, mount_path);
        }

        // Arm trampolines so DataOps dispatched inside the VfsOps::mount
        // path (e.g. backend completion helpers) can reach owner state,
        // even though `OwnerMountCtx` is the primary hand-off.
        let mount_result = {
            let mut ctx = OwnerMountCtx::from_state(state, mh).ok_or(VfsError::Io)?;
            ((*vfsops).mount)(&mut ctx, source, opts, opts_len, can_park)
        };
        match mount_result {
            Ok(crate::vfs_core::outcome::VopControl::Ready(())) => {}
            Ok(crate::vfs_core::outcome::VopControl::Parked(handle)) => {
                return Ok(crate::vfs_core::outcome::VopControl::Parked(handle));
            }
            Err(e) => {
                state.mounts.release(mh);
                return Err(e);
            }
        }

        finalize_mount_tail(state, mh, target_vh, fs_id)?;
        Ok(crate::vfs_core::outcome::VopControl::Ready(mh))
    }
}

pub(crate) unsafe fn do_mount_sync(
    state: &mut VfsState,
    target_vh: VnodeHandle,
    fstype: &[u8],
    mount_path: &[u8],
    source: u64,
    flags: u32,
    opts: *const u8,
    opts_len: u8,
) -> VfsResult<MountHandle> {
    unsafe {
        match do_mount(
            state, target_vh, fstype, mount_path, source, flags, opts, opts_len, false,
        ) {
            Ok(crate::vfs_core::outcome::VopControl::Ready(mh)) => Ok(mh),
            Ok(crate::vfs_core::outcome::VopControl::Parked(_)) => Err(VfsError::Io),
            Err(e) => Err(e),
        }
    }
}

pub(crate) unsafe fn do_mount_with_ops_sync(
    state: &mut VfsState,
    target_vh: VnodeHandle,
    vfsops: *const VfsOps,
    vops: *const VopVector,
    fs_name: &[u8],
    mount_path: &[u8],
    source: u64,
    flags: u32,
    opts: *const u8,
    opts_len: u8,
) -> VfsResult<MountHandle> {
    unsafe {
        match do_mount_with_ops(
            state, target_vh, vfsops, vops, fs_name, mount_path, source, flags, opts, opts_len,
            false,
        ) {
            Ok(crate::vfs_core::outcome::VopControl::Ready(mh)) => Ok(mh),
            Ok(crate::vfs_core::outcome::VopControl::Parked(_)) => Err(VfsError::Io),
            Err(e) => Err(e),
        }
    }
}

pub(crate) unsafe fn finalize_mount_tail(
    state: &mut VfsState,
    mh: MountHandle,
    target_vh: VnodeHandle,
    fs_id: crate::vfs_core::identity::FsInstanceId,
) -> VfsResult<()> {
    unsafe {
        let root_vh = state.mounts.get(mh).ok_or(VfsError::Io)?.root_vnode;
        if root_vh.is_valid() {
            let root_vnode = state.vnodes.get_mut(root_vh).ok_or(VfsError::Io)?;
            root_vnode.mount.set(fs_id, mh);
            root_vnode.pin();
        }
        if target_vh.is_valid() {
            let target_vnode = state.vnodes.get_mut(target_vh).ok_or(VfsError::Io)?;
            target_vnode.flags |= VN_COVERED;
            target_vnode.covered_by.set(fs_id, mh);
            target_vnode.pin();
        }
        Ok(())
    }
}

pub(crate) unsafe fn do_umount(
    state: &mut VfsState,
    target_vh: VnodeHandle,
    flags: u32,
) -> VfsResult<()> {
    unsafe {
        use super::mount::MNT_FORCE;

        let _ = state.vnodes.get(target_vh).ok_or(VfsError::NotSupported)?;
        let mh = covering_mount_for_vnode(state, target_vh).ok_or(VfsError::NotFound)?;
        if !mh.is_valid() {
            return Err(VfsError::NotFound);
        }

        let mp = state.mounts.get(mh).ok_or(VfsError::NotFound)?;
        let force = flags & MNT_FORCE != 0;
        let vfsops = mp.vfsops;

        let root_vh = state
            .mounts
            .get(mh)
            .map(|m| m.root_vnode)
            .unwrap_or(VnodeHandle::INVALID);

        if !vfsops.is_null() {
            let unmount_result = {
                let mut ctx = OwnerMountCtx::from_state(state, mh).ok_or(VfsError::Io)?;
                ((*vfsops).unmount)(&mut ctx, force)
            };
            unmount_result?;
        }

        let target_vnode = state.vnodes.get_mut(target_vh).ok_or(VfsError::Io)?;
        target_vnode.covered_by = crate::vfs_core::cached_ref::CachedRef::<
            crate::vfs_core::identity::FsInstanceId,
            MountHandle,
        >::INVALID;
        target_vnode.flags &= !VN_COVERED;
        target_vnode.unpin();

        if root_vh.is_valid() {
            if let Some(root_vnode) = state.vnodes.get_mut(root_vh) {
                root_vnode.unpin();
            }
        }

        state.mounts.release(mh);

        Ok(())
    }
}

pub(crate) unsafe fn do_pivot_root(
    state: &mut VfsState,
    new_root_mh: MountHandle,
    put_old_vh: VnodeHandle,
) -> VfsResult<()> {
    unsafe {
        crate::boot::pivot_root::vfs_pivot_root(state, new_root_mh, put_old_vh)?;
        refresh_global_ns(state);
        Ok(())
    }
}

// =========================================================================
// Path resolution (mount-control level, no client context)
// =========================================================================

pub(crate) unsafe fn resolve_mount_path(
    state: &mut VfsState,
    path: &[u8],
) -> VfsResult<VnodeHandle> {
    unsafe {
        if !state.root_mount.is_valid() {
            return Err(VfsError::Io);
        }
        let root_mp = state.mounts.get(state.root_mount).ok_or(VfsError::Io)?;
        let mut current = root_mp.root_vnode;
        if !current.is_valid() {
            return Err(VfsError::Io);
        }

        let mut pos = 0usize;
        let len = path.len();

        while pos < len && path[pos] == b'/' {
            pos += 1;
        }

        while pos < len {
            let comp_start = pos;
            while pos < len && path[pos] != b'/' {
                pos += 1;
            }
            let comp_len = pos - comp_start;

            while pos < len && path[pos] == b'/' {
                pos += 1;
            }

            if comp_len == 0 {
                continue;
            }

            // Arm trampolines while we dispatch `lookup` so backend data
            // paths reached by the meta op can still resolve owner state.
            let lookup_result = {
                let mut ctx = match OwnerVopCtx::from_state(state, current) {
                    Some(c) => c,
                    None => {
                        return Err(VfsError::Io);
                    }
                };
                let ops = (*ctx.vnode).ops;
                if ops.is_null() {
                    return Err(VfsError::Io);
                }
                ((*ops).meta.lookup)(&mut ctx, path.as_ptr().add(comp_start), comp_len as u8)
            };
            let child = match lookup_result {
                Ok(Ready(vh)) => vh,
                Ok(Parked(_)) => return Err(VfsError::Busy),
                Err(e) => return Err(e),
            };

            if !child.is_valid() {
                return Err(VfsError::NotFound);
            }

            current = cross_mount_boundary(state, child)?;
        }

        Ok(current)
    }
}

unsafe fn cross_mount_boundary(
    state: &mut VfsState,
    mut vh: VnodeHandle,
) -> VfsResult<VnodeHandle> {
    loop {
        let covering_mh = match covering_mount_for_vnode(state, vh) {
            Some(mh) => mh,
            None => return Ok(vh),
        };
        if !covering_mh.is_valid() {
            return Ok(vh);
        }
        let covering_mp = state.mounts.get(covering_mh).ok_or(VfsError::Io)?;
        let root_vh = covering_mp.root_vnode;
        if !root_vh.is_valid() {
            return Ok(vh);
        }
        vh = root_vh;
    }
}

// =========================================================================
// Namespace refresh
// =========================================================================

pub(crate) fn refresh_global_ns(state: &mut VfsState) {
    if !state.global_ns.is_valid() {
        return;
    }

    let mut handles = [MountHandle::INVALID; super::mount_ns::MAX_NS_MOUNTS];
    let mut count = 0u8;
    state.mounts.for_each_active(|mh, _mp| {
        if (count as usize) < super::mount_ns::MAX_NS_MOUNTS {
            handles[count as usize] = mh;
            count += 1;
            true
        } else {
            false
        }
    });

    let root_mount = state.root_mount;
    if let Some(ns) = state.mount_ns.get_mut(state.global_ns) {
        ns.root_mount = root_mount;
        let n = count as usize;
        ns.mounts[..n].copy_from_slice(&handles[..n]);
        ns.mount_count = count;
    }
}
