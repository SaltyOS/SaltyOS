// SPDX-License-Identifier: GPL-2.0-only
//! devfs — synchronous device namespace instance.
//!
//! The rebuilt VFS keeps character-device semantics in generic fileops,
//! but `/dev` is still a distinct mounted filesystem instance. devfs owns
//! its mount-private state and dispatch anchors so later device-specific
//! behavior can hang off the mount cleanly.

use crate::arena::Handle;
use crate::owner::VfsState;
use crate::vfs_core::identity::FsInstanceId;
use crate::vfs_core::mount::{MOUNT_BACKEND_DEVFS, Mount, MountHandle};
use crate::vfs_core::vnode::{VNODE_BACKEND_DEVFS, Vnode, VnodeHandle};
use crate::vfs_core::vops::empty_vops;

/// Stable handle for one mounted devfs instance.
pub(crate) type DevfsMountHandle = Handle<DevfsMountData>;

#[repr(C)]
pub(crate) struct DevfsMountData {
    /// Owning mount entry in the generic mount table.
    pub(crate) owner_mount: MountHandle,
    /// Stable filesystem identity shared by all devfs vnodes.
    pub(crate) fs_instance_id: FsInstanceId,
    /// Root vnode of the devfs instance.
    pub(crate) root_vnode: VnodeHandle,
}

static DEVFS_VFSOPS: crate::vfs_core::vfsops::VfsOps = crate::vfs_core::vfsops::VfsOps::empty();

#[inline]
pub(crate) fn mount_is_devfs(mount: &Mount) -> bool {
    mount.backend_kind == MOUNT_BACKEND_DEVFS
}

#[inline]
pub(crate) fn devfs_vfsops() -> *const () {
    &raw const DEVFS_VFSOPS as *const crate::vfs_core::vfsops::VfsOps as *const ()
}

#[inline]
pub(crate) fn devfs_vops() -> *const () {
    empty_vops()
}

fn find_mount_data_handle(state: &VfsState, owner_mount: MountHandle) -> Option<DevfsMountHandle> {
    let mut found = DevfsMountHandle::INVALID;
    state.devfs_mounts.for_each_active(|handle, data| {
        if data.owner_mount == owner_mount {
            found = handle;
            return false;
        }
        true
    });
    if found.is_valid() { Some(found) } else { None }
}

pub(crate) fn alloc_mount(
    state: &mut VfsState,
    mount_path: &[u8],
    flags: u32,
    opts: &[u8],
) -> Option<MountHandle> {
    let _ = opts;
    let root_vh = state.vnodes.alloc()?;
    let mh = state.mounts.alloc()?;
    let data_h = state.devfs_mounts.alloc()?;
    let fs_id = state.alloc_fs_instance_id();

    {
        let vnode = state.vnodes.get_mut(root_vh)?;
        *vnode = Vnode::new_mounted_root_dir(fs_id);
        vnode.backend_kind = VNODE_BACKEND_DEVFS;
        vnode.id = 1;
        vnode.ops = devfs_vops();
    }
    state.cache_vnode_key(root_vh);

    {
        let mount = state.mounts.get_mut(mh)?;
        *mount = Mount::new_structural(
            (mh.slot().saturating_add(1)) as u16,
            flags,
            fs_id,
            root_vh,
            b"devfs",
            mount_path,
        );
        mount.backend_kind = MOUNT_BACKEND_DEVFS;
        mount.vfsops = devfs_vfsops();
        mount.vops = devfs_vops();
    }

    let data_ptr = {
        let data = state.devfs_mounts.get_mut(data_h)?;
        *data = DevfsMountData {
            owner_mount: mh,
            fs_instance_id: fs_id,
            root_vnode: root_vh,
        };
        data as *mut DevfsMountData as *mut u8
    };

    {
        let mount = state.mounts.get_mut(mh)?;
        mount.data = data_ptr;
    }
    {
        let vnode = state.vnodes.get_mut(root_vh)?;
        vnode.mount = crate::vfs_core::cached_ref::CachedRef::new(fs_id, mh);
    }

    Some(mh)
}

pub(crate) fn release_mount(state: &mut VfsState, owner_mount: MountHandle) -> bool {
    let Some(data_h) = find_mount_data_handle(state, owner_mount) else {
        return true;
    };
    state.devfs_mounts.release(data_h)
}
