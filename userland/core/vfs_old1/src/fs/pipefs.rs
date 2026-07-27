// SPDX-License-Identifier: GPL-2.0-only
//! pipefs — named pipe namespace instance.
//!
//! `/pipe` is a mounted namespace subtree even though actual byte-stream
//! transport is still handled by the generic pipe helpers. Keeping a real
//! mount-private object here makes Win32 pipe namespace routing and later
//! pipefs-specific behavior composable.

use crate::arena::Handle;
use crate::owner::VfsState;
use crate::vfs_core::identity::FsInstanceId;
use crate::vfs_core::mount::{MOUNT_BACKEND_PIPEFS, Mount, MountHandle};
use crate::vfs_core::vnode::{VNODE_BACKEND_PIPEFS, Vnode, VnodeHandle};
use crate::vfs_core::vops::empty_vops;

pub(crate) type PipefsMountHandle = Handle<PipefsMountData>;

#[repr(C)]
pub(crate) struct PipefsMountData {
    pub(crate) owner_mount: MountHandle,
    pub(crate) fs_instance_id: FsInstanceId,
    pub(crate) root_vnode: VnodeHandle,
}

static PIPEFS_VFSOPS: crate::vfs_core::vfsops::VfsOps = crate::vfs_core::vfsops::VfsOps::empty();

#[inline]
pub(crate) fn mount_is_pipefs(mount: &Mount) -> bool {
    mount.backend_kind == MOUNT_BACKEND_PIPEFS
}

#[inline]
pub(crate) fn pipefs_vfsops() -> *const () {
    &raw const PIPEFS_VFSOPS as *const crate::vfs_core::vfsops::VfsOps as *const ()
}

#[inline]
pub(crate) fn pipefs_vops() -> *const () {
    empty_vops()
}

fn find_mount_data_handle(state: &VfsState, owner_mount: MountHandle) -> Option<PipefsMountHandle> {
    let mut found = PipefsMountHandle::INVALID;
    state.pipefs_mounts.for_each_active(|handle, data| {
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
    let data_h = state.pipefs_mounts.alloc()?;
    let fs_id = state.alloc_fs_instance_id();

    {
        let vnode = state.vnodes.get_mut(root_vh)?;
        *vnode = Vnode::new_mounted_root_dir(fs_id);
        vnode.backend_kind = VNODE_BACKEND_PIPEFS;
        vnode.id = 1;
        vnode.ops = pipefs_vops();
    }
    state.cache_vnode_key(root_vh);

    {
        let mount = state.mounts.get_mut(mh)?;
        *mount = Mount::new_structural(
            (mh.slot().saturating_add(1)) as u16,
            flags,
            fs_id,
            root_vh,
            b"pipefs",
            mount_path,
        );
        mount.backend_kind = MOUNT_BACKEND_PIPEFS;
        mount.vfsops = pipefs_vfsops();
        mount.vops = pipefs_vops();
    }

    let data_ptr = {
        let data = state.pipefs_mounts.get_mut(data_h)?;
        *data = PipefsMountData {
            owner_mount: mh,
            fs_instance_id: fs_id,
            root_vnode: root_vh,
        };
        data as *mut PipefsMountData as *mut u8
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
    state.pipefs_mounts.release(data_h)
}
