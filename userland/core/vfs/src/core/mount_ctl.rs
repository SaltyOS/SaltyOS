// SPDX-License-Identifier: GPL-2.0-only
//
//! Mount control — finalize / refresh routines invoked from the
//! mount completion path. The bulk of mount lifecycle (slot
//! reserve, root vnode allocation, namespace splice) lives in
//! [`crate::owner::mod`] and the per-backend `vfsops` modules;
//! this file is the cross-mount glue called from the saltyfs
//! completion router after the daemon's `BACKEND_OPEN_SESSION`
//! has been finalized.

use crate::core::error::{VfsError, VfsResult};
use crate::core::identity::{FsInstanceId, VnodeKey};
use crate::core::mount::MountHandle;
use crate::core::vnode::VnodeHandle;
use crate::owner::VfsState;

/// Finalise the mount tail — pin the root vnode against arena
/// reclaim, splice the mount onto the parent's covered vnode,
/// and bump the parent mount's vnode_refcount so `umount` waits
/// for the child mount to drain. `target_vh` is the vnode the
/// new mount covers; `INVALID` means "this is the rootfs and
/// there is no covered parent".
pub(crate) unsafe fn finalize_mount_tail(
    state: &mut VfsState,
    mount_h: MountHandle,
    target_vh: VnodeHandle,
    fs_id: FsInstanceId,
) -> VfsResult<()> {
    unsafe {
        let _ = fs_id;
        let mount = state.mounts.get_mut(mount_h).ok_or(VfsError::Io)?;
        let root_vh = mount.root;
        if root_vh.is_valid() {
            if let Some(root_vp) = state.vnodes.raw_ptr(root_vh) {
                (*root_vp).flags |= crate::core::vnode::VN_ROOT;
                (*root_vp).pin();
            }
        }
        if target_vh.is_valid() {
            if let Some(target_vp) = state.vnodes.raw_ptr(target_vh) {
                let covered_key = (*target_vp).key;
                (*target_vp).set_covered_by(
                    state
                        .mounts
                        .get(mount_h)
                        .map(|m| m.fs_instance_id)
                        .unwrap_or(crate::core::identity::FsInstanceId::INVALID),
                );
                (*target_vp).pin();
                if let Some(mount) = state.mounts.get_mut(mount_h) {
                    mount.covered_key = covered_key;
                }
            }
        } else if let Some(mount) = state.mounts.get_mut(mount_h) {
            mount.covered_key = crate::core::identity::VnodeKey::NONE;
        }
        Ok(())
    }
}

/// Refresh any cached mount-tree lookups after a successful
/// finalize. Today the mount tree is walked on demand from
/// `Mount.covered_key` / `Mount.root`; this helper exists so the
/// caller has a single hook for future caching layers (mount-
/// list snapshots, pivot-root invalidation) without a wire ABI
/// change.
pub(crate) unsafe fn refresh_global_ns(_state: &mut VfsState) {
    // No global mount list cache yet; reserved for future
    // mount-list snapshot invalidation.
}

/// Locate the mount whose `covered_key` matches `target_vh`'s
/// composite identity. Returns `None` when the vnode is not a
/// mount cover — either the `VN_COVERED` flag is clear, or the
/// flag is set but the cover has been torn down (a stale flag the
/// caller treats as "no cover" rather than an error).
///
/// `namei_walk_async::chase_covering_mounts` follows the chain
/// returned here: a mount root that itself covers another vnode
/// re-enters this routine until the chain bottoms out at the
/// effective leaf. Mount transparency is the entire point — `/dev`
/// covered by devfs, `/proc` by procfs, and so on.
pub(crate) fn covering_mount_for_vnode(
    state: &VfsState,
    target_vh: VnodeHandle,
) -> Option<MountHandle> {
    let vnode = state.vnodes.get(target_vh)?;
    if (vnode.flags & crate::core::vnode::VN_COVERED) == 0 {
        return None;
    }
    let target_key = vnode.key;
    let mut found = None;
    state.mounts.for_each_active(|mount_h, mount| {
        if mount.covered_key == target_key {
            found = Some(mount_h);
            false
        } else {
            true
        }
    });
    found
}

/// Return the `FsInstanceId` of the active mount covering `key`, if
/// any. Mirrors [`covering_mount_for_vnode`] but keys off the stable
/// `VnodeKey` rather than a live vnode object — used to re-stamp
/// `VN_COVERED` when a covered vnode is reclaimed and re-materialized
/// (the cover flag lives on the vnode object and would otherwise lapse
/// across reclaim).
pub(crate) fn covering_mount_fs_for_key(state: &VfsState, key: VnodeKey) -> Option<FsInstanceId> {
    if !key.is_valid() {
        return None;
    }
    let mut found = None;
    state.mounts.for_each_active(|_mount_h, mount| {
        if mount.covered_key == key {
            found = Some(mount.fs_instance_id);
            false
        } else {
            true
        }
    });
    found
}
