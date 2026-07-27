// SPDX-License-Identifier: GPL-2.0-only
//! `pivot_root` — atomically swap the root filesystem.
//!
//! `vfs_pivot_root(state, new_root_mh, put_old_vh)` performs:
//!
//! 1. Validates that `new_root_mh` is a mounted filesystem (active mount
//!    with a root vnode).
//! 2. Validates that `put_old_vh` is a directory under the new root.
//! 3. Detaches the old root mount from `state.root_mount`.
//! 4. Sets `new_root_mh` as the new `state.root_mount`.
//! 5. Re-parents only the boot scaffold child mounts (`/dev`, `/proc`,
//!    `/tmp`, `/sys`, `/pipe`) whose parent was the old root to point to
//!    the new root mount.
//! 6. Attaches the old root mount at `put_old_vh` (the old root becomes
//!    a subtree under the new root).
//!
//! # Bind mount
//!
//! `vfs_bind_mount` creates a mount whose root vnode is borrowed from an
//! existing filesystem, providing an alternate view of the same subtree
//! at a different mount point.

use crate::owner::VfsState;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::mount::{MNT_BIND, MNT_RBIND, Mount, MountHandle};
use crate::vfs_core::mount_ctl::set_mount_identity;
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::{VN_COVERED, VN_ROOT, VT_DIR, VnodeHandle};

// =========================================================================
// pivot_root
// =========================================================================

const MAX_PIVOT_CHILD_MOUNTS: usize = 16;
const BOOT_SCAFFOLD_CHILD_MOUNTS: [&[u8]; 5] = [b"/dev", b"/proc", b"/tmp", b"/sys", b"/pipe"];

fn boot_scaffold_child_mount_index(mount_path: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i < BOOT_SCAFFOLD_CHILD_MOUNTS.len() {
        if BOOT_SCAFFOLD_CHILD_MOUNTS[i] == mount_path {
            return Some(i);
        }
        i += 1;
    }
    None
}

unsafe fn lookup_mountpoint_under_root(
    state: &mut VfsState,
    root_vh: VnodeHandle,
    mount_path: &[u8],
) -> VfsResult<VnodeHandle> {
    if !root_vh.is_valid() {
        return Err(VfsError::Inval);
    }
    if mount_path.is_empty() || mount_path == b"/" {
        return Ok(root_vh);
    }

    let mut current = root_vh;
    let mut pos = 0usize;
    while pos < mount_path.len() && mount_path[pos] == b'/' {
        pos += 1;
    }

    while pos < mount_path.len() {
        let start = pos;
        while pos < mount_path.len() && mount_path[pos] != b'/' {
            pos += 1;
        }
        let comp = &mount_path[start..pos];
        while pos < mount_path.len() && mount_path[pos] == b'/' {
            pos += 1;
        }
        if comp.is_empty() {
            continue;
        }

        unsafe {
            let mut ctx = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, current)
                .ok_or(VfsError::Io)?;
            let ops = &*(*ctx.vnode).ops;
            let next = match (ops.meta.lookup)(&mut ctx, comp.as_ptr(), comp.len() as u8) {
                Ok(Ready(vh)) => vh,
                Ok(Parked(_)) => {
                    return Err(VfsError::Busy);
                }
                Err(e) => {
                    return Err(e);
                }
            };

            if !next.is_valid() {
                return Err(VfsError::NotFound);
            }

            current = next;
        }
    }

    let vnode = state.vnodes.get(current).ok_or(VfsError::Io)?;
    if vnode.vtype != VT_DIR {
        return Err(VfsError::NotDir);
    }

    Ok(current)
}

/// Atomically swap the VFS root from the current `state.root_mount` to
/// `new_root_mh`, placing the old root at `put_old_vh`.
///
/// # Preconditions
///
/// - `new_root_mh` must be a valid, active mount with a non-null root vnode.
/// - `put_old_vh` must be a directory vnode under `new_root_mh`.
/// - Must be called during boot (single-threaded or with exclusive access).
unsafe fn vfs_pivot_root_inner(
    state: &mut VfsState,
    new_root_mh: MountHandle,
    put_old_vh: VnodeHandle,
    prepared_child_targets: Option<&[VnodeHandle; BOOT_SCAFFOLD_CHILD_MOUNTS.len()]>,
) -> VfsResult<()> {
    if !new_root_mh.is_valid() || !put_old_vh.is_valid() {
        return Err(VfsError::Inval);
    }

    let new_root_mp = state.mounts.get(new_root_mh).ok_or(VfsError::Inval)?;
    let new_root_vh = new_root_mp.root_vnode;
    if !new_root_vh.is_valid() {
        return Err(VfsError::Inval);
    }

    // new_root must be a mount root.
    let new_root_vn = state.vnodes.get(new_root_vh).ok_or(VfsError::Inval)?;
    if new_root_vn.flags & VN_ROOT == 0 {
        return Err(VfsError::Inval);
    }

    // put_old must be a directory.
    let put_old_vn = state.vnodes.get(put_old_vh).ok_or(VfsError::Inval)?;
    if put_old_vn.vtype != VT_DIR {
        return Err(VfsError::NotDir);
    }

    let old_root_mh = state.root_mount;
    if !old_root_mh.is_valid() {
        return Err(VfsError::Inval);
    }

    // Don't pivot onto ourselves.
    if old_root_mh.slot() == new_root_mh.slot() && old_root_mh.epoch() == new_root_mh.epoch() {
        return Err(VfsError::Inval);
    }

    // Stable identity of the old root mount — used for the parent
    // comparison in Step 0 (child-mount scan) and to re-stamp
    // `covered_by` on the put_old vnode in Step 4 below.
    let old_root_fs_id = state
        .mounts
        .get(old_root_mh)
        .map(|m| m.fs_instance_id)
        .unwrap_or(crate::vfs_core::identity::FsInstanceId::INVALID);

    // Collect boot scaffold child mounts that need re-parenting.
    let mut child_mounts: [MountHandle; MAX_PIVOT_CHILD_MOUNTS] =
        [MountHandle::INVALID; MAX_PIVOT_CHILD_MOUNTS];
    let mut child_targets: [VnodeHandle; MAX_PIVOT_CHILD_MOUNTS] =
        [VnodeHandle::INVALID; MAX_PIVOT_CHILD_MOUNTS];
    let mut child_count = 0usize;

    // Scan all active mounts for children of old_root.
    let mut scan_handles = [MountHandle::INVALID; 32];
    let mut scan_count = 0usize;
    state.mounts.for_each_active(|mh, _mp| {
        if scan_count < 32 {
            scan_handles[scan_count] = mh;
            scan_count += 1;
        }
        true
    });

    for i in 0..scan_count {
        let mh = scan_handles[i];
        if mh.slot() == new_root_mh.slot() || mh.slot() == old_root_mh.slot() {
            continue;
        }
        let mut mount_path_buf = [0u8; crate::server::consts::MAX_PATH_LEN];
        let mount_path_len = {
            let mp = match state.mounts.get(mh) {
                Some(m) => m,
                None => continue,
            };
            if mp.parent.id() != old_root_fs_id {
                continue;
            }
            let len = mp.mount_path_len as usize;
            mount_path_buf[..len].copy_from_slice(&mp.mount_path[..len]);
            len
        };
        let mount_path = &mount_path_buf[..mount_path_len];

        let Some(scaffold_idx) = boot_scaffold_child_mount_index(mount_path) else {
            continue;
        };

        if child_count >= MAX_PIVOT_CHILD_MOUNTS {
            return Err(VfsError::NoSpace);
        }

        let target_result = match prepared_child_targets {
            Some(targets) => {
                let vh = targets[scaffold_idx];
                if !vh.is_valid() {
                    Err(VfsError::NotFound)
                } else {
                    match state.vnodes.get(vh) {
                        Some(vn) if vn.vtype == VT_DIR => Ok(vh),
                        Some(_) => Err(VfsError::NotDir),
                        None => Err(VfsError::Io),
                    }
                }
            }
            None => unsafe { lookup_mountpoint_under_root(state, new_root_vh, mount_path) },
        };
        let target_vh = match target_result {
            Ok(vh) => vh,
            Err(e) => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[VFS] pivot_root: cannot reattach child mount ");
                    _lb.bytes(mount_path);
                    _lb.str(b" err=");
                    _lb.hex(e.discriminant() as u64);
                    _lb.str(b"\n");
                });
                return Err(e);
            }
        };

        child_mounts[child_count] = mh;
        child_targets[child_count] = target_vh;
        child_count += 1;
    }

    // ---- Step 1: Detach new_root from its current mount point ----
    {
        let new_mp = state.mounts.get(new_root_mh).ok_or(VfsError::Io)?;
        let new_covered = new_mp.covered.handle_hint();
        if new_covered.is_valid() {
            if let Some(vn) = state.vnodes.get_mut(new_covered) {
                vn.flags &= !VN_COVERED;
                vn.covered_by = crate::vfs_core::cached_ref::CachedRef::<
                    crate::vfs_core::identity::FsInstanceId,
                    MountHandle,
                >::INVALID;
                vn.unpin();
            }
        }
    }

    // ---- Step 2: Set new root as state.root_mount ----
    state.root_mount = new_root_mh;
    {
        let new_mp = state.mounts.get_mut(new_root_mh).ok_or(VfsError::Io)?;
        new_mp.covered = crate::vfs_core::cached_ref::CachedRef::<
            crate::vfs_core::identity::VnodeKey,
            VnodeHandle,
        >::INVALID;
        new_mp.parent = crate::vfs_core::cached_ref::CachedRef::<
            crate::vfs_core::identity::FsInstanceId,
            MountHandle,
        >::INVALID;
    }

    // Capture the new root's `fs_instance_id` for re-parent steps — we
    // consume `state.mounts` via `get_mut` repeatedly below and need
    // the authoritative id available after the borrow ends.
    let new_root_fs_id = state
        .mounts
        .get(new_root_mh)
        .map(|m| m.fs_instance_id)
        .unwrap_or(crate::vfs_core::identity::FsInstanceId::INVALID);

    // ---- Step 3: Re-parent boot scaffold child mounts ----
    for i in 0..child_count {
        let mh = child_mounts[i];
        let new_target = child_targets[i];
        if !mh.is_valid() || !new_target.is_valid() {
            continue;
        }

        // Unwire old covering link.
        let old_target = {
            let mp = state.mounts.get(mh).ok_or(VfsError::Io)?;
            mp.covered.handle_hint()
        };
        if old_target.is_valid() {
            if let Some(vn) = state.vnodes.get_mut(old_target) {
                vn.flags &= !VN_COVERED;
                vn.covered_by = crate::vfs_core::cached_ref::CachedRef::<
                    crate::vfs_core::identity::FsInstanceId,
                    MountHandle,
                >::INVALID;
                vn.unpin();
            }
        }

        // Re-parent and wire new covering link.
        let new_target_key = state
            .vnodes
            .get(new_target)
            .map(|v| v.vnode_key())
            .unwrap_or(crate::vfs_core::identity::VnodeKey::INVALID);
        let covering_fs_id = state
            .mounts
            .get(mh)
            .map(|m| m.fs_instance_id)
            .unwrap_or(crate::vfs_core::identity::FsInstanceId::INVALID);
        {
            let mp = state.mounts.get_mut(mh).ok_or(VfsError::Io)?;
            mp.parent.set(new_root_fs_id, new_root_mh);
            mp.covered.set(new_target_key, new_target);
        }
        if let Some(vn) = state.vnodes.get_mut(new_target) {
            vn.flags |= VN_COVERED;
            vn.covered_by.set(covering_fs_id, mh);
            vn.pin();
        }
    }

    // ---- Step 4: Attach old root at put_old ----
    let put_old_key = state
        .vnodes
        .get(put_old_vh)
        .map(|v| v.vnode_key())
        .unwrap_or(crate::vfs_core::identity::VnodeKey::INVALID);
    {
        let old_mp = state.mounts.get_mut(old_root_mh).ok_or(VfsError::Io)?;
        old_mp.covered.set(put_old_key, put_old_vh);
        old_mp.parent.set(new_root_fs_id, new_root_mh);

        // Update the old root mount's path identity to reflect its new location.
        let mut old_name_buf = [0u8; 16];
        let old_name_len = old_mp.fs_type_name_len as usize;
        old_name_buf[..old_name_len].copy_from_slice(&old_mp.fs_type_name[..old_name_len]);
        set_mount_identity(old_mp, &old_name_buf[..old_name_len], b"/mnt/ramfs");
    }
    if let Some(vn) = state.vnodes.get_mut(put_old_vh) {
        vn.flags |= VN_COVERED;
        vn.covered_by.set(old_root_fs_id, old_root_mh);
        vn.pin();
    }

    Ok(())
}

pub(crate) unsafe fn vfs_pivot_root(
    state: &mut VfsState,
    new_root_mh: MountHandle,
    put_old_vh: VnodeHandle,
) -> VfsResult<()> {
    unsafe { vfs_pivot_root_inner(state, new_root_mh, put_old_vh, None) }
}

pub(crate) unsafe fn vfs_pivot_root_prepared(
    state: &mut VfsState,
    new_root_mh: MountHandle,
    put_old_vh: VnodeHandle,
    prepared_child_targets: &[VnodeHandle; BOOT_SCAFFOLD_CHILD_MOUNTS.len()],
) -> VfsResult<()> {
    unsafe { vfs_pivot_root_inner(state, new_root_mh, put_old_vh, Some(prepared_child_targets)) }
}

// =========================================================================
// Bind mount
// =========================================================================

/// Create a bind mount: mount `source_vh` at `target_vh`.
///
/// The new mount's root vnode is `source_vh` itself (not a copy). This
/// provides an alternate path to the same filesystem subtree.
///
/// When `MNT_RBIND` is set in `flags`, sub-mounts under `source_vh` are
/// also cloned into the new bind mount's subtree.
pub(crate) unsafe fn vfs_bind_mount(
    state: &mut VfsState,
    parent_mh: MountHandle,
    source_vh: VnodeHandle,
    target_vh: VnodeHandle,
    flags: u32,
) -> VfsResult<MountHandle> {
    if !parent_mh.is_valid() || !source_vh.is_valid() || !target_vh.is_valid() {
        return Err(VfsError::Inval);
    }

    let target_vn = state.vnodes.get(target_vh).ok_or(VfsError::Inval)?;
    if target_vn.vtype != VT_DIR {
        return Err(VfsError::NotDir);
    }

    // Get source mount info via identity-backed resolve.
    let source_mh = state
        .resolve_vnode_mount(source_vh)
        .ok_or(VfsError::Inval)?;
    let source_mp = state.mounts.get(source_mh).ok_or(VfsError::Inval)?;
    let vfsops = source_mp.vfsops;
    let vops = source_mp.vops;
    let data = source_mp.data;

    // Allocate a new mount.
    let mh = state.mounts.alloc().ok_or(VfsError::NoSpace)?;
    let fs_id = state.alloc_fs_instance_id();
    let covered_key = state
        .vnodes
        .get(target_vh)
        .map(|v| v.vnode_key())
        .unwrap_or(crate::vfs_core::identity::VnodeKey::INVALID);
    let parent_fs_id = state
        .mounts
        .get(parent_mh)
        .map(|m| m.fs_instance_id)
        .unwrap_or(crate::vfs_core::identity::FsInstanceId::INVALID);
    {
        let mp = state.mounts.get_mut(mh).ok_or(VfsError::Io)?;
        mp.vfsops = vfsops;
        mp.vops = vops;
        mp.data = data;
        mp.flags = MNT_BIND | (flags & MNT_RBIND);
        mp.covered.set(covered_key, target_vh);
        mp.parent.set(parent_fs_id, parent_mh);
        mp.root_vnode = source_vh;
        mp.id = mh.slot() as u16;
        mp.fs_instance_id = fs_id;
        set_mount_identity(mp, b"bind", b"");
    }

    // Wire the covering link.
    if let Some(vn) = state.vnodes.get_mut(target_vh) {
        vn.flags |= VN_COVERED;
        vn.covered_by.set(fs_id, mh);
        vn.pin();
    }

    // Bind mounts reuse the source mount's root vnode; bump its pin
    // so each live `Mount` that cites it contributes one pin and the
    // matching `do_umount` only unpins once.
    if let Some(vn) = state.vnodes.get_mut(source_vh) {
        vn.pin();
    }

    // MNT_RBIND: clone child mounts of source_mh into the new bind mount.
    if (flags & MNT_RBIND) != 0 {
        unsafe { rbind_clone_children(state, mh, source_mh) };
    }

    Ok(mh)
}

/// Clone child mounts of `source_mh` as bind mounts under `new_parent_mh`.
///
/// Best-effort: pool exhaustion stops cloning but does not fail the primary
/// bind mount.
unsafe fn rbind_clone_children(
    state: &mut VfsState,
    new_parent_mh: MountHandle,
    source_mh: MountHandle,
) {
    // Identity of the source mount — parent membership is compared on
    // `fs_instance_id` (authority) rather than on `MountHandle::slot()`
    // to avoid false matches if an `Arena<Mount>` slot was recycled.
    let source_fs_id = state
        .mounts
        .get(source_mh)
        .map(|m| m.fs_instance_id)
        .unwrap_or(crate::vfs_core::identity::FsInstanceId::INVALID);
    let new_parent_fs_id = state
        .mounts
        .get(new_parent_mh)
        .map(|m| m.fs_instance_id)
        .unwrap_or(crate::vfs_core::identity::FsInstanceId::INVALID);
    if !source_fs_id.is_valid() {
        return;
    }

    // Collect child mount handles first to avoid borrow issues.
    let mut children = [MountHandle::INVALID; 16];
    let mut count = 0usize;
    state.mounts.for_each_active(|mh, mp| {
        if count < 16
            && mp.parent.id() == source_fs_id
            && mh.slot() != new_parent_mh.slot()
            && mh.slot() != source_mh.slot()
        {
            children[count] = mh;
            count += 1;
        }
        true
    });

    for i in 0..count {
        let child_mh = children[i];
        let child_mp = match state.mounts.get(child_mh) {
            Some(m) => m,
            None => continue,
        };
        let child_root_vh = child_mp.root_vnode;
        if !child_root_vh.is_valid() {
            continue;
        }
        let child_vfsops = child_mp.vfsops;
        let child_vops = child_mp.vops;
        let child_data = child_mp.data;
        let child_covered = child_mp.covered.handle_hint();
        let child_covered_key = child_mp.covered.id();

        let cloned_mh = match state.mounts.alloc() {
            Some(h) => h,
            None => break,
        };
        let cloned_fs_id = state.alloc_fs_instance_id();
        let cloned = match state.mounts.get_mut(cloned_mh) {
            Some(m) => m,
            None => break,
        };

        cloned.vfsops = child_vfsops;
        cloned.vops = child_vops;
        cloned.data = child_data;
        cloned.flags = MNT_BIND;
        cloned.parent.set(new_parent_fs_id, new_parent_mh);
        cloned.root_vnode = child_root_vh;
        cloned.covered.set(child_covered_key, child_covered);
        cloned.id = cloned_mh.slot() as u16;
        cloned.fs_instance_id = cloned_fs_id;
        set_mount_identity(cloned, b"bind", b"");
        drop(cloned);
        // rbind clones reuse the child mount's root vnode. Bump its
        // pin so each cloned `Mount` contributes one structural hold.
        if let Some(vn) = state.vnodes.get_mut(child_root_vh) {
            vn.pin();
        }
    }
}
