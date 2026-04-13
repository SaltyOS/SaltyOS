// SPDX-License-Identifier: GPL-2.0-only
//! Centralized mount controller — single authority for mount-tree mutations.
//!
//! All mount operations go through this module. Bootstrap, fstab processing,
//! IPC handlers, and late-mount retry all converge here.
//!
//! # Single-owner model
//!
//! The static `MOUNT_POOL` is eliminated. All mount allocation uses
//! `VfsState.mounts` arena. Every function that mutates mount state takes
//! `&mut VfsState`.

use crate::arena::Arena;
use crate::owner::VfsState;

use super::error::{VfsError, VfsResult};
use super::mount::{Mount, MountHandle, VnodeHandle, MOUNT_PATH_MAX};
use super::vfs::{self, VfsOps};
use super::vnode::{Vnode, VN_COVERED, VN_ROOT};
use super::vop::VopVector;
use super::vop_context::VopContext;

// =========================================================================
// Alloc trampoline
// =========================================================================

// The VopContext arena callbacks are bare function pointers — they cannot
// capture state. We use unsafe statics to pass arena pointers to the
// trampolines. This is safe because the VFS main loop is single-threaded:
// the statics are set before a VOP call and cleared after.

static mut VNODE_ARENA_PTR: *mut Arena<Vnode> = core::ptr::null_mut();
static mut MOUNT_ARENA_PTR: *const Arena<Mount> = core::ptr::null();

unsafe fn vnode_alloc_trampoline() -> Option<(VnodeHandle, *mut Vnode)> {
    unsafe {
        let arena = &mut *VNODE_ARENA_PTR;
        let h = arena.alloc()?;
        let ptr = arena.raw_ptr(h)?;
        Some((h, ptr))
    }
}

pub(crate) unsafe fn vnode_resolve_trampoline(vh: VnodeHandle) -> Option<*const Vnode> {
    unsafe {
        let arena = &*VNODE_ARENA_PTR;
        let ptr = arena.raw_ptr(vh)?;
        Some(ptr as *const Vnode)
    }
}

pub(crate) unsafe fn mount_resolve_trampoline(mh: MountHandle) -> Option<*const Mount> {
    unsafe {
        let arena = &*MOUNT_ARENA_PTR;
        let ptr = arena.raw_ptr(mh)?;
        Some(ptr as *const Mount)
    }
}

pub(crate) unsafe fn trampoline_mount_handle_from_slot(slot: u32) -> Option<MountHandle> {
    unsafe {
        let arena = &*MOUNT_ARENA_PTR;
        arena.handle_from_slot(slot)
    }
}

/// Set up the arena trampolines and build a VopContext for a given vnode.
///
/// # Safety
///
/// Caller must ensure no concurrent VOP calls are active (single-threaded
/// guarantee of the owner loop). Must call `clear_trampolines()` after
/// the VOP call completes.
pub(crate) unsafe fn build_vop_context(
    state: &mut VfsState,
    vh: VnodeHandle,
) -> Option<VopContext> {
    unsafe {
        let vnode_ptr = state.vnodes.raw_ptr(vh)?;
        let vnode = &*vnode_ptr;
        let mount_ptr = state.mounts.raw_ptr(vnode.mount)?;
        let mount = &*mount_ptr;

        VNODE_ARENA_PTR = &raw mut state.vnodes;
        MOUNT_ARENA_PTR = &raw const state.mounts;

        Some(VopContext {
            handle: vh,
            vnode: vnode_ptr,
            mount_handle: vnode.mount,
            mount: mount_ptr as *const Mount,
            data: vnode.data,
            mount_data: mount.data,
            alloc: vnode_alloc_trampoline,
            resolve_vnode: vnode_resolve_trampoline,
            resolve_mount: mount_resolve_trampoline,
        })
    }
}

/// Clear the arena trampolines after a VOP call completes.
#[inline]
pub(crate) fn clear_trampolines() {
    unsafe {
        VNODE_ARENA_PTR = core::ptr::null_mut();
        MOUNT_ARENA_PTR = core::ptr::null();
    }
}

/// Set up the arena trampolines without building a full VopContext.
///
/// Used by `do_mount_with_ops` so that `VfsOps::mount` implementations
/// can allocate vnodes via `trampoline_alloc_vnode`.
///
/// # Safety
///
/// Caller must call `clear_trampolines()` after the operation completes.
pub(crate) unsafe fn set_trampolines(state: &mut VfsState) {
    unsafe {
        VNODE_ARENA_PTR = &raw mut state.vnodes;
        MOUNT_ARENA_PTR = &raw const state.mounts;
    }
}

/// Allocate a vnode from the arena via the trampoline.
///
/// Available to backends during `VfsOps::mount` (after `set_trampolines`
/// has been called). Returns `(VnodeHandle, *mut Vnode)` or `None`.
pub(crate) unsafe fn trampoline_alloc_vnode() -> Option<(VnodeHandle, *mut Vnode)> {
    unsafe { vnode_alloc_trampoline() }
}

// =========================================================================
// Covering mount resolution
// =========================================================================

/// Resolve the child mount covering `target_vh`.
///
/// Prefer the direct vnode link when present, but fall back to the mount tree
/// by matching `(parent mount, covered vnode id)`. This keeps mount visibility
/// stable even when backend lookup returns a fresh vnode instance for the same
/// filesystem object.
pub(crate) fn covering_mount_for_vnode(
    state: &VfsState,
    target_vh: VnodeHandle,
) -> Option<MountHandle> {
    let vnode = state.vnodes.get(target_vh)?;
    if vnode.covered_by.is_valid() && state.mounts.get(vnode.covered_by).is_some() {
        return Some(vnode.covered_by);
    }

    let parent_mh = vnode.mount;
    if !parent_mh.is_valid() {
        return None;
    }
    let vnode_id = vnode.id;
    let mut found = None;

    state.mounts.for_each_active(|mh, mp| {
        if mp.parent != parent_mh || !mp.covered_vnode.is_valid() {
            return true;
        }
        let Some(covered_vnode) = state.vnodes.get(mp.covered_vnode) else {
            return true;
        };
        if covered_vnode.id == vnode_id {
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

/// Fill the `fs_type_name` and `mount_path` fields of a mount.
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

/// Mount a filesystem on a resolved target vnode.
///
/// Looks up `fstype` in the FsType registry, allocates a mount slot from
/// the arena, calls `VfsOps.mount`, and wires the covering link.
pub(crate) unsafe fn do_mount(
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
        let ft = vfs::find_fs_type(fstype).ok_or(VfsError::NotFound)?;
        do_mount_with_ops(
            state, target_vh, ft.vfsops, ft.vops, fstype, mount_path, source, flags, opts, opts_len,
        )
    }
}

/// Mount with explicit VfsOps/VopVector (bypasses FsType registry).
///
/// Used by bootstrap for the root ramfs mount which is set up before the
/// registry is populated.
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
) -> VfsResult<MountHandle> {
    unsafe {
        let mh = state.mounts.alloc().ok_or(VfsError::NoSpace)?;
        {
            let mp = state.mounts.get_mut(mh).ok_or(VfsError::Io)?;
            mp.vfsops = vfsops;
            mp.vops = vops;
            mp.covered_vnode = target_vh;
            mp.parent = if target_vh.is_valid() {
                let target_vnode = state.vnodes.get(target_vh).ok_or(VfsError::Io)?;
                target_vnode.mount
            } else {
                MountHandle::INVALID
            };
            mp.flags = flags;
            mp.id = mh.slot() as u16;
            set_mount_identity(mp, fs_name, mount_path);
        }

        // Set up arena trampolines so the backend can allocate vnodes.
        set_trampolines(state);
        let mp_ptr = state.mounts.raw_ptr(mh).ok_or(VfsError::Io)?;
        let mount_result = ((*vfsops).mount)(mp_ptr, source, opts, opts_len);
        clear_trampolines();
        if let Err(e) = mount_result {
            state.mounts.release(mh);
            return Err(e);
        }

        let root_vh = state.mounts.get(mh).ok_or(VfsError::Io)?.root_vnode;
        if root_vh.is_valid() {
            let root_vnode = state.vnodes.get_mut(root_vh).ok_or(VfsError::Io)?;
            root_vnode.mount = mh;
        }

        // Wire covering link on the target vnode.
        if target_vh.is_valid() {
            let target_vnode = state.vnodes.get_mut(target_vh).ok_or(VfsError::Io)?;
            target_vnode.flags |= VN_COVERED;
            target_vnode.covered_by = mh;
        }

        Ok(mh)
    }
}

/// Unmount the filesystem covering a vnode.
pub(crate) unsafe fn do_umount(
    state: &mut VfsState,
    target_vh: VnodeHandle,
    flags: u32,
) -> VfsResult<()> {
    unsafe {
        use super::mount::MNT_FORCE;

        let target_vnode = state.vnodes.get(target_vh).ok_or(VfsError::NotSupported)?;
        let mh = covering_mount_for_vnode(state, target_vh).ok_or(VfsError::NotFound)?;
        if !mh.is_valid() {
            return Err(VfsError::NotFound);
        }

        let mp = state.mounts.get(mh).ok_or(VfsError::NotFound)?;
        let force = flags & MNT_FORCE != 0;
        let vfsops = mp.vfsops;

        if !vfsops.is_null() {
            let mp_ptr = state.mounts.raw_ptr(mh).ok_or(VfsError::Io)?;
            ((*vfsops).unmount)(mp_ptr, force)?;
        }

        // Unwire covering link.
        let target_vnode = state.vnodes.get_mut(target_vh).ok_or(VfsError::Io)?;
        target_vnode.covered_by = MountHandle::INVALID;
        target_vnode.flags &= !VN_COVERED;

        // Release mount slot.
        state.mounts.release(mh);

        Ok(())
    }
}

/// pivot_root wrapper — delegates to the pivot implementation and refreshes
/// the global mount namespace.
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

/// Resolve an absolute path to a vnode starting from `root_mount`.
///
/// Crosses mount boundaries but does not follow symlinks or apply
/// personality filtering. Returns a VnodeHandle.
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

        // Skip leading slashes.
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

            // Build VopContext for lookup.
            let ctx = build_vop_context(state, current).ok_or(VfsError::Io)?;
            let ops = unsafe { &*(*ctx.vnode).ops };
            let child = (ops.meta.lookup)(&ctx, path.as_ptr().add(comp_start), comp_len as u8)?;
            clear_trampolines();

            if !child.is_valid() {
                return Err(VfsError::NotFound);
            }

            // Cross mount boundary if covered.
            current = cross_mount_boundary(state, child)?;
        }

        Ok(current)
    }
}

/// Walk across mount coverage: if the vnode is covered by a child mount,
/// return the child mount's root vnode handle. Repeats if multi-layered.
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

/// Re-snapshot all active mounts from the arena into the global namespace.
pub(crate) fn refresh_global_ns(state: &mut VfsState) {
    if !state.global_ns.is_valid() {
        return;
    }

    // Collect mount handles into a stack buffer first to avoid
    // simultaneous borrows of state.mounts and state.mount_ns.
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
