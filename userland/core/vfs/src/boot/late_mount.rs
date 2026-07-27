// SPDX-License-Identifier: GPL-2.0-only
//
//! Deferred root-pivot mountpoint repair.
//!
//! VFS boots from an initrd ramfs root, then a disk-backed root can
//! later mount over that root vnode. Mounts that were already
//! attached under the initrd root (`/dev`, `/proc`, `/sys`, ...)
//! must move their `covered_key` to the matching directory on the
//! new root. This module discovers those existing child mountpoints
//! generically by readdir/lookup on the old root, then ensures each
//! directory exists on the new root using the new root's own VOPs.
//! Backend-backed roots may park; those requests resume through
//! `FsResume::LatePivot`.

use crate::arena::Handle;
use crate::core::cred::VfsCred;
use crate::core::error::{VfsError, VfsResult};
use crate::core::identity::VnodeKey;
use crate::core::mount::{MountHandle, MountKind};
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::{VN_COVERED, Vnode, VnodeHandle};
use crate::owner::VfsState;
use crate::owner::pending::WALK_NAME_MAX;
use crate::owner::resume::{FsResume, LatePivotOp, Resume};

pub(crate) const LATE_PIVOT_MAX: usize = 16;

const STATE_EMPTY: u8 = 0;
const STATE_LOOKUP_PENDING: u8 = 1;
const STATE_MKDIR_PENDING: u8 = 2;
const STATE_DONE: u8 = 3;
const STATE_FAILED: u8 = 4;

#[derive(Clone, Copy)]
pub(crate) struct LatePivotEntry {
    state: u8,
    name_len: u8,
    _pad: [u8; 6],
    parent_vkey: VnodeKey,
    covered_mount: MountHandle,
    name: [u8; WALK_NAME_MAX],
    result_vkey: VnodeKey,
}

impl LatePivotEntry {
    pub(crate) const EMPTY: Self = Self {
        state: STATE_EMPTY,
        name_len: 0,
        _pad: [0; 6],
        parent_vkey: VnodeKey::NONE,
        covered_mount: MountHandle::INVALID,
        name: [0; WALK_NAME_MAX],
        result_vkey: VnodeKey::NONE,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct LatePivotTable {
    entries: [LatePivotEntry; LATE_PIVOT_MAX],
}

impl LatePivotTable {
    pub(crate) const EMPTY: Self = Self {
        entries: [LatePivotEntry::EMPTY; LATE_PIVOT_MAX],
    };

    fn clear(&mut self) {
        self.entries = [LatePivotEntry::EMPTY; LATE_PIVOT_MAX];
    }

    fn alloc_entry(
        &mut self,
        parent_vkey: VnodeKey,
        covered_mount: MountHandle,
        name: &[u8],
        name_len: u8,
    ) -> Option<u8> {
        if !parent_vkey.is_valid() || name_len == 0 || name_len as usize > WALK_NAME_MAX {
            return None;
        }
        for i in 0..LATE_PIVOT_MAX {
            if self.entries[i].state != STATE_EMPTY {
                continue;
            }
            let mut entry = LatePivotEntry::EMPTY;
            entry.state = STATE_LOOKUP_PENDING;
            entry.parent_vkey = parent_vkey;
            entry.covered_mount = covered_mount;
            entry.name_len = name_len;
            entry.name[..name_len as usize].copy_from_slice(&name[..name_len as usize]);
            self.entries[i] = entry;
            return u8::try_from(i).ok();
        }
        None
    }
}

#[derive(Clone, Copy)]
struct ChildName {
    name: [u8; WALK_NAME_MAX],
    name_len: u8,
}

impl ChildName {
    const EMPTY: Self = Self {
        name: [0; WALK_NAME_MAX],
        name_len: 0,
    };
}

/// Called after a mount is spliced into the namespace. If that
/// mount covers the current namespace root, promote it to the
/// active root and migrate already-mounted child mountpoints to
/// matching directories on the new root.
pub(crate) unsafe fn on_mount_finalized(
    state: &mut VfsState,
    mount_h: MountHandle,
    target_vh: VnodeHandle,
) {
    unsafe {
        if !target_vh.is_valid() || mount_h == state.root_mount {
            return;
        }
        let (old_root_vh, old_root_kind) = match state.mounts.get(state.root_mount) {
            Some(root_mount) => (root_mount.root, root_mount.kind),
            None => return,
        };
        if target_vh != old_root_vh {
            return;
        }
        let new_root_vh = match state.mounts.get(mount_h) {
            Some(mount) => mount.root,
            None => return,
        };
        if !new_root_vh.is_valid() {
            return;
        }

        state.root_mount = mount_h;
        cache_materialised_vnode(state, new_root_vh);
        state.late_pivot.clear();
        if matches!(
            old_root_kind,
            MountKind::Initrd | MountKind::Ramfs | MountKind::Tmpfs
        ) {
            migrate_existing_child_mountpoints(state, old_root_vh, new_root_vh);
        }
    }
}

unsafe fn migrate_existing_child_mountpoints(
    state: &mut VfsState,
    old_root_vh: VnodeHandle,
    new_root_vh: VnodeHandle,
) {
    let Some(new_parent_vkey) = state.vnodes.get(new_root_vh).map(|v| v.key) else {
        return;
    };
    let mut names = [ChildName::EMPTY; LATE_PIVOT_MAX];
    let count = unsafe { collect_root_child_names(state, old_root_vh, &mut names) };
    for child in names.iter().take(count) {
        let old_child = unsafe { lookup_child_ready(state, old_root_vh, child) };
        let Some(old_child_vh) = old_child else {
            continue;
        };
        let Some(covered_mount) = find_covering_mount_for_vnode(state, old_child_vh) else {
            continue;
        };
        let Some(idx) = state.late_pivot.alloc_entry(
            new_parent_vkey,
            covered_mount,
            &child.name[..child.name_len as usize],
            child.name_len,
        ) else {
            continue;
        };
        unsafe {
            issue_lookup_for_entry(state, idx, new_root_vh);
        }
    }
}

unsafe fn collect_root_child_names(
    state: &mut VfsState,
    root_vh: VnodeHandle,
    out: &mut [ChildName; LATE_PIVOT_MAX],
) -> usize {
    let Some(ctx) = (unsafe { crate::core::vop_context::OwnerVopCtx::from_state(state, root_vh) })
    else {
        return 0;
    };
    let ops = unsafe { (*ctx.vnode).ops };
    if ops.is_null() {
        return 0;
    }
    let data_ctx = unsafe { ctx.data_ctx() };
    let mut cookie = 0u64;
    let mut count = 0usize;
    let mut emit =
        |_: u64, name: *const u8, name_len: u8, _: u8, _: &crate::core::file::VAttr| -> bool {
            if name_len == 0 || name_len as usize > WALK_NAME_MAX {
                return true;
            }
            let bytes = unsafe { ::core::slice::from_raw_parts(name, name_len as usize) };
            if bytes == b"." || bytes == b".." {
                return true;
            }
            if count >= LATE_PIVOT_MAX {
                return false;
            }
            out[count].name_len = name_len;
            out[count].name[..name_len as usize].copy_from_slice(bytes);
            count += 1;
            count < LATE_PIVOT_MAX
        };
    match unsafe { ((*ops).data.readdir)(&data_ctx, &mut cookie, &mut emit) } {
        Ok(Ready(())) => count,
        _ => 0,
    }
}

unsafe fn lookup_child_ready(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    child: &ChildName,
) -> Option<VnodeHandle> {
    let Some(mut ctx) =
        (unsafe { crate::core::vop_context::OwnerVopCtx::from_state(state, parent_vh) })
    else {
        return None;
    };
    let ops = unsafe { (*ctx.vnode).ops };
    if ops.is_null() {
        return None;
    }
    match unsafe { ((*ops).meta.lookup)(&mut ctx, child.name.as_ptr(), child.name_len) } {
        Ok(Ready(vh)) if vh.is_valid() => Some(vh),
        _ => None,
    }
}

fn find_covering_mount_for_vnode(state: &VfsState, vnode_h: VnodeHandle) -> Option<MountHandle> {
    let key = state.vnodes.get(vnode_h)?.key;
    let mut found = None;
    state.mounts.for_each_active(|mount_h, mount| {
        if mount.covered_key == key {
            found = Some(mount_h);
            false
        } else {
            true
        }
    });
    found
}

unsafe fn issue_lookup_for_entry(state: &mut VfsState, dir_index: u8, parent_vh: VnodeHandle) {
    let Some(entry) = state.late_pivot.entries.get_mut(dir_index as usize) else {
        return;
    };
    entry.state = STATE_LOOKUP_PENDING;
    let name = entry.name;
    let name_len = entry.name_len;
    let Some(mut ctx) =
        (unsafe { crate::core::vop_context::OwnerVopCtx::from_state(state, parent_vh) })
    else {
        mark_failed(state, dir_index);
        return;
    };
    let ops = unsafe { (*ctx.vnode).ops };
    if ops.is_null() {
        mark_failed(state, dir_index);
        return;
    }
    match unsafe { ((*ops).meta.lookup)(&mut ctx, name.as_ptr(), name_len) } {
        Ok(Ready(vh)) if vh.is_valid() => finish_materialised(state, dir_index, vh),
        Ok(Ready(_)) | Err(VfsError::NoEnt) => {
            drop(ctx);
            unsafe { issue_mkdir_for_entry(state, dir_index, parent_vh) };
        }
        Ok(Parked(handle)) => {
            if state
                .stamp_resume_ctx(
                    handle,
                    0,
                    None,
                    Resume::Fs(FsResume::LatePivot {
                        dir_index,
                        op: LatePivotOp::Lookup,
                    }),
                )
                .is_err()
            {
                mark_failed(state, dir_index);
            }
        }
        Err(_) => mark_failed(state, dir_index),
    }
}

unsafe fn issue_mkdir_for_entry(state: &mut VfsState, dir_index: u8, parent_vh: VnodeHandle) {
    let Some(entry) = state.late_pivot.entries.get_mut(dir_index as usize) else {
        return;
    };
    entry.state = STATE_MKDIR_PENDING;
    let name = entry.name;
    let name_len = entry.name_len;
    let Some(mut ctx) =
        (unsafe { crate::core::vop_context::OwnerVopCtx::from_state(state, parent_vh) })
    else {
        mark_failed(state, dir_index);
        return;
    };
    let ops = unsafe { (*ctx.vnode).ops };
    if ops.is_null() {
        mark_failed(state, dir_index);
        return;
    }
    let cred = VfsCred::root();
    match unsafe { ((*ops).meta.mkdir)(&mut ctx, name.as_ptr(), name_len, 0o755, &raw const cred) }
    {
        Ok(Ready(vh)) if vh.is_valid() => finish_materialised(state, dir_index, vh),
        Ok(Parked(handle)) => {
            if state
                .stamp_resume_ctx(
                    handle,
                    0,
                    None,
                    Resume::Fs(FsResume::LatePivot {
                        dir_index,
                        op: LatePivotOp::Mkdir,
                    }),
                )
                .is_err()
            {
                mark_failed(state, dir_index);
            }
        }
        _ => mark_failed(state, dir_index),
    }
}

/// Resume a deferred-pivot lookup once the backing filesystem has
/// finalised. Missing entries are created through the same root
/// VOP, preserving the mountpoint directory set without assuming a
/// specific backing filesystem.
pub(crate) unsafe fn resume_deferred_pivot_lookup(
    state: &mut VfsState,
    dir_index: u8,
    result: VfsResult<Option<VnodeHandle>>,
) {
    match result {
        Ok(Some(vnode_h)) => finish_materialised(state, dir_index, vnode_h),
        Ok(None) => {
            let Some(parent_vh) = parent_handle_for_entry(state, dir_index) else {
                mark_failed(state, dir_index);
                return;
            };
            unsafe { issue_mkdir_for_entry(state, dir_index, parent_vh) };
        }
        Err(_) => mark_failed(state, dir_index),
    }
}

/// Resume a deferred-pivot mkdir. The created vnode is cached the
/// same way as lookup, then any pre-existing child mount covering
/// the old initrd directory is reattached to the new directory.
pub(crate) unsafe fn resume_deferred_pivot_mkdir(
    state: &mut VfsState,
    dir_index: u8,
    result: VfsResult<VnodeHandle>,
) {
    match result {
        Ok(vnode_h) => finish_materialised(state, dir_index, vnode_h),
        Err(_) => mark_failed(state, dir_index),
    }
}

fn parent_handle_for_entry(state: &VfsState, dir_index: u8) -> Option<VnodeHandle> {
    let entry = state.late_pivot.entries.get(dir_index as usize)?;
    resolve_vkey(state, entry.parent_vkey)
}

fn finish_materialised(state: &mut VfsState, dir_index: u8, vnode_h: VnodeHandle) {
    if !vnode_h.is_valid() {
        mark_failed(state, dir_index);
        return;
    }
    cache_materialised_vnode(state, vnode_h);
    let Some(entry) = state.late_pivot.entries.get_mut(dir_index as usize) else {
        return;
    };
    entry.state = STATE_DONE;
    entry.result_vkey = state
        .vnodes
        .get(vnode_h)
        .map(|v| v.key)
        .unwrap_or(VnodeKey::NONE);
    reattach_covered_mount(state, dir_index, vnode_h);
}

fn reattach_covered_mount(state: &mut VfsState, dir_index: u8, new_cover_vh: VnodeHandle) {
    let Some(entry) = state.late_pivot.entries.get(dir_index as usize).copied() else {
        return;
    };
    if !entry.covered_mount.is_valid() || !new_cover_vh.is_valid() {
        return;
    }
    let Some(new_key) = state.vnodes.get(new_cover_vh).map(|v| v.key) else {
        return;
    };
    let old_key = state
        .mounts
        .get(entry.covered_mount)
        .map(|mount| mount.covered_key)
        .unwrap_or(VnodeKey::NONE);
    if let Some(old_vh) = resolve_vkey(state, old_key) {
        if let Some(old_vnode) = state.vnodes.get_mut(old_vh) {
            old_vnode.flags &= !VN_COVERED;
            old_vnode.covered_by_fs = crate::core::identity::FsInstanceId::INVALID;
            old_vnode.unpin();
        }
    }
    let covered_fs = match state.mounts.get(entry.covered_mount) {
        Some(mount) => mount.fs_instance_id,
        None => return,
    };
    if let Some(new_vnode) = state.vnodes.get_mut(new_cover_vh) {
        new_vnode.set_covered_by(covered_fs);
        new_vnode.pin();
    }
    if let Some(mount) = state.mounts.get_mut(entry.covered_mount) {
        mount.covered_key = new_key;
    }
}

fn mark_failed(state: &mut VfsState, dir_index: u8) {
    if let Some(entry) = state.late_pivot.entries.get_mut(dir_index as usize) {
        entry.state = STATE_FAILED;
    }
}

fn cache_materialised_vnode(state: &mut VfsState, vnode_h: VnodeHandle) {
    if !vnode_h.is_valid() {
        return;
    }
    let Some(vnode) = state.vnodes.get(vnode_h) else {
        return;
    };
    if vnode.key.is_valid() {
        state.install_resolve_cache(vnode.key, vnode_h);
    }
}

fn resolve_vkey(state: &VfsState, vkey: VnodeKey) -> Option<VnodeHandle> {
    if !vkey.is_valid() {
        return None;
    }
    if let Some(handle) = state.lookup_resolve_cache(vkey) {
        return Some(handle);
    }
    let mut found = None;
    state
        .vnodes
        .for_each_active(|handle: Handle<Vnode>, vnode| {
            if vnode.key == vkey {
                found = Some(handle);
                false
            } else {
                true
            }
        });
    found
}
