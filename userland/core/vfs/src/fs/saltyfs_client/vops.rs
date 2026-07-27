// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyFS client VopVector implementation — vnode-level
//! operations.
//!
//! Each function maps to a `VopMetaOps` or `VopDataOps` slot and
//! issues the corresponding SaltyFS IPC call via the `rpc` /
//! `mutate_rpc` / `xattr_rpc` helpers. There is no sync fallback
//! path: every metadata RPC parks on a `PendingOp` and resumes
//! through the saltyfs completion router. Credit / arena
//! exhaustion surfaces as `VfsError::Again` so the dispatch
//! layer can apply backpressure rather than block the owner
//! reactor.
//!
//! Bulk payloads (BACKEND_READ / BACKEND_WRITE / BACKEND_READDIR
//! / BACKEND_GETXATTR / BACKEND_LISTXATTR) ride exclusively
//! through the per-mount-instance SHM ring — there is no inline-
//! regs fast path. Single-mechanism transfer matches the Zircon-
//! VMO model and keeps the completion router uniform.

use trona_kernel::core_types::TronaMsg;

use crate::core::cred::VfsCred;
use crate::core::error::VfsError;
use crate::core::file::{VAttr, VStatfs};
use crate::core::outcome::{Parked, Ready, VopOutcome};
use crate::core::vnode::{VT_DIR, VT_LNK, VT_REG, VnodeHandle};
use crate::core::vop::ReaddirEmit;
use crate::core::vop_context::{OwnerVopCtx, VopDataCtx};
use crate::ipc::protocol::backend::TransferDescriptor;

use super::mutate_rpc;
use super::rpc;
use super::types::{SALTYFS_RING_SLOT_BYTES, SaltyfsMountData, SaltyfsVnodeData};
use super::xattr_rpc;

// ---------------------------------------------------------------------------
// Tiny helpers
// ---------------------------------------------------------------------------

#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut SaltyfsVnodeData {
    ctx.data as *mut SaltyfsVnodeData
}

/// Return the cached file size in bytes from the saltyfs vdata
/// record. Owner-thread synchronous; the cached value is updated by
/// `saltyfs_alloc_or_lookup_vnode` (lookup), `saltyfs_getattr`
/// completion, `saltyfs_truncate`, and the write/setattr completion
/// paths. A null vdata returns 0.
pub(super) unsafe fn saltyfs_data_size(ctx: &mut OwnerVopCtx<'_>) -> u64 {
    let vd = unsafe { vdata(&*ctx) };
    if vd.is_null() {
        0
    } else {
        unsafe { (*vd).size }
    }
}

#[inline]
unsafe fn mdata(ctx: &OwnerVopCtx<'_>) -> *mut SaltyfsMountData {
    ctx.mount_data as *mut SaltyfsMountData
}

#[inline]
unsafe fn vdata_d(ctx: &VopDataCtx) -> *mut SaltyfsVnodeData {
    ctx.data as *mut SaltyfsVnodeData
}

#[inline]
unsafe fn mdata_d(ctx: &VopDataCtx) -> *mut SaltyfsMountData {
    ctx.mount_data as *mut SaltyfsMountData
}

/// POSIX `S_IFMT` mask, mirrored locally so the saltyfs vop layer
/// does not pull in the personality-posix crate.
const S_IFMT_L: u32 = 0o170000;
const MODE_TYPE_DIR: u32 = 0o040000;
const MODE_TYPE_LNK: u32 = 0o120000;

#[inline]
fn mode_to_vtype(mode: u32) -> u8 {
    match mode & S_IFMT_L {
        MODE_TYPE_DIR => VT_DIR,
        MODE_TYPE_LNK => VT_LNK,
        _ => VT_REG,
    }
}

// ---------------------------------------------------------------------------
// Vnode allocation — async-friendly variants used by the completion
// router (state-only) and by sync VOPs (ctx-bearing).
// ---------------------------------------------------------------------------

/// Completion-path entry point: allocate a SaltyFS vnode without
/// a live `OwnerVopCtx`. Mirrors the ctx-bearing wrapper's
/// contract but takes the primitives directly so the async
/// mutation completion router (which holds `&mut VfsState` but
/// no ctx) can materialise the new child vnode. Arena allocation
/// and resolve-cache install go through `VfsState` directly.
pub(crate) fn alloc_saltyfs_vnode_from_state(
    state: &mut crate::owner::VfsState,
    mount_handle: crate::core::mount::MountHandle,
    parent_ino: u64,
    remote_ino: u64,
    remote_seq: u32,
    mode: u32,
    size: u64,
    nlink: u32,
    mtime: u64,
    uid: u32,
    gid: u32,
    dir_type: u8,
    blocks: u64,
) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let (md, fs_id, ops_ptr) = {
            let mount = state.mounts.get(mount_handle).ok_or(VfsError::Io)?;
            let md = mount.data as *mut SaltyfsMountData;
            if md.is_null() {
                return Err(VfsError::Io);
            }
            (md, mount.fs_instance_id, &raw const super::SALTYFS_VOPS)
        };
        alloc_saltyfs_vnode_via_state(
            state,
            md,
            mount_handle,
            fs_id,
            ops_ptr,
            parent_ino,
            remote_ino,
            remote_seq,
            mode,
            size,
            nlink,
            mtime,
            uid,
            gid,
            dir_type,
            blocks,
        )
    }
}

/// Owner-ctx wrapper for [`alloc_saltyfs_vnode_via_state`]. Used
/// by sync vops (lookup-cache hit, late-pivot scaffold builder)
/// that already hold an `OwnerVopCtx`.
unsafe fn alloc_saltyfs_vnode(
    ctx: &mut OwnerVopCtx<'_>,
    parent_ino: u64,
    remote_ino: u64,
    remote_seq: u32,
    mode: u32,
    size: u64,
    nlink: u32,
    mtime: u64,
    uid: u32,
    gid: u32,
    dir_type: u8,
    blocks: u64,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let md = mdata(ctx);
        let mount_h = ctx.mount_handle;
        let fs_id = (*ctx.mount).fs_instance_id;
        let ops_ptr = (*ctx.vnode).ops;
        match alloc_saltyfs_vnode_via_state(
            ctx.state, md, mount_h, fs_id, ops_ptr, parent_ino, remote_ino, remote_seq, mode, size,
            nlink, mtime, uid, gid, dir_type, blocks,
        ) {
            Ok(vnode_h) => Ok(Ready(vnode_h)),
            Err(e) => Err(e),
        }
    }
}

/// Inner allocator. Walks the per-mount vdata pool to honour
/// "one vdata per remote inode" caching, then allocates the
/// arena vnode + populates fields. On cache hit, refreshes the
/// cached attribute snapshot so subsequent stat replies do not
/// have to round-trip the backend.
unsafe fn alloc_saltyfs_vnode_via_state(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    mount_handle: crate::core::mount::MountHandle,
    fs_instance_id: crate::core::identity::FsInstanceId,
    ops: *const crate::core::vop::VopVector,
    parent_ino: u64,
    remote_ino: u64,
    remote_seq: u32,
    mode: u32,
    size: u64,
    nlink: u32,
    mtime: u64,
    uid: u32,
    gid: u32,
    dir_type: u8,
    blocks: u64,
) -> Result<VnodeHandle, VfsError> {
    unsafe {
        // ---- vdata cache hit ----
        let existing_vd = super::pool::find_vdata_by_node(md, remote_ino, remote_seq);
        if !existing_vd.is_null() {
            (*existing_vd).mode = mode;
            (*existing_vd).remote_seq = remote_seq;
            (*existing_vd).size = size;
            (*existing_vd).nlink = nlink;
            (*existing_vd).mtime = mtime;
            (*existing_vd).uid = uid;
            (*existing_vd).gid = gid;
            (*existing_vd).blocks = blocks;
            if parent_ino != 0 {
                (*existing_vd).parent_ino = parent_ino;
            }

            if (*existing_vd).vnode_handle.is_valid()
                && state.vnodes.get((*existing_vd).vnode_handle).is_some()
            {
                return Ok((*existing_vd).vnode_handle);
            }

            let vnode_h = state.vnodes.alloc().ok_or(VfsError::NoMem)?;
            let vnode_ptr = state.vnodes.raw_ptr(vnode_h).ok_or(VfsError::NoMem)?;
            *vnode_ptr = crate::core::vnode::Vnode::EMPTY;
            populate_vnode_fields(
                vnode_ptr,
                fs_instance_id,
                mount_handle,
                ops,
                existing_vd,
                remote_ino,
                remote_seq,
                nlink,
            );
            if remote_ino == (*md).root_ino {
                (*vnode_ptr).flags |= crate::core::vnode::VN_ROOT;
                (*vnode_ptr).pin();
            }
            let key = (*vnode_ptr).vnode_key();
            if let Some(covering_fs_id) = covering_fs_id_for_key_via_state(state, key) {
                (*vnode_ptr).set_covered_by(covering_fs_id);
                (*vnode_ptr).pin();
            }
            (*existing_vd).vnode_handle = vnode_h;
            state.install_resolve_cache(key, vnode_h);
            return Ok(vnode_h);
        }

        // ---- fresh allocation ----
        let vdata = super::pool::alloc_vdata(md);
        if vdata.is_null() {
            return Err(VfsError::NoMem);
        }
        let ftype = if dir_type != 0 {
            super::readdir_dtype_to_vtype(dir_type)
        } else {
            mode_to_vtype(mode)
        };
        (*vdata).active = 1;
        (*vdata).ftype = ftype;
        (*vdata).mode = mode;
        (*vdata).remote_ino = remote_ino;
        (*vdata).parent_ino = parent_ino;
        (*vdata).remote_seq = remote_seq;
        (*vdata).size = size;
        (*vdata).nlink = nlink;
        (*vdata).uid = uid;
        (*vdata).gid = gid;
        (*vdata).mtime = mtime;
        (*vdata).blocks = blocks;

        let vnode_h = match state.vnodes.alloc() {
            Some(h) => h,
            None => {
                (*vdata).active = 0;
                return Err(VfsError::NoMem);
            }
        };
        let vnode_ptr = match state.vnodes.raw_ptr(vnode_h) {
            Some(p) => p,
            None => {
                (*vdata).active = 0;
                return Err(VfsError::NoMem);
            }
        };
        *vnode_ptr = crate::core::vnode::Vnode::EMPTY;
        populate_vnode_fields(
            vnode_ptr,
            fs_instance_id,
            mount_handle,
            ops,
            vdata,
            remote_ino,
            remote_seq,
            nlink,
        );
        (*vdata).vnode_handle = vnode_h;
        let key = (*vnode_ptr).vnode_key();
        state.install_resolve_cache(key, vnode_h);
        Ok(vnode_h)
    }
}

/// Populate the personality-neutral subset of `Vnode` from a
/// freshly-allocated saltyfs vdata + the matching backend
/// identity tuple. `kind` is derived from the vdata's `ftype`
/// byte so the writer side stays single-source-of-truth.
unsafe fn populate_vnode_fields(
    vnode_ptr: *mut crate::core::vnode::Vnode,
    fs_instance_id: crate::core::identity::FsInstanceId,
    mount_handle: crate::core::mount::MountHandle,
    ops: *const crate::core::vop::VopVector,
    vdata: *mut SaltyfsVnodeData,
    remote_ino: u64,
    remote_seq: u32,
    nlink: u32,
) {
    use crate::core::identity::{BackendNodeId, VnodeKey};
    use crate::core::vnode::VnodeKind;
    unsafe {
        let kind = match (*vdata).ftype {
            VT_DIR => VnodeKind::Directory,
            VT_LNK => VnodeKind::Symlink,
            _ => VnodeKind::Regular,
        };
        (*vnode_ptr).key =
            VnodeKey::new(fs_instance_id, BackendNodeId::new(remote_ino, remote_seq));
        (*vnode_ptr).kind = kind;
        (*vnode_ptr).mount = mount_handle;
        (*vnode_ptr).fs_instance_id = fs_instance_id;
        (*vnode_ptr).data = vdata as *mut u8;
        (*vnode_ptr).ops = ops;
        (*vnode_ptr).flags = 0;
        (*vnode_ptr).nlink = nlink;
        (*vnode_ptr).backend_seq = remote_seq;
        (*vnode_ptr).covered_by_fs = crate::core::identity::FsInstanceId::INVALID;
        (*vnode_ptr).open_refcount = 0;
        (*vnode_ptr).cache_pin = 0;
    }
}

/// Walks `VfsState.mounts` looking for a mount whose `covered_key`
/// matches `key`; used by the cache-hit path of
/// `alloc_saltyfs_vnode_via_state` to restore `VN_COVERED` on a
/// vnode reallocated into a slot previously holding a mountpoint.
unsafe fn covering_fs_id_for_key_via_state(
    state: &crate::owner::VfsState,
    key: crate::core::identity::VnodeKey,
) -> Option<crate::core::identity::FsInstanceId> {
    if !key.is_valid() {
        return None;
    }
    let mut found = None;
    state.mounts.for_each_active(|_mh, mp| {
        if mp.covered_key == key {
            found = Some(mp.fs_instance_id);
            return false;
        }
        true
    });
    found
}

// ---------------------------------------------------------------------------
// VopMetaOps
// ---------------------------------------------------------------------------

pub(super) unsafe fn saltyfs_lookup(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);

        // "."
        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }

        // ".." — async via BACKEND_LOOKUP with
        // CORRELATION_F_LOOKUP_PARENT. The completion router
        // unpacks the parent attrs and either echoes the child
        // (root / orphan with parent_ino == 0 / self-loop) or
        // installs a fresh parent vnode.
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            let fs_id = (*ctx.mount).fs_instance_id;
            return match rpc::saltyfs_ipc_lookup_parent_issue(
                ctx.state,
                md,
                (*dir_vdata).remote_ino,
                (*dir_vdata).remote_seq,
                fs_id,
            ) {
                Some(handle) => Ok(Parked(handle)),
                None => Err(VfsError::Again),
            };
        }

        // Regular component — async issue, parked PendingOp
        // resumes through `FsResume::NameiStep`.
        let fs_id = (*ctx.mount).fs_instance_id;
        match rpc::saltyfs_ipc_lookup_issue(
            ctx.state,
            md,
            (*dir_vdata).remote_ino,
            (*dir_vdata).remote_seq,
            name,
            name_len,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_create(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    mode: u32,
    cred: *const VfsCred,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let (uid, gid) = creds_or_root(cred);
        let fs_id = (*ctx.mount).fs_instance_id;
        match mutate_rpc::saltyfs_ipc_create_issue(
            ctx.state,
            md,
            (*dir_vdata).remote_ino,
            (*dir_vdata).remote_seq,
            name,
            name_len,
            mode,
            uid,
            gid,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_mkdir(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    mode: u32,
    cred: *const VfsCred,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let (uid, gid) = creds_or_root(cred);
        let fs_id = (*ctx.mount).fs_instance_id;
        match mutate_rpc::saltyfs_ipc_mkdir_issue(
            ctx.state,
            md,
            (*dir_vdata).remote_ino,
            (*dir_vdata).remote_seq,
            name,
            name_len,
            mode,
            uid,
            gid,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_symlink(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    target: *const u8,
    target_len: u8,
    cred: *const VfsCred,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let (uid, gid) = creds_or_root(cred);
        let fs_id = (*ctx.mount).fs_instance_id;
        match mutate_rpc::saltyfs_ipc_symlink_issue(
            ctx.state,
            md,
            (*dir_vdata).remote_ino,
            (*dir_vdata).remote_seq,
            name,
            name_len,
            target,
            target_len,
            uid,
            gid,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_unlink(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let fs_id = (*ctx.mount).fs_instance_id;
        match mutate_rpc::saltyfs_ipc_unlink_issue(
            ctx.state,
            md,
            (*dir_vdata).remote_ino,
            (*dir_vdata).remote_seq,
            name,
            name_len,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_rmdir(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let fs_id = (*ctx.mount).fs_instance_id;
        match mutate_rpc::saltyfs_ipc_rmdir_issue(
            ctx.state,
            md,
            (*dir_vdata).remote_ino,
            (*dir_vdata).remote_seq,
            name,
            name_len,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_link(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    target: VnodeHandle,
) -> VopOutcome<()> {
    unsafe {
        let dir_vdata = vdata(ctx);
        if dir_vdata.is_null() || (*dir_vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        // Defensive mount-identity check. Cross-mount link is
        // rejected at the dispatch layer (handle_linkat → XDev),
        // but the VOP must not reinterpret foreign vnode data
        // since the cast below is UB for any other backend.
        let target_vp = ctx.resolve_vnode(target).ok_or(VfsError::Inval)?;
        if (*target_vp).fs_instance_id != (*ctx.mount).fs_instance_id {
            return Err(VfsError::XDev);
        }
        let tvd = (*target_vp).data as *mut SaltyfsVnodeData;
        if tvd.is_null() {
            return Err(VfsError::Inval);
        }
        let md = mdata(ctx);
        let fs_id = (*ctx.mount).fs_instance_id;
        match mutate_rpc::saltyfs_ipc_link_issue(
            ctx.state,
            md,
            (*dir_vdata).remote_ino,
            (*dir_vdata).remote_seq,
            (*tvd).remote_ino,
            (*tvd).remote_seq,
            name,
            name_len,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_rename(
    ctx: &mut OwnerVopCtx<'_>,
    old_name: *const u8,
    old_len: u8,
    new_dir: VnodeHandle,
    new_name: *const u8,
    new_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let old_dvd = vdata(ctx);
        if old_dvd.is_null() || (*old_dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let new_vp = ctx.resolve_vnode(new_dir).ok_or(VfsError::Inval)?;
        if (*new_vp).fs_instance_id != (*ctx.mount).fs_instance_id {
            return Err(VfsError::XDev);
        }
        let new_dvd = (*new_vp).data as *mut SaltyfsVnodeData;
        if new_dvd.is_null() || (*new_dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let fs_id = (*ctx.mount).fs_instance_id;
        match mutate_rpc::saltyfs_ipc_rename_issue(
            ctx.state,
            md,
            (*old_dvd).remote_ino,
            (*old_dvd).remote_seq,
            old_name,
            old_len,
            (*new_dvd).remote_ino,
            (*new_dvd).remote_seq,
            new_name,
            new_len,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_open(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(super) unsafe fn saltyfs_close(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(super) unsafe fn saltyfs_getattr(
    ctx: &mut OwnerVopCtx<'_>,
    _attr: *mut VAttr,
) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata(ctx);
        let fs_id = (*ctx.mount).fs_instance_id;
        match rpc::saltyfs_ipc_stat_issue(
            ctx.state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_setattr(
    ctx: &mut OwnerVopCtx<'_>,
    attr: *const VAttr,
) -> VopOutcome<()> {
    use crate::core::file::{
        VATTR_ATIME, VATTR_CTIME, VATTR_GID, VATTR_MODE, VATTR_MTIME, VATTR_UID,
    };
    unsafe {
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata(ctx);

        // The vfs-core `VAttr.valid` mask is the source of truth.
        // Backends and posix handlers all stamp the same bits, so
        // chmod(path, 0) and utimes(path, ts=0) are now expressible
        // — the bit being set is what discriminates "apply this
        // field" from "leave unchanged", not the field's value.
        //
        // VATTR_CTIME is stripped before the wire — the backend
        // manages ctime as a side effect of the apply step rather
        // than as a caller-controlled field. The remaining core
        // bits are then explicitly translated to backend
        // SETATTR_MASK_* bits inside mutate_rpc.
        let valid = (*attr).valid;
        let core_mask = valid & (VATTR_MODE | VATTR_UID | VATTR_GID | VATTR_ATIME | VATTR_MTIME);
        let _ = VATTR_CTIME;
        let mask = mutate_rpc::setattr_mask_from_vattr(core_mask);
        if mask == 0 {
            return Ok(Ready(()));
        }

        let mode_arg = if (core_mask & VATTR_MODE) != 0 {
            (*attr).mode & 0o7777
        } else {
            0
        };
        let uid_arg = if (core_mask & VATTR_UID) != 0 {
            (*attr).uid
        } else {
            0
        };
        let gid_arg = if (core_mask & VATTR_GID) != 0 {
            (*attr).gid
        } else {
            0
        };
        let atime_arg = if (core_mask & VATTR_ATIME) != 0 {
            (*attr).atime
        } else {
            0
        };
        let mtime_arg = if (core_mask & VATTR_MTIME) != 0 {
            (*attr).mtime
        } else {
            0
        };

        let fs_id = (*ctx.mount).fs_instance_id;
        match mutate_rpc::saltyfs_ipc_setattr_issue(
            ctx.state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            mask,
            mode_arg,
            uid_arg,
            gid_arg,
            atime_arg,
            mtime_arg,
            0,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_access(
    ctx: &mut OwnerVopCtx<'_>,
    _mode: u32,
    _cred: *const VfsCred,
) -> VopOutcome<()> {
    // Permission validation is owned by the personality layer
    // (POSIX `access(2)` translates to the bundled mode + cred
    // and runs the checks against the cached attrs). The vop
    // here re-fetches authoritative attrs through the same async
    // stat path as `getattr`; the resume helper applies the
    // permission test.
    unsafe {
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata(ctx);
        let fs_id = (*ctx.mount).fs_instance_id;
        match rpc::saltyfs_ipc_stat_issue(
            ctx.state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_readlink(
    ctx: &mut OwnerVopCtx<'_>,
    _buf: *mut u8,
    _buf_len: usize,
    _cred: *const VfsCred,
) -> VopOutcome<usize> {
    unsafe {
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        if (*vdata).ftype != VT_LNK {
            return Err(VfsError::Inval);
        }
        let md = mdata(ctx);
        let fs_id = (*ctx.mount).fs_instance_id;
        match rpc::saltyfs_ipc_readlink_issue(
            ctx.state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_truncate(ctx: &mut OwnerVopCtx<'_>, new_size: u64) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        if (*vdata).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }
        let md = mdata(ctx);
        let fs_id = (*ctx.mount).fs_instance_id;
        match mutate_rpc::saltyfs_ipc_truncate_issue(
            ctx.state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            new_size,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_inactive(ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    unsafe {
        crate::owner::pager_rpc::release_mo_binding_for_vnode(ctx.state, ctx.handle);
        let vdata = vdata(ctx);
        if !vdata.is_null() {
            (*vdata).vnode_handle = VnodeHandle::INVALID;
            (*vdata).active = 0;
            super::pool::release_vdata(mdata(ctx), vdata);
        }
        Ok(Ready(()))
    }
}

// ---------------------------------------------------------------------------
// VopDataOps
// ---------------------------------------------------------------------------

pub(super) unsafe fn saltyfs_read(
    ctx: &VopDataCtx,
    offset: u64,
    _dst: *mut u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        if (*vdata).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }
        let md = mdata_d(ctx);

        let file_size = (*vdata).size;
        if offset >= file_size {
            return Ok(Ready(0));
        }
        let available = file_size - offset;
        let capped = if len > available { available } else { len };
        if capped == 0 {
            return Ok(Ready(0));
        }
        if !(*md).shm_active {
            return Err(VfsError::Io);
        }

        // SHM-only: every read rides through the per-mount
        // SHM ring slot at offset 0 (the resume helper copies
        // out before releasing the credit, so back-to-back
        // reads serialize through the credit machinery).
        let shm_bound = ::core::cmp::min((*md).shm_size, capped);
        let transfer = TransferDescriptor::shm(0, shm_bound);

        let Some(state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let mount = match state.mounts.get(ctx.mount_handle) {
            Some(m) => m,
            None => return Err(VfsError::Io),
        };
        let fs_id = mount.fs_instance_id;

        let vnode_key = state
            .vnodes
            .get(ctx.vnode_handle)
            .map(|v| v.key)
            .unwrap_or(crate::core::identity::VnodeKey::NONE);
        match rpc::saltyfs_ipc_read_issue(
            state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            offset,
            transfer,
            fs_id,
        ) {
            Some(handle) => {
                // Stamp the precise op kind + vnode key so the
                // fsync barrier collector can distinguish reads
                // from writes against this vnode.
                if let Some(op) = state.pending_ops.get_mut(handle) {
                    op.core.kind = crate::owner::op::OpKind::Read;
                    op.core.vnode_key = vnode_key;
                }
                Ok(Parked(handle))
            }
            None => Err(VfsError::Busy),
        }
    }
}

pub(super) unsafe fn saltyfs_write(
    ctx: &VopDataCtx,
    offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe { saltyfs_write_with_policy(ctx, offset, src, len, true) }
}

pub(super) unsafe fn saltyfs_writeback(
    ctx: &VopDataCtx,
    offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe { saltyfs_write_with_policy(ctx, offset, src, len, false) }
}

unsafe fn saltyfs_write_with_policy(
    ctx: &VopDataCtx,
    offset: u64,
    src: *const u8,
    len: u64,
    allow_mo_fallback: bool,
) -> VopOutcome<u64> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        if (*vdata).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }
        let md = mdata_d(ctx);
        if !(*md).shm_active {
            return Err(VfsError::Io);
        }
        if len == 0 {
            return Ok(Ready(0));
        }

        // Hybrid-1 size dispatch.
        //
        //   ≤ 160 B    →  inline regs[8..28] (no SHM, no MO)
        //   ≤ 4 KiB    →  SHM ring sub-region (one of 16 × 4 KiB)
        //                 with `MM_MO_CREATE`-backed MO fallback if
        //                 the ring is currently saturated
        //   > 4 KiB    →  per-RPC MemoryObject via `MM_MO_CREATE`
        //
        // INLINE: src bytes ride directly in the IPC buffer. The
        // descriptor pins `transfer.length`; mutate_rpc copies the
        // first `length` bytes from `src` into regs[8..28].
        //
        // SHM ring: `ring_alloc` returns the slot index. The sender
        // copies into `shm_vaddr + slot_idx * SALTYFS_RING_SLOT_BYTES`
        // and packs the byte offset into `transfer.offset`. The
        // completion router calls `MountData::ring_free` once the
        // daemon's reply lands.
        //
        // MO: `retype_mo_for_write` retypes a fresh anon MO out of
        // mmsrv's frame pool, briefly maps it into the VFS vspace
        // long enough to memcpy the source bytes, then unmaps and
        // returns the cap. This is valid for user writes, but explicit
        // MAP_SHARED writeback disables it: mmsrv is the requester waiting
        // for VFS completion, so writeback must not synchronously re-enter
        // mmsrv to allocate a transient transfer object.
        let inline_max = trona_protocol::vfs::backend::INLINE_TRANSFER_WIRE_MAX;
        let ring_slot_bytes = SALTYFS_RING_SLOT_BYTES;

        // Slot bookkeeping for cleanup-on-issue-failure. INLINE
        // path leaves both at 0.
        let mut leased_ring_slot: Option<u8> = None;
        let mut transient_mo_cap: u64 = 0;

        let descriptor: TransferDescriptor;
        let inline_payload_ptr: *const u8;

        if len <= inline_max {
            descriptor = TransferDescriptor::inline(len);
            inline_payload_ptr = src;
        } else if len <= ring_slot_bytes {
            // Fits in a single SHM ring slot.
            match (*md).ring_alloc() {
                Some(slot_idx) => {
                    let slot_offset = (slot_idx as u64) * SALTYFS_RING_SLOT_BYTES;
                    let dst_shm = ((*md).shm_vaddr + slot_offset) as *mut u8;
                    if dst_shm.is_null() {
                        (*md).ring_free(slot_idx);
                        return Err(VfsError::Io);
                    }
                    ::core::ptr::copy_nonoverlapping(src, dst_shm, len as usize);
                    descriptor = TransferDescriptor::shm(slot_offset, len);
                    inline_payload_ptr = ::core::ptr::null();
                    leased_ring_slot = Some(slot_idx);
                }
                None => {
                    if !allow_mo_fallback {
                        // Backend credit is temporarily exhausted. The pager
                        // writeback barrier will keep the page dirty and retry
                        // after the reactor observes more backend progress.
                        return Err(VfsError::Busy);
                    }
                    // Ring saturated — fall through to MO transfer for normal
                    // user writes, where a synchronous mmsrv allocation does
                    // not form a writeback completion cycle.
                    match retype_mo_for_write(src, len) {
                        Some(cap) => {
                            descriptor = TransferDescriptor::mo(len);
                            inline_payload_ptr = ::core::ptr::null();
                            transient_mo_cap = cap;
                        }
                        None => return Err(VfsError::Busy),
                    }
                }
            }
        } else {
            if !allow_mo_fallback {
                return Err(VfsError::Busy);
            }
            match retype_mo_for_write(src, len) {
                Some(cap) => {
                    descriptor = TransferDescriptor::mo(len);
                    inline_payload_ptr = ::core::ptr::null();
                    transient_mo_cap = cap;
                }
                None => return Err(VfsError::Busy),
            }
        }

        let Some(state) = ctx.state_mut() else {
            // mo_cap / ring_slot allocated above need teardown.
            if let Some(idx) = leased_ring_slot {
                (*md).ring_free(idx);
            }
            if transient_mo_cap != 0 {
                trona_runtime::core::slot_alloc::delete_and_free(transient_mo_cap);
            }
            return Err(VfsError::Io);
        };
        let mount = match state.mounts.get(ctx.mount_handle) {
            Some(m) => m,
            None => {
                if let Some(idx) = leased_ring_slot {
                    (*md).ring_free(idx);
                }
                if transient_mo_cap != 0 {
                    trona_runtime::core::slot_alloc::delete_and_free(transient_mo_cap);
                }
                return Err(VfsError::Io);
            }
        };
        let fs_id = mount.fs_instance_id;

        let vnode_key = state
            .vnodes
            .get(ctx.vnode_handle)
            .map(|v| v.key)
            .unwrap_or(crate::core::identity::VnodeKey::NONE);
        match mutate_rpc::saltyfs_ipc_write_issue(
            state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            offset,
            descriptor,
            inline_payload_ptr,
            transient_mo_cap,
            fs_id,
        ) {
            Some(handle) => {
                let mut tx_id = crate::owner::pending::TxId::INVALID;
                if let Some(op) = state.pending_ops.get_mut(handle) {
                    op.core.kind = crate::owner::op::OpKind::Write;
                    op.core.vnode_key = vnode_key;
                    tx_id = op.core.tx_id;
                }
                if tx_id.is_valid() {
                    state.ordering.begin_unordered(
                        crate::owner::ordering::OrderingKey::VnodeMutate(vnode_key),
                        tx_id,
                    );
                }
                Ok(Parked(handle))
            }
            None => {
                // Issue failure: roll back any per-RPC state we
                // committed before discovering credit / arena
                // exhaustion. mutate_rpc handles the MO cap
                // teardown internally when send fails after the
                // cap is staged, but the pre-send `None` arm
                // here is reached when reservation fails — the
                // cap is still ours.
                if let Some(idx) = leased_ring_slot {
                    (*md).ring_free(idx);
                }
                if transient_mo_cap != 0 {
                    trona_runtime::core::slot_alloc::delete_and_free(transient_mo_cap);
                }
                Err(VfsError::Busy)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MO retype helper for Hybrid-1 BACKEND_WRITE
// ---------------------------------------------------------------------------

/// Retype a fresh per-RPC MemoryObject sized to `len`, briefly map
/// it into the VFS vspace, copy `src[0..len]` into it, and unmap.
/// Returns the MO cap on success — caller owns the cap and is
/// responsible for releasing it (via `mutate_rpc`'s post-send
/// teardown). Returns `None` on any kernel- or mmsrv-level
/// failure; in that case any partially allocated state has been
/// released before return.
unsafe fn retype_mo_for_write(src: *const u8, len: u64) -> Option<u64> {
    unsafe {
        if len == 0 {
            return None;
        }
        let aligned_len = (len + uapi::KERNITE_PAGE_BYTES - 1) & !(uapi::KERNITE_PAGE_BYTES - 1);
        let ctx = trona_runtime::current_ipc_ctx();
        if ctx.is_null() {
            return None;
        }
        let mmsrv_ep = trona_runtime::client::caps::mmsrv_ep().addr();

        // Reserve a CNode slot the kernel will deposit the new MO
        // cap into. mmsrv replies with the cap installed at the
        // same slot index we armed for the receive.
        let recv =
            trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"saltyfs frontend mo_create");
        // Arm a single-slot receive path so the reply cap lands
        // at `recv`. The reset path on the next outer recv
        // is handled by the owner-loop's normal cycle.
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            ctx,
            uapi::KERNITE_CAP_SELF_CSPACE as u64,
            recv.addr(),
            0,
        );

        // 1. MM_MO_CREATE(len, flags=0) → caps[0] = mo_cap.
        let mut req = TronaMsg::zeroed();
        req.label = trona_protocol::mm::MM_MO_CREATE;
        req.length = 2;
        req.regs[0] = aligned_len;
        req.regs[1] = 0;
        let mut reply = TronaMsg::zeroed();
        let err = trona_kernel::ipc::mp_call_ctx(
            ctx,
            mmsrv_ep,
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != 0 {
            // call failed: no cap landed; `recv` (OwnedSlot, empty) Drop frees it.
            return None;
        }
        // The reply landed the MO cap at `recv`; hand it off raw — it is dup'd
        // for the map and delete'd on the teardown paths below.
        let mo_cap = recv.into_raw();

        // 2. MM_MMAP(kind=MO, hint=0 (auto-place), size=aligned_len,
        //    prot=R+W, flags=0, mo_offset=0; caps[0]=mo_cap)
        //    → mapped_va. The vfs caller's vspace ends up holding
        //    a temporary mapping that we release immediately
        //    after the memcpy.
        // mmsrv's MM_MMAP moves the staged cap into its own region
        // mapping, so dup `mo_cap` for the map and keep the original to
        // hand back for the caller's BACKEND_WRITE forward.
        let map_cap = match trona_runtime::core::slot_alloc::dup_for_transfer(
            trona_runtime::core::slot_alloc::resolved_cap_ref(mo_cap),
        ) {
            Some(c) => c,
            None => {
                trona_runtime::core::slot_alloc::delete_and_free(mo_cap);
                return None;
            }
        };
        trona_kernel::ipc::set_send_cap_ctx(ctx, 0, map_cap.slot());
        let mut req = TronaMsg::zeroed();
        req.label = trona_protocol::mm::MM_MMAP;
        req.length = 6;
        req.regs[0] = trona_protocol::mm::MMAP_KIND_MO;
        req.regs[1] = 0; // hint — let mmsrv pick.
        req.regs[2] = aligned_len;
        req.regs[3] = 0x3; // PROT_READ | PROT_WRITE
        req.regs[4] = 0; // FLAG_FIXED clear
        req.regs[5] = 0; // mo_offset
        let mut reply = TronaMsg::zeroed();
        let err = trona_kernel::ipc::mp_call_ctx(
            ctx,
            mmsrv_ep,
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        // Reclaim the dup's temp slot after the send; `mo_cap` (the
        // original) stays live for the caller's BACKEND_WRITE forward.
        drop(map_cap);
        if err != 0 || reply.label != 0 {
            trona_runtime::core::slot_alloc::delete_and_free(mo_cap);
            return None;
        }
        let mapped_va = reply.regs[0];

        // 3. memcpy(src → mapped_va, len).
        ::core::ptr::copy_nonoverlapping(src, mapped_va as *mut u8, len as usize);

        // 4. MM_MUNMAP(mapped_va, aligned_len). Failure here is a
        //    VA-window leak in the vfs vspace, not a correctness
        //    failure for the BACKEND_WRITE that follows; the cap
        //    is still ours to forward.
        let mut req = TronaMsg::zeroed();
        req.label = trona_protocol::mm::MM_MUNMAP;
        req.length = 2;
        req.regs[0] = mapped_va;
        req.regs[1] = aligned_len;
        let mut reply = TronaMsg::zeroed();
        let _ = trona_kernel::ipc::mp_call_ctx(
            ctx,
            mmsrv_ep,
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );

        // 5. Cap is sender's; caller forwards it on BACKEND_WRITE
        //    and drops it post-send. Return ownership.
        Some(mo_cap)
    }
}

pub(super) unsafe fn saltyfs_fsync(ctx: &VopDataCtx) -> VopOutcome<()> {
    // Issue `BACKEND_FSYNC` against the daemon. Fsync ordering
    // against in-flight WRITE / writeback PendingOps lives on the
    // dispatch layer (PendingOp dependency graph, PRED_BARRIER
    // edges); the dispatcher attaches predecessor edges *after*
    // this returns Parked, so the wire issue happens once each
    // predecessor has cleared its barrier counter.
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let ino = (*vdata).remote_ino;
        let md = mdata_d(ctx);
        if md.is_null() {
            return Err(VfsError::Io);
        }
        let Some(state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let mount = match state.mounts.get(ctx.mount_handle) {
            Some(m) => m,
            None => return Err(VfsError::Io),
        };
        let fs_id = mount.fs_instance_id;
        let seq = (*vdata).remote_seq;
        let vnode_key = state
            .vnodes
            .get(ctx.vnode_handle)
            .map(|v| v.key)
            .unwrap_or(crate::core::identity::VnodeKey::NONE);
        match super::mutate_rpc::saltyfs_ipc_fsync_issue(state, md, ino, seq, 0, fs_id, vnode_key) {
            Some(handle) => {
                if let Some(op) = state.pending_ops.get_mut(handle) {
                    op.core.kind = crate::owner::op::OpKind::Sync;
                    op.core.vnode_key = vnode_key;
                }
                Ok(Parked(handle))
            }
            None => Err(VfsError::Busy),
        }
    }
}

pub(super) unsafe fn saltyfs_readdir(
    ctx: &VopDataCtx,
    cookie: *mut u64,
    _emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() || (*vdata).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata_d(ctx);
        if !(*md).shm_active {
            return Err(VfsError::Io);
        }

        let start = *cookie;
        let open_handle = ctx.open_object.ok_or(VfsError::Io)?;
        let Some(state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let mount = match state.mounts.get(ctx.mount_handle) {
            Some(m) => m,
            None => return Err(VfsError::Io),
        };
        let fs_id = mount.fs_instance_id;

        match rpc::saltyfs_ipc_readdir_issue(
            state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            start,
            0,
            (*md).shm_size,
            fs_id,
            open_handle,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Busy),
        }
    }
}

pub(super) unsafe fn saltyfs_getxattr(
    ctx: &VopDataCtx,
    name: *const u8,
    name_len: u8,
    _buf: *mut u8,
    buf_len: usize,
) -> VopOutcome<usize> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);
        let Some(state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let mount = match state.mounts.get(ctx.mount_handle) {
            Some(m) => m,
            None => return Err(VfsError::Io),
        };
        let fs_id = mount.fs_instance_id;

        match xattr_rpc::saltyfs_ipc_getxattr_issue(
            state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            name,
            name_len,
            buf_len,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_setxattr(
    ctx: &VopDataCtx,
    name: *const u8,
    name_len: u8,
    value: *const u8,
    value_len: usize,
    flags: u32,
) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);
        let Some(state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let mount = match state.mounts.get(ctx.mount_handle) {
            Some(m) => m,
            None => return Err(VfsError::Io),
        };
        let fs_id = mount.fs_instance_id;

        match xattr_rpc::saltyfs_ipc_setxattr_issue(
            state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            name,
            name_len,
            value,
            value_len,
            flags,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_listxattr(
    ctx: &VopDataCtx,
    _buf: *mut u8,
    buf_len: usize,
) -> VopOutcome<usize> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);
        let Some(state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let mount = match state.mounts.get(ctx.mount_handle) {
            Some(m) => m,
            None => return Err(VfsError::Io),
        };
        let fs_id = mount.fs_instance_id;

        match xattr_rpc::saltyfs_ipc_listxattr_issue(
            state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            buf_len,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_removexattr(
    ctx: &VopDataCtx,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata_d(ctx);
        if vdata.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);
        let Some(state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let mount = match state.mounts.get(ctx.mount_handle) {
            Some(m) => m,
            None => return Err(VfsError::Io),
        };
        let fs_id = mount.fs_instance_id;

        match xattr_rpc::saltyfs_ipc_removexattr_issue(
            state,
            md,
            (*vdata).remote_ino,
            (*vdata).remote_seq,
            name,
            name_len,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Again),
        }
    }
}

pub(super) unsafe fn saltyfs_ioctl(
    _ctx: &VopDataCtx,
    _cmd: u32,
    _arg: u64,
) -> crate::core::vop::IoctlResult {
    // SaltyFS does not vend per-vnode ioctls. Personality-specific
    // ioctls (POSIX `FIOCLEX`, `FIONREAD`) are handled by the
    // dispatch layer before reaching the backend.
    Err(VfsError::NotSup)
}

pub(super) unsafe fn saltyfs_mmap_get_page(
    _ctx: &VopDataCtx,
    _page_idx: u64,
    _write: bool,
    _out_cap: *mut u64,
) -> VopOutcome<()> {
    // File-backed mmap routing goes through the mmsrv pager
    // callback (`pager_rpc::handle_pager_read`) instead of the
    // per-vnode mmap_get_page path. Backends that want to expose
    // pages directly (devfs framebuffer) override this in their
    // own VopVector.
    Err(VfsError::NotSup)
}

pub(super) unsafe fn saltyfs_statfs(_ctx: &VopDataCtx, _out: *mut VStatfs) -> VopOutcome<()> {
    // Mount-level statfs lives on `VfsOps::statfs` (see
    // `vfsops::saltyfs_statfs`). The per-vnode hook is reserved
    // for backends that want statfs to follow vnode identity
    // (NFS automounts) — saltyfs uses the mount-level entry.
    Err(VfsError::NotSup)
}

// ---------------------------------------------------------------------------
// Cred extraction helper
// ---------------------------------------------------------------------------

#[inline]
unsafe fn creds_or_root(cred: *const VfsCred) -> (u32, u32) {
    if cred.is_null() {
        (0, 0)
    } else {
        unsafe { ((*cred).euid, (*cred).egid) }
    }
}
