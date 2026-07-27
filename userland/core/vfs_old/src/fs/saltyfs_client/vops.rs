// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS client VopVector implementation — vnode-level operations.
//!
//! Each function maps to a `VopMetaOps` or `VopDataOps` slot and issues the
//! corresponding SaltyFS IPC call via the `rpc` / `mutate_rpc` / `xattr_rpc`
//! helpers.

use trona_kernel::core_types::TronaMsg;
use trona_protocol::posix::{INLINE_TRANSFER_THRESHOLD, TransferDescriptor};
use uapi::*;

use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::VfsError;
use crate::vfs_core::file::{VAttr, VStatfs};
use crate::vfs_core::outcome::{Parked, Ready, VopOutcome};
use crate::vfs_core::vnode::{VT_DIR, VT_LNK, VT_REG, VnodeHandle};
use crate::vfs_core::vop::ReaddirEmit;
use crate::vfs_core::vop_context::{OwnerVopCtx, WorkerIoCtx};

use super::mutate_rpc;
use super::pool;
use super::readdir;
use super::rpc;
use super::types::{SaltyfsMountData, SaltyfsVnodeData};
use super::xattr_rpc;

// =========================================================================
// Helpers
// =========================================================================

#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut SaltyfsVnodeData {
    ctx.data as *mut SaltyfsVnodeData
}

#[inline]
unsafe fn mdata(ctx: &OwnerVopCtx<'_>) -> *mut SaltyfsMountData {
    ctx.mount_data as *mut SaltyfsMountData
}

#[inline]
unsafe fn vdata_d(ctx: &WorkerIoCtx) -> *mut SaltyfsVnodeData {
    ctx.data as *mut SaltyfsVnodeData
}

#[inline]
unsafe fn mdata_d(ctx: &WorkerIoCtx) -> *mut SaltyfsMountData {
    ctx.mount_data as *mut SaltyfsMountData
}

#[inline]
fn mode_to_vtype(mode: u32) -> u8 {
    match mode & S_IFMT_L {
        S_IFDIR_L => VT_DIR,
        S_IFLNK_L => VT_LNK,
        _ => VT_REG,
    }
}

#[inline]
fn dir_type_to_vtype(dir_type: u8) -> u8 {
    match dir_type {
        1 => VT_REG,
        4 => VT_DIR,
        7 => VT_LNK,
        _ => VT_REG,
    }
}

/// Map a TRONA_* IPC error label to a VfsError.
#[inline]
pub(super) fn trona_to_vfs_error(label: u64) -> VfsError {
    match label {
        TRONA_NOT_FOUND => VfsError::NotFound,
        TRONA_NOT_DIRECTORY => VfsError::NotDir,
        TRONA_IS_DIRECTORY => VfsError::IsDir,
        TRONA_ALREADY_EXISTS => VfsError::Exists,
        TRONA_INVALID_ARGUMENT => VfsError::Inval,
        TRONA_INSUFFICIENT_RIGHTS => VfsError::Perm,
        TRONA_OUT_OF_MEMORY => VfsError::NoSpace,
        TRONA_BUSY => VfsError::Busy,
        TRONA_READONLY => VfsError::ReadOnly,
        TRONA_TOO_LARGE => VfsError::TooLarge,
        _ => VfsError::Io,
    }
}

/// Allocate a vnode from the arena and populate it from stat data.
///
/// First checks if a vdata already exists for the remote inode (cache hit).
/// If so, updates cached attributes and allocates a new arena vnode pointing
/// to the existing vdata. Otherwise allocates both vdata and arena vnode.
///
/// `parent_ino` is cached on the returned child's vdata so the `readdir`
/// helper can synthesise `..` without a dedicated `BACKEND_GETPARENT`
/// RPC. Pass `0` when the parent is unknown (e.g. the `..` fallback
/// path in `saltyfs_lookup` where the child's own ctx is the only
/// available context); the reader falls back to echoing the child's
/// own ino for POSIX-compliant self-loop behaviour.
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
        let md_ptr = mdata(ctx);
        let mh = ctx.mount_handle;
        let fs_id = (*ctx.mount).fs_instance_id;
        let ops_ptr = (*ctx.vnode).ops;
        match alloc_saltyfs_vnode_via_state(
            &mut *ctx.state,
            md_ptr,
            mh,
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
        ) {
            Ok(vh) => Ok(Ready(vh)),
            Err(e) => Err(e),
        }
    }
}

/// Completion-path entry point for allocating a SaltyFS vnode without
/// a live `OwnerVopCtx`. Mirrors `alloc_saltyfs_vnode`'s contract but
/// takes the primitives directly so the async-mutation completion
/// router (which holds `&mut VfsState` but no ctx) can materialise
/// the new child vnode. The arena-alloc / resolve-cache side effects
/// go through `VfsState` directly — no trampoline plumbing required.
pub(crate) unsafe fn alloc_saltyfs_vnode_from_state(
    state: &mut crate::owner::VfsState,
    mount_handle: crate::vfs_core::mount::MountHandle,
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

/// Shared inner allocator used by both the OwnerVopCtx wrapper
/// (`alloc_saltyfs_vnode`) and the state-based wrapper
/// (`alloc_saltyfs_vnode_from_state`). Operates on primitives so
/// the arena-alloc and resolve-cache side effects go through
/// `VfsState` directly instead of the trampoline indirection.
unsafe fn alloc_saltyfs_vnode_via_state(
    state: &mut crate::owner::VfsState,
    md: *mut SaltyfsMountData,
    mount_handle: crate::vfs_core::mount::MountHandle,
    fs_instance_id: crate::vfs_core::identity::FsInstanceId,
    ops: *const crate::vfs_core::vop::VopVector,
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
        // Check if vdata already cached for this remote inode
        let existing_vd = pool::find_vdata_by_node(md, remote_ino, remote_seq);
        if !existing_vd.is_null() {
            // Update cached attributes
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

            let vh = state.vnodes.alloc().ok_or(VfsError::NoSpace)?;
            let vp = state.vnodes.raw_ptr(vh).ok_or(VfsError::NoSpace)?;
            (*vp).id = remote_ino;
            (*vp).backend_seq = remote_seq;
            (*vp).vtype = (*existing_vd).ftype;
            (*vp).data = existing_vd as *mut u8;
            (*vp).nlink = nlink;
            (*vp).mount.set(fs_instance_id, mount_handle);
            (*vp).fs_instance_id = fs_instance_id;
            (*vp).ops = ops;
            if remote_ino == (*md).root_ino {
                (*vp).flags |= crate::vfs_core::vnode::VN_ROOT;
                (*vp).pin();
            }
            let key = (*vp).vnode_key();
            if let Some(covering_fs_id) = covering_fs_id_for_key_via_state(state, key) {
                (*vp).flags |= crate::vfs_core::vnode::VN_COVERED;
                (*vp)
                    .covered_by
                    .set_id_only(covering_fs_id, crate::vfs_core::mount::MountHandle::INVALID);
                (*vp).pin();
            }
            (*existing_vd).vnode_handle = vh;
            state.install_resolve_cache((*vp).vnode_key(), vh);
            return Ok(vh);
        }

        // Allocate new vdata
        let vd = pool::alloc_vdata(md);
        if vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        let ftype = if dir_type != 0 {
            dir_type_to_vtype(dir_type)
        } else {
            mode_to_vtype(mode)
        };
        (*vd).active = 1;
        (*vd).ftype = ftype;
        (*vd).mode = mode;
        (*vd).remote_ino = remote_ino;
        (*vd).parent_ino = parent_ino;
        (*vd).remote_seq = remote_seq;
        (*vd).size = size;
        (*vd).nlink = nlink;
        (*vd).uid = uid;
        (*vd).gid = gid;
        (*vd).mtime = mtime;
        (*vd).blocks = blocks;

        // Allocate arena vnode
        let vh = match state.vnodes.alloc() {
            Some(h) => h,
            None => {
                (*vd).active = 0;
                return Err(VfsError::NoSpace);
            }
        };
        let vp = match state.vnodes.raw_ptr(vh) {
            Some(p) => p,
            None => {
                (*vd).active = 0;
                return Err(VfsError::NoSpace);
            }
        };
        (*vp).id = remote_ino;
        (*vp).backend_seq = remote_seq;
        (*vp).vtype = ftype;
        (*vp).data = vd as *mut u8;
        (*vp).nlink = nlink;
        (*vp).mount.set(fs_instance_id, mount_handle);
        (*vp).fs_instance_id = fs_instance_id;
        (*vp).ops = ops;
        (*vd).vnode_handle = vh;
        state.install_resolve_cache((*vp).vnode_key(), vh);

        Ok(vh)
    }
}

/// State-based equivalent of
/// `mount_ctl::`ctx.covering_fs_id_for_key`. Walks the mount
/// arena looking for a mount whose `covered` field matches `key` and
/// returns the covering mount's `fs_instance_id`. Used by
/// `alloc_saltyfs_vnode_via_state` to restore `VN_COVERED` on a vnode
/// that was reallocated into an arena slot previously holding a
/// mountpoint.
unsafe fn covering_fs_id_for_key_via_state(
    state: &crate::owner::VfsState,
    key: crate::vfs_core::identity::VnodeKey,
) -> Option<crate::vfs_core::identity::FsInstanceId> {
    if !key.is_valid() {
        return None;
    }
    let mut found = None;
    state.mounts.for_each_active(|_mh, mp| {
        if mp.covered.id() == key {
            found = Some(mp.fs_instance_id);
            return false;
        }
        true
    });
    found
}

// =========================================================================
// MetaOps — owner-thread metadata operations
// =========================================================================

pub(super) unsafe fn saltyfs_lookup(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }

        let md = mdata(ctx);

        // Handle "."
        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }

        // Handle ".."
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            // Async path: `BACKEND_LOOKUP` with `CORRELATION_F_LOOKUP_PARENT`
            // collapses the former two-RPC (getparent + stat) sequence into a
            // single correlated round-trip; the namei walker's
            // `apply_lookup_reply` handles the completion without any
            // special casing.
            let fs_id = (*ctx.mount).fs_instance_id;
            {
                let state: &mut crate::owner::VfsState = &mut *ctx.state;
                if let Some(handle) = rpc::saltyfs_ipc_lookup_parent_issue(
                    state,
                    md,
                    (*dvd).remote_ino,
                    (*dvd).remote_seq,
                    fs_id,
                ) {
                    return Ok(crate::vfs_core::outcome::VopControl::Parked(handle));
                }
            }
            // Sync fallback — early bootstrap or arena exhaustion.
            // Consults the cached `parent_ino` on the child's vdata
            // (populated on lookup-time vnode materialisation) and
            // follows up with a synchronous stat to obtain the parent
            // attrs needed to allocate the vnode. `parent_ino == 0`
            // means the parent is unknown (root / orphan); POSIX
            // allows self-loops so we echo the child's own handle.
            let parent = (*dvd).parent_ino;
            if parent == 0 || parent == (*dvd).remote_ino {
                return Ok(Ready(ctx.handle));
            }
            match rpc::saltyfs_ipc_stat(md, parent) {
                Some((size, mode, nlink, mtime, blocks, uid, gid, seq)) => {
                    // The parent's own parent (grandparent) is not in
                    // scope here; pass 0 so a subsequent `..` walk has
                    // to go through the async path to populate it.
                    alloc_saltyfs_vnode(
                        ctx, 0, parent, seq, mode, size, nlink, mtime, uid, gid, 0, blocks,
                    )
                }
                None => Ok(Ready(VnodeHandle::INVALID)),
            }
        } else {
            // Async issue path. The namei walk's `NameiStep` resume
            // picks up the reply and threads it through
            // `apply_lookup_reply` to install the child vnode.
            let fs_id = (*ctx.mount).fs_instance_id;
            {
                let state: &mut crate::owner::VfsState = &mut *ctx.state;
                if let Some(handle) = rpc::saltyfs_ipc_lookup_issue(
                    state,
                    md,
                    (*dvd).remote_ino,
                    (*dvd).remote_seq,
                    name,
                    name_len,
                    fs_id,
                ) {
                    return Ok(crate::vfs_core::outcome::VopControl::Parked(handle));
                }
            }
            // Sync fallback — early-boot callers, arena exhaustion, or
            // trampoline not armed. Preserves prior behaviour so the
            // existing sync namei stack continues to work.
            match rpc::saltyfs_ipc_lookup(md, (*dvd).remote_ino, name, name_len) {
                Ok(Some((
                    child_ino,
                    child_seq,
                    mode,
                    size,
                    nlink,
                    mtime,
                    uid,
                    gid,
                    dir_type,
                    blocks,
                ))) => alloc_saltyfs_vnode(
                    ctx,
                    (*dvd).remote_ino,
                    child_ino,
                    child_seq,
                    mode,
                    size,
                    nlink,
                    mtime,
                    uid,
                    gid,
                    dir_type,
                    blocks,
                ),
                Ok(None) => Ok(Ready(VnodeHandle::INVALID)),
                Err(label) => Err(trona_to_vfs_error(label)),
            }
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
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let (uid, gid) = if !cred.is_null() {
            ((*cred).euid, (*cred).egid)
        } else {
            (0, 0)
        };

        // Async path: the dispatcher (handle_openat O_CREAT /
        // handle_mkfifoat through socket lifecycle etc.) that calls
        // `meta.create` must be prepared for a `Parked` return — the
        // completion router (`resume_fill_final_op_child_reply`)
        // materialises the new vnode and either opens an fd
        // (openat) or emits an ack (mkfifo / socket).
        //
        // Credit / pending-arena exhaustion surfaces `WouldBlock`
        // rather than falling through to `ipc::call_ctx` below,
        // because the sync path would violate the per-session
        // inflight-credit cap and block the VFS owner loop until the
        // backend replies. The sync branch is reserved strictly for
        // the "trampoline not armed" case (early boot / pivot_root).
        {
            let state: &mut crate::owner::VfsState = &mut *ctx.state;
            let fs_id = (*ctx.mount).fs_instance_id;
            return match mutate_rpc::saltyfs_ipc_create_issue(
                state,
                md,
                (*dvd).remote_ino,
                (*dvd).remote_seq,
                name,
                name_len,
                mode,
                uid,
                gid,
                fs_id,
            ) {
                Some(handle) => Ok(crate::vfs_core::outcome::VopControl::Parked(handle)),
                None => Err(VfsError::WouldBlock),
            };
        }

        // Sync fallback — trampoline unavailable (early boot only).
        // The two-RPC pattern (create + stat) is preserved so early-
        // bootstrap callers that cannot handle `Parked` still make
        // forward progress.
        let new_ino = mutate_rpc::saltyfs_ipc_create(
            md,
            (*dvd).remote_ino,
            name,
            name_len,
            mode,
            uid,
            gid,
            (*md).v2_protocol,
        );
        if new_ino == 0 {
            return Err(VfsError::Io);
        }
        match rpc::saltyfs_ipc_stat(md, new_ino) {
            Some((size, mode, nlink, mtime, blocks, uid, gid, seq)) => alloc_saltyfs_vnode(
                ctx,
                (*dvd).remote_ino,
                new_ino,
                seq,
                mode,
                size,
                nlink,
                mtime,
                uid,
                gid,
                0,
                blocks,
            ),
            None => Err(VfsError::Io),
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
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let (uid, gid) = if !cred.is_null() {
            ((*cred).euid, (*cred).egid)
        } else {
            (0, 0)
        };

        // Async path — sync fallback is restricted to the early-
        // boot "trampoline not armed" case. See `saltyfs_create` for
        // the rationale (credit cap + owner-loop blocking).
        {
            let state: &mut crate::owner::VfsState = &mut *ctx.state;
            let fs_id = (*ctx.mount).fs_instance_id;
            return match mutate_rpc::saltyfs_ipc_mkdir_issue_async(
                state,
                md,
                (*dvd).remote_ino,
                (*dvd).remote_seq,
                name,
                name_len,
                mode,
                uid,
                gid,
                fs_id,
            ) {
                Some(handle) => Ok(crate::vfs_core::outcome::VopControl::Parked(handle)),
                None => Err(VfsError::WouldBlock),
            };
        }

        // Sync fallback (early boot).
        let (label, new_ino) = mutate_rpc::saltyfs_ipc_mkdir(
            md,
            (*dvd).remote_ino,
            name,
            name_len,
            mode,
            uid,
            gid,
            (*md).v2_protocol,
        );
        if label == TRONA_ALREADY_EXISTS {
            return match rpc::saltyfs_ipc_lookup(md, (*dvd).remote_ino, name, name_len) {
                Ok(Some((
                    child_ino,
                    child_seq,
                    mode,
                    size,
                    nlink,
                    mtime,
                    uid,
                    gid,
                    dir_type,
                    blocks,
                ))) => alloc_saltyfs_vnode(
                    ctx,
                    (*dvd).remote_ino,
                    child_ino,
                    child_seq,
                    mode,
                    size,
                    nlink,
                    mtime,
                    uid,
                    gid,
                    dir_type,
                    blocks,
                ),
                Ok(None) => Err(VfsError::Io),
                Err(lookup_label) => Err(trona_to_vfs_error(lookup_label)),
            };
        }
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        if new_ino == 0 {
            return Err(VfsError::Io);
        }
        match rpc::saltyfs_ipc_stat(md, new_ino) {
            Some((size, mode, nlink, mtime, blocks, uid, gid, seq)) => alloc_saltyfs_vnode(
                ctx,
                (*dvd).remote_ino,
                new_ino,
                seq,
                mode,
                size,
                nlink,
                mtime,
                uid,
                gid,
                0,
                blocks,
            ),
            None => Err(VfsError::Io),
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
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);
        let (uid, gid) = if !cred.is_null() {
            ((*cred).euid, (*cred).egid)
        } else {
            (0, 0)
        };

        // Async path — sync fallback is restricted to the early-
        // boot "trampoline not armed" case. See `saltyfs_create`.
        // Oversized inputs (name > 56, target > 64) fail the async
        // issue helper's bounds check and fall through to the sync
        // path (same wire cap, synchronous `call_ctx`) — a rare
        // edge case that does not exercise the credit machinery.
        {
            let state: &mut crate::owner::VfsState = &mut *ctx.state;
            let fs_id = (*ctx.mount).fs_instance_id;
            if (name_len as usize) <= 56 && (target_len as usize) <= 64 {
                return match mutate_rpc::saltyfs_ipc_symlink_issue_async(
                    state,
                    md,
                    (*dvd).remote_ino,
                    (*dvd).remote_seq,
                    name,
                    name_len,
                    target,
                    target_len,
                    uid,
                    gid,
                    fs_id,
                ) {
                    Some(handle) => Ok(crate::vfs_core::outcome::VopControl::Parked(handle)),
                    None => Err(VfsError::WouldBlock),
                };
            }
            // Oversized: fall through to sync path below.
        }

        // Sync fallback (early boot, or oversized name/target).
        let (label, new_ino) = mutate_rpc::saltyfs_ipc_symlink(
            md,
            (*dvd).remote_ino,
            name,
            name_len,
            target,
            target_len,
            uid,
            gid,
            (*md).v2_protocol,
        );
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        if new_ino == 0 {
            return Err(VfsError::Io);
        }
        match rpc::saltyfs_ipc_stat(md, new_ino) {
            Some((size, mode, nlink, mtime, blocks, uid, gid, seq)) => alloc_saltyfs_vnode(
                ctx,
                (*dvd).remote_ino,
                new_ino,
                seq,
                mode,
                size,
                nlink,
                mtime,
                uid,
                gid,
                0,
                blocks,
            ),
            None => Err(VfsError::Io),
        }
    }
}

pub(super) unsafe fn saltyfs_unlink(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);

        // Async path — sync fallback is restricted to the early-
        // boot "trampoline not armed" case. Credit/arena exhaustion
        // surfaces `WouldBlock`.
        {
            let state: &mut crate::owner::VfsState = &mut *ctx.state;
            let fs_id = (*ctx.mount).fs_instance_id;
            return match mutate_rpc::saltyfs_ipc_unlink_issue(
                state,
                md,
                (*dvd).remote_ino,
                (*dvd).remote_seq,
                name,
                name_len,
                fs_id,
            ) {
                Some(handle) => Ok(crate::vfs_core::outcome::VopControl::Parked(handle)),
                None => Err(VfsError::WouldBlock),
            };
        }

        let label = mutate_rpc::saltyfs_ipc_unlink(md, (*dvd).remote_ino, name, name_len);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        Ok(Ready(()))
    }
}

pub(super) unsafe fn saltyfs_rmdir(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata(ctx);

        // Async path — sync fallback only on "trampoline not
        // armed"; credit/arena exhaustion surfaces `WouldBlock`.
        {
            let state: &mut crate::owner::VfsState = &mut *ctx.state;
            let fs_id = (*ctx.mount).fs_instance_id;
            return match mutate_rpc::saltyfs_ipc_rmdir_issue(
                state,
                md,
                (*dvd).remote_ino,
                (*dvd).remote_seq,
                name,
                name_len,
                fs_id,
            ) {
                Some(handle) => Ok(crate::vfs_core::outcome::VopControl::Parked(handle)),
                None => Err(VfsError::WouldBlock),
            };
        }

        let label = mutate_rpc::saltyfs_ipc_rmdir(md, (*dvd).remote_ino, name, name_len);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        Ok(Ready(()))
    }
}

pub(super) unsafe fn saltyfs_link(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
    target: VnodeHandle,
) -> VopOutcome<()> {
    unsafe {
        let dvd = vdata(ctx);
        if dvd.is_null() || (*dvd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let target_vp = ctx.resolve_vnode(target).ok_or(VfsError::Inval)?;
        // Defensive mount-identity check. The dispatch layer
        // (handle_linkat) already rejects cross-mount link with
        // `CrossDevice`, but the VOP must not reinterpret foreign
        // vnode data if it somehow gets here — the `data as *mut
        // SaltyfsVnodeData` cast below is UB for any other backend.
        if (*target_vp).fs_instance_id != (*ctx.mount).fs_instance_id {
            return Err(VfsError::CrossDevice);
        }
        let tvd = (*target_vp).data as *mut SaltyfsVnodeData;
        if tvd.is_null() {
            return Err(VfsError::Inval);
        }
        let md = mdata(ctx);

        // Async path — plain-ack completion routed via
        // FinalOpAckLink. Sync fallback is restricted to the early-
        // boot "trampoline not armed" case; credit/arena exhaustion
        // surfaces `WouldBlock`.
        {
            let state: &mut crate::owner::VfsState = &mut *ctx.state;
            let fs_id = (*ctx.mount).fs_instance_id;
            return match mutate_rpc::saltyfs_ipc_link_issue_async(
                state,
                md,
                (*tvd).remote_ino,
                (*tvd).remote_seq,
                (*dvd).remote_ino,
                (*dvd).remote_seq,
                name,
                name_len,
                fs_id,
            ) {
                Some(handle) => Ok(crate::vfs_core::outcome::VopControl::Parked(handle)),
                None => Err(VfsError::WouldBlock),
            };
        }

        // Sync fallback (early boot).
        let label =
            mutate_rpc::saltyfs_ipc_link(md, (*tvd).remote_ino, (*dvd).remote_ino, name, name_len);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        Ok(Ready(()))
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
        // Cross-mount rename is rejected by the dispatch layer. The guard
        // here defends against callers that bypass the dispatch path so a
        // foreign-backend `SaltyfsVnodeData` cast never fires.
        let new_vnode = ctx.resolve_vnode(new_dir).ok_or(VfsError::Inval)?;
        if (*ctx.mount).fs_instance_id != (*new_vnode).fs_instance_id {
            return Err(VfsError::CrossDevice);
        }
        let old_dvd = ctx.data as *mut SaltyfsVnodeData;
        let new_dvd = (*new_vnode).data as *mut SaltyfsVnodeData;
        if old_dvd.is_null() || new_dvd.is_null() {
            return Err(VfsError::Inval);
        }
        let md = mdata(ctx);
        let fs_id = (*ctx.mount).fs_instance_id;
        let old_remote_ino = (*old_dvd).remote_ino;
        let old_remote_seq = (*old_dvd).remote_seq;
        let new_remote_ino = (*new_dvd).remote_ino;
        let new_remote_seq = (*new_dvd).remote_seq;

        // Async path — plain-ack completion routed via FinalOpAckRename.
        return match mutate_rpc::saltyfs_ipc_rename_issue_async(
            &mut *ctx.state,
            md,
            old_remote_ino,
            old_remote_seq,
            old_name,
            old_len,
            new_remote_ino,
            new_remote_seq,
            new_name,
            new_len,
            fs_id,
        ) {
            Some(handle) => Ok(crate::vfs_core::outcome::VopControl::Parked(handle)),
            None => Err(VfsError::WouldBlock),
        };
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
    attr: *mut VAttr,
) -> VopOutcome<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata(ctx);

        // Prefer the async issue+park path: reserves a `PendingOp`
        // tagged with `SaltyfsOpKind::Stat`, fires `BACKEND_STAT` via
        // `send_ctx`, and returns `Parked(handle)` so the fileops
        // caller (e.g. `fileops::stat::handle_fstat_owned`) can stamp
        // `FsResume::FillStatReply` on top. The completion router
        // (`saltyfs_completion`) parses the reply back into a `VAttr`
        // and invokes `resume_fill_stat_reply`.
        //
        // Sync fallback covers early-boot callers (pivot_root,
        // namesrv warm-up) where `ctx.state` returns
        // `None`. Arena exhaustion also falls back so the caller
        // unblocks instead of surfacing `TRONA_BUSY` as a stat
        // failure.
        {
            let state: &mut crate::owner::VfsState = &mut *ctx.state;
            let fs_id = (*ctx.mount).fs_instance_id;
            if let Some(handle) =
                rpc::saltyfs_ipc_stat_issue(state, md, (*vd).remote_ino, (*vd).remote_seq, fs_id)
            {
                return Ok(crate::vfs_core::outcome::VopControl::Parked(handle));
            }
        }
        saltyfs_getattr_sync(md, vd, attr)
    }
}

/// Synchronous getattr path — populates the vnode cache + `VAttr`
/// via a blocking `BACKEND_STAT` RPC. Kept reachable for bootstrap
/// callers that run before the owner loop arms its trampoline
/// (`pivot_root`, namesrv warm-up) and for the rare arena-exhausted
/// fallback. Regular runtime callers take the async `_issue` path
/// in `saltyfs_getattr`.
unsafe fn saltyfs_getattr_sync(
    md: *mut super::types::SaltyfsMountData,
    vd: *mut super::types::SaltyfsVnodeData,
    attr: *mut VAttr,
) -> VopOutcome<()> {
    unsafe {
        match rpc::saltyfs_ipc_stat_sync(md, (*vd).remote_ino) {
            Some((size, mode, nlink, mtime, blocks, uid, gid, seq)) => {
                (*vd).size = size;
                (*vd).mode = mode;
                (*vd).nlink = nlink;
                (*vd).mtime = mtime;
                (*vd).blocks = blocks;
                (*vd).uid = uid;
                (*vd).gid = gid;
                (*vd).remote_seq = seq;

                (*attr).size = size;
                (*attr).blocks = blocks;
                (*attr).mode = mode;
                (*attr).uid = uid;
                (*attr).gid = gid;
                (*attr).nlink = nlink;
                (*attr).mtime = mtime;
                (*attr).atime = 0;
                (*attr).ctime = 0;
                (*attr).btime = 0;
                (*attr).dev_id = 0;
                (*attr).rdev = 0;
                Ok(Ready(()))
            }
            None => Err(VfsError::Io),
        }
    }
}

pub(super) unsafe fn saltyfs_setattr(
    ctx: &mut OwnerVopCtx<'_>,
    attr: *const VAttr,
) -> VopOutcome<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata(ctx);

        // Build the bundled mask from the VAttr sentinel values. The
        // caller (fileops::at_attr) zero-initialises every field it
        // doesn't want to touch except uid/gid which use `u32::MAX`
        // as the sentinel.
        let mut mask: u32 = 0;
        if (*attr).mode != 0 {
            mask |= trona_protocol::SETATTR_MASK_MODE;
        }
        if (*attr).uid != u32::MAX {
            mask |= trona_protocol::SETATTR_MASK_UID;
        }
        if (*attr).gid != u32::MAX {
            mask |= trona_protocol::SETATTR_MASK_GID;
        }
        if (*attr).atime != 0 {
            mask |= trona_protocol::SETATTR_MASK_ATIME;
        }
        if (*attr).mtime != 0 {
            mask |= trona_protocol::SETATTR_MASK_MTIME;
        }
        // `size` is deliberately excluded from the setattr mask — the
        // `truncate` VOP owns size mutations and serialises against
        // the extent tree on its own path; callers should reach this
        // VOP only with non-size attribute changes.

        if mask == 0 {
            return Ok(Ready(()));
        }

        let mode_arg = if (mask & trona_protocol::SETATTR_MASK_MODE) != 0 {
            (*attr).mode & 0o7777
        } else {
            0
        };
        let uid_arg = if (mask & trona_protocol::SETATTR_MASK_UID) != 0 {
            (*attr).uid
        } else {
            0
        };
        let gid_arg = if (mask & trona_protocol::SETATTR_MASK_GID) != 0 {
            (*attr).gid
        } else {
            0
        };
        let atime_arg = if (mask & trona_protocol::SETATTR_MASK_ATIME) != 0 {
            (*attr).atime
        } else {
            0
        };
        let mtime_arg = if (mask & trona_protocol::SETATTR_MASK_MTIME) != 0 {
            (*attr).mtime
        } else {
            0
        };

        // Async path — sync fallback only on "trampoline not
        // armed"; credit/arena exhaustion surfaces `WouldBlock`.
        {
            let state: &mut crate::owner::VfsState = &mut *ctx.state;
            let fs_id = (*ctx.mount).fs_instance_id;
            return match mutate_rpc::saltyfs_ipc_setattr_issue(
                state,
                md,
                (*vd).remote_ino,
                (*vd).remote_seq,
                mask,
                mode_arg,
                uid_arg,
                gid_arg,
                atime_arg,
                mtime_arg,
                0,
                fs_id,
            ) {
                Some(handle) => Ok(crate::vfs_core::outcome::VopControl::Parked(handle)),
                None => Err(VfsError::WouldBlock),
            };
        }

        // Sync fallback (early boot). Falls back to the per-field
        // `chmod`/`chown` opcodes so a backend that hasn't adopted
        // `BACKEND_SETATTR` yet still gets covered.
        if (mask & trona_protocol::SETATTR_MASK_MODE) != 0 {
            let label = mutate_rpc::saltyfs_ipc_chmod(md, (*vd).remote_ino, mode_arg);
            if label != TRONA_OK {
                return Err(trona_to_vfs_error(label));
            }
            (*vd).mode = ((*vd).mode & S_IFMT_L) | mode_arg;
        }
        let chown_uid = if (mask & trona_protocol::SETATTR_MASK_UID) != 0 {
            uid_arg
        } else {
            u32::MAX
        };
        let chown_gid = if (mask & trona_protocol::SETATTR_MASK_GID) != 0 {
            gid_arg
        } else {
            u32::MAX
        };
        if chown_uid != u32::MAX || chown_gid != u32::MAX {
            let label = mutate_rpc::saltyfs_ipc_chown(md, (*vd).remote_ino, chown_uid, chown_gid);
            if label != TRONA_OK {
                return Err(trona_to_vfs_error(label));
            }
            if chown_uid != u32::MAX {
                (*vd).uid = chown_uid;
            }
            if chown_gid != u32::MAX {
                (*vd).gid = chown_gid;
            }
        }
        Ok(Ready(()))
    }
}

pub(super) unsafe fn saltyfs_access(
    ctx: &mut OwnerVopCtx<'_>,
    mode: u32,
    cred: *const VfsCred,
) -> VopOutcome<()> {
    unsafe {
        if cred.is_null() {
            return Ok(Ready(()));
        }
        if (*cred).euid == 0 {
            return Ok(Ready(()));
        }
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }

        let file_mode = (*vd).mode;
        let uid = (*vd).uid;
        let gid = (*vd).gid;

        let shift = if (*cred).euid == uid {
            6
        } else if (*cred).in_group(gid) {
            3
        } else {
            0
        };

        let perm = (file_mode >> shift) & 0o7;

        if (mode & 1) != 0 && (perm & 4) == 0 {
            return Err(VfsError::Perm);
        }
        if (mode & 2) != 0 && (perm & 2) == 0 {
            return Err(VfsError::Perm);
        }
        if (mode & 4) != 0 && (perm & 1) == 0 {
            return Err(VfsError::Perm);
        }
        Ok(Ready(()))
    }
}

pub(super) unsafe fn saltyfs_readlink(
    ctx: &mut OwnerVopCtx<'_>,
    buf: *mut u8,
    buf_len: usize,
    _cred: *const VfsCred,
) -> VopOutcome<usize> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        if (*vd).ftype != VT_LNK {
            return Err(VfsError::Inval);
        }
        let md = mdata(ctx);

        // Async issue path. The completion router parses the
        // target bytes out of the reply and forwards them to
        // `fileops::attr::resume_fill_readlink_reply`. Sync
        // fallback (early boot / arena exhaustion) preserves the
        // previous behaviour.
        {
            let state: &mut crate::owner::VfsState = &mut *ctx.state;
            let fs_id = (*ctx.mount).fs_instance_id;
            if let Some(handle) = rpc::saltyfs_ipc_readlink_issue(
                state,
                md,
                (*vd).remote_ino,
                (*vd).remote_seq,
                fs_id,
            ) {
                return Ok(crate::vfs_core::outcome::VopControl::Parked(handle));
            }
        }
        let len = rpc::saltyfs_ipc_readlink_sync(md, (*vd).remote_ino, buf, buf_len);
        if len == 0 {
            return Err(VfsError::Io);
        }
        Ok(Ready(len))
    }
}

pub(super) unsafe fn saltyfs_truncate(ctx: &mut OwnerVopCtx<'_>, new_size: u64) -> VopOutcome<()> {
    unsafe {
        let vd = vdata(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata(ctx);

        // Async path — sync fallback only on "trampoline not
        // armed"; credit/arena exhaustion surfaces `WouldBlock`.
        {
            let state: &mut crate::owner::VfsState = &mut *ctx.state;
            let fs_id = (*ctx.mount).fs_instance_id;
            return match mutate_rpc::saltyfs_ipc_truncate_issue(
                state,
                md,
                (*vd).remote_ino,
                (*vd).remote_seq,
                new_size,
                fs_id,
            ) {
                Some(handle) => Ok(crate::vfs_core::outcome::VopControl::Parked(handle)),
                None => Err(VfsError::WouldBlock),
            };
        }

        let label = mutate_rpc::saltyfs_ipc_truncate(md, (*vd).remote_ino, new_size);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        (*vd).size = new_size;
        Ok(Ready(()))
    }
}

pub(super) unsafe fn saltyfs_inactive(ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    unsafe {
        let vd = vdata(ctx);
        if !vd.is_null() {
            // Keep the per-inode cache entry alive across close/reopen cycles.
            // Only the arena vnode is being reclaimed here; the cached remote
            // inode metadata remains the canonical lookup/vget record.
            (*vd).vnode_handle = VnodeHandle::INVALID;
        }
        (*ctx.vnode).data = core::ptr::null_mut();
        Ok(Ready(()))
    }
}

// =========================================================================
// DataOps — async-capable data operations
// =========================================================================

pub(super) unsafe fn saltyfs_read(
    ctx: &WorkerIoCtx,
    offset: u64,
    _dst: *mut u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        if (*vd).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }
        let md = mdata_d(ctx);

        let file_size = (*vd).size;
        if offset >= file_size {
            return Ok(Ready(0));
        }
        let available = file_size - offset;
        let capped = if len > available { available } else { len };
        if capped == 0 {
            return Ok(Ready(0));
        }

        let transfer = if capped > INLINE_TRANSFER_THRESHOLD && (*md).shm_active {
            let shm_bound = core::cmp::min((*md).shm_size, capped);
            TransferDescriptor::shm(0, shm_bound)
        } else {
            let inline_bound = if capped > INLINE_TRANSFER_THRESHOLD {
                INLINE_TRANSFER_THRESHOLD
            } else {
                capped
            };
            TransferDescriptor::inline(inline_bound)
        };

        let Some(state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let mount = match state.mounts.get(ctx.mount_handle) {
            Some(m) => m,
            None => return Err(VfsError::Io),
        };
        let fs_id = mount.fs_instance_id;

        match rpc::saltyfs_ipc_read_issue(
            state,
            md,
            (*vd).remote_ino,
            (*vd).remote_seq,
            offset,
            transfer,
            fs_id,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Busy),
        }
    }
}

pub(super) unsafe fn saltyfs_write(
    ctx: &WorkerIoCtx,
    offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        if (*vd).ftype == VT_DIR {
            return Err(VfsError::IsDir);
        }

        let md = mdata_d(ctx);

        let (descriptor, payload) = if len > INLINE_TRANSFER_THRESHOLD && (*md).shm_active {
            let shm_limit = (*md).shm_size;
            let write_count = if len > shm_limit { shm_limit } else { len };
            let dst_shm = (*md).shm_vaddr as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst_shm, write_count as usize);
            (TransferDescriptor::shm(0, write_count), core::ptr::null())
        } else {
            let write_count = if len > INLINE_TRANSFER_THRESHOLD {
                INLINE_TRANSFER_THRESHOLD
            } else {
                len
            };
            (TransferDescriptor::inline(write_count), src)
        };

        let (label, written) =
            mutate_rpc::saltyfs_ipc_write(md, (*vd).remote_ino, offset, descriptor, payload);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        let end = offset + written;
        if end > (*vd).size {
            (*vd).size = end;
        }
        Ok(Ready(written))
    }
}

pub(super) unsafe fn saltyfs_fsync(_ctx: &WorkerIoCtx) -> VopOutcome<()> {
    Ok(Ready(()))
}

pub(super) unsafe fn saltyfs_readdir(
    ctx: &WorkerIoCtx,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() || (*vd).ftype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        let md = mdata_d(ctx);

        let start = *cookie;

        // Cache-drain fast path. The resume handler stashes the
        // backend's response in `OpenObject.readdir_batch` so a single
        // `BACKEND_READDIR` completion amortises across many POSIX
        // `readdir` calls. Each call pops one entry from SHM.
        if let Some(open_h) = ctx.open_object {
            if let Some(state) = ctx.state_mut() {
                if let Some(obj) = state.open_objects.get(open_h) {
                    let batch = obj.readdir_batch;
                    if batch.has_pending() {
                        let shm_vaddr = (*md).shm_vaddr;
                        if shm_vaddr == 0 {
                            return Err(VfsError::Io);
                        }
                        let idx = batch.entries_consumed as usize;
                        let base = (shm_vaddr as usize
                            + batch.shm_offset as usize
                            + idx * super::readdir::READDIR_ENTRY_BYTES)
                            as *const u8;
                        let entry_ino = core::ptr::read_unaligned(base as *const u64);
                        let entry_mode = core::ptr::read_unaligned(base.add(32) as *const u32);
                        let entry_dtype_raw = *base.add(48);
                        let mut name_len = *base.add(49) as usize;
                        if name_len > super::readdir::READDIR_NAME_MAX {
                            name_len = super::readdir::READDIR_NAME_MAX;
                        }
                        let name_ptr = base.add(52);
                        let d_type = if entry_dtype_raw != 0 {
                            entry_dtype_raw
                        } else {
                            super::readdir::mode_to_dtype(entry_mode)
                        };
                        let attr = VAttr::zeroed();
                        let _ = emit(entry_ino, name_ptr, name_len as u8, d_type, &attr);
                        // Advance cache state. When drained, reset so
                        // the next call drops into the async-issue
                        // path below, and release SHM ownership so
                        // a concurrent readdir on a different
                        // OpenObject can proceed.
                        let mut fully_drained = false;
                        if let Some(obj_mut) = state.open_objects.get_mut(open_h) {
                            obj_mut.readdir_batch.entries_consumed += 1;
                            if obj_mut.readdir_batch.entries_consumed
                                >= obj_mut.readdir_batch.entries_total
                            {
                                // Cache fully drained; remember backend's next
                                // cursor for the follow-up fetch.
                                let next = obj_mut.readdir_batch.cookie;
                                obj_mut.readdir_batch =
                                    crate::server::open_object::ReaddirBatch::zeroed();
                                obj_mut.readdir_batch.cookie = next;
                                fully_drained = true;
                            }
                        }
                        if fully_drained {
                            super::deferred::release_readdir_shm_if_owner(md, open_h);
                            // Poke the deferred-issue drain so any
                            // parked readdir on a different
                            // OpenObject can take over immediately.
                            if let Some(mount) = state.mounts.get(ctx.mount_handle) {
                                let fs_id = mount.fs_instance_id;
                                super::deferred::drain_deferred_issues(state, fs_id);
                            }
                        }
                        *cookie = start + 1;
                        return Ok(Ready(()));
                    }
                }
            }
        }

        // ".": synthesised inline, never a backend RPC.
        let attr = VAttr::zeroed();
        if start == 0 {
            if !emit((*vd).remote_ino, b".".as_ptr(), 1, 4, &attr) {
                *cookie = 1;
                return Ok(Ready(()));
            }
        }
        // "..": resolved from the cached `parent_ino` stamped at
        // lookup time. `0` means the parent is unknown (root /
        // orphan / first-ever access without a preceding lookup
        // walk); POSIX permits self-loops, so echo the child's own
        // ino in that case. The dedicated `BACKEND_GETPARENT`
        // opcode is retired — any caller needing a fresh parent
        // identity goes through `BACKEND_LOOKUP` +
        // `CORRELATION_F_LOOKUP_PARENT` via the namei walker.
        if start <= 1 {
            let parent = if (*vd).parent_ino != 0 {
                (*vd).parent_ino
            } else {
                (*vd).remote_ino
            };
            if !emit(parent, b"..".as_ptr(), 2, 4, &attr) {
                *cookie = 2;
                return Ok(Ready(()));
            }
        }

        // Backend readdir batch fetch. Look up the backend's next
        // cursor from the OpenObject cache (seeded at 0 on fresh
        // open, updated on each drain), reserve credit + pending,
        // issue BACKEND_READDIR async, and return Parked so the
        // owner loop can continue.
        let Some(open_h) = ctx.open_object else {
            return Err(VfsError::Io);
        };
        let Some(state) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let backend_cookie = state
            .open_objects
            .get(open_h)
            .map(|o| o.readdir_batch.cookie)
            .unwrap_or(0);
        let mount = match state.mounts.get(ctx.mount_handle) {
            Some(m) => m,
            None => return Err(VfsError::Io),
        };
        let fs_id = mount.fs_instance_id;

        // Stream the batch into the start of VFS↔saltyfs SHM. One
        // live batch per mount — concurrent readdirs against the same
        // mount serialise at this boundary (matches the pre-async
        // sync path's exclusivity model). If another OpenObject still
        // holds the SHM region, surface `WouldBlock` so the generic
        // fileops path parks via `DeferArgs::Readdir` on the session
        // waiter ring instead of returning a transient `EBUSY` to the
        // client.
        let shm_bound = if (*md).shm_active {
            (*md).shm_size
        } else {
            return Err(VfsError::NotSupported);
        };

        if !super::deferred::acquire_readdir_shm(state, md, open_h) {
            return Err(VfsError::WouldBlock);
        }

        match rpc::saltyfs_ipc_readdir_issue(
            state,
            md,
            (*vd).remote_ino,
            (*vd).remote_seq,
            backend_cookie,
            0,
            shm_bound,
            fs_id,
            open_h,
        ) {
            Some(handle) => Ok(Parked(handle)),
            None => Err(VfsError::Busy),
        }
    }
}

pub(super) unsafe fn saltyfs_getxattr(
    ctx: &WorkerIoCtx,
    name: *const u8,
    name_len: u8,
    buf: *mut u8,
    buf_len: usize,
) -> VopOutcome<usize> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);
        if !(*md).shm_active {
            return Err(VfsError::NotSupported);
        }

        // Async issue path. The SHM claim + memcpy happens inside the
        // issue helper once the `TxId` has been allocated — serialises
        // against concurrent xattr / readdir ops. The completion router
        // copies the reply value back out of SHM and hands it to
        // `fileops::attr::resume_fill_xattr_get_reply`.
        if let Some(state) = ctx.state_mut() {
            let mh = ctx.mount_handle;
            let fs_id = match state.mounts.get(mh) {
                Some(m) => m.fs_instance_id,
                None => return Err(VfsError::Io),
            };
            // Async-only when the trampoline is armed. `ShmBusy` is
            // dispatch-level parkable; `Failed` (credit / pending
            // arena / SHM not active) surfaces `WouldBlock` rather
            // than falling through to the sync path below, which
            // would block the VFS owner loop and violate the
            // per-session credit cap.
            return match xattr_rpc::saltyfs_ipc_getxattr_issue(
                state,
                md,
                (*vd).remote_ino,
                (*vd).remote_seq,
                name,
                name_len,
                fs_id,
            ) {
                xattr_rpc::XattrIssueOutcome::Issued(handle) => {
                    Ok(crate::vfs_core::outcome::VopControl::Parked(handle))
                }
                xattr_rpc::XattrIssueOutcome::ShmBusy | xattr_rpc::XattrIssueOutcome::Failed => {
                    Err(VfsError::WouldBlock)
                }
            };
        }

        // Synchronous fallback (trampoline unavailable, e.g. early
        // boot). Stage name into SHM then run the blocking RPC.
        let shm_base = (*md).shm_vaddr as *mut u8;
        for i in 0..name_len as usize {
            *shm_base.add(i) = *name.add(i);
        }
        match xattr_rpc::saltyfs_ipc_getxattr_sync(
            md,
            (*vd).remote_ino,
            0,
            buf_len as u64,
            name_len as usize,
        ) {
            Ok(value_len) => {
                if buf_len > 0 && value_len > 0 {
                    let copy = if value_len < buf_len {
                        value_len
                    } else {
                        buf_len
                    };
                    let src = shm_base;
                    for i in 0..copy {
                        *buf.add(i) = *src.add(i);
                    }
                }
                Ok(Ready(value_len))
            }
            Err(TRONA_NOT_FOUND) => Err(VfsError::NotFound),
            Err(TRONA_OUT_OF_RANGE) => Err(VfsError::TooLarge),
            Err(_) => Err(VfsError::Io),
        }
    }
}

pub(super) unsafe fn saltyfs_setxattr(
    ctx: &WorkerIoCtx,
    name: *const u8,
    name_len: u8,
    value: *const u8,
    value_len: usize,
    flags: u32,
) -> VopOutcome<()> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);
        if !(*md).shm_active {
            return Err(VfsError::NotSupported);
        }
        if value_len > u16::MAX as usize {
            return Err(VfsError::TooLarge);
        }
        if value_len > crate::owner::pending::WALK_NAME_MAX {
            // Value larger than the inline replay budget — would be
            // lost on a park/replay round. Surface `TooLarge` so the
            // client sees a deterministic error rather than silent
            // data corruption. Matches the POSIX dispatch cap of 224
            // bytes already enforced at
            // `owner::dispatch::dispatch_setxattr`.
            return Err(VfsError::TooLarge);
        }

        if let Some(state) = ctx.state_mut() {
            let fs_id = match state.mounts.get(ctx.mount_handle) {
                Some(m) => m.fs_instance_id,
                None => return Err(VfsError::Io),
            };
            // Async-only when trampoline armed. Both ShmBusy and
            // Failed surface WouldBlock — falling through to the
            // sync path would block the VFS owner loop.
            return match xattr_rpc::saltyfs_ipc_setxattr_issue(
                state,
                md,
                (*vd).remote_ino,
                (*vd).remote_seq,
                name,
                name_len,
                value,
                value_len as u16,
                flags,
                fs_id,
            ) {
                xattr_rpc::XattrIssueOutcome::Issued(handle) => {
                    Ok(crate::vfs_core::outcome::VopControl::Parked(handle))
                }
                xattr_rpc::XattrIssueOutcome::ShmBusy | xattr_rpc::XattrIssueOutcome::Failed => {
                    Err(VfsError::WouldBlock)
                }
            };
        }

        // Sync fallback — stage name||value then block.
        let shm_base = (*md).shm_vaddr as *mut u8;
        for i in 0..name_len as usize {
            *shm_base.add(i) = *name.add(i);
        }
        for i in 0..value_len {
            *shm_base.add(name_len as usize + i) = *value.add(i);
        }
        let label = xattr_rpc::saltyfs_ipc_setxattr(
            md,
            (*vd).remote_ino,
            0,
            value_len as u64,
            name_len as usize,
            flags,
        );
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        Ok(Ready(()))
    }
}

pub(super) unsafe fn saltyfs_listxattr(
    ctx: &WorkerIoCtx,
    buf: *mut u8,
    buf_len: usize,
) -> VopOutcome<usize> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);
        if !(*md).shm_active {
            return Err(VfsError::NotSupported);
        }

        if let Some(state) = ctx.state_mut() {
            let mh = ctx.mount_handle;
            let fs_id = match state.mounts.get(mh) {
                Some(m) => m.fs_instance_id,
                None => return Err(VfsError::Io),
            };
            match xattr_rpc::saltyfs_ipc_listxattr_issue(
                state,
                md,
                (*vd).remote_ino,
                (*vd).remote_seq,
                buf_len as u64,
                fs_id,
            ) {
                xattr_rpc::XattrIssueOutcome::Issued(handle) => {
                    return Ok(crate::vfs_core::outcome::VopControl::Parked(handle));
                }
                xattr_rpc::XattrIssueOutcome::ShmBusy | xattr_rpc::XattrIssueOutcome::Failed => {
                    // Both surface WouldBlock; falling through to
                    // the sync path below would block the VFS owner
                    // loop.
                    return Err(VfsError::WouldBlock);
                }
            }
        }

        match xattr_rpc::saltyfs_ipc_listxattr(md, (*vd).remote_ino, 0, buf_len as u64) {
            Ok((bytes_needed, bytes_written)) => {
                if buf_len > 0 && bytes_written > 0 {
                    let src = (*md).shm_vaddr as *const u8;
                    let copy = if bytes_written < buf_len {
                        bytes_written
                    } else {
                        buf_len
                    };
                    for i in 0..copy {
                        *buf.add(i) = *src.add(i);
                    }
                }
                Ok(Ready(bytes_needed))
            }
            Err(TRONA_NOT_FOUND) => Ok(Ready(0)),
            Err(_) => Err(VfsError::Io),
        }
    }
}

pub(super) unsafe fn saltyfs_removexattr(
    ctx: &WorkerIoCtx,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<()> {
    unsafe {
        let vd = vdata_d(ctx);
        if vd.is_null() {
            return Err(VfsError::Io);
        }
        let md = mdata_d(ctx);

        if let Some(state) = ctx.state_mut() {
            let fs_id = match state.mounts.get(ctx.mount_handle) {
                Some(m) => m.fs_instance_id,
                None => return Err(VfsError::Io),
            };
            return match xattr_rpc::saltyfs_ipc_removexattr_issue(
                state,
                md,
                (*vd).remote_ino,
                (*vd).remote_seq,
                name,
                name_len,
                fs_id,
            ) {
                Some(handle) => Ok(crate::vfs_core::outcome::VopControl::Parked(handle)),
                None => Err(VfsError::WouldBlock),
            };
        }

        let label = xattr_rpc::saltyfs_ipc_removexattr(md, (*vd).remote_ino, name, name_len);
        if label != TRONA_OK {
            return Err(trona_to_vfs_error(label));
        }
        Ok(Ready(()))
    }
}

pub(super) unsafe fn saltyfs_statfs(ctx: &WorkerIoCtx, out: *mut VStatfs) -> VopOutcome<()> {
    unsafe {
        let md = mdata_d(ctx);
        match rpc::saltyfs_ipc_getinfo(md) {
            Some((total_blocks, used_blocks, block_size)) => {
                (*out).bsize = block_size;
                (*out).blocks = total_blocks;
                (*out).bfree = total_blocks.saturating_sub(used_blocks);
                (*out).bavail = (*out).bfree;
                (*out).files = 0;
                (*out).ffree = 0;
                let ft = &mut (*out).fs_type;
                ft[..7].copy_from_slice(b"saltyfs");
                (*out).flags = 0;
                (*out).name_max = 255;
                Ok(Ready(()))
            }
            None => Err(VfsError::Io),
        }
    }
}
