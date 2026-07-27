// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS client VfsOps implementation — filesystem-level operations.
//!
//! Handles mount (namesrv lookup, BACKEND_OPEN_SESSION IPC, SHM setup),
//! unmount, root, vget, statfs, and sync.

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_protocol::posix::*;
use trona_runtime::core::server_consts::*;
use uapi::*;

use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::outcome::{VopControl::Parked, VopOutcome};
use crate::vfs_core::vnode::{VN_ROOT, VT_DIR, VnodeHandle};
use crate::vfs_core::vop_context::OwnerMountCtx;
use trona_protocol::posix::BackendNodeId;

use super::pool;
use super::rpc;
use super::types::{SaltyfsMountData, SaltyfsVnodeData};

// =========================================================================
// Mount (async — parks on BACKEND_OPEN_SESSION)
// =========================================================================

/// Initialize a SaltyFS mount.
///
/// `source` is the IPC endpoint capability slot for the SaltyFS server.
/// If `source == 0`, the implementation performs a namesrv lookup for
/// "saltyfs".
///
/// The fast half (mount-data allocation, endpoint resolution) runs
/// synchronously; the slow half (`BACKEND_OPEN_SESSION` RPC, session
/// slot registration, pool init, SHM setup, root-vnode materialisation)
/// parks on the backend completion and resumes in
/// [`super::completion`] under the `FsResume::MountReady` arm, which
/// forwards into [`saltyfs_mount_finalize`] below.
pub(super) unsafe fn saltyfs_mount(
    ctx: &mut OwnerMountCtx<'_>,
    source: u64,
    _opts_ptr: *const u8,
    _opts_len: u8,
    can_park: bool,
) -> VopOutcome<()> {
    unsafe {
        // Allocate SaltyfsMountData (sync — fast).
        let alloc_size = core::mem::size_of::<SaltyfsMountData>();
        let alloc_pages = (alloc_size + 4095) / 4096;
        let md_raw = crate::server::mem::map_anon((alloc_pages * 4096) as u64);
        if md_raw.is_null() || md_raw == usize::MAX as *mut u8 {
            return Err(VfsError::NoSpace);
        }
        core::ptr::write_bytes(md_raw, 0, alloc_pages * 4096);

        let md = md_raw as *mut SaltyfsMountData;
        *md = SaltyfsMountData::zeroed();
        (*ctx.mount).data = md as *mut u8;

        // Resolve the SaltyFS server endpoint.
        let fs_cap = if source != 0 {
            source
        } else {
            match resolve_saltyfs_endpoint() {
                Ok(c) => c,
                Err(e) => return Err(e),
            }
        };
        (*md).fs_cap = fs_cap;

        let fs_instance_id = (*ctx.mount).fs_instance_id;
        let mh = ctx.mount_handle;
        let state: &mut crate::owner::VfsState = &mut *ctx.state;

        if can_park {
            // Caller can route the backend's `BACKEND_OPEN_SESSION`
            // completion through its own resume machinery (VFS_MOUNT
            // IPC dispatch path). Park on the backend reply; the
            // completion router (`saltyfs_completion`) will drive
            // `saltyfs_mount_finalize` via `FsResume::MountReady`.
            let (handle, tx_id) = match state.reserve_fs_pending(
                fs_instance_id,
                super::op_kind::SaltyfsOpKind::OpenSession { mh, fs_cap }.pack(),
            ) {
                Some(pair) => pair,
                None => return Err(VfsError::NoSpace),
            };

            let mut req = TronaMsg::zeroed();
            req.label = BACKEND_OPEN_SESSION;
            req.length = 1;
            req.regs[0] = 0;
            rpc::stamp_saltyfs_async_request(md, &mut req, BACKEND_OPEN_SESSION, tx_id, 0, 0);

            // Stage VFS's backend_callback EP as the OPEN_SESSION's single
            // extra cap. SaltyFS's dispatch arm captures this slot into
            // its `BACKEND_CALLBACK_EP` and uses it to push correlated
            // async completions back. Must land before `send_ctx`;
            // `set_send_cap_ctx` stages caps in the IPC buffer and the
            // next `send_ctx` / `call_ctx` emits them.
            if !crate::backend::prepare_backend_callback_endpoint(state) {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[VFS] saltyfs backend_callback EP unavailable\n");
                });
                state.pending_ops.release(handle);
                unmap_mount_data_ptr((*ctx.mount).data);
                (*ctx.mount).data = core::ptr::null_mut();
                return Err(VfsError::Io);
            }
            ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, crate::backend::backend_callback_ep());

            let send_err = ipc::send_ctx(crate::ipc_ctx(), fs_cap, &raw const req);
            if send_err != 0 {
                // IPC send failed (receiver cap revoked, kernel out of
                // reply slots, etc). Completion will never arrive, so
                // tear down the reservation synchronously before the
                // mount caller's reply slot is quietly lost.
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[VFS] saltyfs BACKEND_OPEN_SESSION send failed err=");
                    _lb.hex(send_err as u64);
                    _lb.str(b"\n");
                });
                state.pending_ops.release(handle);
                unmap_mount_data_ptr((*ctx.mount).data);
                (*ctx.mount).data = core::ptr::null_mut();
                return Err(VfsError::Io);
            }
            return Ok(Parked(handle));
        }

        // Sync fallback: the caller cannot drive a backend completion
        // (bootstrap or `late_mount` contexts where the owner receive
        // loop is not available). Issue a blocking `call_ctx` and run
        // finalize inline. The request is NOT correlation-stamped;
        // saltyfs replies through the request's reply cap (the
        // existing V1 behaviour).
        let mut mnt_req = TronaMsg::zeroed();
        mnt_req.label = BACKEND_OPEN_SESSION;
        mnt_req.length = 1;
        mnt_req.regs[0] = 0;

        // Stage the backend_callback EP same as the async path. SaltyFS's
        // dispatch arm captures it identically regardless of sync vs async
        // caller, keeping the two paths symmetric on the saltyfs side.
        // In early-boot/late-mount contexts the caller will not drive
        // async completions, but saltyfs still stores the cap for any
        // subsequent async traffic in this session.
        if !crate::backend::prepare_backend_callback_endpoint(state) {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] saltyfs backend_callback EP unavailable (sync path)\n");
            });
            return Err(VfsError::Io);
        }
        ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, crate::backend::backend_callback_ep());

        let mut mnt_reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            fs_cap,
            &raw const mnt_req,
            &raw mut mnt_reply,
        );
        if err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] saltyfs sync mount IPC error=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            return Err(VfsError::Io);
        }
        match saltyfs_mount_finalize(state, mh, fs_cap, &mnt_reply) {
            Ok(()) => Ok(crate::vfs_core::outcome::VopControl::Ready(())),
            Err(e) => Err(e),
        }
    }
}

/// Unmap the `SaltyfsMountData` anonymous allocation attached to a
/// partially-initialised mount slot. Idempotent — safe to call on a null
/// pointer. Pairs with the `map_anon` in [`saltyfs_mount`] and the
/// failure-cleanup path in [`saltyfs_mount_teardown`].
unsafe fn unmap_mount_data_ptr(md_raw: *mut u8) {
    unsafe {
        if md_raw.is_null() {
            return;
        }
        let alloc_size = core::mem::size_of::<SaltyfsMountData>();
        let alloc_pages = (alloc_size + 4095) / 4096;
        crate::server::mem::unmap(md_raw, (alloc_pages * 4096) as u64);
    }
}

/// Tear down a mount slot that is in the partial / failed state
/// between `saltyfs_mount` returning `Parked` and the
/// [`saltyfs_mount_finalize`] completion having succeeded. Frees the
/// backend session slot (idempotent — no-op if never registered),
/// unmaps the mount-data region, and releases the arena slot. Does
/// NOT call `BACKEND_CLOSE_SESSION`: the backend either never saw a
/// successful session open, or its session is being torn down anyway.
pub(crate) unsafe fn saltyfs_mount_teardown(
    state: &mut crate::owner::VfsState,
    mh: crate::vfs_core::mount::MountHandle,
) {
    unsafe {
        let (md_raw, fs_id) = match state.mounts.get_mut(mh) {
            Some(mp) => {
                let data = mp.data;
                let fs = mp.fs_instance_id;
                mp.data = core::ptr::null_mut();
                mp.root_vnode = VnodeHandle::INVALID;
                (data, fs)
            }
            None => (
                core::ptr::null_mut(),
                crate::vfs_core::identity::FsInstanceId::INVALID,
            ),
        };

        if fs_id.is_valid() {
            state.free_backend_session_slot(fs_id);
        }

        if !md_raw.is_null() {
            let alloc_size = core::mem::size_of::<SaltyfsMountData>();
            let alloc_pages = (alloc_size + 4095) / 4096;
            crate::server::mem::unmap(md_raw, (alloc_pages * 4096) as u64);
        }

        state.mounts.release(mh);
    }
}

/// Complete a mount whose `BACKEND_OPEN_SESSION` just returned. Invoked
/// from [`super::completion`] under the `FsResume::MountReady` arm. The
/// original prepare phase already stored the SaltyFS `MountData`,
/// resolved the endpoint cap, and fired the async request; this
/// function consumes the reply's session identity, registers the
/// backend session slot, and finishes root-vnode setup.
///
/// Returns `Ok(())` on full success. On any error the caller is
/// responsible for tearing down the mount slot + freeing the
/// `SaltyfsMountData` allocation and releasing the reply slot with an
/// error to the original mount caller.
pub(crate) unsafe fn saltyfs_mount_finalize(
    state: &mut crate::owner::VfsState,
    mh: crate::vfs_core::mount::MountHandle,
    fs_cap: Cap,
    reply_msg: &TronaMsg,
) -> VfsResult<()> {
    unsafe {
        if reply_msg.label != TRONA_OK && reply_msg.label != TRONA_ALREADY_EXISTS {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] saltyfs mount failed label=");
                _lb.hex(reply_msg.label);
                _lb.str(b"\n");
            });
            return Err(VfsError::Io);
        }

        let open_reply = trona_protocol::BackendOpenSessionReply::decode_regs([
            reply_msg.regs[0],
            reply_msg.regs[1],
            reply_msg.regs[2],
            reply_msg.regs[3],
        ]);
        let root_node = open_reply.root_node;
        let root_ino = root_node.ino;

        let fs_instance_id = state
            .mounts
            .get(mh)
            .map(|m| m.fs_instance_id)
            .ok_or(VfsError::Io)?;
        let mp_ptr = state.mounts.raw_ptr(mh).ok_or(VfsError::Io)?;
        let md = (*mp_ptr).data as *mut SaltyfsMountData;
        if md.is_null() {
            return Err(VfsError::Io);
        }

        (*md).session_id = open_reply.session_id;
        (*md).max_inflight = open_reply.max_inflight;
        (*md).root_node = root_node;
        (*md).feature_bits = open_reply.feature_bits;
        (*md).root_ino = root_ino;
        (*md).v2_protocol = true;

        if state
            .alloc_backend_session_slot(
                fs_instance_id,
                open_reply.session_id,
                open_reply.max_inflight,
                super::deferred::drain_deferred_issues,
                super::deferred::saltyfs_defer_push,
                super::completion::saltyfs_completion,
                super::deferred::saltyfs_readdir_eof,
            )
            .is_none()
        {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] saltyfs session slot table full for fs_id=");
                _lb.hex(fs_instance_id.raw());
                _lb.str(b"\n");
            });
        }

        // Record the backend's client-facing IPC cap on the session
        // slot so the revocation detector can correlate a future
        // kernel cap-loss notification back to `fs_id`. Our
        // `observe_backend_send` path triggers teardown on any
        // non-transient send error; `set_backend_callback_ep`
        // stashes the cap for the (future) proactive notification
        // path. Idempotent — no-op when the session slot isn't live
        // (e.g. table full above).
        state.set_backend_callback_ep(fs_instance_id, fs_cap);

        if pool::init_pools(md) != 0 {
            return Err(VfsError::NoSpace);
        }
        setup_shm(md, fs_cap);

        // Root vnode materialisation — uses state directly (no trampoline).
        {
            let root_vd = pool::alloc_vdata(md);
            if root_vd.is_null() {
                return Err(VfsError::NoSpace);
            }
            (*root_vd).active = 1;
            (*root_vd).ftype = VT_DIR;
            (*root_vd).mode = S_IFDIR_L | 0o755;
            (*root_vd).remote_ino = root_ino;
            (*root_vd).remote_seq = root_node.seq;
            (*root_vd).nlink = 2;

            let root_vh = state.vnodes.alloc().ok_or(VfsError::NoSpace)?;
            let root_vp = state.vnodes.raw_ptr(root_vh).ok_or(VfsError::NoSpace)?;
            let mount_handle = state
                .mounts
                .handle_from_slot((*mp_ptr).id as u32)
                .ok_or(VfsError::Io)?;
            (*root_vp).id = root_ino;
            (*root_vp).backend_seq = root_node.seq;
            (*root_vp).vtype = VT_DIR;
            (*root_vp).flags = VN_ROOT;
            (*root_vp).data = root_vd as *mut u8;
            (*root_vp).nlink = 2;
            (*root_vp).mount.set((*mp_ptr).fs_instance_id, mount_handle);
            (*root_vp).fs_instance_id = (*mp_ptr).fs_instance_id;
            (*root_vp).ops = &raw const super::SALTYFS_VOPS;
            (*root_vd).vnode_handle = root_vh;

            (*mp_ptr).root_vnode = root_vh;
        }

        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] Mounted saltyfs root_ino=");
            _lb.hex(root_ino);
            _lb.str(b"\n");
        });
        Ok(())
    }
}

// =========================================================================
// Unmount
// =========================================================================

pub(super) unsafe fn saltyfs_unmount(ctx: &mut OwnerMountCtx<'_>, _force: bool) -> VfsResult<()> {
    unsafe {
        let md = (*ctx.mount).data as *mut SaltyfsMountData;
        let fs_cap = if md.is_null() { 0 } else { (*md).fs_cap };
        let session_id = if md.is_null() { 0 } else { (*md).session_id };
        let fs_id = (*ctx.mount).fs_instance_id;

        if fs_cap != 0 {
            let mut req = TronaMsg::zeroed();
            req.label = BACKEND_CLOSE_SESSION;
            req.regs[0] = session_id as u64;
            req.length = 1;
            let mut reply = TronaMsg::zeroed();
            let err = ipc::call_ctx(crate::ipc_ctx(), fs_cap, &raw const req, &raw mut reply);
            if err != 0 {
                trona_runtime::udebug!(|_lb| {
                    _lb.str(b"[VFS] saltyfs BACKEND_CLOSE_SESSION failed err=");
                    _lb.hex(err as u64);
                    _lb.str(b" label=");
                    _lb.hex(reply.label);
                    _lb.str(b"\n");
                });
            }
        }

        ctx.state.free_backend_session_slot(fs_id);

        (*ctx.mount).root_vnode = VnodeHandle::INVALID;
        (*ctx.mount).data = core::ptr::null_mut();
        Ok(())
    }
}

// =========================================================================
// Root
// =========================================================================

pub(super) unsafe fn saltyfs_root(ctx: &OwnerMountCtx<'_>) -> VfsResult<VnodeHandle> {
    unsafe {
        let root = (*ctx.mount).root_vnode;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

// =========================================================================
// Vget
// =========================================================================

pub(super) unsafe fn saltyfs_vget(ctx: &mut OwnerMountCtx<'_>, id: u64) -> VfsResult<VnodeHandle> {
    unsafe {
        let mp = ctx.mount;
        let md = (*mp).data as *mut SaltyfsMountData;
        let mp_id = (*mp).id as u32;
        let mp_fs_id = (*mp).fs_instance_id;
        let mp_root_ino = (*md).root_node.ino;

        // The public vget ABI only passes the remote inode number, so for
        // non-root vnodes we must stat first to recover the backend
        // incarnation sequence before deciding whether a cached vnode still
        // matches.
        let mut cached_seq = None;
        if id == mp_root_ino {
            cached_seq = Some((*md).root_node.seq);
        }
        let existing_vd = match cached_seq {
            Some(seq) => pool::find_vdata_by_node(md, id, seq),
            None => core::ptr::null_mut(),
        };
        if !existing_vd.is_null() {
            if (*existing_vd).vnode_handle.is_valid()
                && ctx.state.vnodes.get((*existing_vd).vnode_handle).is_some()
            {
                return Ok((*existing_vd).vnode_handle);
            }
            // Allocate a new arena vnode pointing to the existing vdata.
            let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
            let mount_handle = ctx
                .state
                .mounts
                .handle_from_slot(mp_id)
                .ok_or(VfsError::Io)?;
            (*vp).id = id;
            (*vp).backend_seq = (*existing_vd).remote_seq;
            (*vp).vtype = (*existing_vd).ftype;
            (*vp).data = existing_vd as *mut u8;
            (*vp).nlink = (*existing_vd).nlink;
            (*vp).mount.set(mp_fs_id, mount_handle);
            (*vp).fs_instance_id = mp_fs_id;
            (*vp).ops = &raw const super::SALTYFS_VOPS;
            if id == mp_root_ino {
                (*vp).flags |= VN_ROOT;
                (*vp).pin();
            }
            let key = (*vp).vnode_key();
            if let Some(covering_fs_id) = covering_fs_id_for_key(ctx.state, key) {
                (*vp).flags |= crate::vfs_core::vnode::VN_COVERED;
                (*vp)
                    .covered_by
                    .set_id_only(covering_fs_id, crate::vfs_core::mount::MountHandle::INVALID);
                (*vp).pin();
            }
            (*existing_vd).vnode_handle = vh;
            ctx.install_resolve_cache(key, vh);
            return Ok(vh);
        }

        // Stat the remote inode to populate a new vnode or recover the
        // incarnation sequence needed to match an existing cache entry.
        match rpc::saltyfs_ipc_stat(md, id) {
            Some((size, mode, nlink, mtime, blocks, uid, gid, seq)) => {
                let existing_vd = pool::find_vdata_by_node(md, id, seq);
                if !existing_vd.is_null() {
                    if (*existing_vd).vnode_handle.is_valid()
                        && ctx.state.vnodes.get((*existing_vd).vnode_handle).is_some()
                    {
                        return Ok((*existing_vd).vnode_handle);
                    }
                    let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
                    let mount_handle = ctx
                        .state
                        .mounts
                        .handle_from_slot(mp_id)
                        .ok_or(VfsError::Io)?;
                    (*existing_vd).mode = mode;
                    (*existing_vd).size = size;
                    (*existing_vd).nlink = nlink;
                    (*existing_vd).uid = uid;
                    (*existing_vd).gid = gid;
                    (*existing_vd).mtime = mtime;
                    (*existing_vd).blocks = blocks;
                    (*vp).id = id;
                    (*vp).backend_seq = seq;
                    (*vp).vtype = (*existing_vd).ftype;
                    (*vp).data = existing_vd as *mut u8;
                    (*vp).nlink = (*existing_vd).nlink;
                    (*vp).mount.set(mp_fs_id, mount_handle);
                    (*vp).fs_instance_id = mp_fs_id;
                    (*vp).ops = &raw const super::SALTYFS_VOPS;
                    if id == mp_root_ino {
                        (*vp).flags |= VN_ROOT;
                        (*vp).pin();
                    }
                    let key = (*vp).vnode_key();
                    if let Some(covering_fs_id) = covering_fs_id_for_key(ctx.state, key) {
                        (*vp).flags |= crate::vfs_core::vnode::VN_COVERED;
                        (*vp).covered_by.set_id_only(
                            covering_fs_id,
                            crate::vfs_core::mount::MountHandle::INVALID,
                        );
                        (*vp).pin();
                    }
                    (*existing_vd).vnode_handle = vh;
                    ctx.install_resolve_cache(key, vh);
                    return Ok(vh);
                }

                let vd = pool::alloc_vdata(md);
                if vd.is_null() {
                    return Err(VfsError::NoSpace);
                }
                let ftype = match mode & S_IFMT_L {
                    S_IFDIR_L => VT_DIR,
                    S_IFLNK_L => crate::vfs_core::vnode::VT_LNK,
                    _ => crate::vfs_core::vnode::VT_REG,
                };
                (*vd).active = 1;
                (*vd).ftype = ftype;
                (*vd).mode = mode;
                (*vd).remote_ino = id;
                (*vd).remote_seq = seq;
                (*vd).size = size;
                (*vd).nlink = nlink;
                (*vd).uid = uid;
                (*vd).gid = gid;
                (*vd).mtime = mtime;
                (*vd).blocks = blocks;

                let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
                let mount_handle = ctx
                    .state
                    .mounts
                    .handle_from_slot(mp_id)
                    .ok_or(VfsError::Io)?;
                (*vp).id = id;
                (*vp).backend_seq = seq;
                (*vp).vtype = ftype;
                (*vp).data = vd as *mut u8;
                (*vp).nlink = nlink;
                (*vp).mount.set(mp_fs_id, mount_handle);
                (*vp).fs_instance_id = mp_fs_id;
                (*vp).ops = &raw const super::SALTYFS_VOPS;
                (*vd).vnode_handle = vh;
                let key = (*vp).vnode_key();
                ctx.install_resolve_cache(key, vh);
                Ok(vh)
            }
            None => Err(VfsError::NotFound),
        }
    }
}

/// Locate a mount whose `covered` `VnodeKey` matches `key`. Returns the
/// covering mount's `FsInstanceId`. Replaces the retired
/// `ctx.covering_fs_id_for_key`.
fn covering_fs_id_for_key(
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
// Statfs
// =========================================================================

pub(super) unsafe fn saltyfs_statfs(ctx: &OwnerMountCtx<'_>, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = (*ctx.mount).data as *mut SaltyfsMountData;
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
                (*out).flags = (*ctx.mount).flags;
                (*out).name_max = 255;
                Ok(())
            }
            None => Err(VfsError::Io),
        }
    }
}

// =========================================================================
// Sync
// =========================================================================

pub(super) unsafe fn saltyfs_sync(_ctx: &OwnerMountCtx<'_>) -> VfsResult<()> {
    Ok(())
}

// =========================================================================
// Helpers
// =========================================================================

/// Resolve the "saltyfs" endpoint via namesrv.
unsafe fn resolve_saltyfs_endpoint() -> VfsResult<u64> {
    unsafe {
        let slot = match trona_runtime::core::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => return Err(VfsError::NoSpace),
        };
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, slot);
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            crate::ipc_ctx(),
            CAP_SELF_CSPACE,
            slot,
            0,
        );

        let mut ns_req = TronaMsg::zeroed();
        ns_req.label = NS_LOOKUP;
        let name = b"saltyfs";
        ns_req.regs[0] = name.len() as u64;
        ns_req.length = 1 + (name.len() as u64 + 7) / 8;
        let ns_dst = &raw mut ns_req.regs[1] as *mut u8;
        for i in 0..name.len() {
            *ns_dst.add(i) = name[i];
        }

        let mut ns_reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep(),
            &raw const ns_req,
            &raw mut ns_reply,
        );

        if err != 0 || ns_reply.label != TRONA_OK {
            let _ = invoke::cnode_delete(CAP_SELF_CSPACE, slot);
            let _ = trona_runtime::core::slot_alloc::slot_free(slot);
            trona_runtime::udebug!(|_lb| {
                _lb.str(b"[VFS] saltyfs not found in namesrv\n");
            });
            return Err(VfsError::NotFound);
        }

        Ok(slot)
    }
}

/// Set up VFS-SaltyFS SHM for bulk data transport.
unsafe fn setup_shm(md: *mut SaltyfsMountData, fs_cap: u64) {
    unsafe {
        let mut shm_create = TronaMsg::zeroed();
        shm_create.label = MM_SHM_CREATE;
        shm_create.length = 2;
        shm_create.regs[0] = VFS_SALTYFS_SHM_ID;
        shm_create.regs[1] = VFS_SALTYFS_SHM_PAGES;

        let mut shm_reply = TronaMsg::zeroed();
        let serr = ipc::call_ctx(
            crate::ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const shm_create,
            &raw mut shm_reply,
        );
        if serr != 0 || (shm_reply.label != 0 && shm_reply.label != TRONA_ALREADY_EXISTS) {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] saltyfs SHM create failed (non-fatal)\n");
            });
            return;
        }

        let mut shm_map = TronaMsg::zeroed();
        shm_map.label = MM_SHM_MAP;
        shm_map.length = 4;
        shm_map.regs[0] = VFS_SALTYFS_SHM_ID;
        shm_map.regs[1] = 0;
        shm_map.regs[2] = VFS_SALTYFS_SHM_VADDR;
        shm_map.regs[3] = 0x3; // RW

        let mut map_reply = TronaMsg::zeroed();
        let merr = ipc::call_ctx(
            crate::ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const shm_map,
            &raw mut map_reply,
        );
        if merr != 0 || map_reply.label != 0 {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] saltyfs SHM map failed (non-fatal)\n");
            });
            return;
        }

        let mut setup_msg = TronaMsg::zeroed();
        setup_msg.label = BACKEND_SHM_SETUP;
        setup_msg.regs[0] = VFS_SALTYFS_SHM_ID;
        setup_msg.length = 1;

        let mut setup_reply = TronaMsg::zeroed();
        let serr2 = ipc::call_ctx(
            crate::ipc_ctx(),
            fs_cap,
            &raw const setup_msg,
            &raw mut setup_reply,
        );
        if serr2 == 0 && setup_reply.label == TRONA_OK {
            trona_runtime::uinfo!(|_lb| {
                _lb.str(b"[VFS] saltyfs SHM transport established\n");
            });
            (*md).shm_active = true;
            (*md).shm_vaddr = VFS_SALTYFS_SHM_VADDR;
            (*md).shm_size = VFS_SALTYFS_SHM_PAGES * 4096;

            *(&raw mut crate::VFS_SHM_ACTIVE) = true;
        } else {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] saltyfs SHM setup failed (non-fatal)\n");
            });
            let mut shm_unmap = TronaMsg::zeroed();
            shm_unmap.label = MM_SHM_UNMAP;
            shm_unmap.length = 3;
            shm_unmap.regs[0] = VFS_SALTYFS_SHM_ID;
            shm_unmap.regs[1] = 0;
            shm_unmap.regs[2] = VFS_SALTYFS_SHM_VADDR;
            let mut unmap_reply = TronaMsg::zeroed();
            let _ = ipc::call_ctx(
                crate::ipc_ctx(),
                trona_runtime::client::caps::mmsrv_ep(),
                &raw const shm_unmap,
                &raw mut unmap_reply,
            );
        }
    }
}
