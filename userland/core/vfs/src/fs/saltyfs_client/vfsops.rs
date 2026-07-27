// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyFS VfsOps — mount-level operations.
//!
//! Wires the saltyfs daemon session into a `Mount` slot. The
//! generic mount dispatcher calls [`begin_mount`]; all SaltyFS
//! feature checks, SHM sizing, vdata pool setup, and root vnode
//! materialisation stay in this module.

use trona_kernel::core_types::{Cap, TronaMsg};

use crate::core::error::VfsError;
use crate::core::file::VStatfs;
use crate::core::identity::{BackendNodeId, VnodeKey};
use crate::core::mount::{Mount, MountHandle, MountKind};
use crate::core::vnode::{VN_ROOT, VnodeHandle};
use crate::core::vop::VfsOps;
use crate::core::vop_context::OwnerMountCtx;
use crate::ipc::protocol::backend::{
    BACKEND_CLOSE_SESSION, BACKEND_DRAIN, BACKEND_GETINFO, VFS_BACKEND_REPLY_OK,
};
use crate::owner::VfsState;
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::types::ClientHandle;

use super::feature::FeatureResult;
use super::types::{SALTYFS_VDATA_POOL_SIZE, SaltyfsMountData, SaltyfsVnodeData};

/// SaltyFS readdir / xattr SHM ring size. Sized to hold ~256
/// readdir records (96 B each) plus a single xattr name+value
/// staging buffer; tuned to fit a single contiguous mmsrv-managed
/// region without spilling into a multi-region scheme.
const SALTYFS_SHM_BYTES: u64 = 64 * 1024;

/// Begin a SaltyFS mount.
///
/// This is deliberately kept in the SaltyFS client module rather
/// than the generic POSIX mount dispatcher: backend name, feature
/// policy, SHM sizing, vdata-pool shape, and root-vnode construction
/// are all SaltyFS-specific. Future ext4 / FAT / NTFS clients should
/// add their own `begin_mount` helpers with their own negotiation
/// rules instead of extending a shared path with filesystem-specific
/// assumptions.
pub(crate) unsafe fn begin_mount(
    state: &mut VfsState,
    client: ClientHandle,
    target_vh: VnodeHandle,
    flags: u64,
    mount_path: &[u8],
    reply_lease: trona_server::ReplyLease,
) {
    // SHM ring sizing — mmsrv counts in pages, vfs in bytes.
    const PAGE_BYTES: u64 = 4096;
    const VDATA_POOL_BYTES: u64 =
        (SALTYFS_VDATA_POOL_SIZE as u64) * (::core::mem::size_of::<SaltyfsVnodeData>() as u64);

    let Some(backend_ep) = trona_runtime::client::lazy_resolve::namesrv_lookup_blocking(b"saltyfs")
    else {
        send_reply_err_for_client(state, client, reply_lease, VfsError::SessionTornDown);
        return;
    };

    let fs_id = state.next_fs_instance_id();
    let Some(mount_h) = state.mounts.alloc() else {
        // `backend_ep` (OwnedCap) drops here, freeing the cap.
        send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
        return;
    };
    if let Some(mount) = state.mounts.get_mut(mount_h) {
        *mount = Mount::EMPTY;
        mount.kind = MountKind::SaltyFs;
        mount.fs_instance_id = fs_id;
        mount.mount_flags = flags;
        mount.case_fold = crate::fs::mount::case_fold_for_flags(flags);
        mount.set_mount_path(mount_path);
    }
    let mount_handle_raw = mount_handle_to_raw(mount_h);

    let md_bytes = ((::core::mem::size_of::<SaltyfsMountData>() as u64) + PAGE_BYTES - 1)
        / PAGE_BYTES
        * PAGE_BYTES;
    let md_ptr = unsafe { crate::server::mem::map_anon(md_bytes) } as *mut SaltyfsMountData;
    if md_ptr as usize == usize::MAX {
        // `backend_ep` (OwnedCap) drops here, freeing the cap.
        state.mounts.release(mount_h);
        send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
        return;
    }
    unsafe { *md_ptr = SaltyfsMountData::zeroed() };

    // Capture the backend EP's raw slot before it moves into the session
    // (which owns its lifetime); the mount keeps a borrowed view in `fs_cap`.
    let backend_ep_raw = backend_ep.as_raw();
    let outcome = match unsafe {
        crate::owner::session::attach_backend_session(
            state,
            backend_ep,
            fs_id,
            mount_handle_raw,
            flags,
            super::completion::saltyfs_completion,
            None,
            None,
            None,
        )
    } {
        Ok(o) => o,
        Err(e) => {
            // `backend_ep` was moved into attach_backend_session, which frees it
            // on its own failure paths; nothing to release here.
            unsafe {
                let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
            }
            state.mounts.release(mount_h);
            send_reply_err_for_client(state, client, reply_lease, e);
            return;
        }
    };

    // After attach succeeds the slot owns `backend_ep` via its
    // `send_cap` field; rolling back from this point forward goes
    // through `tear_down`, never `release_caller_cap`.
    match super::feature::check_features(outcome.feature_bits) {
        FeatureResult::Supported => {}
        FeatureResult::Reject => {
            crate::owner::session::tear_down(state, outcome.slot_idx);
            unsafe {
                let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
            }
            state.mounts.release(mount_h);
            send_reply_err_for_client(state, client, reply_lease, VfsError::NotSup);
            return;
        }
    }
    let root_seq = match u32::try_from(outcome.aux1) {
        Ok(seq) => seq,
        Err(_) => {
            crate::owner::session::tear_down(state, outcome.slot_idx);
            unsafe {
                let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
            }
            state.mounts.release(mount_h);
            send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
            return;
        }
    };
    if outcome.session_token != 0 || outcome.aux2 != SALTYFS_SHM_BYTES {
        crate::owner::session::tear_down(state, outcome.slot_idx);
        unsafe {
            let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
        }
        state.mounts.release(mount_h);
        send_reply_err_for_client(state, client, reply_lease, VfsError::NotSup);
        return;
    }
    let max_inflight = match u16::try_from(outcome.inflight_max) {
        Ok(v) => v,
        Err(_) => {
            crate::owner::session::tear_down(state, outcome.slot_idx);
            unsafe {
                let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
            }
            state.mounts.release(mount_h);
            send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
            return;
        }
    };

    let shm_name = state.alloc_shm_id();
    let (shm_id, shm_cap) = match unsafe {
        crate::owner::client_shm::mmsrv_shm_create(state, shm_name, SALTYFS_SHM_BYTES)
    } {
        Ok(v) => v,
        Err(e) => {
            crate::owner::session::tear_down(state, outcome.slot_idx);
            unsafe {
                let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
            }
            state.mounts.release(mount_h);
            send_reply_err_for_client(state, client, reply_lease, e);
            return;
        }
    };
    // vfs keeps `shm_cap` for release; mmsrv and the daemon each get a
    // disposable copy (the kernel moves a staged cap out of vfs's CSpace).
    let map_cap = match trona_runtime::core::slot_alloc::dup_for_transfer(
        trona_runtime::core::slot_alloc::resolved_cap_ref(shm_cap),
    ) {
        Some(c) => c,
        None => {
            release_saltyfs_shm(shm_id, shm_cap, 0, 0);
            crate::owner::session::tear_down(state, outcome.slot_idx);
            unsafe {
                let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
            }
            state.mounts.release(mount_h);
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            return;
        }
    };
    let vfs_shm_vaddr = match unsafe {
        crate::owner::client_shm::mmsrv_shm_map(shm_id, map_cap, SALTYFS_SHM_BYTES)
    } {
        Ok(va) => va,
        Err(e) => {
            release_saltyfs_shm(shm_id, shm_cap, 0, 0);
            crate::owner::session::tear_down(state, outcome.slot_idx);
            unsafe {
                let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
            }
            state.mounts.release(mount_h);
            send_reply_err_for_client(state, client, reply_lease, e);
            return;
        }
    };

    let setup_cap = match trona_runtime::core::slot_alloc::dup_for_transfer(
        trona_runtime::core::slot_alloc::resolved_cap_ref(shm_cap),
    ) {
        Some(c) => c,
        None => {
            release_saltyfs_shm(shm_id, shm_cap, vfs_shm_vaddr, SALTYFS_SHM_BYTES);
            crate::owner::session::tear_down(state, outcome.slot_idx);
            unsafe {
                let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
            }
            state.mounts.release(mount_h);
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            return;
        }
    };
    if let Err(e) = unsafe {
        crate::owner::session::attach_session_shm_setup(
            state,
            outcome.slot_idx,
            shm_id,
            setup_cap,
            vfs_shm_vaddr,
            SALTYFS_SHM_BYTES,
        )
    } {
        release_saltyfs_shm(shm_id, shm_cap, vfs_shm_vaddr, SALTYFS_SHM_BYTES);
        crate::owner::session::tear_down(state, outcome.slot_idx);
        unsafe {
            let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
        }
        state.mounts.release(mount_h);
        send_reply_err_for_client(state, client, reply_lease, e);
        return;
    }

    let vdata_bytes = ((VDATA_POOL_BYTES) + PAGE_BYTES - 1) / PAGE_BYTES * PAGE_BYTES;
    let vdata_ptr = unsafe { crate::server::mem::map_anon(vdata_bytes) } as *mut SaltyfsVnodeData;
    if vdata_ptr as usize == usize::MAX {
        release_saltyfs_shm(shm_id, shm_cap, vfs_shm_vaddr, SALTYFS_SHM_BYTES);
        crate::owner::session::tear_down(state, outcome.slot_idx);
        unsafe {
            let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
        }
        state.mounts.release(mount_h);
        send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
        return;
    }
    for i in 0..SALTYFS_VDATA_POOL_SIZE {
        unsafe { *vdata_ptr.add(i) = SaltyfsVnodeData::zeroed() };
    }

    let root_ino = outcome.aux0;
    let root_backend_id = BackendNodeId::new(root_ino, root_seq);
    let Some(root_vh) = state.vnodes.alloc() else {
        unsafe {
            let _ = crate::server::mem::unmap(vdata_ptr as *mut u8, vdata_bytes);
        }
        release_saltyfs_shm(shm_id, shm_cap, vfs_shm_vaddr, SALTYFS_SHM_BYTES);
        crate::owner::session::tear_down(state, outcome.slot_idx);
        unsafe {
            let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
        }
        state.mounts.release(mount_h);
        send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
        return;
    };
    if let Some(root_vp) = unsafe { state.vnodes.raw_ptr(root_vh) } {
        unsafe {
            *root_vp = crate::core::vnode::Vnode::EMPTY;
            (*root_vp).kind = crate::core::vnode::VnodeKind::Directory;
            (*root_vp).key = VnodeKey {
                fs_instance_id: fs_id,
                backend_id: root_backend_id,
            };
            (*root_vp).backend_seq = 0;
            (*root_vp).data = ::core::ptr::null_mut();
            (*root_vp).nlink = 1;
            (*root_vp).mount = mount_h;
            (*root_vp).fs_instance_id = fs_id;
            (*root_vp).ops = &raw const super::SALTYFS_VOPS;
            (*root_vp).flags |= VN_ROOT;
        }
    }

    unsafe {
        (*md_ptr).fs_cap = backend_ep_raw;
        (*md_ptr).session_id = outcome.session_id;
        (*md_ptr).max_inflight = max_inflight;
        (*md_ptr).feature_bits = outcome.feature_bits;
        (*md_ptr).root_node = root_backend_id;
        (*md_ptr).root_ino = root_ino;
        (*md_ptr).shm_id = shm_id;
        (*md_ptr).shm_cap = shm_cap;
        (*md_ptr).shm_vaddr = vfs_shm_vaddr;
        (*md_ptr).shm_size = SALTYFS_SHM_BYTES;
        (*md_ptr).shm_active = true;
        (*md_ptr).vdata_ptr = vdata_ptr;
        (*md_ptr).vdata_cap = SALTYFS_VDATA_POOL_SIZE;
        (*md_ptr).backend_session_idx = outcome.slot_idx;
    }

    if let Some(mount) = state.mounts.get_mut(mount_h) {
        mount.root = root_vh;
        mount.data = md_ptr as *mut u8;
        mount.vfsops = &raw const super::SALTYFS_VFSOPS;
        mount.backend_session_idx = outcome.slot_idx;
    }

    if let Err(e) =
        unsafe { crate::core::mount_ctl::finalize_mount_tail(state, mount_h, target_vh, fs_id) }
    {
        let _ = state.vnodes.release(root_vh);
        unsafe {
            let _ = crate::server::mem::unmap(vdata_ptr as *mut u8, vdata_bytes);
        }
        release_saltyfs_shm(shm_id, shm_cap, vfs_shm_vaddr, SALTYFS_SHM_BYTES);
        crate::owner::session::tear_down(state, outcome.slot_idx);
        unsafe {
            let _ = crate::server::mem::unmap(md_ptr as *mut u8, md_bytes);
        }
        state.mounts.release(mount_h);
        send_reply_err_for_client(state, client, reply_lease, e);
        return;
    }
    unsafe {
        crate::core::mount_ctl::refresh_global_ns(state);
    }
    unsafe {
        crate::boot::late_mount::on_mount_finalized(state, mount_h, target_vh);
    }

    send_reply_ok_for_client(state, client, reply_lease, &[fs_id.0]);
}

#[inline]
fn mount_handle_to_raw(mh: MountHandle) -> u64 {
    ((mh.slot() as u64) << 32) | (mh.epoch() as u64)
}

fn release_saltyfs_shm(shm_id: u64, shm_cap: u64, shm_vaddr: u64, shm_size: u64) {
    if shm_vaddr != 0 && shm_size != 0 {
        let _ = unsafe { crate::owner::client_shm::mmsrv_munmap(shm_vaddr, shm_size) };
    }
    // SAFETY: callers pass the SHM cap this vfs owns for the region being torn
    // down (same trusted-caller contract as the munmap/destroy above); freed once.
    unsafe { trona_runtime::core::slot_alloc::delete_and_free(shm_cap) };
    if shm_id != 0 {
        let _ = unsafe { crate::owner::client_shm::mmsrv_shm_destroy(shm_id) };
    }
}

/// Tear down a mount slot whose finalize failed (or whose
/// unmount path has reached zero references). Wipes the
/// session-identifying fields so any in-flight completion
/// observes the cleared state and drops on the live_gen check.
/// The mount slot itself is released by the caller via
/// `state.mounts.retire`.
pub(crate) unsafe fn saltyfs_mount_teardown(state: &mut VfsState, mount_h: MountHandle) {
    unsafe {
        let Some(mount) = state.mounts.get_mut(mount_h) else {
            return;
        };
        let md = mount.data as *mut SaltyfsMountData;
        if !md.is_null() {
            (*md).fs_cap = 0;
            (*md).session_id = 0;
            (*md).max_inflight = 0;
            (*md).shm_active = false;
            (*md).shm_id = 0;
            (*md).shm_cap = 0;
            (*md).shm_vaddr = 0;
            (*md).shm_size = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// SALTYFS_VFSOPS — mount-level entries dispatched through
// `Mount.vfsops`. Backend RPCs run synchronously on the owner thread
// here because the surrounding handlers (handle_umount /
// handle_statvfs) treat the VfsOps return value as the immediate
// reply payload; converting to async would require parking those
// handlers, which is a larger restructuring than the small wins
// would justify on the current call frequency (one per
// unmount/statvfs RPC).
// ---------------------------------------------------------------------------

/// Resolve the backend send cap for a mount the owner is currently
/// inspecting. `BackendSessionSlot.send_cap` is populated by
/// `attach_backend_session` and lives until session teardown; this
/// helper extracts it via the per-mount `backend_session_idx`.
unsafe fn saltyfs_send_cap_for(ctx: &OwnerMountCtx<'_>) -> Result<Cap, VfsError> {
    unsafe {
        let session_idx = (*ctx.mount).backend_session_idx;
        if session_idx == u32::MAX {
            return Err(VfsError::SessionTornDown);
        }
        let handle = ctx
            .state
            .backend_sessions
            .handle_from_slot(session_idx)
            .ok_or(VfsError::SessionTornDown)?;
        let send_cap = ctx
            .state
            .backend_sessions
            .get(handle)
            .map(|s| s.send_cap.as_raw())
            .ok_or(VfsError::SessionTornDown)?;
        if send_cap == 0 {
            return Err(VfsError::SessionTornDown);
        }
        Ok(send_cap)
    }
}

/// Issue a synchronous backend RPC with no transferred caps. Used
/// for mount-level entries (DRAIN / CLOSE_SESSION / GETINFO) where
/// the reply payload is consumed immediately by the calling
/// handler without parking a `PendingOp`.
unsafe fn saltyfs_sync_backend_call(
    send_cap: Cap,
    label: u64,
    regs: &[u64],
) -> Result<TronaMsg, VfsError> {
    let mut req = TronaMsg::default();
    req.label = label;
    let len = regs.len().min(req.regs.len());
    for i in 0..len {
        req.regs[i] = regs[i];
    }
    req.length = len as u64;
    let mut resp = TronaMsg::default();
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            crate::ipc_ctx(),
            send_cap,
            &raw const req,
            &raw mut resp,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        return Err(VfsError::Io);
    }
    if resp.label != VFS_BACKEND_REPLY_OK {
        return Err(VfsError::from_backend_reply(resp.label));
    }
    Ok(resp)
}

/// Mount entry. Saltyfs never reaches this code path through
/// `vfsops_for` — `begin_mount` runs the
/// multi-step `BACKEND_OPEN_SESSION` + `BACKEND_SHM_SETUP` +
/// root-vnode allocation directly and stamps
/// `Mount.vfsops = SALTYFS_VFSOPS` only after the steps have all
/// succeeded. Reaching here means the dispatcher routed a saltyfs
/// mount through the in-memory path by mistake.
pub(crate) unsafe fn saltyfs_mount(_ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    Err(VfsError::Inval)
}

/// Unmount entry. Drains in-flight operations, closes the daemon
/// session, releases mmsrv-owned SHM region, then runs the
/// shared `saltyfs_mount_teardown` to wipe per-mount data.
pub(crate) unsafe fn saltyfs_unmount(ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    unsafe {
        let send_cap = saltyfs_send_cap_for(ctx)?;
        // Drain first so any in-flight backend op completes before
        // we cancel the session. Errors here are logged by the
        // sync helper's `from_backend_reply` mapping; we still
        // proceed to close so the slot is reclaimed even on a
        // partial drain.
        let _ = saltyfs_sync_backend_call(send_cap, BACKEND_DRAIN, &[]);
        let _ = saltyfs_sync_backend_call(send_cap, BACKEND_CLOSE_SESSION, &[]);

        let mount_h = ctx.mount_handle;
        let session_idx = (*ctx.mount).backend_session_idx;
        let (shm_id, shm_cap, shm_vaddr, shm_size) = {
            let md = (*ctx.mount).data as *const SaltyfsMountData;
            if md.is_null() {
                (0, 0, 0, 0)
            } else {
                ((*md).shm_id, (*md).shm_cap, (*md).shm_vaddr, (*md).shm_size)
            }
        };

        if session_idx != u32::MAX {
            crate::owner::session::tear_down(ctx.state, session_idx);
        }
        if shm_id != 0 {
            release_saltyfs_shm(shm_id, shm_cap, shm_vaddr, shm_size);
        }

        saltyfs_mount_teardown(ctx.state, mount_h);
        if let Some(mount) = ctx.state.mounts.get_mut(mount_h) {
            mount.root = VnodeHandle::INVALID;
            mount.data = ::core::ptr::null_mut();
            mount.backend_session_idx = u32::MAX;
        }
        Ok(())
    }
}

/// Return the cached root vnode handle. `begin_mount`
/// installs it before `finalize_mount_tail` runs and never
/// clears it while the mount is reachable, so seeing
/// `VnodeHandle::INVALID` here means a teardown ran ahead of the
/// vops dispatch — surfacing as `VfsError::Io` lets callers fall
/// back without dereferencing the empty slot.
pub(crate) unsafe fn saltyfs_root(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let root = (*ctx.mount).root;
        if root.is_valid() {
            Ok(root)
        } else {
            Err(VfsError::Io)
        }
    }
}

/// Look up a vnode by inode number. The vdata pool acts as the
/// per-mount inode → vnode cache; on a miss we issue a synchronous
/// `BACKEND_GETINFO` against the daemon to materialise the inode's
/// type / mode / parent and allocate a fresh `Vnode`.
pub(crate) unsafe fn saltyfs_vget(
    ctx: &mut OwnerMountCtx<'_>,
    ino: u64,
) -> Result<VnodeHandle, VfsError> {
    unsafe {
        let md = (*ctx.mount).data as *mut SaltyfsMountData;
        if md.is_null() {
            return Err(VfsError::Io);
        }
        let backend_id = BackendNodeId::new(ino, 0);
        // First check the per-mount vdata cache — a hot path that
        // avoids a backend round-trip for already-resolved inodes.
        let cached = super::pool::find_vdata_by_node(md, ino, 0);
        if !cached.is_null()
            && (*cached).vnode_handle.is_valid()
            && ctx.state.vnodes.raw_ptr((*cached).vnode_handle).is_some()
        {
            return Ok((*cached).vnode_handle);
        }

        // Cache miss — query the daemon. `BACKEND_GETINFO` regs[0]
        // = inode number; reply carries (mode, nlink, size,
        // parent_ino, mtime, blocks).
        let send_cap = saltyfs_send_cap_for(ctx)?;
        let resp = saltyfs_sync_backend_call(send_cap, BACKEND_GETINFO, &[ino])?;
        let mode = resp.regs[0] as u32;
        let nlink = resp.regs[1] as u32;
        let size = resp.regs[2];
        let parent_ino = resp.regs[3];

        let vdata = if !cached.is_null() {
            cached
        } else {
            let fresh = super::pool::alloc_vdata(md);
            if fresh.is_null() {
                return Err(VfsError::NoMem);
            }
            fresh
        };
        (*vdata).active = 1;
        (*vdata).mode = mode;
        (*vdata).remote_ino = ino;
        (*vdata).parent_ino = parent_ino;
        (*vdata).nlink = nlink;
        (*vdata).size = size;
        (*vdata).ftype = mode_to_vtype(mode);

        let (vnode_h, vnode_ptr) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let mount_handle = ctx.mount_handle;
        let fs_instance_id = (*ctx.mount).fs_instance_id;
        (*vnode_ptr).kind = crate::core::vnode::vtype_to_kind((*vdata).ftype);
        (*vnode_ptr).key = VnodeKey {
            fs_instance_id,
            backend_id,
        };
        (*vnode_ptr).backend_seq = 0;
        (*vnode_ptr).data = vdata as *mut u8;
        (*vnode_ptr).nlink = (*vdata).nlink;
        (*vnode_ptr).mount = mount_handle;
        (*vnode_ptr).fs_instance_id = fs_instance_id;
        (*vnode_ptr).ops = &raw const super::SALTYFS_VOPS;
        (*vdata).vnode_handle = vnode_h;
        Ok(vnode_h)
    }
}

/// POSIX mode → VnodeKind byte. Mirrors the bit layout of the
/// `S_IFMT` mask. Unknown encodings fall through to
/// `VnodeKind::Empty` rather than guessing — the namei layer
/// surfaces the malformed inode as `VfsError::Io`.
fn mode_to_vtype(mode: u32) -> u8 {
    use crate::core::vnode::{VT_BAD, VT_BLK, VT_CHR, VT_DIR, VT_FIFO, VT_LNK, VT_REG, VT_SOCK};
    match mode & 0o170000 {
        0o100000 => VT_REG,
        0o040000 => VT_DIR,
        0o120000 => VT_LNK,
        0o010000 => VT_FIFO,
        0o140000 => VT_SOCK,
        0o020000 => VT_CHR,
        0o060000 => VT_BLK,
        _ => VT_BAD,
    }
}

/// Filesystem-wide statistics. Issues `BACKEND_GETINFO` with
/// `regs[0] = 0` (mount-level form) and parses the reply into a
/// `VStatfs`. The daemon's reply layout for the mount-level form
/// echoes the (block_size, total_blocks, free_blocks,
/// total_inodes, free_inodes, fsid, namemax) tuple.
pub(crate) unsafe fn saltyfs_statfs(
    ctx: &mut OwnerMountCtx<'_>,
    out: *mut VStatfs,
) -> Result<(), VfsError> {
    unsafe {
        let send_cap = saltyfs_send_cap_for(ctx)?;
        let resp = saltyfs_sync_backend_call(send_cap, BACKEND_GETINFO, &[0])?;
        let bsize = resp.regs[0] as u32;
        let blocks = resp.regs[1];
        let bfree = resp.regs[2];
        let files = resp.regs[3];
        let ffree = resp.regs[4];
        let fsid = resp.regs[5];
        let namemax = resp.regs[6] as u32;
        (*out).bsize = bsize;
        (*out).frsize = bsize;
        (*out).blocks = blocks;
        (*out).bfree = bfree;
        (*out).bavail = bfree;
        (*out).files = files;
        (*out).ffree = ffree;
        (*out).favail = ffree;
        (*out).fsid = fsid;
        (*out).flag = 0;
        (*out).namemax = namemax;
        (*out).set_fs_name(b"saltyfs");
        (*out).set_volume_label(b"saltyfs");
        Ok(())
    }
}

/// Flush dirty state to backing storage. SaltyFS has its own
/// commit pipeline (intent log + B-tree write-out); the daemon
/// drives the actual disk I/O when `BACKEND_DRAIN` lands. The
/// daemon's response indicates the drain has reached the on-disk
/// log; per-fd `fsync(2)` paths use `BACKEND_FSYNC` instead.
pub(crate) unsafe fn saltyfs_sync(ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    unsafe {
        let send_cap = saltyfs_send_cap_for(ctx)?;
        saltyfs_sync_backend_call(send_cap, BACKEND_DRAIN, &[])?;
        Ok(())
    }
}

/// SaltyFS mount-level VfsOps. Pinned on every saltyfs mount via
/// `Mount.vfsops`; `begin_mount` stamps it once the
/// session attach + SHM + pager handshake have all succeeded.
pub(crate) static SALTYFS_VFSOPS: VfsOps = VfsOps {
    mount: saltyfs_mount,
    unmount: saltyfs_unmount,
    root: saltyfs_root,
    vget: saltyfs_vget,
    statfs: saltyfs_statfs,
    sync: saltyfs_sync,
};
