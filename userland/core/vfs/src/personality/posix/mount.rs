// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_MOUNT` / `VFS_UMOUNT` / `VFS_STATVFS` — mount table
//! manipulation and per-mount statfs.
//!
//! ## Wire convention
//!
//! All three handlers take an existing fd as the target reference
//! rather than a path. The personality wrapper opens the
//! mount-point directory (`O_DIRECTORY`), passes its fd here, and
//! the handler resolves `OpenObject` → `Vnode` directly. This
//! avoids an extra namei walk on every mount-table call and keeps
//! the wire payload bounded.
//!
//! `VFS_MOUNT`:
//! - `regs[0]` = `target_fd` (i32) — directory the new mount
//!   should cover.
//! - `regs[1]` = `mount_kind` (`MountKind` enum value as u64).
//! - `regs[2]` = `source_fd` — reserved caller reference to a
//!   backing resource. Current in-tree mount drivers resolve their
//!   backend service through their filesystem client.
//! - `regs[3]` = `flags` — canonical `MNT_*` bits
//!   (`trona_protocol::posix::MNT_*`), passed through to the
//!   backend's mount entry verbatim.
//! - `regs[4]` = `mount_path_len`; `regs[5..]` = absolute
//!   mount-point path bytes (8 per word). Recorded on the mount as
//!   `f_mntonname` for `VFS_MOUNT_LIST`. The `target_fd` remains
//!   the mount authority — the path is descriptive metadata (BSD
//!   `f_mntonname` semantics), so it is stored as supplied rather
//!   than re-walked. `mount_path_len == 0` leaves the path empty.
//!
//! `VFS_UMOUNT`:
//! - `regs[0]` = `target_fd` (the mount-point directory's fd, the
//!   same one originally passed to `VFS_MOUNT`).
//! - `regs[1]` = `flags`.
//!
//! `VFS_STATVFS`:
//! - `regs[0]` = `fd` — any open fd inside the target mount.
//! - reply: `VStatfs` fields packed into `regs[0..11]`.
//!
//! This handler stays wire-only: filesystem-specific negotiation is
//! delegated to `fs::mount`, which in turn calls the owning
//! filesystem client.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::core::file::VStatfs;
use crate::core::mount::{MountHandle, MountKind};
use crate::core::vnode::VnodeHandle;
use crate::core::vop_context::OwnerMountCtx;
use crate::owner::VfsState;
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::types::ClientHandle;

// ---------------------------------------------------------------------------
// VFS_MOUNT
// ---------------------------------------------------------------------------

pub(crate) unsafe fn handle_mount(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let target_fd = msg.regs[0] as i32;
        let kind_raw = msg.regs[1] as u8;
        let _source_fd = msg.regs[2] as i32;
        let flags = msg.regs[3];

        let kind = match MountKind::from_wire(kind_raw) {
            Some(k) => k,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
                return;
            }
        };

        let target_vh = match resolve_target_vnode(state, client, target_fd) {
            Ok(h) => h,
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };

        // Absolute mount-point path: `regs[4]` = length, `regs[5..]`
        // = bytes (packed 8 per word, matching the client's
        // `pack_path(msg, 4, ..)`). Truncated to the stored width;
        // a zero length leaves `f_mntonname` empty.
        let path_len = (msg.regs[4] as usize).min(crate::core::mount::MOUNT_PATH_MAX);
        let mut path_buf = [0u8; crate::core::mount::MOUNT_PATH_MAX];
        let path_src = (&raw const msg.regs[5]) as *const u8;
        for i in 0..path_len {
            path_buf[i] = *path_src.add(i);
        }

        crate::fs::mount::begin_mount(
            state,
            client,
            target_vh,
            kind,
            flags,
            &path_buf[..path_len],
            reply_lease,
        );
    }
}

unsafe fn resolve_target_vnode(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<VnodeHandle, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let cli = state.clients.get(client).ok_or(VfsError::Io)?;
    let oh = cli.slot_table.lookup(fd as u32).ok_or(VfsError::BadF)?;
    let obj = state.open_objects.get(oh).ok_or(VfsError::BadF)?;
    if !obj.vnode.is_valid() {
        return Err(VfsError::BadF);
    }
    Ok(obj.vnode)
}

// ---------------------------------------------------------------------------
// VFS_UMOUNT
// ---------------------------------------------------------------------------

pub(crate) unsafe fn handle_umount(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let target_fd = msg.regs[0] as i32;
        let _flags = msg.regs[1];

        let target_vh = match resolve_target_vnode(state, client, target_fd) {
            Ok(h) => h,
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };

        // The target vnode is the *root* of the mount being
        // unmounted. Find its mount handle by matching `mount.root`.
        let mount_h = match find_mount_by_root(state, target_vh) {
            Some(h) => h,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
                return;
            }
        };

        // Refuse if any vnode in the mount still has a non-zero
        // refcount — busy mount, caller must close all open files
        // first.
        let busy = state
            .mounts
            .get(mount_h)
            .map(|m| m.vnode_refcount > 1)
            .unwrap_or(true);
        if busy {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Busy);
            return;
        }

        let vfsops_ptr = match state.mounts.get(mount_h) {
            Some(m) => m.vfsops,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
                return;
            }
        };
        if vfsops_ptr.is_null() {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
            return;
        }

        let unmount_result = {
            let mut mctx = match OwnerMountCtx::from_state(state, mount_h) {
                Some(c) => c,
                None => {
                    send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
                    return;
                }
            };
            ((*vfsops_ptr).unmount)(&mut mctx)
        };

        if let Err(e) = unmount_result {
            send_reply_err_for_client(state, client, reply_lease, e);
            return;
        }

        // Clear the cover flag on the target vnode (if any) and
        // release the mount slot.
        if let Some(target_vp) = state.vnodes.raw_ptr(target_vh) {
            (*target_vp).flags &= !crate::core::vnode::VN_COVERED;
            (*target_vp).unpin();
        }
        state.mounts.release(mount_h);
        crate::core::mount_ctl::refresh_global_ns(state);

        let mut out = TronaMsg::default();
        out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
        out.length = 0;
        crate::owner::op::reply_send(reply_lease, &out);
    }
}

fn find_mount_by_root(state: &VfsState, root_vh: VnodeHandle) -> Option<MountHandle> {
    let mut found = None;
    state.mounts.for_each_active(|mh, m| {
        if m.root == root_vh {
            found = Some(mh);
            false
        } else {
            true
        }
    });
    found
}

// ---------------------------------------------------------------------------
// VFS_REMOUNT
// ---------------------------------------------------------------------------

/// `mount(2)`-style remount. Updates the live mount entry's
/// `mount_flags` without tearing down or replacing the backend
/// session — the caller's `target_fd` must reference the mount root.
///
/// Wire (vfs canonical):
///   regs[0] = target_fd (mount-point's directory fd; must be the
///             mount root)
///   regs[1] = flags (new `mount_flags` value, replaces the existing
///             value verbatim)
///
/// Backends consult `Mount.mount_flags` on each entry, so this update
/// takes effect for subsequent operations without a backend
/// round-trip. SaltyFs daemons that cache the flag set must read it
/// fresh from the mount record per request.
pub(crate) unsafe fn handle_remount(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let target_fd = msg.regs[0] as i32;
        let flags = msg.regs[1];

        let target_vh = match resolve_target_vnode(state, client, target_fd) {
            Ok(h) => h,
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };

        let mount_h = match find_mount_by_root(state, target_vh) {
            Some(h) => h,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
                return;
            }
        };

        if let Some(mount) = state.mounts.get_mut(mount_h) {
            mount.mount_flags = flags;
            mount.case_fold = crate::fs::mount::case_fold_for_flags(flags);
        } else {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
            return;
        }
        crate::core::mount_ctl::refresh_global_ns(state);

        send_reply_ok_for_client(state, client, reply_lease, &[]);
    }
}

// ---------------------------------------------------------------------------
// VFS_STATVFS
// ---------------------------------------------------------------------------

pub(crate) unsafe fn handle_statvfs(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let target_vh = match resolve_target_vnode(state, client, fd) {
            Ok(h) => h,
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };

        let mount_h = match state.vnodes.get(target_vh).map(|v| v.mount) {
            Some(m) if m.is_valid() => m,
            _ => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
                return;
            }
        };

        let vfsops_ptr = match state.mounts.get(mount_h) {
            Some(m) => m.vfsops,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
                return;
            }
        };
        if vfsops_ptr.is_null() {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
            return;
        }

        let mut stat = VStatfs::zeroed();
        let result = {
            let mut mctx = match OwnerMountCtx::from_state(state, mount_h) {
                Some(c) => c,
                None => {
                    send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
                    return;
                }
            };
            ((*vfsops_ptr).statfs)(&mut mctx, &raw mut stat)
        };

        if let Err(e) = result {
            send_reply_err_for_client(state, client, reply_lease, e);
            return;
        }

        let mut out = TronaMsg::default();
        out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
        out.regs[0] = u64::from(stat.bsize);
        out.regs[1] = u64::from(stat.frsize);
        out.regs[2] = stat.blocks;
        out.regs[3] = stat.bfree;
        out.regs[4] = stat.bavail;
        out.regs[5] = stat.files;
        out.regs[6] = stat.ffree;
        out.regs[7] = stat.favail;
        out.regs[8] = stat.fsid;
        out.regs[9] = u64::from(stat.flag);
        out.regs[10] = u64::from(stat.namemax);
        out.length = 11;
        crate::owner::op::reply_send(reply_lease, &out);
    }
}
